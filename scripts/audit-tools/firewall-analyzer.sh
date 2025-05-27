#!/bin/bash
#
# firewall-analyzer.sh
# macOS Security Toolkit
#
# This script analyzes the macOS firewall configuration, checking status,
# allowed applications, blocked connections, and providing recommendations
# for improving security.
#

# Set strict error handling
set -e
set -o pipefail

# Set colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Script variables
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
OUTPUT_DIR="$HOME/macOS_Security_Toolkit/reports/firewall_audit_$TIMESTAMP"
LOG_FILE="$OUTPUT_DIR/firewall_audit.log"

# Create output directory
mkdir -p "$OUTPUT_DIR"
touch "$LOG_FILE"

# Function to log messages
log_message() {
    local message="$1"
    local level="$2"
    local color="$NC"
    
    case "$level" in
        "INFO") color="$BLUE" ;;
        "SUCCESS") color="$GREEN" ;;
        "WARNING") color="$YELLOW" ;;
        "ERROR") color="$RED" ;;
    esac
    
    echo -e "${color}[$level] $message${NC}"
    echo "[$level] $message" >> "$LOG_FILE"
}

# Function to check if script is run with elevated privileges
check_privileges() {
    if [ "$EUID" -ne 0 ]; then
        log_message "This script requires elevated privileges for complete results." "WARNING"
        log_message "Some checks will be limited. Consider running with sudo." "WARNING"
        return 1
    fi
    return 0
}

# Banner
display_banner() {
    echo -e "${BLUE}"
    echo "============================================================"
    echo "  macOS Firewall Configuration Analyzer"
    echo "  $(date)"
    echo "  Output directory: $OUTPUT_DIR"
    echo "============================================================"
    echo -e "${NC}"
}

# Function to detect Mac architecture and OS version
detect_mac_info() {
    # Detect architecture
    MAC_ARCH=$(uname -m)
    if [[ "$MAC_ARCH" == "arm64"* ]]; then
        MAC_TYPE="Apple Silicon"
    else
        MAC_TYPE="Intel"
    fi
    
    # Detect macOS version
    MAC_OS_VERSION=$(sw_vers -productVersion)
    MAC_OS_MAJOR=$(echo "$MAC_OS_VERSION" | cut -d. -f1)
    MAC_OS_MINOR=$(echo "$MAC_OS_VERSION" | cut -d. -f2)
    
    log_message "Detected $MAC_TYPE Mac running macOS $MAC_OS_VERSION" "INFO"
    
    # Create system info file
    echo "# System Information" > "$OUTPUT_DIR/system_info.md"
    echo "- Mac Type: $MAC_TYPE ($MAC_ARCH)" >> "$OUTPUT_DIR/system_info.md"
    echo "- macOS Version: $MAC_OS_VERSION" >> "$OUTPUT_DIR/system_info.md"
    echo "- Hostname: $(hostname)" >> "$OUTPUT_DIR/system_info.md"
    echo "- Date: $(date)" >> "$OUTPUT_DIR/system_info.md"
}

# Function to check firewall status using multiple methods
check_firewall_status() {
    log_message "Checking firewall status..." "INFO"
    
    echo "# Firewall Status" > "$OUTPUT_DIR/firewall_status.md"
    
    # Method 1: Using defaults command (traditional method)
    FIREWALL_STATUS_1=$(defaults read /Library/Preferences/com.apple.alf globalstate 2>/dev/null || echo "Error")
    
    # Method 2: Using socketfilterfw command (works on more macOS versions)
    if check_privileges; then
        FIREWALL_STATUS_2=$(/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>/dev/null | grep -i "enabled" | awk '{print $2}' || echo "Error")
    else
        FIREWALL_STATUS_2="Error"
    fi
    
    # Method 3: Check if firewall service is running (fallback method)
    FIREWALL_SERVICE_RUNNING=$(launchctl list | grep -i "com.apple.alf" > /dev/null && echo "Yes" || echo "No")
    
    # Method 4: Check firewall using system_profiler (works well on Apple Silicon)
    FIREWALL_STATUS_4=$(system_profiler SPFirewallDataType 2>/dev/null | grep -i "Firewall State" | awk -F": " '{print $2}' || echo "Error")
    
    # Method 5: Check firewall using newer macOS interface status
    # This specifically helps with newer macOS versions on Apple Silicon
    if [ "$MAC_TYPE" = "Apple Silicon" ] && [[ "$MAC_OS_MAJOR" -ge 13 ]]; then
        # Try to detect firewall status using the plist that stores UI state
        if [ -f "$HOME/Library/Preferences/com.apple.security.firewall.plist" ]; then
            FIREWALL_UI_STATUS=$(defaults read "$HOME/Library/Preferences/com.apple.security.firewall" globalstate 2>/dev/null || echo "Error")
            if [ "$FIREWALL_UI_STATUS" != "Error" ] && [ "$FIREWALL_UI_STATUS" = "1" ]; then
                FIREWALL_STATUS_5="Active"
            else
                FIREWALL_STATUS_5="Error"
            fi
        else
            FIREWALL_STATUS_5="Error"
        fi
    else
        FIREWALL_STATUS_5="Error"
    fi
    
    # Determine firewall status from available methods
    if [ "$FIREWALL_STATUS_1" != "Error" ]; then
        FIREWALL_STATUS=$FIREWALL_STATUS_1
        FIREWALL_METHOD="defaults command"
    elif [ "$FIREWALL_STATUS_2" != "Error" ]; then
        if [ "$FIREWALL_STATUS_2" = "enabled" ]; then
            FIREWALL_STATUS=1
        else
            FIREWALL_STATUS=0
        fi
        FIREWALL_METHOD="socketfilterfw command"
    elif [ "$FIREWALL_STATUS_4" != "Error" ]; then
        if [ "$FIREWALL_STATUS_4" = "On" ]; then
            FIREWALL_STATUS=1
        else
            FIREWALL_STATUS=0
        fi
        FIREWALL_METHOD="system_profiler"
    elif [ "$FIREWALL_STATUS_5" = "Active" ]; then
        FIREWALL_STATUS=1
        FIREWALL_METHOD="UI settings check"
    elif [ "$FIREWALL_SERVICE_RUNNING" = "Yes" ]; then
        FIREWALL_STATUS="Running"
        FIREWALL_METHOD="service check"
    else
        # Last resort: Check if the firewall UI shows as active
        if [ "$MAC_TYPE" = "Apple Silicon" ] && [[ "$MAC_OS_MAJOR" -ge 13 ]]; then
            # Try to check the UI directly by looking at System Settings
            if system_profiler SPNetworkDataType 2>/dev/null | grep -A 20 "Firewall" | grep -i "Active" > /dev/null; then
                FIREWALL_STATUS=1
                FIREWALL_METHOD="network profile check"
            else
                FIREWALL_STATUS="Unknown"
                FIREWALL_METHOD="multiple methods"
            fi
        else
            FIREWALL_STATUS="Unknown"
            FIREWALL_METHOD="multiple methods"
        fi
    fi
    
    # Log detection method
    log_message "Firewall status detected using $FIREWALL_METHOD" "INFO"
    echo "- Detection Method: $FIREWALL_METHOD" >> "$OUTPUT_DIR/firewall_status.md"
    
    # Interpret firewall status
    if [ "$FIREWALL_STATUS" = "0" ] || [ "$FIREWALL_STATUS" = "Off" ]; then
        log_message "Firewall is disabled" "WARNING"
        echo "- Status: **DISABLED**" >> "$OUTPUT_DIR/firewall_status.md"
        echo "- Risk Level: **HIGH**" >> "$OUTPUT_DIR/firewall_status.md"
        echo "- Recommendation: Enable the firewall to protect your system from unauthorized network access." >> "$OUTPUT_DIR/firewall_status.md"
    elif [ "$FIREWALL_STATUS" = "1" ] || [ "$FIREWALL_STATUS" = "On" ] || [ "$FIREWALL_STATUS" = "Running" ]; then
        log_message "Firewall is enabled" "SUCCESS"
        echo "- Status: **ENABLED**" >> "$OUTPUT_DIR/firewall_status.md"
        echo "- Risk Level: **LOW to MEDIUM**" >> "$OUTPUT_DIR/firewall_status.md"
        echo "- Recommendation: Review allowed applications and consider using stealth mode." >> "$OUTPUT_DIR/firewall_status.md"
    elif [ "$FIREWALL_STATUS" = "2" ]; then
        log_message "Firewall is enabled for essential services only" "SUCCESS"
        echo "- Status: **ENABLED FOR ESSENTIAL SERVICES**" >> "$OUTPUT_DIR/firewall_status.md"
        echo "- Risk Level: **LOW**" >> "$OUTPUT_DIR/firewall_status.md"
        echo "- Recommendation: Consider enabling stealth mode for additional security." >> "$OUTPUT_DIR/firewall_status.md"
    else
        log_message "Unknown firewall status: $FIREWALL_STATUS" "WARNING"
        echo "- Status: **UNKNOWN**" >> "$OUTPUT_DIR/firewall_status.md"
        echo "- Risk Level: **UNKNOWN**" >> "$OUTPUT_DIR/firewall_status.md"
        echo "- Recommendation: Enable the firewall through System Preferences/Settings." >> "$OUTPUT_DIR/firewall_status.md"
    fi
    
    # Check stealth mode using multiple methods
    STEALTH_MODE_1=$(defaults read /Library/Preferences/com.apple.alf stealthenabled 2>/dev/null || echo "Error")
    
    if check_privileges; then
        STEALTH_MODE_2=$(/usr/libexec/ApplicationFirewall/socketfilterfw --getstealthmode 2>/dev/null | grep -i "enabled" | awk '{print $2}' || echo "Error")
    else
        STEALTH_MODE_2="Error"
    fi
    
    # Determine stealth mode status
    if [ "$STEALTH_MODE_1" != "Error" ]; then
        STEALTH_MODE=$STEALTH_MODE_1
        STEALTH_METHOD="defaults command"
    elif [ "$STEALTH_MODE_2" != "Error" ]; then
        if [ "$STEALTH_MODE_2" = "enabled" ]; then
            STEALTH_MODE=1
        else
            STEALTH_MODE=0
        fi
        STEALTH_METHOD="socketfilterfw command"
    else
        STEALTH_MODE="Unknown"
        STEALTH_METHOD="multiple methods"
    fi
    
    echo -e "\n## Stealth Mode" >> "$OUTPUT_DIR/firewall_status.md"
    echo "- Detection Method: $STEALTH_METHOD" >> "$OUTPUT_DIR/firewall_status.md"
    
    if [ "$STEALTH_MODE" = "1" ] || [ "$STEALTH_MODE" = "enabled" ]; then
        log_message "Stealth mode is enabled" "SUCCESS"
        echo "- Status: **ENABLED**" >> "$OUTPUT_DIR/firewall_status.md"
        echo "- Your computer will not respond to ICMP ping requests or connection attempts from closed TCP and UDP ports." >> "$OUTPUT_DIR/firewall_status.md"
    elif [ "$STEALTH_MODE" = "0" ] || [ "$STEALTH_MODE" = "disabled" ]; then
        log_message "Stealth mode is disabled" "WARNING"
        echo "- Status: **DISABLED**" >> "$OUTPUT_DIR/firewall_status.md"
        echo "- Risk Level: **MEDIUM**" >> "$OUTPUT_DIR/firewall_status.md"
        echo "- Recommendation: Enable stealth mode to prevent your computer from responding to probing requests." >> "$OUTPUT_DIR/firewall_status.md"
    else
        log_message "Could not determine stealth mode status" "WARNING"
        echo "- Status: **UNKNOWN**" >> "$OUTPUT_DIR/firewall_status.md"
        echo "- Recommendation: Enable stealth mode through System Preferences/Settings." >> "$OUTPUT_DIR/firewall_status.md"
    fi
    
    # Check logging using multiple methods
    LOGGING_MODE_1=$(defaults read /Library/Preferences/com.apple.alf loggingenabled 2>/dev/null || echo "Error")
    
    if check_privileges; then
        LOGGING_MODE_2=$(/usr/libexec/ApplicationFirewall/socketfilterfw --getloggingmode 2>/dev/null | grep -i "enabled" | awk '{print $2}' || echo "Error")
    else
        LOGGING_MODE_2="Error"
    fi
    
    # Determine logging status
    if [ "$LOGGING_MODE_1" != "Error" ]; then
        LOGGING_MODE=$LOGGING_MODE_1
        LOGGING_METHOD="defaults command"
    elif [ "$LOGGING_MODE_2" != "Error" ]; then
        if [ "$LOGGING_MODE_2" = "enabled" ]; then
            LOGGING_MODE=1
        else
            LOGGING_MODE=0
        fi
        LOGGING_METHOD="socketfilterfw command"
    else
        LOGGING_MODE="Unknown"
        LOGGING_METHOD="multiple methods"
    fi
    
    echo -e "\n## Firewall Logging" >> "$OUTPUT_DIR/firewall_status.md"
    echo "- Detection Method: $LOGGING_METHOD" >> "$OUTPUT_DIR/firewall_status.md"
    
    if [ "$LOGGING_MODE" = "1" ] || [ "$LOGGING_MODE" = "enabled" ]; then
        log_message "Firewall logging is enabled" "SUCCESS"
        echo "- Status: **ENABLED**" >> "$OUTPUT_DIR/firewall_status.md"
        echo "- Firewall events are being logged for monitoring and troubleshooting." >> "$OUTPUT_DIR/firewall_status.md"
    elif [ "$LOGGING_MODE" = "0" ] || [ "$LOGGING_MODE" = "disabled" ]; then
        log_message "Firewall logging is disabled" "WARNING"
        echo "- Status: **DISABLED**" >> "$OUTPUT_DIR/firewall_status.md"
        echo "- Risk Level: **MEDIUM**" >> "$OUTPUT_DIR/firewall_status.md"
        echo "- Recommendation: Enable firewall logging to track blocked connections and potential threats." >> "$OUTPUT_DIR/firewall_status.md"
    else
        log_message "Could not determine logging status" "WARNING"
        echo "- Status: **UNKNOWN**" >> "$OUTPUT_DIR/firewall_status.md"
        echo "- Recommendation: Enable logging through System Preferences/Settings." >> "$OUTPUT_DIR/firewall_status.md"
    fi
    
    # Add instructions for enabling firewall based on macOS version and architecture
    echo -e "\n## How to Enable Firewall" >> "$OUTPUT_DIR/firewall_status.md"
    
    if [[ "$MAC_OS_MAJOR" -ge 13 ]]; then
        # Ventura (13) or later
        echo "### macOS Ventura or Later" >> "$OUTPUT_DIR/firewall_status.md"
        echo "1. Open System Settings" >> "$OUTPUT_DIR/firewall_status.md"
        echo "2. Click on Network in the sidebar" >> "$OUTPUT_DIR/firewall_status.md"
        echo "3. Click on Firewall at the bottom" >> "$OUTPUT_DIR/firewall_status.md"
        echo "4. Toggle the switch to turn on the Firewall" >> "$OUTPUT_DIR/firewall_status.md"
        echo "5. Click on the 'i' button for additional options" >> "$OUTPUT_DIR/firewall_status.md"
    else
        # Monterey (12) or earlier
        echo "### macOS Monterey or Earlier" >> "$OUTPUT_DIR/firewall_status.md"
        echo "1. Open System Preferences" >> "$OUTPUT_DIR/firewall_status.md"
        echo "2. Click on Security & Privacy" >> "$OUTPUT_DIR/firewall_status.md"
        echo "3. Select the Firewall tab" >> "$OUTPUT_DIR/firewall_status.md"
        echo "4. Click the lock icon to make changes (enter your password)" >> "$OUTPUT_DIR/firewall_status.md"
        echo "5. Click 'Turn On Firewall'" >> "$OUTPUT_DIR/firewall_status.md"
        echo "6. Click 'Firewall Options' to configure additional settings" >> "$OUTPUT_DIR/firewall_status.md"
    fi
    
    log_message "Firewall status check completed" "SUCCESS"
}

# Function to check allowed applications
check_allowed_applications() {
    log_message "Checking allowed applications..." "INFO"
    
    echo "# Allowed Applications" > "$OUTPUT_DIR/allowed_applications.md"
    
    # Get list of allowed applications
    if check_privileges; then
        # This requires sudo access
        /usr/libexec/ApplicationFirewall/socketfilterfw --listapps > "$OUTPUT_DIR/raw_allowed_apps.txt" 2>/dev/null || true
        
        if [ -s "$OUTPUT_DIR/raw_allowed_apps.txt" ]; then
            echo "The following applications are allowed to receive incoming connections:" >> "$OUTPUT_DIR/allowed_applications.md"
            echo "" >> "$OUTPUT_DIR/allowed_applications.md"
            echo "| Application | Allowed | Signed |" >> "$OUTPUT_DIR/allowed_applications.md"
            echo "|-------------|---------|--------|" >> "$OUTPUT_DIR/allowed_applications.md"
            
            grep -A 2 "ALF: " "$OUTPUT_DIR/raw_allowed_apps.txt" | while read -r line; do
                if [[ $line == ALF:* ]]; then
                    app_name=$(echo "$line" | sed 's/ALF: //g')
                    read -r allowed_line
                    read -r signed_line
                    
                    allowed=$(echo "$allowed_line" | grep -o "ALLOWED" || echo "BLOCKED")
                    signed=$(echo "$signed_line" | grep -o "SIGNED" || echo "UNSIGNED")
                    
                    echo "| $app_name | $allowed | $signed |" >> "$OUTPUT_DIR/allowed_applications.md"
                fi
            done
            
            log_message "Found $(grep -c "ALF: " "$OUTPUT_DIR/raw_allowed_apps.txt") allowed applications" "INFO"
        else
            echo "No applications are explicitly allowed through the firewall." >> "$OUTPUT_DIR/allowed_applications.md"
            log_message "No allowed applications found" "INFO"
        fi
    else
        echo "Unable to list allowed applications. Run with sudo for complete results." >> "$OUTPUT_DIR/allowed_applications.md"
    fi
    
    echo -e "\n## Recommendations" >> "$OUTPUT_DIR/allowed_applications.md"
    echo "1. Review all allowed applications and remove any that are unnecessary" >> "$OUTPUT_DIR/allowed_applications.md"
    echo "2. Ensure all allowed applications are signed" >> "$OUTPUT_DIR/allowed_applications.md"
    echo "3. Consider using the most restrictive firewall setting (Block all incoming connections)" >> "$OUTPUT_DIR/allowed_applications.md"
    
    log_message "Allowed applications check completed" "SUCCESS"
}

# Function to check recent blocked connections
check_blocked_connections() {
    log_message "Checking recent blocked connections..." "INFO"
    
    echo "# Recent Blocked Connections" > "$OUTPUT_DIR/blocked_connections.md"
    
    # Check firewall log for blocked connections
    if [ -f "/var/log/appfirewall.log" ] && check_privileges; then
        grep "Deny" /var/log/appfirewall.log > "$OUTPUT_DIR/blocked_connections.txt" 2>/dev/null || true
        
        if [ -s "$OUTPUT_DIR/blocked_connections.txt" ]; then
            BLOCKED_COUNT=$(wc -l < "$OUTPUT_DIR/blocked_connections.txt")
            log_message "Found $BLOCKED_COUNT blocked connection attempts" "INFO"
            
            echo "Found $BLOCKED_COUNT blocked connection attempts in the firewall log:" >> "$OUTPUT_DIR/blocked_connections.md"
            echo "" >> "$OUTPUT_DIR/blocked_connections.md"
            
            # Extract the top 10 most frequently blocked sources
            echo "## Top 10 Blocked Sources" >> "$OUTPUT_DIR/blocked_connections.md"
            echo "" >> "$OUTPUT_DIR/blocked_connections.md"
            
            grep -o "from [0-9]*\.[0-9]*\.[0-9]*\.[0-9]*" "$OUTPUT_DIR/blocked_connections.txt" | sort | uniq -c | sort -nr | head -10 > "$OUTPUT_DIR/top_blocked_sources.txt"
            
            echo "| IP Address | Count |" >> "$OUTPUT_DIR/blocked_connections.md"
            echo "|------------|-------|" >> "$OUTPUT_DIR/blocked_connections.md"
            
            while read -r line; do
                count=$(echo "$line" | awk '{print $1}')
                ip=$(echo "$line" | awk '{print $3}')
                echo "| $ip | $count |" >> "$OUTPUT_DIR/blocked_connections.md"
            done < "$OUTPUT_DIR/top_blocked_sources.txt"
            
            # Extract the top 10 most frequently blocked ports
            echo -e "\n## Top 10 Blocked Ports" >> "$OUTPUT_DIR/blocked_connections.md"
            echo "" >> "$OUTPUT_DIR/blocked_connections.md"
            
            grep -o "port [0-9]*" "$OUTPUT_DIR/blocked_connections.txt" | sort | uniq -c | sort -nr | head -10 > "$OUTPUT_DIR/top_blocked_ports.txt"
            
            echo "| Port | Count | Common Service |" >> "$OUTPUT_DIR/blocked_connections.md"
            echo "|------|-------|---------------|" >> "$OUTPUT_DIR/blocked_connections.md"
            
            while read -r line; do
                count=$(echo "$line" | awk '{print $1}')
                port=$(echo "$line" | awk '{print $3}')
                
                # Identify common services for well-known ports
                service="Unknown"
                case "$port" in
                    21) service="FTP" ;;
                    22) service="SSH" ;;
                    23) service="Telnet" ;;
                    25) service="SMTP" ;;
                    53) service="DNS" ;;
                    80) service="HTTP" ;;
                    110) service="POP3" ;;
                    143) service="IMAP" ;;
                    443) service="HTTPS" ;;
                    445) service="SMB" ;;
                    3389) service="RDP" ;;
                esac
                
                echo "| $port | $count | $service |" >> "$OUTPUT_DIR/blocked_connections.md"
            done < "$OUTPUT_DIR/top_blocked_ports.txt"
        else
            log_message "No blocked connections found in the log" "INFO"
            echo "No blocked connections found in the firewall log." >> "$OUTPUT_DIR/blocked_connections.md"
        fi
    else
        log_message "Cannot access firewall log" "WARNING"
        echo "Cannot access the firewall log. Make sure logging is enabled and run with sudo." >> "$OUTPUT_DIR/blocked_connections.md"
    fi
    
    log_message "Blocked connections check completed" "SUCCESS"
}

# Function to generate recommendations
generate_recommendations() {
    log_message "Generating security recommendations..." "INFO"
    
    echo "# Firewall Security Recommendations" > "$OUTPUT_DIR/recommendations.md"
    echo "Generated: $(date)" >> "$OUTPUT_DIR/recommendations.md"
    echo "" >> "$OUTPUT_DIR/recommendations.md"
    
    # Basic recommendations
    echo "## Basic Recommendations" >> "$OUTPUT_DIR/recommendations.md"
    echo "" >> "$OUTPUT_DIR/recommendations.md"
    echo "1. **Enable the Firewall**: Ensure the macOS firewall is enabled at all times" >> "$OUTPUT_DIR/recommendations.md"
    echo "2. **Enable Stealth Mode**: Prevent your Mac from responding to probing attempts" >> "$OUTPUT_DIR/recommendations.md"
    echo "3. **Enable Logging**: Turn on firewall logging to track blocked connections" >> "$OUTPUT_DIR/recommendations.md"
    echo "4. **Review Allowed Applications**: Regularly audit and remove unnecessary applications" >> "$OUTPUT_DIR/recommendations.md"
    echo "5. **Block All Incoming Connections**: For maximum security, consider blocking all incoming connections" >> "$OUTPUT_DIR/recommendations.md"
    
    # Advanced recommendations
    echo -e "\n## Advanced Recommendations" >> "$OUTPUT_DIR/recommendations.md"
    echo "" >> "$OUTPUT_DIR/recommendations.md"
    echo "1. **Use Third-Party Firewall**: Consider using a more advanced third-party firewall for additional control" >> "$OUTPUT_DIR/recommendations.md"
    echo "2. **Implement Network-Level Firewall**: For organizational environments, implement a network-level firewall" >> "$OUTPUT_DIR/recommendations.md"
    echo "3. **Regular Audits**: Perform regular audits of firewall rules and blocked connections" >> "$OUTPUT_DIR/recommendations.md"
    echo "4. **Monitor Logs**: Regularly review firewall logs for suspicious activity" >> "$OUTPUT_DIR/recommendations.md"
    echo "5. **Update Applications**: Keep all applications up-to-date to minimize security vulnerabilities" >> "$OUTPUT_DIR/recommendations.md"
    
    # How to enable firewall
    echo -e "\n## How to Enable the macOS Firewall" >> "$OUTPUT_DIR/recommendations.md"
    echo "" >> "$OUTPUT_DIR/recommendations.md"
    echo "1. Open System Preferences" >> "$OUTPUT_DIR/recommendations.md"
    echo "2. Click on Security & Privacy" >> "$OUTPUT_DIR/recommendations.md"
    echo "3. Select the Firewall tab" >> "$OUTPUT_DIR/recommendations.md"
    echo "4. Click the lock icon to make changes (if needed)" >> "$OUTPUT_DIR/recommendations.md"
    echo "5. Click 'Turn On Firewall'" >> "$OUTPUT_DIR/recommendations.md"
    echo "6. Click 'Firewall Options' to configure additional settings" >> "$OUTPUT_DIR/recommendations.md"
    echo "7. Check 'Enable stealth mode'" >> "$OUTPUT_DIR/recommendations.md"
    
    log_message "Recommendations generated: $OUTPUT_DIR/recommendations.md" "SUCCESS"
}

# Function to generate a summary report
generate_summary() {
    log_message "Generating summary report..." "INFO"
    
    echo "# macOS Firewall Security Audit Summary" > "$OUTPUT_DIR/summary.md"
    echo "Generated: $(date)" >> "$OUTPUT_DIR/summary.md"
    echo "" >> "$OUTPUT_DIR/summary.md"
    
    # Include system information
    echo "## System Information" >> "$OUTPUT_DIR/summary.md"
    echo "- Mac Type: $MAC_TYPE ($MAC_ARCH)" >> "$OUTPUT_DIR/summary.md"
    echo "- macOS Version: $MAC_OS_VERSION" >> "$OUTPUT_DIR/summary.md"
    echo "- Hostname: $(hostname)" >> "$OUTPUT_DIR/summary.md"
    echo "" >> "$OUTPUT_DIR/summary.md"
    
    # Firewall status summary
    echo "## Firewall Status" >> "$OUTPUT_DIR/summary.md"
    
    # Check if firewall is enabled
    FIREWALL_STATUS=$(defaults read /Library/Preferences/com.apple.alf globalstate 2>/dev/null || echo "Error")
    STEALTH_MODE=$(defaults read /Library/Preferences/com.apple.alf stealthenabled 2>/dev/null || echo "Error")
    LOGGING_MODE=$(defaults read /Library/Preferences/com.apple.alf loggingenabled 2>/dev/null || echo "Error")
    
    # Calculate overall security score
    SCORE=0
    MAX_SCORE=3
    
    if [ "$FIREWALL_STATUS" = "1" ] || [ "$FIREWALL_STATUS" = "2" ]; then
        SCORE=$((SCORE + 1))
        echo "- ✅ Firewall is enabled" >> "$OUTPUT_DIR/summary.md"
    else
        echo "- ❌ Firewall is disabled" >> "$OUTPUT_DIR/summary.md"
    fi
    
    if [ "$STEALTH_MODE" = "1" ]; then
        SCORE=$((SCORE + 1))
        echo "- ✅ Stealth mode is enabled" >> "$OUTPUT_DIR/summary.md"
    else
        echo "- ❌ Stealth mode is disabled" >> "$OUTPUT_DIR/summary.md"
    fi
    
    if [ "$LOGGING_MODE" = "1" ]; then
        SCORE=$((SCORE + 1))
        echo "- ✅ Firewall logging is enabled" >> "$OUTPUT_DIR/summary.md"
    else
        echo "- ❌ Firewall logging is disabled" >> "$OUTPUT_DIR/summary.md"
    fi
    
    # Calculate percentage
    PERCENTAGE=$((SCORE * 100 / MAX_SCORE))
    
    echo -e "\n## Security Score" >> "$OUTPUT_DIR/summary.md"
    echo "" >> "$OUTPUT_DIR/summary.md"
    echo "**$PERCENTAGE%** ($SCORE out of $MAX_SCORE points)" >> "$OUTPUT_DIR/summary.md"
    
    # Security rating
    echo -e "\n## Security Rating" >> "$OUTPUT_DIR/summary.md"
    echo "" >> "$OUTPUT_DIR/summary.md"
    
    if [ "$PERCENTAGE" -eq 100 ]; then
        echo "**Excellent** - Your firewall is properly configured for optimal security." >> "$OUTPUT_DIR/summary.md"
    elif [ "$PERCENTAGE" -ge 66 ]; then
        echo "**Good** - Your firewall provides adequate protection but could be improved." >> "$OUTPUT_DIR/summary.md"
    elif [ "$PERCENTAGE" -ge 33 ]; then
        echo "**Fair** - Your firewall configuration needs significant improvement." >> "$OUTPUT_DIR/summary.md"
    else
        echo "**Poor** - Your firewall configuration is inadequate and leaves your system vulnerable." >> "$OUTPUT_DIR/summary.md"
    fi
    
    # Top recommendations
    echo -e "\n## Top Recommendations" >> "$OUTPUT_DIR/summary.md"
    echo "" >> "$OUTPUT_DIR/summary.md"
    
    if [ "$FIREWALL_STATUS" != "1" ] && [ "$FIREWALL_STATUS" != "2" ]; then
        echo "1. **Enable the firewall** to protect your system from unauthorized access" >> "$OUTPUT_DIR/summary.md"
    fi
    
    if [ "$STEALTH_MODE" != "1" ]; then
        echo "2. **Enable stealth mode** to prevent your system from responding to network probing" >> "$OUTPUT_DIR/summary.md"
    fi
    
    if [ "$LOGGING_MODE" != "1" ]; then
        echo "3. **Enable firewall logging** to track blocked connections and potential threats" >> "$OUTPUT_DIR/summary.md"
    fi
    
    echo "4. **Review allowed applications** regularly and remove unnecessary exceptions" >> "$OUTPUT_DIR/summary.md"
    echo "5. **Monitor firewall logs** for suspicious activity" >> "$OUTPUT_DIR/summary.md"
    
    log_message "Summary report generated: $OUTPUT_DIR/summary.md" "SUCCESS"
}

# Main execution
display_banner
check_privileges

# Detect Mac architecture and OS version
detect_mac_info

# Run all checks
check_firewall_status
check_allowed_applications
check_blocked_connections
generate_recommendations
generate_summary

# Final output
log_message "Firewall analysis completed successfully" "SUCCESS"
log_message "All reports saved to: $OUTPUT_DIR" "SUCCESS"
echo -e "${GREEN}To view the summary report, open:${NC} $OUTPUT_DIR/summary.md"
