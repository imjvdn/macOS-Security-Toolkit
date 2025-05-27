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

# Function to check firewall status
check_firewall_status() {
    log_message "Checking firewall status..." "INFO"
    
    # Check if firewall is enabled
    FIREWALL_STATUS=$(defaults read /Library/Preferences/com.apple.alf globalstate 2>/dev/null || echo "Error")
    
    echo "# Firewall Status" > "$OUTPUT_DIR/firewall_status.md"
    
    if [ "$FIREWALL_STATUS" = "Error" ]; then
        log_message "Could not determine firewall status" "ERROR"
        echo "Could not determine firewall status. Try running with sudo." >> "$OUTPUT_DIR/firewall_status.md"
    else
        case "$FIREWALL_STATUS" in
            0)
                log_message "Firewall is disabled" "WARNING"
                echo "- Status: **DISABLED**" >> "$OUTPUT_DIR/firewall_status.md"
                echo "- Risk Level: **HIGH**" >> "$OUTPUT_DIR/firewall_status.md"
                echo "- Recommendation: Enable the firewall to protect your system from unauthorized network access." >> "$OUTPUT_DIR/firewall_status.md"
                ;;
            1)
                log_message "Firewall is enabled with exceptions" "INFO"
                echo "- Status: **ENABLED WITH EXCEPTIONS**" >> "$OUTPUT_DIR/firewall_status.md"
                echo "- Risk Level: **MEDIUM**" >> "$OUTPUT_DIR/firewall_status.md"
                echo "- Recommendation: Review allowed applications and consider using stealth mode." >> "$OUTPUT_DIR/firewall_status.md"
                ;;
            2)
                log_message "Firewall is enabled for essential services only" "SUCCESS"
                echo "- Status: **ENABLED FOR ESSENTIAL SERVICES**" >> "$OUTPUT_DIR/firewall_status.md"
                echo "- Risk Level: **LOW**" >> "$OUTPUT_DIR/firewall_status.md"
                echo "- Recommendation: Consider enabling stealth mode for additional security." >> "$OUTPUT_DIR/firewall_status.md"
                ;;
            *)
                log_message "Unknown firewall status: $FIREWALL_STATUS" "WARNING"
                echo "- Status: **UNKNOWN ($FIREWALL_STATUS)**" >> "$OUTPUT_DIR/firewall_status.md"
                echo "- Risk Level: **UNKNOWN**" >> "$OUTPUT_DIR/firewall_status.md"
                echo "- Recommendation: Investigate firewall configuration and ensure it is properly set up." >> "$OUTPUT_DIR/firewall_status.md"
                ;;
        esac
    fi
    
    # Check stealth mode
    STEALTH_MODE=$(defaults read /Library/Preferences/com.apple.alf stealthenabled 2>/dev/null || echo "Error")
    
    echo -e "\n## Stealth Mode" >> "$OUTPUT_DIR/firewall_status.md"
    
    if [ "$STEALTH_MODE" = "Error" ]; then
        log_message "Could not determine stealth mode status" "ERROR"
        echo "Could not determine stealth mode status. Try running with sudo." >> "$OUTPUT_DIR/firewall_status.md"
    else
        if [ "$STEALTH_MODE" = "1" ]; then
            log_message "Stealth mode is enabled" "SUCCESS"
            echo "- Status: **ENABLED**" >> "$OUTPUT_DIR/firewall_status.md"
            echo "- Your computer will not respond to ICMP ping requests or connection attempts from closed TCP and UDP ports." >> "$OUTPUT_DIR/firewall_status.md"
        else
            log_message "Stealth mode is disabled" "WARNING"
            echo "- Status: **DISABLED**" >> "$OUTPUT_DIR/firewall_status.md"
            echo "- Risk Level: **MEDIUM**" >> "$OUTPUT_DIR/firewall_status.md"
            echo "- Recommendation: Enable stealth mode to prevent your computer from responding to probing requests." >> "$OUTPUT_DIR/firewall_status.md"
        fi
    fi
    
    # Check logging
    LOGGING_MODE=$(defaults read /Library/Preferences/com.apple.alf loggingenabled 2>/dev/null || echo "Error")
    
    echo -e "\n## Firewall Logging" >> "$OUTPUT_DIR/firewall_status.md"
    
    if [ "$LOGGING_MODE" = "Error" ]; then
        log_message "Could not determine logging status" "ERROR"
        echo "Could not determine logging status. Try running with sudo." >> "$OUTPUT_DIR/firewall_status.md"
    else
        if [ "$LOGGING_MODE" = "1" ]; then
            log_message "Firewall logging is enabled" "SUCCESS"
            echo "- Status: **ENABLED**" >> "$OUTPUT_DIR/firewall_status.md"
            echo "- Firewall events are being logged for monitoring and troubleshooting." >> "$OUTPUT_DIR/firewall_status.md"
        else
            log_message "Firewall logging is disabled" "WARNING"
            echo "- Status: **DISABLED**" >> "$OUTPUT_DIR/firewall_status.md"
            echo "- Risk Level: **MEDIUM**" >> "$OUTPUT_DIR/firewall_status.md"
            echo "- Recommendation: Enable firewall logging to track blocked connections and potential threats." >> "$OUTPUT_DIR/firewall_status.md"
        fi
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
