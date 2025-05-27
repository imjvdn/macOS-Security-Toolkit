#!/bin/bash
#
# user-account-audit.sh
# macOS Security Toolkit
#
# This script performs a comprehensive audit of user accounts on macOS systems,
# identifying potential security issues such as accounts with weak password policies,
# admin privileges, or suspicious login activity.
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
OUTPUT_DIR="$HOME/macOS_Security_Toolkit/reports/user_audit_$TIMESTAMP"
LOG_FILE="$OUTPUT_DIR/user_audit.log"

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
    echo "  macOS User Account Security Audit"
    echo "  $(date)"
    echo "  Output directory: $OUTPUT_DIR"
    echo "============================================================"
    echo -e "${NC}"
}

# Function to get all user accounts
get_user_accounts() {
    log_message "Collecting user account information..." "INFO"
    
    # Get all users
    dscl . list /Users | grep -v "^_" > "$OUTPUT_DIR/all_users.txt"
    log_message "Found $(wc -l < "$OUTPUT_DIR/all_users.txt") user accounts" "INFO"
    
    # Get admin users
    dseditgroup -o checkmember -m admin admin 2>/dev/null | grep "yes" > /dev/null
    ADMIN_STATUS=$?
    
    echo "Username,UID,GID,Admin,Shell,Home Directory" > "$OUTPUT_DIR/user_details.csv"
    
    while read -r username; do
        if [ -n "$username" ] && [ "$username" != "daemon" ] && [ "$username" != "nobody" ]; then
            uid=$(dscl . -read "/Users/$username" UniqueID 2>/dev/null | awk '{print $2}')
            gid=$(dscl . -read "/Users/$username" PrimaryGroupID 2>/dev/null | awk '{print $2}')
            
            # Check if user is admin
            dseditgroup -o checkmember -m "$username" admin 2>/dev/null | grep "yes" > /dev/null
            if [ $? -eq 0 ]; then
                admin="Yes"
            else
                admin="No"
            fi
            
            shell=$(dscl . -read "/Users/$username" UserShell 2>/dev/null | awk '{print $2}')
            home=$(dscl . -read "/Users/$username" NFSHomeDirectory 2>/dev/null | awk '{print $2}')
            
            echo "$username,$uid,$gid,$admin,$shell,$home" >> "$OUTPUT_DIR/user_details.csv"
        fi
    done < "$OUTPUT_DIR/all_users.txt"
    
    log_message "User account details exported to user_details.csv" "SUCCESS"
}

# Function to check password policies
check_password_policies() {
    log_message "Checking password policies..." "INFO"
    
    echo "Username,PasswordLastSet,PasswordExpires,PasswordChangeable,PasswordRequired" > "$OUTPUT_DIR/password_policies.csv"
    
    while read -r username; do
        if [ -n "$username" ] && [ "$username" != "daemon" ] && [ "$username" != "nobody" ]; then
            # Get password policy information
            pwpolicy -u "$username" -getaccountpolicies 2>/dev/null > "$OUTPUT_DIR/temp_policy.xml"
            
            # Parse password policy information
            last_set=$(pwpolicy -u "$username" -getlastpasswordchangetime 2>/dev/null | awk -F': ' '{print $2}')
            [ -z "$last_set" ] && last_set="Unknown"
            
            # Check if password expires
            if grep -q "policyAttributePasswordAgingDays" "$OUTPUT_DIR/temp_policy.xml" 2>/dev/null; then
                expires="Yes"
            else
                expires="No"
            fi
            
            # Check if password is changeable
            if grep -q "policyAttributeAllowUserToChangePassword" "$OUTPUT_DIR/temp_policy.xml" 2>/dev/null; then
                changeable="Yes"
            else
                changeable="No"
            fi
            
            # Check if password is required
            if grep -q "isDisabled" "$OUTPUT_DIR/temp_policy.xml" 2>/dev/null; then
                required="No"
            else
                required="Yes"
            fi
            
            echo "$username,$last_set,$expires,$changeable,$required" >> "$OUTPUT_DIR/password_policies.csv"
        fi
    done < "$OUTPUT_DIR/all_users.txt"
    
    rm -f "$OUTPUT_DIR/temp_policy.xml"
    log_message "Password policies exported to password_policies.csv" "SUCCESS"
}

# Function to check login history
check_login_history() {
    log_message "Checking login history..." "INFO"
    
    # Get last 100 logins
    last -100 > "$OUTPUT_DIR/login_history.txt"
    
    # Extract failed login attempts
    log_message "Checking failed login attempts..." "INFO"
    grep "fail" /var/log/system.log | grep "authentication" > "$OUTPUT_DIR/failed_logins.txt" 2>/dev/null || true
    
    log_message "Login history exported to login_history.txt" "SUCCESS"
    log_message "Failed login attempts exported to failed_logins.txt" "SUCCESS"
}

# Function to check for suspicious user accounts
check_suspicious_accounts() {
    log_message "Checking for suspicious user accounts..." "INFO"
    
    # Check for users with UID 0 (other than root)
    grep ",0," "$OUTPUT_DIR/user_details.csv" | grep -v "^root," > "$OUTPUT_DIR/uid_0_users.txt" || true
    
    # Check for users with empty passwords (requires root)
    if check_privileges; then
        while read -r username; do
            if [ -n "$username" ] && [ "$username" != "daemon" ] && [ "$username" != "nobody" ]; then
                passwd_status=$(passwd -s "$username" 2>/dev/null | awk '{print $2}')
                if [ "$passwd_status" = "NP" ]; then
                    echo "$username" >> "$OUTPUT_DIR/empty_password_users.txt"
                fi
            fi
        done < "$OUTPUT_DIR/all_users.txt"
    fi
    
    # Check for users with non-standard shells
    grep -v "/bin/bash\|/bin/zsh\|/bin/sh\|/usr/bin/false\|/usr/bin/nologin" "$OUTPUT_DIR/user_details.csv" > "$OUTPUT_DIR/nonstandard_shell_users.txt" || true
    
    log_message "Suspicious account checks completed" "SUCCESS"
}

# Function to generate a summary report
generate_summary() {
    log_message "Generating summary report..." "INFO"
    
    echo "# macOS User Account Security Audit Summary" > "$OUTPUT_DIR/summary.md"
    echo "Generated: $(date)" >> "$OUTPUT_DIR/summary.md"
    echo "" >> "$OUTPUT_DIR/summary.md"
    
    echo "## User Account Statistics" >> "$OUTPUT_DIR/summary.md"
    echo "- Total user accounts: $(wc -l < "$OUTPUT_DIR/all_users.txt")" >> "$OUTPUT_DIR/summary.md"
    echo "- Admin accounts: $(grep ",Yes," "$OUTPUT_DIR/user_details.csv" | wc -l)" >> "$OUTPUT_DIR/summary.md"
    echo "- Standard accounts: $(grep ",No," "$OUTPUT_DIR/user_details.csv" | wc -l)" >> "$OUTPUT_DIR/summary.md"
    echo "" >> "$OUTPUT_DIR/summary.md"
    
    echo "## Security Findings" >> "$OUTPUT_DIR/summary.md"
    
    # Check for UID 0 users
    if [ -s "$OUTPUT_DIR/uid_0_users.txt" ]; then
        echo "- **HIGH RISK**: Found $(wc -l < "$OUTPUT_DIR/uid_0_users.txt") users with UID 0 (root privileges)" >> "$OUTPUT_DIR/summary.md"
    else
        echo "- No users with UID 0 (other than root)" >> "$OUTPUT_DIR/summary.md"
    fi
    
    # Check for empty passwords
    if [ -f "$OUTPUT_DIR/empty_password_users.txt" ] && [ -s "$OUTPUT_DIR/empty_password_users.txt" ]; then
        echo "- **HIGH RISK**: Found $(wc -l < "$OUTPUT_DIR/empty_password_users.txt") users with empty passwords" >> "$OUTPUT_DIR/summary.md"
    else
        echo "- No users with empty passwords detected" >> "$OUTPUT_DIR/summary.md"
    fi
    
    # Check for non-standard shells
    if [ -s "$OUTPUT_DIR/nonstandard_shell_users.txt" ]; then
        echo "- **WARNING**: Found $(wc -l < "$OUTPUT_DIR/nonstandard_shell_users.txt") users with non-standard shells" >> "$OUTPUT_DIR/summary.md"
    else
        echo "- No users with non-standard shells" >> "$OUTPUT_DIR/summary.md"
    fi
    
    # Check for failed logins
    if [ -s "$OUTPUT_DIR/failed_logins.txt" ]; then
        echo "- **WARNING**: Found $(wc -l < "$OUTPUT_DIR/failed_logins.txt") failed login attempts" >> "$OUTPUT_DIR/summary.md"
    else
        echo "- No failed login attempts detected" >> "$OUTPUT_DIR/summary.md"
    fi
    
    echo "" >> "$OUTPUT_DIR/summary.md"
    echo "## Recommendations" >> "$OUTPUT_DIR/summary.md"
    echo "1. Review all admin accounts and remove unnecessary privileges" >> "$OUTPUT_DIR/summary.md"
    echo "2. Ensure all accounts have strong password policies" >> "$OUTPUT_DIR/summary.md"
    echo "3. Investigate any accounts with UID 0, empty passwords, or non-standard shells" >> "$OUTPUT_DIR/summary.md"
    echo "4. Monitor and investigate failed login attempts" >> "$OUTPUT_DIR/summary.md"
    echo "5. Implement password aging and complexity requirements" >> "$OUTPUT_DIR/summary.md"
    
    log_message "Summary report generated: $OUTPUT_DIR/summary.md" "SUCCESS"
}

# Main execution
display_banner
check_privileges

# Run all checks
get_user_accounts
check_password_policies
check_login_history
check_suspicious_accounts
generate_summary

# Final output
log_message "User account audit completed successfully" "SUCCESS"
log_message "All reports saved to: $OUTPUT_DIR" "SUCCESS"
echo -e "${GREEN}To view the summary report, open:${NC} $OUTPUT_DIR/summary.md"
