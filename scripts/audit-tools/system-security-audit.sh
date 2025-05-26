#!/bin/bash
#
# system-security-audit.sh
# macOS Security Toolkit
#
# Performs a comprehensive security audit of a macOS system, collecting
# system information, security settings, user accounts, network configuration,
# installed applications, and more.
#
# Usage: ./system-security-audit.sh [--output-dir /path/to/output]
#

# Set strict error handling
set -e
set -o pipefail

# Default output directory
OUTPUT_DIR="$HOME/Documents/macOS-Security-Audit-$(date +%Y%m%d-%H%M%S)"

# Process command line arguments
while [[ $# -gt 0 ]]; do
    key="$1"
    case $key in
        --output-dir)
            OUTPUT_DIR="$2"
            shift
            shift
            ;;
        *)
            echo "Unknown option: $1"
            echo "Usage: $0 [--output-dir /path/to/output]"
            exit 1
            ;;
    esac
done

# Create output directory
mkdir -p "$OUTPUT_DIR"
mkdir -p "$OUTPUT_DIR/system-info"
mkdir -p "$OUTPUT_DIR/security-settings"
mkdir -p "$OUTPUT_DIR/user-accounts"
mkdir -p "$OUTPUT_DIR/network-config"
mkdir -p "$OUTPUT_DIR/applications"
mkdir -p "$OUTPUT_DIR/logs"

# Log file
LOG_FILE="$OUTPUT_DIR/audit.log"

# Function to log messages
log_message() {
    local timestamp=$(date +"%Y-%m-%d %H:%M:%S")
    echo "[$timestamp] $1" | tee -a "$LOG_FILE"
}

# Function to run a command and save output to file
run_command() {
    local cmd="$1"
    local output_file="$2"
    local description="$3"
    
    log_message "Collecting $description..."
    
    if eval "$cmd" > "$output_file" 2>&1; then
        log_message "✅ Successfully collected $description"
    else
        log_message "⚠️ Error collecting $description"
    fi
}

# Print header
log_message "Starting macOS Security Audit"
log_message "Output directory: $OUTPUT_DIR"
log_message "macOS version: $(sw_vers -productVersion)"
log_message "Hostname: $(hostname)"
log_message "Date: $(date)"
log_message "----------------------------------------"

#
# System Information Collection
#
log_message "Collecting system information..."

# Basic system info
run_command "system_profiler SPSoftwareDataType SPHardwareDataType" "$OUTPUT_DIR/system-info/system-overview.txt" "system overview"

# Hardware and software details
run_command "sw_vers" "$OUTPUT_DIR/system-info/os-version.txt" "OS version"
run_command "uname -a" "$OUTPUT_DIR/system-info/kernel-info.txt" "kernel information"
run_command "system_profiler SPStorageDataType" "$OUTPUT_DIR/system-info/storage-info.txt" "storage information"
run_command "system_profiler SPMemoryDataType" "$OUTPUT_DIR/system-info/memory-info.txt" "memory information"
run_command "system_profiler SPPowerDataType" "$OUTPUT_DIR/system-info/power-info.txt" "power information"
run_command "system_profiler SPFirewallDataType" "$OUTPUT_DIR/system-info/firewall-info.txt" "firewall information"
run_command "system_profiler SPNetworkDataType" "$OUTPUT_DIR/system-info/network-hardware.txt" "network hardware"
run_command "system_profiler SPBluetoothDataType" "$OUTPUT_DIR/system-info/bluetooth-info.txt" "bluetooth information"
run_command "system_profiler SPUSBDataType" "$OUTPUT_DIR/system-info/usb-devices.txt" "USB devices"
run_command "system_profiler SPThunderboltDataType" "$OUTPUT_DIR/system-info/thunderbolt-devices.txt" "Thunderbolt devices"

# Running processes and services
run_command "ps -axo user,pid,ppid,%cpu,%mem,start,time,command" "$OUTPUT_DIR/system-info/running-processes.txt" "running processes"
run_command "launchctl list" "$OUTPUT_DIR/system-info/launchd-services.txt" "launchd services"

# Installed kernel extensions
run_command "kextstat" "$OUTPUT_DIR/system-info/kernel-extensions.txt" "kernel extensions"

# Boot arguments and EFI status
run_command "nvram boot-args" "$OUTPUT_DIR/system-info/boot-args.txt" "boot arguments"
run_command "csrutil status" "$OUTPUT_DIR/system-info/sip-status.txt" "System Integrity Protection status"

#
# Security Settings Collection
#
log_message "Collecting security settings..."

# FileVault status
run_command "fdesetup status" "$OUTPUT_DIR/security-settings/filevault-status.txt" "FileVault status"

# Firewall status
run_command "defaults read /Library/Preferences/com.apple.alf globalstate" "$OUTPUT_DIR/security-settings/firewall-state.txt" "firewall state"
run_command "defaults read /Library/Preferences/com.apple.alf allowsignedenabled" "$OUTPUT_DIR/security-settings/firewall-signed-apps.txt" "firewall signed apps setting"
run_command "defaults read /Library/Preferences/com.apple.alf stealthenabled" "$OUTPUT_DIR/security-settings/firewall-stealth-mode.txt" "firewall stealth mode"

# Gatekeeper status
run_command "spctl --status" "$OUTPUT_DIR/security-settings/gatekeeper-status.txt" "Gatekeeper status"

# Password policies
run_command "pwpolicy -getaccountpolicies" "$OUTPUT_DIR/security-settings/password-policies.txt" "password policies"

# Automatic login
run_command "defaults read /Library/Preferences/com.apple.loginwindow autoLoginUser" "$OUTPUT_DIR/security-settings/autologin-user.txt" "automatic login user"

# Screen saver settings
run_command "defaults read com.apple.screensaver askForPassword" "$OUTPUT_DIR/security-settings/screensaver-password.txt" "screen saver password requirement"
run_command "defaults read com.apple.screensaver askForPasswordDelay" "$OUTPUT_DIR/security-settings/screensaver-password-delay.txt" "screen saver password delay"

# Remote services
run_command "systemsetup -getremotelogin" "$OUTPUT_DIR/security-settings/ssh-status.txt" "SSH status"
run_command "systemsetup -getremoteappleevents" "$OUTPUT_DIR/security-settings/remote-apple-events.txt" "Remote Apple Events"
run_command "sharing -l" "$OUTPUT_DIR/security-settings/sharing-services.txt" "sharing services"

# Time Machine
run_command "tmutil status" "$OUTPUT_DIR/security-settings/time-machine-status.txt" "Time Machine status"

# Software updates
run_command "softwareupdate --list" "$OUTPUT_DIR/security-settings/available-updates.txt" "available software updates"
run_command "defaults read /Library/Preferences/com.apple.SoftwareUpdate AutomaticCheckEnabled" "$OUTPUT_DIR/security-settings/auto-update-check.txt" "automatic update check"
run_command "defaults read /Library/Preferences/com.apple.SoftwareUpdate AutomaticDownload" "$OUTPUT_DIR/security-settings/auto-update-download.txt" "automatic update download"
run_command "defaults read /Library/Preferences/com.apple.commerce AutoUpdate" "$OUTPUT_DIR/security-settings/app-store-auto-update.txt" "App Store automatic updates"

# XProtect and MRT
run_command "system_profiler SPInstallHistoryDataType | grep -A 5 -i xprotect" "$OUTPUT_DIR/security-settings/xprotect-updates.txt" "XProtect updates"
run_command "system_profiler SPInstallHistoryDataType | grep -A 5 -i 'Malware Removal Tool'" "$OUTPUT_DIR/security-settings/mrt-updates.txt" "Malware Removal Tool updates"

# Check for SIP status
run_command "csrutil status" "$OUTPUT_DIR/security-settings/sip-status.txt" "System Integrity Protection status"

# Check for Find My Mac
run_command "defaults read /Library/Preferences/com.apple.FindMyMac.plist" "$OUTPUT_DIR/security-settings/find-my-mac.txt" "Find My Mac status"

#
# User Accounts Collection
#
log_message "Collecting user account information..."

# List of users
run_command "dscl . list /Users | grep -v '^_'" "$OUTPUT_DIR/user-accounts/user-list.txt" "user list"

# User details
run_command "dscacheutil -q user" "$OUTPUT_DIR/user-accounts/user-details.txt" "user details"

# Admin users
run_command "dscl . -read /Groups/admin GroupMembership" "$OUTPUT_DIR/user-accounts/admin-users.txt" "admin users"

# Login items for current user
run_command "osascript -e 'tell application \"System Events\" to get the name of every login item'" "$OUTPUT_DIR/user-accounts/login-items.txt" "login items"

# Sudo users
run_command "cat /etc/sudoers /private/etc/sudoers.d/* 2>/dev/null || echo 'No sudoers files found'" "$OUTPUT_DIR/user-accounts/sudoers.txt" "sudoers configuration"

# Last logins
run_command "last -20" "$OUTPUT_DIR/user-accounts/last-logins.txt" "last logins"

#
# Network Configuration Collection
#
log_message "Collecting network configuration..."

# Network interfaces
run_command "ifconfig" "$OUTPUT_DIR/network-config/interfaces.txt" "network interfaces"

# IP configuration
run_command "ipconfig getpacket en0" "$OUTPUT_DIR/network-config/dhcp-info.txt" "DHCP information"

# Routing table
run_command "netstat -nr" "$OUTPUT_DIR/network-config/routing-table.txt" "routing table"

# DNS configuration
run_command "scutil --dns" "$OUTPUT_DIR/network-config/dns-config.txt" "DNS configuration"

# Active network connections
run_command "lsof -i -P" "$OUTPUT_DIR/network-config/network-connections.txt" "network connections"
run_command "netstat -anp tcp" "$OUTPUT_DIR/network-config/tcp-connections.txt" "TCP connections"
run_command "netstat -anp udp" "$OUTPUT_DIR/network-config/udp-connections.txt" "UDP connections"

# Listening ports
run_command "lsof -i -P | grep LISTEN" "$OUTPUT_DIR/network-config/listening-ports.txt" "listening ports"

# Hosts file
run_command "cat /etc/hosts" "$OUTPUT_DIR/network-config/hosts-file.txt" "hosts file"

# ARP cache
run_command "arp -a" "$OUTPUT_DIR/network-config/arp-cache.txt" "ARP cache"

# Wireless networks
run_command "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport -I" "$OUTPUT_DIR/network-config/wifi-info.txt" "WiFi information"
run_command "defaults read /Library/Preferences/SystemConfiguration/com.apple.airport.preferences" "$OUTPUT_DIR/network-config/wifi-preferred-networks.txt" "preferred WiFi networks"

#
# Applications and Services Collection
#
log_message "Collecting installed applications information..."

# Installed applications
run_command "system_profiler SPApplicationsDataType" "$OUTPUT_DIR/applications/installed-apps.txt" "installed applications"
run_command "ls -la /Applications" "$OUTPUT_DIR/applications/applications-directory.txt" "Applications directory"

# Launch agents and daemons
run_command "ls -la /Library/LaunchAgents/" "$OUTPUT_DIR/applications/launch-agents-system.txt" "system launch agents"
run_command "ls -la /Library/LaunchDaemons/" "$OUTPUT_DIR/applications/launch-daemons-system.txt" "system launch daemons"
run_command "ls -la ~/Library/LaunchAgents/" "$OUTPUT_DIR/applications/launch-agents-user.txt" "user launch agents"

# Startup items
run_command "ls -la /Library/StartupItems/ 2>/dev/null || echo 'No startup items found'" "$OUTPUT_DIR/applications/startup-items.txt" "startup items"

# Browser extensions (Safari)
run_command "ls -la ~/Library/Safari/Extensions/ 2>/dev/null || echo 'No Safari extensions found'" "$OUTPUT_DIR/applications/safari-extensions.txt" "Safari extensions"

# Browser extensions (Chrome)
run_command "ls -la ~/Library/Application\ Support/Google/Chrome/Default/Extensions/ 2>/dev/null || echo 'No Chrome extensions found'" "$OUTPUT_DIR/applications/chrome-extensions.txt" "Chrome extensions"

# Browser extensions (Firefox)
run_command "ls -la ~/Library/Application\ Support/Firefox/Profiles/*/extensions/ 2>/dev/null || echo 'No Firefox extensions found'" "$OUTPUT_DIR/applications/firefox-extensions.txt" "Firefox extensions"

#
# Log Collection
#
log_message "Collecting system logs..."

# System logs
run_command "log show --last 1d --predicate 'eventMessage contains \"error\" or eventMessage contains \"fail\"' --style syslog" "$OUTPUT_DIR/logs/system-errors-24h.txt" "system error logs (24h)"

# Security logs
run_command "log show --last 1d --predicate 'subsystem == \"com.apple.securityd\"' --style syslog" "$OUTPUT_DIR/logs/security-logs-24h.txt" "security logs (24h)"

# Login/logout events
run_command "log show --last 1d --predicate 'eventMessage contains \"login\" or eventMessage contains \"logout\"' --style syslog" "$OUTPUT_DIR/logs/login-events-24h.txt" "login/logout events (24h)"

# Firewall logs
run_command "log show --last 1d --predicate 'subsystem == \"com.apple.alf\"' --style syslog" "$OUTPUT_DIR/logs/firewall-logs-24h.txt" "firewall logs (24h)"

#
# Generate Summary Report
#
log_message "Generating summary report..."

SUMMARY_FILE="$OUTPUT_DIR/audit-summary.txt"

echo "macOS SECURITY AUDIT SUMMARY" > "$SUMMARY_FILE"
echo "===========================" >> "$SUMMARY_FILE"
echo "" >> "$SUMMARY_FILE"
echo "Audit Date: $(date)" >> "$SUMMARY_FILE"
echo "Hostname: $(hostname)" >> "$SUMMARY_FILE"
echo "macOS Version: $(sw_vers -productVersion)" >> "$SUMMARY_FILE"
echo "macOS Build: $(sw_vers -buildVersion)" >> "$SUMMARY_FILE"
echo "" >> "$SUMMARY_FILE"

echo "SECURITY SETTINGS" >> "$SUMMARY_FILE"
echo "-----------------" >> "$SUMMARY_FILE"
echo "FileVault: $(cat "$OUTPUT_DIR/security-settings/filevault-status.txt" | grep -i "FileVault" | head -1)" >> "$SUMMARY_FILE"
echo "Firewall: $([ "$(cat "$OUTPUT_DIR/security-settings/firewall-state.txt")" == "1" ] && echo "Enabled" || echo "Disabled")" >> "$SUMMARY_FILE"
echo "Gatekeeper: $(cat "$OUTPUT_DIR/security-settings/gatekeeper-status.txt")" >> "$SUMMARY_FILE"
echo "System Integrity Protection: $(cat "$OUTPUT_DIR/security-settings/sip-status.txt")" >> "$SUMMARY_FILE"
echo "Remote Login (SSH): $(cat "$OUTPUT_DIR/security-settings/ssh-status.txt")" >> "$SUMMARY_FILE"
echo "" >> "$SUMMARY_FILE"

echo "USER ACCOUNTS" >> "$SUMMARY_FILE"
echo "-------------" >> "$SUMMARY_FILE"
echo "Total Users: $(cat "$OUTPUT_DIR/user-accounts/user-list.txt" | wc -l | xargs)" >> "$SUMMARY_FILE"
echo "Admin Users: $(cat "$OUTPUT_DIR/user-accounts/admin-users.txt" | sed 's/GroupMembership: //g' | wc -w | xargs)" >> "$SUMMARY_FILE"
echo "" >> "$SUMMARY_FILE"

echo "NETWORK" >> "$SUMMARY_FILE"
echo "-------" >> "$SUMMARY_FILE"
echo "Active Interfaces: $(ifconfig | grep -c "^[a-z]")" >> "$SUMMARY_FILE"
echo "Listening Ports: $(cat "$OUTPUT_DIR/network-config/listening-ports.txt" | wc -l | xargs)" >> "$SUMMARY_FILE"
echo "Active Connections: $(cat "$OUTPUT_DIR/network-config/network-connections.txt" | grep -v "LISTEN" | wc -l | xargs)" >> "$SUMMARY_FILE"
echo "" >> "$SUMMARY_FILE"

echo "APPLICATIONS" >> "$SUMMARY_FILE"
echo "------------" >> "$SUMMARY_FILE"
echo "Installed Applications: $(cat "$OUTPUT_DIR/applications/installed-apps.txt" | grep "Location:" | wc -l | xargs)" >> "$SUMMARY_FILE"
echo "Launch Agents (System): $(ls -1 /Library/LaunchAgents/ 2>/dev/null | wc -l | xargs)" >> "$SUMMARY_FILE"
echo "Launch Daemons (System): $(ls -1 /Library/LaunchDaemons/ 2>/dev/null | wc -l | xargs)" >> "$SUMMARY_FILE"
echo "Launch Agents (User): $(ls -1 ~/Library/LaunchAgents/ 2>/dev/null | wc -l | xargs)" >> "$SUMMARY_FILE"
echo "" >> "$SUMMARY_FILE"

echo "LOGS (Last 24h)" >> "$SUMMARY_FILE"
echo "---------------" >> "$SUMMARY_FILE"
echo "System Errors: $(cat "$OUTPUT_DIR/logs/system-errors-24h.txt" | wc -l | xargs)" >> "$SUMMARY_FILE"
echo "Security Events: $(cat "$OUTPUT_DIR/logs/security-logs-24h.txt" | wc -l | xargs)" >> "$SUMMARY_FILE"
echo "Login/Logout Events: $(cat "$OUTPUT_DIR/logs/login-events-24h.txt" | wc -l | xargs)" >> "$SUMMARY_FILE"
echo "Firewall Events: $(cat "$OUTPUT_DIR/logs/firewall-logs-24h.txt" | wc -l | xargs)" >> "$SUMMARY_FILE"

# Create a compressed archive of all collected data
log_message "Creating compressed archive of audit data..."
ARCHIVE_FILE="$OUTPUT_DIR.zip"
(cd "$(dirname "$OUTPUT_DIR")" && zip -r "$(basename "$ARCHIVE_FILE")" "$(basename "$OUTPUT_DIR")")

log_message "Audit complete!"
log_message "Results saved to: $OUTPUT_DIR"
log_message "Archive created: $ARCHIVE_FILE"

# Print summary
echo ""
echo "macOS Security Audit Complete!"
echo "-----------------------------"
echo "Results saved to: $OUTPUT_DIR"
echo "Archive created: $ARCHIVE_FILE"
echo ""
echo "To view the summary report, run:"
echo "cat \"$OUTPUT_DIR/audit-summary.txt\""
echo ""

exit 0
