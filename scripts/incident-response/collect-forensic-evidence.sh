#!/bin/bash
#
# collect-forensic-evidence.sh
# macOS Security Toolkit
#
# Collects forensic evidence from a macOS system with proper hashing
# and chain of custody documentation. Gathers system logs, user data,
# system configuration files, and other artifacts relevant for
# forensic investigation.
#
# Usage: ./collect-forensic-evidence.sh [OPTIONS]
#   --output-dir DIR           Directory to save evidence (default: ~/Documents/Forensic-Evidence)
#   --include-user-profiles    Include user profile data collection
#   --include-browser-data     Include browser history and cache data
#   --include-system-logs      Include system log collection
#   --collect-all              Collect all available evidence types
#   --help                     Display this help message
#
# Note: This script should be run with root privileges for complete evidence collection.
#

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "Warning: This script should be run as root for complete evidence collection."
    echo "Some evidence may not be collected due to permission restrictions."
    echo "Run with sudo for best results."
    echo ""
    read -p "Continue anyway? (y/n): " -n 1 -r
    echo ""
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

# Set strict error handling
set -e
set -o pipefail

# Default values
OUTPUT_DIR="$HOME/Documents/Forensic-Evidence-$(date +%Y%m%d-%H%M%S)"
INCLUDE_USER_PROFILES=false
INCLUDE_BROWSER_DATA=false
INCLUDE_SYSTEM_LOGS=false
COLLECT_ALL=false

# Function to display help
show_help() {
    echo "macOS Forensic Evidence Collector"
    echo "Usage: $0 [OPTIONS]"
    echo "Options:"
    echo "  --output-dir DIR           Directory to save evidence (default: ~/Documents/Forensic-Evidence)"
    echo "  --include-user-profiles    Include user profile data collection"
    echo "  --include-browser-data     Include browser history and cache data"
    echo "  --include-system-logs      Include system log collection"
    echo "  --collect-all              Collect all available evidence types"
    echo "  --help                     Display this help message"
    echo ""
    echo "Note: This script should be run with root privileges for complete evidence collection."
    exit 0
}

# Process command line arguments
while [[ $# -gt 0 ]]; do
    key="$1"
    case $key in
        --output-dir)
            OUTPUT_DIR="$2"
            shift
            shift
            ;;
        --include-user-profiles)
            INCLUDE_USER_PROFILES=true
            shift
            ;;
        --include-browser-data)
            INCLUDE_BROWSER_DATA=true
            shift
            ;;
        --include-system-logs)
            INCLUDE_SYSTEM_LOGS=true
            shift
            ;;
        --collect-all)
            COLLECT_ALL=true
            INCLUDE_USER_PROFILES=true
            INCLUDE_BROWSER_DATA=true
            INCLUDE_SYSTEM_LOGS=true
            shift
            ;;
        --help)
            show_help
            ;;
        *)
            echo "Unknown option: $1"
            echo "Use --help for usage information."
            exit 1
            ;;
    esac
done

# Initialize variables
START_TIME=$(date)
HOSTNAME=$(hostname)
EVIDENCE_DIR="${OUTPUT_DIR}/${HOSTNAME}-evidence-$(date +%Y%m%d-%H%M%S)"
CHAIN_OF_CUSTODY_FILE="${EVIDENCE_DIR}/ChainOfCustody.txt"
LOG_FILE="${EVIDENCE_DIR}/Collection.log"

# Create evidence directory
initialize_evidence_collection() {
    mkdir -p "${EVIDENCE_DIR}"
    mkdir -p "${EVIDENCE_DIR}/System"
    mkdir -p "${EVIDENCE_DIR}/Network"
    mkdir -p "${EVIDENCE_DIR}/Users"
    mkdir -p "${EVIDENCE_DIR}/Applications"
    mkdir -p "${EVIDENCE_DIR}/Logs"
    
    # Initialize chain of custody document
    cat > "${CHAIN_OF_CUSTODY_FILE}" << EOF
CHAIN OF CUSTODY DOCUMENT
=========================
Evidence Collection ID: ${HOSTNAME}-$(date +%Y%m%d-%H%M%S)
System: ${HOSTNAME}
Collection Start: ${START_TIME}
Collected by: $(whoami)
Collection Tool: macOS Security Toolkit - collect-forensic-evidence.sh

EVIDENCE ITEMS
=========================

EOF
    
    # Initialize log file
    echo "$(date +"%Y-%m-%d %H:%M:%S") - Starting forensic evidence collection on ${HOSTNAME}" > "${LOG_FILE}"
}

# Function to log messages
log_message() {
    local timestamp=$(date +"%Y-%m-%d %H:%M:%S")
    local level="${2:-INFO}"
    
    echo "[${timestamp}] [${level}] $1" | tee -a "${LOG_FILE}"
}

# Function to compute file hash
get_evidence_hash() {
    local file_path="$1"
    
    if [ -f "${file_path}" ]; then
        shasum -a 256 "${file_path}" | cut -d ' ' -f 1
    else
        echo "HASH_COMPUTATION_FAILED_FILE_NOT_FOUND"
    fi
}

# Function to document evidence item
add_evidence_item() {
    local description="$1"
    local path="$2"
    local hash="$3"
    
    cat >> "${CHAIN_OF_CUSTODY_FILE}" << EOF
Item: ${description}
Path: ${path}
Acquired: $(date +"%Y-%m-%d %H:%M:%S")
SHA256: ${hash}
-------------------------------------------------

EOF
}

# Function to collect system information
collect_system_info() {
    local system_dir="${EVIDENCE_DIR}/System"
    
    log_message "Collecting system information..."
    
    # Basic system info
    system_profiler SPSoftwareDataType SPHardwareDataType > "${system_dir}/SystemInfo.txt"
    local hash=$(get_evidence_hash "${system_dir}/SystemInfo.txt")
    add_evidence_item "System Information" "${system_dir}/SystemInfo.txt" "${hash}"
    
    # Running processes
    ps -axo user,pid,ppid,%cpu,%mem,start,time,command > "${system_dir}/RunningProcesses.txt"
    hash=$(get_evidence_hash "${system_dir}/RunningProcesses.txt")
    add_evidence_item "Running Processes" "${system_dir}/RunningProcesses.txt" "${hash}"
    
    # Loaded kernel extensions
    kextstat > "${system_dir}/LoadedKexts.txt"
    hash=$(get_evidence_hash "${system_dir}/LoadedKexts.txt")
    add_evidence_item "Loaded Kernel Extensions" "${system_dir}/LoadedKexts.txt" "${hash}"
    
    # Launch agents and daemons
    mkdir -p "${system_dir}/LaunchAgents"
    mkdir -p "${system_dir}/LaunchDaemons"
    
    # System launch agents
    if [ -d "/Library/LaunchAgents" ]; then
        cp -R /Library/LaunchAgents/* "${system_dir}/LaunchAgents/" 2>/dev/null || true
        ls -la /Library/LaunchAgents > "${system_dir}/LaunchAgents/directory_listing.txt"
        hash=$(get_evidence_hash "${system_dir}/LaunchAgents/directory_listing.txt")
        add_evidence_item "System Launch Agents" "${system_dir}/LaunchAgents/directory_listing.txt" "${hash}"
    fi
    
    # System launch daemons
    if [ -d "/Library/LaunchDaemons" ]; then
        cp -R /Library/LaunchDaemons/* "${system_dir}/LaunchDaemons/" 2>/dev/null || true
        ls -la /Library/LaunchDaemons > "${system_dir}/LaunchDaemons/directory_listing.txt"
        hash=$(get_evidence_hash "${system_dir}/LaunchDaemons/directory_listing.txt")
        add_evidence_item "System Launch Daemons" "${system_dir}/LaunchDaemons/directory_listing.txt" "${hash}"
    fi
    
    # Installed software
    system_profiler SPApplicationsDataType > "${system_dir}/InstalledApplications.txt"
    hash=$(get_evidence_hash "${system_dir}/InstalledApplications.txt")
    add_evidence_item "Installed Applications" "${system_dir}/InstalledApplications.txt" "${hash}"
    
    # System configuration
    mkdir -p "${system_dir}/Configuration"
    
    # Network configuration
    ifconfig > "${system_dir}/Configuration/NetworkInterfaces.txt"
    hash=$(get_evidence_hash "${system_dir}/Configuration/NetworkInterfaces.txt")
    add_evidence_item "Network Interfaces" "${system_dir}/Configuration/NetworkInterfaces.txt" "${hash}"
    
    # DNS configuration
    scutil --dns > "${system_dir}/Configuration/DNSConfiguration.txt"
    hash=$(get_evidence_hash "${system_dir}/Configuration/DNSConfiguration.txt")
    add_evidence_item "DNS Configuration" "${system_dir}/Configuration/DNSConfiguration.txt" "${hash}"
    
    # Hosts file
    cp /etc/hosts "${system_dir}/Configuration/hosts"
    hash=$(get_evidence_hash "${system_dir}/Configuration/hosts")
    add_evidence_item "Hosts File" "${system_dir}/Configuration/hosts" "${hash}"
    
    # Security settings
    mkdir -p "${system_dir}/Security"
    
    # FileVault status
    fdesetup status > "${system_dir}/Security/FileVaultStatus.txt" 2>&1
    hash=$(get_evidence_hash "${system_dir}/Security/FileVaultStatus.txt")
    add_evidence_item "FileVault Status" "${system_dir}/Security/FileVaultStatus.txt" "${hash}"
    
    # Firewall status
    defaults read /Library/Preferences/com.apple.alf globalstate > "${system_dir}/Security/FirewallStatus.txt" 2>&1
    hash=$(get_evidence_hash "${system_dir}/Security/FirewallStatus.txt")
    add_evidence_item "Firewall Status" "${system_dir}/Security/FirewallStatus.txt" "${hash}"
    
    # SIP status
    csrutil status > "${system_dir}/Security/SIPStatus.txt" 2>&1
    hash=$(get_evidence_hash "${system_dir}/Security/SIPStatus.txt")
    add_evidence_item "System Integrity Protection Status" "${system_dir}/Security/SIPStatus.txt" "${hash}"
    
    log_message "System information collection complete" "SUCCESS"
}

# Function to collect network information
collect_network_info() {
    local network_dir="${EVIDENCE_DIR}/Network"
    
    log_message "Collecting network information..."
    
    # Active network connections
    lsof -i -n -P > "${network_dir}/NetworkConnections.txt"
    local hash=$(get_evidence_hash "${network_dir}/NetworkConnections.txt")
    add_evidence_item "Network Connections" "${network_dir}/NetworkConnections.txt" "${hash}"
    
    # Routing table
    netstat -nr > "${network_dir}/RoutingTable.txt"
    hash=$(get_evidence_hash "${network_dir}/RoutingTable.txt")
    add_evidence_item "Routing Table" "${network_dir}/RoutingTable.txt" "${hash}"
    
    # ARP cache
    arp -a > "${network_dir}/ARPCache.txt"
    hash=$(get_evidence_hash "${network_dir}/ARPCache.txt")
    add_evidence_item "ARP Cache" "${network_dir}/ARPCache.txt" "${hash}"
    
    # Network sharing
    sharing -l > "${network_dir}/SharingServices.txt"
    hash=$(get_evidence_hash "${network_dir}/SharingServices.txt")
    add_evidence_item "Sharing Services" "${network_dir}/SharingServices.txt" "${hash}"
    
    # WiFi information
    mkdir -p "${network_dir}/WiFi"
    
    # Current WiFi info
    /System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport -I > "${network_dir}/WiFi/CurrentConnection.txt" 2>&1
    hash=$(get_evidence_hash "${network_dir}/WiFi/CurrentConnection.txt")
    add_evidence_item "Current WiFi Connection" "${network_dir}/WiFi/CurrentConnection.txt" "${hash}"
    
    # Preferred networks
    defaults read /Library/Preferences/SystemConfiguration/com.apple.airport.preferences > "${network_dir}/WiFi/PreferredNetworks.txt" 2>&1
    hash=$(get_evidence_hash "${network_dir}/WiFi/PreferredNetworks.txt")
    add_evidence_item "Preferred WiFi Networks" "${network_dir}/WiFi/PreferredNetworks.txt" "${hash}"
    
    log_message "Network information collection complete" "SUCCESS"
}

# Function to collect user account information
collect_user_accounts() {
    local users_dir="${EVIDENCE_DIR}/Users"
    
    log_message "Collecting user account information..."
    
    # List of users
    dscl . list /Users | grep -v "^_" > "${users_dir}/UserList.txt"
    local hash=$(get_evidence_hash "${users_dir}/UserList.txt")
    add_evidence_item "User List" "${users_dir}/UserList.txt" "${hash}"
    
    # User details
    dscacheutil -q user > "${users_dir}/UserDetails.txt"
    hash=$(get_evidence_hash "${users_dir}/UserDetails.txt")
    add_evidence_item "User Details" "${users_dir}/UserDetails.txt" "${hash}"
    
    # Admin users
    dscl . -read /Groups/admin GroupMembership > "${users_dir}/AdminUsers.txt"
    hash=$(get_evidence_hash "${users_dir}/AdminUsers.txt")
    add_evidence_item "Admin Users" "${users_dir}/AdminUsers.txt" "${hash}"
    
    # Last logins
    last -20 > "${users_dir}/LastLogins.txt"
    hash=$(get_evidence_hash "${users_dir}/LastLogins.txt")
    add_evidence_item "Last Logins" "${users_dir}/LastLogins.txt" "${hash}"
    
    # Collect user profiles if requested
    if [ "${INCLUDE_USER_PROFILES}" = true ] || [ "${COLLECT_ALL}" = true ]; then
        collect_user_profiles
    fi
    
    log_message "User account information collection complete" "SUCCESS"
}

# Function to collect user profiles
collect_user_profiles() {
    local users_dir="${EVIDENCE_DIR}/Users"
    
    log_message "Collecting user profile data..."
    
    # Get list of user home directories
    local user_homes=$(ls -d /Users/* 2>/dev/null)
    
    for user_home in $user_homes; do
        local username=$(basename "${user_home}")
        
        # Skip system users
        if [[ "${username}" == "Shared" || "${username}" == "Guest" ]]; then
            continue
        fi
        
        log_message "Processing user profile: ${username}"
        
        local user_dir="${users_dir}/${username}"
        mkdir -p "${user_dir}"
        
        # Collect interesting files and folders
        
        # Shell history
        if [ -f "${user_home}/.bash_history" ]; then
            cp "${user_home}/.bash_history" "${user_dir}/bash_history.txt"
            hash=$(get_evidence_hash "${user_dir}/bash_history.txt")
            add_evidence_item "User ${username} - Bash History" "${user_dir}/bash_history.txt" "${hash}"
        fi
        
        if [ -f "${user_home}/.zsh_history" ]; then
            cp "${user_home}/.zsh_history" "${user_dir}/zsh_history.txt"
            hash=$(get_evidence_hash "${user_dir}/zsh_history.txt")
            add_evidence_item "User ${username} - Zsh History" "${user_dir}/zsh_history.txt" "${hash}"
        fi
        
        # SSH keys and config
        if [ -d "${user_home}/.ssh" ]; then
            mkdir -p "${user_dir}/ssh"
            cp -R "${user_home}/.ssh" "${user_dir}/"
            ls -la "${user_home}/.ssh" > "${user_dir}/ssh/directory_listing.txt"
            hash=$(get_evidence_hash "${user_dir}/ssh/directory_listing.txt")
            add_evidence_item "User ${username} - SSH Directory" "${user_dir}/ssh/directory_listing.txt" "${hash}"
        fi
        
        # User launch agents
        if [ -d "${user_home}/Library/LaunchAgents" ]; then
            mkdir -p "${user_dir}/LaunchAgents"
            cp -R "${user_home}/Library/LaunchAgents" "${user_dir}/"
            ls -la "${user_home}/Library/LaunchAgents" > "${user_dir}/LaunchAgents/directory_listing.txt"
            hash=$(get_evidence_hash "${user_dir}/LaunchAgents/directory_listing.txt")
            add_evidence_item "User ${username} - Launch Agents" "${user_dir}/LaunchAgents/directory_listing.txt" "${hash}"
        fi
        
        # Recent items
        if [ -d "${user_home}/Library/Recent Items" ]; then
            mkdir -p "${user_dir}/RecentItems"
            ls -la "${user_home}/Library/Recent Items" > "${user_dir}/RecentItems/directory_listing.txt"
            hash=$(get_evidence_hash "${user_dir}/RecentItems/directory_listing.txt")
            add_evidence_item "User ${username} - Recent Items" "${user_dir}/RecentItems/directory_listing.txt" "${hash}"
        fi
        
        # Downloads folder
        if [ -d "${user_home}/Downloads" ]; then
            ls -la "${user_home}/Downloads" > "${user_dir}/Downloads_listing.txt"
            hash=$(get_evidence_hash "${user_dir}/Downloads_listing.txt")
            add_evidence_item "User ${username} - Downloads Folder" "${user_dir}/Downloads_listing.txt" "${hash}"
        fi
        
        # Collect browser data if requested
        if [ "${INCLUDE_BROWSER_DATA}" = true ] || [ "${COLLECT_ALL}" = true ]; then
            collect_browser_data "${user_home}" "${user_dir}" "${username}"
        fi
    done
    
    log_message "User profile collection complete" "SUCCESS"
}

# Function to collect browser data
collect_browser_data() {
    local user_home="$1"
    local user_dir="$2"
    local username="$3"
    
    log_message "Collecting browser data for user: ${username}"
    
    # Create browser data directory
    local browser_dir="${user_dir}/BrowserData"
    mkdir -p "${browser_dir}"
    
    # Safari
    if [ -d "${user_home}/Library/Safari" ]; then
        local safari_dir="${browser_dir}/Safari"
        mkdir -p "${safari_dir}"
        
        # History
        if [ -f "${user_home}/Library/Safari/History.db" ]; then
            cp "${user_home}/Library/Safari/History.db" "${safari_dir}/"
            hash=$(get_evidence_hash "${safari_dir}/History.db")
            add_evidence_item "User ${username} - Safari History" "${safari_dir}/History.db" "${hash}"
        fi
        
        # Bookmarks
        if [ -f "${user_home}/Library/Safari/Bookmarks.plist" ]; then
            cp "${user_home}/Library/Safari/Bookmarks.plist" "${safari_dir}/"
            hash=$(get_evidence_hash "${safari_dir}/Bookmarks.plist")
            add_evidence_item "User ${username} - Safari Bookmarks" "${safari_dir}/Bookmarks.plist" "${hash}"
        fi
        
        # Downloads
        if [ -f "${user_home}/Library/Safari/Downloads.plist" ]; then
            cp "${user_home}/Library/Safari/Downloads.plist" "${safari_dir}/"
            hash=$(get_evidence_hash "${safari_dir}/Downloads.plist")
            add_evidence_item "User ${username} - Safari Downloads" "${safari_dir}/Downloads.plist" "${hash}"
        fi
        
        # Extensions
        if [ -d "${user_home}/Library/Safari/Extensions" ]; then
            ls -la "${user_home}/Library/Safari/Extensions" > "${safari_dir}/Extensions_listing.txt"
            hash=$(get_evidence_hash "${safari_dir}/Extensions_listing.txt")
            add_evidence_item "User ${username} - Safari Extensions" "${safari_dir}/Extensions_listing.txt" "${hash}"
        fi
    fi
    
    # Chrome
    if [ -d "${user_home}/Library/Application Support/Google/Chrome" ]; then
        local chrome_dir="${browser_dir}/Chrome"
        mkdir -p "${chrome_dir}"
        
        # Default profile
        if [ -d "${user_home}/Library/Application Support/Google/Chrome/Default" ]; then
            local chrome_profile="${user_home}/Library/Application Support/Google/Chrome/Default"
            
            # History
            if [ -f "${chrome_profile}/History" ]; then
                cp "${chrome_profile}/History" "${chrome_dir}/"
                hash=$(get_evidence_hash "${chrome_dir}/History")
                add_evidence_item "User ${username} - Chrome History" "${chrome_dir}/History" "${hash}"
            fi
            
            # Bookmarks
            if [ -f "${chrome_profile}/Bookmarks" ]; then
                cp "${chrome_profile}/Bookmarks" "${chrome_dir}/"
                hash=$(get_evidence_hash "${chrome_dir}/Bookmarks")
                add_evidence_item "User ${username} - Chrome Bookmarks" "${chrome_dir}/Bookmarks" "${hash}"
            fi
            
            # Downloads
            if [ -f "${chrome_profile}/History" ]; then
                # Downloads are in the History database
                cp "${chrome_profile}/History" "${chrome_dir}/Downloads"
                hash=$(get_evidence_hash "${chrome_dir}/Downloads")
                add_evidence_item "User ${username} - Chrome Downloads" "${chrome_dir}/Downloads" "${hash}"
            fi
            
            # Extensions
            if [ -d "${chrome_profile}/Extensions" ]; then
                ls -la "${chrome_profile}/Extensions" > "${chrome_dir}/Extensions_listing.txt"
                hash=$(get_evidence_hash "${chrome_dir}/Extensions_listing.txt")
                add_evidence_item "User ${username} - Chrome Extensions" "${chrome_dir}/Extensions_listing.txt" "${hash}"
            fi
        fi
    fi
    
    # Firefox
    if [ -d "${user_home}/Library/Application Support/Firefox" ]; then
        local firefox_dir="${browser_dir}/Firefox"
        mkdir -p "${firefox_dir}"
        
        # Find profile directories
        if [ -d "${user_home}/Library/Application Support/Firefox/Profiles" ]; then
            local profiles_dir="${user_home}/Library/Application Support/Firefox/Profiles"
            
            # List profiles
            ls -la "${profiles_dir}" > "${firefox_dir}/Profiles_listing.txt"
            hash=$(get_evidence_hash "${firefox_dir}/Profiles_listing.txt")
            add_evidence_item "User ${username} - Firefox Profiles" "${firefox_dir}/Profiles_listing.txt" "${hash}"
            
            # Process each profile
            for profile in "${profiles_dir}"/*; do
                if [ -d "${profile}" ]; then
                    local profile_name=$(basename "${profile}")
                    local profile_dir="${firefox_dir}/${profile_name}"
                    mkdir -p "${profile_dir}"
                    
                    # History (places.sqlite contains history and bookmarks)
                    if [ -f "${profile}/places.sqlite" ]; then
                        cp "${profile}/places.sqlite" "${profile_dir}/"
                        hash=$(get_evidence_hash "${profile_dir}/places.sqlite")
                        add_evidence_item "User ${username} - Firefox History/Bookmarks (${profile_name})" "${profile_dir}/places.sqlite" "${hash}"
                    fi
                    
                    # Downloads
                    if [ -f "${profile}/downloads.sqlite" ]; then
                        cp "${profile}/downloads.sqlite" "${profile_dir}/"
                        hash=$(get_evidence_hash "${profile_dir}/downloads.sqlite")
                        add_evidence_item "User ${username} - Firefox Downloads (${profile_name})" "${profile_dir}/downloads.sqlite" "${hash}"
                    fi
                    
                    # Extensions
                    if [ -d "${profile}/extensions" ]; then
                        ls -la "${profile}/extensions" > "${profile_dir}/Extensions_listing.txt"
                        hash=$(get_evidence_hash "${profile_dir}/Extensions_listing.txt")
                        add_evidence_item "User ${username} - Firefox Extensions (${profile_name})" "${profile_dir}/Extensions_listing.txt" "${hash}"
                    fi
                fi
            done
        fi
    fi
    
    log_message "Browser data collection for user ${username} complete" "SUCCESS"
}

# Function to collect system logs
collect_system_logs() {
    if [ "${INCLUDE_SYSTEM_LOGS}" = false ] && [ "${COLLECT_ALL}" = false ]; then
        log_message "Skipping system log collection as requested"
        return
    fi
    
    local logs_dir="${EVIDENCE_DIR}/Logs"
    
    log_message "Collecting system logs..."
    
    # System logs using log command (unified logging)
    log show --last 24h --style syslog > "${logs_dir}/system_last_24h.log"
    local hash=$(get_evidence_hash "${logs_dir}/system_last_24h.log")
    add_evidence_item "System Logs (Last 24h)" "${logs_dir}/system_last_24h.log" "${hash}"
    
    # Security logs
    log show --last 24h --predicate 'subsystem == "com.apple.securityd"' --style syslog > "${logs_dir}/security_last_24h.log"
    hash=$(get_evidence_hash "${logs_dir}/security_last_24h.log")
    add_evidence_item "Security Logs (Last 24h)" "${logs_dir}/security_last_24h.log" "${hash}"
    
    # Authentication logs
    log show --last 24h --predicate 'eventMessage contains "authentication" or eventMessage contains "login" or eventMessage contains "logout"' --style syslog > "${logs_dir}/auth_last_24h.log"
    hash=$(get_evidence_hash "${logs_dir}/auth_last_24h.log")
    add_evidence_item "Authentication Logs (Last 24h)" "${logs_dir}/auth_last_24h.log" "${hash}"
    
    # Firewall logs
    log show --last 24h --predicate 'subsystem == "com.apple.alf"' --style syslog > "${logs_dir}/firewall_last_24h.log"
    hash=$(get_evidence_hash "${logs_dir}/firewall_last_24h.log")
    add_evidence_item "Firewall Logs (Last 24h)" "${logs_dir}/firewall_last_24h.log" "${hash}"
    
    # Traditional system logs if they exist
    if [ -d "/var/log" ]; then
        mkdir -p "${logs_dir}/var_logs"
        
        # Copy important log files
        for log_file in system.log install.log wifi.log; do
            if [ -f "/var/log/${log_file}" ]; then
                cp "/var/log/${log_file}" "${logs_dir}/var_logs/"
                hash=$(get_evidence_hash "${logs_dir}/var_logs/${log_file}")
                add_evidence_item "Log File: ${log_file}" "${logs_dir}/var_logs/${log_file}" "${hash}"
            fi
        done
        
        # List all log files
        ls -la /var/log > "${logs_dir}/var_logs/directory_listing.txt"
        hash=$(get_evidence_hash "${logs_dir}/var_logs/directory_listing.txt")
        add_evidence_item "Log Directory Listing" "${logs_dir}/var_logs/directory_listing.txt" "${hash}"
    fi
    
    log_message "System log collection complete" "SUCCESS"
}

# Function to create final evidence package
complete_evidence_collection() {
    # Finalize chain of custody document
    local end_time=$(date)
    local duration=$(($(date +%s) - $(date -j -f "%a %b %d %T %Z %Y" "${START_TIME}" +%s)))
    local hours=$((duration / 3600))
    local minutes=$(((duration % 3600) / 60))
    local seconds=$((duration % 60))
    
    cat >> "${CHAIN_OF_CUSTODY_FILE}" << EOF

COLLECTION SUMMARY
=========================
Collection End: ${end_time}
Total Duration: ${hours} hours, ${minutes} minutes, ${seconds} seconds
Evidence Package Hash: 

EOF
    
    # Create evidence ZIP archive
    local evidence_zip="${EVIDENCE_DIR}.zip"
    log_message "Creating evidence package: ${evidence_zip}"
    
    (cd "$(dirname "${EVIDENCE_DIR}")" && zip -r "$(basename "${evidence_zip}")" "$(basename "${EVIDENCE_DIR}")")
    
    # Calculate package hash
    local package_hash=$(get_evidence_hash "${evidence_zip}")
    
    # Update chain of custody with package hash
    sed -i '' "s/Evidence Package Hash: /Evidence Package Hash: ${package_hash}/" "${CHAIN_OF_CUSTODY_FILE}"
    
    # Update the archive with the updated chain of custody file
    (cd "$(dirname "${EVIDENCE_DIR}")" && zip -u "$(basename "${evidence_zip}")" "$(basename "${EVIDENCE_DIR}")/ChainOfCustody.txt")
    
    log_message "Evidence collection complete. Package saved to: ${evidence_zip}" "SUCCESS"
    log_message "Evidence package SHA256: ${package_hash}" "SUCCESS"
    
    echo "${evidence_zip}"
}

# Main execution
main() {
    # Initialize evidence collection
    initialize_evidence_collection
    
    # Collect system information (always collected)
    collect_system_info
    
    # Collect network information (always collected)
    collect_network_info
    
    # Collect user account information (always collected)
    collect_user_accounts
    
    # Collect system logs if requested
    collect_system_logs
    
    # Create final evidence package
    local evidence_package=$(complete_evidence_collection)
    
    if [ -n "${evidence_package}" ]; then
        echo ""
        echo "Forensic evidence collection complete!"
        echo "Evidence package: ${evidence_package}"
        echo ""
    else
        echo ""
        echo "Forensic evidence collection completed with errors. Check the log file for details."
        echo ""
    fi
}

# Run main function
main
