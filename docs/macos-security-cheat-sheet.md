# macOS Security Command Cheat Sheet

This cheat sheet provides quick reference commands for various security tasks in macOS environments.

## System Information

```bash
# Get basic system information
system_profiler SPSoftwareDataType SPHardwareDataType

# Get macOS version
sw_vers

# List all kernel extensions
kextstat

# Check System Integrity Protection status
csrutil status

# Check if FileVault is enabled
fdesetup status

# Check Gatekeeper status
spctl --status
```

## User Management

```bash
# List all users
dscl . list /Users | grep -v '^_'

# List admin users
dscl . -read /Groups/admin GroupMembership

# Get detailed user information
dscacheutil -q user

# Check login history
last -10

# Check sudo permissions
cat /etc/sudoers
```

## Network Security

```bash
# Show network interfaces and IP addresses
ifconfig

# Show routing table
netstat -nr

# Show active network connections
lsof -i -n -P

# Show listening ports
lsof -i -n -P | grep LISTEN

# Show established connections
lsof -i -n -P | grep ESTABLISHED

# Show DNS configuration
scutil --dns

# Show ARP cache
arp -a

# Show current WiFi information
/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport -I
```

## Firewall Management

```bash
# Check firewall status
defaults read /Library/Preferences/com.apple.alf globalstate

# Enable firewall
sudo defaults write /Library/Preferences/com.apple.alf globalstate -int 1

# Disable firewall
sudo defaults write /Library/Preferences/com.apple.alf globalstate -int 0

# Enable stealth mode
sudo defaults write /Library/Preferences/com.apple.alf stealthenabled -int 1

# Check firewall logging
sudo defaults read /Library/Preferences/com.apple.alf loggingenabled
```

## Process Management

```bash
# List all running processes
ps -axo user,pid,ppid,%cpu,%mem,start,time,command

# List all processes with open network connections
lsof -i -n -P

# List all processes running as root
ps -axo user,pid,ppid,command | grep "^root"

# Kill a process by PID
kill -9 [PID]

# Find processes listening on a specific port
lsof -i :[PORT]
```

## File System Security

```bash
# Show file permissions
ls -la [file/directory]

# Change file permissions
chmod 644 [file]  # -rw-r--r--
chmod 755 [file]  # -rwxr-xr-x
chmod 600 [file]  # -rw-------

# Change file ownership
chown [user]:[group] [file]

# Find all setuid files
sudo find / -perm -4000 -type f -exec ls -la {} \; 2>/dev/null

# Find all world-writable files
sudo find / -perm -2 -type f -exec ls -la {} \; 2>/dev/null

# Find all files modified in the last 24 hours
find / -mtime -1 -type f -exec ls -la {} \; 2>/dev/null
```

## Application Security

```bash
# List all installed applications
system_profiler SPApplicationsDataType

# Check application signature
codesign -vv [path/to/application]

# Check if an application is allowed by Gatekeeper
spctl --assess --verbose [path/to/application]

# List all launch agents and daemons
ls -la /Library/LaunchAgents/
ls -la /Library/LaunchDaemons/
ls -la ~/Library/LaunchAgents/
```

## Log Analysis

```bash
# View system logs (last 1 hour)
log show --last 1h

# View system logs with specific predicate
log show --predicate 'eventMessage contains "error" or eventMessage contains "fail"'

# View security-related logs
log show --predicate 'subsystem == "com.apple.securityd"'

# View authentication logs
log show --predicate 'eventMessage contains "authentication"'

# View firewall logs
log show --predicate 'subsystem == "com.apple.alf"'
```

## Disk and Storage Security

```bash
# Check FileVault status
fdesetup status

# List all volumes
diskutil list

# Get APFS volume information
diskutil apfs list

# Securely erase free space (HFS+ volumes only)
diskutil secureErase freespace 1 /Volumes/[volume_name]

# Create encrypted disk image
hdiutil create -encryption -size 100m -volname "SecureVolume" -fs APFS [path/to/image.dmg]
```

## SSL/TLS Security

```bash
# Check SSL/TLS connection
openssl s_client -connect [hostname]:[port]

# Check certificate expiration
echo | openssl s_client -connect [hostname]:[port] 2>/dev/null | openssl x509 -noout -dates

# Check SSL/TLS protocols supported
openssl s_client -connect [hostname]:[port] -tls1_3
openssl s_client -connect [hostname]:[port] -tls1_2
openssl s_client -connect [hostname]:[port] -tls1_1
openssl s_client -connect [hostname]:[port] -tls1

# Check certificate information
echo | openssl s_client -connect [hostname]:[port] 2>/dev/null | openssl x509 -noout -text
```

## System Hardening

```bash
# Enable automatic updates
sudo defaults write /Library/Preferences/com.apple.SoftwareUpdate AutomaticCheckEnabled -bool true
sudo defaults write /Library/Preferences/com.apple.SoftwareUpdate AutomaticDownload -bool true
sudo defaults write /Library/Preferences/com.apple.commerce AutoUpdate -bool true

# Require password immediately after sleep or screen saver
defaults write com.apple.screensaver askForPassword -int 1
defaults write com.apple.screensaver askForPasswordDelay -int 0

# Disable guest user
sudo defaults write /Library/Preferences/com.apple.loginwindow GuestEnabled -bool false

# Disable remote Apple events
sudo systemsetup -setremoteappleevents off

# Disable remote login (SSH)
sudo systemsetup -setremotelogin off

# Enable firewall and stealth mode
sudo defaults write /Library/Preferences/com.apple.alf globalstate -int 1
sudo defaults write /Library/Preferences/com.apple.alf stealthenabled -int 1
```

## Incident Response

```bash
# Capture system snapshot
sudo tmutil localsnapshot

# Create disk image of a volume
sudo dd if=/dev/disk0s2 of=/path/to/disk_image.dd bs=1m

# Collect system logs
log collect --output /path/to/logs.logarchive

# Capture memory dump (requires third-party tools)
# Example with OSXPmem:
# sudo osxpmem -o /path/to/memory.dump

# List all recently modified files
find / -mtime -1 -type f -exec ls -la {} \; 2>/dev/null
```
