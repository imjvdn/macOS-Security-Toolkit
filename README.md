<div align="center">
  <h1>🛡️ macOS Security Toolkit</h1>
  <p>A comprehensive collection of scripts for security analysis, auditing, and incident response on macOS systems.</p>
  
  [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
  [![GitHub stars](https://img.shields.io/github/stars/imjvdn/macOS-Security-Toolkit?style=social)](https://github.com/imjvdn/macOS-Security-Toolkit/stargazers)
  ![Version](https://img.shields.io/badge/version-1.0.0-blue)
</div>

The macOS Security Toolkit is a collection of security tools designed specifically for macOS environments. It includes scripts for comprehensive system security audits, network port scanning, SSL/TLS configuration checking, and forensic evidence collection with proper chain of custody documentation.

Unlike many security tools that are ported from other platforms, this toolkit is built natively for macOS, leveraging built-in commands and utilities for maximum compatibility and minimal dependencies. Perfect for security professionals, system administrators, and privacy-conscious users who need to assess and improve the security posture of their macOS systems.

## Table of Contents

- [Features](#-features)
- [Quick Start](#-quick-start)
- [How to Use This Toolkit](#-how-to-use-this-toolkit)
  - [Ready-to-Use Security Scripts](#1-ready-to-use-security-scripts)
  - [Advanced Usage](#2-advanced-usage)
- [Documentation](#-documentation)
  - [Security Command References](#security-command-references)
- [Security Scripts](#-security-scripts)
  - [Audit Tools](#audit-tools)
  - [Incident Response Tools](#incident-response-tools)
  - [Reporting Tools](#reporting-tools)
- [Baseline Reporting](#-baseline-reporting)
- [Testing](#-testing)
- [Advanced Usage](#-advanced-usage)
- [Security Commands Reference](#-security-commands-reference)
- [Additional Resources](#-additional-resources)
- [License](#-license)

## 🎯 Features

- **Comprehensive Auditing**: Collect system, user, and network security information on macOS
- **Security Compliance**: Evaluate systems against CIS and NIST benchmarks for macOS
- **Network Security**: Scan ports and evaluate SSL/TLS configurations
- **User Account Security**: Audit user accounts for security issues and policy compliance
- **Firewall Analysis**: Check firewall configurations and blocked connections
- **Malware Scanning**: Detect potential malware and suspicious activity
- **Forensic Collection**: Gather system artifacts with proper chain of custody
- **Easy to Use**: Simple, intuitive scripts for security professionals
- **macOS Native**: Designed specifically for macOS security architecture and tools
- **Universal Compatibility**: Works on both Intel and Apple Silicon (M-series) Macs

## 🚀 Quick Start

```bash
# Clone the repository
git clone https://github.com/imjvdn/macOS-Security-Toolkit.git
cd macOS-Security-Toolkit

# Make scripts executable
chmod +x scripts/**/*.sh

# Run a basic system security audit
./scripts/audit-tools/system-security-audit.sh
```

## 💼 How to Use This Toolkit

This toolkit provides multiple ways to perform security audits and generate reports:

### 1. Ready-to-Use Security Scripts

The easiest way to get started is to use our ready-made security scripts in the `scripts/` directory:

```bash
# Navigate to the scripts directory
cd scripts/audit-tools

# Run a system security audit
./system-security-audit.sh

# Run a network port scan
./network-port-scan.sh --target localhost --scan-type quick

# Check TLS/SSL security
./tls-security-check.sh --target example.com
```

### 2. Advanced Usage

For advanced users who want more control, individual modules can be used separately or combined in custom workflows.

## 📚 Documentation

#### Security Command References
- 🔐 [macOS Security Cheat Sheet](docs/macos-security-cheat-sheet.md): Quick reference for security commands

<details>
<summary>🔍 Script Examples</summary>

### system-security-audit.sh

```bash
./system-security-audit.sh [--output-dir /path/to/output]
```

Performs a comprehensive security audit of the macOS system, collecting information about:
- System configuration and security settings
- User accounts and permissions
- Network settings and connections
- Running processes and services
- Installed applications
- Security settings and policies

#### Output Files

The script creates the following files in the output directory:
- SystemInfo.txt
- SecuritySettings.txt
- UserAccounts.txt
- NetworkConfig.txt
- RunningProcesses.txt
- InstalledApplications.txt

### user-account-audit.sh

```bash
./user-account-audit.sh
```

Performs a comprehensive audit of user accounts on the macOS system, identifying:
- Accounts with admin privileges
- Password policies and expiration settings
- Login history and failed login attempts
- Suspicious accounts (UID 0, empty passwords, non-standard shells)

#### Output Files

The script creates the following files in the output directory:
- user_details.csv: Details of all user accounts
- password_policies.csv: Password policy information
- login_history.txt: Recent login history
- failed_logins.txt: Failed login attempts
- summary.md: Summary report with findings and recommendations

### firewall-analyzer.sh

```bash
./firewall-analyzer.sh
```

Analyzes the macOS firewall configuration, checking:
- Firewall status and settings
- Stealth mode configuration
- Allowed applications
- Blocked connection attempts
- Logging configuration

#### Output Files

The script creates the following files in the output directory:
- firewall_status.md: Current firewall configuration
- allowed_applications.md: Applications allowed through the firewall
- blocked_connections.md: Recent blocked connection attempts
- recommendations.md: Security recommendations
- summary.md: Summary report with security score

### malware-scanner.sh

```bash
./malware-scanner.sh
```

Scans the system for potential malware and suspicious activity:
- Suspicious launch agents and daemons
- Processes with unusual behavior or high resource usage
- Browser extensions that might be malicious
- Suspicious cron jobs
- Unusual network connections

#### Output Files

The script creates the following files in the output directory:
- launch_agents.md: Suspicious launch agents and daemons
- suspicious_processes.md: Processes with unusual behavior
- browser_extensions.md: Installed browser extensions
- cron_jobs.md: Scheduled tasks that might be suspicious
- network_connections.md: Active network connections
- summary.md: Summary report with findings and recommendations

</details>

## 💼 Security Scripts

### Audit Tools

The `scripts/audit-tools/` directory contains scripts for security auditing and assessment:

- **system-security-audit.sh**: Comprehensive system-wide security audit
- **user-account-audit.sh**: Audits user accounts for security issues and policy compliance
- **firewall-analyzer.sh**: Analyzes firewall configuration and provides security recommendations
- **malware-scanner.sh**: Scans for potential malware and suspicious activity
- **network-port-scan.sh**: Native port scanner for network security assessment
- **tls-security-check.sh**: Checks SSL/TLS configurations and certificate security

### Incident Response Tools

- **collect-forensic-evidence.sh**: Gathers system artifacts with proper hashing and chain of custody

### Reporting Tools

The `scripts/reporting-tools/` directory contains tools for generating professional reports from audit data:

- **generate-baseline-report.sh**: Creates comprehensive baseline security reports by running all audit tools
- **format-security-report.sh**: Formats security data into various output formats (Markdown, HTML, JSON, CSV, PDF)

## 📊 Baseline Reporting

The toolkit includes tools to generate comprehensive baseline security reports by running all audit tools and consolidating their outputs:

```bash
# Generate a baseline report in markdown format
./scripts/reporting-tools/generate-baseline-report.sh

# Generate a report in HTML format
./scripts/reporting-tools/generate-baseline-report.sh --format html

# Generate a report in a specific directory
./scripts/reporting-tools/generate-baseline-report.sh --output-dir ~/Desktop/security-reports
```

Reports include:
- Executive summary with security scores
- Key findings and recommendations
- Detailed results from each security tool

For more information, see [scripts/reporting-tools/README.md](scripts/reporting-tools/README.md).

## 🧪 Testing

The toolkit includes a comprehensive test framework to ensure all scripts function correctly.

```bash
# Run the test suite
./tests/run-tests.sh
```

The test framework:
- Verifies that all scripts exist and are executable
- Runs each script with safe test parameters
- Validates script output against expected patterns
- Generates a detailed test report

For more information about the testing process, see [tests/README.md](tests/README.md).

## 🔧 Advanced Usage

<details>
<summary>Advanced Usage Details</summary>

### Custom Scan Options
```bash
# Run a full network port scan
./scripts/audit-tools/network-port-scan.sh --target 192.168.1.0/24 --scan-type full --output-dir ~/Documents/NetworkScan

# Check SSL/TLS security with custom timeout
./scripts/audit-tools/tls-security-check.sh --target secure-website.com --port 443 --timeout 10
```

### Collect Forensic Evidence
```bash
# Collect all available evidence types
./scripts/incident-response/collect-forensic-evidence.sh --output-dir ~/Evidence --collect-all

# Collect specific evidence types
./scripts/incident-response/collect-forensic-evidence.sh --output-dir ~/Evidence --include-system-logs --include-user-profiles
```

### Run as Administrator
For best results, run the toolkit with administrative privileges:
```bash
# Use sudo to run with elevated privileges
sudo ./scripts/audit-tools/system-security-audit.sh
```

</details>

## 🔍 Security Commands Reference

<details>
<summary>Basic System Information Commands</summary>

### View System Information
```bash
# Get basic system information
system_profiler SPSoftwareDataType SPHardwareDataType
```

### Check Uptime
```bash
# Check system uptime
uptime
```
</details>

<details>
<summary>User Management Commands</summary>

### List All Users
```bash
# List all user accounts
dscl . list /Users | grep -v '^_'
```

### View Admin Users
```bash
# List members of the admin group
dscl . -read /Groups/admin GroupMembership
```

### Check Logged In Users
```bash
# See currently logged in users
who
```
</details>

<details>
<summary>Network Commands</summary>

### View Active Connections
```bash
# List active network connections
lsof -i -n -P | grep ESTABLISHED
```

### Check Firewall Status
```bash
# Check macOS firewall status
defaults read /Library/Preferences/com.apple.alf globalstate
```

### Flush DNS Cache
```bash
# Clear DNS cache
sudo dscacheutil -flushcache; sudo killall -HUP mDNSResponder
```
</details>

<details>
<summary>System Inspection Commands</summary>

### List Running Processes
```bash
# View all running processes
ps -axo user,pid,ppid,%cpu,%mem,start,time,command
```

### View Installed Software
```bash
# List installed applications
system_profiler SPApplicationsDataType
```

### Check Launch Agents
```bash
# See what programs run at login
ls -la ~/Library/LaunchAgents /Library/LaunchAgents
```
</details>

## 📦 One-Click Security Check

Run this in Terminal for a quick system check:
```bash
echo "=== SECURITY CHECK ===" && \
echo "\n[+] Users:" && dscl . list /Users | grep -v '^_' && \
echo "\n[+] Admin Users:" && dscl . -read /Groups/admin GroupMembership && \
echo "\n[+] Active Connections:" && lsof -i -n -P | grep ESTABLISHED && \
echo "\n[+] Firewall Status:" && defaults read /Library/Preferences/com.apple.alf globalstate && \
echo "\n[+] System Uptime:" && uptime
```

## 📚 Additional Resources

- [Official Apple Security Documentation](https://support.apple.com/guide/security/welcome/web)
- [CIS macOS Benchmarks](https://www.cisecurity.org/benchmark/apple_os)
- [macOS Security and Privacy Guide](https://github.com/drduh/macOS-Security-and-Privacy-Guide)

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
