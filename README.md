<div align="center">
  <h1>🛡️ macOS Security Toolkit</h1>
  <p>A comprehensive collection of scripts for security analysis, auditing, and incident response on macOS systems.</p>
  
  [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
</div>

## Table of Contents

- [Features](#-features)
- [Quick Start](#-quick-start)
- [How to Use This Toolkit](#-how-to-use-this-toolkit)
  - [Ready-to-Use Security Scripts](#1-ready-to-use-security-scripts)
  - [Advanced Usage](#2-advanced-usage)
- [Documentation](#-documentation)
  - [Security Command References](#security-command-references)
  - [Guides & Tutorials](#guides--tutorials)
- [Security Scripts](#-security-scripts)
  - [Audit Tools](#audit-tools)
  - [Incident Response Tools](#incident-response-tools)
  - [Reporting Tools](#reporting-tools)
- [Testing](#-testing)
- [Security Commands Reference](#-security-commands-reference)
- [Additional Resources](#-additional-resources)
- [License](#-license)

## 🎯 Features

- **Comprehensive Auditing**: Collect system, user, and network security information on macOS
- **Security Compliance**: Evaluate systems against CIS and NIST benchmarks for macOS
- **Interactive Visualizations**: Dynamic dashboards and reports for security analysis
- **Easy to Use**: Simple, intuitive scripts for security professionals
- **Detailed Reporting**: Multiple output formats for analysis and documentation
- **macOS Native**: Designed specifically for macOS security architecture and tools

## 🚀 Quick Start

```bash
# Clone the repository
git clone https://github.com/yourusername/macOS-Security-Toolkit.git
cd macOS-Security-Toolkit

# Make scripts executable
chmod +x scripts/**/*.sh

# Run a basic system security audit
./scripts/audit-tools/system-security-audit.sh
```

## 💻 How to Use This Toolkit

This toolkit provides multiple ways to perform security audits and generate reports:

### 1. Ready-to-Use Security Scripts

The easiest way to get started is to use our ready-made security scripts in the `scripts/` directory:

```bash
# Navigate to the scripts directory
cd scripts

# Run a comprehensive security assessment that combines multiple tools
./complete-security-assessment.sh --target localhost --include-network-scan --include-tls-check

# Or run individual audit tools
cd audit-tools
./system-security-audit.sh
./user-accounts-audit.sh
```

### 2. Advanced Usage

For advanced users who want more control, individual modules can be used separately or combined in custom workflows.

## 📚 Documentation

### Security Command References

The `docs/` directory contains reference guides for common security commands and tools on macOS:

- [macOS Security Cheat Sheet](docs/macos-security-cheat-sheet.md): Quick reference for security commands
- [Security Tools Guide](docs/security-tools-guide.md): Detailed guide to built-in and third-party security tools

### Guides & Tutorials

- [Hardening Guide](docs/hardening-guide.md): Step-by-step guide to harden macOS systems
- [Incident Response Playbook](docs/incident-response-playbook.md): Procedures for responding to security incidents

## 🔒 Security Scripts

### Audit Tools

The `scripts/audit-tools/` directory contains scripts for security auditing and assessment:

- **system-security-audit.sh**: Comprehensive system-wide security audit
- **user-accounts-audit.sh**: Focused audit of user accounts and permissions
- **network-security-audit.sh**: Network configuration and security assessment
- **security-compliance-check.sh**: Evaluates system against CIS and NIST security benchmarks
- **malware-scan.sh**: Scans for indicators of compromise and potential threats
- **network-port-scan.sh**: Native port scanner for network security assessment
- **tls-security-check.sh**: Checks SSL/TLS configurations and certificate security

### Incident Response Tools

- **collect-forensic-evidence.sh**: Gathers system artifacts with proper hashing and chain of custody
- **export-volatile-data.sh**: Captures memory dumps and volatile system state

### Reporting Tools

The `scripts/reporting-tools/` directory contains tools for generating professional reports from audit data:

- **convert-audit-to-html.sh**: Converts audit data to interactive HTML reports
- **generate-executive-summary.sh**: Creates executive-level summary of security findings
- **convert-audit-to-dashboard.sh**: Creates interactive security dashboards from audit data

## 🧪 Testing

To ensure the toolkit works correctly on your system, run the included tests:

```bash
# Run all tests
./run-tests.sh

# Run specific test category
./run-tests.sh --category audit-tools
```

## 🔍 Security Commands Reference

For a quick reference of useful security commands on macOS, see our [Security Commands Cheat Sheet](docs/macos-security-cheat-sheet.md).

## 📖 Additional Resources

- [Official Apple Security Documentation](https://support.apple.com/guide/security/welcome/web)
- [CIS macOS Benchmarks](https://www.cisecurity.org/benchmark/apple_os)
- [macOS Security and Privacy Guide](https://github.com/drduh/macOS-Security-and-Privacy-Guide)

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
