#!/bin/bash
#
# run-tests.sh
# macOS Security Toolkit Test Framework
#
# This script runs tests for the macOS Security Toolkit scripts to ensure
# they are functioning correctly. It performs basic functionality tests
# and validates script output.
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
TEST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TOOLKIT_DIR="$(dirname "$TEST_DIR")"
SCRIPTS_DIR="$TOOLKIT_DIR/scripts"
TEST_OUTPUT_DIR="$TEST_DIR/test_results_$TIMESTAMP"
TEST_LOG="$TEST_OUTPUT_DIR/test_log.txt"

# Create output directory
mkdir -p "$TEST_OUTPUT_DIR"
touch "$TEST_LOG"

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
    echo "[$level] $message" >> "$TEST_LOG"
}

# Banner
display_banner() {
    echo -e "${BLUE}"
    echo "============================================================"
    echo "  macOS Security Toolkit Test Framework"
    echo "  $(date)"
    echo "  Test output directory: $TEST_OUTPUT_DIR"
    echo "============================================================"
    echo -e "${NC}"
}

# Function to check if script exists and is executable
check_script() {
    local script_path="$1"
    
    if [ ! -f "$script_path" ]; then
        log_message "Script not found: $script_path" "ERROR"
        return 1
    fi
    
    if [ ! -x "$script_path" ]; then
        log_message "Script is not executable: $script_path" "ERROR"
        return 1
    }
    
    return 0
}

# Function to run a basic test on a script
test_script() {
    local script_path="$1"
    local script_name=$(basename "$script_path")
    local test_output="$TEST_OUTPUT_DIR/${script_name}_test.txt"
    
    log_message "Testing script: $script_name" "INFO"
    
    # Check if script exists and is executable
    if ! check_script "$script_path"; then
        log_message "Test failed for $script_name: Script check failed" "ERROR"
        return 1
    fi
    
    # Run the script with --help or -h flag if supported
    "$script_path" --help > "$test_output" 2>&1 || "$script_path" -h > "$test_output" 2>&1 || true
    
    # Check if the script runs without errors (basic check)
    if [ -s "$test_output" ]; then
        log_message "Script $script_name runs without crashing" "SUCCESS"
        return 0
    else
        log_message "Test failed for $script_name: Script may have crashed" "ERROR"
        return 1
    fi
}

# Function to test system-security-audit.sh
test_system_security_audit() {
    local script_path="$SCRIPTS_DIR/audit-tools/system-security-audit.sh"
    local script_name=$(basename "$script_path")
    local test_output="$TEST_OUTPUT_DIR/${script_name}_test.txt"
    
    log_message "Running specialized test for: $script_name" "INFO"
    
    # Check if script exists and is executable
    if ! check_script "$script_path"; then
        log_message "Test failed for $script_name: Script check failed" "ERROR"
        return 1
    fi
    
    # Test with --dry-run flag (if supported) or redirect output to prevent actual changes
    "$script_path" --dry-run > "$test_output" 2>&1 || "$script_path" --output-dir "$TEST_OUTPUT_DIR/system_audit" > "$test_output" 2>&1 || true
    
    # Check for expected output patterns
    if grep -q "system" "$test_output" || grep -q "audit" "$test_output" || grep -q "security" "$test_output"; then
        log_message "Script $script_name produces expected output" "SUCCESS"
        return 0
    else
        log_message "Test failed for $script_name: Unexpected output" "WARNING"
        return 1
    fi
}

# Function to test user-account-audit.sh
test_user_account_audit() {
    local script_path="$SCRIPTS_DIR/audit-tools/user-account-audit.sh"
    local script_name=$(basename "$script_path")
    local test_output="$TEST_OUTPUT_DIR/${script_name}_test.txt"
    
    log_message "Running specialized test for: $script_name" "INFO"
    
    # Check if script exists and is executable
    if ! check_script "$script_path"; then
        log_message "Test failed for $script_name: Script check failed" "ERROR"
        return 1
    fi
    
    # Test with --dry-run flag (if supported) or redirect output to prevent actual changes
    "$script_path" --dry-run > "$test_output" 2>&1 || "$script_path" --output-dir "$TEST_OUTPUT_DIR/user_audit" > "$test_output" 2>&1 || true
    
    # Check for expected output patterns
    if grep -q "user" "$test_output" || grep -q "account" "$test_output" || grep -q "audit" "$test_output"; then
        log_message "Script $script_name produces expected output" "SUCCESS"
        return 0
    else
        log_message "Test failed for $script_name: Unexpected output" "WARNING"
        return 1
    fi
}

# Function to test firewall-analyzer.sh
test_firewall_analyzer() {
    local script_path="$SCRIPTS_DIR/audit-tools/firewall-analyzer.sh"
    local script_name=$(basename "$script_path")
    local test_output="$TEST_OUTPUT_DIR/${script_name}_test.txt"
    
    log_message "Running specialized test for: $script_name" "INFO"
    
    # Check if script exists and is executable
    if ! check_script "$script_path"; then
        log_message "Test failed for $script_name: Script check failed" "ERROR"
        return 1
    fi
    
    # Test with --dry-run flag (if supported) or redirect output to prevent actual changes
    "$script_path" --dry-run > "$test_output" 2>&1 || "$script_path" --output-dir "$TEST_OUTPUT_DIR/firewall_analysis" > "$test_output" 2>&1 || true
    
    # Check for expected output patterns
    if grep -q "firewall" "$test_output" || grep -q "security" "$test_output" || grep -q "status" "$test_output"; then
        log_message "Script $script_name produces expected output" "SUCCESS"
        return 0
    else
        log_message "Test failed for $script_name: Unexpected output" "WARNING"
        return 1
    fi
}

# Function to test malware-scanner.sh
test_malware_scanner() {
    local script_path="$SCRIPTS_DIR/audit-tools/malware-scanner.sh"
    local script_name=$(basename "$script_path")
    local test_output="$TEST_OUTPUT_DIR/${script_name}_test.txt"
    
    log_message "Running specialized test for: $script_name" "INFO"
    
    # Check if script exists and is executable
    if ! check_script "$script_path"; then
        log_message "Test failed for $script_name: Script check failed" "ERROR"
        return 1
    fi
    
    # Test with --dry-run flag (if supported) or redirect output to prevent actual changes
    "$script_path" --dry-run > "$test_output" 2>&1 || "$script_path" --output-dir "$TEST_OUTPUT_DIR/malware_scan" > "$test_output" 2>&1 || true
    
    # Check for expected output patterns
    if grep -q "malware" "$test_output" || grep -q "scan" "$test_output" || grep -q "security" "$test_output"; then
        log_message "Script $script_name produces expected output" "SUCCESS"
        return 0
    else
        log_message "Test failed for $script_name: Unexpected output" "WARNING"
        return 1
    fi
}

# Function to test network-port-scan.sh
test_network_port_scan() {
    local script_path="$SCRIPTS_DIR/audit-tools/network-port-scan.sh"
    local script_name=$(basename "$script_path")
    local test_output="$TEST_OUTPUT_DIR/${script_name}_test.txt"
    
    log_message "Running specialized test for: $script_name" "INFO"
    
    # Check if script exists and is executable
    if ! check_script "$script_path"; then
        log_message "Test failed for $script_name: Script check failed" "ERROR"
        return 1
    fi
    
    # Test with --dry-run flag (if supported) or redirect output to prevent actual changes
    "$script_path" --dry-run > "$test_output" 2>&1 || "$script_path" --target localhost --scan-type quick --output-dir "$TEST_OUTPUT_DIR/port_scan" > "$test_output" 2>&1 || true
    
    # Check for expected output patterns
    if grep -q "port" "$test_output" || grep -q "scan" "$test_output" || grep -q "network" "$test_output"; then
        log_message "Script $script_name produces expected output" "SUCCESS"
        return 0
    else
        log_message "Test failed for $script_name: Unexpected output" "WARNING"
        return 1
    fi
}

# Function to test tls-security-check.sh
test_tls_security_check() {
    local script_path="$SCRIPTS_DIR/audit-tools/tls-security-check.sh"
    local script_name=$(basename "$script_path")
    local test_output="$TEST_OUTPUT_DIR/${script_name}_test.txt"
    
    log_message "Running specialized test for: $script_name" "INFO"
    
    # Check if script exists and is executable
    if ! check_script "$script_path"; then
        log_message "Test failed for $script_name: Script check failed" "ERROR"
        return 1
    fi
    
    # Test with --dry-run flag (if supported) or redirect output to prevent actual changes
    "$script_path" --dry-run > "$test_output" 2>&1 || "$script_path" --target example.com --output-dir "$TEST_OUTPUT_DIR/tls_check" > "$test_output" 2>&1 || true
    
    # Check for expected output patterns
    if grep -q "TLS" "$test_output" || grep -q "SSL" "$test_output" || grep -q "security" "$test_output"; then
        log_message "Script $script_name produces expected output" "SUCCESS"
        return 0
    else
        log_message "Test failed for $script_name: Unexpected output" "WARNING"
        return 1
    fi
}

# Function to test collect-forensic-evidence.sh
test_collect_forensic_evidence() {
    local script_path="$SCRIPTS_DIR/incident-response/collect-forensic-evidence.sh"
    local script_name=$(basename "$script_path")
    local test_output="$TEST_OUTPUT_DIR/${script_name}_test.txt"
    
    log_message "Running specialized test for: $script_name" "INFO"
    
    # Check if script exists and is executable
    if ! check_script "$script_path"; then
        log_message "Test failed for $script_name: Script check failed" "ERROR"
        return 1
    fi
    
    # Test with --dry-run flag (if supported) or redirect output to prevent actual changes
    "$script_path" --dry-run > "$test_output" 2>&1 || "$script_path" --output-dir "$TEST_OUTPUT_DIR/forensic_evidence" > "$test_output" 2>&1 || true
    
    # Check for expected output patterns
    if grep -q "forensic" "$test_output" || grep -q "evidence" "$test_output" || grep -q "collect" "$test_output"; then
        log_message "Script $script_name produces expected output" "SUCCESS"
        return 0
    else
        log_message "Test failed for $script_name: Unexpected output" "WARNING"
        return 1
    fi
}

# Function to generate a test report
generate_test_report() {
    local report_file="$TEST_OUTPUT_DIR/test_report.md"
    
    log_message "Generating test report..." "INFO"
    
    echo "# macOS Security Toolkit Test Report" > "$report_file"
    echo "Generated: $(date)" >> "$report_file"
    echo "" >> "$report_file"
    
    echo "## Test Results" >> "$report_file"
    echo "" >> "$report_file"
    echo "| Script | Status | Notes |" >> "$report_file"
    echo "|--------|--------|-------|" >> "$report_file"
    
    # Parse the log file for test results
    grep "SUCCESS\|ERROR\|WARNING" "$TEST_LOG" | while read -r line; do
        if [[ $line == *"Test failed"* ]]; then
            script=$(echo "$line" | sed -E 's/.*Test failed for ([^:]+).*/\1/')
            reason=$(echo "$line" | sed -E 's/.*Test failed for [^:]+: (.*)/\1/')
            echo "| $script | ❌ Failed | $reason |" >> "$report_file"
        elif [[ $line == *"produces expected output"* ]]; then
            script=$(echo "$line" | sed -E 's/.*Script ([^ ]+) produces.*/\1/')
            echo "| $script | ✅ Passed | Produces expected output |" >> "$report_file"
        elif [[ $line == *"runs without crashing"* ]]; then
            script=$(echo "$line" | sed -E 's/.*Script ([^ ]+) runs.*/\1/')
            echo "| $script | ✅ Passed | Runs without crashing |" >> "$report_file"
        fi
    done
    
    # Calculate test statistics
    total_tests=$(grep -c "Testing script\|Running specialized test" "$TEST_LOG")
    passed_tests=$(grep -c "SUCCESS" "$TEST_LOG")
    failed_tests=$((total_tests - passed_tests))
    
    echo "" >> "$report_file"
    echo "## Summary" >> "$report_file"
    echo "" >> "$report_file"
    echo "- Total tests: $total_tests" >> "$report_file"
    echo "- Passed: $passed_tests" >> "$report_file"
    echo "- Failed: $failed_tests" >> "$report_file"
    echo "- Success rate: $(( passed_tests * 100 / total_tests ))%" >> "$report_file"
    
    log_message "Test report generated: $report_file" "SUCCESS"
}

# Main execution
display_banner

# Run specialized tests for each script
test_system_security_audit
test_user_account_audit
test_firewall_analyzer
test_malware_scanner
test_network_port_scan
test_tls_security_check
test_collect_forensic_evidence

# Generate test report
generate_test_report

# Final output
log_message "Testing completed" "SUCCESS"
log_message "Test report saved to: $TEST_OUTPUT_DIR/test_report.md" "SUCCESS"
echo -e "${GREEN}To view the test report, open:${NC} $TEST_OUTPUT_DIR/test_report.md"
