#!/bin/bash
#
# generate-baseline-report.sh
# Part of macOS Security Toolkit
#
# Generates a comprehensive baseline security report by running
# all audit tools and consolidating their outputs into a single report.
#
# Usage: ./generate-baseline-report.sh [--output-dir /path/to/dir] [--format html|md|txt|json|csv|pdf]

# Set default values
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TOOLKIT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
AUDIT_TOOLS_DIR="$TOOLKIT_ROOT/scripts/audit-tools"
OUTPUT_DIR="$TOOLKIT_ROOT/reports/$(date +%Y-%m-%d_%H-%M-%S)"
FORMAT="md"
TIMESTAMP=$(date +"%Y-%m-%d %H:%M:%S")
HOSTNAME=$(hostname)
OS_VERSION=$(sw_vers -productVersion)
ARCH=$(uname -m)

# Parse command line arguments
while [[ "$#" -gt 0 ]]; do
    case $1 in
        --output-dir)
            OUTPUT_DIR="$2"
            shift 2
            ;;
        --format)
            FORMAT="$2"
            shift 2
            ;;
        --help)
            echo "Usage: $0 [--output-dir /path/to/dir] [--format html|md|txt|json|csv|pdf]"
            exit 0
            ;;
        *)
            echo "Unknown parameter: $1"
            echo "Usage: $0 [--output-dir /path/to/dir] [--format html|md|txt|json|csv|pdf]"
            exit 1
            ;;
    esac
done

# Create output directory if it doesn't exist
mkdir -p "$OUTPUT_DIR"
echo "Output directory: $OUTPUT_DIR"

# Create a temporary directory for individual tool outputs
TEMP_DIR="$OUTPUT_DIR/temp"
mkdir -p "$TEMP_DIR"

# Function to run a script and capture its output
run_script() {
    local script="$1"
    local output_dir="$2"
    local script_name=$(basename "$script" .sh)
    
    echo "Running $script_name..."
    
    # Create script-specific output directory
    mkdir -p "$output_dir/$script_name"
    
    # Run the script with output directory parameter
    "$script" --output-dir "$output_dir/$script_name" > "$output_dir/$script_name.log" 2>&1
    
    # Return the exit code of the script
    return $?
}

# Function to extract security scores from script outputs
extract_security_score() {
    local script_output_dir="$1"
    local script_name=$(basename "$script_output_dir")
    
    # Look for summary.md or similar files that might contain scores
    if [[ -f "$script_output_dir/summary.md" ]]; then
        # Extract score (assuming format like "Security Score: 85/100")
        local score=$(grep -i "security score" "$script_output_dir/summary.md" | grep -o '[0-9]\+/[0-9]\+' | head -1)
        if [[ -n "$score" ]]; then
            echo "$score"
        else
            echo "N/A"
        fi
    else
        echo "N/A"
    fi
}

# Function to extract key findings
extract_key_findings() {
    local script_output_dir="$1"
    local script_name=$(basename "$script_output_dir")
    local findings_file="$TEMP_DIR/${script_name}_findings.txt"
    
    # Look for findings in various output files
    if [[ -f "$script_output_dir/summary.md" ]]; then
        grep -A 10 -i "findings\|issues\|vulnerabilities\|recommendations" "$script_output_dir/summary.md" > "$findings_file"
    elif [[ -f "$script_output_dir/recommendations.md" ]]; then
        cat "$script_output_dir/recommendations.md" > "$findings_file"
    else
        # Try to find any markdown or text files that might contain findings
        find "$script_output_dir" -name "*.md" -o -name "*.txt" | xargs grep -l -i "findings\|issues\|vulnerabilities\|recommendations" | 
        while read file; do
            grep -A 5 -i "findings\|issues\|vulnerabilities\|recommendations" "$file" >> "$findings_file"
        done
    fi
    
    # If we found findings, return the file path, otherwise return empty
    if [[ -s "$findings_file" ]]; then
        echo "$findings_file"
    else
        echo ""
    fi
}

# Run all audit tools and collect their outputs
echo "Starting baseline security assessment at $TIMESTAMP"
echo "Host: $HOSTNAME"
echo "macOS Version: $OS_VERSION"
echo "Architecture: $ARCH"
echo "-------------------------------------------"

# Array of audit scripts to run
AUDIT_SCRIPTS=(
    "$AUDIT_TOOLS_DIR/system-security-audit.sh"
    "$AUDIT_TOOLS_DIR/user-account-audit.sh"
    "$AUDIT_TOOLS_DIR/firewall-analyzer.sh"
    "$AUDIT_TOOLS_DIR/malware-scanner.sh"
    "$AUDIT_TOOLS_DIR/network-port-scan.sh"
    "$AUDIT_TOOLS_DIR/tls-security-check.sh"
)

# Run each script and collect results
for script in "${AUDIT_SCRIPTS[@]}"; do
    if [[ -x "$script" ]]; then
        script_name=$(basename "$script" .sh)
        run_script "$script" "$TEMP_DIR"
        if [[ $? -eq 0 ]]; then
            echo "✅ $script_name completed successfully"
        else
            echo "❌ $script_name failed"
        fi
    else
        echo "⚠️ Script not found or not executable: $script"
    fi
done

# Generate the consolidated report
REPORT_FILE="$OUTPUT_DIR/baseline_security_report.$FORMAT"

# Use the report formatter to generate the final report
"$SCRIPT_DIR/format-security-report.sh" \
    --input-dir "$TEMP_DIR" \
    --output-file "$REPORT_FILE" \
    --format "$FORMAT" \
    --title "macOS Security Baseline Report" \
    --timestamp "$TIMESTAMP" \
    --hostname "$HOSTNAME" \
    --os-version "$OS_VERSION" \
    --architecture "$ARCH"

# Clean up temporary files if the report was generated successfully
if [[ $? -eq 0 && -f "$REPORT_FILE" ]]; then
    echo "✅ Baseline security report generated: $REPORT_FILE"
    # Uncomment to clean up temp files
    # rm -rf "$TEMP_DIR"
else
    echo "❌ Failed to generate baseline security report"
fi

echo "-------------------------------------------"
echo "Baseline security assessment completed"
echo "Report saved to: $REPORT_FILE"
