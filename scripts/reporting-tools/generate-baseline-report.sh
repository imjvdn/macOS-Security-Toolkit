#!/bin/bash
#
# generate-baseline-report.sh
# Part of macOS Security Toolkit
#
# Generates a comprehensive baseline security report by running
# all audit tools and consolidating their outputs into a single report.
#
# Usage: ./generate-baseline-report.sh [--output-dir /path/to/dir] [--format html|md|txt|json|csv|pdf] [--verbose]

# Terminal colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

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
VERBOSE=false

# Spinner animation function
spinner() {
    local pid=$1
    local message=$2
    local delay=0.1
    local spinstr='|/-\'
    
    echo -n "$message "
    
    while kill -0 $pid 2>/dev/null; do
        local temp=${spinstr#?}
        printf "\r$message [%c]  " "$spinstr"
        local spinstr=$temp${spinstr%"$temp"}
        sleep $delay
    done
    
    printf "\r$message [✓]  \n"
}

# Progress bar function
progress_bar() {
    local current=$1
    local total=$2
    local width=40
    local percent=$((current * 100 / total))
    local completed=$((width * current / total))
    
    printf "\r[%-${width}s] %d%% " "$(printf '%0.s#' $(seq 1 $completed))" "$percent"
}

# Function to print section headers
print_header() {
    local title=$1
    local width=60
    local padding=$(( (width - ${#title}) / 2 ))
    
    echo
    printf "%${width}s\n" | tr ' ' '='
    printf "%${padding}s${BOLD}${title}${NC}%${padding}s\n"
    printf "%${width}s\n" | tr ' ' '='
    echo
}

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
        --verbose)
            VERBOSE=true
            shift
            ;;
        --help)
            echo -e "${BOLD}Usage:${NC} $0 [--output-dir /path/to/dir] [--format html|md|txt|json|csv|pdf] [--verbose]"
            echo
            echo -e "${BOLD}Options:${NC}"
            echo -e "  --output-dir DIR    Directory to save the report (default: reports/YYYY-MM-DD_HH-MM-SS)"
            echo -e "  --format FORMAT     Output format: md, html, json, csv, pdf (default: md)"
            echo -e "  --verbose           Show detailed output during execution"
            echo -e "  --help              Show this help message"
            exit 0
            ;;
        *)
            echo -e "${RED}Unknown parameter: $1${NC}"
            echo -e "${BOLD}Usage:${NC} $0 [--output-dir /path/to/dir] [--format html|md|txt|json|csv|pdf] [--verbose]"
            exit 1
            ;;
    esac
done

# Create output directory if it doesn't exist
mkdir -p "$OUTPUT_DIR"
echo -e "${CYAN}Output directory:${NC} $OUTPUT_DIR"

# Create a temporary directory for individual tool outputs
TEMP_DIR="$OUTPUT_DIR/temp"
mkdir -p "$TEMP_DIR"

# Function to run a script and capture its output
run_script() {
    local script="$1"
    local output_dir="$2"
    local script_name=$(basename "$script" .sh)
    
    echo -e "\n${CYAN}Running ${BOLD}$script_name${NC}${CYAN}...${NC}"
    
    # Create script-specific output directory
    mkdir -p "$output_dir/$script_name"
    
    # Run the script with output directory parameter
    if [[ "$VERBOSE" == "true" ]]; then
        # Run with visible output in verbose mode
        echo -e "${YELLOW}Running in verbose mode. Full output will be displayed.${NC}\n"
        "$script" --output-dir "$output_dir/$script_name" | tee "$output_dir/$script_name.log"
        local exit_code=${PIPESTATUS[0]}
    else
        # Run with spinner in non-verbose mode
        echo -e "${YELLOW}Running in standard mode. Use --verbose to see detailed output.${NC}"
        "$script" --output-dir "$output_dir/$script_name" > "$output_dir/$script_name.log" 2>&1 &
        local pid=$!
        spinner $pid "Processing $script_name"
        wait $pid
        local exit_code=$?
    fi
    
    # Return the exit code of the script
    return $exit_code
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

# Print welcome message
clear
echo -e "${BOLD}${BLUE}"
echo "  __  __             _____ _____    _____                      _ _           _______          _ _    _ _   "
echo " |  \/  |           / ____|  __ \  / ____|                    (_) |         |__   __|        | | |  (_) |  "
echo " | \  / | __ _  ___| |    | |__) || (___   ___  ___ _   _ _ __ _| |_ _   _    | | ___   ___ | | | ___| |_ "
echo " | |\/| |/ _\` |/ __| |    |  ___/  \___ \ / _ \/ __| | | | '__| | __| | | |   | |/ _ \ / _ \| | |/ / | __|"
echo " | |  | | (_| | (__| |____| |      ____) |  __/ (__| |_| | |  | | |_| |_| |   | | (_) | (_) | |   <| | |_ "
echo " |_|  |_|\__,_|\___|\_____|_|     |_____/ \___|\___|\__,_|_|  |_|\__|\__, |   |_|\___/ \___/|_|_|\_\_|\__|"
echo "                                                                       __/ |                               "
echo "                                                                      |___/                                "
echo -e "${NC}"

# Print assessment information
print_header "BASELINE SECURITY ASSESSMENT"

echo -e "${BOLD}Started:${NC}      $TIMESTAMP"
echo -e "${BOLD}Host:${NC}         $HOSTNAME"
echo -e "${BOLD}macOS Version:${NC} $OS_VERSION"
echo -e "${BOLD}Architecture:${NC}  $ARCH"
echo -e "${BOLD}Report Format:${NC} $FORMAT"
echo -e "${BOLD}Output:${NC}       $OUTPUT_DIR"
echo

# Array of audit scripts to run
AUDIT_SCRIPTS=(
    "$AUDIT_TOOLS_DIR/system-security-audit.sh"
    "$AUDIT_TOOLS_DIR/user-account-audit.sh"
    "$AUDIT_TOOLS_DIR/firewall-analyzer.sh"
    "$AUDIT_TOOLS_DIR/malware-scanner.sh"
    "$AUDIT_TOOLS_DIR/network-port-scan.sh"
    "$AUDIT_TOOLS_DIR/tls-security-check.sh"
)

# Print assessment phase
print_header "RUNNING SECURITY TOOLS"

# Calculate total number of scripts for progress tracking
TOTAL_SCRIPTS=${#AUDIT_SCRIPTS[@]}
CURRENT_SCRIPT=0
SUCCESSFUL_SCRIPTS=0
FAILED_SCRIPTS=0

echo -e "${BOLD}Total security tools to run:${NC} $TOTAL_SCRIPTS"
echo

# Run each script and collect results
for script in "${AUDIT_SCRIPTS[@]}"; do
    if [[ -x "$script" ]]; then
        script_name=$(basename "$script" .sh)
        
        # Update progress
        CURRENT_SCRIPT=$((CURRENT_SCRIPT + 1))
        
        # Show overall progress
        echo -e "${BOLD}Overall Progress:${NC} Tool $CURRENT_SCRIPT of $TOTAL_SCRIPTS"
        progress_bar $CURRENT_SCRIPT $TOTAL_SCRIPTS
        echo -e "\n"
        
        # Run the script
        run_script "$script" "$TEMP_DIR"
        
        # Check result
        if [[ $? -eq 0 ]]; then
            echo -e "\n${GREEN}✅ $script_name completed successfully${NC}"
            SUCCESSFUL_SCRIPTS=$((SUCCESSFUL_SCRIPTS + 1))
        else
            echo -e "\n${RED}❌ $script_name failed${NC}"
            FAILED_SCRIPTS=$((FAILED_SCRIPTS + 1))
        fi
        
        # Add a separator between tools
        echo -e "\n${YELLOW}----------------------------------------${NC}"
    else
        echo -e "${YELLOW}⚠️ Script not found or not executable: $script${NC}"
    fi
done

# Print report generation phase
print_header "GENERATING REPORT"

echo -e "${BOLD}Security tools summary:${NC}"
echo -e "  ${GREEN}✅ Successful:${NC} $SUCCESSFUL_SCRIPTS"
echo -e "  ${RED}❌ Failed:${NC} $FAILED_SCRIPTS"
echo -e "  ${BOLD}Total:${NC} $TOTAL_SCRIPTS"
echo

# Generate the consolidated report
REPORT_FILE="$OUTPUT_DIR/baseline_security_report.$FORMAT"

echo -e "${CYAN}Generating $FORMAT report...${NC}"

# Use the report formatter to generate the final report
if [[ "$VERBOSE" == "true" ]]; then
    "$SCRIPT_DIR/format-security-report.sh" \
        --input-dir "$TEMP_DIR" \
        --output-file "$REPORT_FILE" \
        --format "$FORMAT" \
        --title "macOS Security Baseline Report" \
        --timestamp "$TIMESTAMP" \
        --hostname "$HOSTNAME" \
        --os-version "$OS_VERSION" \
        --architecture "$ARCH"
else
    # Run with spinner in non-verbose mode
    "$SCRIPT_DIR/format-security-report.sh" \
        --input-dir "$TEMP_DIR" \
        --output-file "$REPORT_FILE" \
        --format "$FORMAT" \
        --title "macOS Security Baseline Report" \
        --timestamp "$TIMESTAMP" \
        --hostname "$HOSTNAME" \
        --os-version "$OS_VERSION" \
        --architecture "$ARCH" > /dev/null 2>&1 &
    
    pid=$!
    spinner $pid "Formatting and generating report"
    wait $pid
fi

# Check if report was generated successfully
if [[ $? -eq 0 && -f "$REPORT_FILE" ]]; then
    echo -e "\n${GREEN}✅ Baseline security report generated successfully${NC}"
    # Uncomment to clean up temp files
    # echo -e "${YELLOW}Cleaning up temporary files...${NC}"
    # rm -rf "$TEMP_DIR"
else
    echo -e "\n${RED}❌ Failed to generate baseline security report${NC}"
fi

# Print completion message
print_header "ASSESSMENT COMPLETE"

echo -e "${GREEN}Baseline security assessment completed at $(date +"%Y-%m-%d %H:%M:%S")${NC}"
echo -e "${BOLD}Report saved to:${NC} $REPORT_FILE"
echo

# Print next steps
echo -e "${BOLD}Next Steps:${NC}"
echo -e "  1. Review the report to identify security issues"
echo -e "  2. Address any critical findings"
echo -e "  3. Schedule regular security assessments"
echo

# Print a nice border at the end
printf "%60s\n" | tr ' ' '='
