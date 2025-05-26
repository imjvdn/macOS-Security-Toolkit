#!/bin/bash
#
# network-port-scan.sh
# macOS Security Toolkit
#
# A native macOS port scanner that uses built-in tools to scan
# for open ports on local or remote systems. Identifies services,
# generates reports, and provides security recommendations.
#
# Usage: ./network-port-scan.sh [OPTIONS]
#   --target TARGET       Target IP address or hostname (default: localhost)
#   --port-range RANGE    Port range to scan (default: 1-1024)
#   --scan-type TYPE      Scan type: quick, common, or full (default: common)
#   --output-dir DIR      Directory to save results (default: ~/Documents/Port-Scan-Results)
#   --timeout SECONDS     Timeout in seconds for each port (default: 1)
#   --threads NUMBER      Number of parallel threads (default: 10)
#   --service-detection   Attempt to identify services (default: enabled)
#   --no-service-detection Disable service detection
#   --help                Display this help message
#

# Set strict error handling
set -e
set -o pipefail

# Default values
TARGET="localhost"
PORT_RANGE="1-1024"
SCAN_TYPE="common"
OUTPUT_DIR="$HOME/Documents/Port-Scan-Results-$(date +%Y%m%d-%H%M%S)"
TIMEOUT=1
THREADS=10
SERVICE_DETECTION=true

# Common ports to scan in "common" mode
COMMON_PORTS=(
    21    # FTP
    22    # SSH
    23    # Telnet
    25    # SMTP
    53    # DNS
    80    # HTTP
    88    # Kerberos
    110   # POP3
    123   # NTP
    137   # NetBIOS Name Service
    138   # NetBIOS Datagram Service
    139   # NetBIOS Session Service
    143   # IMAP
    161   # SNMP
    389   # LDAP
    443   # HTTPS
    445   # SMB
    465   # SMTPS
    500   # ISAKMP
    514   # Syslog
    587   # SMTP Submission
    631   # IPP (CUPS)
    636   # LDAPS
    993   # IMAPS
    995   # POP3S
    1433  # MS SQL
    1521  # Oracle
    3306  # MySQL
    3389  # RDP
    5432  # PostgreSQL
    5900  # VNC
    6379  # Redis
    8080  # HTTP Alternate
    8443  # HTTPS Alternate
    27017 # MongoDB
)

# Function to display help
show_help() {
    echo "macOS Network Port Scanner"
    echo "Usage: $0 [OPTIONS]"
    echo "Options:"
    echo "  --target TARGET       Target IP address or hostname (default: localhost)"
    echo "  --port-range RANGE    Port range to scan (default: 1-1024)"
    echo "  --scan-type TYPE      Scan type: quick, common, or full (default: common)"
    echo "  --output-dir DIR      Directory to save results (default: ~/Documents/Port-Scan-Results)"
    echo "  --timeout SECONDS     Timeout in seconds for each port (default: 1)"
    echo "  --threads NUMBER      Number of parallel threads (default: 10)"
    echo "  --service-detection   Attempt to identify services (default: enabled)"
    echo "  --no-service-detection Disable service detection"
    echo "  --help                Display this help message"
    exit 0
}

# Process command line arguments
while [[ $# -gt 0 ]]; do
    key="$1"
    case $key in
        --target)
            TARGET="$2"
            shift
            shift
            ;;
        --port-range)
            PORT_RANGE="$2"
            shift
            shift
            ;;
        --scan-type)
            SCAN_TYPE="$2"
            if [[ ! "$SCAN_TYPE" =~ ^(quick|common|full)$ ]]; then
                echo "Error: Invalid scan type. Must be quick, common, or full."
                exit 1
            fi
            shift
            shift
            ;;
        --output-dir)
            OUTPUT_DIR="$2"
            shift
            shift
            ;;
        --timeout)
            TIMEOUT="$2"
            shift
            shift
            ;;
        --threads)
            THREADS="$2"
            shift
            shift
            ;;
        --service-detection)
            SERVICE_DETECTION=true
            shift
            ;;
        --no-service-detection)
            SERVICE_DETECTION=false
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

# Create output directory
mkdir -p "$OUTPUT_DIR"

# Log file
LOG_FILE="$OUTPUT_DIR/port-scan.log"
RESULTS_FILE="$OUTPUT_DIR/open-ports.csv"
HTML_REPORT="$OUTPUT_DIR/port-scan-report.html"

# Function to log messages
log_message() {
    local timestamp=$(date +"%Y-%m-%d %H:%M:%S")
    echo "[$timestamp] $1" | tee -a "$LOG_FILE"
}

# Initialize CSV file with header
echo "Port,Status,Service,Banner" > "$RESULTS_FILE"

# Function to check if a port is open
check_port() {
    local target=$1
    local port=$2
    local timeout=$3
    local service_detection=$4
    
    # Use timeout to prevent hanging on filtered ports
    if timeout "$timeout" bash -c "echo >/dev/tcp/$target/$port" 2>/dev/null; then
        local service="Unknown"
        local banner=""
        
        # Attempt service detection if enabled
        if [ "$service_detection" = true ]; then
            # Try to get service name from /etc/services
            service=$(grep -w "$port/tcp" /etc/services 2>/dev/null | head -1 | awk '{print $1}' || echo "Unknown")
            
            # Try to grab banner
            banner=$(timeout 2 bash -c "exec 3</dev/tcp/$target/$port; echo '' >&3; cat <&3 2>/dev/null" | tr -d '\r\n' | tr -c '[:print:]' ' ' | cut -c 1-100 || echo "")
            
            # Clean banner for CSV
            banner=$(echo "$banner" | sed 's/,/;/g' | sed 's/"/'\''/g')
        fi
        
        # Output to CSV
        echo "$port,Open,$service,\"$banner\"" >> "$RESULTS_FILE"
        echo "Port $port: Open ($service)"
        return 0
    else
        return 1
    fi
}

# Function to scan a range of ports
scan_ports() {
    local target=$1
    local start_port=$2
    local end_port=$3
    local timeout=$4
    local service_detection=$5
    
    log_message "Scanning ports $start_port to $end_port on $target..."
    
    # Create a temporary directory for parallel processing
    local temp_dir=$(mktemp -d)
    
    # Process each port
    for port in $(seq $start_port $end_port); do
        # Limit the number of parallel processes
        while [ $(jobs -p | wc -l) -ge $THREADS ]; do
            sleep 0.1
        done
        
        # Check port in background
        (check_port "$target" "$port" "$timeout" "$service_detection") &
    done
    
    # Wait for all background jobs to finish
    wait
    
    # Clean up
    rm -rf "$temp_dir"
}

# Function to generate HTML report
generate_html_report() {
    local results_file=$1
    local html_file=$2
    local target=$3
    
    log_message "Generating HTML report..."
    
    # Count open ports
    local open_ports=$(grep -c "Open" "$results_file" || echo "0")
    
    # Create HTML report
    cat > "$html_file" << EOF
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Port Scan Report for $target</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            line-height: 1.6;
            margin: 0;
            padding: 20px;
            color: #333;
        }
        h1, h2, h3 {
            color: #2c3e50;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
        }
        .header {
            text-align: center;
            margin-bottom: 30px;
        }
        .summary {
            background-color: #f8f9fa;
            border-radius: 5px;
            padding: 15px;
            margin-bottom: 20px;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 20px;
        }
        th, td {
            padding: 10px;
            border: 1px solid #ddd;
            text-align: left;
        }
        th {
            background-color: #f2f2f2;
        }
        tr:nth-child(even) {
            background-color: #f9f9f9;
        }
        .port-open {
            background-color: #ffebee;
        }
        .footer {
            margin-top: 30px;
            text-align: center;
            font-size: 0.8em;
            color: #777;
        }
        .risk-high {
            background-color: #ffebee;
            color: #c62828;
        }
        .risk-medium {
            background-color: #fff8e1;
            color: #ff8f00;
        }
        .risk-low {
            background-color: #e8f5e9;
            color: #2e7d32;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>macOS Security Toolkit</h1>
            <h2>Network Port Scan Report</h2>
        </div>
        
        <div class="summary">
            <h3>Scan Summary</h3>
            <p><strong>Target:</strong> $target</p>
            <p><strong>Scan Date:</strong> $(date)</p>
            <p><strong>Open Ports:</strong> $open_ports</p>
            <p><strong>Scan Type:</strong> $SCAN_TYPE</p>
            <p><strong>Port Range:</strong> $PORT_RANGE</p>
        </div>

        <h3>Open Ports</h3>
        <table>
            <tr>
                <th>Port</th>
                <th>Status</th>
                <th>Service</th>
                <th>Banner</th>
                <th>Risk Level</th>
                <th>Recommendations</th>
            </tr>
EOF

    # Add table rows for each open port
    awk -F, 'NR>1 {
        gsub(/"/, "", $4);
        port = $1;
        status = $2;
        service = $3;
        banner = $4;
        
        # Determine risk level and recommendations
        risk = "Low";
        recommendation = "Verify if this service is needed. If not, consider disabling it.";
        risk_class = "risk-low";
        
        if (port == 21 || port == 23 || port == 25 || port == 110 || port == 143 || port == 445 || port == 3389) {
            risk = "High";
            recommendation = "This service may transmit data in cleartext or has known vulnerabilities. Consider disabling or replacing with a secure alternative.";
            risk_class = "risk-high";
        } else if (port == 22 || port == 80 || port == 443 || port == 3306 || port == 5432) {
            risk = "Medium";
            recommendation = "Ensure this service is properly configured, using strong authentication and encryption where applicable.";
            risk_class = "risk-medium";
        }
        
        print "<tr class=\"port-open\">";
        print "  <td>" port "</td>";
        print "  <td>" status "</td>";
        print "  <td>" service "</td>";
        print "  <td>" banner "</td>";
        print "  <td class=\"" risk_class "\">" risk "</td>";
        print "  <td>" recommendation "</td>";
        print "</tr>";
    }' "$results_file" >> "$html_file"

    # Complete the HTML file
    cat >> "$html_file" << EOF
        </table>
        
        <div class="recommendations">
            <h3>General Security Recommendations</h3>
            <ul>
                <li>Close unnecessary ports to reduce attack surface</li>
                <li>Use a firewall to restrict access to necessary services only</li>
                <li>Keep all services updated with security patches</li>
                <li>Use strong authentication for all network services</li>
                <li>Consider using encryption for sensitive services</li>
                <li>Monitor logs for suspicious connection attempts</li>
            </ul>
        </div>
        
        <div class="footer">
            <p>Generated by macOS Security Toolkit - Network Port Scanner</p>
            <p>$(date)</p>
        </div>
    </div>
</body>
</html>
EOF

    log_message "HTML report generated: $html_file"
}

# Main execution
log_message "Starting port scan on $TARGET"
log_message "Scan type: $SCAN_TYPE"
log_message "Output directory: $OUTPUT_DIR"

# Determine port range based on scan type
if [ "$SCAN_TYPE" = "quick" ]; then
    # Quick scan: Top 20 common ports
    log_message "Quick scan: Checking top 20 common ports"
    for port in ${COMMON_PORTS[@]:0:20}; do
        check_port "$TARGET" "$port" "$TIMEOUT" "$SERVICE_DETECTION"
    done
elif [ "$SCAN_TYPE" = "common" ]; then
    # Common scan: All common ports
    log_message "Common scan: Checking all common ports"
    for port in ${COMMON_PORTS[@]}; do
        check_port "$TARGET" "$port" "$TIMEOUT" "$SERVICE_DETECTION"
    done
else
    # Full scan: Custom port range
    log_message "Full scan: Checking port range $PORT_RANGE"
    START_PORT=$(echo $PORT_RANGE | cut -d'-' -f1)
    END_PORT=$(echo $PORT_RANGE | cut -d'-' -f2)
    scan_ports "$TARGET" "$START_PORT" "$END_PORT" "$TIMEOUT" "$SERVICE_DETECTION"
fi

# Generate HTML report
generate_html_report "$RESULTS_FILE" "$HTML_REPORT" "$TARGET"

# Print summary
open_ports=$(grep -c "Open" "$RESULTS_FILE" || echo "0")
log_message "Scan complete! Found $open_ports open ports."
log_message "Results saved to: $OUTPUT_DIR"
log_message "CSV report: $RESULTS_FILE"
log_message "HTML report: $HTML_REPORT"

echo ""
echo "Port Scan Complete!"
echo "------------------"
echo "Target: $TARGET"
echo "Open ports: $open_ports"
echo ""
echo "Results saved to: $OUTPUT_DIR"
echo "To view the HTML report, open: $HTML_REPORT"
echo ""

exit 0
