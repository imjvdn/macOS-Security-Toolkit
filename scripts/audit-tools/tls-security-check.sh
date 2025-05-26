#!/bin/bash
#
# tls-security-check.sh
# macOS Security Toolkit
#
# Checks SSL/TLS configurations on web servers, including protocol support,
# certificate validity, and security recommendations.
#
# Usage: ./tls-security-check.sh [OPTIONS]
#   --target TARGET       Target hostname or IP (default: localhost)
#   --port PORT           Target port (default: 443)
#   --output-dir DIR      Directory to save results (default: ~/Documents/TLS-Check-Results)
#   --timeout SECONDS     Connection timeout in seconds (default: 5)
#   --help                Display this help message
#

# Set strict error handling
set -e
set -o pipefail

# Default values
TARGET="localhost"
PORT="443"
OUTPUT_DIR="$HOME/Documents/TLS-Check-Results-$(date +%Y%m%d-%H%M%S)"
TIMEOUT=5

# Function to display help
show_help() {
    echo "macOS TLS Security Checker"
    echo "Usage: $0 [OPTIONS]"
    echo "Options:"
    echo "  --target TARGET       Target hostname or IP (default: localhost)"
    echo "  --port PORT           Target port (default: 443)"
    echo "  --output-dir DIR      Directory to save results (default: ~/Documents/TLS-Check-Results)"
    echo "  --timeout SECONDS     Connection timeout in seconds (default: 5)"
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
        --port)
            PORT="$2"
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
LOG_FILE="$OUTPUT_DIR/tls-check.log"
RESULTS_FILE="$OUTPUT_DIR/tls-results.csv"
HTML_REPORT="$OUTPUT_DIR/tls-report.html"

# Function to log messages
log_message() {
    local timestamp=$(date +"%Y-%m-%d %H:%M:%S")
    echo "[$timestamp] $1" | tee -a "$LOG_FILE"
}

# Initialize CSV file with header
echo "Test,Result,Details,Risk" > "$RESULTS_FILE"

# Function to check if openssl is available
check_openssl() {
    if ! command -v openssl &> /dev/null; then
        log_message "ERROR: OpenSSL is not installed or not in PATH"
        echo "ERROR: OpenSSL is not installed or not in PATH"
        exit 1
    fi
}

# Function to test SSL/TLS protocol support
test_protocol() {
    local target=$1
    local port=$2
    local protocol=$3
    local timeout=$4
    
    log_message "Testing $protocol support..."
    
    if echo | timeout $timeout openssl s_client -connect ${target}:${port} -${protocol} 2>/dev/null | grep -q "BEGIN CERTIFICATE"; then
        echo "$protocol,Pass,Protocol $protocol is supported,Info" >> "$RESULTS_FILE"
        log_message "$protocol: Supported"
        return 0
    else
        echo "$protocol,Fail,Protocol $protocol is not supported,Info" >> "$RESULTS_FILE"
        log_message "$protocol: Not supported"
        return 1
    fi
}

# Function to check certificate validity
check_certificate() {
    local target=$1
    local port=$2
    local timeout=$3
    
    log_message "Checking certificate validity..."
    
    # Get certificate information
    local cert_info=$(timeout $timeout openssl s_client -connect ${target}:${port} -showcerts 2>/dev/null </dev/null | openssl x509 -noout -text 2>/dev/null)
    
    if [ -z "$cert_info" ]; then
        echo "Certificate Validity,Fail,Unable to retrieve certificate information,High" >> "$RESULTS_FILE"
        log_message "Certificate: Unable to retrieve information"
        return 1
    fi
    
    # Save certificate to file
    timeout $timeout openssl s_client -connect ${target}:${port} -showcerts 2>/dev/null </dev/null | openssl x509 -outform PEM > "$OUTPUT_DIR/certificate.pem"
    
    # Check certificate expiration
    local expiry_date=$(openssl x509 -in "$OUTPUT_DIR/certificate.pem" -noout -enddate 2>/dev/null | cut -d= -f2)
    local expiry_epoch=$(date -j -f "%b %d %H:%M:%S %Y %Z" "$expiry_date" +%s 2>/dev/null)
    local current_epoch=$(date +%s)
    local seconds_until_expiry=$((expiry_epoch - current_epoch))
    local days_until_expiry=$((seconds_until_expiry / 86400))
    
    if [ $days_until_expiry -lt 0 ]; then
        echo "Certificate Expiry,Fail,Certificate has expired ($expiry_date),Critical" >> "$RESULTS_FILE"
        log_message "Certificate: Expired on $expiry_date"
    elif [ $days_until_expiry -lt 30 ]; then
        echo "Certificate Expiry,Warn,Certificate expires soon: $days_until_expiry days ($expiry_date),High" >> "$RESULTS_FILE"
        log_message "Certificate: Expires soon ($days_until_expiry days)"
    else
        echo "Certificate Expiry,Pass,Certificate valid for $days_until_expiry more days,Low" >> "$RESULTS_FILE"
        log_message "Certificate: Valid for $days_until_expiry more days"
    fi
    
    # Check certificate subject
    local subject=$(openssl x509 -in "$OUTPUT_DIR/certificate.pem" -noout -subject 2>/dev/null | sed 's/^subject=//')
    echo "Certificate Subject,Info,$subject,Info" >> "$RESULTS_FILE"
    log_message "Certificate Subject: $subject"
    
    # Check certificate issuer
    local issuer=$(openssl x509 -in "$OUTPUT_DIR/certificate.pem" -noout -issuer 2>/dev/null | sed 's/^issuer=//')
    echo "Certificate Issuer,Info,$issuer,Info" >> "$RESULTS_FILE"
    log_message "Certificate Issuer: $issuer"
    
    # Check if certificate is self-signed
    local is_self_signed=false
    if [ "$subject" = "$issuer" ]; then
        is_self_signed=true
        echo "Self-Signed Certificate,Fail,Certificate is self-signed,High" >> "$RESULTS_FILE"
        log_message "Certificate: Self-signed"
    else
        echo "Self-Signed Certificate,Pass,Certificate is issued by a CA,Low" >> "$RESULTS_FILE"
        log_message "Certificate: Issued by CA"
    fi
    
    # Check key size
    local key_size=$(openssl x509 -in "$OUTPUT_DIR/certificate.pem" -noout -text 2>/dev/null | grep "Public-Key:" | grep -o "[0-9]\+ bit")
    local key_size_value=$(echo $key_size | grep -o "[0-9]\+")
    
    if [ -z "$key_size_value" ]; then
        echo "Key Size,Fail,Unable to determine key size,Medium" >> "$RESULTS_FILE"
        log_message "Key Size: Unable to determine"
    elif [ $key_size_value -lt 2048 ]; then
        echo "Key Size,Fail,Key size too small: $key_size (should be at least 2048 bit),High" >> "$RESULTS_FILE"
        log_message "Key Size: Too small ($key_size)"
    else
        echo "Key Size,Pass,Key size adequate: $key_size,Low" >> "$RESULTS_FILE"
        log_message "Key Size: Adequate ($key_size)"
    fi
    
    # Check signature algorithm
    local sig_alg=$(openssl x509 -in "$OUTPUT_DIR/certificate.pem" -noout -text 2>/dev/null | grep "Signature Algorithm" | head -1 | sed 's/.*Signature Algorithm: //')
    
    if [[ "$sig_alg" == *"sha1"* || "$sig_alg" == *"md5"* ]]; then
        echo "Signature Algorithm,Fail,Weak signature algorithm: $sig_alg,High" >> "$RESULTS_FILE"
        log_message "Signature Algorithm: Weak ($sig_alg)"
    else
        echo "Signature Algorithm,Pass,Strong signature algorithm: $sig_alg,Low" >> "$RESULTS_FILE"
        log_message "Signature Algorithm: Strong ($sig_alg)"
    fi
    
    # Verify certificate chain if not self-signed
    if [ "$is_self_signed" = false ]; then
        if openssl verify "$OUTPUT_DIR/certificate.pem" &>/dev/null; then
            echo "Certificate Chain,Pass,Certificate chain is valid,Low" >> "$RESULTS_FILE"
            log_message "Certificate Chain: Valid"
        else
            echo "Certificate Chain,Fail,Certificate chain verification failed,High" >> "$RESULTS_FILE"
            log_message "Certificate Chain: Invalid"
        fi
    fi
}

# Function to check cipher suites
check_ciphers() {
    local target=$1
    local port=$2
    local timeout=$3
    
    log_message "Checking supported cipher suites..."
    
    # Get all supported ciphers
    local ciphers=$(timeout $timeout openssl ciphers 'ALL:eNULL' | tr ':' ' ')
    local weak_ciphers=0
    local strong_ciphers=0
    
    # Test each cipher
    for cipher in $ciphers; do
        if timeout $timeout openssl s_client -connect ${target}:${port} -cipher $cipher -tls1_2 &>/dev/null </dev/null; then
            # Check if it's a weak cipher
            if [[ "$cipher" == *"NULL"* || "$cipher" == *"EXP"* || "$cipher" == *"RC4"* || "$cipher" == *"DES"* || "$cipher" == *"MD5"* ]]; then
                echo "Weak Cipher,Fail,$cipher is supported,High" >> "$RESULTS_FILE"
                log_message "Weak Cipher: $cipher is supported"
                weak_ciphers=$((weak_ciphers + 1))
            else
                strong_ciphers=$((strong_ciphers + 1))
            fi
        fi
    done
    
    # Summary of cipher strength
    if [ $weak_ciphers -gt 0 ]; then
        echo "Cipher Strength,Fail,$weak_ciphers weak ciphers and $strong_ciphers strong ciphers supported,High" >> "$RESULTS_FILE"
        log_message "Cipher Strength: $weak_ciphers weak, $strong_ciphers strong"
    else
        echo "Cipher Strength,Pass,No weak ciphers supported ($strong_ciphers strong ciphers),Low" >> "$RESULTS_FILE"
        log_message "Cipher Strength: All strong ($strong_ciphers ciphers)"
    fi
}

# Function to check for Heartbleed vulnerability
check_heartbleed() {
    local target=$1
    local port=$2
    local timeout=$3
    
    log_message "Checking for Heartbleed vulnerability..."
    
    # Simple check for Heartbleed - this is not comprehensive
    if echo "Q" | timeout $timeout openssl s_client -connect ${target}:${port} 2>/dev/null | grep -qi "heartbeat"; then
        echo "Heartbleed,Warn,TLS heartbeat extension is enabled (further testing recommended),Medium" >> "$RESULTS_FILE"
        log_message "Heartbleed: TLS heartbeat extension is enabled"
    else
        echo "Heartbleed,Pass,TLS heartbeat extension not detected,Low" >> "$RESULTS_FILE"
        log_message "Heartbleed: TLS heartbeat extension not detected"
    fi
}

# Function to generate HTML report
generate_html_report() {
    local results_file=$1
    local html_file=$2
    local target=$3
    local port=$4
    
    log_message "Generating HTML report..."
    
    # Calculate security score
    local total_tests=$(grep -c "," "$results_file")
    local failed_tests=$(grep -c ",Fail," "$results_file")
    local warn_tests=$(grep -c ",Warn," "$results_file")
    local pass_tests=$(grep -c ",Pass," "$results_file")
    
    # Calculate weighted score (failures count more)
    local weighted_score=$((100 - (failed_tests * 15) - (warn_tests * 5)))
    if [ $weighted_score -lt 0 ]; then
        weighted_score=0
    fi
    
    # Determine grade
    local grade="F"
    if [ $weighted_score -ge 90 ]; then
        grade="A"
    elif [ $weighted_score -ge 80 ]; then
        grade="B"
    elif [ $weighted_score -ge 70 ]; then
        grade="C"
    elif [ $weighted_score -ge 60 ]; then
        grade="D"
    fi
    
    # Create HTML report
    cat > "$html_file" << EOF
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>TLS Security Report for $target:$port</title>
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
        .score {
            font-size: 48px;
            font-weight: bold;
            text-align: center;
            width: 100px;
            height: 100px;
            line-height: 100px;
            border-radius: 50%;
            margin: 0 auto 20px;
        }
        .grade-a {
            background-color: #4caf50;
            color: white;
        }
        .grade-b {
            background-color: #8bc34a;
            color: white;
        }
        .grade-c {
            background-color: #ffc107;
            color: #333;
        }
        .grade-d {
            background-color: #ff9800;
            color: white;
        }
        .grade-f {
            background-color: #f44336;
            color: white;
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
        .result-pass {
            background-color: #e8f5e9;
            color: #2e7d32;
        }
        .result-fail {
            background-color: #ffebee;
            color: #c62828;
        }
        .result-warn {
            background-color: #fff8e1;
            color: #ff8f00;
        }
        .result-info {
            background-color: #e3f2fd;
            color: #1565c0;
        }
        .risk-critical {
            background-color: #d50000;
            color: white;
            font-weight: bold;
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
        .footer {
            margin-top: 30px;
            text-align: center;
            font-size: 0.8em;
            color: #777;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>macOS Security Toolkit</h1>
            <h2>TLS Security Report</h2>
        </div>
        
        <div class="summary">
            <div class="score grade-${grade,,}">$grade</div>
            <h3>Security Score: $weighted_score/100</h3>
            <p><strong>Target:</strong> $target:$port</p>
            <p><strong>Scan Date:</strong> $(date)</p>
            <p><strong>Tests Performed:</strong> $total_tests</p>
            <p><strong>Tests Passed:</strong> $pass_tests</p>
            <p><strong>Tests Failed:</strong> $failed_tests</p>
            <p><strong>Warnings:</strong> $warn_tests</p>
        </div>

        <h3>Test Results</h3>
        <table>
            <tr>
                <th>Test</th>
                <th>Result</th>
                <th>Details</th>
                <th>Risk Level</th>
            </tr>
EOF

    # Add table rows for each test result
    awk -F, '{
        test = $1;
        result = $2;
        details = $3;
        risk = $4;
        
        result_class = "result-" tolower(result);
        risk_class = "risk-" tolower(risk);
        
        print "<tr>";
        print "  <td>" test "</td>";
        print "  <td class=\"" result_class "\">" result "</td>";
        print "  <td>" details "</td>";
        print "  <td class=\"" risk_class "\">" risk "</td>";
        print "</tr>";
    }' "$results_file" >> "$html_file"

    # Complete the HTML file
    cat >> "$html_file" << EOF
        </table>
        
        <div class="recommendations">
            <h3>Security Recommendations</h3>
            <ul>
                <li>Disable SSL 2.0 and 3.0 protocols (they are insecure)</li>
                <li>Disable TLS 1.0 and 1.1 if possible (they have known vulnerabilities)</li>
                <li>Use TLS 1.2 or 1.3 for all secure communications</li>
                <li>Remove support for weak cipher suites</li>
                <li>Ensure certificates are valid and not expired</li>
                <li>Use certificates with at least 2048-bit keys</li>
                <li>Use strong signature algorithms (SHA-256 or better)</li>
                <li>Implement HTTP Strict Transport Security (HSTS)</li>
                <li>Configure secure TLS settings in your web server</li>
            </ul>
        </div>
        
        <div class="footer">
            <p>Generated by macOS Security Toolkit - TLS Security Checker</p>
            <p>$(date)</p>
        </div>
    </div>
</body>
</html>
EOF

    log_message "HTML report generated: $html_file"
}

# Main execution
log_message "Starting TLS security check on $TARGET:$PORT"
log_message "Output directory: $OUTPUT_DIR"

# Check if openssl is available
check_openssl

# Test SSL/TLS protocols
test_protocol "$TARGET" "$PORT" "ssl2" "$TIMEOUT" || true
test_protocol "$TARGET" "$PORT" "ssl3" "$TIMEOUT" || true
test_protocol "$TARGET" "$PORT" "tls1" "$TIMEOUT" || true
test_protocol "$TARGET" "$PORT" "tls1_1" "$TIMEOUT" || true
test_protocol "$TARGET" "$PORT" "tls1_2" "$TIMEOUT" || true
test_protocol "$TARGET" "$PORT" "tls1_3" "$TIMEOUT" || true

# Check certificate
check_certificate "$TARGET" "$PORT" "$TIMEOUT"

# Check cipher suites
check_ciphers "$TARGET" "$PORT" "$TIMEOUT"

# Check for Heartbleed vulnerability
check_heartbleed "$TARGET" "$PORT" "$TIMEOUT"

# Generate HTML report
generate_html_report "$RESULTS_FILE" "$HTML_REPORT" "$TARGET" "$PORT"

# Print summary
log_message "TLS security check complete!"
log_message "Results saved to: $OUTPUT_DIR"
log_message "CSV report: $RESULTS_FILE"
log_message "HTML report: $HTML_REPORT"

echo ""
echo "TLS Security Check Complete!"
echo "--------------------------"
echo "Target: $TARGET:$PORT"
echo ""
echo "Results saved to: $OUTPUT_DIR"
echo "To view the HTML report, open: $HTML_REPORT"
echo ""

exit 0
