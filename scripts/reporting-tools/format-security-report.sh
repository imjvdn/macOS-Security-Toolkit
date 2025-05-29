#!/bin/bash
#
# format-security-report.sh
# Part of macOS Security Toolkit
#
# Formats security report data into various output formats
# including Markdown, HTML, JSON, CSV, and PDF (if dependencies available)
#
# Usage: ./format-security-report.sh --input-dir /path/to/input --output-file /path/to/output.ext --format [md|html|json|csv|pdf]

# Set default values
INPUT_DIR=""
OUTPUT_FILE=""
FORMAT="md"
TITLE="Security Report"
TIMESTAMP=$(date +"%Y-%m-%d %H:%M:%S")
HOSTNAME=$(hostname)
OS_VERSION=$(sw_vers -productVersion)
ARCHITECTURE=$(uname -m)

# Parse command line arguments
while [[ "$#" -gt 0 ]]; do
    case $1 in
        --input-dir)
            INPUT_DIR="$2"
            shift 2
            ;;
        --output-file)
            OUTPUT_FILE="$2"
            shift 2
            ;;
        --format)
            FORMAT="$2"
            shift 2
            ;;
        --title)
            TITLE="$2"
            shift 2
            ;;
        --timestamp)
            TIMESTAMP="$2"
            shift 2
            ;;
        --hostname)
            HOSTNAME="$2"
            shift 2
            ;;
        --os-version)
            OS_VERSION="$2"
            shift 2
            ;;
        --architecture)
            ARCHITECTURE="$2"
            shift 2
            ;;
        --help)
            echo "Usage: $0 --input-dir /path/to/input --output-file /path/to/output.ext --format [md|html|json|csv|pdf]"
            exit 0
            ;;
        *)
            echo "Unknown parameter: $1"
            echo "Usage: $0 --input-dir /path/to/input --output-file /path/to/output.ext --format [md|html|json|csv|pdf]"
            exit 1
            ;;
    esac
done

# Validate required parameters
if [[ -z "$INPUT_DIR" || -z "$OUTPUT_FILE" ]]; then
    echo "Error: Input directory and output file are required"
    echo "Usage: $0 --input-dir /path/to/input --output-file /path/to/output.ext --format [md|html|json|csv|pdf]"
    exit 1
fi

# Check if input directory exists
if [[ ! -d "$INPUT_DIR" ]]; then
    echo "Error: Input directory does not exist: $INPUT_DIR"
    exit 1
fi

# Create output directory if it doesn't exist
OUTPUT_DIR=$(dirname "$OUTPUT_FILE")
mkdir -p "$OUTPUT_DIR"

# Function to generate a markdown report
generate_markdown() {
    local output_file="$1"
    
    # Start with the header
    cat > "$output_file" << EOF
# $TITLE

**Generated:** $TIMESTAMP  
**Hostname:** $HOSTNAME  
**macOS Version:** $OS_VERSION  
**Architecture:** $ARCHITECTURE  

## Executive Summary

This report provides a comprehensive security baseline assessment of the macOS system.
It includes findings from multiple security tools and provides an overall security posture evaluation.

### Security Scores

| Security Category | Score | Status |
|-------------------|-------|--------|
EOF
    
    # Add security scores for each tool
    for dir in "$INPUT_DIR"/*/ ; do
        if [[ -d "$dir" ]]; then
            tool_name=$(basename "$dir" | tr '-' ' ' | awk '{for(i=1;i<=NF;i++)sub(/./,toupper(substr($i,1,1)),$i)}1')
            
            # Extract score if available
            score=$(grep -i "security score" "$dir/summary.md" 2>/dev/null | grep -o '[0-9]\+/[0-9]\+' | head -1)
            if [[ -z "$score" ]]; then
                score="N/A"
            fi
            
            # Determine status based on score
            status="⚠️ Unknown"
            if [[ "$score" != "N/A" ]]; then
                score_num=$(echo "$score" | cut -d'/' -f1)
                max_score=$(echo "$score" | cut -d'/' -f2)
                
                if (( score_num >= max_score * 9 / 10 )); then
                    status="✅ Good"
                elif (( score_num >= max_score * 7 / 10 )); then
                    status="⚠️ Needs Attention"
                else
                    status="❌ Critical"
                fi
            fi
            
            echo "| $tool_name | $score | $status |" >> "$output_file"
        fi
    done
    
    # Add key findings section
    cat >> "$output_file" << EOF

## Key Findings and Recommendations

This section highlights the most important security findings and recommendations.

EOF
    
    # Add findings from each tool
    for dir in "$INPUT_DIR"/*/ ; do
        if [[ -d "$dir" ]]; then
            tool_name=$(basename "$dir" | tr '-' ' ' | awk '{for(i=1;i<=NF;i++)sub(/./,toupper(substr($i,1,1)),$i)}1')
            
            echo "### $tool_name Findings" >> "$output_file"
            
            # Look for findings in summary.md or recommendations.md
            if [[ -f "$dir/summary.md" ]]; then
                # Extract findings section
                awk '/## Findings/,/##/' "$dir/summary.md" 2>/dev/null | grep -v "^##" >> "$output_file"
            elif [[ -f "$dir/recommendations.md" ]]; then
                cat "$dir/recommendations.md" >> "$output_file"
            else
                echo "No detailed findings available." >> "$output_file"
            fi
            
            echo "" >> "$output_file"
        fi
    done
    
    # Add detailed results section
    cat >> "$output_file" << EOF

## Detailed Results

This section provides detailed results from each security tool.

EOF
    
    # Add detailed results from each tool
    for dir in "$INPUT_DIR"/*/ ; do
        if [[ -d "$dir" ]]; then
            tool_name=$(basename "$dir" | tr '-' ' ' | awk '{for(i=1;i<=NF;i++)sub(/./,toupper(substr($i,1,1)),$i)}1')
            
            echo "### $tool_name" >> "$output_file"
            
            # Include log output
            log_file="$INPUT_DIR/$(basename "$dir").log"
            if [[ -f "$log_file" ]]; then
                echo "#### Tool Output" >> "$output_file"
                echo '```' >> "$output_file"
                cat "$log_file" >> "$output_file"
                echo '```' >> "$output_file"
            fi
            
            # Include any other relevant files
            echo "#### Detailed Analysis" >> "$output_file"
            for md_file in "$dir"/*.md; do
                if [[ -f "$md_file" && "$(basename "$md_file")" != "summary.md" && "$(basename "$md_file")" != "recommendations.md" ]]; then
                    echo "##### $(basename "$md_file" .md | tr '-' ' ' | awk '{for(i=1;i<=NF;i++)sub(/./,toupper(substr($i,1,1)),$i)}1')" >> "$output_file"
                    cat "$md_file" >> "$output_file"
                    echo "" >> "$output_file"
                fi
            done
            
            echo "" >> "$output_file"
        fi
    done
}

# Function to convert markdown to HTML
markdown_to_html() {
    local md_file="$1"
    local html_file="$2"
    
    # Create HTML header
    cat > "$html_file" << EOF
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>$TITLE</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, 'Open Sans', 'Helvetica Neue', sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }
        h1, h2, h3, h4, h5, h6 {
            color: #2c3e50;
        }
        h1 {
            border-bottom: 2px solid #eaecef;
            padding-bottom: 10px;
        }
        h2 {
            border-bottom: 1px solid #eaecef;
            padding-bottom: 5px;
        }
        table {
            border-collapse: collapse;
            width: 100%;
            margin: 20px 0;
        }
        th, td {
            border: 1px solid #ddd;
            padding: 8px 12px;
            text-align: left;
        }
        th {
            background-color: #f2f2f2;
        }
        tr:nth-child(even) {
            background-color: #f9f9f9;
        }
        code {
            font-family: 'SFMono-Regular', Consolas, 'Liberation Mono', Menlo, monospace;
            background-color: #f6f8fa;
            padding: 2px 4px;
            border-radius: 3px;
        }
        pre {
            background-color: #f6f8fa;
            border-radius: 3px;
            padding: 16px;
            overflow: auto;
        }
        .good {
            color: #2ecc71;
        }
        .warning {
            color: #f39c12;
        }
        .critical {
            color: #e74c3c;
        }
        .unknown {
            color: #7f8c8d;
        }
        .header-info {
            background-color: #f8f9fa;
            padding: 15px;
            border-radius: 5px;
            margin-bottom: 20px;
        }
    </style>
</head>
<body>
EOF

    # Convert markdown to HTML
    if command -v pandoc &>/dev/null; then
        # Use pandoc if available
        pandoc -f markdown -t html "$md_file" >> "$html_file"
    else
        # Basic conversion if pandoc is not available
        echo "<div class='markdown-content'>" >> "$html_file"
        
        # Very basic markdown to HTML conversion
        while IFS= read -r line; do
            # Headers
            if [[ "$line" =~ ^#\ (.+)$ ]]; then
                echo "<h1>${BASH_REMATCH[1]}</h1>" >> "$html_file"
            elif [[ "$line" =~ ^##\ (.+)$ ]]; then
                echo "<h2>${BASH_REMATCH[1]}</h2>" >> "$html_file"
            elif [[ "$line" =~ ^###\ (.+)$ ]]; then
                echo "<h3>${BASH_REMATCH[1]}</h3>" >> "$html_file"
            elif [[ "$line" =~ ^####\ (.+)$ ]]; then
                echo "<h4>${BASH_REMATCH[1]}</h4>" >> "$html_file"
            elif [[ "$line" =~ ^#####\ (.+)$ ]]; then
                echo "<h5>${BASH_REMATCH[1]}</h5>" >> "$html_file"
            # Bold
            elif [[ "$line" =~ \*\*([^*]+)\*\* ]]; then
                echo "${line/\*\*$BASH_REMATCH\*\*/<strong>$BASH_REMATCH</strong>}" >> "$html_file"
            # Code blocks
            elif [[ "$line" == '```' ]]; then
                if [[ "$in_code_block" == "true" ]]; then
                    echo "</pre>" >> "$html_file"
                    in_code_block="false"
                else
                    echo "<pre><code>" >> "$html_file"
                    in_code_block="true"
                fi
            # Tables
            elif [[ "$line" =~ \|.*\| ]]; then
                if [[ "$in_table" != "true" ]]; then
                    echo "<table>" >> "$html_file"
                    in_table="true"
                fi
                
                # Table row
                echo "<tr>" >> "$html_file"
                # Split by pipe and create cells
                IFS='|' read -ra cells <<< "$line"
                for cell in "${cells[@]}"; do
                    if [[ -n "$cell" ]]; then
                        if [[ "$line" =~ \|\-+ ]]; then
                            # This is a header separator row, skip it
                            continue
                        elif [[ "$in_table_header" == "true" ]]; then
                            echo "<th>${cell}</th>" >> "$html_file"
                        else
                            echo "<td>${cell}</td>" >> "$html_file"
                        fi
                    fi
                done
                echo "</tr>" >> "$html_file"
                
                # If this was the header row, next row is separator
                if [[ "$in_table_header" != "true" && ! "$line" =~ \|\-+ ]]; then
                    in_table_header="true"
                fi
            # End of table
            elif [[ "$in_table" == "true" && ! "$line" =~ \|.*\| ]]; then
                echo "</table>" >> "$html_file"
                in_table="false"
                in_table_header="false"
            # Regular paragraph
            elif [[ -n "$line" ]]; then
                echo "<p>$line</p>" >> "$html_file"
            else
                echo "<br>" >> "$html_file"
            fi
        done < "$md_file"
        
        # Close any open elements
        if [[ "$in_code_block" == "true" ]]; then
            echo "</pre>" >> "$html_file"
        fi
        if [[ "$in_table" == "true" ]]; then
            echo "</table>" >> "$html_file"
        fi
        
        echo "</div>" >> "$html_file"
    fi
    
    # Add HTML footer
    cat >> "$html_file" << EOF
</body>
</html>
EOF
}

# Function to convert data to JSON
generate_json() {
    local output_file="$1"
    
    # Start JSON structure
    cat > "$output_file" << EOF
{
  "report": {
    "title": "$TITLE",
    "timestamp": "$TIMESTAMP",
    "hostname": "$HOSTNAME",
    "os_version": "$OS_VERSION",
    "architecture": "$ARCHITECTURE",
    "security_tools": [
EOF
    
    # Add data for each tool
    first_tool=true
    for dir in "$INPUT_DIR"/*/ ; do
        if [[ -d "$dir" ]]; then
            tool_name=$(basename "$dir")
            
            # Add comma for all but the first tool
            if [[ "$first_tool" == "true" ]]; then
                first_tool=false
            else
                echo "," >> "$output_file"
            fi
            
            # Extract score if available
            score=$(grep -i "security score" "$dir/summary.md" 2>/dev/null | grep -o '[0-9]\+/[0-9]\+' | head -1)
            if [[ -z "$score" ]]; then
                score="N/A"
            fi
            
            # Start tool JSON object
            cat >> "$output_file" << EOF
      {
        "name": "$tool_name",
        "score": "$score",
EOF
            
            # Add findings if available
            if [[ -f "$dir/summary.md" ]]; then
                echo '        "findings": [' >> "$output_file"
                
                # Extract findings from summary.md
                findings=$(awk '/## Findings/,/##/' "$dir/summary.md" 2>/dev/null | grep -v "^##" | grep "^-" | sed 's/^- //')
                
                first_finding=true
                while IFS= read -r finding; do
                    if [[ -n "$finding" ]]; then
                        # Add comma for all but the first finding
                        if [[ "$first_finding" == "true" ]]; then
                            first_finding=false
                        else
                            echo "," >> "$output_file"
                        fi
                        
                        # Escape quotes in finding
                        finding="${finding//\"/\\\"}"
                        echo "          \"$finding\"" >> "$output_file"
                    fi
                done <<< "$findings"
                
                echo '        ]' >> "$output_file"
            else
                echo '        "findings": []' >> "$output_file"
            fi
            
            # Close tool JSON object
            echo '      }' >> "$output_file"
        fi
    done
    
    # Close JSON structure
    cat >> "$output_file" << EOF
    ]
  }
}
EOF
}

# Function to generate CSV report
generate_csv() {
    local output_file="$1"
    
    # Write CSV header
    echo "Category,Tool,Score,Finding" > "$output_file"
    
    # Add data for each tool
    for dir in "$INPUT_DIR"/*/ ; do
        if [[ -d "$dir" ]]; then
            tool_name=$(basename "$dir")
            category=$(echo "$tool_name" | sed 's/-.*$//')
            
            # Extract score if available
            score=$(grep -i "security score" "$dir/summary.md" 2>/dev/null | grep -o '[0-9]\+/[0-9]\+' | head -1)
            if [[ -z "$score" ]]; then
                score="N/A"
            fi
            
            # Extract findings
            if [[ -f "$dir/summary.md" ]]; then
                findings=$(awk '/## Findings/,/##/' "$dir/summary.md" 2>/dev/null | grep -v "^##" | grep "^-" | sed 's/^- //')
                
                # If no findings, add a row with empty finding
                if [[ -z "$findings" ]]; then
                    echo "\"$category\",\"$tool_name\",\"$score\",\"\"" >> "$output_file"
                else
                    # Add a row for each finding
                    while IFS= read -r finding; do
                        if [[ -n "$finding" ]]; then
                            # Escape quotes in finding and tool name
                            finding="${finding//\"/\"\"}"
                            echo "\"$category\",\"$tool_name\",\"$score\",\"$finding\"" >> "$output_file"
                        fi
                    done <<< "$findings"
                fi
            else
                # No summary file, add a row with empty finding
                echo "\"$category\",\"$tool_name\",\"$score\",\"\"" >> "$output_file"
            fi
        fi
    done
}

# Function to generate PDF (requires wkhtmltopdf)
generate_pdf() {
    local html_file="$1"
    local pdf_file="$2"
    
    if command -v wkhtmltopdf &>/dev/null; then
        wkhtmltopdf "$html_file" "$pdf_file"
        return $?
    elif command -v textutil &>/dev/null && command -v cupsfilter &>/dev/null; then
        # macOS alternative using textutil and cupsfilter
        local temp_html="${html_file%.html}.temp.html"
        cp "$html_file" "$temp_html"
        textutil -convert rtf -output "${temp_html%.html}.rtf" "$temp_html"
        cupsfilter "${temp_html%.html}.rtf" > "$pdf_file"
        rm -f "$temp_html" "${temp_html%.html}.rtf"
        return $?
    else
        echo "Error: PDF generation requires wkhtmltopdf or textutil/cupsfilter (macOS)"
        return 1
    fi
}

# Generate the report based on the specified format
case "$FORMAT" in
    md)
        generate_markdown "$OUTPUT_FILE"
        ;;
    html)
        # Generate markdown first, then convert to HTML
        MD_FILE="${OUTPUT_FILE%.html}.md"
        generate_markdown "$MD_FILE"
        markdown_to_html "$MD_FILE" "$OUTPUT_FILE"
        # Clean up temporary markdown file
        rm -f "$MD_FILE"
        ;;
    json)
        generate_json "$OUTPUT_FILE"
        ;;
    csv)
        generate_csv "$OUTPUT_FILE"
        ;;
    pdf)
        # Generate HTML first, then convert to PDF
        HTML_FILE="${OUTPUT_FILE%.pdf}.html"
        MD_FILE="${OUTPUT_FILE%.pdf}.md"
        generate_markdown "$MD_FILE"
        markdown_to_html "$MD_FILE" "$HTML_FILE"
        generate_pdf "$HTML_FILE" "$OUTPUT_FILE"
        # Clean up temporary files
        rm -f "$MD_FILE" "$HTML_FILE"
        ;;
    *)
        echo "Error: Unsupported format: $FORMAT"
        echo "Supported formats: md, html, json, csv, pdf"
        exit 1
        ;;
esac

# Check if output file was created successfully
if [[ -f "$OUTPUT_FILE" ]]; then
    echo "Report generated successfully: $OUTPUT_FILE"
    exit 0
else
    echo "Error: Failed to generate report"
    exit 1
fi
