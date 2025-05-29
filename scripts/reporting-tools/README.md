# Reporting Tools

This directory contains scripts for generating comprehensive security reports from the macOS Security Toolkit audit tools.

## Available Tools

### generate-baseline-report.sh

Generates a comprehensive baseline security report by running all audit tools and consolidating their outputs into a single report.

#### Usage

```bash
./generate-baseline-report.sh [--output-dir /path/to/dir] [--format html|md|txt|json|csv|pdf]
```

#### Options

- `--output-dir`: Directory to save the report (default: `../../reports/YYYY-MM-DD_HH-MM-SS`)
- `--format`: Output format (default: `md`)
  - Supported formats: `md` (Markdown), `html`, `json`, `csv`, `pdf` (requires wkhtmltopdf)

#### Example

```bash
# Generate a baseline report in the default location with markdown format
./generate-baseline-report.sh

# Generate an HTML report in a specific directory
./generate-baseline-report.sh --output-dir ~/Desktop/security-reports --format html

# Generate a PDF report
./generate-baseline-report.sh --format pdf
```

### format-security-report.sh

Formats security report data into various output formats including Markdown, HTML, JSON, CSV, and PDF.

#### Usage

```bash
./format-security-report.sh --input-dir /path/to/input --output-file /path/to/output.ext --format [md|html|json|csv|pdf]
```

#### Options

- `--input-dir`: Directory containing security tool outputs (required)
- `--output-file`: Path to the output report file (required)
- `--format`: Output format (required)
  - Supported formats: `md` (Markdown), `html`, `json`, `csv`, `pdf` (requires wkhtmltopdf)
- `--title`: Report title (default: "Security Report")
- `--timestamp`: Report timestamp (default: current time)
- `--hostname`: Hostname (default: current hostname)
- `--os-version`: macOS version (default: current OS version)
- `--architecture`: System architecture (default: current architecture)

#### Example

```bash
# Format collected data as HTML
./format-security-report.sh --input-dir ~/security-data --output-file ~/report.html --format html --title "Monthly Security Report"
```

## Report Structure

The generated reports include:

1. **Executive Summary**: Overview of the security assessment with scores for each category
2. **Key Findings and Recommendations**: Important security issues that need attention
3. **Detailed Results**: Comprehensive output from each security tool

## Dependencies

- For PDF output: `wkhtmltopdf` (can be installed via Homebrew: `brew install wkhtmltopdf`)
- For enhanced HTML conversion: `pandoc` (optional, can be installed via Homebrew: `brew install pandoc`)
