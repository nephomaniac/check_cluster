#!/bin/bash
#
# Generate HTML Health Check Report for ROSA Cluster
#
# Usage:
#   ./generate_html_report.sh <cluster-directory> [output-file]
#
# Example:
#   ./generate_html_report.sh testgood_multi_az
#   ./generate_html_report.sh testgood_multi_az my_report.html
#

set -e

# Check arguments
if [ -z "$1" ]; then
    echo "Usage: $0 <cluster-directory> [output-file]"
    echo ""
    echo "Examples:"
    echo "  $0 testgood_multi_az"
    echo "  $0 testgood_multi_az custom_report.html"
    exit 1
fi

CLUSTER_DIR="$1"
OUTPUT_FILE="${2:-cluster_health_report.html}"

# Verify cluster directory exists
if [ ! -d "$CLUSTER_DIR" ]; then
    echo "Error: Cluster directory '$CLUSTER_DIR' does not exist"
    exit 1
fi

echo "================================================"
echo "Generating ROSA Cluster Health Check Report"
echo "================================================"
echo "Cluster Directory: $CLUSTER_DIR"
echo "Output File: $OUTPUT_FILE"
echo ""

# Run pytest with HTML reporter
echo "Running health checks..."
uv run pytest tests/ \
    --cluster-dir="$CLUSTER_DIR" \
    --html="$OUTPUT_FILE" \
    --self-contained-html \
    -v

echo ""
echo "================================================"
echo "Report generated successfully!"
echo "================================================"
echo ""
echo "Open the report in your browser:"
echo "  file://$(pwd)/$OUTPUT_FILE"
echo ""
echo "Or run:"
echo "  open $OUTPUT_FILE    # macOS"
echo "  xdg-open $OUTPUT_FILE    # Linux"
echo ""
