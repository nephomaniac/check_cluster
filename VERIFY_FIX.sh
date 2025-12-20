#!/bin/bash
# Verification script for IAM tracking fix

set -e

CLUSTER_ID="2n8vju3lvso2737t2evim9oh4o1aof49"
DATA_DIR="test_fixed_iam_tracking"

echo "========================================="
echo "IAM API Tracking - Verification Script"
echo "========================================="
echo ""

# Step 1: Clean up old data
echo "Step 1: Cleaning up old test directory..."
rm -rf "$DATA_DIR"
echo "✓ Cleaned up"
echo ""

# Step 2: Collect data
echo "Step 2: Collecting cluster data..."
echo "Running: python get_install_artifacts.py -c $CLUSTER_ID -d $DATA_DIR"
python get_install_artifacts.py -c "$CLUSTER_ID" -d "$DATA_DIR" 2>&1 | tee /tmp/collection_output.txt
echo ""

# Step 3: Check API requests file
echo "Step 3: Checking API requests log..."
API_FILE="$DATA_DIR/sources/aws/${CLUSTER_ID}_api_requests.json"

if [ ! -f "$API_FILE" ]; then
    echo "❌ ERROR: API requests file not found: $API_FILE"
    exit 1
fi

echo "✓ API requests file exists"
echo ""

# Step 4: Check for IAM requests
echo "Step 4: Verifying IAM requests were tracked..."
IAM_COUNT=$(cat "$API_FILE" | jq '[.requests[] | select(.service == "iam")] | length')

echo "Total IAM requests tracked: $IAM_COUNT"

if [ "$IAM_COUNT" -eq 0 ]; then
    echo "❌ ERROR: No IAM requests were tracked!"
    echo ""
    echo "Total requests by service:"
    cat "$API_FILE" | jq -r '.requests[] | .service' | sort | uniq -c
    exit 1
fi

echo "✓ IAM requests are being tracked"
echo ""

echo "IAM operations tracked:"
cat "$API_FILE" | jq -r '.requests[] | select(.service == "iam") | "  - \(.operation) (\(.success))"'
echo ""

# Step 5: Check for errors
echo "Step 5: Checking for IAM errors..."
IAM_ERRORS=$(cat "$API_FILE" | jq '[.requests[] | select(.service == "iam" and .success == false)] | length')

if [ "$IAM_ERRORS" -gt 0 ]; then
    echo "⚠ Found $IAM_ERRORS IAM error(s) - these will be displayed in tests/HTML"
    echo ""
    echo "Failed IAM operations:"
    cat "$API_FILE" | jq '.requests[] | select(.service == "iam" and .success == false) | {operation, error_code: .error.code, error_message: .error.message, timestamp, response_code, duration_ms}'
    echo ""
else
    echo "✓ All IAM requests succeeded"
    echo ""
fi

# Step 6: Run tests
echo "Step 6: Running tests..."
echo "Running: ./run_tests.py --cluster-dir $DATA_DIR"
./run_tests.py --cluster-dir "$DATA_DIR" 2>&1 | tee /tmp/test_output.txt
TEST_EXIT_CODE=$?
echo ""

# Step 7: Check HTML report
echo "Step 7: Checking HTML report..."
HTML_FILE=$(ls -t "$DATA_DIR/results/"test_report_*.html 2>/dev/null | head -1)

if [ -z "$HTML_FILE" ]; then
    HTML_FILE=$(ls -t "$DATA_DIR/"test_report_*.html 2>/dev/null | head -1)
fi

if [ -n "$HTML_FILE" ]; then
    echo "✓ HTML report generated: $HTML_FILE"

    # Check if HTML contains API request errors section
    if grep -q "API Request Errors" "$HTML_FILE"; then
        echo "✓ HTML report contains 'API Request Errors' section"
    else
        echo "ℹ HTML report does not contain API error section (tests may have passed)"
    fi

    echo ""
    echo "Open HTML report:"
    echo "  open \"$HTML_FILE\""
else
    echo "⚠ HTML report not found"
fi

echo ""
echo "========================================="
echo "Verification Complete!"
echo "========================================="
echo ""
echo "Summary:"
echo "  ✓ IAM requests tracked: $IAM_COUNT"
if [ "$IAM_ERRORS" -gt 0 ]; then
    echo "  ⚠ IAM errors found: $IAM_ERRORS (will be shown in test output)"
fi
echo "  ✓ Tests executed (exit code: $TEST_EXIT_CODE)"
echo ""
echo "Next steps:"
echo "  1. Review test output: /tmp/test_output.txt"
echo "  2. Open HTML report: $HTML_FILE"
echo "  3. Check for 'API Request Errors' section in failed tests"
echo ""
