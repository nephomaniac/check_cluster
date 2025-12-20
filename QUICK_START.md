# Quick Start - Verify the Fix Works

## The Fix

✅ **Script Error:** Fixed - used correct method `_tracked_request()` instead of `_make_tracked_request()`
✅ **IAM Tracking:** Fixed - all 5 IAM methods now track requests
✅ **Error Display:** Already working - tests and HTML show complete error details

## Test It Now

```bash
# 1. Get credentials
eval $(ocm backplane cloud credentials 2n8vju3lvso2737t2evim9oh4o1aof49 -o env)

# 2. Run automated verification
./VERIFY_FIX.sh
```

**That's it!** The script will collect data, run tests, and show you the results.

## What You'll See

### ✅ Success Case (If IAM permissions available)

```
Step 4: Verifying IAM requests were tracked...
Total IAM requests tracked: 15
✓ IAM requests are being tracked

IAM operations tracked:
  - get_role (true)
  - list_role_policies (true)
  - list_attached_role_policies (true)
  ...

Step 5: Checking for IAM errors...
✓ All IAM requests succeeded
```

### ⚠️ Error Case (If IAM permissions missing)

```
Step 4: Verifying IAM requests were tracked...
Total IAM requests tracked: 15
✓ IAM requests are being tracked

Step 5: Checking for IAM errors...
⚠ Found 5 IAM error(s) - these will be displayed in tests/HTML

Failed IAM operations:
{
  "operation": "list_attached_role_policies",
  "error_code": "AccessDenied",
  "error_message": "User: ... is not authorized...",
  "timestamp": "2025-12-19T23:15:42Z",
  "response_code": 403,
  "duration_ms": 187
}
```

Then in test output:

```
❌ Failed Policy API Calls:

  Operation: list_attached_role_policies
  Error Code: AccessDenied
  Error Message: User: ... is not authorized...
  Timestamp: 2025-12-19T23:15:42Z          ← SHOWS WHEN
  Response Code: 403                        ← SHOWS HTTP CODE
  Duration: 187ms                          ← SHOWS HOW LONG
```

And in HTML report:

```
🚫 API Request Errors (5)
  [AccessDenied] list_attached_role_policies
  Time: 2025-12-19T23:15:42Z
  Response Code: 403
  Duration: 187ms
  💡 Remediation: IAM permissions missing...
```

## Manual Steps (If You Prefer)

```bash
# Clean up
rm -rf test_manual

# Collect data
python get_install_artifacts.py -c 2n8vju3lvso2737t2evim9oh4o1aof49 -d test_manual

# Verify IAM tracking
cat test_manual/sources/aws/*_api_requests.json | jq '.requests[] | select(.service == "iam") | {operation, success, timestamp, response_code, duration_ms}'

# Run tests
./run_tests.py --cluster-dir test_manual

# Open HTML
open test_manual/results/test_report_*.html
```

## Key Files

- **`COMPLETE_FIX_SUMMARY.md`** - Detailed explanation of all fixes
- **`IAM_TRACKING_FIX.md`** - Technical details of the IAM tracking fix
- **`VERIFY_FIX.sh`** - Automated verification script
- **`QUICK_START.md`** - This file

## Need Help?

Check `COMPLETE_FIX_SUMMARY.md` for:
- What was broken
- What was fixed
- Expected output for different scenarios
- Troubleshooting guide
