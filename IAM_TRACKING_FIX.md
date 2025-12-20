# IAM API Request Tracking - CRITICAL FIX

## Problem Found

The IAM API methods in `get_install_artifacts.py` were **NOT** using the `_make_tracked_request()` wrapper. This meant:

1. ❌ IAM API calls were NOT tracked in `api_requests.json`
2. ❌ IAM permission errors were NOT captured
3. ❌ Tests couldn't display IAM error details (timestamp, response code, duration)
4. ❌ HTML report couldn't show IAM API errors

## Root Cause

**Before the fix:**
```python
def list_attached_role_policies(self, role_name: str) -> Dict:
    """List attached managed policies for IAM role"""
    try:
        return self.iam.list_attached_role_policies(RoleName=role_name)
    except (self.ClientError, self.BotoCoreError) as e:
        self._handle_aws_error(e, f'list attached role policies for {role_name}')
        # Exception raised but NOT tracked!
```

This meant IAM calls were never logged to `api_requests.json`.

## What Was Fixed

Updated **5 IAM methods** to use tracked requests:

1. ✅ `get_iam_role()` - Now tracked (lines 1110-1119)
2. ✅ `list_role_policies()` - Now tracked (lines 1121-1130)
3. ✅ `list_attached_role_policies()` - Now tracked (lines 1132-1141)
4. ✅ `list_open_id_connect_providers()` - Now tracked (lines 1143-1152)
5. ✅ `get_open_id_connect_provider()` - Now tracked (lines 1154-1163)

**After the fix:**
```python
def list_attached_role_policies(self, role_name: str) -> Dict:
    """List attached managed policies for IAM role"""
    return self._make_tracked_request(
        service='iam',
        operation='list_attached_role_policies',
        func=lambda: self.iam.list_attached_role_policies(RoleName=role_name),
        params={'RoleName': role_name},
        description=f'list attached role policies for {role_name}'
    )
```

Now every IAM call is tracked with:
- ✅ Timestamp
- ✅ Response code (403, 404, etc.)
- ✅ Duration (ms)
- ✅ Error details (if failed)

## How to Verify the Fix

### Step 1: Delete existing cluster data directory

```bash
rm -rf new_2n8vju3lvso2737t2evim9oh4o1aof49
```

### Step 2: Re-collect data with fixed script

```bash
# Get AWS credentials
eval $(ocm backplane cloud credentials 2n8vju3lvso2737t2evim9oh4o1aof49 -o env)

# Collect data
python get_install_artifacts.py -c 2n8vju3lvso2737t2evim9oh4o1aof49 -d new_2n8vju3lvso2737t2evim9oh4o1aof49
```

### Step 3: Check API requests were tracked

```bash
# Should show IAM requests now!
cat new_2n8vju3lvso2737t2evim9oh4o1aof49/sources/aws/*_api_requests.json | jq '.summary'
```

**Expected output:**
```json
{
  "total_requests": 50,              ← Should be much higher now
  "successful_requests": 45,
  "failed_requests": 5,              ← If IAM permissions missing
  "permission_errors": 5,             ← These will show in tests
  ...
}
```

Check for IAM requests:
```bash
cat new_2n8vju3lvso2737t2evim9oh4o1aof49/sources/aws/*_api_requests.json | jq '.requests[] | select(.service == "iam")'
```

### Step 4: Run tests

```bash
./run_tests.py --cluster-dir new_2n8vju3lvso2737t2evim9oh4o1aof49
```

### Step 5: Verify error display

**Console Output - Test Failures:**
```
❌ Failed Policy API Calls:

  Operation: list_attached_role_policies
  Error Code: AccessDenied
  Error Message: You are not authorized to perform this operation.
  Timestamp: 2025-12-19T22:57:23Z          ← NOW SHOWS
  Response Code: 403                        ← NOW SHOWS
  Duration: 234ms                          ← NOW SHOWS
  Role ARN: ManagedOpenShift-Installer-Role
```

**HTML Report:**
- Open the generated HTML file
- Failed tests will have "🚫 API Request Errors" section
- Shows:
  - Color-coded error badges (red for permissions)
  - Timestamp, response code, duration
  - Inline remediation guidance

### Step 6: Verify security group events

If you have security group revoke events in CloudTrail:

```
Found 2 security group revoke events:
2025-12-19 10:30:15 - RevokeSecurityGroupIngress by john.doe
  Security Group: sg-0123456789abcdef0          ← NOW SHOWS
  Revoked Rules:                                ← NOW SHOWS
    - Protocol tcp, Ports 22-22, CIDR: 0.0.0.0/0
```

## Summary of All Fixes

1. ✅ **IAM API tracking** - All IAM calls now tracked (THIS FIX)
2. ✅ **Test error display** - Tests show timestamp, response code, duration
3. ✅ **HTML report** - API errors displayed with color coding
4. ✅ **Security group events** - Shows security group ID and revoked rules
5. ✅ **conftest.py hook** - Captures API errors to user_properties
6. ✅ **run_tests.py** - Fixed invalid pytest flag

## Why This Fixes Your Issue

**Before:**
- IAM calls not tracked → Empty `api_requests.json` for IAM
- Tests fail but can't explain WHY (no API error data)
- HTML report has no error information

**After:**
- All IAM calls tracked → Complete `api_requests.json`
- Tests show EXACTLY what failed (timestamp, code, duration)
- HTML report shows all errors with remediation
- You can diagnose permission issues immediately

## Testing Different Scenarios

### Scenario 1: All Permissions Available
- All IAM calls succeed
- Policy files created
- Tests pass

### Scenario 2: Missing IAM Permissions
- IAM calls fail with AccessDenied
- API request log captures all failures
- Tests show detailed error information
- HTML report displays permission errors with remediation

### Scenario 3: AWS Service Issues
- IAM calls fail with 5xx errors
- Request log captures service errors
- Tests show service error details
- Can distinguish from permission issues

## Next Steps

1. **Delete old cluster data directory**
2. **Re-run data collection** with the fixed script
3. **Run tests** and verify error details are shown
4. **Check HTML report** for complete error display

The fix is complete and ready to use!
