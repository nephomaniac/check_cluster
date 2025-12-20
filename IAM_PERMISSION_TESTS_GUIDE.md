# IAM Permission Tests Guide

## Overview

The IAM permission tests (`tests/test_iam_permissions.py`) validate AWS IAM permissions by analyzing the API request log created during cluster data collection. These tests help diagnose cluster installation and support issues related to missing or insufficient IAM permissions.

## How It Works

1. **Data Collection**: When `get_install_artifacts.py` runs, it creates `{cluster_id}_api_requests.json` containing all AWS API requests with their success/failure status
2. **Test Execution**: The IAM permission tests analyze this log to identify permission errors
3. **HTML Report**: Permission errors are displayed in the test report with remediation guidance

## Test Categories

### Critical Tests

#### `test_no_permission_errors_in_api_requests`
- **Purpose**: Ensures no permission-denied errors occurred during data collection
- **Error Codes Checked**:
  - `AccessDenied`
  - `UnauthorizedOperation`
  - `Forbidden`
  - `AccessDeniedException`
- **Output**: Lists all permission errors grouped by AWS service
- **Severity**: CRITICAL

#### `test_critical_operations_succeeded`
- **Purpose**: Validates that essential AWS operations completed successfully
- **Critical Operations**:
  - `ec2:describe_instances`
  - `ec2:describe_vpcs`
  - `ec2:describe_subnets`
  - `ec2:describe_security_groups`
  - `elbv2:describe_load_balancers`
  - `elbv2:describe_target_groups`
- **Severity**: HIGH

### Service-Specific Permission Tests

#### `test_ec2_permissions_available`
- **Validates**: EC2 describe permissions
- **Required Permissions**:
  ```json
  {
    "Effect": "Allow",
    "Action": [
      "ec2:DescribeInstances",
      "ec2:DescribeVpcs",
      "ec2:DescribeSubnets",
      "ec2:DescribeSecurityGroups",
      "ec2:DescribeVolumes",
      "ec2:DescribeNetworkInterfaces",
      "ec2:DescribeRouteTables",
      "ec2:DescribeInternetGateways",
      "ec2:DescribeNatGateways"
    ],
    "Resource": "*"
  }
  ```
- **Severity**: MEDIUM

#### `test_elb_permissions_available`
- **Validates**: ELB/ELBv2 describe permissions
- **Required Permissions**:
  ```json
  {
    "Effect": "Allow",
    "Action": [
      "elasticloadbalancing:DescribeLoadBalancers",
      "elasticloadbalancing:DescribeTargetGroups",
      "elasticloadbalancing:DescribeTargetHealth",
      "elasticloadbalancing:DescribeListeners"
    ],
    "Resource": "*"
  }
  ```
- **Severity**: MEDIUM

#### `test_route53_permissions_available`
- **Validates**: Route53 permissions
- **Required Permissions**:
  ```json
  {
    "Effect": "Allow",
    "Action": [
      "route53:ListHostedZones",
      "route53:ListResourceRecordSets",
      "route53:GetHostedZone"
    ],
    "Resource": "*"
  }
  ```
- **Severity**: MEDIUM

#### `test_iam_permissions_available`
- **Validates**: IAM describe permissions
- **Required Permissions**:
  ```json
  {
    "Effect": "Allow",
    "Action": [
      "iam:ListInstanceProfiles",
      "iam:GetRole",
      "iam:GetInstanceProfile"
    ],
    "Resource": "*"
  }
  ```
- **Severity**: LOW

### General Validation Tests

#### `test_no_failed_api_requests`
- **Purpose**: Checks for any failed API requests
- **Output**: Summary of all failures categorized by error code
- **Severity**: HIGH

#### `test_no_throttling_errors`
- **Purpose**: Detects AWS API rate limiting issues
- **Throttling Error Codes**:
  - `Throttling`
  - `RequestLimitExceeded`
  - `TooManyRequestsException`
  - `ThrottlingException`
- **Remediation**: Retry data collection or request rate limit increase
- **Severity**: MEDIUM

#### `test_api_request_summary`
- **Purpose**: Displays overview of all API requests
- **Output**:
  - Total requests, success/failure counts
  - Breakdown by AWS service
  - Error categories
- **Severity**: INFO (informational only)

## Running the Tests

### Run All IAM Permission Tests
```bash
pytest tests/test_iam_permissions.py -v
```

### Run Specific Test
```bash
pytest tests/test_iam_permissions.py::test_no_permission_errors_in_api_requests -v
```

### Run Tests by Severity
```bash
# Critical tests only
pytest -m "severity=='CRITICAL'" tests/test_iam_permissions.py -v

# High priority tests
pytest -m "severity=='HIGH'" tests/test_iam_permissions.py -v
```

### Run with Cluster Data
```bash
pytest tests/test_iam_permissions.py --cluster-dir=/path/to/cluster/data -v
```

## Understanding Test Output

### Successful Permission Validation
```
test_ec2_permissions_available PASSED

✓ EC2 permissions validated - 15 operations succeeded
```

### Permission Error Detected
```
test_ec2_permissions_available FAILED

✗ Found 2 EC2 permission error(s):
[
  {
    "operation": "describe_instances",
    "error": "User: arn:aws:iam::123456789012:user/test-user is not authorized to perform: ec2:DescribeInstances"
  },
  {
    "operation": "describe_vpcs",
    "error": "User: arn:aws:iam::123456789012:user/test-user is not authorized to perform: ec2:DescribeVpcs"
  }
]

EC2 permissions missing for: describe_instances, describe_vpcs
```

## Remediation Workflow

When permission errors are found:

1. **Identify the Service and Operations**
   - Check test output for specific service and operation names
   - Example: `ec2.describe_instances`, `elbv2.describe_load_balancers`

2. **Review Current IAM Policy**
   ```bash
   aws iam get-user-policy --user-name <username> --policy-name <policy-name>
   # or for roles:
   aws iam get-role-policy --role-name <role-name> --policy-name <policy-name>
   ```

3. **Add Missing Permissions**
   - Update the IAM policy to include missing actions
   - See service-specific permission examples above

4. **Verify Permissions**
   ```bash
   # Test individual permission
   aws ec2 describe-instances --dry-run

   # Re-run data collection
   python get_install_artifacts.py

   # Re-run tests
   pytest tests/test_iam_permissions.py -v
   ```

## Complete IAM Policy Template

Here's a complete IAM policy with all permissions needed for cluster diagnostics:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "EC2Permissions",
      "Effect": "Allow",
      "Action": [
        "ec2:DescribeInstances",
        "ec2:DescribeInstanceStatus",
        "ec2:DescribeInstanceAttribute",
        "ec2:DescribeVpcs",
        "ec2:DescribeSubnets",
        "ec2:DescribeSecurityGroups",
        "ec2:DescribeSecurityGroupRules",
        "ec2:DescribeVolumes",
        "ec2:DescribeVolumeStatus",
        "ec2:DescribeNetworkInterfaces",
        "ec2:DescribeRouteTables",
        "ec2:DescribeInternetGateways",
        "ec2:DescribeNatGateways",
        "ec2:DescribeVpcEndpoints",
        "ec2:DescribeAvailabilityZones",
        "ec2:DescribeRegions"
      ],
      "Resource": "*"
    },
    {
      "Sid": "ELBPermissions",
      "Effect": "Allow",
      "Action": [
        "elasticloadbalancing:DescribeLoadBalancers",
        "elasticloadbalancing:DescribeLoadBalancerAttributes",
        "elasticloadbalancing:DescribeTargetGroups",
        "elasticloadbalancing:DescribeTargetHealth",
        "elasticloadbalancing:DescribeListeners",
        "elasticloadbalancing:DescribeRules"
      ],
      "Resource": "*"
    },
    {
      "Sid": "Route53Permissions",
      "Effect": "Allow",
      "Action": [
        "route53:ListHostedZones",
        "route53:ListResourceRecordSets",
        "route53:GetHostedZone"
      ],
      "Resource": "*"
    },
    {
      "Sid": "IAMPermissions",
      "Effect": "Allow",
      "Action": [
        "iam:ListInstanceProfiles",
        "iam:GetRole",
        "iam:GetInstanceProfile",
        "iam:GetOpenIDConnectProvider"
      ],
      "Resource": "*"
    },
    {
      "Sid": "AutoScalingPermissions",
      "Effect": "Allow",
      "Action": [
        "autoscaling:DescribeAutoScalingGroups",
        "autoscaling:DescribeLaunchConfigurations"
      ],
      "Resource": "*"
    },
    {
      "Sid": "CloudTrailPermissions",
      "Effect": "Allow",
      "Action": [
        "cloudtrail:LookupEvents"
      ],
      "Resource": "*"
    },
    {
      "Sid": "STSPermissions",
      "Effect": "Allow",
      "Action": [
        "sts:GetCallerIdentity"
      ],
      "Resource": "*"
    }
  ]
}
```

## Integration with HTML Reports

Permission errors detected by these tests are automatically included in the HTML test report:

- **Test Details Section**: Shows the specific permission error
- **Remediation Section**: Displays required IAM permissions from test docstring
- **Severity Badge**: Color-coded by severity level (CRITICAL, HIGH, MEDIUM, LOW, INFO)

## Best Practices

1. **Run Permission Tests First**: Identify missing permissions before running resource validation tests
2. **Review Summary Test**: `test_api_request_summary` provides good overview of data collection status
3. **Check Critical Operations**: Ensure `test_critical_operations_succeeded` passes for comprehensive diagnostics
4. **Monitor Throttling**: If `test_no_throttling_errors` fails, add delays or request rate limit increase
5. **Validate After Changes**: Re-run tests after updating IAM policies to verify fixes

## Troubleshooting

### Test is Skipped
```
test_ec2_permissions_available SKIPPED (API request log not available)
```
**Solution**: Ensure `get_install_artifacts.py` completed successfully and created the API request log

### False Negatives
If tests pass but data is missing:
- Check `test_api_request_summary` for overall success rate
- Some operations may not have been attempted (no request = no error)
- Review individual resource tests for missing data

### Permission Errors in Other Tests
If permission errors appear in resource validation tests (not IAM tests):
- The request tracker may not have been enabled during data collection
- Re-run data collection with updated `get_install_artifacts.py`

## Related Documentation

- `AWS_REQUEST_TRACKING_IMPLEMENTATION.md` - API request tracking implementation details
- `TEST_CLOUDTRAIL_CORRELATION_EXAMPLE.md` - CloudTrail event correlation patterns
- AWS IAM Documentation: https://docs.aws.amazon.com/IAM/latest/UserGuide/
