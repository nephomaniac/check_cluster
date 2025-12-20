# Quick Start - Individual IAM Tests

## New Structure

IAM tests have been split into individual, granular tests for better diagnostics and HTML report output.

## Test Files

### 1. Installer Role Tests
**File**: `tests/test_rosa_installer_role.py`

**Tests** (3 total):
- ✓ `test_installer_role_exists` - CRITICAL
- ✓ `test_installer_role_has_managed_policy` - HIGH
- ✓ `test_installer_role_trust_policy` - MEDIUM

**Run**:
```bash
pytest tests/test_rosa_installer_role.py -v
```

### 2. Worker Role Tests
**File**: `tests/test_rosa_worker_role.py`

**Tests** (3 total):
- ✓ `test_worker_role_exists` - CRITICAL
- ✓ `test_worker_role_has_managed_policy` - HIGH
- ✓ `test_worker_role_has_instance_profile` - MEDIUM

**Run**:
```bash
pytest tests/test_rosa_worker_role.py -v
```

### 3. Operator Role Tests
**File**: `tests/test_rosa_operator_roles.py`

**Tests** (10 total):
- ✓ `test_ebs_csi_driver_operator_role_exists` - CRITICAL
- ✓ `test_cloud_credentials_operator_role_exists` - HIGH
- ✓ `test_ingress_operator_role_exists` - HIGH
- ✓ `test_image_registry_operator_role_exists` - HIGH
- ✓ `test_machine_api_operator_role_exists` - HIGH
- ✓ `test_cloud_network_config_controller_role_exists` - MEDIUM
- ✓ `test_cloud_controller_manager_role_exists` - LOW
- ✓ `test_control_plane_operator_role_exists` - LOW
- ✓ `test_kube_controller_manager_role_exists` - LOW
- ✓ `test_operator_roles_summary` - INFO

**Run**:
```bash
pytest tests/test_rosa_operator_roles.py -v
```

### 4. Permission Validation Tests
**File**: `tests/test_iam_permission_validation.py`

**Tests** (9 total with checkbox output):
- ✓ `test_ec2_describe_instances_permission` - CRITICAL
- ✓ `test_ec2_vpc_permissions` - HIGH (5 permissions checked)
- ✓ `test_ec2_volume_permissions` - HIGH (2 permissions checked)
- ✓ `test_elb_describe_permissions` - HIGH (4 permissions checked)
- ✓ `test_route53_permissions` - MEDIUM (3 permissions checked)
- ✓ `test_iam_read_permissions` - MEDIUM (4 permissions checked)
- ✓ `test_s3_permissions` - LOW (optional)
- ✓ `test_cloudtrail_permissions` - LOW (optional)
- ✓ `test_all_permissions_summary` - INFO

**Run**:
```bash
pytest tests/test_iam_permission_validation.py -v
```

## Common Commands

### Run All New IAM Tests
```bash
pytest tests/test_rosa_*.py tests/test_iam_permission_validation.py -v
```

### Run Only Critical Tests
```bash
pytest tests/test_rosa_*.py tests/test_iam_permission_validation.py -m "severity=='CRITICAL'" -v
```

### Run Only IAM Role Tests
```bash
pytest -m iam_roles -v
```

### Run Only Operator Role Tests
```bash
pytest -m operator_roles -v
```

### Run Only Permission Validation Tests
```bash
pytest -m iam_permissions -v
```

### Run Specific Test
```bash
pytest tests/test_rosa_operator_roles.py::test_ebs_csi_driver_operator_role_exists -v
```

### Generate HTML Report
```bash
# Run tests with JSON output
pytest tests/test_rosa_*.py tests/test_iam_permission_validation.py \
  --cluster-dir=/path/to/cluster \
  --json-report --json-report-file=test_results.json

# Generate HTML report
python reporters/html_generator.py test_results.json /path/to/cluster cluster_health_report.html
```

## What's Different?

### Before (Grouped Tests)
```
❌ test_operator_roles_exist - FAILED
   Missing operator roles: ebs-csi-driver, machine-api
```

### After (Individual Tests)
```
✓ test_ebs_csi_driver_operator_role_exists - PASSED
✓ test_cloud_credentials_operator_role_exists - PASSED
✓ test_ingress_operator_role_exists - PASSED
✓ test_image_registry_operator_role_exists - PASSED
❌ test_machine_api_operator_role_exists - FAILED

   Machine API operator role not found.

   📋 Diagnostic Information:
     • Other operator roles were found, but not Machine API role

   💡 Possible Causes:
     1. Machine API operator role was not created
     2. Role was deleted after cluster creation

   🔧 Remediation:
     • Create missing operator role:
       rosa create operator-roles --cluster <cluster-name> --mode manual
```

## Key Features

### ✓ Granular Pass/Fail
Each IAM resource gets its own test result in the HTML report

### ✓ Enhanced Diagnostics
When resources are missing, tests explain:
- Is API request log available?
- Were IAM API calls made?
- Did API calls succeed or fail?
- If failed, what was the error?
- Does resource exist in AWS?
- Are files corrupted?

### ✓ Checkbox Output for Permissions
```
EC2 VPC Permissions
────────────────────────────────────────────────────────────────────────────────
  ☑ ec2:DescribeVpcs                                         [GRANTED]
  ☑ ec2:DescribeSubnets                                      [GRANTED]
  ☐ ec2:DescribeRouteTables                                  [MISSING]
  ☑ ec2:DescribeSecurityGroups                               [GRANTED]
  ☑ ec2:DescribeNetworkInterfaces                            [GRANTED]
────────────────────────────────────────────────────────────────────────────────
  Summary: 4/5 permissions verified
```

### ✓ Specific Remediation Steps
Each failure includes exact commands to fix the issue:
```
🔧 Remediation:
  • Attach policy:
    aws iam attach-role-policy --role-name my-cluster-Worker-Role \
      --policy-arn arn:aws:iam::aws:policy/ROSAWorkerInstancePolicy
```

## Pytest Markers

All tests include markers for filtering:

- `@pytest.mark.aws_resources` - AWS resource tests
- `@pytest.mark.iam_roles` - IAM role tests
- `@pytest.mark.operator_roles` - Operator role tests
- `@pytest.mark.iam_permissions` - Permission validation tests
- `@pytest.mark.severity("CRITICAL"|"HIGH"|"MEDIUM"|"LOW"|"INFO")` - Test severity

### Filter by Marker
```bash
# Only operator roles
pytest -m operator_roles -v

# Only critical severity
pytest -m "severity=='CRITICAL'" -v

# IAM roles but not permissions
pytest -m "iam_roles and not iam_permissions" -v
```

## Example Output

### Successful Test
```
$ pytest tests/test_rosa_installer_role.py::test_installer_role_exists -v

tests/test_rosa_installer_role.py::test_installer_role_exists PASSED

-------------------------------- Captured stdout ---------------------------------
✓ Found installer role: my-cluster-Installer-Role
  ARN: arn:aws:iam::123456789012:role/my-cluster-Installer-Role
  File: cluster123_iam_role_installer_my-cluster-Installer-Role.json
  Type tag: installer
  Managed tag: true
```

### Failed Test with Diagnostics
```
$ pytest tests/test_rosa_worker_role.py::test_worker_role_has_managed_policy -v

tests/test_rosa_worker_role.py::test_worker_role_has_managed_policy FAILED

-------------------------------- Captured stdout ---------------------------------

❌ Worker role 'my-cluster-Worker-Role' has no attached policies.

📋 Diagnostic Information:
  • Policies file exists but shows no policies

🔧 Remediation:
  • Attach policy:
    aws iam attach-role-policy --role-name my-cluster-Worker-Role \
      --policy-arn arn:aws:iam::aws:policy/ROSAWorkerInstancePolicy

📄 Required Policy:
  • AWS Managed: arn:aws:iam::aws:policy/ROSAWorkerInstancePolicy
  • Required permissions:
    - ecr:GetAuthorizationToken, ecr:BatchGetImage
    - ec2:DescribeInstances, ec2:DescribeRegions
```

### Permission Test with Checkboxes
```
$ pytest tests/test_iam_permission_validation.py::test_ec2_vpc_permissions -v

tests/test_iam_permission_validation.py::test_ec2_vpc_permissions PASSED

-------------------------------- Captured stdout ---------------------------------

EC2 VPC Permissions
────────────────────────────────────────────────────────────────────────────────
  ☑ ec2:DescribeVpcs                                         [GRANTED]
  ☑ ec2:DescribeSubnets                                      [GRANTED]
  ☑ ec2:DescribeRouteTables                                  [GRANTED]
  ☑ ec2:DescribeSecurityGroups                               [GRANTED]
  ☑ ec2:DescribeNetworkInterfaces                            [GRANTED]
────────────────────────────────────────────────────────────────────────────────
  Summary: 5/5 permissions verified
```

## Backward Compatibility

Old test files still work:
- `tests/test_rosa_iam_resources.py`
- `tests/test_iam_permissions.py`

But new files are recommended for:
- Better HTML reports
- Detailed diagnostics
- Granular test results
- Easier troubleshooting

## Next Steps

1. **Run all IAM tests** to verify cluster IAM configuration
2. **Check HTML report** for detailed results and diagnostics
3. **Address failures** using specific remediation steps
4. **Re-run tests** to verify fixes

## Documentation

- `IAM_TESTS_RESTRUCTURED.md` - Complete restructuring documentation
- `IAM_PERMISSION_TESTS_GUIDE.md` - IAM permission testing guide
- `ROSA_OSD_IAM_REQUIREMENTS.md` - ROSA/OSD IAM requirements reference

## Summary

**25 individual tests** across 4 test files:
- 3 installer role tests
- 3 worker role tests
- 10 operator role tests
- 9 permission validation tests

All tests include:
- ✓ Severity levels
- ✓ Comprehensive diagnostics
- ✓ Specific remediation steps
- ✓ HTML report integration
- ✓ Pytest markers for filtering
