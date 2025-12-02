# AWS Resources from cluster.json Feature

## Overview

This feature automatically fetches AWS IAM resources and OIDC providers specified in the cluster configuration at `.aws.sts`. This enables comprehensive validation of STS (Security Token Service) cluster configurations.

## Architecture

### Data Collection (`get_install_artifacts.py`)

#### New AWS Collector Methods

**IAM Methods (lines 1024-1062)**:
- `get_iam_role(role_name)` - Fetch IAM role details
- `list_role_policies(role_name)` - List inline policies
- `list_attached_role_policies(role_name)` - List attached managed policies
- `list_open_id_connect_providers()` - List all OIDC providers
- `get_open_id_connect_provider(arn)` - Get OIDC provider details

#### New Collection Methods

**`_get_iam_resources_from_cluster_json()` (lines 1682-1747)**
- Reads `.aws.sts` section from cluster.json
- Extracts IAM role ARNs for:
  - Installer role (`sts.role_arn`)
  - Support role (`sts.support_role_arn`)
  - Master instance role (`sts.instance_iam_roles.master_role_arn`)
  - Worker instance role (`sts.instance_iam_roles.worker_role_arn`)
  - Operator roles (`sts.operator_iam_roles[]`)
  - Audit log role (`aws.audit_log.role_arn`)
- Extracts OIDC endpoint URL (`sts.oidc_endpoint_url`)
- Calls `_fetch_iam_role()` and `_fetch_oidc_provider()` for each resource

**`_fetch_iam_role(role_type, role_arn)` (lines 1749-1807)**
- Extracts role name from ARN
- Fetches role details → `<cluster_id>_iam_role_<type>_<name>.json`
- Fetches inline policies → `<cluster_id>_iam_role_<type>_<name>_policies.json`
- Fetches attached policies → `<cluster_id>_iam_role_<type>_<name>_attached_policies.json`

**`_fetch_oidc_provider(oidc_url)` (lines 1809-1872)**
- Lists all OIDC providers → `<cluster_id>_oidc_providers_list.json`
- Finds matching provider by cluster ID
- Fetches provider details → `<cluster_id>_oidc_provider_<arn>.json`

## Test Suite (`tests/test_aws_resources.py`)

### Test Coverage (10 tests)

1. **`test_sts_configuration_exists`**
   - Validates STS is enabled and configured
   - Checks for required fields (role_arn, oidc_endpoint_url)

2. **`test_installer_role_fetched`**
   - Ensures installer role file exists
   - Critical for cluster provisioning

3. **`test_support_role_fetched`**
   - Ensures support role file exists
   - Required for Red Hat SRE access

4. **`test_master_instance_role_fetched`**
   - Ensures master/control plane role file exists
   - Required for master node AWS access

5. **`test_worker_instance_role_fetched`**
   - Ensures worker instance role file exists
   - Required for worker node AWS access

6. **`test_all_operator_roles_fetched`**
   - Validates all operator role files exist
   - Typically 6 operator roles (EBS CSI, ingress, image registry, etc.)

7. **`test_iam_roles_have_policies_fetched`**
   - Ensures policy files exist for roles
   - Helps troubleshoot permission issues

8. **`test_oidc_provider_fetched`**
   - Validates OIDC provider list and details files
   - Critical for STS authentication

9. **`test_iam_role_files_contain_valid_data`**
   - Validates file structure and data integrity
   - Checks for required fields

10. **`test_audit_log_role_fetched_if_configured`**
    - Optional test for audit logging configuration
    - Only validates if audit log role is configured

## File Naming Conventions

### IAM Role Files
**Format**: `<cluster_id>_iam_role_<type>_<role_name>.json`

**Types**:
- `installer` - Installer role
- `support` - Support role
- `master` - Master/ControlPlane instance role
- `worker` - Worker instance role
- `operator-<namespace>-<name>` - Operator roles
- `audit-log` - Audit log role (if configured)

**Examples**:
```
2mmfeq6n72nis2kekgvim4k1lmrho0ri_iam_role_installer_maclarktest-Installer-Role.json
2mmfeq6n72nis2kekgvim4k1lmrho0ri_iam_role_support_maclarktest-Support-Role.json
2mmfeq6n72nis2kekgvim4k1lmrho0ri_iam_role_master_maclarktest-ControlPlane-Role.json
2mmfeq6n72nis2kekgvim4k1lmrho0ri_iam_role_worker_maclarktest-Worker-Role.json
2mmfeq6n72nis2kekgvim4k1lmrho0ri_iam_role_operator-openshift-ingress-operator-cloud-credentials_maclarkrosa1120-d0k8-openshift-ingress-operator-cloud-credential.json
```

### IAM Policy Files
**Formats**:
- `<cluster_id>_iam_role_<type>_<role_name>_policies.json` - Inline policies
- `<cluster_id>_iam_role_<type>_<role_name>_attached_policies.json` - Attached policies

### OIDC Provider Files
**Formats**:
- `<cluster_id>_oidc_providers_list.json` - List of all providers
- `<cluster_id>_oidc_provider_<sanitized_arn>.json` - Provider details

## cluster.json Structure

### STS Configuration
```json
{
  "aws": {
    "sts": {
      "enabled": true,
      "role_arn": "arn:aws:iam::ACCOUNT:role/Installer-Role",
      "support_role_arn": "arn:aws:iam::ACCOUNT:role/Support-Role",
      "oidc_endpoint_url": "https://oidc.example.com/cluster-id",
      "operator_iam_roles": [
        {
          "name": "ebs-cloud-credentials",
          "namespace": "openshift-cluster-csi-drivers",
          "role_arn": "arn:aws:iam::ACCOUNT:role/...",
          "service_account": ""
        }
      ],
      "instance_iam_roles": {
        "master_role_arn": "arn:aws:iam::ACCOUNT:role/ControlPlane-Role",
        "worker_role_arn": "arn:aws:iam::ACCOUNT:role/Worker-Role"
      }
    },
    "audit_log": {
      "role_arn": "arn:aws:iam::ACCOUNT:role/Audit-Role"
    }
  }
}
```

## Usage

### Running Data Collection
```bash
# Standard collection (includes IAM resources for STS clusters)
python get_install_artifacts.py --cluster-name my-rosa-cluster

# The script will:
# 1. Load cluster.json
# 2. Check for aws.sts.enabled
# 3. Extract all IAM role ARNs
# 4. Fetch each role and its policies
# 5. Extract OIDC endpoint URL
# 6. Fetch OIDC provider details
```

### Running AWS Resources Tests
```bash
# Run all AWS resources tests
pytest tests/test_aws_resources.py --cluster-dir=<data_directory> -v

# Run specific test
pytest tests/test_aws_resources.py::test_installer_role_fetched \
  --cluster-dir=<data_directory> -v
```

### Expected Behavior

**For STS Clusters**:
- 10 tests execute validation
- Tests verify all roles and OIDC provider were fetched
- Detailed failure messages guide remediation

**For Non-STS Clusters**:
- All 10 tests skip with message: "STS not enabled"
- No false failures for non-STS clusters

## AWS Permissions Required

### For IAM Role Fetching
```json
{
  "Effect": "Allow",
  "Action": [
    "iam:GetRole",
    "iam:ListRolePolicies",
    "iam:ListAttachedRolePolicies"
  ],
  "Resource": "*"
}
```

### For OIDC Provider Fetching
```json
{
  "Effect": "Allow",
  "Action": [
    "iam:ListOpenIDConnectProviders",
    "iam:GetOpenIDConnectProvider"
  ],
  "Resource": "*"
}
```

## Error Handling

### Role Not Found
**Scenario**: Role ARN in cluster.json doesn't exist in AWS

**Error Message**:
```
Failed to fetch IAM role {role_name}: {error}
```

**Common Causes**:
- Role was deleted after cluster creation
- Wrong AWS account
- Insufficient permissions

**Test Failure**:
```
test_installer_role_fetched FAILED
AssertionError: Installer role file not found: ....json
Run get_install_artifacts.py to fetch IAM resources.
```

### OIDC Provider Not Found
**Scenario**: OIDC provider doesn't exist in AWS

**Error Message**:
```
No OIDC provider found matching cluster ID: {cluster_id}
```

**Common Causes**:
- Provider was deleted
- Wrong AWS account
- Cluster not fully provisioned

## Troubleshooting Guide

### Problem: Tests are skipping
**Solution**: This is expected if STS is not enabled. Check cluster.json:
```bash
jq '.aws.sts.enabled' <cluster_id>_cluster.json
```

### Problem: Role files missing
**Solution**: Re-run data collection:
```bash
python get_install_artifacts.py --cluster-name <cluster-name>
```

### Problem: Permission errors
**Cause**: IAM credentials lack required permissions

**Investigation**:
```bash
# Check current identity
aws sts get-caller-identity

# Test IAM permissions
aws iam get-role --role-name <role-name>
aws iam list-open-id-connect-providers
```

**Fix**: Ensure credentials have IAM read permissions (see AWS Permissions Required above)

### Problem: OIDC provider fetch fails
**Cause**: Multiple OIDC providers or naming mismatch

**Investigation**:
```bash
# List all OIDC providers
cat <cluster_id>_oidc_providers_list.json | jq '.OpenIDConnectProviderList'

# Check cluster ID in OIDC URL
jq '.aws.sts.oidc_endpoint_url' <cluster_id>_cluster.json
```

**Fix**: Verify cluster ID matches OIDC provider ARN pattern

## Integration with Existing Tests

The AWS resources tests complement existing infrastructure tests:

- **Existing IAM tests** (`test_iam.py`): Validate basic configuration
- **New AWS resources tests** (`test_aws_resources.py`): Validate STS-specific resources

Both test suites can run simultaneously:
- STS cluster: Both sets execute
- Non-STS cluster: Only basic IAM tests execute, AWS resources tests skip

## Future Enhancements

### Potential Additions

1. **Policy Content Validation**
   - Verify required permissions in policies
   - Check for overly permissive policies

2. **Trust Relationship Validation**
   - Verify AssumeRolePolicyDocument correctness
   - Check OIDC provider trust configuration

3. **Role Usage Analysis**
   - Track when roles were last used
   - Identify unused roles

4. **Permission Boundary Validation**
   - Check for permission boundaries
   - Validate boundary effectiveness

5. **IAM Best Practices**
   - Check for wildcard permissions
   - Validate least privilege principle

## Benefits

### Comprehensive Validation
- All STS cluster IAM resources verified
- OIDC authentication configuration validated
- Policy attachment confirmed

### Troubleshooting Support
- Policy files available for permission debugging
- Trust relationships captured for analysis
- Complete IAM configuration documented

### Automation Ready
- Automated fetching from cluster.json
- No manual ARN entry required
- Consistent file naming and structure

---

**Generated**: 2025-12-01
**Status**: ✅ Implementation complete
**Tests**: 10 new tests (7 will pass when IAM data is collected)
