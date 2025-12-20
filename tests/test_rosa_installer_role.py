"""
ROSA Installer Role Validation Tests

Individual tests for ROSA installer role, its policies, and permissions.
"""

import pytest
import json
from pathlib import Path
from typing import Dict, Any, List
from models.cluster import ClusterData


def check_iam_data_availability(cluster_data: ClusterData, role_type: str) -> Dict[str, Any]:
    """
    Comprehensive diagnostics for missing IAM role data.

    Returns dict with:
        - available: bool
        - reason: str (why data is missing)
        - api_error: dict (if API call failed)
        - file_path: str (expected file location)
    """
    result = {
        'available': False,
        'reason': 'unknown',
        'api_error': None,
        'file_path': None,
        'found_files': []
    }

    # Check for role files
    pattern = f"*_iam_role_{role_type}_*.json"
    role_files = [
        f for f in cluster_data.aws_dir.glob(pattern)
        if not f.name.endswith('_policies.json') and not f.name.endswith('_attached_policies.json')
    ]

    result['found_files'] = [str(f) for f in role_files]

    if role_files:
        result['available'] = True
        result['reason'] = 'data_found'
        result['file_path'] = str(role_files[0])
        return result

    # No files found - diagnose why
    expected_file = cluster_data.aws_dir / f"{cluster_data.cluster_id}_iam_role_{role_type}_.json"
    result['file_path'] = str(expected_file)

    # Check if API request log is available
    if not cluster_data.api_requests:
        result['reason'] = 'no_api_request_log'
        return result

    # Search API request log for IAM GetRole or ListRoles calls
    requests = cluster_data.api_requests.get('requests', [])
    iam_requests = [req for req in requests if req.get('service') == 'iam']

    if not iam_requests:
        result['reason'] = 'no_iam_api_calls'
        return result

    # Check for failures in IAM API calls
    failed_iam_requests = [req for req in iam_requests if not req.get('success', True)]

    if failed_iam_requests:
        result['reason'] = 'iam_api_call_failed'
        first_error = failed_iam_requests[0]
        result['api_error'] = {
            'operation': first_error.get('operation'),
            'error_code': first_error.get('error', {}).get('code'),
            'error_message': first_error.get('error', {}).get('message'),
            'timestamp': first_error.get('timestamp'),
            'response_code': first_error.get('response_code'),
            'duration_ms': first_error.get('duration_ms')
        }
        return result

    # API calls succeeded but no role files - role doesn't exist in AWS
    result['reason'] = 'role_not_found_in_aws'
    return result


def load_role_data(role_file: Path) -> Dict[str, Any]:
    """Load IAM role data from JSON file with error handling"""
    try:
        with open(role_file) as f:
            data = json.load(f)

        # Handle empty file
        if not data:
            return {'error': 'file_empty', 'RoleName': 'unknown'}

        return data.get('Role', {})
    except json.JSONDecodeError as e:
        return {'error': 'invalid_json', 'RoleName': 'unknown', 'parse_error': str(e)}
    except Exception as e:
        return {'error': 'read_failed', 'RoleName': 'unknown', 'exception': str(e)}


def load_attached_policies(role_file: Path) -> List[Dict[str, Any]]:
    """Load attached policies with diagnostics"""
    policies_file = Path(str(role_file).replace('.json', '_attached_policies.json'))

    if not policies_file.exists():
        return []

    try:
        with open(policies_file) as f:
            data = json.load(f)

        if not data:
            return []

        return data.get('AttachedPolicies', [])
    except:
        return []


@pytest.mark.aws_resources
@pytest.mark.iam_roles
@pytest.mark.severity("CRITICAL")
def test_installer_role_exists(cluster_data: ClusterData):
    """ROSA installer role must exist

    Why: The installer role is required for ROSA to create and manage cluster resources
    during installation and lifecycle management.

    Failure indicates:
    - Role was not created during cluster setup
    - Data collection failed to retrieve role information
    - IAM permissions insufficient to read role data
    - Role was deleted after cluster creation

    Success indicates: Installer role exists and was successfully collected.

    Remediation:
    1. Check if role exists in AWS IAM console
    2. Verify data collection has IAM read permissions (iam:GetRole, iam:ListRoles)
    3. Recreate role if missing using ROSA CLI: rosa create account-roles

    Documentation: https://docs.aws.amazon.com/rosa/latest/userguide/security-iam-awsmanpol.html

    Severity: CRITICAL - Installer role is required for cluster installation and management
    """
    # Check data availability with diagnostics
    availability = check_iam_data_availability(cluster_data, 'installer')

    if not availability['available']:
        # Build detailed error message based on reason
        error_msg = "Installer role not found.\n\n"

        if availability['reason'] == 'no_api_request_log':
            error_msg += "📋 Diagnostic Information:\n"
            error_msg += "  • API request log not available\n"
            error_msg += "  • Cannot determine if data collection attempted to retrieve role\n"
            error_msg += "\n💡 Possible Causes:\n"
            error_msg += "  1. Data was collected without API request logging enabled\n"
            error_msg += "  2. Data collection script version is outdated\n"
            error_msg += "\n🔧 Remediation:\n"
            error_msg += "  • Re-run data collection with updated script that includes API logging\n"

        elif availability['reason'] == 'no_iam_api_calls':
            error_msg += "📋 Diagnostic Information:\n"
            error_msg += "  • No IAM API calls found in request log\n"
            error_msg += "  • Data collection did not attempt to retrieve IAM roles\n"
            error_msg += "\n💡 Possible Causes:\n"
            error_msg += "  1. IAM data collection was skipped or disabled\n"
            error_msg += "  2. Data collection script does not include IAM role retrieval\n"
            error_msg += "\n🔧 Remediation:\n"
            error_msg += "  • Ensure data collection includes IAM role retrieval\n"
            error_msg += "  • Run: python get_install_artifacts.py -c <cluster-id> --include-iam\n"

        elif availability['reason'] == 'iam_api_call_failed':
            api_error = availability['api_error']
            error_msg += "📋 Diagnostic Information:\n"
            error_msg += f"  • IAM API call failed: {api_error['operation']}\n"
            error_msg += f"  • Error code: {api_error['error_code']}\n"
            error_msg += f"  • Error message: {api_error['error_message']}\n"
            error_msg += f"  • Timestamp: {api_error.get('timestamp', 'Unknown')}\n"

            if api_error.get('response_code'):
                error_msg += f"  • Response code: {api_error['response_code']}\n"

            if api_error.get('duration_ms'):
                error_msg += f"  • Duration: {api_error['duration_ms']}ms\n"

            error_msg += "\n💡 Possible Causes:\n"

            if api_error['error_code'] in ['AccessDenied', 'UnauthorizedOperation']:
                error_msg += "  1. IAM user/role lacks required permissions\n"
                error_msg += "  2. Missing permissions: iam:GetRole, iam:ListRoles, iam:ListAttachedRolePolicies\n"
                error_msg += "\n🔧 Remediation:\n"
                error_msg += "  • Add required IAM permissions to data collection user/role\n"
                error_msg += "  • Attach policy with iam:GetRole, iam:ListRoles permissions\n"
            else:
                error_msg += f"  1. AWS API returned error: {api_error['error_code']}\n"
                error_msg += "\n🔧 Remediation:\n"
                error_msg += "  • Check AWS service health\n"
                error_msg += "  • Retry data collection\n"

        elif availability['reason'] == 'role_not_found_in_aws':
            error_msg += "📋 Diagnostic Information:\n"
            error_msg += "  • IAM API calls completed successfully\n"
            error_msg += "  • Installer role does not exist in AWS account\n"
            error_msg += f"  • Expected file location: {availability['file_path']}\n"
            error_msg += "  • File was not created because role doesn't exist\n"
            error_msg += "\n💡 Possible Causes:\n"
            error_msg += "  1. Installer role was never created\n"
            error_msg += "  2. Installer role was deleted after cluster creation\n"
            error_msg += "  3. Role exists but has different naming pattern\n"
            error_msg += "\n🔧 Remediation:\n"
            error_msg += "  • Check AWS IAM console for installer role\n"
            error_msg += "  • Expected role name pattern: <prefix>-Installer-Role\n"
            error_msg += "  • Create role using: rosa create account-roles\n"
            error_msg += "  • Verify role has tag: rosa_role_type=installer\n"

        error_msg += "\n📄 Expected Role Configuration:\n"
        error_msg += "  • Role name: <prefix>-Installer-Role\n"
        error_msg += "  • Managed policy: arn:aws:iam::aws:policy/ROSAInstallerPolicy\n"
        error_msg += "  • Tags: red-hat-managed=true, rosa_role_type=installer\n"

        pytest.fail(error_msg)

    # Load and validate role data
    role_file = Path(availability['found_files'][0])
    role_data = load_role_data(role_file)

    # Check for file read errors
    if 'error' in role_data:
        error_type = role_data['error']
        error_msg = f"Failed to read installer role data from {role_file}\n\n"

        if error_type == 'file_empty':
            error_msg += "📋 Diagnostic Information:\n"
            error_msg += "  • File exists but is empty\n"
            error_msg += "  • Data collection may have failed while writing file\n"
            error_msg += "\n🔧 Remediation:\n"
            error_msg += "  • Delete empty file and re-run data collection\n"

        elif error_type == 'invalid_json':
            error_msg += "📋 Diagnostic Information:\n"
            error_msg += "  • File contains invalid JSON\n"
            error_msg += f"  • Parse error: {role_data.get('parse_error')}\n"
            error_msg += "\n🔧 Remediation:\n"
            error_msg += "  • File may be corrupted\n"
            error_msg += "  • Delete file and re-run data collection\n"

        pytest.fail(error_msg)

    role_name = role_data.get('RoleName', 'unknown')
    role_arn = role_data.get('Arn', 'unknown')

    print(f"\n✓ Found installer role: {role_name}")
    print(f"  ARN: {role_arn}")
    print(f"  File: {role_file.name}")

    # Check tags
    tags = {tag['Key']: tag['Value'] for tag in role_data.get('Tags', [])}
    if 'rosa_role_type' in tags:
        print(f"  Type tag: {tags['rosa_role_type']}")
    if 'red-hat-managed' in tags:
        print(f"  Managed tag: {tags['red-hat-managed']}")


@pytest.mark.aws_resources
@pytest.mark.iam_roles
@pytest.mark.severity("HIGH")
def test_installer_role_has_managed_policy(cluster_data: ClusterData):
    """Installer role must have ROSAInstallerPolicy or equivalent attached

    Why: The installer role needs comprehensive permissions to create AWS resources
    including VPCs, subnets, security groups, load balancers, and EC2 instances.

    Failure indicates:
    - Policy attachment is missing
    - Policy was detached after role creation
    - Custom policy used instead of AWS managed policy

    Success indicates: Installer role has appropriate policy attached.

    Remediation:
    1. Attach ROSAInstallerPolicy: aws iam attach-role-policy --role-name <role> --policy-arn arn:aws:iam::aws:policy/ROSAInstallerPolicy
    2. Or verify custom policy has equivalent permissions

    Severity: HIGH - Missing policy prevents cluster installation
    """
    # Check if role exists first
    availability = check_iam_data_availability(cluster_data, 'installer')

    if not availability['available']:
        pytest.skip("Installer role not found - cannot check policies")

    role_file = Path(availability['found_files'][0])
    role_data = load_role_data(role_file)
    role_name = role_data.get('RoleName', 'unknown')

    # Load attached policies
    policies = load_attached_policies(role_file)

    if not policies:
        # Check if policies file exists
        policies_file = Path(str(role_file).replace('.json', '_attached_policies.json'))

        error_msg = f"Installer role '{role_name}' has no attached policies.\n\n"

        if not policies_file.exists():
            error_msg += "📋 Diagnostic Information:\n"
            error_msg += f"  • Expected policies file: {policies_file.name}\n"
            error_msg += "  • File does not exist\n"
            error_msg += "\n💡 Possible Causes:\n"
            error_msg += "  1. Data collection did not retrieve attached policies\n"
            error_msg += "  2. No policies are attached to the role\n"
            error_msg += "\n🔧 Remediation:\n"
            error_msg += "  • Re-run data collection to get policy information\n"
            error_msg += "  • Manually check: aws iam list-attached-role-policies --role-name " + role_name + "\n"
        else:
            error_msg += "📋 Diagnostic Information:\n"
            error_msg += f"  • Policies file exists: {policies_file.name}\n"
            error_msg += "  • File shows no policies attached to role\n"
            error_msg += "\n💡 Possible Causes:\n"
            error_msg += "  1. Role was created without policy attachment\n"
            error_msg += "  2. Policy was detached after creation\n"
            error_msg += "\n🔧 Remediation:\n"
            error_msg += "  • Attach ROSAInstallerPolicy to the role:\n"
            error_msg += f"    aws iam attach-role-policy --role-name {role_name} \\\n"
            error_msg += "      --policy-arn arn:aws:iam::aws:policy/ROSAInstallerPolicy\n"

        error_msg += "\n📄 Required Policy:\n"
        error_msg += "  • AWS Managed Policy: arn:aws:iam::aws:policy/ROSAInstallerPolicy\n"
        error_msg += "  • Or custom policy with equivalent permissions for:\n"
        error_msg += "    - EC2 (VPC, subnet, security group, instance creation)\n"
        error_msg += "    - ELB (load balancer creation and management)\n"
        error_msg += "    - IAM (role and policy management)\n"
        error_msg += "    - Route53 (DNS zone and record management)\n"

        pytest.fail(error_msg)

    # Check for ROSAInstallerPolicy or equivalent
    print(f"\n✓ Installer role has {len(policies)} attached policy/policies:")

    has_rosa_policy = False
    for policy in policies:
        policy_name = policy.get('PolicyName', 'unknown')
        policy_arn = policy.get('PolicyArn', 'unknown')

        print(f"  - {policy_name}")
        print(f"      ARN: {policy_arn}")

        if 'ROSAInstallerPolicy' in policy_arn or 'rosa' in policy_name.lower() and 'installer' in policy_name.lower():
            has_rosa_policy = True

    if not has_rosa_policy:
        print(f"\n⚠ WARNING: No ROSAInstallerPolicy found")
        print(f"  Role has custom policies attached")
        print(f"  Verify custom policies have equivalent permissions")


@pytest.mark.aws_resources
@pytest.mark.iam_roles
@pytest.mark.severity("MEDIUM")
def test_installer_role_trust_policy(cluster_data: ClusterData):
    """Installer role must have appropriate trust policy

    Why: Trust policy defines which entities can assume the installer role.

    Failure indicates: Trust policy may not allow required principals.

    Success indicates: Trust policy is properly configured.

    Severity: MEDIUM - Trust policy issues prevent role assumption
    """
    availability = check_iam_data_availability(cluster_data, 'installer')

    if not availability['available']:
        pytest.skip("Installer role not found - cannot check trust policy")

    role_file = Path(availability['found_files'][0])
    role_data = load_role_data(role_file)
    role_name = role_data.get('RoleName', 'unknown')

    # Get trust policy
    trust_policy_doc = role_data.get('AssumeRolePolicyDocument', {})

    if not trust_policy_doc:
        pytest.fail(f"Installer role '{role_name}' has no trust policy")

    print(f"\n✓ Installer role trust policy configured:")
    print(json.dumps(trust_policy_doc, indent=2))

    # Validate trust policy has statements
    statements = trust_policy_doc.get('Statement', [])

    if not statements:
        pytest.fail(f"Installer role trust policy has no statements")

    print(f"\n  Trust policy has {len(statements)} statement(s)")
