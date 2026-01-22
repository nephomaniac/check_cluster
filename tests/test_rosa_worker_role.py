"""
ROSA Worker Role Validation Tests

Individual tests for ROSA worker role validation.
"""

import pytest
import json
from pathlib import Path
from typing import Dict, Any, List
from models.cluster import ClusterData


def check_iam_data_availability(cluster_data: ClusterData, role_type: str) -> Dict[str, Any]:
    """Check IAM role data availability with diagnostics"""
    result = {
        'available': False,
        'reason': 'unknown',
        'api_error': None,
        'file_path': None,
        'found_files': []
    }

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

    expected_file = cluster_data.aws_dir / f"{cluster_data.cluster_id}_iam_role_{role_type}_.json"
    result['file_path'] = str(expected_file)

    if not cluster_data.api_requests:
        result['reason'] = 'no_api_request_log'
        return result

    requests = cluster_data.api_requests.get('requests', [])
    iam_requests = [req for req in requests if req.get('service') == 'iam']

    if not iam_requests:
        result['reason'] = 'no_iam_api_calls'
        return result

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

    result['reason'] = 'role_not_found_in_aws'
    return result


def load_role_data(role_file: Path) -> Dict[str, Any]:
    """Load IAM role data from JSON file"""
    try:
        with open(role_file) as f:
            data = json.load(f)
        if not data:
            return {'error': 'file_empty', 'RoleName': 'unknown'}
        return data.get('Role', {})
    except json.JSONDecodeError as e:
        return {'error': 'invalid_json', 'RoleName': 'unknown', 'parse_error': str(e)}
    except Exception as e:
        return {'error': 'read_failed', 'RoleName': 'unknown', 'exception': str(e)}


def load_attached_policies(role_file: Path) -> List[Dict[str, Any]]:
    """Load attached policies"""
    policies_file = Path(str(role_file).replace('.json', '_attached_policies.json'))
    if not policies_file.exists():
        return []
    try:
        with open(policies_file) as f:
            data = json.load(f)
        return data.get('AttachedPolicies', [])
    except:
        return []


@pytest.mark.aws_resources
@pytest.mark.iam_roles
@pytest.mark.severity("CRITICAL")
def test_worker_role_exists(cluster_data: ClusterData):
    """ROSA worker instance role must exist

    Why: Worker nodes require an IAM instance profile with permissions to:
    - Pull container images from ECR
    - Manage EBS volumes
    - Report node status to the cluster
    - Access AWS services required by workloads

    Failure indicates:
    - Worker role was not created during cluster setup
    - Data collection failed to retrieve role
    - IAM permissions insufficient to read role data
    - Role was deleted after cluster creation

    Success indicates: Worker role exists and was successfully collected.

    Remediation:
    1. Check if role exists: aws iam get-role --role-name <prefix>-Worker-Role
    2. Verify data collection has IAM read permissions
    3. Create role if missing: rosa create account-roles

    Documentation: https://docs.aws.amazon.com/rosa/latest/userguide/security-iam-awsmanpol.html

    Severity: CRITICAL - Worker nodes cannot function without this role
    """
    availability = check_iam_data_availability(cluster_data, 'worker')

    if not availability['available']:
        error_msg = "Worker role not found.\n\n"

        if availability['reason'] == 'no_api_request_log':
            error_msg += "📋 Diagnostic Information:\n"
            error_msg += "  • API request log not available\n"
            error_msg += "  • Cannot determine if data collection attempted to retrieve role\n"
            error_msg += "\n🔧 Remediation:\n"
            error_msg += "  • Re-run data collection with API request logging enabled\n"

        elif availability['reason'] == 'no_iam_api_calls':
            error_msg += "📋 Diagnostic Information:\n"
            error_msg += "  • No IAM API calls found in request log\n"
            error_msg += "  • IAM data collection was not performed\n"
            error_msg += "\n🔧 Remediation:\n"
            error_msg += "  • Run: check_cluster.py <cluster-id> --collect --resources=iam\n"

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

            if api_error['error_code'] in ['AccessDenied', 'UnauthorizedOperation']:
                error_msg += "\n💡 Cause: Insufficient IAM permissions\n"
                error_msg += "\n🔧 Remediation:\n"
                error_msg += "  • Add IAM permissions: iam:GetRole, iam:ListRoles, iam:ListAttachedRolePolicies\n"
            else:
                error_msg += "\n🔧 Remediation:\n"
                error_msg += "  • Check AWS service health and retry\n"

        elif availability['reason'] == 'role_not_found_in_aws':
            error_msg += "📋 Diagnostic Information:\n"
            error_msg += "  • IAM API calls completed successfully\n"
            error_msg += "  • Worker role does not exist in AWS account\n"
            error_msg += f"  • Expected file: {availability['file_path']}\n"
            error_msg += "\n💡 Possible Causes:\n"
            error_msg += "  1. Worker role was never created\n"
            error_msg += "  2. Worker role was deleted\n"
            error_msg += "  3. Role has different naming pattern\n"
            error_msg += "\n🔧 Remediation:\n"
            error_msg += "  • Check AWS IAM console for worker role\n"
            error_msg += "  • Expected pattern: <prefix>-Worker-Role\n"
            error_msg += "  • Create role: rosa create account-roles\n"

        error_msg += "\n📄 Expected Role Configuration:\n"
        error_msg += "  • Role name: <prefix>-Worker-Role\n"
        error_msg += "  • Managed policy: arn:aws:iam::aws:policy/ROSAWorkerInstancePolicy\n"
        error_msg += "  • Tags: red-hat-managed=true, rosa_role_type=worker\n"

        pytest.fail(error_msg)

    role_file = Path(availability['found_files'][0])
    role_data = load_role_data(role_file)

    if 'error' in role_data:
        error_type = role_data['error']
        error_msg = f"Failed to read worker role data from {role_file}\n\n"

        if error_type == 'file_empty':
            error_msg += "📋 File exists but is empty\n"
            error_msg += "🔧 Delete and re-run data collection\n"
        elif error_type == 'invalid_json':
            error_msg += f"📋 Invalid JSON: {role_data.get('parse_error')}\n"
            error_msg += "🔧 File corrupted - delete and re-collect\n"

        pytest.fail(error_msg)

    role_name = role_data.get('RoleName', 'unknown')
    role_arn = role_data.get('Arn', 'unknown')

    print(f"\n✓ Found worker role: {role_name}")
    print(f"  ARN: {role_arn}")
    print(f"  File: {role_file.name}")

    tags = {tag['Key']: tag['Value'] for tag in role_data.get('Tags', [])}
    if 'rosa_role_type' in tags:
        print(f"  Type tag: {tags['rosa_role_type']}")
    if 'red-hat-managed' in tags:
        print(f"  Managed tag: {tags['red-hat-managed']}")


@pytest.mark.aws_resources
@pytest.mark.iam_roles
@pytest.mark.severity("HIGH")
def test_worker_role_has_managed_policy(cluster_data: ClusterData):
    """Worker role must have ROSAWorkerInstancePolicy or equivalent

    Why: Worker nodes need permissions for:
    - ECR: Pulling container images
    - EC2: Managing instance metadata and networking
    - EBS: Attaching and managing volumes
    - CloudWatch: Sending logs and metrics

    Failure indicates: Policy is missing or detached.

    Success indicates: Worker role has appropriate policy.

    Remediation:
    aws iam attach-role-policy --role-name <role> --policy-arn arn:aws:iam::aws:policy/ROSAWorkerInstancePolicy


    Documentation: https://docs.aws.amazon.com/rosa/latest/userguide/security-iam-awsmanpol.html
    Severity: HIGH - Worker nodes cannot function without required permissions
    """
    availability = check_iam_data_availability(cluster_data, 'worker')

    if not availability['available']:
        pytest.skip("Worker role not found - cannot check policies")

    role_file = Path(availability['found_files'][0])
    role_data = load_role_data(role_file)
    role_name = role_data.get('RoleName', 'unknown')

    policies = load_attached_policies(role_file)

    if not policies:
        policies_file = Path(str(role_file).replace('.json', '_attached_policies.json'))
        error_msg = f"Worker role '{role_name}' has no attached policies.\n\n"

        if not policies_file.exists():
            error_msg += "📋 Diagnostic Information:\n"
            error_msg += f"  • Policies file missing: {policies_file.name}\n"
            error_msg += "\n🔧 Remediation:\n"
            error_msg += "  • Re-run data collection\n"
            error_msg += f"  • Check: aws iam list-attached-role-policies --role-name {role_name}\n"
        else:
            error_msg += "📋 Diagnostic Information:\n"
            error_msg += "  • Policies file exists but shows no policies\n"
            error_msg += "\n🔧 Remediation:\n"
            error_msg += f"  • Attach policy:\n"
            error_msg += f"    aws iam attach-role-policy --role-name {role_name} \\\n"
            error_msg += "      --policy-arn arn:aws:iam::aws:policy/ROSAWorkerInstancePolicy\n"

        error_msg += "\n📄 Required Policy:\n"
        error_msg += "  • AWS Managed: arn:aws:iam::aws:policy/ROSAWorkerInstancePolicy\n"
        error_msg += "  • Required permissions:\n"
        error_msg += "    - ecr:GetAuthorizationToken, ecr:BatchGetImage\n"
        error_msg += "    - ec2:DescribeInstances, ec2:DescribeRegions\n"

        pytest.fail(error_msg)

    print(f"\n✓ Worker role has {len(policies)} attached policy/policies:")

    has_rosa_policy = False
    for policy in policies:
        policy_name = policy.get('PolicyName', 'unknown')
        policy_arn = policy.get('PolicyArn', 'unknown')
        print(f"  - {policy_name}")
        print(f"      ARN: {policy_arn}")

        if 'ROSAWorkerInstancePolicy' in policy_arn:
            has_rosa_policy = True

    if not has_rosa_policy:
        print(f"\n⚠ WARNING: No ROSAWorkerInstancePolicy found")
        print(f"  Verify custom policies have equivalent permissions")


@pytest.mark.aws_resources
@pytest.mark.iam_roles
@pytest.mark.severity("MEDIUM")
def test_worker_role_has_instance_profile(cluster_data: ClusterData):
    """Worker role should be associated with instance profile

    Why: EC2 instances use instance profiles to assume IAM roles.

    Failure indicates: Role may not be usable by worker instances.

    Success indicates: Instance profile is configured.


    Documentation: https://docs.aws.amazon.com/rosa/latest/userguide/security-iam-awsmanpol.html
    Severity: MEDIUM - Instance profile is required for EC2 role assumption
    """
    availability = check_iam_data_availability(cluster_data, 'worker')

    if not availability['available']:
        pytest.skip("Worker role not found")

    role_file = Path(availability['found_files'][0])

    # Look for instance profile file
    instance_profile_file = Path(str(role_file).replace('.json', '_instance_profile.json'))

    if instance_profile_file.exists():
        try:
            with open(instance_profile_file) as f:
                profile_data = json.load(f)
            print(f"\n✓ Worker role has instance profile configured")
            print(json.dumps(profile_data, indent=2))
        except:
            pytest.skip("Instance profile file exists but cannot be read")
    else:
        print(f"\n⚠ No instance profile file found")
        print(f"  Note: May not be collected by default")
        pytest.skip("Instance profile information not available")
