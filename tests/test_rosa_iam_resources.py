"""
ROSA IAM Resources Validation Tests

Validates that cluster IAM resources match ROSA requirements documented at:
https://docs.aws.amazon.com/rosa/latest/userguide/security-iam-awsmanpol.html

Tests check for required IAM roles, attached policies, and OIDC providers.
"""

import pytest
import json
from pathlib import Path
from typing import List, Dict, Any, Set
from models.cluster import ClusterData


def get_iam_role_files(cluster_data: ClusterData, role_type: str) -> List[Path]:
    """
    Get IAM role files for a specific role type.

    Args:
        cluster_data: ClusterData instance
        role_type: Role type (installer, master, worker, support, operator)

    Returns:
        List of Path objects for matching role files
    """
    pattern = f"*_iam_role_{role_type}_*.json"
    # Exclude policy files
    role_files = [
        f for f in cluster_data.aws_dir.glob(pattern)
        if not f.name.endswith('_policies.json') and not f.name.endswith('_attached_policies.json')
    ]
    return role_files


def load_role_data(role_file: Path) -> Dict[str, Any]:
    """Load IAM role data from JSON file"""
    with open(role_file) as f:
        data = json.load(f)
    return data.get('Role', {})


def load_attached_policies(role_file: Path) -> List[Dict[str, Any]]:
    """Load attached policies for a role"""
    # Replace .json with _attached_policies.json
    policies_file = Path(str(role_file).replace('.json', '_attached_policies.json'))
    if not policies_file.exists():
        return []

    with open(policies_file) as f:
        data = json.load(f)
    return data.get('AttachedPolicies', [])


def get_policy_arns(role_file: Path) -> Set[str]:
    """Get set of policy ARNs attached to a role"""
    policies = load_attached_policies(role_file)
    return {p.get('PolicyArn', '') for p in policies}


@pytest.mark.aws_resources
@pytest.mark.severity("CRITICAL")
def test_installer_role_exists(cluster_data: ClusterData):
    """Cluster must have ROSA installer role

    Why: The installer role is required for ROSA to create and manage cluster resources.

    Failure indicates: Installer role is missing or was not collected.

    Success indicates: Installer role exists and was properly configured.

    Documentation: https://docs.aws.amazon.com/rosa/latest/userguide/security-iam-awsmanpol.html

    Severity: CRITICAL - Installer role is required for cluster installation
    """
    from utils.iam_diagnostics import diagnose_missing_iam_data

    installer_roles = get_iam_role_files(cluster_data, 'installer')

    if not installer_roles:
        # Comprehensive diagnostics for missing installer role
        diagnostics = diagnose_missing_iam_data(
            cluster_data=cluster_data,
            resource_type="ROSA installer role",
            expected_file_pattern="*_iam_role_installer_*.json",
            api_service="iam",
            api_operations=["get_role", "list_roles"]
        )

        error_msg = "No installer role found.\n\n"
        error_msg += diagnostics['diagnostic_message']
        error_msg += "\n" + diagnostics['remediation']

        error_msg += "\n📄 Expected Role Configuration:\n"
        error_msg += "  • Role name pattern: <prefix>-Installer-Role\n"
        error_msg += "  • Managed policy: arn:aws:iam::aws:policy/ROSAInstallerPolicy\n"
        error_msg += "  • Tags: red-hat-managed=true, rosa_role_type=installer\n"

        pytest.fail(error_msg)

    # Load role details
    role_data = load_role_data(installer_roles[0])
    role_name = role_data.get('RoleName', 'unknown')
    role_arn = role_data.get('Arn', 'unknown')

    print(f"\n✓ Found installer role: {role_name}")
    print(f"  ARN: {role_arn}")

    # Check tags
    tags = {tag['Key']: tag['Value'] for tag in role_data.get('Tags', [])}
    if 'rosa_role_type' in tags:
        print(f"  Type tag: {tags['rosa_role_type']}")

    assert len(installer_roles) > 0, "Installer role is required for ROSA"


@pytest.mark.aws_resources
@pytest.mark.severity("HIGH")
def test_installer_role_has_policy(cluster_data: ClusterData):
    """Installer role must have appropriate policy attached

    Why: Installer role needs permissions to create AWS resources for the cluster.

    Failure indicates: Installer role lacks required policy attachment.

    Success indicates: Installer role has policy attached (should include permissions equivalent to ROSAInstallerPolicy).

    Remediation: Attach ROSAInstallerPolicy or equivalent custom policy to installer role.


    Documentation: https://docs.aws.amazon.com/rosa/latest/userguide/security-iam-awsmanpol.html
    Severity: HIGH - Missing policy prevents cluster installation
    """
    installer_roles = get_iam_role_files(cluster_data, 'installer')

    if not installer_roles:
        pytest.skip("No installer role found")

    role_file = installer_roles[0]
    role_data = load_role_data(role_file)
    role_name = role_data.get('RoleName', 'unknown')

    policies = load_attached_policies(role_file)

    if not policies:
        pytest.fail(
            f"Installer role '{role_name}' has no attached policies. "
            "It should have ROSAInstallerPolicy or equivalent custom policy attached."
        )

    print(f"\n✓ Installer role has {len(policies)} attached policy/policies:")
    for policy in policies:
        print(f"  - {policy.get('PolicyName')} ({policy.get('PolicyArn')})")

    assert len(policies) > 0, f"Installer role must have at least one policy attached"


@pytest.mark.aws_resources
@pytest.mark.severity("CRITICAL")
def test_worker_role_exists(cluster_data: ClusterData):
    """Cluster must have worker instance role

    Why: Worker nodes need an IAM role to access AWS services (ECR, EBS, etc.).

    Failure indicates: Worker role is missing or was not collected.

    Success indicates: Worker role exists and is available for worker nodes.

    Documentation: https://docs.aws.amazon.com/rosa/latest/userguide/security-iam-awsmanpol.html

    Severity: CRITICAL - Worker role is required for worker nodes to function
    """
    from utils.iam_diagnostics import diagnose_missing_iam_data

    worker_roles = get_iam_role_files(cluster_data, 'worker')

    if not worker_roles:
        diagnostics = diagnose_missing_iam_data(
            cluster_data=cluster_data,
            resource_type="ROSA worker role",
            expected_file_pattern="*_iam_role_worker_*.json",
            api_service="iam",
            api_operations=["get_role", "list_roles"]
        )

        error_msg = "No worker role found.\n\n"
        error_msg += diagnostics['diagnostic_message']
        error_msg += "\n" + diagnostics['remediation']

        error_msg += "\n📄 Expected Role Configuration:\n"
        error_msg += "  • Role name pattern: <prefix>-Worker-Role\n"
        error_msg += "  • Managed policy: arn:aws:iam::aws:policy/ROSAWorkerInstancePolicy\n"
        error_msg += "  • Tags: red-hat-managed=true, rosa_role_type=worker\n"

        pytest.fail(error_msg)

    # Load role details
    role_data = load_role_data(worker_roles[0])
    role_name = role_data.get('RoleName', 'unknown')
    role_arn = role_data.get('Arn', 'unknown')

    print(f"\n✓ Found worker role: {role_name}")
    print(f"  ARN: {role_arn}")

    # Check tags
    tags = {tag['Key']: tag['Value'] for tag in role_data.get('Tags', [])}
    if 'rosa_role_type' in tags:
        print(f"  Type tag: {tags['rosa_role_type']}")

    assert len(worker_roles) > 0, "Worker role is required for ROSA"


@pytest.mark.aws_resources
@pytest.mark.severity("HIGH")
def test_worker_role_has_policy(cluster_data: ClusterData):
    """Worker role must have appropriate policy attached

    Why: Worker nodes need permissions for ECR (container images) and EC2 (instance operations).

    Failure indicates: Worker role lacks required policy attachment.

    Success indicates: Worker role has policy attached (should include permissions equivalent to ROSAWorkerInstancePolicy).

    Remediation: Attach ROSAWorkerInstancePolicy or equivalent custom policy to worker role.


    Documentation: https://docs.aws.amazon.com/rosa/latest/userguide/security-iam-awsmanpol.html
    Severity: HIGH - Missing policy prevents worker nodes from functioning properly
    """
    worker_roles = get_iam_role_files(cluster_data, 'worker')

    if not worker_roles:
        pytest.skip("No worker role found")

    role_file = worker_roles[0]
    role_data = load_role_data(role_file)
    role_name = role_data.get('RoleName', 'unknown')

    policies = load_attached_policies(role_file)

    if not policies:
        pytest.fail(
            f"Worker role '{role_name}' has no attached policies. "
            "It should have ROSAWorkerInstancePolicy or equivalent custom policy attached."
        )

    print(f"\n✓ Worker role has {len(policies)} attached policy/policies:")
    for policy in policies:
        print(f"  - {policy.get('PolicyName')} ({policy.get('PolicyArn')})")

    assert len(policies) > 0, f"Worker role must have at least one policy attached"


@pytest.mark.aws_resources
@pytest.mark.severity("HIGH")
def test_control_plane_role_exists(cluster_data: ClusterData):
    """Cluster should have control plane/master role

    Why: Control plane nodes need an IAM role for AWS API access.

    Failure indicates: Master/control plane role is missing or was not collected.

    Success indicates: Control plane role exists.


    Documentation: https://docs.aws.amazon.com/rosa/latest/userguide/security-iam-awsmanpol.html
    Severity: HIGH - Control plane role is required for master nodes
    """
    master_roles = get_iam_role_files(cluster_data, 'master')

    if not master_roles:
        print("\n⚠ No master/control plane role found")
        print("  This may be expected for ROSA with HCP (hosted control plane)")
        pytest.skip("No master role found (may be expected for HCP clusters)")

    # Load role details
    role_data = load_role_data(master_roles[0])
    role_name = role_data.get('RoleName', 'unknown')
    role_arn = role_data.get('Arn', 'unknown')

    print(f"\n✓ Found master/control plane role: {role_name}")
    print(f"  ARN: {role_arn}")

    assert len(master_roles) > 0


@pytest.mark.aws_resources
@pytest.mark.severity("MEDIUM")
def test_support_role_exists(cluster_data: ClusterData):
    """Cluster should have Red Hat SRE support role

    Why: Red Hat SRE team needs access to cluster resources for support.

    Failure indicates: Support role is missing (may be optional depending on configuration).

    Success indicates: Support role exists with ROSASRESupportPolicy.


    Documentation: https://docs.aws.amazon.com/rosa/latest/userguide/security-iam-awsmanpol.html
    Severity: MEDIUM - Support role is recommended for Red Hat SRE access
    """
    support_roles = get_iam_role_files(cluster_data, 'support')

    if not support_roles:
        print("\n⚠ No SRE support role found")
        print("  This role allows Red Hat SRE to troubleshoot cluster issues")
        pytest.skip("No support role found (may be optional)")

    # Load role details
    role_data = load_role_data(support_roles[0])
    role_name = role_data.get('RoleName', 'unknown')
    role_arn = role_data.get('Arn', 'unknown')

    print(f"\n✓ Found support role: {role_name}")
    print(f"  ARN: {role_arn}")

    # Check policies
    policies = load_attached_policies(support_roles[0])
    if policies:
        print(f"  Attached policies: {len(policies)}")
        for policy in policies:
            print(f"    - {policy.get('PolicyName')}")


@pytest.mark.aws_resources
@pytest.mark.severity("HIGH")
def test_operator_roles_exist(cluster_data: ClusterData):
    """Cluster should have operator IAM roles

    Why: OpenShift operators need IAM roles to access AWS services (EBS, Route53, etc.).

    Failure indicates: Operator roles are missing or were not collected.

    Success indicates: Operator roles exist for cluster operators.


    Documentation: https://docs.aws.amazon.com/rosa/latest/userguide/security-iam-awsmanpol.html
    Severity: HIGH - Operator roles are required for operator functionality
    """
    from utils.iam_diagnostics import diagnose_missing_iam_data

    # Find all operator role files
    operator_pattern = "*_iam_role_operator-*.json"
    operator_files = [
        f for f in cluster_data.aws_dir.glob(operator_pattern)
        if not f.name.endswith('_policies.json') and not f.name.endswith('_attached_policies.json')
    ]

    if not operator_files:
        diagnostics = diagnose_missing_iam_data(
            cluster_data=cluster_data,
            resource_type="ROSA operator roles",
            expected_file_pattern="*_iam_role_operator-*.json",
            api_service="iam",
            api_operations=["get_role", "list_roles"]
        )

        error_msg = "No operator roles found.\n\n"
        error_msg += diagnostics['diagnostic_message']
        error_msg += "\n" + diagnostics['remediation']

        error_msg += "\n📄 Required Operator Roles:\n"
        error_msg += "  - openshift-cluster-csi-drivers-ebs-cloud-credentials (EBS CSI driver)\n"
        error_msg += "  - openshift-ingress-operator-cloud-credentials (Ingress operator)\n"
        error_msg += "  - openshift-image-registry-installer-cloud-credentials (Image registry)\n"
        error_msg += "  - openshift-machine-api-aws-cloud-credentials (Machine API)\n"
        error_msg += "  - openshift-cloud-network-config-controller-cloud-credentials (Network config)\n"

        pytest.fail(error_msg)

    print(f"\n✓ Found {len(operator_files)} operator role(s):")

    operator_summary = []
    for role_file in operator_files:
        role_data = load_role_data(role_file)
        role_name = role_data.get('RoleName', 'unknown')

        # Extract operator name from role name
        # Format: <prefix>-<operator-namespace>-<operator-name>
        operator_name = 'unknown'
        if 'openshift-' in role_name:
            parts = role_name.split('openshift-', 1)
            if len(parts) > 1:
                operator_name = 'openshift-' + parts[1]

        policies = load_attached_policies(role_file)

        operator_summary.append({
            'role_name': role_name,
            'operator': operator_name,
            'arn': role_data.get('Arn'),
            'policies_count': len(policies)
        })

        print(f"  - {operator_name}")
        print(f"      Role: {role_name}")
        print(f"      Policies: {len(policies)}")

    # Check for critical operators
    critical_operators = [
        'openshift-cluster-csi-drivers-ebs',
        'openshift-machine-api-aws',
        'openshift-ingress-operator'
    ]

    found_operators = [op['operator'] for op in operator_summary]
    missing_critical = []

    for critical_op in critical_operators:
        if not any(critical_op in op for op in found_operators):
            missing_critical.append(critical_op)

    if missing_critical:
        print(f"\n⚠ Missing critical operator roles:")
        for op in missing_critical:
            print(f"  - {op}")

    assert len(operator_files) > 0, "At least one operator role is required"


@pytest.mark.aws_resources
@pytest.mark.severity("HIGH")
def test_ebs_csi_driver_operator_role_exists(cluster_data: ClusterData):
    """EBS CSI driver operator role must exist

    Why: EBS CSI driver requires IAM role to manage EBS volumes for persistent storage.

    Failure indicates: EBS CSI driver operator role is missing.

    Success indicates: EBS CSI driver operator role exists.


    Documentation: https://docs.aws.amazon.com/rosa/latest/userguide/security-iam-awsmanpol.html
    Severity: HIGH - Required for persistent volume provisioning
    """
    operator_pattern = "*_iam_role_operator-openshift-cluster-csi-drivers-ebs*.json"
    operator_files = [
        f for f in cluster_data.aws_dir.glob(operator_pattern)
        if not f.name.endswith('_policies.json') and not f.name.endswith('_attached_policies.json')
    ]

    if not operator_files:
        pytest.fail(
            "EBS CSI driver operator role not found. This role is required for:\n"
            "  - Creating and attaching EBS volumes\n"
            "  - Managing persistent volumes\n"
            "  - Dynamic volume provisioning"
        )

    role_data = load_role_data(operator_files[0])
    role_name = role_data.get('RoleName', 'unknown')

    print(f"\n✓ Found EBS CSI driver operator role: {role_name}")

    # Check policies
    policies = load_attached_policies(operator_files[0])
    if policies:
        print(f"  Attached policies: {len(policies)}")
        for policy in policies:
            print(f"    - {policy.get('PolicyName')}")
    else:
        pytest.fail(f"EBS CSI driver operator role '{role_name}' has no attached policies")


@pytest.mark.aws_resources
@pytest.mark.severity("MEDIUM")
def test_oidc_provider_exists(cluster_data: ClusterData):
    """Cluster should have OIDC provider configured

    Why: OIDC provider enables secure authentication for service accounts.

    Failure indicates: OIDC provider is missing or was not collected.

    Success indicates: OIDC provider is configured for the cluster.


    Documentation: https://docs.aws.amazon.com/rosa/latest/userguide/security-iam-awsmanpol.html
    Severity: MEDIUM - OIDC provider is required for some authentication scenarios
    """
    # Find OIDC provider files
    oidc_pattern = "*_oidc_provider_*.json"
    oidc_files = list(cluster_data.aws_dir.glob(oidc_pattern))

    if not oidc_files:
        pytest.skip("No OIDC provider found (may not be required for all cluster types)")

    print(f"\n✓ Found {len(oidc_files)} OIDC provider(s):")

    for oidc_file in oidc_files:
        with open(oidc_file) as f:
            oidc_data = json.load(f)

        url = oidc_data.get('Url', 'unknown')
        thumbprints = oidc_data.get('ThumbprintList', [])
        client_ids = oidc_data.get('ClientIDList', [])

        print(f"  URL: {url}")
        print(f"  Thumbprints: {len(thumbprints)}")
        print(f"  Client IDs: {len(client_ids)}")


@pytest.mark.aws_resources
@pytest.mark.severity("HIGH")
def test_iam_roles_have_policies_fetched(cluster_data: ClusterData):
    """IAM roles should have attached policies data collected

    Why: Attached policies define what permissions each IAM role has. Without policy
    data, we cannot validate that roles have correct permissions.

    Failure indicates: Policy data was not collected during data gathering.

    Success indicates: Policy files exist for IAM roles.


    Documentation: https://docs.aws.amazon.com/rosa/latest/userguide/security-iam-awsmanpol.html
    Severity: HIGH - Policy data is essential for permission validation
    """
    from utils.iam_diagnostics import diagnose_missing_iam_data

    # Find all IAM role files
    all_role_files = [
        f for f in cluster_data.aws_dir.glob("*_iam_role_*.json")
        if not f.name.endswith('_policies.json') and not f.name.endswith('_attached_policies.json')
    ]

    if not all_role_files:
        # No role files - diagnose why
        diagnostics = diagnose_missing_iam_data(
            cluster_data=cluster_data,
            resource_type="IAM roles",
            expected_file_pattern="*_iam_role_*.json",
            api_service="iam",
            api_operations=["get_role", "list_roles"]
        )

        error_msg = "No IAM role files found.\n\n"
        error_msg += diagnostics['diagnostic_message']
        error_msg += "\n" + diagnostics['remediation']

        pytest.fail(error_msg)

    # Check which roles have policy files
    roles_without_policies = []
    roles_with_empty_policies = []
    roles_with_policies = []

    for role_file in all_role_files:
        role_data = load_role_data(role_file)
        role_name = role_data.get('RoleName', 'unknown')

        # Look for attached policies file
        policies_file = Path(str(role_file).replace('.json', '_attached_policies.json'))

        if not policies_file.exists():
            roles_without_policies.append({
                'role_name': role_name,
                'role_file': role_file.name,
                'policies_file': policies_file.name
            })
        else:
            # Check if policies file has content
            try:
                with open(policies_file) as f:
                    policies_data = json.load(f)

                attached_policies = policies_data.get('AttachedPolicies', [])

                if not attached_policies:
                    roles_with_empty_policies.append({
                        'role_name': role_name,
                        'role_file': role_file.name,
                        'policies_file': policies_file.name
                    })
                else:
                    roles_with_policies.append({
                        'role_name': role_name,
                        'policy_count': len(attached_policies)
                    })
            except Exception as e:
                roles_without_policies.append({
                    'role_name': role_name,
                    'role_file': role_file.name,
                    'policies_file': policies_file.name,
                    'error': str(e)
                })

    if roles_without_policies or roles_with_empty_policies:
        # Build comprehensive diagnostic message
        error_msg = f"Policy data missing for {len(roles_without_policies) + len(roles_with_empty_policies)} IAM role(s).\n\n"

        if roles_without_policies:
            error_msg += "📋 Roles Missing Policy Files:\n"
            for role in roles_without_policies:
                error_msg += f"  • {role['role_name']}\n"
                error_msg += f"      Role file: {role['role_file']}\n"
                error_msg += f"      Expected policy file: {role['policies_file']} (NOT FOUND)\n"
                if 'error' in role:
                    error_msg += f"      Error: {role['error']}\n"

        if roles_with_empty_policies:
            error_msg += "\n📋 Roles with Empty Policy Files:\n"
            for role in roles_with_empty_policies:
                error_msg += f"  • {role['role_name']}\n"
                error_msg += f"      Policy file exists but contains no policies\n"

        # Check API request log for policy collection attempts
        if cluster_data.api_requests:
            requests = cluster_data.api_requests.get('requests', [])
            policy_requests = [
                req for req in requests
                if req.get('service') == 'iam' and
                   req.get('operation') in ['list_attached_role_policies', 'list_role_policies']
            ]

            error_msg += "\n📋 API Request Log Analysis:\n"

            if not policy_requests:
                error_msg += "  • No IAM policy API calls found in request log\n"
                error_msg += "  • Data collection script did NOT attempt to fetch policies\n"
                error_msg += "\n💡 Root Cause:\n"
                error_msg += "  Data collection script does not include policy collection step\n"
                error_msg += "\n🔧 Remediation:\n"
                error_msg += "  1. Update data collection script to include policy collection\n"
                error_msg += "  2. Ensure script calls ListAttachedRolePolicies for each role\n"
                error_msg += "  3. Re-run: check_cluster.py <cluster-id> --collect --resources=iam\n"

            else:
                failed_policy_requests = [req for req in policy_requests if not req.get('success', True)]

                if failed_policy_requests:
                    error_msg += f"  • Found {len(policy_requests)} policy API calls\n"
                    error_msg += f"  • {len(failed_policy_requests)} call(s) FAILED\n"
                    error_msg += "\n❌ Failed Policy API Calls:\n"

                    for req in failed_policy_requests[:3]:  # Show first 3
                        error = req.get('error', {})
                        timestamp = req.get('timestamp', 'Unknown')
                        response_code = req.get('response_code')
                        duration_ms = req.get('duration_ms')

                        error_msg += f"\n  Operation: {req.get('operation')}\n"
                        error_msg += f"  Error Code: {error.get('code', 'Unknown')}\n"
                        error_msg += f"  Error Message: {error.get('message', 'No message')}\n"
                        error_msg += f"  Timestamp: {timestamp}\n"

                        if response_code:
                            error_msg += f"  Response Code: {response_code}\n"

                        if duration_ms:
                            error_msg += f"  Duration: {duration_ms}ms\n"

                        error_msg += f"  Role ARN: {req.get('parameters', {}).get('RoleName', 'Unknown')}\n"

                    error_msg += "\n💡 Root Cause:\n"
                    error_msg += "  AWS API calls to fetch policies FAILED\n"

                    # Categorize by error type
                    error_codes = [req.get('error', {}).get('code') for req in failed_policy_requests]

                    if 'AccessDenied' in error_codes or 'UnauthorizedOperation' in error_codes:
                        error_msg += "  Reason: Insufficient IAM permissions\n"
                        error_msg += "\n🔧 Remediation:\n"
                        error_msg += "  1. Add IAM permission: iam:ListAttachedRolePolicies\n"
                        error_msg += "  2. Add IAM permission: iam:ListRolePolicies\n"
                        error_msg += "  3. Update IAM policy attached to data collection user/role\n"
                        error_msg += "  4. Re-run data collection\n"
                    else:
                        error_msg += "\n🔧 Remediation:\n"
                        error_msg += "  1. Review error messages above\n"
                        error_msg += "  2. Check AWS service health\n"
                        error_msg += "  3. Retry data collection\n"

                else:
                    error_msg += f"  • Found {len(policy_requests)} policy API calls\n"
                    error_msg += "  • All policy API calls SUCCEEDED\n"
                    error_msg += "\n💡 Analysis:\n"
                    error_msg += "  API calls succeeded but policy files not created or empty\n"
                    error_msg += "\n💡 Possible Causes:\n"
                    error_msg += "  1. Roles have no policies attached (AWS returned empty list)\n"
                    error_msg += "  2. File write failed after API call\n"
                    error_msg += "  3. Script bug in file creation logic\n"
                    error_msg += "\n🔧 Remediation:\n"
                    error_msg += "  1. Check AWS IAM console - do roles have attached policies?\n"
                    error_msg += "  2. Review data collection script logs for file write errors\n"
                    error_msg += "  3. Re-run data collection with verbose logging\n"
        else:
            error_msg += "\n📋 API Request Log:\n"
            error_msg += "  • API request log not available\n"
            error_msg += "  • Cannot determine if policy collection was attempted\n"
            error_msg += "\n🔧 Remediation:\n"
            error_msg += "  1. Use data collection script with API logging enabled\n"
            error_msg += "  2. Re-run: check_cluster.py <cluster-id> --collect\n"

        pytest.fail(error_msg)

    # All roles have policies
    print(f"\n✓ All {len(all_role_files)} IAM roles have attached policies data:\n")
    for role in sorted(roles_with_policies, key=lambda x: x['role_name']):
        print(f"  • {role['role_name']}: {role['policy_count']} attached policy/policies")


@pytest.mark.aws_resources
@pytest.mark.severity("INFO")
def test_iam_roles_summary(cluster_data: ClusterData):
    """Display summary of all IAM roles for the cluster

    Why: Provides overview of cluster IAM configuration.


    Documentation: https://docs.aws.amazon.com/rosa/latest/userguide/security-iam-awsmanpol.html
    Severity: INFO - Informational test only
    """
    # Find all IAM role files
    all_role_files = [
        f for f in cluster_data.aws_dir.glob("*_iam_role_*.json")
        if not f.name.endswith('_policies.json') and not f.name.endswith('_attached_policies.json')
    ]

    if not all_role_files:
        pytest.skip("No IAM roles found")

    print(f"\n📊 IAM Roles Summary ({len(all_role_files)} total):\n")

    roles_by_type = {
        'installer': [],
        'worker': [],
        'master': [],
        'support': [],
        'operator': []
    }

    for role_file in all_role_files:
        role_data = load_role_data(role_file)
        role_name = role_data.get('RoleName', 'unknown')
        role_arn = role_data.get('Arn', 'unknown')

        # Determine role type from filename
        filename = role_file.name
        if '_iam_role_installer_' in filename:
            role_type = 'installer'
        elif '_iam_role_worker_' in filename:
            role_type = 'worker'
        elif '_iam_role_master_' in filename:
            role_type = 'master'
        elif '_iam_role_support_' in filename:
            role_type = 'support'
        elif '_iam_role_operator-' in filename:
            role_type = 'operator'
        else:
            role_type = 'unknown'

        # Get policies
        policies = load_attached_policies(role_file)
        policy_names = [p.get('PolicyName', 'unknown') for p in policies]

        # Get tags
        tags = {tag['Key']: tag['Value'] for tag in role_data.get('Tags', [])}

        role_info = {
            'name': role_name,
            'arn': role_arn,
            'policies': policy_names,
            'tags': tags
        }

        if role_type in roles_by_type:
            roles_by_type[role_type].append(role_info)

    # Print summary by type
    for role_type, roles in roles_by_type.items():
        if roles:
            print(f"  {role_type.upper()} Roles ({len(roles)}):")
            for role in roles:
                print(f"    - {role['name']}")
                if role['policies']:
                    print(f"        Policies: {', '.join(role['policies'][:3])}")
                    if len(role['policies']) > 3:
                        print(f"        ... and {len(role['policies']) - 3} more")
            print()


@pytest.mark.aws_resources
@pytest.mark.severity("HIGH")
def test_roles_have_rosa_tags(cluster_data: ClusterData):
    """IAM roles should have ROSA identification tags

    Why: ROSA tags help identify and manage cluster resources.

    Failure indicates: Roles are missing standard ROSA tags (red-hat-managed, rosa_role_type, etc.).

    Success indicates: Roles are properly tagged for ROSA management.


    Documentation: https://docs.aws.amazon.com/rosa/latest/userguide/security-iam-awsmanpol.html
    Severity: HIGH - Tags are important for resource management
    """
    all_role_files = [
        f for f in cluster_data.aws_dir.glob("*_iam_role_*.json")
        if not f.name.endswith('_policies.json') and not f.name.endswith('_attached_policies.json')
    ]

    if not all_role_files:
        pytest.skip("No IAM roles found")

    roles_without_rosa_tags = []
    roles_with_tags = []

    for role_file in all_role_files:
        role_data = load_role_data(role_file)
        role_name = role_data.get('RoleName', 'unknown')
        tags = {tag['Key']: tag['Value'] for tag in role_data.get('Tags', [])}

        # Check for ROSA tags
        has_red_hat_managed = 'red-hat-managed' in tags
        has_rosa_role_type = 'rosa_role_type' in tags

        if has_red_hat_managed and has_rosa_role_type:
            roles_with_tags.append({
                'name': role_name,
                'role_type': tags.get('rosa_role_type'),
                'red_hat_managed': tags.get('red-hat-managed')
            })
        else:
            roles_without_rosa_tags.append({
                'name': role_name,
                'has_red_hat_managed': has_red_hat_managed,
                'has_rosa_role_type': has_rosa_role_type,
                'tags': list(tags.keys())
            })

    if roles_with_tags:
        print(f"\n✓ {len(roles_with_tags)} role(s) with proper ROSA tags:")
        for role in roles_with_tags[:5]:  # Show first 5
            print(f"  - {role['name']} (type: {role['role_type']})")
        if len(roles_with_tags) > 5:
            print(f"  ... and {len(roles_with_tags) - 5} more")

    if roles_without_rosa_tags:
        print(f"\n⚠ {len(roles_without_rosa_tags)} role(s) missing ROSA tags:")
        print(json.dumps(roles_without_rosa_tags, indent=2))

        pytest.fail(
            f"{len(roles_without_rosa_tags)} role(s) missing standard ROSA tags. "
            "Roles should have 'red-hat-managed' and 'rosa_role_type' tags."
        )
