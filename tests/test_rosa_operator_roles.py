"""
ROSA Operator Role Individual Tests

Individual tests for each ROSA operator role required by the cluster.
Each operator has its own test to provide granular pass/fail status.

Documentation:
- ROSA Operator Roles: https://docs.redhat.com/en/documentation/red_hat_openshift_service_on_aws/4/html/architecture/rosa-sts-about-iam-resources#rosa-sts-operator-roles
- Operator IAM Roles Reference: https://docs.redhat.com/en/documentation/red_hat_openshift_service_on_aws/4/html/introduction_to_rosa/rosa-sts-about-iam-resources#rosa-sts-understanding-aws-account-association
- Creating Operator Roles: https://docs.redhat.com/en/documentation/red_hat_openshift_service_on_aws/4/html/install_rosa_classic_clusters/rosa-sts-creating-a-cluster-quickly#rosa-sts-creating-operator-roles-and-policies_rosa-sts-creating-a-cluster-quickly
"""

import pytest
import json
from pathlib import Path
from typing import Dict, Any, List
from models.cluster import ClusterData


def check_operator_role(cluster_data: ClusterData, operator_name: str) -> Dict[str, Any]:
    """
    Check for specific operator role with comprehensive diagnostics.

    Args:
        cluster_data: ClusterData instance
        operator_name: Operator name pattern (e.g., 'ebs-cloud-credentials')

    Returns:
        Dict with availability status and diagnostic information
    """
    result = {
        'available': False,
        'reason': 'unknown',
        'role_file': None,
        'role_data': None,
        'policies': []
    }

    # Search for operator role file
    pattern = f"*_iam_role_operator-*{operator_name}*.json"
    role_files = [
        f for f in cluster_data.aws_dir.glob(pattern)
        if not f.name.endswith('_policies.json') and not f.name.endswith('_attached_policies.json')
    ]

    if not role_files:
        # Check if ANY operator roles exist
        all_operator_pattern = "*_iam_role_operator-*.json"
        all_operator_files = [
            f for f in cluster_data.aws_dir.glob(all_operator_pattern)
            if not f.name.endswith('_policies.json') and not f.name.endswith('_attached_policies.json')
        ]

        if not all_operator_files:
            result['reason'] = 'no_operator_roles_collected'
        else:
            result['reason'] = 'operator_role_not_found'
            result['other_operators'] = [f.name for f in all_operator_files]

        return result

    # Role found - load data
    try:
        role_file = role_files[0]
        with open(role_file) as f:
            data = json.load(f)

        role_data = data.get('Role', {})

        # Load attached policies
        policies_file = Path(str(role_file).replace('.json', '_attached_policies.json'))
        policies = []
        if policies_file.exists():
            with open(policies_file) as f:
                policies_data = json.load(f)
            policies = policies_data.get('AttachedPolicies', [])

        result['available'] = True
        result['reason'] = 'found'
        result['role_file'] = role_file
        result['role_data'] = role_data
        result['policies'] = policies

    except Exception as e:
        result['reason'] = 'file_read_error'
        result['error'] = str(e)

    return result


# ============================================================================
# EBS CSI Driver Operator
# ============================================================================

@pytest.mark.aws_resources
@pytest.mark.iam_roles
@pytest.mark.operator_roles
@pytest.mark.severity("CRITICAL")
def test_ebs_csi_driver_operator_role_exists(cluster_data: ClusterData):
    """EBS CSI driver operator role must exist

    Why: The EBS CSI driver requires IAM permissions to create, attach, and manage
    EBS volumes for persistent storage in the cluster.

    Failure indicates:
    - Operator role was not created
    - Persistent volume provisioning will fail
    - Pods requiring persistent storage cannot start

    Success indicates: EBS CSI driver operator role exists.

    Remediation:
    1. Create operator roles: rosa create operator-roles --cluster <cluster-name>
    2. Verify role exists: aws iam get-role --role-name <prefix>-openshift-cluster-csi-drivers-ebs-cloud-credentials


    Documentation: https://docs.redhat.com/en/documentation/red_hat_openshift_service_on_aws/4/html/prepare_your_environment/rosa-sts-aws-prereqs#rosa-sts-understanding-aws-account-association
    Severity: CRITICAL - Required for persistent volume provisioning
    """
    result = check_operator_role(cluster_data, 'ebs-cloud-credentials')

    if not result['available']:
        error_msg = "EBS CSI driver operator role not found.\n\n"

        if result['reason'] == 'no_operator_roles_collected':
            error_msg += "📋 Diagnostic Information:\n"
            error_msg += "  • No operator role files found in data directory\n"
            error_msg += "  • Data collection may not have retrieved operator roles\n"
            error_msg += "\n🔧 Remediation:\n"
            error_msg += "  • Re-run data collection with operator role retrieval\n"
            error_msg += "  • Ensure IAM permissions include iam:GetRole, iam:ListRoles\n"

        elif result['reason'] == 'operator_role_not_found':
            error_msg += "📋 Diagnostic Information:\n"
            error_msg += "  • Other operator roles were found, but not EBS CSI driver role\n"
            error_msg += "\n  Found operators:\n"
            for op in result.get('other_operators', []):
                error_msg += f"    - {op}\n"
            error_msg += "\n💡 Possible Causes:\n"
            error_msg += "  1. EBS CSI driver operator role was not created\n"
            error_msg += "  2. Role was deleted after cluster creation\n"
            error_msg += "\n🔧 Remediation:\n"
            error_msg += "  • Create missing operator role:\n"
            error_msg += "    rosa create operator-roles --cluster <cluster-name> --mode manual\n"

        error_msg += "\n📄 Required Role:\n"
        error_msg += "  • Role name pattern: <prefix>-openshift-cluster-csi-drivers-ebs-cloud-credentials\n"
        error_msg += "  • Required for: EBS volume provisioning, attachment, and management\n"

        pytest.fail(error_msg)

    role_data = result['role_data']
    role_name = role_data.get('RoleName', 'unknown')
    role_arn = role_data.get('Arn', 'unknown')

    print(f"\n✓ Found EBS CSI driver operator role")
    print(f"  Role: {role_name}")
    print(f"  ARN: {role_arn}")

    # Check policies
    policies = result['policies']
    if policies:
        print(f"  Policies: {len(policies)}")
        for policy in policies:
            print(f"    ✓ {policy.get('PolicyName')}")
    else:
        print(f"  ⚠ WARNING: No policies attached")


# ============================================================================
# Cloud Credentials Operator
# ============================================================================

@pytest.mark.aws_resources
@pytest.mark.iam_roles
@pytest.mark.operator_roles
@pytest.mark.severity("HIGH")
def test_cloud_credentials_operator_role_exists(cluster_data: ClusterData):
    """Cloud credentials operator role must exist

    Why: Manages AWS credentials for other operators in the cluster.

    Failure indicates: Cloud credentials operator cannot manage credentials.

    Success indicates: Cloud credentials operator role exists.


    Documentation: https://docs.redhat.com/en/documentation/red_hat_openshift_service_on_aws/4/html/prepare_your_environment/rosa-sts-aws-prereqs#rosa-sts-understanding-aws-account-association
    Severity: HIGH - Required for operator credential management
    """
    result = check_operator_role(cluster_data, 'cloud-credentials')

    if not result['available']:
        if result['reason'] == 'no_operator_roles_collected':
            pytest.skip("No operator roles collected")

        pytest.fail(
            f"Cloud credentials operator role not found.\n"
            f"Expected role pattern: <prefix>-openshift-cloud-credential-operator-cloud-credentials"
        )

    role_data = result['role_data']
    print(f"\n✓ Found cloud credentials operator role: {role_data.get('RoleName')}")


# ============================================================================
# Ingress Operator
# ============================================================================

@pytest.mark.aws_resources
@pytest.mark.iam_roles
@pytest.mark.operator_roles
@pytest.mark.severity("HIGH")
def test_ingress_operator_role_exists(cluster_data: ClusterData):
    """Ingress operator role must exist

    Why: The ingress operator requires IAM permissions to create and manage
    load balancers for application ingress routes.

    Failure indicates:
    - Operator role was not created
    - Ingress routes cannot create load balancers
    - Applications cannot be accessed externally

    Success indicates: Ingress operator role exists.

    Remediation:
    1. Create operator roles: rosa create operator-roles --cluster <cluster-name>
    2. Verify role: aws iam get-role --role-name <prefix>-openshift-ingress-operator-cloud-credentials


    Documentation: https://docs.redhat.com/en/documentation/red_hat_openshift_service_on_aws/4/html/prepare_your_environment/rosa-sts-aws-prereqs#rosa-sts-understanding-aws-account-association
    Severity: HIGH - Required for application ingress
    """
    result = check_operator_role(cluster_data, 'ingress-operator-cloud-credentials')

    if not result['available']:
        if result['reason'] == 'no_operator_roles_collected':
            pytest.skip("No operator roles collected")

        error_msg = "Ingress operator role not found.\n\n"
        error_msg += "📋 Impact:\n"
        error_msg += "  • Cannot create load balancers for ingress routes\n"
        error_msg += "  • Application external access will fail\n"
        error_msg += "\n🔧 Remediation:\n"
        error_msg += "  • Create operator roles: rosa create operator-roles --cluster <cluster-name>\n"
        error_msg += "\n📄 Required Role:\n"
        error_msg += "  • Role pattern: <prefix>-openshift-ingress-operator-cloud-credentials\n"

        pytest.fail(error_msg)

    role_data = result['role_data']
    role_name = role_data.get('RoleName')

    print(f"\n✓ Found ingress operator role: {role_name}")

    # Check policies
    policies = result['policies']
    if policies:
        print(f"  Policies: {len(policies)}")
    else:
        pytest.fail(f"Ingress operator role '{role_name}' has no attached policies")


# ============================================================================
# Image Registry Operator
# ============================================================================

@pytest.mark.aws_resources
@pytest.mark.iam_roles
@pytest.mark.operator_roles
@pytest.mark.severity("HIGH")
def test_image_registry_operator_role_exists(cluster_data: ClusterData):
    """Image registry operator role must exist

    Why: The image registry operator requires IAM permissions to manage
    S3 buckets for the internal container image registry.

    Failure indicates:
    - Image registry cannot store container images
    - Image builds and deployments will fail

    Success indicates: Image registry operator role exists.


    Documentation: https://docs.redhat.com/en/documentation/red_hat_openshift_service_on_aws/4/html/prepare_your_environment/rosa-sts-aws-prereqs#rosa-sts-understanding-aws-account-association
    Severity: HIGH - Required for image registry storage
    """
    result = check_operator_role(cluster_data, 'image-registry')

    if not result['available']:
        if result['reason'] == 'no_operator_roles_collected':
            pytest.skip("No operator roles collected")

        pytest.fail(
            "Image registry operator role not found.\n"
            "Expected: <prefix>-openshift-image-registry-installer-cloud-credentials"
        )

    role_data = result['role_data']
    print(f"\n✓ Found image registry operator role: {role_data.get('RoleName')}")


# ============================================================================
# Machine API Operator
# ============================================================================

@pytest.mark.aws_resources
@pytest.mark.iam_roles
@pytest.mark.operator_roles
@pytest.mark.severity("HIGH")
def test_machine_api_operator_role_exists(cluster_data: ClusterData):
    """Machine API operator role must exist

    Why: The machine API operator requires IAM permissions to create and manage
    EC2 instances for worker nodes and machine sets.

    Failure indicates:
    - Cannot create or scale worker nodes
    - Machine autoscaling will not work
    - Node replacement will fail

    Success indicates: Machine API operator role exists.


    Documentation: https://docs.redhat.com/en/documentation/red_hat_openshift_service_on_aws/4/html/prepare_your_environment/rosa-sts-aws-prereqs#rosa-sts-understanding-aws-account-association
    Severity: HIGH - Required for node management and scaling
    """
    result = check_operator_role(cluster_data, 'machine-api-aws')

    if not result['available']:
        if result['reason'] == 'no_operator_roles_collected':
            pytest.skip("No operator roles collected")

        pytest.fail(
            "Machine API operator role not found.\n"
            "Expected: <prefix>-openshift-machine-api-aws-cloud-credentials"
        )

    role_data = result['role_data']
    print(f"\n✓ Found machine API operator role: {role_data.get('RoleName')}")


# ============================================================================
# Cloud Network Config Controller
# ============================================================================

@pytest.mark.aws_resources
@pytest.mark.iam_roles
@pytest.mark.operator_roles
@pytest.mark.severity("MEDIUM")
def test_cloud_network_config_controller_role_exists(cluster_data: ClusterData):
    """Cloud network config controller operator role must exist

    Why: Manages cloud-specific network configuration for the cluster.

    Failure indicates: Network configuration management may be impaired.

    Success indicates: Cloud network config controller role exists.


    Documentation: https://docs.redhat.com/en/documentation/red_hat_openshift_service_on_aws/4/html/prepare_your_environment/rosa-sts-aws-prereqs#rosa-sts-understanding-aws-account-association
    Severity: MEDIUM - Required for cloud network configuration
    """
    result = check_operator_role(cluster_data, 'cloud-network-config-controller')

    if not result['available']:
        if result['reason'] == 'no_operator_roles_collected':
            pytest.skip("No operator roles collected")

        pytest.skip(
            "Cloud network config controller role not found (may not be required for all cluster versions)"
        )

    role_data = result['role_data']
    print(f"\n✓ Found cloud network config controller role: {role_data.get('RoleName')}")


# ============================================================================
# Additional Operator Roles
# ============================================================================

@pytest.mark.aws_resources
@pytest.mark.iam_roles
@pytest.mark.operator_roles
@pytest.mark.severity("LOW")
def test_cloud_controller_manager_role_exists(cluster_data: ClusterData):
    """Cloud controller manager role (if present)
    Documentation: https://docs.redhat.com/en/documentation/red_hat_openshift_service_on_aws/4/html/prepare_your_environment/rosa-sts-aws-prereqs#rosa-sts-understanding-aws-account-association
    """
    result = check_operator_role(cluster_data, 'cloud-controller-manager')

    if result['available']:
        print(f"\n✓ Found cloud controller manager role: {result['role_data'].get('RoleName')}")
    else:
        pytest.skip("Cloud controller manager role not found (may not be required)")


@pytest.mark.aws_resources
@pytest.mark.iam_roles
@pytest.mark.operator_roles
@pytest.mark.severity("LOW")
def test_control_plane_operator_role_exists(cluster_data: ClusterData):
    """Control plane operator role (if present)
    Documentation: https://docs.redhat.com/en/documentation/red_hat_openshift_service_on_aws/4/html/prepare_your_environment/rosa-sts-aws-prereqs#rosa-sts-understanding-aws-account-association
    """
    result = check_operator_role(cluster_data, 'control-plane-operator')

    if result['available']:
        print(f"\n✓ Found control plane operator role: {result['role_data'].get('RoleName')}")
    else:
        pytest.skip("Control plane operator role not found (may not be required)")


@pytest.mark.aws_resources
@pytest.mark.iam_roles
@pytest.mark.operator_roles
@pytest.mark.severity("LOW")
def test_kube_controller_manager_role_exists(cluster_data: ClusterData):
    """Kube controller manager role (if present)
    Documentation: https://docs.redhat.com/en/documentation/red_hat_openshift_service_on_aws/4/html/prepare_your_environment/rosa-sts-aws-prereqs#rosa-sts-understanding-aws-account-association
    """
    result = check_operator_role(cluster_data, 'kube-controller-manager')

    if result['available']:
        print(f"\n✓ Found kube controller manager role: {result['role_data'].get('RoleName')}")
    else:
        pytest.skip("Kube controller manager role not found (may not be required)")


# ============================================================================
# Operator Roles Summary
# ============================================================================

@pytest.mark.aws_resources
@pytest.mark.iam_roles
@pytest.mark.operator_roles
@pytest.mark.severity("INFO")
def test_operator_roles_summary(cluster_data: ClusterData):
    """Display summary of all operator roles


    Documentation: https://docs.redhat.com/en/documentation/red_hat_openshift_service_on_aws/4/html/prepare_your_environment/rosa-sts-aws-prereqs#rosa-sts-understanding-aws-account-association
    Severity: INFO - Informational test only
    """
    # Find all operator role files
    operator_pattern = "*_iam_role_operator-*.json"
    operator_files = [
        f for f in cluster_data.aws_dir.glob(operator_pattern)
        if not f.name.endswith('_policies.json') and not f.name.endswith('_attached_policies.json')
    ]

    if not operator_files:
        pytest.skip("No operator roles found")

    print(f"\n📊 Operator Roles Summary ({len(operator_files)} total):\n")

    for role_file in operator_files:
        try:
            with open(role_file) as f:
                data = json.load(f)
            role_data = data.get('Role', {})
            role_name = role_data.get('RoleName', 'unknown')

            # Load policies
            policies_file = Path(str(role_file).replace('.json', '_attached_policies.json'))
            policy_count = 0
            if policies_file.exists():
                with open(policies_file) as f:
                    policies_data = json.load(f)
                policy_count = len(policies_data.get('AttachedPolicies', []))

            # Extract operator name from role name
            operator_name = 'unknown'
            if 'openshift-' in role_name:
                parts = role_name.split('openshift-', 1)
                if len(parts) > 1:
                    operator_name = 'openshift-' + parts[1]

            print(f"  ✓ {operator_name}")
            print(f"      Role: {role_name}")
            print(f"      Policies: {policy_count}")
            print()

        except Exception as e:
            print(f"  ✗ Error reading {role_file.name}: {e}")
