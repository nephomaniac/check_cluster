"""
Tests for AWS Resources from cluster.json

Validates that AWS resources specified in cluster.json .aws section
were successfully fetched from AWS and saved to files.
"""

import json
import pytest
from pathlib import Path
from models.cluster import ClusterData


def has_sts_enabled(cluster_data: ClusterData) -> bool:
    """Check if cluster has STS enabled."""
    return cluster_data.cluster_json.get('aws', {}).get('sts', {}).get('enabled', False)


@pytest.fixture
def sts_config(cluster_data: ClusterData):
    """Get STS configuration from cluster.json if available."""
    return cluster_data.cluster_json.get('aws', {}).get('sts', {})


@pytest.fixture
def aws_config(cluster_data: ClusterData):
    """Get AWS configuration from cluster.json."""
    return cluster_data.cluster_json.get('aws', {})


@pytest.mark.aws_resources
def test_sts_configuration_exists(cluster_data: ClusterData, sts_config):
    """STS configuration should exist and be enabled for STS clusters.

    Why: ROSA STS clusters use AWS STS (Security Token Service) with IAM roles
    for authentication and authorization rather than long-lived AWS access keys.

    Failure indicates: This may not be an STS cluster, or cluster configuration
    is incomplete.
    """
    if not sts_config:
        print("\n✗ No STS configuration in cluster.json")
        pytest.skip("No STS configuration in cluster.json")

    if not sts_config.get('enabled'):
        print(f"\n✗ STS not enabled for this cluster")
        print(json.dumps({"StsEnabled": False}, indent=2))
        pytest.skip("STS not enabled for this cluster")

    print(f"\n✓ STS configuration found:")
    print(json.dumps({
        "StsEnabled": sts_config.get('enabled'),
        "InstallerRoleArn": sts_config.get('role_arn'),
        "OidcEndpointUrl": sts_config.get('oidc_endpoint_url'),
        "SupportRoleArn": sts_config.get('support_role_arn')
    }, indent=2))

    assert sts_config.get('enabled') is True, "STS should be enabled"
    assert sts_config.get('role_arn'), "Installer role ARN should be present"
    assert sts_config.get('oidc_endpoint_url'), "OIDC endpoint URL should be present"


@pytest.mark.aws_resources
def test_installer_role_fetched(cluster_data: ClusterData, sts_config):
    """Installer IAM role must be fetched from AWS.

    Why: The installer role is used by ROSA to provision and manage cluster
    infrastructure. It must exist in AWS for cluster operations.

    Failure indicates: Role fetch failed or role doesn't exist in AWS.
    Check get_install_artifacts.py output for errors.
    """
    if not has_sts_enabled(cluster_data):
        pytest.skip("STS not enabled")

    role_arn = sts_config.get('role_arn')
    if not role_arn:
        pytest.skip("No installer role ARN in cluster.json")

    # Extract role name from ARN
    role_name = role_arn.split('/')[-1]

    # Check for role file
    role_file = cluster_data.aws_dir / f"{cluster_data.cluster_id}_iam_role_installer_{role_name}.json"

    if role_file.exists():
        print(f"\n✓ Installer role found:")
        print(json.dumps({
            "RoleName": role_name,
            "RoleArn": role_arn,
            "RoleFile": role_file.name
        }, indent=2))
    else:
        print(f"\n✗ Installer role file not found:")
        print(json.dumps({
            "RoleName": role_name,
            "RoleArn": role_arn,
            "ExpectedFile": role_file.name
        }, indent=2))

    assert role_file.exists(), \
        f"Installer role file not found: {role_file.name}. " \
        f"Run get_install_artifacts.py to fetch IAM resources."


@pytest.mark.aws_resources
def test_support_role_fetched(cluster_data: ClusterData, sts_config):
    """Support IAM role must be fetched from AWS.

    Why: The support role allows Red Hat SRE to access and troubleshoot
    the cluster when needed.

    Failure indicates: Role fetch failed or role doesn't exist in AWS.
    """
    if not has_sts_enabled(cluster_data):
        pytest.skip("STS not enabled")

    role_arn = sts_config.get('support_role_arn')
    if not role_arn:
        pytest.skip("No support role ARN in cluster.json")

    role_name = role_arn.split('/')[-1]
    role_file = cluster_data.aws_dir / f"{cluster_data.cluster_id}_iam_role_support_{role_name}.json"

    if role_file.exists():
        print(f"\n✓ Support role found:")
        print(json.dumps({
            "RoleName": role_name,
            "RoleArn": role_arn,
            "RoleFile": role_file.name
        }, indent=2))
    else:
        print(f"\n✗ Support role file not found:")
        print(json.dumps({
            "RoleName": role_name,
            "RoleArn": role_arn,
            "ExpectedFile": role_file.name
        }, indent=2))

    assert role_file.exists(), \
        f"Support role file not found: {role_file.name}. " \
        f"Run get_install_artifacts.py to fetch IAM resources."


@pytest.mark.aws_resources
def test_master_instance_role_fetched(cluster_data: ClusterData, sts_config):
    """Master/ControlPlane IAM instance role must be fetched from AWS.

    Why: Master nodes use this IAM role to access AWS services required
    for cluster control plane operations.

    Failure indicates: Role fetch failed or role doesn't exist in AWS.
    """
    if not has_sts_enabled(cluster_data):
        pytest.skip("STS not enabled")

    instance_roles = sts_config.get('instance_iam_roles', {})
    role_arn = instance_roles.get('master_role_arn')

    if not role_arn:
        pytest.skip("No master instance role ARN in cluster.json")

    role_name = role_arn.split('/')[-1]
    role_file = cluster_data.aws_dir / f"{cluster_data.cluster_id}_iam_role_master_{role_name}.json"

    if role_file.exists():
        print(f"\n✓ Master instance role found:")
        print(json.dumps({
            "RoleName": role_name,
            "RoleArn": role_arn,
            "RoleFile": role_file.name
        }, indent=2))
    else:
        print(f"\n✗ Master instance role file not found:")
        print(json.dumps({
            "RoleName": role_name,
            "RoleArn": role_arn,
            "ExpectedFile": role_file.name
        }, indent=2))

    assert role_file.exists(), \
        f"Master instance role file not found: {role_file.name}. " \
        f"Run get_install_artifacts.py to fetch IAM resources."


@pytest.mark.aws_resources
def test_worker_instance_role_fetched(cluster_data: ClusterData, sts_config):
    """Worker IAM instance role must be fetched from AWS.

    Why: Worker nodes use this IAM role to access AWS services required
    for running workloads and cluster operations.

    Failure indicates: Role fetch failed or role doesn't exist in AWS.
    """
    if not has_sts_enabled(cluster_data):
        pytest.skip("STS not enabled")

    instance_roles = sts_config.get('instance_iam_roles', {})
    role_arn = instance_roles.get('worker_role_arn')

    if not role_arn:
        pytest.skip("No worker instance role ARN in cluster.json")

    role_name = role_arn.split('/')[-1]
    role_file = cluster_data.aws_dir / f"{cluster_data.cluster_id}_iam_role_worker_{role_name}.json"

    if role_file.exists():
        print(f"\n✓ Worker instance role found:")
        print(json.dumps({
            "RoleName": role_name,
            "RoleArn": role_arn,
            "RoleFile": role_file.name
        }, indent=2))
    else:
        print(f"\n✗ Worker instance role file not found:")
        print(json.dumps({
            "RoleName": role_name,
            "RoleArn": role_arn,
            "ExpectedFile": role_file.name
        }, indent=2))

    assert role_file.exists(), \
        f"Worker instance role file not found: {role_file.name}. " \
        f"Run get_install_artifacts.py to fetch IAM resources."


@pytest.mark.aws_resources
def test_all_operator_roles_fetched(cluster_data: ClusterData, sts_config):
    """All operator IAM roles must be fetched from AWS.

    Why: Operator roles allow OpenShift operators to access AWS services
    (e.g., EBS CSI driver, image registry, ingress controller).

    Failure indicates: One or more operator roles failed to fetch or don't
    exist in AWS. This could cause operator functionality issues.
    """
    if not has_sts_enabled(cluster_data):
        pytest.skip("STS not enabled")

    operator_roles = sts_config.get('operator_iam_roles', [])

    if not operator_roles:
        pytest.skip("No operator roles in cluster.json")

    missing_roles = []
    found_roles = []

    for op_role in operator_roles:
        role_arn = op_role.get('role_arn')
        namespace = op_role.get('namespace', 'unknown')
        name = op_role.get('name', 'unknown')

        if not role_arn:
            continue

        role_name = role_arn.split('/')[-1]
        safe_role_type = f"operator-{namespace}-{name}".replace('/', '-').replace(':', '-')
        role_file = cluster_data.aws_dir / f"{cluster_data.cluster_id}_iam_role_{safe_role_type}_{role_name}.json"

        if role_file.exists():
            found_roles.append({
                "Operator": f"{namespace}/{name}",
                "RoleName": role_name,
                "RoleArn": role_arn
            })
        else:
            missing_roles.append(f"{namespace}/{name} ({role_name})")

    if found_roles:
        print(f"\n✓ Found {len(found_roles)} operator roles:")
        print(json.dumps(found_roles, indent=2))

    if missing_roles:
        print(f"\n✗ Missing {len(missing_roles)} operator roles:")
        print(json.dumps(missing_roles, indent=2))

    assert not missing_roles, \
        f"Operator role files not found for: {', '.join(missing_roles)}. " \
        f"Run get_install_artifacts.py to fetch IAM resources."


@pytest.mark.aws_resources
def test_iam_roles_have_policies_fetched(cluster_data: ClusterData, sts_config):
    """IAM roles should have their policies fetched.

    Why: IAM role policies define what AWS actions the role can perform.
    Validating policies exist helps troubleshoot permission issues.

    Failure indicates: Policy fetch failed. This is non-critical but helpful
    for troubleshooting.
    """
    if not has_sts_enabled(cluster_data):
        pytest.skip("STS not enabled")

    # Check installer role policies
    role_arn = sts_config.get('role_arn')
    if role_arn:
        role_name = role_arn.split('/')[-1]
        policies_file = cluster_data.aws_dir / f"{cluster_data.cluster_id}_iam_role_installer_{role_name}_policies.json"
        attached_file = cluster_data.aws_dir / f"{cluster_data.cluster_id}_iam_role_installer_{role_name}_attached_policies.json"

        # At least one policy file should exist (inline or attached)
        has_policies = policies_file.exists() or attached_file.exists()

        policy_files = []
        if policies_file.exists():
            policy_files.append({"Type": "Inline", "File": policies_file.name})
        if attached_file.exists():
            policy_files.append({"Type": "Attached", "File": attached_file.name})

        if has_policies:
            print(f"\n✓ Installer role policies found:")
            print(json.dumps({
                "RoleName": role_name,
                "PolicyFiles": policy_files
            }, indent=2))
        else:
            print(f"\n✗ No policy files found:")
            print(json.dumps({
                "RoleName": role_name,
                "ExpectedFiles": [
                    policies_file.name,
                    attached_file.name
                ]
            }, indent=2))

        assert has_policies, \
            f"No policy files found for installer role {role_name}. " \
            f"Run get_install_artifacts.py to fetch IAM resources."


@pytest.mark.aws_resources
def test_oidc_provider_fetched(cluster_data: ClusterData, sts_config):
    """OIDC provider must be fetched from AWS.

    Why: The OIDC provider enables STS authentication for service accounts.
    OpenShift operators use OIDC to assume IAM roles without credentials.

    Failure indicates: OIDC provider fetch failed or provider doesn't exist
    in AWS. This would prevent operators from functioning correctly.
    """
    if not has_sts_enabled(cluster_data):
        pytest.skip("STS not enabled")

    oidc_url = sts_config.get('oidc_endpoint_url')
    if not oidc_url:
        pytest.skip("No OIDC endpoint URL in cluster.json")

    # OIDC provider files should exist
    oidc_list_file = cluster_data.aws_dir / f"{cluster_data.cluster_id}_oidc_providers_list.json"

    # Check for specific OIDC provider file (filename contains sanitized ARN)
    # We'll look for any file matching the pattern
    oidc_files = list(cluster_data.aws_dir.glob(f"{cluster_data.cluster_id}_oidc_provider_*.json"))

    # Exclude the list file
    oidc_files = [f for f in oidc_files if not f.name.endswith('_oidc_providers_list.json')]

    if oidc_list_file.exists() and oidc_files:
        print(f"\n✓ OIDC provider found:")
        print(json.dumps({
            "OidcEndpointUrl": oidc_url,
            "ListFile": oidc_list_file.name,
            "ProviderFiles": [f.name for f in oidc_files]
        }, indent=2))
    else:
        print(f"\n✗ OIDC provider files not found:")
        print(json.dumps({
            "OidcEndpointUrl": oidc_url,
            "ListFileExists": oidc_list_file.exists(),
            "ProviderFilesFound": len(oidc_files),
            "ExpectedListFile": oidc_list_file.name
        }, indent=2))

    assert oidc_list_file.exists(), \
        f"OIDC providers list file not found: {oidc_list_file.name}. " \
        f"Run get_install_artifacts.py to fetch IAM resources."

    assert oidc_files, \
        f"No OIDC provider detail files found. " \
        f"Run get_install_artifacts.py to fetch IAM resources."


@pytest.mark.aws_resources
def test_iam_role_files_contain_valid_data(cluster_data: ClusterData, sts_config):
    """IAM role files should contain valid AWS response data.

    Why: Ensures the fetched role data is complete and parseable.

    Failure indicates: File corruption or incomplete data fetch.
    """
    if not has_sts_enabled(cluster_data):
        pytest.skip("STS not enabled")

    # Check installer role if it exists
    role_arn = sts_config.get('role_arn')
    if not role_arn:
        pytest.skip("No installer role ARN in cluster.json")

    role_name = role_arn.split('/')[-1]
    role_file = cluster_data.aws_dir / f"{cluster_data.cluster_id}_iam_role_installer_{role_name}.json"

    if not role_file.exists():
        pytest.skip(f"Role file not found: {role_file.name}")

    with open(role_file) as f:
        role_data = json.load(f)

    # Validate response structure
    assert 'Role' in role_data, "IAM role response should contain 'Role' key"

    role = role_data['Role']

    print(f"\n✓ IAM role data validated:")
    print(json.dumps({
        "RoleName": role.get('RoleName'),
        "Arn": role.get('Arn'),
        "HasAssumeRolePolicy": 'AssumeRolePolicyDocument' in role,
        "CreateDate": role.get('CreateDate'),
        "RoleFile": role_file.name
    }, indent=2, default=str))

    assert role.get('RoleName') == role_name, \
        f"Role name mismatch: expected {role_name}, got {role.get('RoleName')}"
    assert role.get('Arn') == role_arn, \
        f"Role ARN mismatch: expected {role_arn}, got {role.get('Arn')}"
    assert 'AssumeRolePolicyDocument' in role, \
        "Role should have AssumeRolePolicyDocument"


@pytest.mark.aws_resources
def test_audit_log_role_fetched_if_configured(cluster_data: ClusterData, aws_config):
    """Audit log IAM role should be fetched if configured.

    Why: The audit log role allows ROSA to forward audit logs to CloudWatch.

    Failure indicates: Role fetch failed. This is optional, so failure is
    non-critical if audit logging isn't configured.
    """
    if not has_sts_enabled(cluster_data):
        pytest.skip("STS not enabled")

    audit_config = aws_config.get('audit_log', {})
    role_arn = audit_config.get('role_arn')

    if not role_arn:
        pytest.skip("No audit log role configured")

    role_name = role_arn.split('/')[-1]
    role_file = cluster_data.aws_dir / f"{cluster_data.cluster_id}_iam_role_audit-log_{role_name}.json"

    if role_file.exists():
        print(f"\n✓ Audit log role found:")
        print(json.dumps({
            "RoleName": role_name,
            "RoleArn": role_arn,
            "RoleFile": role_file.name
        }, indent=2))
    else:
        print(f"\n✗ Audit log role file not found:")
        print(json.dumps({
            "RoleName": role_name,
            "RoleArn": role_arn,
            "ExpectedFile": role_file.name
        }, indent=2))

    assert role_file.exists(), \
        f"Audit log role file not found: {role_file.name}. " \
        f"Run get_install_artifacts.py to fetch IAM resources."
