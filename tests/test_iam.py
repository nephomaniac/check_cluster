"""
IAM Tests

Validates IAM instance profiles and roles for EC2 instances.

Documentation:
- ROSA IAM Resources: https://docs.redhat.com/en/documentation/red_hat_openshift_service_on_aws/4/html/introduction_to_rosa/rosa-sts-about-iam-resources
- AWS IAM Roles: https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles.html
- ROSA STS Mode: https://docs.redhat.com/en/documentation/red_hat_openshift_service_on_aws/4/html/architecture/rosa-sts-about-iam-resources
"""

import pytest
import json
from pathlib import Path
from models.cluster import ClusterData


@pytest.mark.instances
def test_iam_instance_profiles_exist(cluster_data: ClusterData, infra_id: str):
    """Cluster should have IAM instance profiles for EC2 instances
    Documentation: https://docs.redhat.com/en/documentation/red_hat_openshift_service_on_aws/4/html/prepare_your_environment/rosa-sts-aws-prereqs#rosa-sts-overview-of-the-deployment-workflow
    """
    iam_file = cluster_data.aws_dir / f"{cluster_data.cluster_id}_iam_instance_profiles.json"

    if not iam_file.exists():
        pytest.skip(f"IAM instance profiles file not found: {iam_file}")

    with open(iam_file) as f:
        iam_data = json.load(f)

    profiles = iam_data.get('InstanceProfiles', [])

    if profiles:
        print(f"\n✓ Found {len(profiles)} IAM instance profiles:")
        profile_summary = [{
            "InstanceProfileId": profile.get("InstanceProfileId"),
            "InstanceProfileName": profile.get("InstanceProfileName"),
            "Arn": profile.get("Arn"),
            "RoleCount": len(profile.get("Roles", [])),
            "RoleNames": [role.get("RoleName") for role in profile.get("Roles", [])]
        } for profile in profiles]
        print(json.dumps(profile_summary, indent=2))
    else:
        print(f"\n✗ No IAM instance profiles found for cluster {infra_id}")

    # IAM profiles are expected for ROSA clusters
    assert len(profiles) > 0, f"No IAM instance profiles found for cluster {infra_id}"


@pytest.mark.instances
def test_master_iam_instance_profile_exists(cluster_data: ClusterData, infra_id: str):
    """Cluster should have IAM instance profile for master/control plane nodes
    Documentation: https://docs.redhat.com/en/documentation/red_hat_openshift_service_on_aws/4/html/prepare_your_environment/rosa-sts-aws-prereqs#rosa-sts-overview-of-the-deployment-workflow
    """
    iam_file = cluster_data.aws_dir / f"{cluster_data.cluster_id}_iam_instance_profiles.json"

    if not iam_file.exists():
        pytest.skip(f"IAM instance profiles file not found: {iam_file}")

    with open(iam_file) as f:
        iam_data = json.load(f)

    profiles = iam_data.get('InstanceProfiles', [])

    # Find master node profile
    master_profiles = [
        profile for profile in profiles
        if 'master' in profile.get('InstanceProfileName', '').lower() or
           'control' in profile.get('InstanceProfileName', '').lower()
    ]

    if master_profiles:
        print(f"\n✓ Found {len(master_profiles)} master/control plane instance profile(s):")
        master_profile_summary = [{
            "InstanceProfileId": profile.get("InstanceProfileId"),
            "InstanceProfileName": profile.get("InstanceProfileName"),
            "Arn": profile.get("Arn"),
            "RoleNames": [role.get("RoleName") for role in profile.get("Roles", [])]
        } for profile in master_profiles]
        print(json.dumps(master_profile_summary, indent=2))
    else:
        print(f"\n✗ No IAM instance profile found for master/control plane nodes")

    assert len(master_profiles) > 0, \
        f"No IAM instance profile found for master/control plane nodes"


@pytest.mark.instances
def test_worker_iam_instance_profile_exists(cluster_data: ClusterData, infra_id: str):
    """Cluster should have IAM instance profile for worker nodes
    Documentation: https://docs.redhat.com/en/documentation/red_hat_openshift_service_on_aws/4/html/prepare_your_environment/rosa-sts-aws-prereqs#rosa-sts-overview-of-the-deployment-workflow
    """
    iam_file = cluster_data.aws_dir / f"{cluster_data.cluster_id}_iam_instance_profiles.json"

    if not iam_file.exists():
        pytest.skip(f"IAM instance profiles file not found: {iam_file}")

    with open(iam_file) as f:
        iam_data = json.load(f)

    profiles = iam_data.get('InstanceProfiles', [])

    # Find worker node profile
    worker_profiles = [
        profile for profile in profiles
        if 'worker' in profile.get('InstanceProfileName', '').lower()
    ]

    if worker_profiles:
        print(f"\n✓ Found {len(worker_profiles)} worker instance profile(s):")
        worker_profile_summary = [{
            "InstanceProfileId": profile.get("InstanceProfileId"),
            "InstanceProfileName": profile.get("InstanceProfileName"),
            "Arn": profile.get("Arn"),
            "RoleNames": [role.get("RoleName") for role in profile.get("Roles", [])]
        } for profile in worker_profiles]
        print(json.dumps(worker_profile_summary, indent=2))
    else:
        print(f"\n✗ No IAM instance profile found for worker nodes")

    assert len(worker_profiles) > 0, \
        f"No IAM instance profile found for worker nodes"


@pytest.mark.instances
def test_iam_profiles_have_roles(cluster_data: ClusterData, infra_id: str):
    """IAM instance profiles should have roles attached
    Documentation: https://docs.redhat.com/en/documentation/red_hat_openshift_service_on_aws/4/html/prepare_your_environment/rosa-sts-aws-prereqs#rosa-sts-overview-of-the-deployment-workflow
    """
    iam_file = cluster_data.aws_dir / f"{cluster_data.cluster_id}_iam_instance_profiles.json"

    if not iam_file.exists():
        pytest.skip(f"IAM instance profiles file not found: {iam_file}")

    with open(iam_file) as f:
        iam_data = json.load(f)

    profiles = iam_data.get('InstanceProfiles', [])

    if len(profiles) == 0:
        pytest.skip("No IAM instance profiles found")

    profiles_without_roles = []
    profile_role_summary = []

    for profile in profiles:
        profile_name = profile.get('InstanceProfileName', 'unknown')
        profile_id = profile.get('InstanceProfileId', 'unknown')
        roles = profile.get('Roles', [])

        profile_role_summary.append({
            "InstanceProfileId": profile_id,
            "InstanceProfileName": profile_name,
            "RoleCount": len(roles),
            "Roles": [{
                "RoleName": role.get("RoleName"),
                "RoleId": role.get("RoleId"),
                "Arn": role.get("Arn")
            } for role in roles]
        })

        if len(roles) == 0:
            profiles_without_roles.append(profile_name)

    if len(profiles_without_roles) == 0:
        print(f"\n✓ All {len(profiles)} instance profiles have roles attached:")
        print(json.dumps(profile_role_summary, indent=2))
    else:
        print(f"\n✗ Instance profiles without roles:")
        print(json.dumps([p for p in profile_role_summary if p["RoleCount"] == 0], indent=2))

    assert len(profiles_without_roles) == 0, \
        f"IAM instance profiles without roles: {', '.join(profiles_without_roles)}"


@pytest.mark.instances
def test_iam_profiles_have_valid_arns(cluster_data: ClusterData, infra_id: str):
    """IAM instance profiles should have valid ARNs
    Documentation: https://docs.redhat.com/en/documentation/red_hat_openshift_service_on_aws/4/html/prepare_your_environment/rosa-sts-aws-prereqs#rosa-sts-overview-of-the-deployment-workflow
    """
    iam_file = cluster_data.aws_dir / f"{cluster_data.cluster_id}_iam_instance_profiles.json"

    if not iam_file.exists():
        pytest.skip(f"IAM instance profiles file not found: {iam_file}")

    with open(iam_file) as f:
        iam_data = json.load(f)

    profiles = iam_data.get('InstanceProfiles', [])

    if len(profiles) == 0:
        pytest.skip("No IAM instance profiles found")

    invalid_arns = []
    arn_validation_summary = []

    for profile in profiles:
        profile_name = profile.get('InstanceProfileName', 'unknown')
        profile_id = profile.get('InstanceProfileId', 'unknown')
        arn = profile.get('Arn', '')

        # Validate ARN format
        is_valid = arn and arn.startswith('arn:aws:iam::')

        arn_validation_summary.append({
            "InstanceProfileId": profile_id,
            "InstanceProfileName": profile_name,
            "Arn": arn,
            "IsValid": is_valid
        })

        if not is_valid:
            invalid_arns.append(f"{profile_name} (ARN: {arn})")

    if len(invalid_arns) == 0:
        print(f"\n✓ All {len(profiles)} instance profiles have valid ARNs:")
        print(json.dumps(arn_validation_summary, indent=2))
    else:
        print(f"\n✗ Instance profiles with invalid ARNs:")
        print(json.dumps([a for a in arn_validation_summary if not a["IsValid"]], indent=2))

    assert len(invalid_arns) == 0, \
        f"IAM instance profiles with invalid ARNs: {', '.join(invalid_arns)}"
