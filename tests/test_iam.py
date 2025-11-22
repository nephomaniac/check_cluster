"""
IAM Tests

Validates IAM instance profiles and roles for EC2 instances.
"""

import pytest
import json
from pathlib import Path
from models.cluster import ClusterData


@pytest.mark.instances
def test_iam_instance_profiles_exist(cluster_data: ClusterData, infra_id: str):
    """Cluster should have IAM instance profiles for EC2 instances"""
    iam_file = cluster_data.data_dir / f"{cluster_data.cluster_id}_iam_instance_profiles.json"

    if not iam_file.exists():
        pytest.skip(f"IAM instance profiles file not found: {iam_file}")

    with open(iam_file) as f:
        iam_data = json.load(f)

    profiles = iam_data.get('InstanceProfiles', [])

    # IAM profiles are expected for ROSA clusters
    assert len(profiles) > 0, f"No IAM instance profiles found for cluster {infra_id}"


@pytest.mark.instances
def test_master_iam_instance_profile_exists(cluster_data: ClusterData, infra_id: str):
    """Cluster should have IAM instance profile for master/control plane nodes"""
    iam_file = cluster_data.data_dir / f"{cluster_data.cluster_id}_iam_instance_profiles.json"

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

    assert len(master_profiles) > 0, \
        f"No IAM instance profile found for master/control plane nodes"


@pytest.mark.instances
def test_worker_iam_instance_profile_exists(cluster_data: ClusterData, infra_id: str):
    """Cluster should have IAM instance profile for worker nodes"""
    iam_file = cluster_data.data_dir / f"{cluster_data.cluster_id}_iam_instance_profiles.json"

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

    assert len(worker_profiles) > 0, \
        f"No IAM instance profile found for worker nodes"


@pytest.mark.instances
def test_iam_profiles_have_roles(cluster_data: ClusterData, infra_id: str):
    """IAM instance profiles should have roles attached"""
    iam_file = cluster_data.data_dir / f"{cluster_data.cluster_id}_iam_instance_profiles.json"

    if not iam_file.exists():
        pytest.skip(f"IAM instance profiles file not found: {iam_file}")

    with open(iam_file) as f:
        iam_data = json.load(f)

    profiles = iam_data.get('InstanceProfiles', [])

    if len(profiles) == 0:
        pytest.skip("No IAM instance profiles found")

    profiles_without_roles = []
    for profile in profiles:
        profile_name = profile.get('InstanceProfileName', 'unknown')
        roles = profile.get('Roles', [])

        if len(roles) == 0:
            profiles_without_roles.append(profile_name)

    assert len(profiles_without_roles) == 0, \
        f"IAM instance profiles without roles: {', '.join(profiles_without_roles)}"


@pytest.mark.instances
def test_iam_profiles_have_valid_arns(cluster_data: ClusterData, infra_id: str):
    """IAM instance profiles should have valid ARNs"""
    iam_file = cluster_data.data_dir / f"{cluster_data.cluster_id}_iam_instance_profiles.json"

    if not iam_file.exists():
        pytest.skip(f"IAM instance profiles file not found: {iam_file}")

    with open(iam_file) as f:
        iam_data = json.load(f)

    profiles = iam_data.get('InstanceProfiles', [])

    if len(profiles) == 0:
        pytest.skip("No IAM instance profiles found")

    invalid_arns = []
    for profile in profiles:
        profile_name = profile.get('InstanceProfileName', 'unknown')
        arn = profile.get('Arn', '')

        # Validate ARN format
        if not arn or not arn.startswith('arn:aws:iam::'):
            invalid_arns.append(f"{profile_name} (ARN: {arn})")

    assert len(invalid_arns) == 0, \
        f"IAM instance profiles with invalid ARNs: {', '.join(invalid_arns)}"
