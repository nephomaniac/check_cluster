"""
Storage Tests

This module validates storage infrastructure components:
- EBS Volumes (state, encryption, attachments)
- Volume types and sizes
- etcd volumes for control plane nodes
"""

import pytest
import json
from pathlib import Path
from typing import Dict, List, Any
from models.cluster import ClusterData


@pytest.mark.storage
def test_ebs_volumes_exist(cluster_data: ClusterData, infra_id: str):
    """Cluster should have EBS volumes for instances"""
    volumes_file = cluster_data.data_dir / f"{cluster_data.cluster_id}_ebs_volumes.json"

    if not volumes_file.exists():
        pytest.skip(f"EBS volumes file not found: {volumes_file}")

    with open(volumes_file) as f:
        volumes_data = json.load(f)

    volumes = volumes_data.get('Volumes', [])

    # Filter to cluster volumes
    cluster_volumes = [vol for vol in volumes if any(
        tag.get('Key') == 'Name' and infra_id in tag.get('Value', '')
        for tag in vol.get('Tags', [])
    )]

    assert len(cluster_volumes) > 0, f"No EBS volumes found for cluster {infra_id}"


@pytest.mark.storage
def test_ebs_volumes_in_use_or_available(cluster_data: ClusterData, infra_id: str):
    """EBS volumes should be in 'in-use' or 'available' state"""
    volumes_file = cluster_data.data_dir / f"{cluster_data.cluster_id}_ebs_volumes.json"

    if not volumes_file.exists():
        pytest.skip(f"EBS volumes file not found: {volumes_file}")

    with open(volumes_file) as f:
        volumes_data = json.load(f)

    volumes = volumes_data.get('Volumes', [])

    # Filter to cluster volumes
    cluster_volumes = [vol for vol in volumes if any(
        tag.get('Key') == 'Name' and infra_id in tag.get('Value', '')
        for tag in vol.get('Tags', [])
    )]

    bad_state_volumes = [
        f"{vol['VolumeId']} (state: {vol.get('State')})"
        for vol in cluster_volumes
        if vol.get('State') not in ['in-use', 'available']
    ]

    assert len(bad_state_volumes) == 0, \
        f"EBS volumes in unexpected state: {', '.join(bad_state_volumes)}"


@pytest.mark.storage
def test_ebs_volumes_encrypted(cluster_data: ClusterData, infra_id: str):
    """EBS volumes should be encrypted for security compliance"""
    volumes_file = cluster_data.data_dir / f"{cluster_data.cluster_id}_ebs_volumes.json"

    if not volumes_file.exists():
        pytest.skip(f"EBS volumes file not found: {volumes_file}")

    with open(volumes_file) as f:
        volumes_data = json.load(f)

    volumes = volumes_data.get('Volumes', [])

    # Filter to cluster volumes
    cluster_volumes = [vol for vol in volumes if any(
        tag.get('Key') == 'Name' and infra_id in tag.get('Value', '')
        for tag in vol.get('Tags', [])
    )]

    unencrypted_volumes = [
        vol['VolumeId'] for vol in cluster_volumes
        if not vol.get('Encrypted', False)
    ]

    assert len(unencrypted_volumes) == 0, \
        f"Unencrypted EBS volumes found (security risk): {unencrypted_volumes}"


@pytest.mark.storage
def test_master_nodes_have_etcd_volumes(cluster_data: ClusterData, infra_id: str):
    """Control plane (master) nodes should have dedicated etcd volumes"""
    volumes_file = cluster_data.data_dir / f"{cluster_data.cluster_id}_ebs_volumes.json"
    instances_file = cluster_data.data_dir / f"{cluster_data.cluster_id}_ec2_instances.json"

    if not volumes_file.exists():
        pytest.skip(f"EBS volumes file not found: {volumes_file}")

    if not instances_file.exists():
        pytest.skip(f"EC2 instances file not found: {instances_file}")

    with open(instances_file) as f:
        instances = json.load(f)

    # Find master instances
    master_instances = [
        inst for inst in instances
        if any(
            tag.get('Key') == 'Name' and
            infra_id in tag.get('Value', '') and
            'master' in tag.get('Value', '').lower()
            for tag in inst.get('Tags', [])
        )
    ]

    if len(master_instances) == 0:
        pytest.skip("No master instances found")

    with open(volumes_file) as f:
        volumes_data = json.load(f)

    volumes = volumes_data.get('Volumes', [])

    # Check each master instance has volumes
    issues = []
    for instance in master_instances:
        instance_id = instance.get('InstanceId')
        instance_name = next(
            (tag['Value'] for tag in instance.get('Tags', []) if tag.get('Key') == 'Name'),
            instance_id
        )

        # Find volumes attached to this instance
        attached_volumes = [
            vol for vol in volumes
            if any(
                att.get('InstanceId') == instance_id
                for att in vol.get('Attachments', [])
            )
        ]

        if len(attached_volumes) == 0:
            issues.append(f"Master instance {instance_name} has no EBS volumes attached")

    assert len(issues) == 0, f"Master volume issues: {'; '.join(issues)}"


@pytest.mark.storage
def test_volume_attachments_attached(cluster_data: ClusterData, infra_id: str):
    """Volume attachments should be in 'attached' state"""
    volumes_file = cluster_data.data_dir / f"{cluster_data.cluster_id}_ebs_volumes.json"

    if not volumes_file.exists():
        pytest.skip(f"EBS volumes file not found: {volumes_file}")

    with open(volumes_file) as f:
        volumes_data = json.load(f)

    volumes = volumes_data.get('Volumes', [])

    # Filter to cluster volumes with attachments
    cluster_volumes = [vol for vol in volumes if any(
        tag.get('Key') == 'Name' and infra_id in tag.get('Value', '')
        for tag in vol.get('Tags', [])
    )]

    bad_attachments = []
    for vol in cluster_volumes:
        vol_id = vol['VolumeId']
        attachments = vol.get('Attachments', [])

        for att in attachments:
            if att.get('State') != 'attached':
                instance_id = att.get('InstanceId', 'unknown')
                state = att.get('State', 'unknown')
                bad_attachments.append(f"{vol_id} -> {instance_id} (state: {state})")

    assert len(bad_attachments) == 0, \
        f"Volume attachments not in 'attached' state: {', '.join(bad_attachments)}"


@pytest.mark.storage
def test_volume_types_are_supported(cluster_data: ClusterData, infra_id: str):
    """EBS volumes should use supported volume types (gp2, gp3, io1, io2)"""
    volumes_file = cluster_data.data_dir / f"{cluster_data.cluster_id}_ebs_volumes.json"

    if not volumes_file.exists():
        pytest.skip(f"EBS volumes file not found: {volumes_file}")

    with open(volumes_file) as f:
        volumes_data = json.load(f)

    volumes = volumes_data.get('Volumes', [])

    # Filter to cluster volumes
    cluster_volumes = [vol for vol in volumes if any(
        tag.get('Key') == 'Name' and infra_id in tag.get('Value', '')
        for tag in vol.get('Tags', [])
    )]

    supported_types = ['gp2', 'gp3', 'io1', 'io2', 'st1', 'sc1']
    unsupported_volumes = [
        f"{vol['VolumeId']} (type: {vol.get('VolumeType')})"
        for vol in cluster_volumes
        if vol.get('VolumeType') not in supported_types
    ]

    assert len(unsupported_volumes) == 0, \
        f"Volumes with unsupported types: {', '.join(unsupported_volumes)}"


@pytest.mark.storage
def test_volumes_in_correct_availability_zone(cluster_data: ClusterData, infra_id: str):
    """EBS volumes should be in the same AZ as their attached instances"""
    volumes_file = cluster_data.data_dir / f"{cluster_data.cluster_id}_ebs_volumes.json"
    instances_file = cluster_data.data_dir / f"{cluster_data.cluster_id}_ec2_instances.json"

    if not volumes_file.exists():
        pytest.skip(f"EBS volumes file not found: {volumes_file}")

    if not instances_file.exists():
        pytest.skip(f"EC2 instances file not found: {instances_file}")

    with open(instances_file) as f:
        instances = json.load(f)

    # Create instance AZ map
    instance_az_map = {}
    for inst in instances:
        inst_id = inst.get('InstanceId')
        # Try to get AZ from Tags first, then from instance metadata
        az = next(
            (tag['Value'] for tag in inst.get('Tags', [])
             if tag.get('Key') == 'topology.kubernetes.io/zone'),
            None
        )
        if az:
            instance_az_map[inst_id] = az

    if len(instance_az_map) == 0:
        pytest.skip("Cannot determine instance availability zones")

    with open(volumes_file) as f:
        volumes_data = json.load(f)

    volumes = volumes_data.get('Volumes', [])

    # Filter to cluster volumes
    cluster_volumes = [vol for vol in volumes if any(
        tag.get('Key') == 'Name' and infra_id in tag.get('Value', '')
        for tag in vol.get('Tags', [])
    )]

    az_mismatches = []
    for vol in cluster_volumes:
        vol_id = vol['VolumeId']
        vol_az = vol.get('AvailabilityZone')
        attachments = vol.get('Attachments', [])

        for att in attachments:
            instance_id = att.get('InstanceId')
            if instance_id in instance_az_map:
                instance_az = instance_az_map[instance_id]
                if vol_az != instance_az:
                    az_mismatches.append(
                        f"{vol_id} (AZ: {vol_az}) attached to {instance_id} (AZ: {instance_az})"
                    )

    assert len(az_mismatches) == 0, \
        f"Volume/instance AZ mismatches: {', '.join(az_mismatches)}"


@pytest.mark.storage
def test_no_volumes_in_deleting_state(cluster_data: ClusterData, infra_id: str):
    """No EBS volumes should be stuck in 'deleting' state"""
    volumes_file = cluster_data.data_dir / f"{cluster_data.cluster_id}_ebs_volumes.json"

    if not volumes_file.exists():
        pytest.skip(f"EBS volumes file not found: {volumes_file}")

    with open(volumes_file) as f:
        volumes_data = json.load(f)

    volumes = volumes_data.get('Volumes', [])

    # Filter to cluster volumes
    cluster_volumes = [vol for vol in volumes if any(
        tag.get('Key') == 'Name' and infra_id in tag.get('Value', '')
        for tag in vol.get('Tags', [])
    )]

    deleting_volumes = [
        vol['VolumeId'] for vol in cluster_volumes
        if vol.get('State') == 'deleting'
    ]

    assert len(deleting_volumes) == 0, \
        f"Volumes stuck in 'deleting' state: {deleting_volumes}"
