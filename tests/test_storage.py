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
    """Cluster should have EBS volumes for instances

    Why: EBS volumes provide persistent storage for cluster nodes and etcd data.

    Failure indicates: No EBS volume data was collected or volumes don't exist in AWS.

    Success indicates: EBS volume data exists and was successfully collected.
    """
    volumes_file = cluster_data.aws_dir / f"{cluster_data.cluster_id}_ebs_volumes.json"

    if not volumes_file.exists():
        # Import diagnostic helper
        from utils.aws_resource_diagnostics import diagnose_missing_aws_resource

        # Get comprehensive diagnostics
        diagnostics = diagnose_missing_aws_resource(
            cluster_data=cluster_data,
            resource_type="EBS Volumes",
            expected_file=f"{cluster_data.cluster_id}_ebs_volumes.json",
            api_service="ec2",
            api_operation="describe_volumes",
            resource_identifier=infra_id
        )

        pytest.fail(f"No EBS volumes data found.\n\n{diagnostics}")

    with open(volumes_file) as f:
        volumes_data = json.load(f)

    volumes = volumes_data.get('Volumes', [])

    # Filter to cluster volumes
    cluster_volumes = [vol for vol in volumes if any(
        tag.get('Key') == 'Name' and infra_id in tag.get('Value', '')
        for tag in vol.get('Tags', [])
    )]

    if cluster_volumes:
        print(f"\n✓ Found {len(cluster_volumes)} EBS volumes:")
        volume_summary = [{
            "VolumeId": vol.get("VolumeId"),
            "Size": vol.get("Size"),
            "VolumeType": vol.get("VolumeType"),
            "State": vol.get("State"),
            "Encrypted": vol.get("Encrypted", False)
        } for vol in cluster_volumes]
        print("\n" + "─"*80)
        print("EC2 DESCRIBE-VOLUMES OUTPUT - EBS Volumes for Cluster")
        print(f"Shows {len(cluster_volumes)} volume(s) with size, type, state, and encryption status")
        print("Relevance: EBS volumes provide persistent storage for cluster nodes and data")
        print("─"*80)
        print(json.dumps(volume_summary, indent=2))
        print("─"*80)
    else:
        # Import diagnostic helper
        from utils.aws_resource_diagnostics import diagnose_missing_aws_resource

        # File exists but contains no cluster volumes
        diagnostics = diagnose_missing_aws_resource(
            cluster_data=cluster_data,
            resource_type="EBS Volumes",
            expected_file=f"{cluster_data.cluster_id}_ebs_volumes.json",
            api_service="ec2",
            api_operation="describe_volumes",
            resource_identifier=infra_id
        )

        print(f"\n✗ No EBS volumes found for cluster {infra_id}")
        pytest.fail(f"No EBS volumes found for cluster {infra_id}.\n\n{diagnostics}")

    assert len(cluster_volumes) > 0, f"No EBS volumes found for cluster {infra_id}"


@pytest.mark.storage
def test_ebs_volumes_in_use_or_available(cluster_data: ClusterData, infra_id: str):
    """EBS volumes should be in 'in-use' or 'available' state"""
    volumes_file = cluster_data.aws_dir / f"{cluster_data.cluster_id}_ebs_volumes.json"

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

    if len(bad_state_volumes) == 0:
        print(f"\n✓ All {len(cluster_volumes)} volumes in valid state:")
        volume_states = [{
            "VolumeId": vol.get("VolumeId"),
            "State": vol.get("State")
        } for vol in cluster_volumes]
        print("\n" + "─"*80)
        print("EC2 DESCRIBE-VOLUMES OUTPUT - Volume State Verification")
        print(f"Showing all {len(cluster_volumes)} volumes are in 'in-use' or 'available' state")
        print("Relevance: Ensures volumes are properly attached or ready for use")
        print("─"*80)
        print(json.dumps(volume_states, indent=2))
        print("─"*80)
    else:
        print(f"\n✗ Volumes in unexpected state:")
        print("\n" + "─"*80)
        print("EC2 DESCRIBE-VOLUMES OUTPUT - Volumes in Unexpected State")
        print(f"Shows {len(bad_state_volumes)} volume(s) not in 'in-use' or 'available' state")
        print("Relevance: Volumes in bad states may indicate detachment issues or failures")
        print("─"*80)
        print(json.dumps(bad_state_volumes, indent=2))
        print("─"*80)

    assert len(bad_state_volumes) == 0, \
        f"EBS volumes in unexpected state: {', '.join(bad_state_volumes)}"


@pytest.mark.storage
def test_ebs_volumes_encrypted(cluster_data: ClusterData, infra_id: str):
    """EBS volumes should be encrypted for security compliance"""
    volumes_file = cluster_data.aws_dir / f"{cluster_data.cluster_id}_ebs_volumes.json"

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

    encrypted_count = len(cluster_volumes) - len(unencrypted_volumes)

    if len(unencrypted_volumes) == 0:
        print(f"\n✓ All {len(cluster_volumes)} volumes encrypted:")
        encryption_summary = [{
            "VolumeId": vol.get("VolumeId"),
            "Encrypted": vol.get("Encrypted", False),
            "KmsKeyId": vol.get("KmsKeyId", "default")
        } for vol in cluster_volumes]
        print("\n" + "─"*80)
        print("EC2 DESCRIBE-VOLUMES OUTPUT - Volume Encryption Status")
        print(f"Showing all {len(cluster_volumes)} volumes are encrypted")
        print("Relevance: Encryption is required for security compliance and data protection")
        print("─"*80)
        print(json.dumps(encryption_summary, indent=2))
        print("─"*80)
    else:
        print(f"\n✗ Found {len(unencrypted_volumes)} unencrypted volumes:")
        print("\n" + "─"*80)
        print("EC2 DESCRIBE-VOLUMES OUTPUT - Unencrypted Volumes Found")
        print(f"Shows {len(unencrypted_volumes)} unencrypted volume(s) - SECURITY RISK")
        print("Relevance: Unencrypted volumes violate security compliance requirements")
        print("─"*80)
        print(json.dumps({
            "TotalVolumes": len(cluster_volumes),
            "EncryptedCount": encrypted_count,
            "UnencryptedCount": len(unencrypted_volumes),
            "UnencryptedVolumeIds": unencrypted_volumes
        }, indent=2))
        print("─"*80)

    assert len(unencrypted_volumes) == 0, \
        f"Unencrypted EBS volumes found (security risk): {unencrypted_volumes}"


@pytest.mark.storage
def test_master_nodes_have_etcd_volumes(cluster_data: ClusterData, infra_id: str):
    """Control plane (master) nodes should have dedicated etcd volumes"""
    volumes_file = cluster_data.aws_dir / f"{cluster_data.cluster_id}_ebs_volumes.json"
    instances_file = cluster_data.aws_dir / f"{cluster_data.cluster_id}_ec2_instances.json"

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

    # Get all cluster volumes for context
    cluster_volumes = [vol for vol in volumes if any(
        tag.get('Key') == 'Name' and infra_id in tag.get('Value', '')
        for tag in vol.get('Tags', [])
    )]

    # Check each master instance has volumes
    issues = []
    master_volume_summary = []

    for instance in master_instances:
        instance_id = instance.get('InstanceId')
        instance_name = next(
            (tag['Value'] for tag in instance.get('Tags', []) if tag.get('Key') == 'Name'),
            instance_id
        )
        instance_state = instance.get('State', 'unknown')

        # Find volumes attached to this instance
        attached_volumes = [
            vol for vol in volumes
            if any(
                att.get('InstanceId') == instance_id
                for att in vol.get('Attachments', [])
            )
        ]

        volume_details = [{
            "VolumeId": vol.get('VolumeId'),
            "Size": vol.get('Size'),
            "State": vol.get('State'),
            "Device": next((att.get('Device') for att in vol.get('Attachments', [])
                           if att.get('InstanceId') == instance_id), None)
        } for vol in attached_volumes]

        master_volume_summary.append({
            "InstanceName": instance_name,
            "InstanceId": instance_id,
            "InstanceState": instance_state,
            "VolumeCount": len(attached_volumes),
            "Volumes": volume_details
        })

        if len(attached_volumes) == 0:
            issues.append(f"Master instance {instance_name} ({instance_id}) has no EBS volumes attached")

    if len(issues) == 0:
        print(f"\n✓ All {len(master_instances)} master instances have volumes:")
        print(json.dumps(master_volume_summary, indent=2))
    else:
        print(f"\n✗ FAILURE: {len(issues)} master instance(s) without volumes:")
        print(json.dumps(master_volume_summary, indent=2))
        print(f"\nCluster context:")
        print(f"  Total master instances found: {len(master_instances)}")
        print(f"  Total cluster volumes: {len(cluster_volumes)}")
        print(f"  Masters without volumes: {len(issues)}")

        # Show which volumes exist but aren't attached to masters
        attached_volume_ids = set()
        for summary in master_volume_summary:
            for vol in summary.get('Volumes', []):
                attached_volume_ids.add(vol['VolumeId'])

        unattached_cluster_volumes = [
            {
                "VolumeId": vol.get('VolumeId'),
                "Size": vol.get('Size'),
                "State": vol.get('State'),
                "AvailabilityZone": vol.get('AvailabilityZone'),
                "Attachments": vol.get('Attachments', [])
            }
            for vol in cluster_volumes
            if vol.get('VolumeId') not in attached_volume_ids
        ]

        if unattached_cluster_volumes:
            print(f"\n  Cluster volumes not attached to any master ({len(unattached_cluster_volumes)}):")
            print(json.dumps(unattached_cluster_volumes[:5], indent=2))  # Show first 5
            if len(unattached_cluster_volumes) > 5:
                print(f"  ... and {len(unattached_cluster_volumes) - 5} more")

        print(f"\nPossible causes:")
        print(f"  - Master instances are in terminated/stopped state")
        print(f"  - Volumes were detached or deleted")
        print(f"  - Cluster is in degraded state")
        print(f"  - Volumes exist but attachment state is incorrect")

    assert len(issues) == 0, f"Master volume issues: {'; '.join(issues)}"


@pytest.mark.storage
def test_volume_attachments_attached(cluster_data: ClusterData, infra_id: str):
    """Volume attachments should be in 'attached' state"""
    volumes_file = cluster_data.aws_dir / f"{cluster_data.cluster_id}_ebs_volumes.json"

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
    all_attachments = []

    for vol in cluster_volumes:
        vol_id = vol['VolumeId']
        attachments = vol.get('Attachments', [])

        for att in attachments:
            state = att.get('State', 'unknown')
            instance_id = att.get('InstanceId', 'unknown')

            all_attachments.append({
                "VolumeId": vol_id,
                "InstanceId": instance_id,
                "Device": att.get('Device'),
                "State": state
            })

            if state != 'attached':
                bad_attachments.append(f"{vol_id} -> {instance_id} (state: {state})")

    if len(bad_attachments) == 0:
        print(f"\n✓ All {len(all_attachments)} volume attachments in attached state:")
        print(json.dumps(all_attachments, indent=2))
    else:
        print(f"\n✗ Volume attachments not in attached state:")
        print(json.dumps([a for a in all_attachments if a["State"] != 'attached'], indent=2))

    assert len(bad_attachments) == 0, \
        f"Volume attachments not in 'attached' state: {', '.join(bad_attachments)}"


@pytest.mark.storage
def test_volume_types_are_supported(cluster_data: ClusterData, infra_id: str):
    """EBS volumes should use supported volume types (gp2, gp3, io1, io2)"""
    volumes_file = cluster_data.aws_dir / f"{cluster_data.cluster_id}_ebs_volumes.json"

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

    volume_types_summary = [{
        "VolumeId": vol.get("VolumeId"),
        "VolumeType": vol.get("VolumeType"),
        "IsSupported": vol.get("VolumeType") in supported_types
    } for vol in cluster_volumes]

    if len(unsupported_volumes) == 0:
        print(f"\n✓ All {len(cluster_volumes)} volumes use supported types:")
        print(json.dumps(volume_types_summary, indent=2))
    else:
        print(f"\n✗ Volumes with unsupported types:")
        print(json.dumps([v for v in volume_types_summary if not v["IsSupported"]], indent=2))

    assert len(unsupported_volumes) == 0, \
        f"Volumes with unsupported types: {', '.join(unsupported_volumes)}"


@pytest.mark.storage
def test_volumes_in_correct_availability_zone(cluster_data: ClusterData, infra_id: str):
    """EBS volumes should be in the same AZ as their attached instances"""
    volumes_file = cluster_data.aws_dir / f"{cluster_data.cluster_id}_ebs_volumes.json"
    instances_file = cluster_data.aws_dir / f"{cluster_data.cluster_id}_ec2_instances.json"

    if not volumes_file.exists():
        pytest.skip(f"EBS volumes file not found: {volumes_file}")

    if not instances_file.exists():
        pytest.skip(f"EC2 instances file not found: {instances_file}")

    with open(instances_file) as f:
        instances = json.load(f)

    # Create instance AZ map from Kubernetes topology tags
    instance_az_map_k8s = {}
    # Also create AZ map from EC2 Placement for fallback
    instance_az_map_ec2 = {}
    instances_without_k8s_tag = []

    for inst in instances:
        inst_id = inst.get('InstanceId')
        inst_name = next(
            (tag['Value'] for tag in inst.get('Tags', []) if tag.get('Key') == 'Name'),
            inst_id
        )

        # Try to get AZ from Kubernetes topology tag
        az_k8s = next(
            (tag['Value'] for tag in inst.get('Tags', [])
             if tag.get('Key') == 'topology.kubernetes.io/zone'),
            None
        )

        # Get AZ from EC2 Placement metadata
        az_ec2 = inst.get('Placement', {}).get('AvailabilityZone')

        if az_k8s:
            instance_az_map_k8s[inst_id] = az_k8s
        else:
            instances_without_k8s_tag.append({
                "InstanceId": inst_id,
                "InstanceName": inst_name,
                "PlacementAZ": az_ec2
            })

        if az_ec2:
            instance_az_map_ec2[inst_id] = az_ec2

    # Use Kubernetes tag if available, fallback to EC2 Placement
    instance_az_map = {**instance_az_map_ec2, **instance_az_map_k8s}

    if len(instance_az_map) == 0:
        pytest.skip("Cannot determine instance availability zones from either Kubernetes tags or EC2 Placement")

    with open(volumes_file) as f:
        volumes_data = json.load(f)

    volumes = volumes_data.get('Volumes', [])

    # Filter to cluster volumes
    cluster_volumes = [vol for vol in volumes if any(
        tag.get('Key') == 'Name' and infra_id in tag.get('Value', '')
        for tag in vol.get('Tags', [])
    )]

    az_mismatches = []
    volume_az_checks = []
    volumes_not_checked = []

    for vol in cluster_volumes:
        vol_id = vol['VolumeId']
        vol_az = vol.get('AvailabilityZone')
        attachments = vol.get('Attachments', [])

        vol_name = next(
            (tag['Value'] for tag in vol.get('Tags', []) if tag.get('Key') == 'Name'),
            vol_id
        )

        if not attachments:
            continue

        for att in attachments:
            instance_id = att.get('InstanceId')

            if instance_id in instance_az_map:
                instance_az = instance_az_map[instance_id]
                az_match = vol_az == instance_az

                # Determine AZ source
                az_source = "kubernetes-tag" if instance_id in instance_az_map_k8s else "ec2-placement"

                volume_az_checks.append({
                    "VolumeId": vol_id,
                    "VolumeName": vol_name,
                    "VolumeAZ": vol_az,
                    "InstanceId": instance_id,
                    "InstanceAZ": instance_az,
                    "AZSource": az_source,
                    "Match": az_match
                })

                if not az_match:
                    az_mismatches.append(
                        f"{vol_id} (AZ: {vol_az}) attached to {instance_id} (AZ: {instance_az})"
                    )
            else:
                volumes_not_checked.append({
                    "VolumeId": vol_id,
                    "VolumeName": vol_name,
                    "VolumeAZ": vol_az,
                    "InstanceId": instance_id,
                    "Reason": "Instance AZ could not be determined"
                })

    if len(az_mismatches) == 0:
        print(f"\n✓ All volumes in correct AZ for attached instances:")
        print(json.dumps(volume_az_checks, indent=2))

        if instances_without_k8s_tag:
            print(f"\nNote: {len(instances_without_k8s_tag)} instance(s) missing 'topology.kubernetes.io/zone' tag, used EC2 Placement instead:")
            print(json.dumps(instances_without_k8s_tag[:3], indent=2))
    else:
        print(f"\n✗ FAILURE: {len(az_mismatches)} volume/instance AZ mismatch(es) found:")
        print(json.dumps([c for c in volume_az_checks if not c["Match"]], indent=2))

        print(f"\nDiagnostic Information:")
        print(f"  Total volumes checked: {len(volume_az_checks)}")
        print(f"  Volumes with AZ mismatches: {len(az_mismatches)}")
        print(f"  Volumes not checked: {len(volumes_not_checked)}")
        print(f"  Instances missing K8s zone tag: {len(instances_without_k8s_tag)}")

        if volumes_not_checked:
            print(f"\n  Volumes that could not be checked:")
            print(json.dumps(volumes_not_checked, indent=2))

        if instances_without_k8s_tag:
            print(f"\n  Instances missing 'topology.kubernetes.io/zone' tag (used EC2 Placement):")
            print(json.dumps(instances_without_k8s_tag[:3], indent=2))
            if len(instances_without_k8s_tag) > 3:
                print(f"  ... and {len(instances_without_k8s_tag) - 3} more")

        print(f"\nPossible causes:")
        print(f"  - Volumes were created in wrong AZ")
        print(f"  - Instances were migrated/replaced across AZs")
        print(f"  - Manual volume attachments outside cluster automation")
        print(f"  - Cluster topology changes (AZ additions/removals)")
        print(f"  - Missing or incorrect Kubernetes topology tags")

    assert len(az_mismatches) == 0, \
        f"Volume/instance AZ mismatches: {', '.join(az_mismatches)}"


@pytest.mark.storage
def test_no_volumes_in_deleting_state(cluster_data: ClusterData, infra_id: str):
    """No EBS volumes should be stuck in 'deleting' state"""
    volumes_file = cluster_data.aws_dir / f"{cluster_data.cluster_id}_ebs_volumes.json"

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

    all_volume_states = [{
        "VolumeId": vol.get("VolumeId"),
        "State": vol.get("State")
    } for vol in cluster_volumes]

    if len(deleting_volumes) == 0:
        print(f"\n✓ No volumes stuck in deleting state (checked {len(cluster_volumes)} volumes):")
        print(json.dumps(all_volume_states, indent=2))
    else:
        print(f"\n✗ Volumes stuck in deleting state:")
        print(json.dumps([v for v in all_volume_states if v["State"] == 'deleting'], indent=2))

    assert len(deleting_volumes) == 0, \
        f"Volumes stuck in 'deleting' state: {deleting_volumes}"
