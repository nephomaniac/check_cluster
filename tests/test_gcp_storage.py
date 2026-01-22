"""
GCP Storage Configuration Tests

Validates disk types and storage configuration for OpenShift.

Documentation:
- GCP Disks: https://cloud.google.com/compute/docs/disks
- OpenShift on GCP: https://docs.redhat.com/en/documentation/openshift_container_platform/4.19/html/installing_on_gcp/index
"""

import json
import pytest


# Mark all tests as GCP-specific
pytestmark = pytest.mark.gcp


REQUIRED_DISK_TYPES = [
    'pd-ssd',        # SSD Persistent Disk - for etcd and performance
    'pd-standard',   # Standard Persistent Disk - for general use
    'pd-balanced',   # Balanced Persistent Disk - for general use
]


@pytest.mark.storage
def test_disk_types_file_exists(gcp_cluster_data):
    """Disk types file must exist.

    Documentation: https://cloud.google.com/compute/docs/disks
    """
    disk_types_file = gcp_cluster_data.gcp_dir / f"{gcp_cluster_data.cluster_id}_disk_types.json"

    if not disk_types_file.exists():
        pytest.skip(f"Disk types file not found - run check_cluster.py {gcp_cluster_data.cluster_id} --collect --resources=storage")

    print(f"\n✓ Found disk types: {disk_types_file}")


@pytest.mark.storage
def test_ssd_persistent_disk_available(gcp_cluster_data):
    """SSD Persistent Disk (pd-ssd) must be available.

    Required for etcd performance and control plane nodes.

    Documentation: https://cloud.google.com/compute/docs/disks#disk-types
    """
    disk_types_file = gcp_cluster_data.gcp_dir / f"{gcp_cluster_data.cluster_id}_disk_types.json"

    if not disk_types_file.exists():
        pytest.skip("Disk types file not found")

    with open(disk_types_file) as f:
        disk_types_data = json.load(f)

    # Find pd-ssd
    pd_ssd = None
    for disk_type in disk_types_data:
        if disk_type.get('name', '').endswith('pd-ssd'):
            pd_ssd = disk_type
            break

    print(f"\n✓ SSD Persistent Disk (pd-ssd):")
    if pd_ssd:
        print(f"  Available: Yes")
        print(f"  Name: {pd_ssd.get('name')}")
        print(f"  Zone: {pd_ssd.get('zone', '').split('/')[-1]}")
    else:
        print(f"  Available: No")

    assert pd_ssd is not None, \
        "SSD Persistent Disk (pd-ssd) is not available in the region"


@pytest.mark.storage
def test_standard_persistent_disk_available(gcp_cluster_data):
    """Standard Persistent Disk (pd-standard) must be available.

    Used for general-purpose storage.

    Documentation: https://cloud.google.com/compute/docs/disks#disk-types
    """
    disk_types_file = gcp_cluster_data.gcp_dir / f"{gcp_cluster_data.cluster_id}_disk_types.json"

    if not disk_types_file.exists():
        pytest.skip("Disk types file not found")

    with open(disk_types_file) as f:
        disk_types_data = json.load(f)

    # Find pd-standard
    pd_standard = None
    for disk_type in disk_types_data:
        if disk_type.get('name', '').endswith('pd-standard'):
            pd_standard = disk_type
            break

    print(f"\n✓ Standard Persistent Disk (pd-standard):")
    if pd_standard:
        print(f"  Available: Yes")
        print(f"  Name: {pd_standard.get('name')}")
    else:
        print(f"  Available: No")

    assert pd_standard is not None, \
        "Standard Persistent Disk (pd-standard) is not available in the region"


@pytest.mark.storage
def test_balanced_persistent_disk_available(gcp_cluster_data):
    """Balanced Persistent Disk (pd-balanced) must be available.

    Used for balanced performance and cost.

    Documentation: https://cloud.google.com/compute/docs/disks#disk-types
    """
    disk_types_file = gcp_cluster_data.gcp_dir / f"{gcp_cluster_data.cluster_id}_disk_types.json"

    if not disk_types_file.exists():
        pytest.skip("Disk types file not found")

    with open(disk_types_file) as f:
        disk_types_data = json.load(f)

    # Find pd-balanced
    pd_balanced = None
    for disk_type in disk_types_data:
        if disk_type.get('name', '').endswith('pd-balanced'):
            pd_balanced = disk_type
            break

    print(f"\n✓ Balanced Persistent Disk (pd-balanced):")
    if pd_balanced:
        print(f"  Available: Yes")
        print(f"  Name: {pd_balanced.get('name')}")
    else:
        print(f"  Available: No")

    assert pd_balanced is not None, \
        "Balanced Persistent Disk (pd-balanced) is not available in the region"


@pytest.mark.storage
def test_all_disk_types_available(gcp_cluster_data):
    """All required disk types must be available.

    Documentation: https://cloud.google.com/compute/docs/disks#disk-types
    """
    disk_types_file = gcp_cluster_data.gcp_dir / f"{gcp_cluster_data.cluster_id}_disk_types.json"

    if not disk_types_file.exists():
        pytest.skip("Disk types file not found")

    with open(disk_types_file) as f:
        disk_types_data = json.load(f)

    # Get all disk type names
    available_types = set()
    for disk_type in disk_types_data:
        name = disk_type.get('name', '')
        # Extract the type (e.g., pd-ssd from zones/us-west1-a/diskTypes/pd-ssd)
        if '/' in name:
            type_name = name.split('/')[-1]
            available_types.add(type_name)

    print(f"\n✓ Disk Types Availability:")

    missing_types = []
    for required_type in REQUIRED_DISK_TYPES:
        if required_type in available_types:
            print(f"  ✓ {required_type}: Available")
        else:
            print(f"  ✗ {required_type}: Not available")
            missing_types.append(required_type)

    if missing_types:
        print(f"\n  Missing {len(missing_types)} required disk type(s)")

    assert len(missing_types) == 0, \
        f"Missing required disk types: {', '.join(missing_types)}"


@pytest.mark.storage
def test_storage_summary(gcp_cluster_data):
    """Summary of storage configuration.

    Documentation: https://cloud.google.com/compute/docs/disks
    """
    disk_types_file = gcp_cluster_data.gcp_dir / f"{gcp_cluster_data.cluster_id}_disk_types.json"

    if not disk_types_file.exists():
        pytest.skip("Disk types file not found")

    with open(disk_types_file) as f:
        disk_types_data = json.load(f)

    # Get unique disk types
    disk_types_set = set()
    for disk_type in disk_types_data:
        name = disk_type.get('name', '')
        if '/' in name:
            type_name = name.split('/')[-1]
            disk_types_set.add(type_name)

    print(f"\n✓ Storage Configuration Summary:")
    print(f"  Region: {gcp_cluster_data.region}")
    print(f"  Total disk types collected: {len(disk_types_data)}")
    print(f"  Unique disk types: {len(disk_types_set)}")

    print(f"\n  Available disk types:")
    for dt in sorted(disk_types_set):
        print(f"    - {dt}")

    print(f"\n  Required for OpenShift:")
    for required in REQUIRED_DISK_TYPES:
        status = "✓" if required in disk_types_set else "✗"
        print(f"    {status} {required}")

    assert True  # Informational test
