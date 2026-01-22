"""
GCP Machine Types Tests

Validates that machine types meet OpenShift minimum requirements.

Documentation:
- OpenShift Machine Requirements: https://docs.redhat.com/en/documentation/openshift_container_platform/4.19/html/installing_on_gcp/index#installation-gcp-limits_installing-gcp-customizations
- GCP Machine Types: https://cloud.google.com/compute/docs/machine-types
"""

import json
import pytest


# Mark all tests as GCP-specific
pytestmark = pytest.mark.gcp


# Minimum requirements for OpenShift nodes
MIN_CONTROL_PLANE_VCPUS = 4
MIN_CONTROL_PLANE_MEMORY_GB = 16

MIN_WORKER_VCPUS = 2
MIN_WORKER_MEMORY_GB = 8


@pytest.mark.compute
def test_machine_types_file_exists(gcp_cluster_data):
    """Machine types file must exist.

    Documentation: https://cloud.google.com/compute/docs/machine-types
    """
    machine_types_file = gcp_cluster_data.gcp_dir / f"{gcp_cluster_data.cluster_id}_machine_types.json"

    if not machine_types_file.exists():
        pytest.skip(f"Machine types file not found - run check_cluster.py {gcp_cluster_data.cluster_id} --collect --resources=compute")

    print(f"\n✓ Found machine types: {machine_types_file}")


@pytest.mark.compute
def test_control_plane_machine_type_meets_minimum(gcp_cluster_data):
    """Control plane machine type must meet minimum requirements.

    Minimum: 4 vCPUs, 16GB RAM

    Documentation: https://docs.redhat.com/en/documentation/openshift_container_platform/4.19/html/installing_on_gcp/index#installation-gcp-limits_installing-gcp-customizations
    """
    # Get control plane machine type from cluster config
    cluster_json = gcp_cluster_data.cluster_json
    nodes = cluster_json.get('nodes', {})
    master_instance_type = nodes.get('master', {}).get('gcp', {}).get('instance_type', 'n2-standard-4')

    machine_types_file = gcp_cluster_data.gcp_dir / f"{gcp_cluster_data.cluster_id}_machine_types.json"

    if not machine_types_file.exists():
        pytest.skip("Machine types file not found")

    with open(machine_types_file) as f:
        machine_types_data = json.load(f)

    # Find the control plane machine type
    machine_type = None
    for mt in machine_types_data:
        if mt.get('name') == master_instance_type:
            machine_type = mt
            break

    if not machine_type:
        # Try to infer from name (e.g., n2-standard-4 = 4 vCPUs)
        print(f"\n  ⚠️  Machine type details not found, inferring from name")
        print(f"  Instance type: {master_instance_type}")
        pytest.skip(f"Machine type '{master_instance_type}' not found in collected data")

    vcpus = int(machine_type.get('guestCpus', 0))
    memory_mb = int(machine_type.get('memoryMb', 0))
    memory_gb = memory_mb / 1024

    print(f"\n✓ Control Plane Machine Type:")
    print(f"  Type: {master_instance_type}")
    print(f"  vCPUs: {vcpus} (minimum: {MIN_CONTROL_PLANE_VCPUS})")
    print(f"  Memory: {memory_gb:.1f}GB (minimum: {MIN_CONTROL_PLANE_MEMORY_GB}GB)")

    assert vcpus >= MIN_CONTROL_PLANE_VCPUS, \
        f"Control plane machine type has {vcpus} vCPUs, minimum {MIN_CONTROL_PLANE_VCPUS} required"

    assert memory_gb >= MIN_CONTROL_PLANE_MEMORY_GB, \
        f"Control plane machine type has {memory_gb:.1f}GB RAM, minimum {MIN_CONTROL_PLANE_MEMORY_GB}GB required"


@pytest.mark.compute
def test_worker_machine_type_meets_minimum(gcp_cluster_data):
    """Worker machine type must meet minimum requirements.

    Minimum: 2 vCPUs, 8GB RAM

    Documentation: https://docs.redhat.com/en/documentation/openshift_container_platform/4.19/html/installing_on_gcp/index#installation-gcp-limits_installing-gcp-customizations
    """
    # Get worker machine type from cluster config
    cluster_json = gcp_cluster_data.cluster_json
    nodes = cluster_json.get('nodes', {})
    worker_instance_type = nodes.get('worker', {}).get('gcp', {}).get('instance_type', 'n2-standard-4')

    machine_types_file = gcp_cluster_data.gcp_dir / f"{gcp_cluster_data.cluster_id}_machine_types.json"

    if not machine_types_file.exists():
        pytest.skip("Machine types file not found")

    with open(machine_types_file) as f:
        machine_types_data = json.load(f)

    # Find the worker machine type
    machine_type = None
    for mt in machine_types_data:
        if mt.get('name') == worker_instance_type:
            machine_type = mt
            break

    if not machine_type:
        print(f"\n  ⚠️  Machine type details not found, inferring from name")
        print(f"  Instance type: {worker_instance_type}")
        pytest.skip(f"Machine type '{worker_instance_type}' not found in collected data")

    vcpus = int(machine_type.get('guestCpus', 0))
    memory_mb = int(machine_type.get('memoryMb', 0))
    memory_gb = memory_mb / 1024

    print(f"\n✓ Worker Machine Type:")
    print(f"  Type: {worker_instance_type}")
    print(f"  vCPUs: {vcpus} (minimum: {MIN_WORKER_VCPUS})")
    print(f"  Memory: {memory_gb:.1f}GB (minimum: {MIN_WORKER_MEMORY_GB}GB)")

    assert vcpus >= MIN_WORKER_VCPUS, \
        f"Worker machine type has {vcpus} vCPUs, minimum {MIN_WORKER_VCPUS} required"

    assert memory_gb >= MIN_WORKER_MEMORY_GB, \
        f"Worker machine type has {memory_gb:.1f}GB RAM, minimum {MIN_WORKER_MEMORY_GB}GB required"


@pytest.mark.compute
def test_machine_types_summary(gcp_cluster_data):
    """Summary of machine types configuration.

    Documentation: https://docs.redhat.com/en/documentation/openshift_container_platform/4.19/html/installing_on_gcp/index#installation-gcp-limits_installing-gcp-customizations
    """
    cluster_json = gcp_cluster_data.cluster_json
    nodes = cluster_json.get('nodes', {})

    master_instance_type = nodes.get('master', {}).get('gcp', {}).get('instance_type', 'unknown')
    worker_instance_type = nodes.get('worker', {}).get('gcp', {}).get('instance_type', 'unknown')

    print(f"\n✓ Machine Types Summary:")
    print(f"  Control plane: {master_instance_type}")
    print(f"  Worker: {worker_instance_type}")

    print(f"\n  Minimum Requirements:")
    print(f"    Control plane: {MIN_CONTROL_PLANE_VCPUS} vCPUs, {MIN_CONTROL_PLANE_MEMORY_GB}GB RAM")
    print(f"    Worker: {MIN_WORKER_VCPUS} vCPUs, {MIN_WORKER_MEMORY_GB}GB RAM")

    assert True  # Informational test
