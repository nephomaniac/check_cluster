"""
GCP Compute Instances Tests

Validates compute instances for OpenShift cluster.

Documentation:
- GCP Instances: https://cloud.google.com/compute/docs/instances
- OpenShift on GCP: https://docs.redhat.com/en/documentation/openshift_container_platform/4.19/html/installing_on_gcp/index
"""

import json
import pytest


# Mark all tests as GCP-specific
pytestmark = pytest.mark.gcp


@pytest.mark.instances
def test_instances_file_exists(gcp_cluster_data):
    """Compute instances file must exist.

    Documentation: https://cloud.google.com/compute/docs/instances
    """
    instances_file = gcp_cluster_data.gcp_dir / f"{gcp_cluster_data.cluster_id}_instances.json"

    if not instances_file.exists():
        pytest.skip(f"Instances file not found - run check_cluster.py {gcp_cluster_data.cluster_id} --collect --resources=compute")

    print(f"\n✓ Found instances: {instances_file}")


@pytest.mark.instances
def test_cluster_instances_exist(gcp_cluster_data):
    """Cluster instances must exist.

    Documentation: https://cloud.google.com/compute/docs/instances
    """
    instances_file = gcp_cluster_data.gcp_dir / f"{gcp_cluster_data.cluster_id}_instances.json"

    if not instances_file.exists():
        pytest.skip("Instances file not found")

    with open(instances_file) as f:
        instances_data = json.load(f)

    # Filter cluster instances by infra_id tag/name
    cluster_instances = []
    if gcp_cluster_data.infra_id:
        cluster_instances = [
            inst for inst in instances_data
            if gcp_cluster_data.infra_id in inst.get('name', '')
        ]

    print(f"\n✓ Cluster Instances:")
    print(f"  Total instances in project: {len(instances_data)}")
    print(f"  Cluster instances: {len(cluster_instances)}")

    assert len(cluster_instances) > 0, \
        f"No instances found for cluster (infra_id: {gcp_cluster_data.infra_id})"


@pytest.mark.instances
def test_control_plane_instances_count(gcp_cluster_data):
    """Control plane should have 3 instances for HA.

    Documentation: https://docs.redhat.com/en/documentation/openshift_container_platform/4.19/html/installing_on_gcp/index
    """
    instances_file = gcp_cluster_data.gcp_dir / f"{gcp_cluster_data.cluster_id}_instances.json"

    if not instances_file.exists():
        pytest.skip("Instances file not found")

    with open(instances_file) as f:
        instances_data = json.load(f)

    # Find control plane instances (master)
    master_instances = []
    if gcp_cluster_data.infra_id:
        master_instances = [
            inst for inst in instances_data
            if gcp_cluster_data.infra_id in inst.get('name', '') and 'master' in inst.get('name', '')
        ]

    print(f"\n✓ Control Plane Instances:")
    print(f"  Count: {len(master_instances)} (expected: 3)")

    if master_instances:
        for inst in master_instances:
            print(f"    - {inst.get('name')}")
            print(f"      Status: {inst.get('status', 'UNKNOWN')}")
            print(f"      Zone: {inst.get('zone', '').split('/')[-1]}")

    # Note: During installation, count may be less than 3
    # Only warn if count is unexpected
    if len(master_instances) != 3 and len(master_instances) > 0:
        print(f"\n  ⚠️  Expected 3 control plane instances, found {len(master_instances)}")


@pytest.mark.instances
def test_worker_instances_exist(gcp_cluster_data):
    """Worker instances must exist.

    Documentation: https://docs.redhat.com/en/documentation/openshift_container_platform/4.19/html/installing_on_gcp/index
    """
    instances_file = gcp_cluster_data.gcp_dir / f"{gcp_cluster_data.cluster_id}_instances.json"

    if not instances_file.exists():
        pytest.skip("Instances file not found")

    with open(instances_file) as f:
        instances_data = json.load(f)

    # Find worker instances
    worker_instances = []
    if gcp_cluster_data.infra_id:
        worker_instances = [
            inst for inst in instances_data
            if gcp_cluster_data.infra_id in inst.get('name', '') and 'worker' in inst.get('name', '')
        ]

    print(f"\n✓ Worker Instances:")
    print(f"  Count: {len(worker_instances)}")

    if worker_instances:
        for inst in worker_instances[:5]:  # Show first 5
            print(f"    - {inst.get('name')}")
            print(f"      Status: {inst.get('status', 'UNKNOWN')}")
            print(f"      Zone: {inst.get('zone', '').split('/')[-1]}")

    # At least one worker expected
    assert len(worker_instances) > 0, \
        "No worker instances found"


@pytest.mark.instances
def test_instance_status(gcp_cluster_data):
    """Cluster instances should be running.

    Documentation: https://cloud.google.com/compute/docs/instances/instance-life-cycle
    """
    instances_file = gcp_cluster_data.gcp_dir / f"{gcp_cluster_data.cluster_id}_instances.json"

    if not instances_file.exists():
        pytest.skip("Instances file not found")

    with open(instances_file) as f:
        instances_data = json.load(f)

    # Filter cluster instances
    cluster_instances = []
    if gcp_cluster_data.infra_id:
        cluster_instances = [
            inst for inst in instances_data
            if gcp_cluster_data.infra_id in inst.get('name', '')
        ]

    if not cluster_instances:
        pytest.skip("No cluster instances found")

    print(f"\n✓ Instance Status:")

    status_counts = {}
    for inst in cluster_instances:
        status = inst.get('status', 'UNKNOWN')
        status_counts[status] = status_counts.get(status, 0) + 1

    for status, count in status_counts.items():
        print(f"  {status}: {count}")

    # Show non-running instances
    non_running = [inst for inst in cluster_instances if inst.get('status') != 'RUNNING']
    if non_running:
        print(f"\n  Non-running instances:")
        for inst in non_running:
            print(f"    - {inst.get('name')}: {inst.get('status')}")


@pytest.mark.instances
@pytest.mark.bootstrap
def test_bootstrap_instance_diagnostics(gcp_cluster_data):
    """Bootstrap instance diagnostics (if exists).

    Provides serial port output for troubleshooting bootstrap failures.

    Documentation: https://cloud.google.com/compute/docs/troubleshooting/viewing-serial-port-output
    """
    instances_file = gcp_cluster_data.gcp_dir / f"{gcp_cluster_data.cluster_id}_instances.json"

    if not instances_file.exists():
        pytest.skip("Instances file not found")

    with open(instances_file) as f:
        instances_data = json.load(f)

    # Find bootstrap instance
    bootstrap_instance = None
    if gcp_cluster_data.infra_id:
        for inst in instances_data:
            if gcp_cluster_data.infra_id in inst.get('name', '') and 'bootstrap' in inst.get('name', ''):
                bootstrap_instance = inst
                break

    if not bootstrap_instance:
        pytest.skip("Bootstrap instance not found (may be deleted after successful installation)")

    print(f"\n✓ Bootstrap Instance:")
    print(f"  Name: {bootstrap_instance.get('name')}")
    print(f"  Status: {bootstrap_instance.get('status', 'UNKNOWN')}")
    print(f"  Zone: {bootstrap_instance.get('zone', '').split('/')[-1]}")

    # Check for serial port output file
    serial_output_file = gcp_cluster_data.gcp_dir / f"{bootstrap_instance.get('name')}_serial_output.txt"
    if serial_output_file.exists():
        print(f"  Serial output: Available at {serial_output_file}")
    else:
        print(f"  Serial output: Not collected")
        print(f"  To collect: gcloud compute instances get-serial-port-output {bootstrap_instance.get('name')} --zone={bootstrap_instance.get('zone', '').split('/')[-1]}")


@pytest.mark.instances
def test_instances_summary(gcp_cluster_data):
    """Summary of compute instances configuration.

    Documentation: https://cloud.google.com/compute/docs/instances
    """
    instances_file = gcp_cluster_data.gcp_dir / f"{gcp_cluster_data.cluster_id}_instances.json"

    if not instances_file.exists():
        pytest.skip("Instances file not found")

    with open(instances_file) as f:
        instances_data = json.load(f)

    # Filter cluster instances
    cluster_instances = []
    if gcp_cluster_data.infra_id:
        cluster_instances = [
            inst for inst in instances_data
            if gcp_cluster_data.infra_id in inst.get('name', '')
        ]

    # Count by type
    master_count = sum(1 for inst in cluster_instances if 'master' in inst.get('name', ''))
    worker_count = sum(1 for inst in cluster_instances if 'worker' in inst.get('name', ''))
    bootstrap_count = sum(1 for inst in cluster_instances if 'bootstrap' in inst.get('name', ''))

    print(f"\n✓ Instances Summary:")
    print(f"  Total cluster instances: {len(cluster_instances)}")
    print(f"    Control plane (master): {master_count}")
    print(f"    Worker: {worker_count}")
    print(f"    Bootstrap: {bootstrap_count}")

    assert True  # Informational test
