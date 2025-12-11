"""
EC2 Instance Tests

Validates EC2 instances for ROSA cluster nodes (control plane and workers).
"""

import json
import pytest
from models.cluster import ClusterData


def get_instances_by_role(cluster_data: ClusterData, role: str) -> list:
    """
    Get instances filtered by role (master or worker).

    Args:
        cluster_data: ClusterData object
        role: 'master' or 'worker'

    Returns:
        List of instances matching the role
    """
    instances = []
    infra_id = cluster_data.infra_id

    for instance in cluster_data.ec2_instances:
        tags = {tag['Key']: tag['Value'] for tag in instance.get('Tags', [])}
        instance_name = tags.get('Name', '')

        if role == 'master' and 'master' in instance_name.lower():
            instances.append(instance)
        elif role == 'worker' and 'worker' in instance_name.lower():
            instances.append(instance)

    return instances


@pytest.mark.instances
def test_instances_exist(cluster_data: ClusterData):
    """Cluster must have EC2 instances.

    Why: ROSA clusters require EC2 instances to run both control plane and worker nodes.
    Without instances, the cluster cannot function.

    Failure indicates: The cluster has no compute infrastructure, suggesting incomplete
    installation, catastrophic infrastructure failure, or incorrect data collection.
    """
    instances = cluster_data.ec2_instances
    infra_id = cluster_data.infra_id

    print(f"\n✓ Found {len(instances)} EC2 instances:")

    # Build brief summaries for all instances
    instance_summaries = []
    for instance in instances:
        instance_id = instance.get('InstanceId', 'unknown')

        # Handle both state formats
        state_data = instance.get('State', 'unknown')
        if isinstance(state_data, dict):
            state = state_data.get('Name', 'unknown')
        else:
            state = state_data

        # Extract tags
        tags = {tag['Key']: tag['Value'] for tag in instance.get('Tags', [])}
        name = tags.get('Name', 'unknown')

        # Find cluster-linking tag
        cluster_tag = None
        for key, value in tags.items():
            if f'kubernetes.io/cluster/{infra_id}' == key:
                cluster_tag = f"{key}={value}"
                break
            elif 'kubernetes.io/cluster' in key:
                cluster_tag = f"{key}={value}"
                break

        summary = {
            "InstanceId": instance_id,
            "Name": name,
            "State": state,
        }

        if cluster_tag:
            summary["ClusterTag"] = cluster_tag

        if tags.get('red-hat-managed'):
            summary["RedHatManaged"] = tags.get('red-hat-managed')

        instance_summaries.append(summary)

    print(json.dumps(instance_summaries, indent=2, default=str))

    assert cluster_data.ec2_instances, "No EC2 instances found"
    assert len(cluster_data.ec2_instances) > 0, "EC2 instance list is empty"


@pytest.mark.instances
def test_control_plane_instances_running(cluster_data: ClusterData):
    """Control plane instances must be in running state.

    Why: Control plane instances host the Kubernetes API server, etcd, and other critical
    cluster services. Non-running control plane instances prevent cluster management and workload operations.

    Failure indicates: Control plane instances are stopped, stopping, or terminated. This could indicate
    infrastructure issues, manual intervention, or cluster degradation requiring immediate attention.
    """
    masters = get_instances_by_role(cluster_data, 'master')

    # Check if EC2 instances file exists
    if not cluster_data.ec2_instances:
        print("\n✗ No EC2 instances data found")
        print("\nTo collect EC2 instance data, run:")
        print("  aws ec2 describe-instances --output json > <cluster-id>_ec2_instances.json")
        print("\nOr use the data collection script:")
        print("  ./get_install_artifacts.sh -c <cluster-id>")
        print("  # OR")
        print("  ./get_install_artifacts.py -c <cluster-id>")
        pytest.skip("No EC2 instances data file found - run data collection script")

    if not masters:
        print("\n✗ No control plane instances found")
        print(f"\nExpected: At least 1 control plane instance with 'master' in the Name tag")
        print("\nExpected resource structure:")
        expected = {
            "InstanceId": "i-0master000000001a",
            "State": {"Name": "running", "Code": 16},
            "InstanceType": "m5.2xlarge",
            "PrivateIpAddress": "10.0.1.10",
            "Tags": [
                {"Key": "Name", "Value": "<infra-id>-master-0"},
                {"Key": f"kubernetes.io/cluster/{cluster_data.infra_id}", "Value": "owned"},
                {"Key": "red-hat-managed", "Value": "true"},
                {"Key": "api.openshift.com/id", "Value": cluster_data.infra_id}
            ]
        }
        print(json.dumps(expected, indent=2))
        pytest.skip("No control plane instances found")

    # Extract cluster-linking tags and build brief summaries
    infra_id = cluster_data.infra_id
    master_summaries = []

    print(f"\n✓ Found {len(masters)} control plane instances:")

    for idx, instance in enumerate(masters, 1):
        instance_id = instance.get('InstanceId', 'unknown')

        # Handle both formats: string or dict for State
        state_data = instance.get('State', 'unknown')
        if isinstance(state_data, dict):
            state = state_data.get('Name', 'unknown')
        else:
            state = state_data

        # Extract tags
        tags = {tag['Key']: tag['Value'] for tag in instance.get('Tags', [])}
        name = tags.get('Name', 'unknown')

        # Find primary cluster-linking tag
        cluster_tag_key = None
        cluster_tag_value = None
        for key, value in tags.items():
            if f'kubernetes.io/cluster/{infra_id}' == key:
                cluster_tag_key = key
                cluster_tag_value = value
                break
            elif 'kubernetes.io/cluster' in key and infra_id in key:
                cluster_tag_key = key
                cluster_tag_value = value
                break

        # Build brief summary for each instance
        summary = {
            "InstanceId": instance_id,
            "Name": name,
            "State": state,
        }

        if cluster_tag_key:
            summary["ClusterTag"] = f"{cluster_tag_key}={cluster_tag_value}"

        # Add other cluster-linking tags
        if tags.get('red-hat-managed'):
            summary["RedHatManaged"] = tags.get('red-hat-managed')

        if instance.get('LaunchTime'):
            summary["LaunchTime"] = instance.get('LaunchTime')

        master_summaries.append(summary)

    # Print each instance summary
    print(json.dumps(master_summaries, indent=2, default=str))

    # Check for non-running instances
    non_running = []
    non_running_details = []

    for instance in masters:
        instance_id = instance.get('InstanceId', 'unknown')
        state_data = instance.get('State', 'unknown')

        if isinstance(state_data, dict):
            state = state_data.get('Name', 'unknown')
        else:
            state = state_data

        if state != 'running':
            non_running.append(f"{instance_id} ({state})")

            # Get full instance details for failure message
            tags = {tag['Key']: tag['Value'] for tag in instance.get('Tags', [])}
            non_running_details.append({
                "InstanceId": instance_id,
                "Name": tags.get('Name', 'unknown'),
                "State": state_data,
                "InstanceType": instance.get('InstanceType', 'unknown')
            })

    if non_running:
        print(f"\n✗ Control plane instances not running: {', '.join(non_running)}")
        print("\nNon-running instance details:")
        print(json.dumps(non_running_details, indent=2, default=str))

        print("\nExpected state:")
        print(json.dumps({"State": {"Name": "running", "Code": 16}}, indent=2))

        assert False, f"Control plane instances not running: {', '.join(non_running)}"


@pytest.mark.instances
def test_worker_instances_running(cluster_data: ClusterData):
    """Worker instances must be in running state.

    Why: Worker nodes run application workloads and cluster operators. Non-running workers
    reduce cluster capacity and may prevent workloads from scheduling or running.

    Failure indicates: Worker instances are stopped, stopping, or terminated. This could indicate
    auto-scaling issues, infrastructure failures, or capacity problems affecting workload availability.
    """
    workers = get_instances_by_role(cluster_data, 'worker')

    # Check if EC2 instances file exists
    if not cluster_data.ec2_instances:
        print("\n✗ No EC2 instances data found")
        print("\nTo collect EC2 instance data, run:")
        print("  aws ec2 describe-instances --output json > <cluster-id>_ec2_instances.json")
        print("\nOr use the data collection script:")
        print("  ./get_install_artifacts.sh -c <cluster-id>")
        print("  # OR")
        print("  ./get_install_artifacts.py -c <cluster-id>")
        pytest.skip("No EC2 instances data file found - run data collection script")

    if not workers:
        print("\n✗ No worker instances found")
        print(f"\nExpected: At least 2 worker instances with 'worker' in the Name tag")
        print("\nExpected resource structure:")
        expected = {
            "InstanceId": "i-0worker00000001a",
            "State": {"Name": "running", "Code": 16},
            "InstanceType": "m5.xlarge",
            "PrivateIpAddress": "10.0.2.10",
            "Tags": [
                {"Key": "Name", "Value": "<infra-id>-worker-0"},
                {"Key": f"kubernetes.io/cluster/{cluster_data.infra_id}", "Value": "owned"},
                {"Key": "red-hat-managed", "Value": "true"},
                {"Key": "api.openshift.com/id", "Value": cluster_data.infra_id}
            ]
        }
        print(json.dumps(expected, indent=2))
        pytest.skip("No worker instances found")

    # Extract cluster-linking tags and build brief summaries
    infra_id = cluster_data.infra_id
    worker_summaries = []

    print(f"\n✓ Found {len(workers)} worker instances:")

    for idx, instance in enumerate(workers, 1):
        instance_id = instance.get('InstanceId', 'unknown')

        # Handle both formats: string or dict for State
        state_data = instance.get('State', 'unknown')
        if isinstance(state_data, dict):
            state = state_data.get('Name', 'unknown')
        else:
            state = state_data

        # Extract tags
        tags = {tag['Key']: tag['Value'] for tag in instance.get('Tags', [])}
        name = tags.get('Name', 'unknown')

        # Find primary cluster-linking tag
        cluster_tag_key = None
        cluster_tag_value = None
        for key, value in tags.items():
            if f'kubernetes.io/cluster/{infra_id}' == key:
                cluster_tag_key = key
                cluster_tag_value = value
                break
            elif 'kubernetes.io/cluster' in key and infra_id in key:
                cluster_tag_key = key
                cluster_tag_value = value
                break

        # Build brief summary for each instance
        summary = {
            "InstanceId": instance_id,
            "Name": name,
            "State": state,
        }

        if cluster_tag_key:
            summary["ClusterTag"] = f"{cluster_tag_key}={cluster_tag_value}"

        # Add other cluster-linking tags
        if tags.get('red-hat-managed'):
            summary["RedHatManaged"] = tags.get('red-hat-managed')

        if instance.get('LaunchTime'):
            summary["LaunchTime"] = instance.get('LaunchTime')

        worker_summaries.append(summary)

    # Print each instance summary
    print(json.dumps(worker_summaries, indent=2, default=str))

    # Check for non-running instances
    non_running = []
    non_running_details = []

    for instance in workers:
        instance_id = instance.get('InstanceId', 'unknown')
        state_data = instance.get('State', 'unknown')

        if isinstance(state_data, dict):
            state = state_data.get('Name', 'unknown')
        else:
            state = state_data

        if state != 'running':
            non_running.append(f"{instance_id} ({state})")

            # Get full instance details for failure message
            tags = {tag['Key']: tag['Value'] for tag in instance.get('Tags', [])}
            non_running_details.append({
                "InstanceId": instance_id,
                "Name": tags.get('Name', 'unknown'),
                "State": state_data,
                "InstanceType": instance.get('InstanceType', 'unknown')
            })

    if non_running:
        print(f"\n✗ Worker instances not running: {', '.join(non_running)}")
        print("\nNon-running instance details:")
        print(json.dumps(non_running_details, indent=2, default=str))

        print("\nExpected state:")
        print(json.dumps({"State": {"Name": "running", "Code": 16}}, indent=2))

        assert False, f"Worker instances not running: {', '.join(non_running)}"


@pytest.mark.instances
def test_instances_have_private_ips(cluster_data: ClusterData):
    """All instances must have private IP addresses.

    Why: Private IP addresses are required for node-to-node communication, pod networking,
    and cluster service discovery. Without private IPs, nodes cannot participate in the cluster.

    Failure indicates: Instances were terminated or networking failed to initialize. This prevents
    the instance from joining the cluster and requires investigation of EC2 networking configuration.
    """
    instances_without_ip = []

    for instance in cluster_data.ec2_instances:
        instance_id = instance.get('InstanceId', 'unknown')
        private_ip = instance.get('PrivateIpAddress')

        # Check for null, empty string, or missing
        if not private_ip:
            instances_without_ip.append(instance_id)

    assert not instances_without_ip, f"Instances without private IP: {', '.join(instances_without_ip)}"


@pytest.mark.instances
def test_instances_in_vpc(cluster_data: ClusterData, vpc_cidr: str):
    """All instances must be in the cluster VPC"""
    instances_outside_vpc = []

    for instance in cluster_data.ec2_instances:
        instance_id = instance.get('InstanceId', 'unknown')
        vpc_id = instance.get('VpcId', '')

        # Get expected VPC ID from VPC data
        expected_vpc_id = ''
        vpcs = cluster_data.vpcs.get('Vpcs', [])
        if vpcs:
            expected_vpc_id = vpcs[0].get('VpcId', '')

        if vpc_id != expected_vpc_id:
            instances_outside_vpc.append(f"{instance_id} (in VPC {vpc_id})")

    assert not instances_outside_vpc, f"Instances not in cluster VPC: {', '.join(instances_outside_vpc)}"


@pytest.mark.instances
def test_instances_have_security_groups(cluster_data: ClusterData):
    """All instances must have security groups attached.

    Why: Security groups control network traffic to and from instances. Missing security groups
    would either block all traffic (preventing cluster operation) or allow unrestricted access (security risk).

    Failure indicates: Instance networking is misconfigured. This could prevent cluster communication
    or indicate incomplete instance initialization requiring investigation.
    """
    instances_without_sgs = []

    for instance in cluster_data.ec2_instances:
        instance_id = instance.get('InstanceId', 'unknown')
        security_groups = instance.get('SecurityGroups')

        # Check for null, empty list, or missing
        if not security_groups:
            instances_without_sgs.append(instance_id)

    assert not instances_without_sgs, f"Instances without security groups: {', '.join(instances_without_sgs)}"


@pytest.mark.instances
def test_control_plane_instance_count(cluster_data: ClusterData):
    """Control plane should have 3 instances for HA.

    Why: ROSA production clusters deploy 3 control plane instances for high availability
    and etcd quorum requirements. This ensures cluster resilience during single-node failures.

    Failure indicates: The cluster has fewer or more than 3 control plane instances, indicating
    either incomplete deployment, instance failure, or non-standard configuration that may affect availability.
    """
    masters = get_instances_by_role(cluster_data, 'master')
    infra_id = cluster_data.infra_id

    print(f"\n✓ Found {len(masters)} control plane instances:")

    # Build brief summaries
    master_summaries = []
    for instance in masters:
        instance_id = instance.get('InstanceId', 'unknown')

        # Handle both state formats
        state_data = instance.get('State', 'unknown')
        if isinstance(state_data, dict):
            state = state_data.get('Name', 'unknown')
        else:
            state = state_data

        # Extract tags
        tags = {tag['Key']: tag['Value'] for tag in instance.get('Tags', [])}
        name = tags.get('Name', 'unknown')

        # Find cluster-linking tag
        cluster_tag = None
        for key, value in tags.items():
            if f'kubernetes.io/cluster/{infra_id}' == key:
                cluster_tag = f"{key}={value}"
                break
            elif 'kubernetes.io/cluster' in key:
                cluster_tag = f"{key}={value}"
                break

        summary = {
            "InstanceId": instance_id,
            "Name": name,
            "State": state,
        }

        if cluster_tag:
            summary["ClusterTag"] = cluster_tag

        master_summaries.append(summary)

    print(json.dumps(master_summaries, indent=2, default=str))

    if not masters:
        pytest.skip("No control plane instances found")

    master_count = len(masters)

    if master_count != 3:
        pytest.fail(f"Expected 3 control plane instances for HA, found {master_count}")


@pytest.mark.instances
def test_instances_have_cluster_tags(cluster_data: ClusterData):
    """All instances must have cluster ownership tags.

    Why: Cluster ownership tags (kubernetes.io/cluster/<infra-id>) enable Kubernetes cloud controllers
    to identify and manage cluster resources. Missing tags prevent automatic lifecycle management.

    Failure indicates: Instances are missing required cluster identification tags. This could prevent
    cloud provider integrations from working correctly and may indicate incomplete instance provisioning.
    """
    infra_id = cluster_data.infra_id
    instances_without_tags = []

    for instance in cluster_data.ec2_instances:
        instance_id = instance.get('InstanceId', 'unknown')
        tags = {tag['Key']: tag['Value'] for tag in instance.get('Tags', [])}

        # Check for cluster ownership tag
        has_cluster_tag = False
        for key in tags.keys():
            if infra_id in key or f"kubernetes.io/cluster/{infra_id}" == key:
                has_cluster_tag = True
                break

        if not has_cluster_tag:
            instances_without_tags.append(instance_id)

    assert not instances_without_tags, f"Instances without cluster tags: {', '.join(instances_without_tags)}"


@pytest.mark.instances
def test_instances_have_iam_profile(cluster_data: ClusterData):
    """Instances should have IAM instance profiles for AWS API access"""
    instances_without_profile = []

    for instance in cluster_data.ec2_instances:
        instance_id = instance.get('InstanceId', 'unknown')
        iam_profile = instance.get('IamInstanceProfile', {})

        if not iam_profile:
            instances_without_profile.append(instance_id)

    # IAM profiles are recommended but not strictly required
    if instances_without_profile:
        pytest.skip(f"Instances without IAM profiles (optional): {', '.join(instances_without_profile)}")
