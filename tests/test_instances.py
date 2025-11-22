"""
EC2 Instance Tests

Validates EC2 instances for ROSA cluster nodes (control plane and workers).
"""

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
    """Cluster must have EC2 instances"""
    assert cluster_data.ec2_instances, "No EC2 instances found"
    assert len(cluster_data.ec2_instances) > 0, "EC2 instance list is empty"


@pytest.mark.instances
def test_control_plane_instances_running(cluster_data: ClusterData):
    """Control plane instances must be in running state"""
    masters = get_instances_by_role(cluster_data, 'master')

    if not masters:
        pytest.skip("No control plane instances found")

    non_running = []
    for instance in masters:
        instance_id = instance.get('InstanceId', 'unknown')

        # Handle both formats: string or dict
        state_data = instance.get('State', 'unknown')
        if isinstance(state_data, dict):
            state = state_data.get('Name', 'unknown')
        else:
            state = state_data

        if state != 'running':
            non_running.append(f"{instance_id} ({state})")

    assert not non_running, f"Control plane instances not running: {', '.join(non_running)}"


@pytest.mark.instances
def test_worker_instances_running(cluster_data: ClusterData):
    """Worker instances must be in running state"""
    workers = get_instances_by_role(cluster_data, 'worker')

    if not workers:
        pytest.skip("No worker instances found")

    non_running = []
    for instance in workers:
        instance_id = instance.get('InstanceId', 'unknown')

        # Handle both formats: string or dict
        state_data = instance.get('State', 'unknown')
        if isinstance(state_data, dict):
            state = state_data.get('Name', 'unknown')
        else:
            state = state_data

        if state != 'running':
            non_running.append(f"{instance_id} ({state})")

    assert not non_running, f"Worker instances not running: {', '.join(non_running)}"


@pytest.mark.instances
def test_instances_have_private_ips(cluster_data: ClusterData):
    """All instances must have private IP addresses"""
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
    """All instances must have security groups attached"""
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
    """Control plane should have 3 instances for HA"""
    masters = get_instances_by_role(cluster_data, 'master')

    if not masters:
        pytest.skip("No control plane instances found")

    master_count = len(masters)

    if master_count != 3:
        pytest.fail(f"Expected 3 control plane instances for HA, found {master_count}")


@pytest.mark.instances
def test_instances_have_cluster_tags(cluster_data: ClusterData):
    """All instances must have cluster ownership tags"""
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
