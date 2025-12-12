"""
Auto Scaling Groups Tests

Validates Auto Scaling Group configuration for ROSA worker nodes.
Tests ASG capacity, health checks, and launch template configuration.
"""

import pytest
import json
from pathlib import Path
from models.cluster import ClusterData


@pytest.mark.instances
def test_autoscaling_groups_exist(cluster_data: ClusterData, infra_id: str):
    """Cluster should have Auto Scaling Groups for worker nodes"""
    asg_file = cluster_data.aws_dir / f"{cluster_data.cluster_id}_autoscaling_groups.json"

    if not asg_file.exists():
        pytest.skip(f"Auto Scaling Groups file not found: {asg_file}")

    with open(asg_file) as f:
        asg_data = json.load(f)

    asgs = asg_data.get('AutoScalingGroups', [])

    # ASGs are optional - some clusters may use other scaling mechanisms
    if len(asgs) == 0:
        pytest.skip("No Auto Scaling Groups found (cluster may use other scaling mechanisms)")

    # If ASGs exist, report for informational purposes
    print(f"Found {len(asgs)} Auto Scaling Group(s)")


@pytest.mark.instances
def test_asgs_have_desired_capacity(cluster_data: ClusterData, infra_id: str):
    """Auto Scaling Groups should have desired capacity set"""
    asg_file = cluster_data.aws_dir / f"{cluster_data.cluster_id}_autoscaling_groups.json"

    if not asg_file.exists():
        pytest.skip(f"Auto Scaling Groups file not found: {asg_file}")

    with open(asg_file) as f:
        asg_data = json.load(f)

    asgs = asg_data.get('AutoScalingGroups', [])

    if len(asgs) == 0:
        pytest.skip("No Auto Scaling Groups found")

    asgs_without_capacity = []
    for asg in asgs:
        asg_name = asg.get('AutoScalingGroupName', 'unknown')
        desired_capacity = asg.get('DesiredCapacity')

        if desired_capacity is None or desired_capacity < 0:
            asgs_without_capacity.append(asg_name)

    assert len(asgs_without_capacity) == 0, \
        f"Auto Scaling Groups with invalid desired capacity: {', '.join(asgs_without_capacity)}"


@pytest.mark.instances
def test_asgs_have_min_max_capacity(cluster_data: ClusterData, infra_id: str):
    """Auto Scaling Groups should have min and max capacity configured"""
    asg_file = cluster_data.aws_dir / f"{cluster_data.cluster_id}_autoscaling_groups.json"

    if not asg_file.exists():
        pytest.skip(f"Auto Scaling Groups file not found: {asg_file}")

    with open(asg_file) as f:
        asg_data = json.load(f)

    asgs = asg_data.get('AutoScalingGroups', [])

    if len(asgs) == 0:
        pytest.skip("No Auto Scaling Groups found")

    asgs_with_invalid_capacity = []
    for asg in asgs:
        asg_name = asg.get('AutoScalingGroupName', 'unknown')
        min_size = asg.get('MinSize')
        max_size = asg.get('MaxSize')
        desired = asg.get('DesiredCapacity')

        # Validate min <= desired <= max
        if min_size is None or max_size is None:
            asgs_with_invalid_capacity.append(f"{asg_name} (missing min/max)")
        elif desired is not None and not (min_size <= desired <= max_size):
            asgs_with_invalid_capacity.append(
                f"{asg_name} (min:{min_size}, desired:{desired}, max:{max_size})"
            )

    assert len(asgs_with_invalid_capacity) == 0, \
        f"Auto Scaling Groups with invalid capacity configuration: {', '.join(asgs_with_invalid_capacity)}"


@pytest.mark.instances
def test_asgs_have_health_check_configured(cluster_data: ClusterData, infra_id: str):
    """Auto Scaling Groups should have health checks configured"""
    asg_file = cluster_data.aws_dir / f"{cluster_data.cluster_id}_autoscaling_groups.json"

    if not asg_file.exists():
        pytest.skip(f"Auto Scaling Groups file not found: {asg_file}")

    with open(asg_file) as f:
        asg_data = json.load(f)

    asgs = asg_data.get('AutoScalingGroups', [])

    if len(asgs) == 0:
        pytest.skip("No Auto Scaling Groups found")

    asgs_without_health_check = []
    for asg in asgs:
        asg_name = asg.get('AutoScalingGroupName', 'unknown')
        health_check_type = asg.get('HealthCheckType', '')

        if not health_check_type:
            asgs_without_health_check.append(asg_name)

    assert len(asgs_without_health_check) == 0, \
        f"Auto Scaling Groups without health check: {', '.join(asgs_without_health_check)}"


@pytest.mark.instances
def test_asgs_in_multiple_azs(cluster_data: ClusterData, infra_id: str):
    """Auto Scaling Groups should span multiple AZs for HA (multi-AZ clusters)"""
    asg_file = cluster_data.aws_dir / f"{cluster_data.cluster_id}_autoscaling_groups.json"

    if not asg_file.exists():
        pytest.skip(f"Auto Scaling Groups file not found: {asg_file}")

    # Check if this is a multi-AZ cluster
    multi_az = cluster_data.cluster_json.get('multi_az', False)

    if not multi_az:
        pytest.skip("Single-AZ cluster, multi-AZ ASG check not applicable")

    with open(asg_file) as f:
        asg_data = json.load(f)

    asgs = asg_data.get('AutoScalingGroups', [])

    if len(asgs) == 0:
        pytest.skip("No Auto Scaling Groups found")

    asgs_single_az = []
    for asg in asgs:
        asg_name = asg.get('AutoScalingGroupName', 'unknown')
        azs = asg.get('AvailabilityZones', [])

        if len(azs) < 2:
            asgs_single_az.append(f"{asg_name} ({len(azs)} AZ(s))")

    assert len(asgs_single_az) == 0, \
        f"Multi-AZ cluster: Auto Scaling Groups in single AZ: {', '.join(asgs_single_az)}"


@pytest.mark.instances
def test_asgs_have_launch_template_or_config(cluster_data: ClusterData, infra_id: str):
    """Auto Scaling Groups should have launch template or launch configuration"""
    asg_file = cluster_data.aws_dir / f"{cluster_data.cluster_id}_autoscaling_groups.json"

    if not asg_file.exists():
        pytest.skip(f"Auto Scaling Groups file not found: {asg_file}")

    with open(asg_file) as f:
        asg_data = json.load(f)

    asgs = asg_data.get('AutoScalingGroups', [])

    if len(asgs) == 0:
        pytest.skip("No Auto Scaling Groups found")

    asgs_without_launch_spec = []
    for asg in asgs:
        asg_name = asg.get('AutoScalingGroupName', 'unknown')
        launch_template = asg.get('LaunchTemplate') or asg.get('MixedInstancesPolicy', {}).get('LaunchTemplate')
        launch_config = asg.get('LaunchConfigurationName')

        if not launch_template and not launch_config:
            asgs_without_launch_spec.append(asg_name)

    assert len(asgs_without_launch_spec) == 0, \
        f"Auto Scaling Groups without launch template/config: {', '.join(asgs_without_launch_spec)}"


@pytest.mark.instances
def test_asgs_have_tags(cluster_data: ClusterData, infra_id: str):
    """Auto Scaling Groups should have tags for identification"""
    asg_file = cluster_data.aws_dir / f"{cluster_data.cluster_id}_autoscaling_groups.json"

    if not asg_file.exists():
        pytest.skip(f"Auto Scaling Groups file not found: {asg_file}")

    with open(asg_file) as f:
        asg_data = json.load(f)

    asgs = asg_data.get('AutoScalingGroups', [])

    if len(asgs) == 0:
        pytest.skip("No Auto Scaling Groups found")

    asgs_without_tags = []
    for asg in asgs:
        asg_name = asg.get('AutoScalingGroupName', 'unknown')
        tags = asg.get('Tags', [])

        if len(tags) == 0:
            asgs_without_tags.append(asg_name)

    assert len(asgs_without_tags) == 0, \
        f"Auto Scaling Groups without tags: {', '.join(asgs_without_tags)}"
