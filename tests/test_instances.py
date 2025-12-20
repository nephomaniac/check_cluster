"""
EC2 Instance Tests

Validates EC2 instances for ROSA cluster nodes (control plane and workers).
"""

import json
import pytest
from models.cluster import ClusterData


def get_instances_by_role(cluster_data: ClusterData, role: str) -> list:
    """
    Get instances filtered by role (master, worker, or infra).

    Args:
        cluster_data: ClusterData object
        role: 'master', 'worker', or 'infra'

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
        elif role == 'infra' and 'infra' in instance_name.lower():
            instances.append(instance)

    return instances


def search_cloudtrail_for_instance(cluster_data: ClusterData, instance_id: str) -> dict:
    """
    Search CloudTrail events for instance-related events.

    Args:
        cluster_data: ClusterData object
        instance_id: EC2 instance ID to search for

    Returns:
        Dictionary with categorized CloudTrail events
    """
    events = cluster_data.cloudtrail_events

    if not events:
        return {
            'found': False,
            'message': 'No CloudTrail data available',
            'events': []
        }

    instance_events = []

    for event in events:
        # Check if event is related to this instance
        event_str = str(event).lower()
        if instance_id.lower() in event_str:
            event_name = event.get('EventName', '')
            event_time = event.get('EventTime', '')
            username = event.get('Username', '')

            # Parse CloudTrailEvent JSON if present
            cloud_trail_event = event.get('CloudTrailEvent', '{}')
            try:
                import json as json_lib
                ct_data = json_lib.loads(cloud_trail_event) if isinstance(cloud_trail_event, str) else cloud_trail_event

                # Extract relevant details
                error_code = ct_data.get('errorCode', '')
                error_message = ct_data.get('errorMessage', '')
                request_params = ct_data.get('requestParameters', {})
                response_elements = ct_data.get('responseElements', {})

                instance_events.append({
                    'EventName': event_name,
                    'EventTime': event_time,
                    'Username': username,
                    'ErrorCode': error_code,
                    'ErrorMessage': error_message[:200] if error_message else '',
                    'RequestParameters': request_params,
                    'ResponseElements': response_elements
                })
            except:
                # If parsing fails, just include basic info
                instance_events.append({
                    'EventName': event_name,
                    'EventTime': event_time,
                    'Username': username
                })

    if instance_events:
        return {
            'found': True,
            'count': len(instance_events),
            'events': instance_events
        }
    else:
        return {
            'found': False,
            'message': f'No CloudTrail events found for {instance_id}',
            'events': []
        }


def get_expected_infra_count(cluster_data: ClusterData) -> int:
    """
    Determine expected number of infra nodes based on cluster configuration.

    Args:
        cluster_data: ClusterData object

    Returns:
        Expected minimum number of infra nodes
    """
    # Check if cluster is multi-AZ
    cluster_json = cluster_data.cluster_json
    multi_az = cluster_json.get('multi_az', False)

    # Multi-AZ clusters typically have 3 infra nodes (one per AZ)
    # Single-AZ clusters typically have 2 infra nodes for HA
    if multi_az:
        return 3
    else:
        return 2


@pytest.mark.instances
def test_instances_exist(cluster_data: ClusterData):
    """Cluster must have EC2 instances.

    Why: ROSA clusters require EC2 instances to run both control plane and worker nodes.
    Without instances, the cluster cannot function.

    Failure indicates: The cluster has no compute infrastructure, suggesting incomplete
    installation, catastrophic infrastructure failure, or incorrect data collection.

    Success indicates: EC2 instances exist and were successfully collected.
    """
    instances = cluster_data.ec2_instances
    infra_id = cluster_data.infra_id

    if not instances:
        # Import diagnostic helper
        from utils.aws_resource_diagnostics import diagnose_missing_aws_resource

        # Get comprehensive diagnostics
        diagnostics = diagnose_missing_aws_resource(
            cluster_data=cluster_data,
            resource_type="EC2 Instances",
            expected_file=f"{cluster_data.cluster_id}_instances.json",
            api_service="ec2",
            api_operation="describe_instances",
            resource_identifier=infra_id
        )

        pytest.fail(f"No EC2 instances found.\n\n{diagnostics}")

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

    print("\n" + "─"*80)
    print("EC2 DESCRIBE-INSTANCES OUTPUT - All Cluster Instances")
    print("Shows EC2 instance IDs, names, states, and cluster ownership tags")
    print("Relevance: Verifies cluster has compute resources and all instances are tagged correctly")
    print("─"*80)
    print(json.dumps(instance_summaries, indent=2, default=str))
    print("─"*80)

    assert len(instances) > 0, "EC2 instance list is empty"


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
        print("\n" + "─"*80)
        print("Expected Control Plane Instance Structure")
        print("Example of what a valid control plane instance should look like")
        print("─"*80)
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
        print("─"*80)
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
    print("\n" + "─"*80)
    print("EC2 DESCRIBE-INSTANCES OUTPUT - Control Plane Instances")
    print("Shows master node instance IDs, states, and launch times")
    print("Relevance: Verifies control plane nodes exist and are properly tagged")
    print("─"*80)
    print(json.dumps(master_summaries, indent=2, default=str))
    print("─"*80)

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
        print("\n" + "─"*80)
        print("EC2 DESCRIBE-INSTANCES OUTPUT - Non-Running Control Plane Instances")
        print(f"Shows {len(non_running_details)} master node(s) in unexpected state(s)")
        print("Relevance: CRITICAL - Control plane not running prevents cluster operations")
        print("─"*80)
        print(json.dumps(non_running_details, indent=2, default=str))
        print("─"*80)

        print("\n" + "─"*80)
        print("EXPECTED EC2 STATE - Control Plane Instances Must Be Running")
        print("AWS EC2 State.Name must be 'running' (Code 16) for cluster to function")
        print("Relevance: Compares actual state above with required state for healthy cluster")
        print("─"*80)
        print(json.dumps({"State": {"Name": "running", "Code": 16}}, indent=2))
        print("─"*80)

        # Search CloudTrail for events related to non-running instances
        print("\n" + "="*80)
        print("CloudTrail Investigation - Control Plane Instance State Changes")
        print("="*80)

        for instance in masters:
            instance_id = instance.get('InstanceId', 'unknown')
            state_data = instance.get('State', 'unknown')

            if isinstance(state_data, dict):
                state = state_data.get('Name', 'unknown')
            else:
                state = state_data

            if state != 'running':
                tags = {tag['Key']: tag['Value'] for tag in instance.get('Tags', [])}
                instance_name = tags.get('Name', 'unknown')

                print(f"\nSearching CloudTrail for {instance_name} ({instance_id})...")
                cloudtrail_results = search_cloudtrail_for_instance(cluster_data, instance_id)

                if cloudtrail_results['found']:
                    print(f"✓ Found {cloudtrail_results['count']} CloudTrail event(s):")

                    # Determine what the events show
                    event_names = [e.get('EventName', '') for e in cloudtrail_results['events']]
                    if 'TerminateInstances' in event_names:
                        action_desc = "showing instance was terminated"
                    elif 'StopInstances' in event_names:
                        action_desc = "showing instance was stopped"
                    elif 'RunInstances' in event_names:
                        action_desc = "showing instance was created/launched"
                    else:
                        action_desc = "showing instance state change events"

                    print("\n" + "─"*80)
                    print(f"CLOUDTRAIL API LOGS - {action_desc.upper()}")
                    print(f"Instance: {instance_name} ({instance_id})")
                    print(f"Relevance: Identifies WHO changed instance state, WHEN it occurred, and WHY (if error)")
                    print("Key fields: EventName (API call), EventTime, Username (IAM identity), ErrorCode")
                    print("─"*80)
                    print(json.dumps(cloudtrail_results['events'], indent=2, default=str))
                    print("─"*80)
                else:
                    print(f"✗ {cloudtrail_results['message']}")

        print("="*80 + "\n")

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
        print("\n" + "─"*80)
        print("Expected Worker Instance Structure")
        print("Example of what a valid worker instance should look like")
        print("─"*80)
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
        print("─"*80)
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
    print("\n" + "─"*80)
    print("EC2 DESCRIBE-INSTANCES OUTPUT - Worker Instances")
    print("Shows worker node instance IDs, states, and launch times")
    print("Relevance: Verifies worker nodes exist for running application workloads")
    print("─"*80)
    print(json.dumps(worker_summaries, indent=2, default=str))
    print("─"*80)

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
        print("\n" + "─"*80)
        print("EC2 DESCRIBE-INSTANCES OUTPUT - Non-Running Worker Instances")
        print(f"Shows {len(non_running_details)} worker node(s) in unexpected state(s)")
        print("Relevance: Worker nodes not running reduces cluster capacity for workloads")
        print("─"*80)
        print(json.dumps(non_running_details, indent=2, default=str))
        print("─"*80)

        print("\n" + "─"*80)
        print("EXPECTED EC2 STATE - Worker Instances Should Be Running")
        print("AWS EC2 State.Name should be 'running' (Code 16) for full cluster capacity")
        print("Relevance: Compares actual state above with required state for healthy cluster")
        print("─"*80)
        print(json.dumps({"State": {"Name": "running", "Code": 16}}, indent=2))
        print("─"*80)

        # Search CloudTrail for events related to non-running instances
        print("\n" + "="*80)
        print("CloudTrail Investigation - Worker Instance State Changes")
        print("="*80)

        for instance in workers:
            instance_id = instance.get('InstanceId', 'unknown')
            state_data = instance.get('State', 'unknown')

            if isinstance(state_data, dict):
                state = state_data.get('Name', 'unknown')
            else:
                state = state_data

            if state != 'running':
                tags = {tag['Key']: tag['Value'] for tag in instance.get('Tags', [])}
                instance_name = tags.get('Name', 'unknown')

                print(f"\nSearching CloudTrail for {instance_name} ({instance_id})...")
                cloudtrail_results = search_cloudtrail_for_instance(cluster_data, instance_id)

                if cloudtrail_results['found']:
                    print(f"✓ Found {cloudtrail_results['count']} CloudTrail event(s):")

                    # Determine what the events show
                    event_names = [e.get('EventName', '') for e in cloudtrail_results['events']]
                    if 'TerminateInstances' in event_names:
                        action_desc = "showing instance was terminated"
                    elif 'StopInstances' in event_names:
                        action_desc = "showing instance was stopped"
                    elif 'RunInstances' in event_names:
                        action_desc = "showing instance was created/launched"
                    else:
                        action_desc = "showing instance state change events"

                    print("\n" + "─"*80)
                    print(f"CLOUDTRAIL API LOGS - {action_desc.upper()}")
                    print(f"Instance: {instance_name} ({instance_id})")
                    print(f"Relevance: Identifies WHO changed instance state, WHEN it occurred, and WHY (if error)")
                    print("Key fields: EventName (API call), EventTime, Username (IAM identity), ErrorCode")
                    print("─"*80)
                    print(json.dumps(cloudtrail_results['events'], indent=2, default=str))
                    print("─"*80)
                else:
                    print(f"✗ {cloudtrail_results['message']}")

        print("="*80 + "\n")

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

    print("\n" + "─"*80)
    print("EC2 DESCRIBE-INSTANCES OUTPUT - Control Plane Instance Count Verification")
    print("Expected: 3 control plane instances for high availability (HA)")
    print("Relevance: HA requires 3 masters for etcd quorum and resilience to single node failure")
    print("─"*80)
    print(json.dumps(master_summaries, indent=2, default=str))
    print("─"*80)

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
def test_infra_instances_running(cluster_data: ClusterData):
    """Infra instances must be in running state.

    Why: Infra nodes run critical cluster infrastructure components including the ingress router,
    image registry, and monitoring stack. Non-running infra instances degrade cluster functionality
    and may prevent application access.

    Failure indicates: Infra instances are stopped, stopping, or terminated. This could indicate
    infrastructure failures, auto-scaling issues, or capacity problems affecting cluster services.
    """
    infras = get_instances_by_role(cluster_data, 'infra')

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

    if not infras:
        print("\n✗ No infra instances found")
        print(f"\nExpected: At least 2 infra instances with 'infra' in the Name tag")
        print("\n" + "─"*80)
        print("Expected Infra Instance Structure")
        print("Example of what a valid infra instance should look like")
        print("─"*80)
        expected = {
            "InstanceId": "i-0infra000000001a",
            "State": {"Name": "running", "Code": 16},
            "InstanceType": "m5.xlarge",
            "PrivateIpAddress": "10.0.2.10",
            "Tags": [
                {"Key": "Name", "Value": "<infra-id>-infra-0"},
                {"Key": f"kubernetes.io/cluster/{cluster_data.infra_id}", "Value": "owned"},
                {"Key": "red-hat-managed", "Value": "true"},
                {"Key": "api.openshift.com/id", "Value": cluster_data.infra_id}
            ]
        }
        print(json.dumps(expected, indent=2))
        print("─"*80)
        pytest.skip("No infra instances found")

    # Extract cluster-linking tags and build brief summaries
    infra_id = cluster_data.infra_id
    infra_summaries = []

    print(f"\n✓ Found {len(infras)} infra instances:")

    for idx, instance in enumerate(infras, 1):
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

        infra_summaries.append(summary)

    # Print each instance summary
    print("\n" + "─"*80)
    print("EC2 DESCRIBE-INSTANCES OUTPUT - Infrastructure Instances")
    print("Shows infra node instance IDs, states, and launch times")
    print("Relevance: Verifies infrastructure nodes exist for ingress, registry, and monitoring")
    print("─"*80)
    print(json.dumps(infra_summaries, indent=2, default=str))
    print("─"*80)

    # Check for non-running instances
    non_running = []
    non_running_details = []

    for instance in infras:
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
        print(f"\n✗ Infra instances not running: {', '.join(non_running)}")
        print("\n" + "─"*80)
        print("EC2 DESCRIBE-INSTANCES OUTPUT - Non-Running Infrastructure Instances")
        print(f"Shows {len(non_running_details)} infra node(s) in unexpected state(s)")
        print("Relevance: Infra nodes not running degrades ingress, registry, and monitoring services")
        print("─"*80)
        print(json.dumps(non_running_details, indent=2, default=str))
        print("─"*80)

        print("\n" + "─"*80)
        print("EXPECTED EC2 STATE - Infra Instances Should Be Running")
        print("AWS EC2 State.Name should be 'running' (Code 16) for full service availability")
        print("Relevance: Compares actual state above with required state for healthy infrastructure")
        print("─"*80)
        print(json.dumps({"State": {"Name": "running", "Code": 16}}, indent=2))
        print("─"*80)

        # Search CloudTrail for events related to non-running instances
        print("\n" + "="*80)
        print("CloudTrail Investigation - Infra Instance State Changes")
        print("="*80)

        for instance in infras:
            instance_id = instance.get('InstanceId', 'unknown')
            state_data = instance.get('State', 'unknown')

            if isinstance(state_data, dict):
                state = state_data.get('Name', 'unknown')
            else:
                state = state_data

            if state != 'running':
                tags = {tag['Key']: tag['Value'] for tag in instance.get('Tags', [])}
                instance_name = tags.get('Name', 'unknown')

                print(f"\nSearching CloudTrail for {instance_name} ({instance_id})...")
                cloudtrail_results = search_cloudtrail_for_instance(cluster_data, instance_id)

                if cloudtrail_results['found']:
                    print(f"✓ Found {cloudtrail_results['count']} CloudTrail event(s):")

                    # Determine what the events show
                    event_names = [e.get('EventName', '') for e in cloudtrail_results['events']]
                    if 'TerminateInstances' in event_names:
                        action_desc = "showing instance was terminated"
                    elif 'StopInstances' in event_names:
                        action_desc = "showing instance was stopped"
                    elif 'RunInstances' in event_names:
                        action_desc = "showing instance was created/launched"
                    else:
                        action_desc = "showing instance state change events"

                    print("\n" + "─"*80)
                    print(f"CLOUDTRAIL API LOGS - {action_desc.upper()}")
                    print(f"Instance: {instance_name} ({instance_id})")
                    print(f"Relevance: Identifies WHO changed instance state, WHEN it occurred, and WHY (if error)")
                    print("Key fields: EventName (API call), EventTime, Username (IAM identity), ErrorCode")
                    print("─"*80)
                    print(json.dumps(cloudtrail_results['events'], indent=2, default=str))
                    print("─"*80)
                else:
                    print(f"✗ {cloudtrail_results['message']}")

        print("="*80 + "\n")

        assert False, f"Infra instances not running: {', '.join(non_running)}"


@pytest.mark.instances
def test_infra_instance_count(cluster_data: ClusterData):
    """Infra nodes should meet minimum count based on cluster configuration.

    Why: Infra nodes provide high availability for cluster infrastructure services.
    Multi-AZ clusters require 3 infra nodes (one per AZ), single-AZ clusters require
    2 infra nodes for redundancy.

    Failure indicates: Missing infra nodes (capacity issue), excess infra nodes (investigate why),
    or non-running infra nodes requiring immediate attention.
    """
    infras = get_instances_by_role(cluster_data, 'infra')
    infra_id = cluster_data.infra_id

    # Determine expected count based on cluster configuration
    expected_count = get_expected_infra_count(cluster_data)
    multi_az = cluster_data.cluster_json.get('multi_az', False)

    print(f"\n✓ Cluster configuration:")
    print(f"  - Multi-AZ: {multi_az}")
    print(f"  - Expected minimum infra nodes: {expected_count}")
    print(f"  - Found infra nodes: {len(infras)}")

    if not infras:
        print("\n✗ No infra instances found")
        pytest.fail(f"Expected at least {expected_count} infra instances, found 0")

    # Build summaries
    infra_summaries = []
    for instance in infras:
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

        infra_summaries.append(summary)

    print("\n" + "─"*80)
    print("EC2 DESCRIBE-INSTANCES OUTPUT - Infrastructure Instance Count Verification")
    print(f"Expected minimum: {expected_count} infra nodes ({'Multi-AZ' if multi_az else 'Single-AZ'} cluster)")
    print(f"Actual count: {len(infras)} infra nodes found")
    print(f"Relevance: Infra nodes provide HA for cluster services (ingress, registry, monitoring)")
    print("─"*80)
    print(json.dumps(infra_summaries, indent=2, default=str))
    print("─"*80)

    infra_count = len(infras)

    # Check for fewer than expected
    if infra_count < expected_count:
        print(f"\n✗ Insufficient infra nodes: found {infra_count}, expected minimum {expected_count}")

        # Search CloudTrail for any terminated/stopped infra instances
        print("\n" + "="*80)
        print("CloudTrail Investigation - Missing Infra Instances")
        print("="*80)
        print("\nSearching for recent instance termination or stop events...")

        # Search all instances, not just current ones
        for instance in infras:
            instance_id = instance.get('InstanceId', 'unknown')
            tags = {tag['Key']: tag['Value'] for tag in instance.get('Tags', [])}
            instance_name = tags.get('Name', 'unknown')

            print(f"\nSearching CloudTrail for {instance_name} ({instance_id})...")
            cloudtrail_results = search_cloudtrail_for_instance(cluster_data, instance_id)

            if cloudtrail_results['found']:
                print(f"✓ Found {cloudtrail_results['count']} CloudTrail event(s):")
                print(json.dumps(cloudtrail_results['events'], indent=2, default=str))
            else:
                print(f"✗ {cloudtrail_results['message']}")

        print("="*80 + "\n")

        pytest.fail(f"Insufficient infra nodes: found {infra_count}, expected minimum {expected_count}")

    # Check for more than expected
    elif infra_count > expected_count:
        print(f"\n⚠ More infra nodes than expected: found {infra_count}, expected {expected_count}")
        print("\n⚠ WARNING: Minimum infra node count requirement is met, but there are more instances than expected.")
        print("  Please verify this is intentional and not the result of:")
        print("  - Failed scale-down operations")
        print("  - Manual instance creation")
        print("  - Auto-scaling configuration issues")
        print("  - Incomplete instance cleanup")

        # Search CloudTrail for instance creation events
        print("\n" + "="*80)
        print("CloudTrail Investigation - Excess Infra Instances")
        print("="*80)
        print("\nSearching for instance creation events to understand why there are extra infra nodes...")

        for instance in infras:
            instance_id = instance.get('InstanceId', 'unknown')
            tags = {tag['Key']: tag['Value'] for tag in instance.get('Tags', [])}
            instance_name = tags.get('Name', 'unknown')

            print(f"\nSearching CloudTrail for {instance_name} ({instance_id})...")
            cloudtrail_results = search_cloudtrail_for_instance(cluster_data, instance_id)

            if cloudtrail_results['found']:
                # Filter for RunInstances events
                run_instance_events = [e for e in cloudtrail_results['events'] if 'RunInstances' in e.get('EventName', '')]
                if run_instance_events:
                    print(f"✓ Found instance creation event(s):")
                    print("\n" + "─"*80)
                    print(f"CLOUDTRAIL API LOGS - SHOWING INSTANCE WAS CREATED/LAUNCHED")
                    print(f"Instance: {instance_name} ({instance_id})")
                    print(f"Relevance: Identifies WHO created this instance and WHEN to understand why extra instances exist")
                    print("Key fields: EventTime (when created), Username (IAM identity), RequestParameters (instance config)")
                    print("─"*80)
                    print(json.dumps(run_instance_events, indent=2, default=str))
                    print("─"*80)
                else:
                    print(f"✗ No RunInstances events found (may be outside CloudTrail retention window)")
            else:
                print(f"✗ {cloudtrail_results['message']}")

        print("="*80 + "\n")

        pytest.fail(f"More infra nodes than expected: found {infra_count}, expected {expected_count}. Administrator should confirm this is intentional.")

    # Exactly the expected count - check all are running
    else:
        print(f"\n✓ Infra node count matches expectation: {infra_count}")

        # Verify all are in running state
        non_running = []
        for instance in infras:
            instance_id = instance.get('InstanceId', 'unknown')
            state_data = instance.get('State', 'unknown')

            if isinstance(state_data, dict):
                state = state_data.get('Name', 'unknown')
            else:
                state = state_data

            if state != 'running':
                tags = {tag['Key']: tag['Value'] for tag in instance.get('Tags', [])}
                instance_name = tags.get('Name', 'unknown')
                non_running.append(f"{instance_name} ({instance_id}): {state}")

        if non_running:
            print(f"\n✗ Some infra instances are not running:")
            for nr in non_running:
                print(f"  - {nr}")

            # This would be caught by test_infra_instances_running, but provide info here too
            pytest.fail(f"Infra instances not in running state: {', '.join(non_running)}")


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
