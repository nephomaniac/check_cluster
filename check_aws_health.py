#!/usr/bin/env python3
"""
AWS Health Check Script
Checks the health of AWS resources for an OpenShift cluster
"""

import argparse
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Tuple

# Global variables
markdown_output = []  # Accumulate markdown output
source_directory = Path('.')  # Source directory for cluster data files

def add_markdown(text: str):
    """Add text to markdown output"""
    global markdown_output
    markdown_output.append(text)

# Color codes for output
class Colors:
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BLUE = '\033[94m'
    END = '\033[0m'
    BOLD = '\033[1m'

def print_header(text: str):
    """Print a section header"""
    print(f"\n{Colors.BOLD}{Colors.BLUE}{'=' * 80}{Colors.END}")
    print(f"{Colors.BOLD}{Colors.BLUE}{text.center(80)}{Colors.END}")
    print(f"{Colors.BOLD}{Colors.BLUE}{'=' * 80}{Colors.END}\n")

    # Add to markdown with proper anchor
    section_id = text.lower().replace(' ', '-').replace('/', '-')
    add_markdown(f'\n<a name="{section_id}"></a>\n## {text}\n')

def print_status(status: str, message: str):
    """Print a status message with color coding"""
    if status.upper() == "OK" or status.upper() == "HEALTHY":
        color = Colors.GREEN
        symbol = "✓"
        md_badge = "🟢"
    elif status.upper() == "WARNING":
        color = Colors.YELLOW
        symbol = "⚠"
        md_badge = "🟡"
    else:
        color = Colors.RED
        symbol = "✗"
        md_badge = "🔴"

    print(f"{color}{symbol} {status}{Colors.END}: {message}")

    # Add to markdown
    add_markdown(f"{md_badge} **{status}**: {message}\n\n")

def load_json_file(filename: str) -> Dict:
    """Load a JSON file and return its contents"""
    global source_directory
    filepath = source_directory / filename
    if not filepath.exists():
        print_status("WARNING", f"File not found: {filename}")
        return {}

    try:
        with open(filepath, 'r') as f:
            return json.load(f)
    except json.JSONDecodeError as e:
        print_status("ERROR", f"Failed to parse {filename}: {e}")
        return {}

def find_related_cloudtrail_events(cluster_id: str, infra_id: str,
                                  search_terms: List[str],
                                  required_resource_ids: List[str] = None,
                                  max_results: int = 10) -> List[Dict]:
    """
    Search CloudTrail logs for events related to specific error conditions
    Args:
        cluster_id: The cluster ID used for file naming
        infra_id: The infrastructure ID to filter events
        search_terms: List of general terms to search for (e.g., API calls, error codes)
        required_resource_ids: List of specific resource IDs that MUST be present in events
        max_results: Maximum number of events to return
    Returns: List of matching CloudTrail events
    """
    data = load_json_file(f"{cluster_id}_cloudtrail.json")
    if not data:
        return []

    events = data if isinstance(data, list) else []
    if not events:
        return []

    matching_events = []

    for event in events:
        event_name = event.get('EventName', '')
        event_source = event.get('EventSource', '')
        username = event.get('Username', '')
        event_time = event.get('EventTime', '')

        # Parse CloudTrailEvent JSON
        cloud_trail_event = event.get('CloudTrailEvent', '{}')
        try:
            ct_data = json.loads(cloud_trail_event)
            error_code = ct_data.get('errorCode', '')
            error_message = ct_data.get('errorMessage', '')

            # Convert event to string for searching
            event_str = json.dumps(ct_data).lower()

            # If required_resource_ids is specified, event MUST contain at least one
            if required_resource_ids:
                has_required_resource = False
                matched_required_ids = []

                for resource_id in required_resource_ids:
                    if resource_id.lower() in event_str:
                        has_required_resource = True
                        matched_required_ids.append(resource_id)

                # Skip this event if it doesn't contain any required resource ID
                if not has_required_resource:
                    continue

                # Event contains required resource ID, now check for additional context
                matched_terms = matched_required_ids.copy()

                # Add any matching general search terms for context
                for term in search_terms:
                    if term.lower() in event_str and term not in matched_terms:
                        matched_terms.append(term)

                # Extract event ID and request parameters
                event_id = ct_data.get('eventID', 'unknown')
                request_params = ct_data.get('requestParameters', {})

                # Add event to results
                matching_events.append({
                    'event_name': event_name,
                    'event_source': event_source,
                    'event_time': event_time,
                    'username': username,
                    'event_id': event_id,
                    'error_code': error_code,
                    'error_message': error_message[:200] if error_message else '',
                    'request_params': request_params,
                    'matched_terms': matched_terms,
                    'full_event': ct_data
                })
            else:
                # No required resource IDs specified, use original logic
                matched = False
                matched_terms = []

                for term in search_terms:
                    if term.lower() in event_str:
                        matched = True
                        matched_terms.append(term)

                # If matched, add to results
                if matched and (infra_id.lower() in event_str or cluster_id.lower() in event_str or error_code):
                    # Extract event ID and request parameters
                    event_id = ct_data.get('eventID', 'unknown')
                    request_params = ct_data.get('requestParameters', {})

                    matching_events.append({
                        'event_name': event_name,
                        'event_source': event_source,
                        'event_time': event_time,
                        'username': username,
                        'event_id': event_id,
                        'error_code': error_code,
                        'error_message': error_message[:200] if error_message else '',
                        'request_params': request_params,
                        'matched_terms': matched_terms,
                        'full_event': ct_data
                    })

            if len(matching_events) >= max_results:
                break

        except json.JSONDecodeError:
            continue

    return matching_events

def get_cluster_resource_ids(cluster_id: str, infra_id: str) -> Dict:
    """
    Build a comprehensive set of all AWS resource IDs that belong to this cluster
    by scanning local JSON files, log files, and install logs
    Args:
        cluster_id: The cluster ID
        infra_id: The infrastructure ID
    Returns: Dictionary with sets of resource IDs by type
    """
    cluster_resources = {
        'security_groups': set(),
        'instances': set(),
        'load_balancers': set(),
        'volumes': set(),
        'network_interfaces': set(),
        'subnets': set(),
        'vpcs': set(),
        'route_tables': set(),
        'internet_gateways': set(),
        'nat_gateways': set(),
        'elastic_ips': set(),
        'iam_roles': set(),
        'iam_instance_profiles': set(),
        'all_ids': set()
    }

    # 1. Scan security groups file
    sg_data = load_json_file(f"{cluster_id}_security_groups.json")
    if sg_data:
        for sg in sg_data.get('SecurityGroups', []):
            sg_id = sg.get('GroupId')
            sg_name = sg.get('GroupName', '')
            # Check if cluster-owned by infra_id in name or tags
            if sg_id and (infra_id in sg_name or
                         any(infra_id in str(tag.get('Value', '')) for tag in sg.get('Tags', []))):
                cluster_resources['security_groups'].add(sg_id)
                cluster_resources['all_ids'].add(sg_id)

    # 2. Scan instances file
    instances_data = load_json_file(f"{cluster_id}_ec2_instances.json")
    if instances_data:
        instances = []
        if isinstance(instances_data, list):
            for item in instances_data:
                if isinstance(item, list):
                    instances.extend(item)
                else:
                    instances.append(item)

        for instance in instances:
            instance_id = instance.get('InstanceId')
            tags = instance.get('Tags', [])
            # Check if cluster-owned
            if instance_id and any(infra_id in str(tag.get('Value', '')) for tag in tags):
                cluster_resources['instances'].add(instance_id)
                cluster_resources['all_ids'].add(instance_id)

                # Also track related resources
                for vol in instance.get('BlockDeviceMappings', []):
                    vol_id = vol.get('Ebs', {}).get('VolumeId')
                    if vol_id:
                        cluster_resources['volumes'].add(vol_id)
                        cluster_resources['all_ids'].add(vol_id)

                for eni in instance.get('NetworkInterfaces', []):
                    eni_id = eni.get('NetworkInterfaceId')
                    if eni_id:
                        cluster_resources['network_interfaces'].add(eni_id)
                        cluster_resources['all_ids'].add(eni_id)
                    subnet_id = eni.get('SubnetId')
                    if subnet_id:
                        cluster_resources['subnets'].add(subnet_id)
                        cluster_resources['all_ids'].add(subnet_id)

                vpc_id = instance.get('VpcId')
                if vpc_id:
                    cluster_resources['vpcs'].add(vpc_id)
                    cluster_resources['all_ids'].add(vpc_id)

                iam_profile = instance.get('IamInstanceProfile', {}).get('Arn', '')
                if iam_profile:
                    cluster_resources['iam_instance_profiles'].add(iam_profile)
                    cluster_resources['all_ids'].add(iam_profile)

    # 3. Scan load balancers file
    lb_data = load_json_file(f"{cluster_id}_LB_ALL.json")
    if lb_data:
        for lb in lb_data.get('LoadBalancers', []):
            lb_name = lb.get('LoadBalancerName', '')
            lb_arn = lb.get('LoadBalancerArn', '')
            # Check if cluster-owned
            if infra_id in lb_name:
                if lb_arn:
                    cluster_resources['load_balancers'].add(lb_arn)
                    cluster_resources['all_ids'].add(lb_arn)
                if lb_name:
                    cluster_resources['load_balancers'].add(lb_name)
                    cluster_resources['all_ids'].add(lb_name)

                # Track VPC and subnets
                vpc_id = lb.get('VpcId')
                if vpc_id:
                    cluster_resources['vpcs'].add(vpc_id)
                    cluster_resources['all_ids'].add(vpc_id)
                for subnet_id in lb.get('AvailabilityZones', []):
                    if isinstance(subnet_id, dict):
                        subnet = subnet_id.get('SubnetId')
                        if subnet:
                            cluster_resources['subnets'].add(subnet)
                            cluster_resources['all_ids'].add(subnet)

    # 4. Scan install logs from resources.json
    resources_data = load_json_file(f"{cluster_id}_resources.json")
    if resources_data:
        # Parse install logs which may contain resource IDs
        install_logs = resources_data.get('resources', {}).get('install_logs', '')
        if install_logs:
            # Extract AWS resource IDs from install logs using regex patterns
            import re

            # Security group IDs: sg-xxxxxxxxxxxxxxxxx
            sg_ids = re.findall(r'sg-[a-f0-9]{17}', install_logs)
            cluster_resources['security_groups'].update(sg_ids)
            cluster_resources['all_ids'].update(sg_ids)

            # Instance IDs: i-xxxxxxxxxxxxxxxxx
            instance_ids = re.findall(r'i-[a-f0-9]{17}', install_logs)
            cluster_resources['instances'].update(instance_ids)
            cluster_resources['all_ids'].update(instance_ids)

            # Subnet IDs: subnet-xxxxxxxxxxxxxxxxx
            subnet_ids = re.findall(r'subnet-[a-f0-9]{17}', install_logs)
            cluster_resources['subnets'].update(subnet_ids)
            cluster_resources['all_ids'].update(subnet_ids)

            # VPC IDs: vpc-xxxxxxxxxxxxxxxxx
            vpc_ids = re.findall(r'vpc-[a-f0-9]{17}', install_logs)
            cluster_resources['vpcs'].update(vpc_ids)
            cluster_resources['all_ids'].update(vpc_ids)

            # Volume IDs: vol-xxxxxxxxxxxxxxxxx
            vol_ids = re.findall(r'vol-[a-f0-9]{17}', install_logs)
            cluster_resources['volumes'].update(vol_ids)
            cluster_resources['all_ids'].update(vol_ids)

            # Network interface IDs: eni-xxxxxxxxxxxxxxxxx
            eni_ids = re.findall(r'eni-[a-f0-9]{17}', install_logs)
            cluster_resources['network_interfaces'].update(eni_ids)
            cluster_resources['all_ids'].update(eni_ids)

            # Route table IDs: rtb-xxxxxxxxxxxxxxxxx
            rtb_ids = re.findall(r'rtb-[a-f0-9]{17}', install_logs)
            cluster_resources['route_tables'].update(rtb_ids)
            cluster_resources['all_ids'].update(rtb_ids)

            # Internet gateway IDs: igw-xxxxxxxxxxxxxxxxx
            igw_ids = re.findall(r'igw-[a-f0-9]{17}', install_logs)
            cluster_resources['internet_gateways'].update(igw_ids)
            cluster_resources['all_ids'].update(igw_ids)

            # NAT gateway IDs: nat-xxxxxxxxxxxxxxxxx
            nat_ids = re.findall(r'nat-[a-f0-9]{17}', install_logs)
            cluster_resources['nat_gateways'].update(nat_ids)
            cluster_resources['all_ids'].update(nat_ids)

    # 5. Scan any .log files in source directory
    global source_directory
    for log_file in source_directory.glob("*.log"):
        try:
            with open(log_file, 'r') as f:
                log_content = f.read()
                # Extract resource IDs
                import re
                sg_ids = re.findall(r'sg-[a-f0-9]{17}', log_content)
                cluster_resources['security_groups'].update(sg_ids)
                cluster_resources['all_ids'].update(sg_ids)

                instance_ids = re.findall(r'i-[a-f0-9]{17}', log_content)
                cluster_resources['instances'].update(instance_ids)
                cluster_resources['all_ids'].update(instance_ids)

                subnet_ids = re.findall(r'subnet-[a-f0-9]{17}', log_content)
                cluster_resources['subnets'].update(subnet_ids)
                cluster_resources['all_ids'].update(subnet_ids)
        except:
            pass  # Skip files we can't read

    return cluster_resources

def get_resource_info_from_local_files(cluster_id: str, resource_id: str, resource_type: str) -> Dict:
    """
    Get resource information from local JSON files
    Args:
        cluster_id: The cluster ID
        resource_id: The AWS resource ID (sg-xxx, i-xxx, etc.)
        resource_type: Type of resource (sg, instance, lb, etc.)
    Returns: Dictionary with resource info including tags, usage, and source filename
    """
    resource_info = {
        'tags': {},
        'name': 'unknown',
        'role': 'unknown',
        'found': False,
        'details': {},
        'source_file': None
    }

    # Search in appropriate file based on resource type
    if resource_type in ['sg', 'security-group']:
        filename = f"{cluster_id}_security_groups.json"
        data = load_json_file(filename)
        if data:
            for sg in data.get('SecurityGroups', []):
                if sg.get('GroupId') == resource_id:
                    resource_info['found'] = True
                    resource_info['name'] = sg.get('GroupName', 'unknown')
                    resource_info['details'] = sg
                    resource_info['source_file'] = filename
                    # Extract tags
                    for tag in sg.get('Tags', []):
                        resource_info['tags'][tag.get('Key')] = tag.get('Value')
                    break

    elif resource_type in ['instance', 'i']:
        filename = f"{cluster_id}_ec2_instances.json"
        data = load_json_file(filename)
        if data:
            instances = []
            if isinstance(data, list):
                for item in data:
                    if isinstance(item, list):
                        instances.extend(item)
                    else:
                        instances.append(item)

            for instance in instances:
                if instance.get('InstanceId') == resource_id:
                    resource_info['found'] = True
                    resource_info['details'] = instance
                    resource_info['source_file'] = filename
                    # Extract tags and determine role
                    for tag in instance.get('Tags', []):
                        key = tag.get('Key')
                        value = tag.get('Value')
                        resource_info['tags'][key] = value

                        if key == 'Name':
                            resource_info['name'] = value

                        # Determine role
                        value_lower = value.lower()
                        if 'bootstrap' in value_lower:
                            resource_info['role'] = 'bootstrap'
                        elif 'master' in value_lower or 'control-plane' in value_lower:
                            resource_info['role'] = 'master'
                        elif 'infra' in value_lower:
                            resource_info['role'] = 'infra'
                        elif 'worker' in value_lower:
                            resource_info['role'] = 'worker'
                    break

    elif resource_type in ['lb', 'loadbalancer']:
        filename = f"{cluster_id}_LB_ALL.json"
        data = load_json_file(filename)
        if data:
            for lb in data.get('LoadBalancers', []):
                if lb.get('LoadBalancerArn') == resource_id or lb.get('LoadBalancerName') == resource_id:
                    resource_info['found'] = True
                    resource_info['name'] = lb.get('LoadBalancerName', 'unknown')
                    resource_info['details'] = lb
                    resource_info['source_file'] = filename
                    break

    return resource_info

def analyze_event_impact_with_context(cluster_id: str, event_name: str, request_params: Dict,
                                      error_code: str = '', infra_id: str = '',
                                      cluster_resources: Dict = None) -> tuple:
    """
    Analyze why a CloudTrail event could impact cluster functionality using local resource data
    Args:
        cluster_id: The cluster ID
        event_name: The AWS API event name
        request_params: The request parameters from the event
        error_code: Any error code if the event failed
        infra_id: The infrastructure ID
        cluster_resources: Dictionary of known cluster resource IDs
    Returns: (impact_description, is_cluster_impacting, missing_data_commands)
    """
    impact_analysis = []
    missing_data_commands = []
    is_cluster_impacting = False
    event_lower = event_name.lower()

    # If cluster_resources not provided, return not impacting
    if not cluster_resources:
        return ('', False, [])

    # Extract resource IDs from request parameters
    affected_resource_id = None
    resource_type = None
    verified_cluster_resource = False

    # Security Group events
    if 'securitygroup' in event_lower:
        affected_resource_id = request_params.get('groupId') or request_params.get('groupName')
        resource_type = 'sg'

        # Verify this security group is a known cluster resource
        if affected_resource_id and affected_resource_id in cluster_resources['all_ids']:
            verified_cluster_resource = True
        else:
            # Not a verified cluster resource, skip
            return ('', False, [])

        if 'revoke' in event_lower or 'delete' in event_lower:
            if affected_resource_id:
                resource_info = get_resource_info_from_local_files(cluster_id, affected_resource_id, resource_type)

                if resource_info['found']:
                    sg_name = resource_info['name']
                    tags = resource_info['tags']
                    source_file = resource_info.get('source_file', 'unknown')

                    # This is a verified cluster security group
                    if True:  # Already verified above
                        is_cluster_impacting = True
                        impact_analysis.append(f"CLUSTER SECURITY GROUP MODIFIED: {sg_name}")
                        if source_file:
                            impact_analysis.append(f"▸ Resource Details File: {source_file}")

                        # Determine specific role
                        if f"{infra_id}-controlplane" in sg_name or f"{infra_id}-master" in sg_name:
                            impact_analysis.append("▸ Role: Control Plane/Master node security group")
                            impact_analysis.append("▸ Cluster Usage: Protects master nodes running API server, etcd, scheduler")
                            impact_analysis.append("▸ Impact: Revoking rules blocks control plane communication")
                            impact_analysis.append("▸ Consequences: API server unreachable, cluster management impossible")
                        elif f"{infra_id}-node" in sg_name or f"{infra_id}-worker" in sg_name:
                            impact_analysis.append("▸ Role: Worker/Compute node security group")
                            impact_analysis.append("▸ Cluster Usage: Protects worker nodes running application workloads")
                            impact_analysis.append("▸ Impact: Blocks pod-to-pod communication, NodePort access, CNI traffic")
                            impact_analysis.append("▸ Consequences: Pods cannot communicate, services unavailable")
                        elif f"{infra_id}-lb" in sg_name or "apiserver" in sg_name:
                            impact_analysis.append("▸ Role: Load Balancer security group")
                            impact_analysis.append("▸ Cluster Usage: Controls access to API server and ingress")
                            impact_analysis.append("▸ Impact: Blocks external access to cluster API (port 6443)")
                            impact_analysis.append("▸ Consequences: kubectl commands fail, cluster unreachable")

                        # Show specific rules that were revoked
                        if 'ipPermissions' in request_params:
                            impact_analysis.append("▸ Rules Modified:")
                            perms = request_params.get('ipPermissions', {})
                            if isinstance(perms, dict):
                                items = perms.get('items', [perms])
                            else:
                                items = perms if isinstance(perms, list) else [perms]

                            for perm in items[:3]:  # Show first 3
                                if isinstance(perm, dict):
                                    from_port = perm.get('fromPort', 'any')
                                    to_port = perm.get('toPort', 'any')
                                    protocol = perm.get('ipProtocol', 'any')
                                    impact_analysis.append(f"  - Port {from_port}-{to_port} ({protocol})")
                # If resource not found in local files, skip this event (no source_file mapping)
                # User will not see events without local resource data

    # Instance events
    elif 'instance' in event_lower and ('stop' in event_lower or 'terminate' in event_lower or 'reboot' in event_lower):
        # Extract instance IDs
        instance_ids = []
        if 'instancesSet' in request_params:
            items = request_params['instancesSet'].get('items', [])
            instance_ids = [item.get('instanceId') for item in items if item.get('instanceId')]
        elif 'instanceId' in request_params:
            instance_ids = [request_params['instanceId']]

        # Filter to only verified cluster instances
        verified_instance_ids = [iid for iid in instance_ids if iid in cluster_resources['all_ids']]

        if not verified_instance_ids:
            # None of these instances belong to the cluster
            return ('', False, [])

        for instance_id in verified_instance_ids:
            verified_cluster_resource = True
            resource_info = get_resource_info_from_local_files(cluster_id, instance_id, 'instance')

            if resource_info['found']:
                instance_name = resource_info['name']
                role = resource_info['role']
                tags = resource_info['tags']
                source_file = resource_info.get('source_file', 'unknown')

                # Already verified as cluster instance above
                is_cluster_impacting = True
                impact_analysis.append(f"CLUSTER INSTANCE AFFECTED: {instance_name} ({instance_id})")
                if source_file:
                    impact_analysis.append(f"▸ Resource Details File: {source_file}")
                impact_analysis.append(f"▸ Instance Role: {role.upper()}")

                if role == 'bootstrap':
                    impact_analysis.append("▸ Cluster Usage: Bootstrap node initializes the cluster control plane")
                    impact_analysis.append("▸ Runs: Temporary etcd, API server to bootstrap masters")
                    if 'stop' in event_lower or 'terminate' in event_lower:
                        impact_analysis.append("▸ Impact: CRITICAL - Cluster installation will fail")
                        impact_analysis.append("▸ Consequences: Masters cannot join, API server unreachable")
                elif role == 'master':
                    impact_analysis.append("▸ Cluster Usage: Master/Control plane node")
                    impact_analysis.append("▸ Runs: API server, etcd, scheduler, controller manager")
                    if 'stop' in event_lower or 'terminate' in event_lower:
                        impact_analysis.append("▸ Impact: CRITICAL - Control plane capacity reduced")
                        impact_analysis.append("▸ Consequences: May lose etcd quorum (needs 2/3 masters)")
                        impact_analysis.append("▸ Result: Cluster becomes read-only or unavailable")
                elif role == 'worker':
                    impact_analysis.append("▸ Cluster Usage: Worker node runs application workloads")
                    impact_analysis.append("▸ Runs: User pods, cluster operators, logging/monitoring")
                    if 'stop' in event_lower or 'terminate' in event_lower:
                        impact_analysis.append("▸ Impact: Workload capacity reduced")
                        impact_analysis.append("▸ Consequences: Pods evicted, apps may become unavailable")
                elif role == 'infra':
                    impact_analysis.append("▸ Cluster Usage: Infrastructure node for cluster services")
                    impact_analysis.append("▸ Runs: Ingress routers, registry, monitoring, logging")
                    if 'stop' in event_lower or 'terminate' in event_lower:
                        impact_analysis.append("▸ Impact: Cluster services disrupted")
                        impact_analysis.append("▸ Consequences: Ingress down, monitoring unavailable")

                # Show instance details
                instance_details = resource_info['details']
                if 'InstanceType' in instance_details:
                    impact_analysis.append(f"▸ Instance Type: {instance_details['InstanceType']}")
                if 'State' in instance_details:
                    impact_analysis.append(f"▸ Current State: {instance_details['State']}")
            # If instance not found in local files, skip this event (no source_file mapping)
            # User will not see events without local resource data

    # Load Balancer events
    elif 'loadbalancer' in event_lower or 'targetgroup' in event_lower:
        if 'delete' in event_lower or 'deregister' in event_lower or 'modify' in event_lower:
            lb_name = request_params.get('loadBalancerName') or request_params.get('name')
            lb_arn = request_params.get('loadBalancerArn')

            # Verify this is a cluster load balancer
            if (lb_name and lb_name in cluster_resources['all_ids']) or \
               (lb_arn and lb_arn in cluster_resources['all_ids']):
                verified_cluster_resource = True
            else:
                # Not a verified cluster resource
                return ('', False, [])

            if lb_name or lb_arn:
                resource_info = get_resource_info_from_local_files(cluster_id, lb_name or lb_arn, 'lb')

                if resource_info['found']:
                    source_file = resource_info.get('source_file', 'unknown')
                    is_cluster_impacting = True
                    impact_analysis.append(f"CLUSTER LOAD BALANCER MODIFIED: {lb_name or lb_arn}")
                    if source_file:
                        impact_analysis.append(f"▸ Resource Details File: {source_file}")
                    impact_analysis.append("▸ Cluster Usage: Load balancer provides cluster API endpoint")
                    impact_analysis.append("▸ Routes traffic to: Master nodes on port 6443 (API) and 22623 (MCS)")

                    if 'delete' in event_lower:
                        impact_analysis.append("▸ Impact: CRITICAL - API endpoint destroyed")
                        impact_analysis.append("▸ Consequences: Cluster completely unreachable")
                    elif 'deregister' in event_lower:
                        impact_analysis.append("▸ Impact: Master nodes removed from load balancer")
                        impact_analysis.append("▸ Consequences: API requests fail, cluster unreachable")
                # If load balancer not found in local files, skip this event (no source_file mapping)
                # User will not see events without local resource data

    # Network/VPC events
    elif any(x in event_lower for x in ['vpc', 'subnet', 'routetable', 'internetgateway', 'natgateway']):
        if 'delete' in event_lower or 'detach' in event_lower or 'disassociate' in event_lower:
            # Extract resource ID from request parameters
            network_resource_id = None
            if request_params and isinstance(request_params, dict):
                if 'vpcId' in request_params:
                    network_resource_id = request_params.get('vpcId')
                elif 'subnetId' in request_params:
                    network_resource_id = request_params.get('subnetId')
                elif 'routeTableId' in request_params:
                    network_resource_id = request_params.get('routeTableId')
                elif 'internetGatewayId' in request_params:
                    network_resource_id = request_params.get('internetGatewayId')
                elif 'DeleteNatGatewayRequest' in request_params:
                    nat_req = request_params.get('DeleteNatGatewayRequest', {})
                    network_resource_id = nat_req.get('NatGatewayId')

            # Only mark as cluster-impacting if resource ID is in cluster_resources
            if network_resource_id and cluster_resources and network_resource_id in cluster_resources['all_ids']:
                is_cluster_impacting = True
                impact_analysis.append("CLUSTER NETWORK INFRASTRUCTURE MODIFIED")
                impact_analysis.append("▸ Cluster Usage: VPC provides network isolation for cluster")
                impact_analysis.append("▸ Impact: Network connectivity disrupted")
                impact_analysis.append("▸ Consequences: Nodes cannot communicate, pods cannot network")
            # If resource not found in cluster_resources, skip this event

    # Only return impact if this event actually affects the cluster
    if is_cluster_impacting:
        return ('\n      '.join(impact_analysis), True, missing_data_commands)
    else:
        return ('', False, [])

def print_cloudtrail_correlation(events: List[Dict], context: str, cluster_id: str = '', infra_id: str = '', cluster_resources: Dict = None):
    """
    Print CloudTrail events that may be related to an error
    Args:
        events: List of CloudTrail events
        context: Description of what we're correlating (e.g., "bootstrap failure")
        cluster_id: The cluster ID for looking up resource info
        infra_id: The infrastructure ID
        cluster_resources: Dictionary of known cluster resource IDs
    """
    if not events:
        return

    # Build cluster resources if not provided
    if not cluster_resources and cluster_id and infra_id:
        cluster_resources = get_cluster_resource_ids(cluster_id, infra_id)

    print(f"\n{Colors.BOLD}{Colors.YELLOW}Related CloudTrail Events ({context}):{Colors.END}")
    print(f"Found {len(events)} potentially related CloudTrail event(s):\n")

    for i, evt in enumerate(events[:5], 1):  # Show top 5
        print(f"  {Colors.BOLD}Event {i}:{Colors.END}")
        print(f"    Event ID: {evt.get('event_id', 'unknown')}")
        print(f"    Time: {evt['event_time']}")
        print(f"    Action: {evt['event_name']} ({evt['event_source']})")
        print(f"    User: {evt['username']}")

        # Display request parameters summary
        request_params = evt.get('request_params', {})
        if request_params and isinstance(request_params, dict):
            # Show a concise summary of key request parameters
            param_summary = []
            for key, value in list(request_params.items())[:3]:  # Show first 3 params
                if isinstance(value, (str, int, bool)):
                    param_summary.append(f"{key}={value}")
                elif isinstance(value, dict):
                    param_summary.append(f"{key}={{...}}")
                elif isinstance(value, list):
                    param_summary.append(f"{key}=[{len(value)} items]")

            if param_summary:
                print(f"    Request: {', '.join(param_summary)}")

        if evt['error_code']:
            print(f"    {Colors.RED}Error Code: {evt['error_code']}{Colors.END}")
            print(f"    Error Message: {evt['error_message']}")

        if evt['matched_terms']:
            print(f"    Matched Terms: {', '.join(evt['matched_terms'])}")

        # Add impact analysis if cluster_id and infra_id are provided
        if cluster_id and infra_id and cluster_resources:
            impact_text, is_impacting, _ = analyze_event_impact_with_context(
                cluster_id, evt['event_name'], request_params, evt.get('error_code', ''),
                infra_id, cluster_resources
            )
            if impact_text:
                print(f"\n    {Colors.BOLD}{Colors.YELLOW}Why This Matters:{Colors.END}")
                print(f"      {impact_text}")
        print()

def check_security_groups(cluster_id: str, infra_id: str = None) -> Tuple[str, List[str]]:
    """
    Check security groups health and verify required OpenShift rules
    Args:
        cluster_id: The cluster ID used for file naming
        infra_id: The infrastructure ID (if None, will derive from cluster_id)
    Returns: (status, list of issues)
    """
    print_header("Security Groups Health Check")

    data = load_json_file(f"{cluster_id}_security_groups.json")
    if not data:
        return ("ERROR", ["Security groups file not found or empty"])

    issues = []
    security_groups = data.get('SecurityGroups', [])
    faulty_resource_ids = []  # Track resource IDs with issues

    print(f"Total Security Groups: {len(security_groups)}")

    # Required security groups and their rules for OpenShift/ROSA
    if infra_id is None:
        infra_id = cluster_id.split('_')[0]

    print(f"Using Infrastructure ID: {infra_id}")

    # Determine cluster type (public or private) based on API listening mode
    cluster_data = load_json_file(f"{cluster_id}_cluster.json")
    api_listening = cluster_data.get('api', {}).get('listening', 'unknown') if cluster_data else 'unknown'
    is_private_cluster = (api_listening == 'internal')

    print(f"Cluster Type: {'PRIVATE' if is_private_cluster else 'PUBLIC'}")
    print(f"API Listening: {api_listening}")

    required_security_groups = {
        f"{infra_id}-lb": {
            "description": "Load Balancer Security Group",
            "required_ingress": [
                {"port": 6443, "protocol": "tcp", "description": "Kubernetes API Server"},
                {"port": 22623, "protocol": "tcp", "description": "Machine Config Server"},
            ]
        },
        f"{infra_id}-node": {
            "description": "Worker/Compute Node Security Group",
            "required_ingress": [
                {"port": 22, "protocol": "tcp", "description": "SSH"},
                {"port": 10250, "protocol": "tcp", "description": "Kubelet"},
                {"port_range": (30000, 32767), "protocol": "tcp", "description": "NodePort Services"},
                {"port": 4789, "protocol": "udp", "description": "VXLAN"},
                {"port": 6081, "protocol": "udp", "description": "Geneve"},
                {"port_range": (9000, 9999), "protocol": "tcp", "description": "Internal cluster communication"},
            ]
        },
        f"{infra_id}-controlplane": {
            "description": "Control Plane/Master Security Group",
            "required_ingress": [
                {"port": 6443, "protocol": "tcp", "description": "Kubernetes API Server"},
                {"port": 22623, "protocol": "tcp", "description": "Machine Config Server"},
                {"port": 2379, "protocol": "tcp", "description": "etcd", "optional": True},
                {"port": 2380, "protocol": "tcp", "description": "etcd peer", "optional": True},
            ]
        },
        f"{infra_id}-apiserver-lb": {
            "description": "API Server Load Balancer Security Group",
            "required_ingress": [
                {"port": 6443, "protocol": "tcp", "description": "Kubernetes API Server"},
            ]
        }
    }

    # Find cluster security groups
    cluster_sgs = {}
    for sg in security_groups:
        sg_name = sg.get('GroupName', '')
        if infra_id in sg_name:
            cluster_sgs[sg_name] = sg

    print(f"Cluster Security Groups Found: {len(cluster_sgs)}")

    # Check for required security groups
    for required_sg_name, requirements in required_security_groups.items():
        if required_sg_name not in cluster_sgs:
            issues.append(f"Missing required security group: {required_sg_name} ({requirements['description']})")
            print_status("ERROR", f"Missing security group: {required_sg_name}")
            continue

        sg = cluster_sgs[required_sg_name]
        sg_id = sg.get('GroupId', 'unknown')

        print(f"\n{Colors.BOLD}Checking: {required_sg_name} ({sg_id}){Colors.END}")
        print(f"  Description: {requirements['description']}")

        # Get ingress rules
        ingress_rules = sg.get('IpPermissions', [])

        # Check each required rule
        for required_rule in requirements.get('required_ingress', []):
            required_port = required_rule.get('port')
            required_port_range = required_rule.get('port_range')
            required_protocol = required_rule.get('protocol')
            rule_description = required_rule.get('description')
            is_optional = required_rule.get('optional', False)

            rule_found = False
            matched_rule = None

            for rule in ingress_rules:
                rule_protocol = rule.get('IpProtocol', '')
                from_port = rule.get('FromPort')
                to_port = rule.get('ToPort')

                # Check if rule matches
                if required_port:
                    if (rule_protocol == required_protocol and
                        from_port == required_port and
                        to_port == required_port):
                        rule_found = True
                        matched_rule = rule
                        break
                elif required_port_range:
                    min_port, max_port = required_port_range
                    if (rule_protocol == required_protocol and
                        from_port == min_port and
                        to_port == max_port):
                        rule_found = True
                        matched_rule = rule
                        break

            if rule_found and matched_rule:
                # Extract source information
                sources = []

                # CIDR blocks
                for ip_range in matched_rule.get('IpRanges', []):
                    cidr = ip_range.get('CidrIp', '')
                    if cidr:
                        sources.append(cidr)

                # Security group references
                for sg_pair in matched_rule.get('UserIdGroupPairs', []):
                    sg_id = sg_pair.get('GroupId', '')
                    if sg_id:
                        sources.append(sg_id)

                # IPv6 ranges
                for ipv6_range in matched_rule.get('Ipv6Ranges', []):
                    cidr = ipv6_range.get('CidrIpv6', '')
                    if cidr:
                        sources.append(cidr)

                source_str = ", ".join(sources) if sources else "any"
                print_status("OK", f"Required rule present: {rule_description} ({required_protocol}/{required_port or required_port_range}) from {source_str}")

                # Validate access type matches cluster type for API/MCS ports on load balancer SGs
                if required_sg_name in [f"{infra_id}-lb", f"{infra_id}-apiserver-lb"]:
                    if required_port in [6443, 22623]:  # API and MCS ports
                        has_public_access = False
                        has_vpc_only_access = False

                        # Check CIDR blocks for access type
                        for ip_range in matched_rule.get('IpRanges', []):
                            cidr = ip_range.get('CidrIp', '')
                            if cidr == '0.0.0.0/0':
                                has_public_access = True
                            elif cidr.startswith('10.') or cidr.startswith('172.') or cidr.startswith('192.168.'):
                                has_vpc_only_access = True

                        # Validate based on cluster type
                        if not is_private_cluster and has_vpc_only_access and not has_public_access:
                            # Public cluster should have public access on API/MCS ports
                            if sg_id not in faulty_resource_ids:
                                faulty_resource_ids.append(sg_id)
                            issue_msg = f"{required_sg_name} ({sg_id}): Public cluster but {rule_description} only allows VPC traffic ({source_str}), should allow 0.0.0.0/0 or specific installer IP"
                            issues.append(issue_msg)
                            print_status("WARNING", f"Public cluster but rule only allows VPC traffic - may cause installation failures")
                            print(f"    Expected rule: {required_protocol}/{required_port} from 0.0.0.0/0 (or specific installer IP)")
                            add_markdown(f"- **Expected rule**: {required_protocol}/{required_port} from 0.0.0.0/0 (or specific installer IP)\n\n")

                        elif is_private_cluster and has_public_access:
                            # Private cluster should not have public access on API/MCS ports
                            if sg_id not in faulty_resource_ids:
                                faulty_resource_ids.append(sg_id)
                            issue_msg = f"{required_sg_name} ({sg_id}): Private cluster but {rule_description} allows public access (0.0.0.0/0)"
                            issues.append(issue_msg)
                            print_status("WARNING", f"Private cluster but rule allows public access - potential security risk")
            else:
                # Track faulty security group ID
                if sg_id not in faulty_resource_ids:
                    faulty_resource_ids.append(sg_id)

                if is_optional:
                    print_status("WARNING", f"Optional rule missing: {rule_description} ({required_protocol}/{required_port or required_port_range})")
                else:
                    # Show what the missing rule should be based on cluster type
                    expected_source = ""
                    if is_private_cluster:
                        expected_source = " (expected source: VPC CIDR or security group references)"
                    else:
                        if required_port in [6443, 22623]:  # API and MCS ports
                            expected_source = " (expected source: 0.0.0.0/0 for public access, or specific installer IP)"
                        else:
                            expected_source = " (expected source: security group references or VPC CIDR)"

                    issue_msg = f"{required_sg_name} ({sg_id}): Missing required rule for {rule_description} ({required_protocol}/{required_port or required_port_range}){expected_source}"
                    issues.append(issue_msg)
                    print_status("ERROR", f"Missing required rule: {rule_description}{expected_source}")

        # Check egress rules
        egress_rules = sg.get('IpPermissionsEgress', [])
        if not egress_rules:
            issues.append(f"Security Group {sg_id} ({required_sg_name}) has no egress rules")
            print_status("WARNING", f"No egress rules found")
        else:
            # Check for all-traffic egress (typical for OpenShift)
            has_all_egress = False
            for egress in egress_rules:
                if egress.get('IpProtocol') == '-1':
                    has_all_egress = True
                    break
            if has_all_egress:
                print_status("OK", "Egress: All traffic allowed")
            else:
                print_status("WARNING", f"Egress: {len(egress_rules)} rules (not all-traffic)")

        # Check for overly permissive public ingress rules
        for rule in ingress_rules:
            from_port = rule.get('FromPort', 'any')
            to_port = rule.get('ToPort', 'any')
            protocol = rule.get('IpProtocol', 'any')

            for ip_range in rule.get('IpRanges', []):
                cidr = ip_range.get('CidrIp', '')
                if cidr == '0.0.0.0/0':
                    # Public access to API server (6443) may be intentional
                    if from_port == 6443 and to_port == 6443:
                        print_status("WARNING", f"Public access allowed on port 6443 (API Server) - verify this is intentional")
                    else:
                        port_range = f"{from_port}-{to_port}" if from_port != to_port else str(from_port)
                        issues.append(f"{required_sg_name}: Public access (0.0.0.0/0) on port(s) {port_range}")
                        print_status("WARNING", f"Public access on port(s) {port_range}")

    # Detailed Security Group Analysis
    print(f"\n{Colors.BOLD}Detailed Security Group Analysis:{Colors.END}")

    # Analyze each security group in detail
    for sg_name, sg in cluster_sgs.items():
        if sg_name not in required_security_groups:
            continue

        sg_id = sg.get('GroupId', 'unknown')
        ingress_rules = sg.get('IpPermissions', [])

        print(f"\n{Colors.BOLD}{sg_name} ({sg_id}):{Colors.END}")

        # Categorize and display all ingress rules
        print(f"  {Colors.BOLD}Ingress Rules ({len(ingress_rules)} total):{Colors.END}")

        for rule in ingress_rules:
            protocol = rule.get('IpProtocol', 'unknown')
            from_port = rule.get('FromPort', 'N/A')
            to_port = rule.get('ToPort', 'N/A')

            # Format port range
            if from_port == to_port or from_port == 'N/A':
                port_str = str(from_port)
            else:
                port_str = f"{from_port}-{to_port}"

            # Get sources
            sources = []
            for ip_range in rule.get('IpRanges', []):
                cidr = ip_range.get('CidrIp', '')
                desc = ip_range.get('Description', '')
                if cidr:
                    sources.append(f"{cidr}" + (f" ({desc})" if desc else ""))

            for sg_pair in rule.get('UserIdGroupPairs', []):
                sg_id_ref = sg_pair.get('GroupId', '')
                desc = sg_pair.get('Description', '')
                if sg_id_ref:
                    sources.append(f"{sg_id_ref}" + (f" ({desc})" if desc else ""))

            source_str = ", ".join(sources) if sources else "any"

            # Display the rule
            if protocol in ['tcp', 'udp']:
                print(f"    • Port {port_str} ({protocol.upper()}) from {source_str}")
            elif protocol == 'icmp':
                print(f"    • ICMP from {source_str}")
            elif protocol == '50':
                print(f"    • ESP (Protocol 50) from {source_str}")
            elif protocol == '-1':
                print(f"    • All traffic from {source_str}")
            else:
                print(f"    • Protocol {protocol}, ports {port_str} from {source_str}")

    # Summary
    print(f"\n{Colors.BOLD}Security Group Summary:{Colors.END}")
    print(f"  Required Groups: {len(required_security_groups)}")
    print(f"  Found: {len(cluster_sgs)}")
    print(f"  Issues: {len(issues)}")

    # API Endpoint & Security Group Configuration Mismatch Analysis
    print(f"\n{Colors.BOLD}API Endpoint & Security Group Configuration Analysis:{Colors.END}")

    # Load API endpoint from route53 data
    api_data = load_json_file(f"{cluster_id}_route53_api_record_sets.json")
    if api_data and isinstance(api_data, list) and len(api_data) > 0:
        record = api_data[0]
        api_name = record.get('Name', 'unknown')
        if 'AliasTarget' in record:
            api_endpoint = record['AliasTarget'].get('DNSName', 'unknown')
            print(f"API Endpoint: {api_name} → {api_endpoint}")

    # Find the load balancer security group (controls API access)
    lb_sg = None
    for sg_name in [f"{infra_id}-lb", f"{infra_id}-apiserver-lb"]:
        if sg_name in cluster_sgs:
            lb_sg = cluster_sgs[sg_name]
            break

    if lb_sg:
        lb_sg_id = lb_sg.get('GroupId', 'unknown')
        lb_sg_name = lb_sg.get('GroupName', 'unknown')

        print(f"Analyzing Load Balancer Security Group: {lb_sg_name} ({lb_sg_id})")

        # Check API port (6443) ingress rules
        ingress_rules = lb_sg.get('IpPermissions', [])
        api_rule_found = False
        allows_public_access = False
        vpc_only_access = False
        allowed_cidrs = []

        for rule in ingress_rules:
            from_port = rule.get('FromPort')
            to_port = rule.get('ToPort')

            if from_port == 6443 and to_port == 6443:
                api_rule_found = True

                # Check CIDR blocks
                for ip_range in rule.get('IpRanges', []):
                    cidr = ip_range.get('CidrIp', '')
                    desc = ip_range.get('Description', '')
                    if cidr:
                        allowed_cidrs.append(cidr)
                        print(f"  Port 6443 allows: {cidr} ({desc})")

                        if cidr == '0.0.0.0/0':
                            allows_public_access = True
                        elif cidr.startswith('10.') or cidr.startswith('172.') or cidr.startswith('192.168.'):
                            vpc_only_access = True

        if api_rule_found:
            # Analyze configuration mismatch
            print(f"\n{Colors.BOLD}Configuration Mismatch Analysis:{Colors.END}")

            # Case 1: Public cluster (api.listening=external) with restrictive security groups
            if not is_private_cluster and vpc_only_access and not allows_public_access:
                print_status("ERROR", "CONFIGURATION MISMATCH DETECTED!")
                print(f"\n{Colors.RED}{Colors.BOLD}Critical Issue:{Colors.END}")
                print(f"  • Cluster Type: PUBLIC (API Listening: {api_listening})")
                print(f"  • API Listening: {api_listening} (configured for PUBLIC access)")
                print(f"  • Security Group: Only allows VPC internal traffic ({', '.join(allowed_cidrs)})")
                print(f"  • Impact: Installer cannot reach public API endpoint from outside VPC")

                print(f"\n{Colors.YELLOW}Root Cause:{Colors.END}")
                print("  This is a PRIVATE cluster security group configuration applied to a PUBLIC cluster.")
                print("  The cluster has public IPs but security groups block external access.")
                print("  This mismatch prevents external installers from reaching the API during bootstrap.")

                issues.append(f"Public cluster (api.listening={api_listening}) but security groups only allow VPC internal traffic")

                print(f"\n{Colors.BOLD}Remediation Options:{Colors.END}")
                print("\n  Option 1: Add Installer IP to Security Group (Quick Fix)")
                print("    # Get installer's public IP")
                print("    INSTALLER_IP=$(curl -s ifconfig.me)")
                print("    # Add rule to allow installer access to API")
                print(f"    aws ec2 authorize-security-group-ingress \\")
                print(f"      --group-id {lb_sg_id} \\")
                print(f"      --protocol tcp \\")
                print(f"      --port 6443 \\")
                print(f"      --cidr ${{INSTALLER_IP}}/32 \\")
                print(f"      --region {cluster_data.get('region', {}).get('id', 'us-east-1')}")

                print("\n  Option 2: Allow Public Access (If Intentional - Less Secure)")
                print(f"    aws ec2 authorize-security-group-ingress \\")
                print(f"      --group-id {lb_sg_id} \\")
                print(f"      --protocol tcp \\")
                print(f"      --port 6443 \\")
                print(f"      --cidr 0.0.0.0/0 \\")
                print(f"      --region {cluster_data.get('region', {}).get('id', 'us-east-1')}")

                print("\n  Option 3: Run Installer from Within VPC (Recommended)")
                print(f"    Deploy installer on EC2 instance within VPC ({allowed_cidrs[0] if allowed_cidrs else '10.0.0.0/16'})")

                print("\n  Option 4: Recreate Cluster with Correct Configuration")
                print("    Delete and recreate with either:")
                print("    - Private cluster: Use api.listening=internal")
                print("    - Public cluster: Ensure security groups allow public access from the start")

                # Add LB security group to faulty resources if not already there
                if lb_sg_id not in faulty_resource_ids:
                    faulty_resource_ids.append(lb_sg_id)

            # Case 2: Public cluster with unrestricted security group (0.0.0.0/0)
            elif not is_private_cluster and allows_public_access:
                print_status("WARNING", "Public cluster with unrestricted security group access")
                print(f"\n{Colors.YELLOW}Security Recommendation:{Colors.END}")
                print(f"  • Cluster Type: PUBLIC (API Listening: {api_listening})")
                print("  • Security Group: Allows 0.0.0.0/0 access on port 6443")
                print("  • Impact: API server is accessible from anywhere on the internet")
                print(f"\n{Colors.BOLD}Recommendations:{Colors.END}")
                print("  1. Consider restricting access to specific IP ranges")
                print("  2. Use api.listening=internal for production clusters")
                print("  3. Implement additional network security controls (WAF, VPN, etc.)")
                print(f"  4. Restrict access to known installer IPs:")
                print(f"     aws ec2 revoke-security-group-ingress --group-id {lb_sg_id} --protocol tcp --port 6443 --cidr 0.0.0.0/0")
                print(f"     aws ec2 authorize-security-group-ingress --group-id {lb_sg_id} --protocol tcp --port 6443 --cidr <YOUR_IP>/32")

                issues.append("Public cluster with unrestricted (0.0.0.0/0) API access - security risk")

            # Case 3: Private cluster with VPC-only access (correct)
            elif is_private_cluster and vpc_only_access and not allows_public_access:
                print_status("OK", "Private cluster with VPC-only security group rules (correct configuration)")
                print(f"  • Cluster Type: PRIVATE (API Listening: {api_listening})")
                print(f"  • Security Group: Restricted to VPC CIDR ({', '.join(allowed_cidrs)})")
                print("  • Configuration: Properly secured for private cluster")

            # Case 4: Private cluster with public access (unusual)
            elif is_private_cluster and allows_public_access:
                print_status("WARNING", "Private cluster configured with public security group access")
                print(f"\n{Colors.YELLOW}Unusual Configuration:{Colors.END}")
                print(f"  • Cluster Type: PRIVATE (API Listening: {api_listening})")
                print("  • Security Group: Allows 0.0.0.0/0 access")
                print("  • Note: This is unusual for a private cluster")
                print("  • Recommendation: Review if public access is intended")
                issues.append("Private cluster with public (0.0.0.0/0) security group access - unusual configuration")

            # Case 5: Consistent configuration
            else:
                if is_private_cluster:
                    print_status("OK", "Private cluster configuration appears consistent")
                else:
                    print_status("OK", "Public cluster configuration appears consistent")

    if not issues:
        print_status("OK", "All required security groups and rules are present")
        return ("OK", [])
    else:
        # Search CloudTrail for security group related events using specific resource IDs
        search_terms = [infra_id, 'SecurityGroup', 'AuthorizeSecurityGroupIngress',
                       'CreateSecurityGroup', 'RevokeSecurityGroupIngress',
                       'ModifySecurityGroupRules', 'InvalidGroup']

        # Add specific faulty security group IDs to search terms
        if faulty_resource_ids:
            print(f"\n{Colors.BOLD}Searching CloudTrail for events related to faulty security groups:{Colors.END}")
            print(f"  Security Group IDs: {', '.join(faulty_resource_ids)}")

        related_events = find_related_cloudtrail_events(cluster_id, infra_id, search_terms,
                                                        required_resource_ids=faulty_resource_ids if faulty_resource_ids else None,
                                                        max_results=10)
        print_cloudtrail_correlation(related_events, "Security Group Configuration", cluster_id, infra_id)

        return ("ERROR" if len(issues) > 3 else "WARNING", issues)

def check_instances(cluster_id: str, infra_id: str = None) -> Tuple[str, List[str]]:
    """
    Check EC2 instances health
    Args:
        cluster_id: The cluster ID used for file naming
        infra_id: The infrastructure ID (if None, will derive from cluster_id)
    Returns: (status, list of issues)
    """
    print_header("EC2 Instances Health Check")

    data = load_json_file(f"{cluster_id}_ec2_instances.json")
    if not data:
        return ("ERROR", ["Instances file not found or empty"])

    issues = []
    instances = []
    faulty_instance_ids = []  # Track instance IDs with issues

    # Handle nested array structure
    if isinstance(data, list):
        for item in data:
            if isinstance(item, list):
                instances.extend(item)
            else:
                instances.append(item)

    print(f"Total Instances: {len(instances)}")

    # Use infra_id for filtering
    if infra_id is None:
        infra_id = cluster_id.split('_')[0]

    # Count instances by state
    state_counts = {}
    cluster_instances = []

    for instance in instances:
        state = instance.get('State', 'unknown')
        state_counts[state] = state_counts.get(state, 0) + 1

        # Check if instance is part of the cluster
        tags = instance.get('Tags', [])
        for tag in tags:
            if infra_id in tag.get('Value', ''):
                cluster_instances.append(instance)
                break

    print(f"\nInstance States:")
    for state, count in sorted(state_counts.items()):
        print(f"  {state}: {count}")

    print(f"\nCluster-related Instances: {len(cluster_instances)}")

    # Check cluster instances
    for instance in cluster_instances:
        instance_id = instance.get('InstanceId', 'unknown')
        state = instance.get('State', 'unknown')
        launch_time = instance.get('LaunchTime', 'unknown')

        # Extract instance name and role from tags
        tags = instance.get('Tags', [])
        instance_name = 'N/A'
        node_role = 'unknown'

        for tag in tags:
            key = tag.get('Key', '')
            value = tag.get('Value', '')

            if key == 'Name':
                instance_name = value

            # Determine role from tags
            if 'bootstrap' in value.lower():
                node_role = 'bootstrap'
            elif 'master' in value.lower() or 'control-plane' in value.lower():
                if node_role == 'unknown':  # Don't override bootstrap
                    node_role = 'master'
            elif 'infra' in value.lower():
                if node_role == 'unknown':
                    node_role = 'infra'
            elif 'worker' in value.lower():
                if node_role == 'unknown':
                    node_role = 'worker'

        instance_info = f"{instance_id} ({instance_name}) [Role: {node_role}]"

        if state == 'stopped':
            faulty_instance_ids.append(instance_id)
            issues.append(f"Instance {instance_info} is stopped")
            print_status("WARNING", f"Instance {instance_info} is stopped")
        elif state == 'stopping':
            faulty_instance_ids.append(instance_id)
            issues.append(f"Instance {instance_info} is stopping")
            print_status("WARNING", f"Instance {instance_info} is stopping")
        elif state == 'terminated':
            faulty_instance_ids.append(instance_id)
            issues.append(f"Instance {instance_info} is terminated")
            print_status("ERROR", f"Instance {instance_info} is terminated")
        elif state == 'running':
            print_status("OK", f"Instance {instance_info} is running (launched: {launch_time})")

    if not cluster_instances:
        print_status("WARNING", f"No instances found for infra ID {infra_id}")
        return ("WARNING", ["No cluster instances found"])

    if issues:
        for issue in issues:
            print_status("WARNING", issue)

        # Search CloudTrail for instance-related events using specific instance IDs
        search_terms = [infra_id, 'RunInstances', 'TerminateInstances', 'StopInstances',
                       'StartInstances', 'InsufficientInstanceCapacity', 'InvalidParameterValue',
                       'Unsupported', 'InstanceLimitExceeded']

        # Add specific faulty instance IDs to search terms
        if faulty_instance_ids:
            print(f"\n{Colors.BOLD}Searching CloudTrail for events related to faulty instances:{Colors.END}")
            print(f"  Instance IDs: {', '.join(faulty_instance_ids)}")

        related_events = find_related_cloudtrail_events(cluster_id, infra_id, search_terms,
                                                        required_resource_ids=faulty_instance_ids if faulty_instance_ids else None,
                                                        max_results=10)
        print_cloudtrail_correlation(related_events, "EC2 Instance Issues", cluster_id, infra_id)

        return ("WARNING", issues)
    else:
        return ("OK", [])

def check_load_balancers(cluster_id: str, infra_id: str = None) -> Tuple[str, List[str]]:
    """
    Check load balancers health
    Args:
        cluster_id: The cluster ID used for file naming
        infra_id: The infrastructure ID (if None, will derive from cluster_id)
    Returns: (status, list of issues)
    """
    print_header("Load Balancers Health Check")

    data = load_json_file(f"{cluster_id}_LB_ALL.json")
    if not data:
        return ("ERROR", ["Load balancers file not found or empty"])

    issues = []
    load_balancers = data.get('LoadBalancers', [])
    faulty_lb_arns = []  # Track load balancer ARNs with issues

    print(f"Total Load Balancers: {len(load_balancers)}")

    # Use infra_id for filtering
    if infra_id is None:
        infra_id = cluster_id.split('_')[0]

    cluster_lbs = []
    for lb in load_balancers:
        lb_name = lb.get('LoadBalancerName', '')
        if infra_id in lb_name:
            cluster_lbs.append(lb)

    print(f"Cluster-related Load Balancers: {len(cluster_lbs)}")

    for lb in cluster_lbs:
        lb_arn = lb.get('LoadBalancerArn', 'unknown')
        lb_name = lb.get('LoadBalancerName', 'unknown')
        state = lb.get('State', {}).get('Code', 'unknown')
        lb_type = lb.get('Type', 'unknown')
        scheme = lb.get('Scheme', 'unknown')

        print(f"\nLoad Balancer: {lb_name}")
        print(f"  Type: {lb_type}")
        print(f"  Scheme: {scheme}")
        print(f"  State: {state}")

        if state == 'active':
            print_status("OK", f"Load balancer {lb_name} is active")
        elif state == 'provisioning':
            faulty_lb_arns.append(lb_arn)
            print_status("WARNING", f"Load balancer {lb_name} is provisioning")
            issues.append(f"Load balancer {lb_name} ({lb_arn}) is still provisioning")
        elif state == 'failed':
            faulty_lb_arns.append(lb_arn)
            print_status("ERROR", f"Load balancer {lb_name} is in failed state")
            issues.append(f"Load balancer {lb_name} ({lb_arn}) is in failed state")
        else:
            faulty_lb_arns.append(lb_arn)
            print_status("WARNING", f"Load balancer {lb_name} has unknown state: {state}")
            issues.append(f"Load balancer {lb_name} ({lb_arn}) has state: {state}")

    if not cluster_lbs:
        print_status("WARNING", f"No load balancers found for infra ID {infra_id}")
        return ("WARNING", ["No cluster load balancers found"])

    if issues:
        # Search CloudTrail for load balancer related events using specific ARNs
        search_terms = [infra_id, 'CreateLoadBalancer', 'ModifyLoadBalancer',
                       'DeleteLoadBalancer', 'RegisterTargets', 'DeregisterTargets',
                       'CreateTargetGroup', 'InvalidTarget', 'TargetNotFound']

        # Add specific faulty load balancer ARNs and names to search terms
        all_lb_identifiers = []
        if faulty_lb_arns:
            print(f"\n{Colors.BOLD}Searching CloudTrail for events related to faulty load balancers:{Colors.END}")
            # Extract LB names from ARNs for better readability
            lb_names = [arn.split('/')[-2] if '/' in arn else arn for arn in faulty_lb_arns]
            print(f"  Load Balancer ARNs: {', '.join(lb_names)}")
            all_lb_identifiers.extend(faulty_lb_arns)
            all_lb_identifiers.extend(lb_names)

        related_events = find_related_cloudtrail_events(cluster_id, infra_id, search_terms,
                                                        required_resource_ids=all_lb_identifiers if all_lb_identifiers else None,
                                                        max_results=10)
        print_cloudtrail_correlation(related_events, "Load Balancer Issues", cluster_id, infra_id)

        return ("WARNING", issues)
    else:
        return ("OK", [])

def check_route53(cluster_id: str) -> Tuple[str, List[str]]:
    """
    Check Route53 DNS records health
    Returns: (status, list of issues)
    """
    print_header("Route53 Health Check")

    issues = []

    # Check hosted zones
    zones_data = load_json_file(f"{cluster_id}_hosted_zones.json")
    print(f"Hosted Zones file loaded: {bool(zones_data)}")

    # Check API record sets
    api_data = load_json_file(f"{cluster_id}_route53_api_record_sets.json")
    if api_data:
        print(f"\nAPI Record Sets: {len(api_data) if isinstance(api_data, list) else 0}")
        if isinstance(api_data, list):
            for record in api_data:
                name = record.get('Name', 'unknown')
                rec_type = record.get('Type', 'unknown')

                if 'AliasTarget' in record:
                    target = record['AliasTarget'].get('DNSName', 'unknown')
                    print_status("OK", f"API DNS: {name} ({rec_type}) -> {target}")
                elif 'ResourceRecords' in record:
                    targets = [r.get('Value', '') for r in record.get('ResourceRecords', [])]
                    print_status("OK", f"API DNS: {name} ({rec_type}) -> {', '.join(targets)}")
    else:
        issues.append("No API record sets found")
        print_status("WARNING", "No API record sets found")

    # Check apps record sets
    apps_data = load_json_file(f"{cluster_id}_route53_apps_record_sets.json")
    if apps_data and isinstance(apps_data, list) and len(apps_data) > 0:
        print(f"\nApps Record Sets: {len(apps_data)}")
        for record in apps_data:
            name = record.get('Name', 'unknown')
            rec_type = record.get('Type', 'unknown')
            print_status("OK", f"Apps DNS: {name} ({rec_type})")
    else:
        issues.append("No apps record sets found (may be expected for failed installations)")
        print_status("WARNING", "No apps record sets found")

    if issues:
        return ("WARNING", issues)
    else:
        return ("OK", [])

def check_cloudtrail_logs(cluster_id: str, infra_id: str = None) -> Tuple[str, List[str]]:
    """
    Check CloudTrail logs for recent activity and errors
    Args:
        cluster_id: The cluster ID used for file naming
        infra_id: The infrastructure ID (if None, will derive from cluster_id)
    Returns: (status, list of issues)
    """
    print_header("CloudTrail Logs Health Check")

    data = load_json_file(f"{cluster_id}_cloudtrail.json")
    if not data:
        return ("ERROR", ["CloudTrail logs file not found or empty"])

    issues = []
    events = data if isinstance(data, list) else []

    print(f"Total CloudTrail Events: {len(events)}")

    if not events:
        return ("WARNING", ["No CloudTrail events found"])

    # Analyze events
    error_events = []
    warning_events = []
    delete_revoke_events = []
    event_sources = {}
    event_names = {}

    # Use infra_id for filtering
    if infra_id is None:
        infra_id = cluster_id.split('_')[0]

    # Define delete/revoke/stop/terminate event patterns to search for
    # These patterns match destructive operations similar to jq query:
    # jq '.[] | select(.EventName | contains("Delete") or contains("Revoke") or contains("Stop") or contains("Terminate") or ...) | .CloudTrailEvent | fromjson | .requestParameters'
    delete_revoke_patterns = [
        'Delete', 'Revoke', 'Stop', 'Terminate', 'Remove', 'Detach',
        'Disassociate', 'Deregister', 'Destroy', 'Release', 'Disable',
        'Cancel', 'Reject', 'Deny'
    ]

    for event in events:
        event_name = event.get('EventName', 'unknown')
        event_source = event.get('EventSource', 'unknown')
        read_only = event.get('ReadOnly', 'true')
        event_time = event.get('EventTime', '')
        username = event.get('Username', '')

        event_sources[event_source] = event_sources.get(event_source, 0) + 1
        event_names[event_name] = event_names.get(event_name, 0) + 1

        # Parse CloudTrailEvent JSON
        cloud_trail_event = event.get('CloudTrailEvent', '{}')
        try:
            ct_data = json.loads(cloud_trail_event)
            error_code = ct_data.get('errorCode', '')
            error_message = ct_data.get('errorMessage', '')
            event_str = json.dumps(ct_data)

            # Check for delete/revoke type events (matching EventName contains pattern)
            # This mimics: select(.EventName | contains("Delete") or contains("Revoke") or ...)
            is_delete_revoke = any(pattern.lower() in event_name.lower() for pattern in delete_revoke_patterns)

            if is_delete_revoke:
                request_params = ct_data.get('requestParameters', {})
                response_elements = ct_data.get('responseElements', {})
                event_id = ct_data.get('eventID', 'unknown')
                event_type = ct_data.get('eventType', 'unknown')
                aws_region = ct_data.get('awsRegion', 'unknown')
                source_ip = ct_data.get('sourceIPAddress', 'unknown')
                user_agent = ct_data.get('userAgent', 'unknown')

                # Check if cluster-related
                is_cluster_related = infra_id in event_str or cluster_id in event_str

                delete_revoke_events.append({
                    'name': event_name,
                    'source': event_source,
                    'time': event_time,
                    'username': username,
                    'error_code': error_code,
                    'error_message': error_message[:100] if error_message else '',
                    'request_params': request_params,
                    'response_elements': response_elements,
                    'event_id': event_id,
                    'event_type': event_type,
                    'aws_region': aws_region,
                    'source_ip': source_ip,
                    'user_agent': user_agent,
                    'full_cloudtrail_event': ct_data,
                    'is_cluster_related': is_cluster_related
                })

            if error_code:
                # Check if error is related to cluster
                if infra_id in event_str or cluster_id in event_str:
                    error_events.append({
                        'name': event_name,
                        'source': event_source,
                        'error_code': error_code,
                        'error_message': error_message[:100]
                    })
        except json.JSONDecodeError:
            pass

    print(f"\nTop Event Sources:")
    for source, count in sorted(event_sources.items(), key=lambda x: x[1], reverse=True)[:5]:
        print(f"  {source}: {count}")

    print(f"\nTop Event Names:")
    for name, count in sorted(event_names.items(), key=lambda x: x[1], reverse=True)[:5]:
        print(f"  {name}: {count}")

    # Display delete/revoke/stop/terminate events
    # This mimics the jq query:
    # jq '.[] | select(.EventName | contains("Delete") or contains("Revoke") or contains("Stop") or contains("Terminate") or ...) | .CloudTrailEvent | fromjson | .requestParameters'
    if delete_revoke_events:
        print(f"\n{Colors.BOLD}{Colors.YELLOW}{'=' * 80}{Colors.END}")
        print(f"{Colors.BOLD}{Colors.YELLOW}DELETE/REVOKE/STOP/TERMINATE EVENTS FOUND: {len(delete_revoke_events)}{Colors.END}")
        print(f"{Colors.BOLD}{Colors.YELLOW}(Equivalent to: jq '.[] | select(.EventName | contains(\"Delete\") or contains(\"Revoke\") or contains(\"Stop\") or contains(\"Terminate\") or ...) | .CloudTrailEvent | fromjson | .requestParameters'){Colors.END}")
        print(f"{Colors.BOLD}{Colors.YELLOW}{'=' * 80}{Colors.END}")

        # Separate cluster-related and non-cluster-related events
        cluster_related_events = [e for e in delete_revoke_events if e.get('is_cluster_related', False)]
        other_events = [e for e in delete_revoke_events if not e.get('is_cluster_related', False)]

        if cluster_related_events:
            print(f"\n{Colors.BOLD}{Colors.RED}CLUSTER-RELATED DELETE/REVOKE/STOP/TERMINATE EVENTS: {len(cluster_related_events)}{Colors.END}")
            print(f"{Colors.RED}{'─' * 80}{Colors.END}")

        # Build comprehensive list of cluster resources from local files
        print(f"\n{Colors.BOLD}{Colors.BLUE}Building cluster resource inventory from local files...{Colors.END}")
        cluster_resources = get_cluster_resource_ids(cluster_id, infra_id)
        print(f"  Security Groups: {len(cluster_resources['security_groups'])}")
        print(f"  Instances: {len(cluster_resources['instances'])}")
        print(f"  Load Balancers: {len(cluster_resources['load_balancers'])}")
        print(f"  VPCs: {len(cluster_resources['vpcs'])}")
        print(f"  Subnets: {len(cluster_resources['subnets'])}")
        print(f"  Total Unique Resource IDs: {len(cluster_resources['all_ids'])}")

        # Filter and display only cluster-impacting events
        cluster_impacting_events = []
        all_missing_commands = []
        event_counter = 0

        for event in delete_revoke_events:
            # Analyze event with local resource context
            impact_text, is_impacting, missing_cmds = analyze_event_impact_with_context(
                cluster_id, event['name'], event['request_params'],
                event['error_code'], infra_id, cluster_resources
            )

            if is_impacting:
                cluster_impacting_events.append({
                    **event,
                    'impact_analysis': impact_text,
                    'missing_commands': missing_cmds
                })
                all_missing_commands.extend(missing_cmds)

        # Only display events that actually impact the cluster
        if not cluster_impacting_events:
            print(f"\n{Colors.BOLD}{Colors.GREEN}No cluster-impacting delete/revoke/stop/terminate events found.{Colors.END}")
            print(f"{Colors.GREEN}All destructive operations were on non-cluster resources.{Colors.END}")
            add_markdown("\n### ✅ No Cluster-Impacting Events\n\n")
            add_markdown("All destructive operations were on non-cluster resources.\n\n")
        else:
            # Add markdown section header
            add_markdown("\n### 🔴 Cluster-Impacting Events\n\n")

            for i, event in enumerate(cluster_impacting_events, 1):
                event_counter += 1

                print(f"\n{Colors.BOLD}{Colors.RED}[{i}] EventName: {event['name']}{Colors.END}")
                print(f"{Colors.BOLD}    EventID:{Colors.END} {event.get('event_id', 'unknown')}")
                print(f"{Colors.BOLD}    EventTime:{Colors.END} {event['time']}")
                print(f"{Colors.BOLD}    User:{Colors.END} {event['username']}")
                print(f"{Colors.BOLD}    SourceIP:{Colors.END} {event.get('source_ip', 'unknown')}")
                print(f"{Colors.BOLD}    Region:{Colors.END} {event.get('aws_region', 'unknown')}")
                print(f"{Colors.BOLD}    {Colors.RED}CLUSTER-IMPACTING: YES{Colors.END}")

                # Add collapsible markdown for this event
                add_markdown(f"\n<details>\n<summary><strong>🔴 Event {i}: {event['name']}</strong> - {event['time']}</summary>\n\n")
                add_markdown(f"**Event Details:**\n\n")
                add_markdown(f"- **Event ID**: `{event.get('event_id', 'unknown')}`\n")
                add_markdown(f"- **Event Time**: {event['time']}\n")
                add_markdown(f"- **User**: {event['username']}\n")
                add_markdown(f"- **Source IP**: {event.get('source_ip', 'unknown')}\n")
                add_markdown(f"- **Region**: {event.get('aws_region', 'unknown')}\n")
                add_markdown(f"- **Cluster-Impacting**: ✅ YES\n\n")

                if event['error_code']:
                    print(f"{Colors.BOLD}    {Colors.RED}Status: FAILED{Colors.END}")
                    print(f"{Colors.BOLD}    ErrorCode:{Colors.END} {event['error_code']}")
                    if event['error_message']:
                        print(f"{Colors.BOLD}    ErrorMessage:{Colors.END} {event['error_message']}")
                    add_markdown(f"**Status**: 🔴 FAILED\n\n")
                    add_markdown(f"**Error Code**: `{event['error_code']}`\n\n")
                    if event['error_message']:
                        add_markdown(f"**Error Message**: {event['error_message']}\n\n")
                else:
                    print(f"{Colors.BOLD}    {Colors.GREEN}Status: SUCCESS{Colors.END}")
                    add_markdown(f"**Status**: 🟢 SUCCESS\n\n")

                # Display CloudTrailEvent.requestParameters JSON
                if event['request_params']:
                    print(f"\n{Colors.BOLD}{Colors.YELLOW}    CloudTrailEvent.requestParameters:{Colors.END}")
                    try:
                        request_json = json.dumps(event['request_params'], indent=2, default=str)
                        for line in request_json.split('\n'):
                            print(f"    {line}")

                        # Add to markdown
                        add_markdown(f"**CloudTrailEvent.requestParameters:**\n\n")
                        add_markdown(f"```json\n{request_json}\n```\n\n")
                    except (TypeError, ValueError) as e:
                        print(f"    {Colors.RED}Error formatting request parameters: {e}{Colors.END}")
                else:
                    print(f"\n{Colors.BOLD}{Colors.YELLOW}    CloudTrailEvent.requestParameters:{Colors.END}")
                    print(f"    {Colors.YELLOW}(empty or null){Colors.END}")
                    add_markdown(f"**CloudTrailEvent.requestParameters:** _(empty or null)_\n\n")

                # Display detailed impact analysis with cluster context
                if event['impact_analysis']:
                    print(f"\n{Colors.BOLD}{Colors.RED}    ⚠ CLUSTER IMPACT ANALYSIS:{Colors.END}")
                    for line in event['impact_analysis'].split('\n'):
                        line = line.strip()
                        if line:
                            print(f"      {line}")

                    # Add to markdown
                    add_markdown(f"**⚠️ CLUSTER IMPACT ANALYSIS:**\n\n")
                    for line in event['impact_analysis'].split('\n'):
                        line = line.strip()
                        if line:
                            add_markdown(f"- {line}\n")
                    add_markdown("\n")

                # Show missing data commands if needed
                if event['missing_commands']:
                    print(f"\n{Colors.BOLD}{Colors.YELLOW}    📋 Missing Data - Run these commands for more details:{Colors.END}")
                    for cmd in event['missing_commands']:
                        print(f"      {cmd}")

                    # Add to markdown
                    add_markdown(f"**📋 Missing Data Commands:**\n\n")
                    add_markdown(f"```bash\n")
                    for cmd in event['missing_commands']:
                        add_markdown(f"{cmd}\n")
                    add_markdown(f"```\n\n")

                # Close the collapsible section
                add_markdown(f"</details>\n\n")

                print(f"\n{Colors.BLUE}{'─' * 80}{Colors.END}")

            # Show aggregated missing commands at the end
            if all_missing_commands:
                print(f"\n{Colors.BOLD}{Colors.YELLOW}MISSING DATA SUMMARY:{Colors.END}")
                print(f"{Colors.YELLOW}The following AWS CLI commands can populate missing resource data:{Colors.END}\n")
                unique_commands = list(dict.fromkeys(all_missing_commands))  # Remove duplicates
                for cmd in unique_commands:
                    print(f"  {cmd}")

        # Summary
        print(f"\n{Colors.BOLD}Summary:{Colors.END}")
        print(f"  Total Delete/Revoke/Stop/Terminate Events Detected: {len(delete_revoke_events)}")
        print(f"  Cluster-Impacting Events (printed above): {len(cluster_impacting_events)}")
        print(f"  Non-Impacting Events (filtered out): {len(delete_revoke_events) - len(cluster_impacting_events)}")

        if cluster_impacting_events:
            issues.append(f"Found {len(cluster_impacting_events)} cluster-impacting delete/revoke/stop/terminate operations")
            print_status("WARNING", f"Found {len(cluster_impacting_events)} cluster-impacting operations that may have caused cluster failure/degradation")
        else:
            print_status("OK", "No cluster-impacting destructive operations detected")

    if error_events:
        print(f"\n{Colors.BOLD}Cluster-related Errors Found: {len(error_events)}{Colors.END}")
        for i, error in enumerate(error_events[:10], 1):
            print(f"\n  Error {i}:")
            print(f"    Event: {error['name']}")
            print(f"    Source: {error['source']}")
            print(f"    Error Code: {error['error_code']}")
            print(f"    Message: {error['error_message']}")
        issues.append(f"Found {len(error_events)} error events")

    if error_events or delete_revoke_events:
        return ("WARNING", issues)
    else:
        print_status("OK", "No significant errors or destructive operations found in CloudTrail logs")
        return ("OK", [])

def check_vpc_dns_attributes(cluster_id: str, infra_id: str = None) -> Tuple[str, List[str]]:
    """
    Check VPC DNS attributes (enableDnsHostnames and enableDnsSupport)
    Args:
        cluster_id: The cluster ID used for file naming
        infra_id: The infrastructure ID (if None, will derive from cluster_id)
    Returns: (status, list of issues)
    """
    print_header("VPC DNS Attributes Health Check")

    issues = []
    missing_data_commands = []

    # Use infra_id for filtering
    if infra_id is None:
        infra_id = cluster_id.split('_')[0]

    # Find VPC files
    global source_directory
    vpc_files = list(source_directory.glob(f"{cluster_id}_vpc-*_VPC.json"))

    if not vpc_files:
        print_status("WARNING", "No VPC files found")
        missing_data_commands.append(f"# Get VPC IDs for cluster:")
        missing_data_commands.append(f"aws ec2 describe-vpcs --filters \"Name=tag:Name,Values=*{infra_id}*\" > {cluster_id}_vpcs.json")
        missing_data_commands.append(f"# Then for each VPC ID, get attributes:")
        missing_data_commands.append(f"aws ec2 describe-vpc-attribute --vpc-id <VPC_ID> --attribute enableDnsHostnames > {cluster_id}_<VPC_ID>_VPC_attrDnsHost.json")
        missing_data_commands.append(f"aws ec2 describe-vpc-attribute --vpc-id <VPC_ID> --attribute enableDnsSupport > {cluster_id}_<VPC_ID>_VPC_attrDnsSupp.json")

        print(f"\n{Colors.BOLD}{Colors.YELLOW}Missing Data - Run these commands:{Colors.END}")
        for cmd in missing_data_commands:
            print(f"  {cmd}")

        return ("WARNING", ["VPC files not found - cannot validate DNS attributes"])

    # Check each VPC
    vpcs_checked = 0
    for vpc_file in vpc_files:
        # Extract VPC ID from filename
        import re
        vpc_match = re.search(r'(vpc-[a-f0-9]{17})', str(vpc_file.name))
        if not vpc_match:
            continue

        vpc_id = vpc_match.group(1)
        vpcs_checked += 1

        print(f"\n{Colors.BOLD}Checking VPC: {vpc_id}{Colors.END}")

        # Load VPC data (pass just filename, load_json_file adds source_directory)
        vpc_data = load_json_file(vpc_file.name)
        if not vpc_data or 'Vpcs' not in vpc_data or len(vpc_data['Vpcs']) == 0:
            issues.append(f"VPC {vpc_id}: Failed to load VPC data")
            continue

        vpc_info = vpc_data['Vpcs'][0]
        vpc_name = 'unknown'
        for tag in vpc_info.get('Tags', []):
            if tag.get('Key') == 'Name':
                vpc_name = tag.get('Value', 'unknown')
                break

        print(f"  VPC Name: {vpc_name}")

        # Check DNS Hostnames attribute
        dns_host_file = f"{cluster_id}_{vpc_id}_VPC_attrDnsHost.json"
        dns_host_data = load_json_file(dns_host_file)

        if dns_host_data and 'EnableDnsHostnames' in dns_host_data:
            dns_hostnames_enabled = dns_host_data['EnableDnsHostnames'].get('Value', False)
            if dns_hostnames_enabled:
                print_status("OK", f"enableDnsHostnames is enabled for {vpc_id}")
            else:
                issues.append(f"VPC {vpc_id} ({vpc_name}): enableDnsHostnames is disabled - required for private Route53 zones")
                print_status("ERROR", f"enableDnsHostnames is DISABLED for {vpc_id}")
                print(f"    {Colors.YELLOW}Impact: Private DNS resolution will not work{Colors.END}")
                print(f"    {Colors.YELLOW}Fix: aws ec2 modify-vpc-attribute --vpc-id {vpc_id} --enable-dns-hostnames{Colors.END}")
        else:
            issues.append(f"VPC {vpc_id}: Missing enableDnsHostnames data")
            missing_data_commands.append(f"aws ec2 describe-vpc-attribute --vpc-id {vpc_id} --attribute enableDnsHostnames > {dns_host_file}")

        # Check DNS Support attribute
        dns_supp_file = f"{cluster_id}_{vpc_id}_VPC_attrDnsSupp.json"
        dns_supp_data = load_json_file(dns_supp_file)

        if dns_supp_data and 'EnableDnsSupport' in dns_supp_data:
            dns_support_enabled = dns_supp_data['EnableDnsSupport'].get('Value', False)
            if dns_support_enabled:
                print_status("OK", f"enableDnsSupport is enabled for {vpc_id}")
            else:
                issues.append(f"VPC {vpc_id} ({vpc_name}): enableDnsSupport is disabled - required for DNS resolution")
                print_status("ERROR", f"enableDnsSupport is DISABLED for {vpc_id}")
                print(f"    {Colors.YELLOW}Impact: DNS queries will not be resolved within VPC{Colors.END}")
                print(f"    {Colors.YELLOW}Fix: aws ec2 modify-vpc-attribute --vpc-id {vpc_id} --enable-dns-support{Colors.END}")
        else:
            issues.append(f"VPC {vpc_id}: Missing enableDnsSupport data")
            missing_data_commands.append(f"aws ec2 describe-vpc-attribute --vpc-id {vpc_id} --attribute enableDnsSupport > {dns_supp_file}")

    print(f"\nVPCs Checked: {vpcs_checked}")

    if missing_data_commands:
        print(f"\n{Colors.BOLD}{Colors.YELLOW}Missing Data - Run these commands:{Colors.END}")
        for cmd in missing_data_commands:
            print(f"  {cmd}")

    if not issues:
        print_status("OK", "All VPC DNS attributes are correctly configured")
        return ("OK", [])
    else:
        return ("ERROR" if any("DISABLED" in issue for issue in issues) else "WARNING", issues)

def check_dhcp_options(cluster_id: str, infra_id: str = None) -> Tuple[str, List[str]]:
    """
    Check DHCP Options Sets for Kubernetes/OpenShift compatibility
    Args:
        cluster_id: The cluster ID used for file naming
        infra_id: The infrastructure ID (if None, will derive from cluster_id)
    Returns: (status, list of issues)
    """
    print_header("DHCP Options Health Check")

    issues = []
    missing_data_commands = []

    # Use infra_id for filtering
    if infra_id is None:
        infra_id = cluster_id.split('_')[0]

    # Find VPC files to get DHCP Options Set IDs
    global source_directory
    vpc_files = list(source_directory.glob(f"{cluster_id}_vpc-*_VPC.json"))

    if not vpc_files:
        print_status("WARNING", "No VPC files found")
        missing_data_commands.append(f"# Get VPC IDs and DHCP Options Set IDs:")
        missing_data_commands.append(f"aws ec2 describe-vpcs --filters \"Name=tag:Name,Values=*{infra_id}*\" > {cluster_id}_vpcs.json")

        print(f"\n{Colors.BOLD}{Colors.YELLOW}Missing Data - Run these commands:{Colors.END}")
        for cmd in missing_data_commands:
            print(f"  {cmd}")

        return ("WARNING", ["VPC files not found - cannot check DHCP Options"])

    dhcp_checked = 0
    for vpc_file in vpc_files:
        # Pass just filename, load_json_file adds source_directory
        vpc_data = load_json_file(vpc_file.name)
        if not vpc_data or 'Vpcs' not in vpc_data or len(vpc_data['Vpcs']) == 0:
            continue

        vpc_info = vpc_data['Vpcs'][0]
        vpc_id = vpc_info.get('VpcId', 'unknown')
        dhcp_options_id = vpc_info.get('DhcpOptionsId', 'unknown')

        print(f"\n{Colors.BOLD}Checking VPC: {vpc_id}{Colors.END}")
        print(f"  DHCP Options Set ID: {dhcp_options_id}")

        # Check if DHCP Options file exists
        dhcp_file = f"{cluster_id}_dhcp_{dhcp_options_id}.json"
        dhcp_data = load_json_file(dhcp_file)

        if not dhcp_data or 'DhcpOptions' not in dhcp_data:
            print_status("WARNING", f"DHCP Options data not found for {dhcp_options_id}")
            missing_data_commands.append(f"aws ec2 describe-dhcp-options --dhcp-options-ids {dhcp_options_id} > {dhcp_file}")
            continue

        dhcp_checked += 1

        # Get DHCP configurations
        if len(dhcp_data['DhcpOptions']) == 0:
            issues.append(f"DHCP Options Set {dhcp_options_id}: No configurations found")
            continue

        dhcp_configs = dhcp_data['DhcpOptions'][0].get('DhcpConfigurations', [])

        # Check domain-name configuration
        domain_name_found = False
        for config in dhcp_configs:
            if config.get('Key') == 'domain-name':
                domain_name_found = True
                values = config.get('Values', [])

                for value_obj in values:
                    domain_name = value_obj.get('Value', '')
                    print(f"  Domain Name: {domain_name}")

                    # Check for uppercase letters (Kubernetes DNS incompatible)
                    if domain_name != domain_name.lower():
                        issues.append(f"DHCP Options {dhcp_options_id}: domain-name '{domain_name}' contains uppercase letters - Kubernetes DNS incompatible")
                        print_status("ERROR", f"Domain name contains UPPERCASE letters")
                        print(f"    {Colors.YELLOW}Impact: Kubernetes DNS will fail to resolve{Colors.END}")
                        print(f"    {Colors.YELLOW}Reference: https://kubernetes.io/docs/concepts/overview/working-with-objects/names/#dns-subdomain-names{Colors.END}")
                    else:
                        print_status("OK", "Domain name is all lowercase")

                    # Check for spaces (CoreOS bug #1934)
                    if ' ' in domain_name:
                        issues.append(f"DHCP Options {dhcp_options_id}: domain-name '{domain_name}' contains spaces - CoreOS bug #1934")
                        print_status("ERROR", f"Domain name contains SPACES")
                        print(f"    {Colors.YELLOW}Impact: CoreOS networking issues{Colors.END}")
                        print(f"    {Colors.YELLOW}Reference: https://github.com/coreos/bugs/issues/1934{Colors.END}")
                    else:
                        print_status("OK", "Domain name contains no spaces")

        if not domain_name_found:
            print_status("OK", "No custom domain-name configured (using AWS default)")

    print(f"\nDHCP Options Sets Checked: {dhcp_checked}")

    if missing_data_commands:
        print(f"\n{Colors.BOLD}{Colors.YELLOW}Missing Data - Run these commands:{Colors.END}")
        for cmd in missing_data_commands:
            print(f"  {cmd}")

    if not issues:
        print_status("OK", "All DHCP Options are compatible with Kubernetes/OpenShift")
        return ("OK", [])
    else:
        return ("ERROR", issues)

def check_vpc_endpoint_service(cluster_id: str, infra_id: str = None) -> Tuple[str, List[str]]:
    """
    Check VPC Endpoint Service for PrivateLink clusters
    Args:
        cluster_id: The cluster ID used for file naming
        infra_id: The infrastructure ID (if None, will derive from cluster_id)
    Returns: (status, list of issues)
    """
    print_header("VPC Endpoint Service Health Check (PrivateLink)")

    issues = []
    missing_data_commands = []

    # Use infra_id for filtering
    if infra_id is None:
        infra_id = cluster_id.split('_')[0]

    # Check if cluster is PrivateLink
    cluster_data = load_json_file(f"{cluster_id}_cluster.json")
    is_privatelink = False
    if cluster_data:
        is_privatelink = cluster_data.get('aws', {}).get('private_link', False)

    if not is_privatelink:
        print_status("OK", "Cluster is not PrivateLink - VPC Endpoint Service not required")
        return ("OK", [])

    print(f"{Colors.BOLD}Cluster Type: PrivateLink{Colors.END}")
    print("VPC Endpoint Service is required for Hive/backplane management\n")

    # Check VPC Endpoint Service file
    vpce_svc_file = f"{cluster_id}_vpc_endpoint_service.json"
    vpce_svc_data = load_json_file(vpce_svc_file)

    if not vpce_svc_data or 'ServiceConfigurations' not in vpce_svc_data:
        print_status("WARNING", "VPC Endpoint Service data not found")
        missing_data_commands.append(f"# Get VPC Endpoint Service for PrivateLink cluster:")
        missing_data_commands.append(f"aws ec2 describe-vpc-endpoint-service-configurations \\")
        missing_data_commands.append(f"  --filters \\")
        missing_data_commands.append(f"    \"Name=tag:Name,Values={infra_id}-vpc-endpoint-service\" \\")
        missing_data_commands.append(f"    \"Name=tag:hive.openshift.io/private-link-access-for,Values={infra_id}\" \\")
        missing_data_commands.append(f"  > {vpce_svc_file}")

        print(f"\n{Colors.BOLD}{Colors.YELLOW}Missing Data - Run these commands:{Colors.END}")
        for cmd in missing_data_commands:
            print(f"  {cmd}")

        return ("WARNING", ["VPC Endpoint Service data not found"])

    # Check service count
    service_configs = vpce_svc_data.get('ServiceConfigurations', [])
    service_count = len(service_configs)

    print(f"VPC Endpoint Services Found: {service_count}")

    if service_count == 0:
        issues.append("No VPC Endpoint Service found for PrivateLink cluster")
        print_status("ERROR", "No VPC Endpoint Service found")
        print(f"  {Colors.YELLOW}Impact: Hive cannot manage cluster via PrivateLink{Colors.END}")
        print(f"  {Colors.YELLOW}Consequence: SyncSets and backplane access unavailable{Colors.END}")
        return ("ERROR", issues)
    elif service_count > 1:
        issues.append(f"Multiple VPC Endpoint Services found ({service_count}) - expected 1")
        print_status("WARNING", f"Multiple VPC Endpoint Services found: {service_count}")
    else:
        print_status("OK", "Found 1 VPC Endpoint Service")

    # Check first service
    service = service_configs[0]
    service_id = service.get('ServiceId', 'unknown')
    service_name = service.get('ServiceName', 'unknown')
    service_state = service.get('ServiceState', 'unknown')

    print(f"\n{Colors.BOLD}VPC Endpoint Service Details:{Colors.END}")
    print(f"  Service ID: {service_id}")
    print(f"  Service Name: {service_name}")
    print(f"  Service State: {service_state}")

    if service_state != 'Available':
        issues.append(f"VPC Endpoint Service {service_id} is in state '{service_state}' - expected 'Available'")
        print_status("ERROR", f"Service state is '{service_state}' (expected 'Available')")
    else:
        print_status("OK", "Service state is Available")

    # Check VPC Endpoint Connections
    vpce_conn_file = f"{cluster_id}_vpc_endpoint_connections.json"
    vpce_conn_data = load_json_file(vpce_conn_file)

    if not vpce_conn_data or 'VpcEndpointConnections' not in vpce_conn_data:
        print_status("WARNING", "VPC Endpoint Connections data not found")
        missing_data_commands.append(f"# Get VPC Endpoint Connections:")
        missing_data_commands.append(f"aws ec2 describe-vpc-endpoint-connections \\")
        missing_data_commands.append(f"  --filters \\")
        missing_data_commands.append(f"    \"Name=service-id,Values={service_id}\" \\")
        missing_data_commands.append(f"    \"Name=vpc-endpoint-state,Values=available\" \\")
        missing_data_commands.append(f"  > {vpce_conn_file}")
    else:
        connections = vpce_conn_data.get('VpcEndpointConnections', [])
        conn_count = len(connections)

        print(f"\n{Colors.BOLD}VPC Endpoint Connections:{Colors.END}")
        print(f"  Available Connections: {conn_count}")

        if conn_count == 0:
            issues.append(f"No available VPC Endpoint connections for service {service_id}")
            print_status("ERROR", "No available VPC Endpoint connections")
            print(f"  {Colors.YELLOW}Impact: Hive cannot connect to cluster{Colors.END}")
        elif conn_count > 1:
            issues.append(f"Multiple VPC Endpoint connections ({conn_count}) - expected 1")
            print_status("WARNING", f"Multiple connections found: {conn_count}")
        else:
            conn = connections[0]
            vpc_endpoint_id = conn.get('VpcEndpointId', 'unknown')
            vpc_endpoint_state = conn.get('VpcEndpointState', 'unknown')
            print_status("OK", f"Found 1 available connection: {vpc_endpoint_id} (state: {vpc_endpoint_state})")

    if missing_data_commands:
        print(f"\n{Colors.BOLD}{Colors.YELLOW}Missing Data - Run these commands:{Colors.END}")
        for cmd in missing_data_commands:
            print(f"  {cmd}")

    if not issues:
        print_status("OK", "VPC Endpoint Service is correctly configured")
        return ("OK", [])
    else:
        return ("ERROR" if any("No VPC Endpoint" in issue or "not Available" in issue for issue in issues) else "WARNING", issues)

def check_installation_status(cluster_id: str, infra_id: str = None) -> Tuple[str, List[str]]:
    """
    Check cluster installation status and identify failure reasons
    Args:
        cluster_id: The cluster ID used for file naming
        infra_id: The infrastructure ID (if None, will derive from cluster_id)
    Returns: (status, list of issues)
    """
    print_header("Installation Status Check")

    issues = []
    provision_failed = None

    # Check cluster.json for state
    cluster_data = load_json_file(f"{cluster_id}_cluster.json")
    if cluster_data:
        state = cluster_data.get('state', 'unknown')
        print(f"Cluster State: {state}")

        if state == 'error':
            print_status("ERROR", "Cluster is in ERROR state")
            issues.append("Cluster installation failed")
        elif state == 'ready':
            print_status("OK", "Cluster is READY")
            return ("OK", [])
        elif state == 'installing':
            print_status("WARNING", "Cluster is still INSTALLING")
            return ("WARNING", ["Installation in progress"])

    # Check resources.json for detailed failure info
    resources_data = load_json_file(f"{cluster_id}_resources.json")
    if not resources_data:
        return ("WARNING", ["Could not load resources.json"])

    # Parse cluster_deployment for detailed conditions
    cluster_deployment_str = resources_data.get('resources', {}).get('cluster_deployment', '')
    if cluster_deployment_str:
        try:
            cd_parsed = json.loads(cluster_deployment_str)
            if 'String' in cd_parsed:
                cd_data = json.loads(cd_parsed['String'])

                conditions = cd_data.get('status', {}).get('conditions', [])

                print(f"\n{Colors.BOLD}Installation Failure Analysis:{Colors.END}")

                # Key failure conditions
                provision_failed = None
                provision_stopped = None

                for condition in conditions:
                    ctype = condition.get('type')
                    status = condition.get('status')

                    if ctype == 'ProvisionFailed' and status == 'True':
                        provision_failed = condition
                    elif ctype == 'ProvisionStopped' and status == 'True':
                        provision_stopped = condition

                if provision_failed:
                    reason = provision_failed.get('reason', 'Unknown')
                    message = provision_failed.get('message', 'No message')
                    print_status("ERROR", f"Provision Failed: {reason}")
                    print(f"  Message: {message}")
                    issues.append(f"ProvisionFailed: {reason} - {message}")

                    # Specific failure analysis
                    if reason == 'KubeAPIWaitFailed':
                        print(f"\n{Colors.YELLOW}Root Cause Analysis:{Colors.END}")
                        print("  - The Kubernetes API server failed to become available")
                        print("  - This typically indicates bootstrap host problems")
                        print("  - Common causes:")
                        print("    • Bootstrap instance failed to start properly")
                        print("    • Network connectivity issues to bootstrap instance")
                        print("    • Bootstrap instance unable to download required images")
                        print("    • Security group blocking required ports")
                        print("    • IAM permissions insufficient for bootstrap operations")

                if provision_stopped:
                    reason = provision_stopped.get('reason', 'Unknown')
                    print_status("ERROR", f"Provision Stopped: {reason}")
                    issues.append(f"ProvisionStopped: {reason}")

                # Check install restart count
                install_restarts = cd_data.get('status', {}).get('installRestarts', 0)
                if install_restarts > 0:
                    print_status("WARNING", f"Installation restarted {install_restarts} times")
                    issues.append(f"Installation restarted {install_restarts} times")

        except (json.JSONDecodeError, KeyError) as e:
            print_status("WARNING", f"Could not parse cluster deployment data: {e}")

    # Check for bootstrap instance
    instances_data = load_json_file(f"{cluster_id}_ec2_instances.json")
    bootstrap_found = False
    bootstrap_instance_id = None
    if instances_data:
        instances = []
        if isinstance(instances_data, list):
            for item in instances_data:
                if isinstance(item, list):
                    instances.extend(item)
                else:
                    instances.append(item)

        for instance in instances:
            tags = instance.get('Tags', [])
            instance_name = 'N/A'

            # Get instance name
            for tag in tags:
                if tag.get('Key') == 'Name':
                    instance_name = tag.get('Value', 'N/A')
                    break

            # Check if bootstrap
            for tag in tags:
                if 'bootstrap' in tag.get('Value', '').lower():
                    bootstrap_found = True
                    instance_id = instance.get('InstanceId')
                    bootstrap_instance_id = instance_id
                    state = instance.get('State')
                    launch_time = instance.get('LaunchTime', 'unknown')

                    print(f"\n{Colors.BOLD}Bootstrap Instance Found:{Colors.END}")
                    print(f"  Instance ID: {instance_id}")
                    print(f"  Name: {instance_name}")
                    print(f"  Role: bootstrap")
                    print(f"  State: {state}")
                    print(f"  Launch Time: {launch_time}")

                    if state != 'running':
                        issues.append(f"Bootstrap instance {instance_id} ({instance_name}) is {state}, expected running")
                        print_status("ERROR", f"Bootstrap instance is {state}")
                    else:
                        print_status("OK", f"Bootstrap instance is running")
                    break

    if not bootstrap_found:
        print_status("WARNING", "No bootstrap instance found (may have been terminated)")

    # If errors were detected, search CloudTrail for related events
    if issues:
        # Use infra_id for filtering
        if infra_id is None:
            infra_id = cluster_id.split('_')[0]

        # Search terms based on detected issues
        search_terms = [infra_id, 'bootstrap', 'RunInstances', 'AuthorizationError',
                       'UnauthorizedOperation', 'InvalidParameter', 'SecurityGroup',
                       'VPC', 'Subnet', 'NetworkInterface']

        # Add bootstrap instance ID if found
        bootstrap_resource_ids = []
        if bootstrap_instance_id:
            print(f"\n{Colors.BOLD}Searching CloudTrail for events related to bootstrap instance:{Colors.END}")
            print(f"  Bootstrap Instance ID: {bootstrap_instance_id}")
            bootstrap_resource_ids.append(bootstrap_instance_id)

        # Add specific search terms based on failure reason
        if provision_failed:
            reason = provision_failed.get('reason', '')
            if 'KubeAPI' in reason:
                search_terms.extend(['6443', 'apiserver', 'loadbalancer', 'TargetGroup'])
            elif 'Network' in reason:
                search_terms.extend(['RouteTable', 'InternetGateway', 'NatGateway'])

        related_events = find_related_cloudtrail_events(cluster_id, infra_id, search_terms,
                                                        required_resource_ids=bootstrap_resource_ids if bootstrap_resource_ids else None,
                                                        max_results=10)
        print_cloudtrail_correlation(related_events, "Installation Failure", cluster_id, infra_id)

        return ("ERROR", issues)
    else:
        return ("OK", [])

def check_cluster_context(cluster_id: str, infra_id: str = None) -> Tuple[str, List[str]]:
    """
    Check cluster context data from osdctl cluster context output
    Args:
        cluster_id: The cluster ID used for file naming
        infra_id: The infrastructure ID (if None, will derive from cluster_id)
    Returns: (status, list of issues)
    """
    print_header("Cluster Context Check")

    issues = []

    # Load cluster_context.json
    context_file = f"{cluster_id}_cluster_context.json"
    context_data = load_json_file(context_file)

    if not context_data:
        print_status("WARNING", f"Cluster context file not found: {context_file}")
        add_markdown(f"⚠️ **Cluster context file not found**: `{context_file}`\n\n")
        add_markdown("To generate this file, run:\n```bash\n")
        add_markdown(f"osdctl cluster context -C {cluster_id} -o json > {context_file}\n```\n\n")
        return ("WARNING", ["Cluster context file not found"])

    # Extract and display key information
    cluster_name = context_data.get('ClusterName', 'unknown')
    cluster_version = context_data.get('ClusterVersion', 'unknown')
    ocm_env = context_data.get('OCMEnv', 'unknown')
    region_id = context_data.get('RegionID', 'unknown')

    print(f"Cluster Name: {cluster_name}")
    print(f"Cluster Version: {cluster_version}")
    print(f"OCM Environment: {ocm_env}")
    print(f"Region ID: {region_id or 'Not specified'}")

    add_markdown(f"**Cluster Name**: {cluster_name}\n\n")
    add_markdown(f"**Cluster Version**: {cluster_version}\n\n")
    add_markdown(f"**OCM Environment**: {ocm_env}\n\n")
    add_markdown(f"**Region ID**: {region_id or 'Not specified'}\n\n")

    # Network Configuration
    network_type = context_data.get('NetworkType', 'unknown')
    network_machine_cidr = context_data.get('NetworkMachineCIDR', 'unknown')
    network_service_cidr = context_data.get('NetworkServiceCIDR', 'unknown')
    network_pod_cidr = context_data.get('NetworkPodCIDR', 'unknown')
    network_host_prefix = context_data.get('NetworkHostPrefix', 0)
    max_nodes = context_data.get('NetworkMaxNodesFromPodCIDR', 0)
    max_pods_per_node = context_data.get('NetworkMaxPodsPerNode', 0)
    max_services = context_data.get('NetworkMaxServices', 0)

    print(f"\n{Colors.BOLD}Network Configuration:{Colors.END}")
    print(f"  Network Type: {network_type}")
    print(f"  Machine CIDR: {network_machine_cidr}")
    print(f"  Service CIDR: {network_service_cidr}")
    print(f"  Pod CIDR: {network_pod_cidr}")
    print(f"  Host Prefix: {network_host_prefix}")
    print(f"  Max Nodes (from Pod CIDR): {max_nodes}")
    print(f"  Max Pods per Node: {max_pods_per_node}")
    print(f"  Max Services: {max_services}")

    add_markdown(f"\n### Network Configuration\n\n")
    add_markdown(f"| Parameter | Value |\n")
    add_markdown(f"|-----------|-------|\n")
    add_markdown(f"| Network Type | `{network_type}` |\n")
    add_markdown(f"| Machine CIDR | `{network_machine_cidr}` |\n")
    add_markdown(f"| Service CIDR | `{network_service_cidr}` |\n")
    add_markdown(f"| Pod CIDR | `{network_pod_cidr}` |\n")
    add_markdown(f"| Host Prefix | `{network_host_prefix}` |\n")
    add_markdown(f"| Max Nodes (from Pod CIDR) | `{max_nodes}` |\n")
    add_markdown(f"| Max Pods per Node | `{max_pods_per_node}` |\n")
    add_markdown(f"| Max Services | `{max_services}` |\n\n")

    # Validate network configuration
    if network_type == 'unknown':
        issues.append("Network type is unknown")
        print_status("WARNING", "Network type is unknown")
    else:
        print_status("OK", f"Network type is {network_type}")

    # Jira Issues
    jira_issues = context_data.get('JiraIssues', [])
    print(f"\n{Colors.BOLD}Jira Issues:{Colors.END}")
    print(f"  Total Issues: {len(jira_issues)}")

    add_markdown(f"\n### Jira Issues\n\n")
    add_markdown(f"**Total Issues**: {len(jira_issues)}\n\n")

    if jira_issues:
        for issue in jira_issues:
            issue_key = issue.get('key', 'unknown')
            issue_fields = issue.get('fields', {})
            summary = issue_fields.get('summary', 'No summary')
            status_obj = issue_fields.get('status', {})
            status = status_obj.get('name', 'unknown')
            priority_obj = issue_fields.get('priority', {})
            priority = priority_obj.get('name', 'unknown')
            created = issue_fields.get('created', 'unknown')

            print(f"\n  Issue: {issue_key}")
            print(f"    Summary: {summary}")
            print(f"    Status: {status}")
            print(f"    Priority: {priority}")
            print(f"    Created: {created}")

            # Add to markdown with collapsible details
            add_markdown(f"\n<details>\n")
            add_markdown(f"<summary><strong>📋 {issue_key}</strong> - {summary[:80]}{'...' if len(summary) > 80 else ''}</summary>\n\n")
            add_markdown(f"- **Summary**: {summary}\n")
            add_markdown(f"- **Status**: {status}\n")
            add_markdown(f"- **Priority**: {priority}\n")
            add_markdown(f"- **Created**: {created}\n")
            add_markdown(f"- **Link**: [View in Jira](https://issues.redhat.com/browse/{issue_key})\n\n")

            # Include description if available
            description = issue_fields.get('description', '')
            if description:
                # Truncate long descriptions
                desc_preview = description[:500] + ('...' if len(description) > 500 else '')
                add_markdown(f"**Description**:\n```\n{desc_preview}\n```\n\n")

            add_markdown(f"</details>\n\n")

            # Check if issue indicates cluster problems
            if status.lower() not in ['resolved', 'closed', 'done']:
                issues.append(f"Open Jira issue: {issue_key} - {summary}")
                print_status("WARNING", f"Open issue: {issue_key}")
    else:
        print_status("OK", "No Jira issues found")
        add_markdown("✅ No Jira issues found for this cluster.\n\n")

    # Handover Announcements - REMOVED FROM OUTPUT (still loaded for summary count)
    handover_announcements = context_data.get('HandoverAnnouncements', [])
    # print(f"\n{Colors.BOLD}Handover Announcements:{Colors.END}")
    # print(f"  Total Announcements: {len(handover_announcements)}")
    #
    # add_markdown(f"\n### Handover Announcements\n\n")
    # add_markdown(f"**Total Announcements**: {len(handover_announcements)}\n\n")
    #
    # if handover_announcements:
    #     for i, announcement in enumerate(handover_announcements[:10], 1):  # Show first 10
    #         ann_key = announcement.get('key', 'unknown')
    #         ann_fields = announcement.get('fields', {})
    #         summary = ann_fields.get('summary', 'No summary')
    #         print(f"  {i}. {ann_key}: {summary}")
    #         add_markdown(f"{i}. [{ann_key}](https://issues.redhat.com/browse/{ann_key}): {summary}\n")
    #
    #     if len(handover_announcements) > 10:
    #         remaining = len(handover_announcements) - 10
    #         print(f"  ... and {remaining} more")
    #         add_markdown(f"\n_... and {remaining} more announcements_\n")
    #     add_markdown("\n")
    # else:
    #     add_markdown("No handover announcements.\n\n")

    # Support Exceptions
    support_exceptions = context_data.get('SupportExceptions', [])
    print(f"\n{Colors.BOLD}Support Exceptions:{Colors.END}")
    if support_exceptions:
        print(f"  Total Exceptions: {len(support_exceptions)}")
        issues.append(f"Cluster has {len(support_exceptions)} support exceptions")
        print_status("WARNING", f"Found {len(support_exceptions)} support exceptions")
        add_markdown(f"\n### ⚠️ Support Exceptions\n\n")
        add_markdown(f"**Total Exceptions**: {len(support_exceptions)}\n\n")
    else:
        print(f"  None")
        print_status("OK", "No support exceptions")
        add_markdown(f"\n### ✅ Support Exceptions\n\n")
        add_markdown(f"No support exceptions found.\n\n")

    # PD Alerts
    pd_alerts = context_data.get('PdAlerts', {})
    print(f"\n{Colors.BOLD}PagerDuty Alerts:{Colors.END}")
    if pd_alerts and isinstance(pd_alerts, dict) and pd_alerts:
        alert_count = len(pd_alerts)
        print(f"  Active Alerts: {alert_count}")
        issues.append(f"Cluster has {alert_count} active PagerDuty alerts")
        print_status("WARNING", f"Found {alert_count} active PD alerts")
        add_markdown(f"\n### ⚠️ PagerDuty Alerts\n\n")
        add_markdown(f"**Active Alerts**: {alert_count}\n\n")
    else:
        print(f"  None")
        print_status("OK", "No active PagerDuty alerts")
        add_markdown(f"\n### ✅ PagerDuty Alerts\n\n")
        add_markdown(f"No active PagerDuty alerts.\n\n")

    # Limited Support Reasons
    limited_support = context_data.get('LimitedSupportReasons', None)
    if limited_support:
        print(f"\n{Colors.BOLD}Limited Support:{Colors.END}")
        print(f"  Reasons: {limited_support}")
        issues.append(f"Cluster has limited support: {limited_support}")
        print_status("WARNING", "Cluster has limited support")
        add_markdown(f"\n### ⚠️ Limited Support\n\n")
        add_markdown(f"**Reasons**: {limited_support}\n\n")

    # SDN to OVN Migration
    migration_state = context_data.get('MigrationStateValue', '')
    sdn_to_ovn_migration = context_data.get('SdnToOvnMigration', None)
    if migration_state or sdn_to_ovn_migration:
        print(f"\n{Colors.BOLD}Network Migration:{Colors.END}")
        if migration_state:
            print(f"  Migration State: {migration_state}")
            print_status("WARNING", f"Network migration in progress: {migration_state}")
            issues.append(f"Network migration state: {migration_state}")
            add_markdown(f"\n### ⚠️ Network Migration\n\n")
            add_markdown(f"**Migration State**: `{migration_state}`\n\n")
        if sdn_to_ovn_migration:
            print(f"  SDN to OVN Migration: {sdn_to_ovn_migration}")
            add_markdown(f"**SDN to OVN Migration**: {sdn_to_ovn_migration}\n\n")

    # Summary
    print(f"\n{Colors.BOLD}Cluster Context Summary:{Colors.END}")
    print(f"  Jira Issues: {len(jira_issues)}")
    # print(f"  Handover Announcements: {len(handover_announcements)}")  # REMOVED FROM OUTPUT
    print(f"  Support Exceptions: {len(support_exceptions)}")
    print(f"  Issues Found: {len(issues)}")

    if not issues:
        print_status("OK", "All cluster context checks passed")
        return ("OK", [])
    else:
        return ("WARNING", issues)

def write_markdown_report(cluster_name: str, cluster_uuid: str, infra_id: str,
                          region: str, openshift_version: str, cluster_state: str,
                          results: Dict) -> str:
    """Write the markdown report to a file"""
    global markdown_output

    # Generate timestamp
    timestamp = int(time.time())
    filename = f"results_{timestamp}.md"

    # Build the complete markdown document
    full_markdown = []

    # Title and metadata
    full_markdown.append(f"# AWS Health Check Report - {cluster_name}\n")
    full_markdown.append(f"**Generated**: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}\n\n")

    # Cluster Information
    full_markdown.append('<a name="cluster-information"></a>\n')
    full_markdown.append("## Cluster Information\n\n")
    full_markdown.append(f"- **Cluster Name**: {cluster_name}\n")
    full_markdown.append(f"- **Cluster ID**: `{cluster_uuid}`\n")
    full_markdown.append(f"- **Infrastructure ID**: `{infra_id}`\n")
    full_markdown.append(f"- **Region**: {region}\n")
    full_markdown.append(f"- **OpenShift Version**: {openshift_version}\n")
    full_markdown.append(f"- **State**: {cluster_state}\n\n")

    # Table of Contents
    full_markdown.append('<a name="table-of-contents"></a>\n')
    full_markdown.append("## Table of Contents\n\n")
    full_markdown.append("1. [Cluster Information](#cluster-information)\n")
    full_markdown.append("2. [Health Check Summary](#health-check-summary)\n")
    full_markdown.append("3. [Installation Status Check](#installation-status-check)\n")
    full_markdown.append("4. [Cluster Context Check](#cluster-context-check)\n")
    full_markdown.append("5. [VPC DNS Attributes Health Check](#vpc-dns-attributes-health-check)\n")
    full_markdown.append("6. [DHCP Options Health Check](#dhcp-options-health-check)\n")
    full_markdown.append("7. [VPC Endpoint Service Health Check (PrivateLink)](#vpc-endpoint-service-health-check-(privatelink))\n")
    full_markdown.append("8. [Security Groups Health Check](#security-groups-health-check)\n")
    full_markdown.append("9. [EC2 Instances Health Check](#ec2-instances-health-check)\n")
    full_markdown.append("10. [Load Balancers Health Check](#load-balancers-health-check)\n")
    full_markdown.append("11. [Route53 Health Check](#route53-health-check)\n")
    full_markdown.append("12. [CloudTrail Logs Health Check](#cloudtrail-logs-health-check)\n")
    full_markdown.append("13. [Detailed Analysis](#detailed-analysis)\n\n")

    full_markdown.append("---\n\n")

    # Health Check Summary section (moved to top, after TOC)
    full_markdown.append('<a name="health-check-summary"></a>\n')
    full_markdown.append("## Health Check Summary\n\n")
    full_markdown.append("| Component | Status | Issues |\n")
    full_markdown.append("|-----------|--------|--------|\n")

    # Mapping from result keys to section anchors
    section_anchors = {
        'installation_status': 'installation-status-check',
        'cluster_context': 'cluster-context-check',
        'vpc_dns_attributes': 'vpc-dns-attributes-health-check',
        'dhcp_options': 'dhcp-options-health-check',
        'vpc_endpoint_service': 'vpc-endpoint-service-health-check-(privatelink)',
        'security_groups': 'security-groups-health-check',
        'instances': 'ec2-instances-health-check',
        'load_balancers': 'load-balancers-health-check',
        'route53': 'route53-health-check',
        'cloudtrail': 'cloudtrail-logs-health-check'
    }

    for category, (status, issues) in results.items():
        category_name = category.replace('_', ' ').title()
        status_badge = "🟢" if status == "OK" else ("🟡" if status == "WARNING" else "🔴")
        issue_count = len(issues)

        # Make component name a clickable link to its section
        anchor = section_anchors.get(category, category.replace('_', '-'))
        linked_name = f"[{category_name}](#{anchor})"

        full_markdown.append(f"| {linked_name} | {status_badge} {status} | {issue_count} |\n")

    full_markdown.append("\n---\n\n")

    # Add all accumulated markdown content (detailed sections)
    full_markdown.extend(markdown_output)

    # Write to file
    with open(filename, 'w') as f:
        f.write(''.join(full_markdown))

    return filename

def main():
    """Main health check function"""
    global markdown_output, source_directory
    markdown_output = []  # Reset markdown output

    # Parse command-line arguments
    parser = argparse.ArgumentParser(
        description='AWS Health Check for OpenShift/ROSA clusters',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Run health check in current directory
  python3 check_aws_health.py

  # Run health check on data in a specific directory
  python3 check_aws_health.py -d /path/to/cluster/data
  python3 check_aws_health.py --directory ~/clusters/my-cluster

Notes:
  The script expects cluster data files in the following format:
    {cluster_id}_cluster.json
    {cluster_id}_resources.json
    {cluster_id}_ec2_instances.json
    {cluster_id}_security_groups.json
    ... and other cluster data files

  Use get_install_artifacts.sh to collect all required data files.
"""
    )
    parser.add_argument(
        '-d', '--directory',
        type=str,
        default='.',
        help='Source directory containing cluster JSON and log files (default: current directory)'
    )

    args = parser.parse_args()

    # Set source directory
    source_directory = Path(args.directory).resolve()
    if not source_directory.exists():
        print_status("ERROR", f"Source directory does not exist: {source_directory}")
        sys.exit(1)
    if not source_directory.is_dir():
        print_status("ERROR", f"Source path is not a directory: {source_directory}")
        sys.exit(1)

    print(f"{Colors.BOLD}Source directory: {source_directory}{Colors.END}")

    # Get cluster ID from first file in directory
    cluster_files = list(source_directory.glob('*_cluster.json'))
    if not cluster_files:
        print_status("ERROR", f"No cluster files found in: {source_directory}")
        print(f"\nMake sure the directory contains cluster data files in the format:")
        print(f"  {{cluster_id}}_cluster.json")
        print(f"  {{cluster_id}}_resources.json")
        print(f"  ... etc.\n")
        print(f"Use get_install_artifacts.sh to collect cluster data.")
        sys.exit(1)

    cluster_id = cluster_files[0].stem.replace('_cluster', '')

    # Load cluster.json to get infra_id and cluster name
    cluster_data = load_json_file(f"{cluster_id}_cluster.json")
    if not cluster_data:
        print_status("ERROR", "Failed to load cluster.json file")
        sys.exit(1)

    infra_id = cluster_data.get('infra_id', cluster_id.split('_')[0])
    cluster_name = cluster_data.get('name', 'unknown')
    cluster_uuid = cluster_data.get('id', cluster_id)
    region = cluster_data.get('region', {}).get('id', 'unknown')
    openshift_version = cluster_data.get('openshift_version', 'unknown')
    cluster_state = cluster_data.get('state', 'unknown')

    # Load cluster context data if available
    context_file = f"{cluster_id}_cluster_context.json"
    context_data = load_json_file(context_file)

    network_type = 'unknown'
    jira_issues_count = 0
    # handover_count = 0  # REMOVED FROM OUTPUT

    if context_data:
        network_type = context_data.get('NetworkType', 'unknown')
        jira_issues_count = len(context_data.get('JiraIssues', []))
        # handover_count = len(context_data.get('HandoverAnnouncements', []))  # REMOVED FROM OUTPUT

    print(f"\n{Colors.BOLD}AWS Health Check for OpenShift Cluster{Colors.END}")
    print(f"{Colors.BOLD}Cluster Name: {cluster_name}{Colors.END}")
    print(f"{Colors.BOLD}Cluster ID: {cluster_uuid}{Colors.END}")
    print(f"{Colors.BOLD}Infra ID: {infra_id}{Colors.END}")
    print(f"{Colors.BOLD}Region: {region}{Colors.END}")
    print(f"{Colors.BOLD}OpenShift Version: {openshift_version}{Colors.END}")
    print(f"{Colors.BOLD}State: {cluster_state}{Colors.END}")
    print(f"{Colors.BOLD}Network Type: {network_type}{Colors.END}")
    if jira_issues_count > 0:
        print(f"{Colors.BOLD}{Colors.YELLOW}Jira Issues: {jira_issues_count}{Colors.END}")
    # if handover_count > 0:  # REMOVED FROM OUTPUT
    #     print(f"{Colors.BOLD}Handover Announcements: {handover_count}{Colors.END}")
    print(f"{Colors.BOLD}Timestamp: {datetime.now(timezone.utc).isoformat()}{Colors.END}")

    # Run all health checks
    results = {}

    # Check installation status first (most important)
    results['installation_status'] = check_installation_status(cluster_id, infra_id)

    # Check cluster context (network config, Jira issues)
    results['cluster_context'] = check_cluster_context(cluster_id, infra_id)

    # Check VPC DNS attributes (required for Route53 private zones)
    results['vpc_dns_attributes'] = check_vpc_dns_attributes(cluster_id, infra_id)

    # Check DHCP Options (Kubernetes/OpenShift compatibility)
    results['dhcp_options'] = check_dhcp_options(cluster_id, infra_id)

    # Check VPC Endpoint Service (PrivateLink clusters only)
    results['vpc_endpoint_service'] = check_vpc_endpoint_service(cluster_id, infra_id)

    # Check security groups (includes API endpoint and security group configuration mismatch)
    results['security_groups'] = check_security_groups(cluster_id, infra_id)
    results['instances'] = check_instances(cluster_id, infra_id)
    results['load_balancers'] = check_load_balancers(cluster_id, infra_id)
    results['route53'] = check_route53(cluster_id)
    results['cloudtrail'] = check_cloudtrail_logs(cluster_id, infra_id)

    # Summary (terminal output only - markdown summary is generated in write_markdown_report)
    print(f"\n{Colors.BOLD}{Colors.BLUE}{'=' * 80}{Colors.END}")
    print(f"{Colors.BOLD}{Colors.BLUE}{'Health Check Summary'.center(80)}{Colors.END}")
    print(f"{Colors.BOLD}{Colors.BLUE}{'=' * 80}{Colors.END}\n")

    all_ok = True
    for category, (status, issues) in results.items():
        category_name = category.replace('_', ' ').title()
        print(f"\n{Colors.BOLD}{category_name}:{Colors.END}")
        print_status(status, f"{len(issues)} issue(s) found" if issues else "All checks passed")

        if status != "OK":
            all_ok = False

    print("\n" + "=" * 80)
    if all_ok:
        print_status("OK", "Overall cluster health: HEALTHY")
    else:
        print_status("WARNING", "Overall cluster health: ISSUES DETECTED")

    # Write markdown report
    print(f"\n{Colors.BOLD}{Colors.BLUE}Generating markdown report...{Colors.END}")
    markdown_file = write_markdown_report(
        cluster_name, cluster_uuid, infra_id,
        region, openshift_version, cluster_state,
        results
    )
    print(f"{Colors.BOLD}{Colors.GREEN}✓ Markdown report written to: {markdown_file}{Colors.END}")

    return 0 if all_ok else 1

if __name__ == "__main__":
    sys.exit(main())
