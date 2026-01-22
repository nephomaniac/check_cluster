"""
Security Group Tests - Detailed by Category

This module validates security group configurations for ROSA Classic multi-AZ clusters.
Tests are categorized by security group function:
- Control Plane (Master Node) Security Groups
- Worker/Infra Node Security Groups
- Load Balancer Security Groups
- Egress Access

Each test shows expected rules and which security groups/rules satisfy the requirements.
"""

import pytest
import json
from pathlib import Path
from typing import Dict, List, Any, Tuple
from models.cluster import ClusterData
from utils.test_helpers import check_resource_in_api_requests


def format_api_request_error(cluster_data: ClusterData, operation: str, service: str = "ec2") -> str:
    """
    Format API request error information for display.

    Args:
        cluster_data: ClusterData instance
        operation: AWS API operation name (e.g., "describe_security_groups")
        service: AWS service name (e.g., "ec2")

    Returns:
        Formatted error string with request details
    """
    req_info = check_resource_in_api_requests(cluster_data, operation, service)

    if not req_info:
        return "No API request information available (api_requests.json not found or operation not logged)"

    if req_info['success']:
        return f"API request succeeded but resource not found in results (operation: {service}.{operation}, timestamp: {req_info['timestamp']})"

    # Request failed - show error details
    error = req_info.get('error', {})
    error_code = error.get('code', 'Unknown')
    error_message = error.get('message', 'No error message')
    timestamp = req_info.get('timestamp', 'Unknown')
    duration_ms = req_info.get('duration_ms', 0)

    error_info = {
        "AWSErrorCode": error_code,
        "ErrorMessage": error_message,
        "Timestamp": timestamp,
        "Duration": f"{duration_ms}ms",
        "Service": service,
        "Operation": operation
    }

    return json.dumps(error_info, indent=2)


def get_security_groups(cluster_data: ClusterData) -> List[Dict[str, Any]]:
    """Load security groups from cluster data"""
    sg_file = cluster_data.aws_dir / f"{cluster_data.cluster_id}_security_groups.json"

    if not sg_file.exists():
        return []

    with open(sg_file) as f:
        data = json.load(f)

    return data.get('SecurityGroups', [])


def find_security_group_by_name(security_groups: List[Dict], name_pattern: str) -> Dict[str, Any]:
    """Find a security group by name pattern"""
    for sg in security_groups:
        sg_name = next((t['Value'] for t in sg.get('Tags', []) if t['Key'] == 'Name'), '')
        if name_pattern in sg_name:
            return sg
    return {}


def get_sg_name(sg: Dict[str, Any]) -> str:
    """Extract security group name from tags"""
    return next((t['Value'] for t in sg.get('Tags', []) if t['Key'] == 'Name'), 'Unknown')


def format_rule_summary(rule: Dict[str, Any], direction: str = 'ingress') -> Dict[str, Any]:
    """Format a security group rule for display"""
    protocol = rule.get('IpProtocol', 'unknown')
    from_port = rule.get('FromPort', 'N/A')
    to_port = rule.get('ToPort', 'N/A')

    # Handle special protocols
    if protocol == '-1':
        protocol_display = 'All'
        port_display = 'All'
    elif protocol == 'icmp':
        protocol_display = 'ICMP'
        port_display = 'All ICMP types'
    elif protocol == '50':
        protocol_display = 'ESP (IPSec)'
        port_display = 'N/A'
    else:
        protocol_display = protocol.upper()
        if from_port == to_port:
            port_display = str(from_port)
        else:
            port_display = f"{from_port}-{to_port}"

    # Get sources/destinations
    sources = []
    for pair in rule.get('UserIdGroupPairs', []):
        desc = pair.get('Description', 'No description')
        sg_id = pair.get('GroupId', 'unknown')
        sources.append({
            'type': 'security_group',
            'value': sg_id,
            'description': desc
        })

    for ip_range in rule.get('IpRanges', []):
        cidr = ip_range.get('CidrIp', 'unknown')
        desc = ip_range.get('Description', f'CIDR {cidr}')
        sources.append({
            'type': 'cidr',
            'value': cidr,
            'description': desc
        })

    return {
        'protocol': protocol,
        'protocol_display': protocol_display,
        'from_port': from_port,
        'to_port': to_port,
        'port_display': port_display,
        'sources': sources,
        'direction': direction
    }


def check_rule_exists(sg: Dict[str, Any], protocol: str, from_port: int = None,
                     to_port: int = None, source_sg_id: str = None,
                     direction: str = 'ingress') -> Tuple[bool, List[Dict]]:
    """
    Check if a specific rule exists in a security group.

    Returns: (exists: bool, matching_rules: List[Dict])
    """
    rules_key = 'IpPermissions' if direction == 'ingress' else 'IpPermissionsEgress'
    rules = sg.get(rules_key, [])

    matching_rules = []

    for rule in rules:
        # Check protocol match
        rule_protocol = rule.get('IpProtocol', '')
        if protocol == '-1' or rule_protocol == '-1':
            # Match any protocol if looking for 'all' or rule allows 'all'
            protocol_match = True
        elif protocol == rule_protocol:
            protocol_match = True
        else:
            protocol_match = False

        if not protocol_match:
            continue

        # Check port match (only for TCP/UDP)
        if from_port is not None and to_port is not None and protocol in ['tcp', 'udp']:
            rule_from = rule.get('FromPort')
            rule_to = rule.get('ToPort')

            # Port range must contain the specified ports
            if rule_from is not None and rule_to is not None:
                if from_port >= rule_from and to_port <= rule_to:
                    port_match = True
                else:
                    port_match = False
            else:
                port_match = False
        else:
            port_match = True

        if not port_match:
            continue

        # Check source match (if specified)
        if source_sg_id:
            source_match = False
            for pair in rule.get('UserIdGroupPairs', []):
                if pair.get('GroupId') == source_sg_id:
                    source_match = True
                    break
        else:
            source_match = True

        if protocol_match and port_match and source_match:
            matching_rules.append(format_rule_summary(rule, direction))

    return len(matching_rules) > 0, matching_rules


# =============================================================================
# SECURITY GROUP DATA EXISTENCE TEST
# =============================================================================

@pytest.mark.security_groups
def test_security_groups_data_exists(cluster_data: ClusterData):
    """Security group data must be available

    Why: Security groups control network traffic to cluster resources. Without security
    group data, we cannot validate that proper network access controls are in place.

    Failure indicates: Security group data was not collected or doesn't exist in AWS.

    Success indicates: Security group data exists and was successfully collected.
    
    Documentation: https://docs.redhat.com/en/documentation/red_hat_openshift_service_on_aws/4/html/prepare_your_environment/rosa-sts-aws-prereqs#rosa-security-groups
    """
    sg_file = cluster_data.aws_dir / f"{cluster_data.cluster_id}_security_groups.json"

    if not sg_file.exists():
        # Import diagnostic helper
        from utils.aws_resource_diagnostics import diagnose_missing_aws_resource

        # Get comprehensive diagnostics
        diagnostics = diagnose_missing_aws_resource(
            cluster_data=cluster_data,
            resource_type="Security Groups",
            expected_file=f"{cluster_data.cluster_id}_security_groups.json",
            api_service="ec2",
            api_operation="describe_security_groups",
            resource_identifier=cluster_data.infra_id
        )

        # Show AWS API request error details
        print(f"\n{'─'*80}")
        print("AWS API REQUEST INFORMATION")
        print(f"{'─'*80}")
        print(format_api_request_error(cluster_data, "describe_security_groups", "ec2"))
        print(f"{'─'*80}\n")

        pytest.fail(f"No security groups data found.\n\n{diagnostics}")

    with open(sg_file) as f:
        data = json.load(f)

    security_groups = data.get('SecurityGroups', [])

    if not security_groups:
        # Import diagnostic helper
        from utils.aws_resource_diagnostics import diagnose_missing_aws_resource

        # File exists but contains no security groups
        diagnostics = diagnose_missing_aws_resource(
            cluster_data=cluster_data,
            resource_type="Security Groups",
            expected_file=f"{cluster_data.cluster_id}_security_groups.json",
            api_service="ec2",
            api_operation="describe_security_groups",
            resource_identifier=cluster_data.infra_id
        )

        # Show AWS API request error details
        print(f"\n{'─'*80}")
        print("AWS API REQUEST INFORMATION")
        print(f"{'─'*80}")
        print(format_api_request_error(cluster_data, "describe_security_groups", "ec2"))
        print(f"{'─'*80}\n")

        pytest.fail(f"No security groups found in data file.\n\n{diagnostics}")

    print(f"\n✓ Found {len(security_groups)} security groups in cluster data")


# =============================================================================
# CONTROL PLANE (MASTER NODE) SECURITY GROUP TESTS
# =============================================================================

@pytest.mark.security_groups
@pytest.mark.controlplane
def test_controlplane_security_group_exists(cluster_data: ClusterData, infra_id: str):
    """Control plane security group must exist for master nodes
    Documentation: https://docs.redhat.com/en/documentation/red_hat_openshift_service_on_aws/4/html/prepare_your_environment/rosa-sts-aws-prereqs#rosa-security-groups
    """
    security_groups = get_security_groups(cluster_data)

    if not security_groups:
        pytest.skip("No security group data available")

    # Find controlplane security group
    controlplane_sg = find_security_group_by_name(security_groups, 'controlplane')

    if controlplane_sg:
        sg_name = get_sg_name(controlplane_sg)
        print(f"\n✓ Found control plane security group:")
        print("\n" + "─"*80)
        print("EC2 DESCRIBE-SECURITY-GROUPS OUTPUT - Control Plane Security Group")
        print("Shows master node security group exists")
        print("Relevance: Required for protecting Kubernetes control plane access")
        print("─"*80)
        print(json.dumps({
            "GroupId": controlplane_sg.get('GroupId'),
            "GroupName": controlplane_sg.get('GroupName'),
            "Name": sg_name,
            "VpcId": controlplane_sg.get('VpcId'),
            "IngressRuleCount": len(controlplane_sg.get('IpPermissions', [])),
            "EgressRuleCount": len(controlplane_sg.get('IpPermissionsEgress', []))
        }, indent=2))
        print("─"*80)
    else:
        print(f"\n✗ Control plane security group not found for {infra_id}")

    assert controlplane_sg, f"Control plane security group not found for {infra_id}"


@pytest.mark.security_groups
@pytest.mark.controlplane
def test_controlplane_api_server_access(cluster_data: ClusterData, infra_id: str):
    """
    Control plane must allow API server access on port 6443.

    Expected: TCP port 6443 ingress from:
    - Control plane security group (master-to-master)
    - Node security group (nodes-to-master)
    - API server load balancer security group
    
    Documentation: https://docs.redhat.com/en/documentation/red_hat_openshift_service_on_aws/4/html/prepare_your_environment/rosa-sts-aws-prereqs#rosa-security-groups
    """
    security_groups = get_security_groups(cluster_data)

    if not security_groups:
        pytest.skip("No security group data available")

    controlplane_sg = find_security_group_by_name(security_groups, 'controlplane')
    if not controlplane_sg:
        pytest.skip("Control plane security group not found")

    # Check for port 6443 TCP ingress
    exists, matching_rules = check_rule_exists(
        controlplane_sg,
        protocol='tcp',
        from_port=6443,
        to_port=6443,
        direction='ingress'
    )

    if exists:
        print(f"\n✓ API server access (TCP 6443) configured correctly")

        print("\n" + "─"*80)
        print("EXPECTED SECURITY GROUP RULE - Kubernetes API Server Access")
        print("Control plane must accept API requests on port 6443")
        print("Relevance: Port 6443 is the Kubernetes API server endpoint")
        print("─"*80)
        print(json.dumps({
            "Protocol": "TCP",
            "Port": "6443",
            "Direction": "Ingress",
            "ExpectedSources": [
                "Control plane security group (master-to-master communication)",
                "Node security group (kubelet-to-apiserver)",
                "API server load balancer security group"
            ]
        }, indent=2))
        print("─"*80)

        print("\n" + "─"*80)
        print("ACTUAL SECURITY GROUP RULES - Satisfying Requirements")
        print(f"Security Group: {get_sg_name(controlplane_sg)} ({controlplane_sg.get('GroupId')})")
        print(f"Found {len(matching_rules)} rule(s) allowing TCP port 6443 ingress")
        print("─"*80)

        for idx, rule in enumerate(matching_rules, 1):
            sources_summary = []
            for src in rule['sources']:
                if src['type'] == 'security_group':
                    sources_summary.append({
                        "SourceType": "Security Group",
                        "SecurityGroupId": src['value'],
                        "Description": src['description']
                    })
                else:
                    sources_summary.append({
                        "SourceType": "CIDR",
                        "CIDR": src['value'],
                        "Description": src['description']
                    })

            print(json.dumps({
                f"Rule{idx}": {
                    "Protocol": rule['protocol_display'],
                    "Port": rule['port_display'],
                    "SourceCount": len(sources_summary),
                    "Sources": sources_summary
                }
            }, indent=2))
        print("─"*80)
    else:
        print(f"\n✗ API server access (TCP 6443) NOT properly configured")

    assert exists, "Control plane security group must allow TCP port 6443 ingress"


@pytest.mark.security_groups
@pytest.mark.controlplane
def test_controlplane_etcd_access(cluster_data: ClusterData, infra_id: str):
    """
    Control plane must allow etcd access on ports 2379-2380.

    Expected:
    - TCP port 2379 (etcd client) - ingress from control plane only
    - TCP port 2380 (etcd peer) - ingress from control plane only
    
    Documentation: https://docs.redhat.com/en/documentation/red_hat_openshift_service_on_aws/4/html/prepare_your_environment/rosa-sts-aws-prereqs#rosa-security-groups
    """
    security_groups = get_security_groups(cluster_data)

    if not security_groups:
        pytest.skip("No security group data available")

    controlplane_sg = find_security_group_by_name(security_groups, 'controlplane')
    if not controlplane_sg:
        pytest.skip("Control plane security group not found")

    controlplane_sg_id = controlplane_sg.get('GroupId')

    # Check for port 2379 (etcd client)
    exists_2379, rules_2379 = check_rule_exists(
        controlplane_sg,
        protocol='tcp',
        from_port=2379,
        to_port=2379,
        source_sg_id=controlplane_sg_id,
        direction='ingress'
    )

    # Check for port 2380 (etcd peer)
    exists_2380, rules_2380 = check_rule_exists(
        controlplane_sg,
        protocol='tcp',
        from_port=2380,
        to_port=2380,
        source_sg_id=controlplane_sg_id,
        direction='ingress'
    )

    issues = []
    if not exists_2379:
        issues.append("Missing TCP port 2379 (etcd client) ingress rule")
    if not exists_2380:
        issues.append("Missing TCP port 2380 (etcd peer) ingress rule")

    if len(issues) == 0:
        print(f"\n✓ etcd access (TCP 2379-2380) configured correctly")

        print("\n" + "─"*80)
        print("EXPECTED SECURITY GROUP RULES - etcd Database Access")
        print("Control plane nodes must communicate with etcd cluster")
        print("Relevance: etcd stores all Kubernetes cluster state and configuration")
        print("─"*80)
        print(json.dumps({
            "Port2379": {
                "Protocol": "TCP",
                "Port": "2379",
                "Purpose": "etcd client API",
                "Direction": "Ingress",
                "ExpectedSource": "Control plane security group only"
            },
            "Port2380": {
                "Protocol": "TCP",
                "Port": "2380",
                "Purpose": "etcd peer communication",
                "Direction": "Ingress",
                "ExpectedSource": "Control plane security group only"
            }
        }, indent=2))
        print("─"*80)

        print("\n" + "─"*80)
        print("ACTUAL SECURITY GROUP RULES - Satisfying Requirements")
        print(f"Security Group: {get_sg_name(controlplane_sg)} ({controlplane_sg_id})")
        print("─"*80)

        all_rules = []
        for rule in rules_2379:
            all_rules.append({
                "Port": "2379",
                "Purpose": "etcd client",
                "Protocol": rule['protocol_display'],
                "SourceCount": len(rule['sources'])
            })
        for rule in rules_2380:
            all_rules.append({
                "Port": "2380",
                "Purpose": "etcd peer",
                "Protocol": rule['protocol_display'],
                "SourceCount": len(rule['sources'])
            })

        print(json.dumps(all_rules, indent=2))
        print("─"*80)
    else:
        print(f"\n✗ etcd access NOT properly configured")
        print("\n" + "─"*80)
        print("MISSING SECURITY GROUP RULES")
        print("─"*80)
        print(json.dumps({"Issues": issues}, indent=2))
        print("─"*80)

    assert len(issues) == 0, f"etcd access issues: {'; '.join(issues)}"


@pytest.mark.security_groups
@pytest.mark.controlplane
def test_controlplane_mcs_access(cluster_data: ClusterData, infra_id: str):
    """
    Control plane must allow Machine Config Server (MCS) access on port 22623.

    Expected: TCP port 22623 ingress from:
    - Control plane security group
    - Node security group
    
    Documentation: https://docs.redhat.com/en/documentation/red_hat_openshift_service_on_aws/4/html/prepare_your_environment/rosa-sts-aws-prereqs#rosa-security-groups
    """
    security_groups = get_security_groups(cluster_data)

    if not security_groups:
        pytest.skip("No security group data available")

    controlplane_sg = find_security_group_by_name(security_groups, 'controlplane')
    if not controlplane_sg:
        pytest.skip("Control plane security group not found")

    exists, matching_rules = check_rule_exists(
        controlplane_sg,
        protocol='tcp',
        from_port=22623,
        to_port=22623,
        direction='ingress'
    )

    if exists:
        print(f"\n✓ Machine Config Server access (TCP 22623) configured correctly")

        print("\n" + "─"*80)
        print("EXPECTED SECURITY GROUP RULE - Machine Config Server (MCS)")
        print("MCS provides Ignition configs and updates to cluster nodes")
        print("Relevance: Required for node bootstrapping and configuration updates")
        print("─"*80)
        print(json.dumps({
            "Protocol": "TCP",
            "Port": "22623",
            "Purpose": "Machine Config Server",
            "Direction": "Ingress",
            "ExpectedSources": [
                "Control plane security group",
                "Node security group"
            ]
        }, indent=2))
        print("─"*80)

        print("\n" + "─"*80)
        print("ACTUAL SECURITY GROUP RULES - Satisfying Requirements")
        print(f"Security Group: {get_sg_name(controlplane_sg)} ({controlplane_sg.get('GroupId')})")
        print(f"Found {len(matching_rules)} rule(s) allowing TCP port 22623 ingress")
        print("─"*80)
        print(json.dumps([{
            "Protocol": rule['protocol_display'],
            "Port": rule['port_display'],
            "SourceCount": len(rule['sources'])
        } for rule in matching_rules], indent=2))
        print("─"*80)
    else:
        print(f"\n✗ MCS access (TCP 22623) NOT properly configured")

    assert exists, "Control plane must allow TCP port 22623 for Machine Config Server"


@pytest.mark.security_groups
@pytest.mark.controlplane
def test_controlplane_kube_components_access(cluster_data: ClusterData, infra_id: str):
    """
    Control plane must allow kube-controller-manager and kube-scheduler access.

    Expected:
    - TCP port 10257 (kube-controller-manager) - ingress from control plane and nodes
    - TCP port 10259 (kube-scheduler) - ingress from control plane and nodes
    
    Documentation: https://docs.redhat.com/en/documentation/red_hat_openshift_service_on_aws/4/html/prepare_your_environment/rosa-sts-aws-prereqs#rosa-security-groups
    """
    security_groups = get_security_groups(cluster_data)

    if not security_groups:
        pytest.skip("No security group data available")

    controlplane_sg = find_security_group_by_name(security_groups, 'controlplane')
    if not controlplane_sg:
        pytest.skip("Control plane security group not found")

    # Check for port 10257 (controller-manager)
    exists_10257, rules_10257 = check_rule_exists(
        controlplane_sg,
        protocol='tcp',
        from_port=10257,
        to_port=10257,
        direction='ingress'
    )

    # Check for port 10259 (kube-scheduler)
    exists_10259, rules_10259 = check_rule_exists(
        controlplane_sg,
        protocol='tcp',
        from_port=10259,
        to_port=10259,
        direction='ingress'
    )

    issues = []
    if not exists_10257:
        issues.append("Missing TCP port 10257 (kube-controller-manager)")
    if not exists_10259:
        issues.append("Missing TCP port 10259 (kube-scheduler)")

    if len(issues) == 0:
        print(f"\n✓ Kubernetes component access configured correctly")

        print("\n" + "─"*80)
        print("EXPECTED SECURITY GROUP RULES - Kubernetes Control Plane Components")
        print("Controller manager and scheduler must be accessible for metrics/health")
        print("Relevance: Required for cluster monitoring and health checks")
        print("─"*80)
        print(json.dumps({
            "Port10257": {
                "Protocol": "TCP",
                "Port": "10257",
                "Component": "kube-controller-manager",
                "Purpose": "Metrics and health checks"
            },
            "Port10259": {
                "Protocol": "TCP",
                "Port": "10259",
                "Component": "kube-scheduler",
                "Purpose": "Metrics and health checks"
            }
        }, indent=2))
        print("─"*80)

        print("\n" + "─"*80)
        print("ACTUAL SECURITY GROUP RULES - Satisfying Requirements")
        print(f"Security Group: {get_sg_name(controlplane_sg)} ({controlplane_sg.get('GroupId')})")
        print("─"*80)

        all_rules = []
        for rule in rules_10257:
            all_rules.append({
                "Port": "10257",
                "Component": "controller-manager",
                "SourceCount": len(rule['sources'])
            })
        for rule in rules_10259:
            all_rules.append({
                "Port": "10259",
                "Component": "kube-scheduler",
                "SourceCount": len(rule['sources'])
            })

        print(json.dumps(all_rules, indent=2))
        print("─"*80)
    else:
        print(f"\n✗ Kubernetes component access NOT properly configured")
        print("\n" + "─"*80)
        print("MISSING SECURITY GROUP RULES")
        print("─"*80)
        print(json.dumps({"Issues": issues}, indent=2))
        print("─"*80)

    assert len(issues) == 0, f"Kubernetes component access issues: {'; '.join(issues)}"


# =============================================================================
# WORKER/INFRA NODE SECURITY GROUP TESTS
# =============================================================================

@pytest.mark.security_groups
@pytest.mark.node
def test_node_security_group_exists(cluster_data: ClusterData, infra_id: str):
    """Worker/infra node security group must exist
    Documentation: https://docs.redhat.com/en/documentation/red_hat_openshift_service_on_aws/4/html/prepare_your_environment/rosa-sts-aws-prereqs#rosa-security-groups
    """
    security_groups = get_security_groups(cluster_data)

    if not security_groups:
        pytest.skip("No security group data available")

    # Find node security group
    node_sg = find_security_group_by_name(security_groups, '-node')

    if node_sg:
        sg_name = get_sg_name(node_sg)
        print(f"\n✓ Found worker/infra node security group:")
        print("\n" + "─"*80)
        print("EC2 DESCRIBE-SECURITY-GROUPS OUTPUT - Worker/Infra Node Security Group")
        print("Shows worker and infrastructure node security group exists")
        print("Relevance: Required for protecting cluster workload and infra nodes")
        print("─"*80)
        print(json.dumps({
            "GroupId": node_sg.get('GroupId'),
            "GroupName": node_sg.get('GroupName'),
            "Name": sg_name,
            "VpcId": node_sg.get('VpcId'),
            "IngressRuleCount": len(node_sg.get('IpPermissions', [])),
            "EgressRuleCount": len(node_sg.get('IpPermissionsEgress', []))
        }, indent=2))
        print("─"*80)
    else:
        print(f"\n✗ Worker/infra node security group not found for {infra_id}")

    assert node_sg, f"Worker/infra node security group not found for {infra_id}"


@pytest.mark.security_groups
@pytest.mark.node
def test_node_kubelet_access(cluster_data: ClusterData, infra_id: str):
    """
    Worker/infra nodes must allow kubelet API access on port 10250.

    Expected: TCP port 10250 ingress from:
    - Control plane security group (for metrics scraping)
    - Node security group (for pod-to-pod communication)
    
    Documentation: https://docs.redhat.com/en/documentation/red_hat_openshift_service_on_aws/4/html/prepare_your_environment/rosa-sts-aws-prereqs#rosa-security-groups
    """
    security_groups = get_security_groups(cluster_data)

    if not security_groups:
        pytest.skip("No security group data available")

    node_sg = find_security_group_by_name(security_groups, '-node')
    if not node_sg:
        pytest.skip("Node security group not found")

    exists, matching_rules = check_rule_exists(
        node_sg,
        protocol='tcp',
        from_port=10250,
        to_port=10250,
        direction='ingress'
    )

    if exists:
        print(f"\n✓ Kubelet API access (TCP 10250) configured correctly")

        print("\n" + "─"*80)
        print("EXPECTED SECURITY GROUP RULE - Kubelet API Access")
        print("Kubelet exposes API for node management and metrics")
        print("Relevance: Required for control plane to manage nodes and collect metrics")
        print("─"*80)
        print(json.dumps({
            "Protocol": "TCP",
            "Port": "10250",
            "Purpose": "Kubelet API",
            "Direction": "Ingress",
            "ExpectedSources": [
                "Control plane security group (metrics scraping)",
                "Node security group (inter-node communication)"
            ]
        }, indent=2))
        print("─"*80)

        print("\n" + "─"*80)
        print("ACTUAL SECURITY GROUP RULES - Satisfying Requirements")
        print(f"Security Group: {get_sg_name(node_sg)} ({node_sg.get('GroupId')})")
        print(f"Found {len(matching_rules)} rule(s) allowing TCP port 10250 ingress")
        print("─"*80)
        print(json.dumps([{
            "Protocol": rule['protocol_display'],
            "Port": rule['port_display'],
            "SourceCount": len(rule['sources'])
        } for rule in matching_rules], indent=2))
        print("─"*80)
    else:
        print(f"\n✗ Kubelet API access (TCP 10250) NOT properly configured")

    assert exists, "Node security group must allow TCP port 10250 for kubelet API"


@pytest.mark.security_groups
@pytest.mark.node
def test_node_service_ports_access(cluster_data: ClusterData, infra_id: str):
    """
    Worker/infra nodes must allow NodePort service access on ports 30000-32767.

    Expected:
    - TCP ports 30000-32767 ingress from node security group
    - UDP ports 30000-32767 ingress from node security group
    
    Documentation: https://docs.redhat.com/en/documentation/red_hat_openshift_service_on_aws/4/html/prepare_your_environment/rosa-sts-aws-prereqs#rosa-security-groups
    """
    security_groups = get_security_groups(cluster_data)

    if not security_groups:
        pytest.skip("No security group data available")

    node_sg = find_security_group_by_name(security_groups, '-node')
    if not node_sg:
        pytest.skip("Node security group not found")

    # Check for TCP service ports
    exists_tcp, rules_tcp = check_rule_exists(
        node_sg,
        protocol='tcp',
        from_port=30000,
        to_port=32767,
        direction='ingress'
    )

    # Check for UDP service ports
    exists_udp, rules_udp = check_rule_exists(
        node_sg,
        protocol='udp',
        from_port=30000,
        to_port=32767,
        direction='ingress'
    )

    issues = []
    if not exists_tcp:
        issues.append("Missing TCP ports 30000-32767 for NodePort services")
    if not exists_udp:
        issues.append("Missing UDP ports 30000-32767 for NodePort services")

    if len(issues) == 0:
        print(f"\n✓ NodePort service access (30000-32767) configured correctly")

        print("\n" + "─"*80)
        print("EXPECTED SECURITY GROUP RULES - Kubernetes NodePort Services")
        print("NodePort services expose applications on specific ports across all nodes")
        print("Relevance: Required for external access to services via NodePort type")
        print("─"*80)
        print(json.dumps({
            "TCPPorts": {
                "Protocol": "TCP",
                "PortRange": "30000-32767",
                "Purpose": "NodePort services (TCP)"
            },
            "UDPPorts": {
                "Protocol": "UDP",
                "PortRange": "30000-32767",
                "Purpose": "NodePort services (UDP)"
            },
            "ExpectedSources": ["Node security group", "Load balancer security group"]
        }, indent=2))
        print("─"*80)

        print("\n" + "─"*80)
        print("ACTUAL SECURITY GROUP RULES - Satisfying Requirements")
        print(f"Security Group: {get_sg_name(node_sg)} ({node_sg.get('GroupId')})")
        print("─"*80)

        all_rules = []
        for rule in rules_tcp:
            all_rules.append({
                "Protocol": "TCP",
                "PortRange": "30000-32767",
                "RuleCount": len(rules_tcp),
                "SourceCount": len(rule['sources'])
            })
        for rule in rules_udp:
            all_rules.append({
                "Protocol": "UDP",
                "PortRange": "30000-32767",
                "RuleCount": len(rules_udp),
                "SourceCount": len(rule['sources'])
            })

        print(json.dumps(all_rules, indent=2))
        print("─"*80)
    else:
        print(f"\n✗ NodePort service access NOT properly configured")
        print("\n" + "─"*80)
        print("MISSING SECURITY GROUP RULES")
        print("─"*80)
        print(json.dumps({"Issues": issues}, indent=2))
        print("─"*80)

    assert len(issues) == 0, f"NodePort access issues: {'; '.join(issues)}"


@pytest.mark.security_groups
@pytest.mark.node
def test_node_ssh_access(cluster_data: ClusterData, infra_id: str):
    """
    Worker/infra nodes must allow SSH access on port 22.

    Expected: TCP port 22 ingress from:
    - Control plane security group
    - Node security group
    
    Documentation: https://docs.redhat.com/en/documentation/red_hat_openshift_service_on_aws/4/html/prepare_your_environment/rosa-sts-aws-prereqs#rosa-security-groups
    """
    security_groups = get_security_groups(cluster_data)

    if not security_groups:
        pytest.skip("No security group data available")

    node_sg = find_security_group_by_name(security_groups, '-node')
    if not node_sg:
        pytest.skip("Node security group not found")

    exists, matching_rules = check_rule_exists(
        node_sg,
        protocol='tcp',
        from_port=22,
        to_port=22,
        direction='ingress'
    )

    if exists:
        print(f"\n✓ SSH access (TCP 22) configured correctly")

        print("\n" + "─"*80)
        print("EXPECTED SECURITY GROUP RULE - SSH Access")
        print("SSH required for node debugging and maintenance")
        print("Relevance: Allows cluster administrators to access nodes for troubleshooting")
        print("─"*80)
        print(json.dumps({
            "Protocol": "TCP",
            "Port": "22",
            "Purpose": "SSH access",
            "Direction": "Ingress",
            "ExpectedSources": [
                "Control plane security group",
                "Node security group"
            ]
        }, indent=2))
        print("─"*80)

        print("\n" + "─"*80)
        print("ACTUAL SECURITY GROUP RULES - Satisfying Requirements")
        print(f"Security Group: {get_sg_name(node_sg)} ({node_sg.get('GroupId')})")
        print(f"Found {len(matching_rules)} rule(s) allowing TCP port 22 ingress")
        print("─"*80)
        print(json.dumps([{
            "Protocol": rule['protocol_display'],
            "Port": rule['port_display'],
            "SourceCount": len(rule['sources'])
        } for rule in matching_rules], indent=2))
        print("─"*80)
    else:
        print(f"\n✗ SSH access (TCP 22) NOT properly configured")

    assert exists, "Node security group must allow TCP port 22 for SSH access"


# =============================================================================
# NETWORK OVERLAY TESTS
# =============================================================================

@pytest.mark.security_groups
@pytest.mark.network
def test_network_overlay_vxlan_geneve(cluster_data: ClusterData, infra_id: str):
    """
    Cluster must allow overlay network protocols (VXLAN/Geneve) for pod networking.

    Expected in both control plane and node security groups:
    - UDP port 4789 (VXLAN)
    - UDP port 6081 (Geneve)
    - TCP ports 6441-6442 (OVN database)
    
    Documentation: https://docs.redhat.com/en/documentation/red_hat_openshift_service_on_aws/4/html/prepare_your_environment/rosa-sts-aws-prereqs#rosa-security-groups
    """
    security_groups = get_security_groups(cluster_data)

    if not security_groups:
        pytest.skip("No security group data available")

    controlplane_sg = find_security_group_by_name(security_groups, 'controlplane')
    node_sg = find_security_group_by_name(security_groups, '-node')

    if not controlplane_sg or not node_sg:
        pytest.skip("Required security groups not found")

    issues = []
    results = {}

    # Check VXLAN on control plane
    exists_cp_vxlan, _ = check_rule_exists(controlplane_sg, 'udp', 4789, 4789, direction='ingress')
    results['controlplane_vxlan'] = exists_cp_vxlan
    if not exists_cp_vxlan:
        issues.append("Control plane missing UDP port 4789 (VXLAN)")

    # Check Geneve on control plane
    exists_cp_geneve, _ = check_rule_exists(controlplane_sg, 'udp', 6081, 6081, direction='ingress')
    results['controlplane_geneve'] = exists_cp_geneve
    if not exists_cp_geneve:
        issues.append("Control plane missing UDP port 6081 (Geneve)")

    # Check OVN database on control plane
    exists_cp_ovn, _ = check_rule_exists(controlplane_sg, 'tcp', 6441, 6442, direction='ingress')
    results['controlplane_ovn'] = exists_cp_ovn
    if not exists_cp_ovn:
        issues.append("Control plane missing TCP ports 6441-6442 (OVN database)")

    # Check VXLAN on nodes
    exists_node_vxlan, _ = check_rule_exists(node_sg, 'udp', 4789, 4789, direction='ingress')
    results['node_vxlan'] = exists_node_vxlan
    if not exists_node_vxlan:
        issues.append("Node security group missing UDP port 4789 (VXLAN)")

    # Check Geneve on nodes
    exists_node_geneve, _ = check_rule_exists(node_sg, 'udp', 6081, 6081, direction='ingress')
    results['node_geneve'] = exists_node_geneve
    if not exists_node_geneve:
        issues.append("Node security group missing UDP port 6081 (Geneve)")

    # Check OVN database on nodes
    exists_node_ovn, _ = check_rule_exists(node_sg, 'tcp', 6441, 6442, direction='ingress')
    results['node_ovn'] = exists_node_ovn
    if not exists_node_ovn:
        issues.append("Node security group missing TCP ports 6441-6442 (OVN database)")

    if len(issues) == 0:
        print(f"\n✓ Network overlay protocols configured correctly")

        print("\n" + "─"*80)
        print("EXPECTED SECURITY GROUP RULES - Overlay Network Protocols")
        print("VXLAN/Geneve and OVN enable pod-to-pod networking across nodes")
        print("Relevance: Required for Kubernetes pod network communication")
        print("─"*80)
        print(json.dumps({
            "VXLAN": {
                "Protocol": "UDP",
                "Port": "4789",
                "Purpose": "VXLAN overlay encapsulation"
            },
            "Geneve": {
                "Protocol": "UDP",
                "Port": "6081",
                "Purpose": "Geneve overlay encapsulation"
            },
            "OVNDatabase": {
                "Protocol": "TCP",
                "PortRange": "6441-6442",
                "Purpose": "OVN northbound/southbound database"
            },
            "RequiredOn": ["Control plane security group", "Node security group"]
        }, indent=2))
        print("─"*80)

        print("\n" + "─"*80)
        print("ACTUAL SECURITY GROUP RULES - Satisfying Requirements")
        print("─"*80)
        print(json.dumps({
            "ControlPlane": {
                "SecurityGroup": get_sg_name(controlplane_sg),
                "VXLAN_UDP_4789": "✓" if results['controlplane_vxlan'] else "✗",
                "Geneve_UDP_6081": "✓" if results['controlplane_geneve'] else "✗",
                "OVN_TCP_6441-6442": "✓" if results['controlplane_ovn'] else "✗"
            },
            "Node": {
                "SecurityGroup": get_sg_name(node_sg),
                "VXLAN_UDP_4789": "✓" if results['node_vxlan'] else "✗",
                "Geneve_UDP_6081": "✓" if results['node_geneve'] else "✗",
                "OVN_TCP_6441-6442": "✓" if results['node_ovn'] else "✗"
            }
        }, indent=2))
        print("─"*80)
    else:
        print(f"\n✗ Network overlay protocols NOT properly configured")
        print("\n" + "─"*80)
        print("MISSING SECURITY GROUP RULES")
        print("─"*80)
        print(json.dumps({"Issues": issues}, indent=2))
        print("─"*80)

    assert len(issues) == 0, f"Network overlay issues: {'; '.join(issues)}"


@pytest.mark.security_groups
@pytest.mark.network
def test_ipsec_vpn_access(cluster_data: ClusterData, infra_id: str):
    """
    Cluster must allow IPSec VPN protocols for encrypted pod traffic (if enabled).

    Expected in both control plane and node security groups:
    - Protocol 50 (ESP - Encapsulating Security Payload)
    - UDP port 500 (IKE - Internet Key Exchange)
    - UDP port 4500 (IKE NAT traversal)
    
    Documentation: https://docs.redhat.com/en/documentation/red_hat_openshift_service_on_aws/4/html/prepare_your_environment/rosa-sts-aws-prereqs#rosa-security-groups
    """
    security_groups = get_security_groups(cluster_data)

    if not security_groups:
        pytest.skip("No security group data available")

    controlplane_sg = find_security_group_by_name(security_groups, 'controlplane')
    node_sg = find_security_group_by_name(security_groups, '-node')

    if not controlplane_sg or not node_sg:
        pytest.skip("Required security groups not found")

    issues = []
    results = {}

    # Check ESP on control plane
    exists_cp_esp, _ = check_rule_exists(controlplane_sg, '50', direction='ingress')
    results['controlplane_esp'] = exists_cp_esp
    if not exists_cp_esp:
        issues.append("Control plane missing protocol 50 (ESP)")

    # Check IKE on control plane
    exists_cp_ike, _ = check_rule_exists(controlplane_sg, 'udp', 500, 500, direction='ingress')
    results['controlplane_ike'] = exists_cp_ike
    if not exists_cp_ike:
        issues.append("Control plane missing UDP port 500 (IKE)")

    # Check IKE NAT on control plane
    exists_cp_ike_nat, _ = check_rule_exists(controlplane_sg, 'udp', 4500, 4500, direction='ingress')
    results['controlplane_ike_nat'] = exists_cp_ike_nat
    if not exists_cp_ike_nat:
        issues.append("Control plane missing UDP port 4500 (IKE NAT)")

    # Check ESP on nodes
    exists_node_esp, _ = check_rule_exists(node_sg, '50', direction='ingress')
    results['node_esp'] = exists_node_esp
    if not exists_node_esp:
        issues.append("Node security group missing protocol 50 (ESP)")

    # Check IKE on nodes
    exists_node_ike, _ = check_rule_exists(node_sg, 'udp', 500, 500, direction='ingress')
    results['node_ike'] = exists_node_ike
    if not exists_node_ike:
        issues.append("Node security group missing UDP port 500 (IKE)")

    # Check IKE NAT on nodes
    exists_node_ike_nat, _ = check_rule_exists(node_sg, 'udp', 4500, 4500, direction='ingress')
    results['node_ike_nat'] = exists_node_ike_nat
    if not exists_node_ike_nat:
        issues.append("Node security group missing UDP port 4500 (IKE NAT)")

    if len(issues) == 0:
        print(f"\n✓ IPSec VPN protocols configured correctly")

        print("\n" + "─"*80)
        print("EXPECTED SECURITY GROUP RULES - IPSec VPN Protocols")
        print("IPSec enables encrypted pod-to-pod communication across nodes")
        print("Relevance: Required for secure pod network encryption (if enabled)")
        print("─"*80)
        print(json.dumps({
            "ESP": {
                "Protocol": "50 (ESP)",
                "Purpose": "Encapsulating Security Payload for encrypted traffic"
            },
            "IKE": {
                "Protocol": "UDP",
                "Port": "500",
                "Purpose": "Internet Key Exchange for VPN negotiation"
            },
            "IKE_NAT": {
                "Protocol": "UDP",
                "Port": "4500",
                "Purpose": "IKE NAT traversal"
            },
            "RequiredOn": ["Control plane security group", "Node security group"]
        }, indent=2))
        print("─"*80)

        print("\n" + "─"*80)
        print("ACTUAL SECURITY GROUP RULES - Satisfying Requirements")
        print("─"*80)
        print(json.dumps({
            "ControlPlane": {
                "SecurityGroup": get_sg_name(controlplane_sg),
                "ESP_Protocol_50": "✓" if results['controlplane_esp'] else "✗",
                "IKE_UDP_500": "✓" if results['controlplane_ike'] else "✗",
                "IKE_NAT_UDP_4500": "✓" if results['controlplane_ike_nat'] else "✗"
            },
            "Node": {
                "SecurityGroup": get_sg_name(node_sg),
                "ESP_Protocol_50": "✓" if results['node_esp'] else "✗",
                "IKE_UDP_500": "✓" if results['node_ike'] else "✗",
                "IKE_NAT_UDP_4500": "✓" if results['node_ike_nat'] else "✗"
            }
        }, indent=2))
        print("─"*80)
    else:
        print(f"\n✗ IPSec VPN protocols NOT properly configured")
        print("\n" + "─"*80)
        print("MISSING SECURITY GROUP RULES")
        print("─"*80)
        print(json.dumps({"Issues": issues}, indent=2))
        print("─"*80)

    assert len(issues) == 0, f"IPSec VPN issues: {'; '.join(issues)}"


# =============================================================================
# LOAD BALANCER SECURITY GROUP TESTS
# =============================================================================

@pytest.mark.security_groups
@pytest.mark.loadbalancer
def test_api_loadbalancer_security_group_exists(cluster_data: ClusterData, infra_id: str):
    """API server load balancer security group must exist
    Documentation: https://docs.redhat.com/en/documentation/red_hat_openshift_service_on_aws/4/html/prepare_your_environment/rosa-sts-aws-prereqs#rosa-security-groups
    """
    security_groups = get_security_groups(cluster_data)

    if not security_groups:
        pytest.skip("No security group data available")

    # Find API server LB security group
    api_lb_sg = find_security_group_by_name(security_groups, 'apiserver-lb')

    if api_lb_sg:
        sg_name = get_sg_name(api_lb_sg)
        print(f"\n✓ Found API server load balancer security group:")
        print("\n" + "─"*80)
        print("EC2 DESCRIBE-SECURITY-GROUPS OUTPUT - API Server Load Balancer")
        print("Shows API server load balancer security group exists")
        print("Relevance: Required for external API access via load balancer")
        print("─"*80)
        print(json.dumps({
            "GroupId": api_lb_sg.get('GroupId'),
            "GroupName": api_lb_sg.get('GroupName'),
            "Name": sg_name,
            "VpcId": api_lb_sg.get('VpcId'),
            "IngressRuleCount": len(api_lb_sg.get('IpPermissions', [])),
            "EgressRuleCount": len(api_lb_sg.get('IpPermissionsEgress', []))
        }, indent=2))
        print("─"*80)
    else:
        print(f"\n✗ API server load balancer security group not found for {infra_id}")

    assert api_lb_sg, f"API server load balancer security group not found for {infra_id}"


@pytest.mark.security_groups
@pytest.mark.loadbalancer
def test_application_loadbalancer_security_group_exists(cluster_data: ClusterData, infra_id: str):
    """Application (router) load balancer security group must exist
    Documentation: https://docs.redhat.com/en/documentation/red_hat_openshift_service_on_aws/4/html/prepare_your_environment/rosa-sts-aws-prereqs#rosa-security-groups
    """
    security_groups = get_security_groups(cluster_data)

    if not security_groups:
        pytest.skip("No security group data available")

    # Find application LB security group (not apiserver-lb)
    app_lb_sg = None
    for sg in security_groups:
        sg_name = get_sg_name(sg)
        if '-lb' in sg_name and 'apiserver' not in sg_name:
            app_lb_sg = sg
            break

    if app_lb_sg:
        sg_name = get_sg_name(app_lb_sg)
        print(f"\n✓ Found application load balancer security group:")
        print("\n" + "─"*80)
        print("EC2 DESCRIBE-SECURITY-GROUPS OUTPUT - Application Load Balancer")
        print("Shows router/application load balancer security group exists")
        print("Relevance: Required for external HTTP/HTTPS access to cluster applications")
        print("─"*80)
        print(json.dumps({
            "GroupId": app_lb_sg.get('GroupId'),
            "GroupName": app_lb_sg.get('GroupName'),
            "Name": sg_name,
            "VpcId": app_lb_sg.get('VpcId'),
            "IngressRuleCount": len(app_lb_sg.get('IpPermissions', [])),
            "EgressRuleCount": len(app_lb_sg.get('IpPermissionsEgress', []))
        }, indent=2))
        print("─"*80)
    else:
        print(f"\n✗ Application load balancer security group not found for {infra_id}")

    assert app_lb_sg, f"Application load balancer security group not found for {infra_id}"


# =============================================================================
# EGRESS ACCESS TESTS
# =============================================================================

@pytest.mark.security_groups
@pytest.mark.egress
def test_all_security_groups_allow_egress(cluster_data: ClusterData, infra_id: str):
    """
    All security groups must allow egress traffic.

    Expected: Egress rule allowing all protocols to 0.0.0.0/0
    
    Documentation: https://docs.redhat.com/en/documentation/red_hat_openshift_service_on_aws/4/html/prepare_your_environment/rosa-sts-aws-prereqs#rosa-security-groups
    """
    security_groups = get_security_groups(cluster_data)

    if not security_groups:
        pytest.skip("No security group data available")

    # Filter to cluster security groups
    cluster_sgs = [sg for sg in security_groups if any(
        tag.get('Key') == 'Name' and infra_id in tag.get('Value', '')
        for tag in sg.get('Tags', [])
    )]

    issues = []
    results = []

    for sg in cluster_sgs:
        sg_name = get_sg_name(sg)
        sg_id = sg.get('GroupId')

        # Check for egress rule allowing all traffic
        egress_rules = sg.get('IpPermissionsEgress', [])
        has_open_egress = False

        for rule in egress_rules:
            if rule.get('IpProtocol') == '-1':
                # Check if allows to 0.0.0.0/0
                for ip_range in rule.get('IpRanges', []):
                    if ip_range.get('CidrIp') == '0.0.0.0/0':
                        has_open_egress = True
                        break

        results.append({
            "SecurityGroup": sg_name,
            "GroupId": sg_id,
            "AllowsEgress": has_open_egress
        })

        if not has_open_egress:
            issues.append(f"{sg_name} ({sg_id}) does not allow open egress")

    if len(issues) == 0:
        print(f"\n✓ All {len(cluster_sgs)} security groups allow egress traffic")

        print("\n" + "─"*80)
        print("EXPECTED SECURITY GROUP RULE - Egress Traffic")
        print("All security groups should allow unrestricted outbound traffic")
        print("Relevance: Nodes need egress for pulling images, updates, and external services")
        print("─"*80)
        print(json.dumps({
            "Protocol": "All (-1)",
            "Destination": "0.0.0.0/0",
            "Purpose": "Allow all outbound traffic",
            "RequiredOn": "All cluster security groups"
        }, indent=2))
        print("─"*80)

        print("\n" + "─"*80)
        print("ACTUAL SECURITY GROUP RULES - Satisfying Requirements")
        print(f"Verified {len(cluster_sgs)} cluster security groups")
        print("─"*80)
        print(json.dumps(results, indent=2))
        print("─"*80)
    else:
        print(f"\n✗ Egress rules NOT properly configured on all security groups")
        print("\n" + "─"*80)
        print("SECURITY GROUPS WITH MISSING EGRESS RULES")
        print("─"*80)
        print(json.dumps({"Issues": issues, "Details": results}, indent=2))
        print("─"*80)

    assert len(issues) == 0, f"Egress issues: {'; '.join(issues)}"


@pytest.mark.security_groups
@pytest.mark.icmp
def test_icmp_allowed_between_nodes(cluster_data: ClusterData, infra_id: str):
    """
    ICMP must be allowed between all cluster nodes for connectivity checks.

    Expected: ICMP ingress in both control plane and node security groups
    
    Documentation: https://docs.redhat.com/en/documentation/red_hat_openshift_service_on_aws/4/html/prepare_your_environment/rosa-sts-aws-prereqs#rosa-security-groups
    """
    security_groups = get_security_groups(cluster_data)

    if not security_groups:
        pytest.skip("No security group data available")

    controlplane_sg = find_security_group_by_name(security_groups, 'controlplane')
    node_sg = find_security_group_by_name(security_groups, '-node')

    if not controlplane_sg or not node_sg:
        pytest.skip("Required security groups not found")

    # Check ICMP on control plane
    exists_cp, rules_cp = check_rule_exists(controlplane_sg, 'icmp', direction='ingress')

    # Check ICMP on nodes
    exists_node, rules_node = check_rule_exists(node_sg, 'icmp', direction='ingress')

    issues = []
    if not exists_cp:
        issues.append("Control plane missing ICMP ingress")
    if not exists_node:
        issues.append("Node security group missing ICMP ingress")

    if len(issues) == 0:
        print(f"\n✓ ICMP configured correctly for node connectivity checks")

        print("\n" + "─"*80)
        print("EXPECTED SECURITY GROUP RULE - ICMP Protocol")
        print("ICMP enables ping and network diagnostics between nodes")
        print("Relevance: Required for cluster health checks and network troubleshooting")
        print("─"*80)
        print(json.dumps({
            "Protocol": "ICMP",
            "Purpose": "Ping and network diagnostics",
            "Direction": "Ingress",
            "RequiredOn": ["Control plane security group", "Node security group"]
        }, indent=2))
        print("─"*80)

        print("\n" + "─"*80)
        print("ACTUAL SECURITY GROUP RULES - Satisfying Requirements")
        print("─"*80)
        print(json.dumps({
            "ControlPlane": {
                "SecurityGroup": get_sg_name(controlplane_sg),
                "ICMPEnabled": True,
                "RuleCount": len(rules_cp)
            },
            "Node": {
                "SecurityGroup": get_sg_name(node_sg),
                "ICMPEnabled": True,
                "RuleCount": len(rules_node)
            }
        }, indent=2))
        print("─"*80)
    else:
        print(f"\n✗ ICMP NOT properly configured")
        print("\n" + "─"*80)
        print("MISSING SECURITY GROUP RULES")
        print("─"*80)
        print(json.dumps({"Issues": issues}, indent=2))
        print("─"*80)

    assert len(issues) == 0, f"ICMP issues: {'; '.join(issues)}"
