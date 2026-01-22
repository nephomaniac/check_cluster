"""
Security Group Tests

Validates that security groups allow necessary traffic flows for ROSA clusters.
Each test validates a specific traffic flow expectation.

Documentation:
- ROSA Network Security: https://docs.redhat.com/en/documentation/red_hat_openshift_service_on_aws/4/html/prepare_your_environment/rosa-sts-aws-prereqs#rosa-security-groups
- AWS Security Groups: https://docs.aws.amazon.com/vpc/latest/userguide/vpc-security-groups.html
- ROSA Firewall Requirements: https://docs.redhat.com/en/documentation/red_hat_openshift_service_on_aws/4/html/prepare_your_environment/rosa-sts-aws-prereqs#osd-aws-privatelink-firewall-prerequisites
"""

import json
import pytest
from models.cluster import ClusterData


# Helper functions for checking security group rules

def rule_allows_traffic(rule: dict, protocol: str, from_port: int, to_port: int,
                        direction: str, source_type: str = "any") -> tuple[bool, str]:
    """
    Check if a security group rule allows specific traffic.

    Args:
        rule: Security group rule dict
        protocol: Expected protocol (tcp, udp, icmp, -1 for all)
        from_port: Expected from port
        to_port: Expected to port
        direction: ingress or egress
        source_type: Type of source to check (public, vpc, sg, any)

    Returns:
        Tuple of (matches, details) where details describes the rule
    """
    rule_protocol = rule.get('IpProtocol', '')

    # Check protocol
    if protocol != '-1' and rule_protocol != protocol and rule_protocol != '-1':
        return False, ""

    # Check ports
    rule_from = rule.get('FromPort')
    rule_to = rule.get('ToPort')

    if rule_from is not None and rule_to is not None:
        if not (rule_from <= from_port and rule_to >= to_port):
            return False, ""

    # Get sources
    sources = []
    for ip_range in rule.get('IpRanges', []):
        cidr = ip_range.get('CidrIp', '')
        if cidr:
            sources.append(cidr)
    for sg_pair in rule.get('UserIdGroupPairs', []):
        sg_id = sg_pair.get('GroupId', '')
        if sg_id:
            sources.append(sg_id)

    # Check source type
    if source_type == "public":
        if "0.0.0.0/0" not in sources and "::/0" not in sources:
            return False, ""
    elif source_type == "vpc":
        if not any(_is_private_cidr(s) for s in sources):
            return False, ""
    elif source_type == "sg":
        if not any(s.startswith('sg-') for s in sources):
            return False, ""

    # Build details string
    port_str = f"{from_port}" if from_port == to_port else f"{from_port}-{to_port}"
    source_str = ", ".join(sources) if sources else "any"
    details = f"{protocol}/{port_str} from {source_str}"

    return True, details


def _is_private_cidr(cidr: str) -> bool:
    """Check if CIDR is a private IP range"""
    return (cidr.startswith('10.') or
            cidr.startswith('172.16.') or cidr.startswith('172.17.') or
            cidr.startswith('172.18.') or cidr.startswith('172.19.') or
            cidr.startswith('172.20.') or cidr.startswith('172.21.') or
            cidr.startswith('172.22.') or cidr.startswith('172.23.') or
            cidr.startswith('172.24.') or cidr.startswith('172.25.') or
            cidr.startswith('172.26.') or cidr.startswith('172.27.') or
            cidr.startswith('172.28.') or cidr.startswith('172.29.') or
            cidr.startswith('172.30.') or cidr.startswith('172.31.') or
            cidr.startswith('192.168.'))


def find_rule_for_traffic(sgs: dict, sg_names: list[str], protocol: str,
                          from_port: int, to_port: int, direction: str,
                          source_type: str = "any") -> tuple[bool, str, list[dict]]:
    """
    Search security groups for a rule that allows specific traffic.

    Returns:
        Tuple of (found, details, matching_rule_objects) where details describes matching rules
        and matching_rule_objects contains the actual rule dicts that matched
    """
    matching_rules = []
    matching_objects = []

    for sg_name in sg_names:
        if sg_name not in sgs:
            continue

        sg = sgs[sg_name]
        sg_id = sg.get('GroupId', 'unknown')

        # Get rules based on direction
        rules = sg.get('IpPermissions' if direction == 'ingress' else 'IpPermissionsEgress', [])

        for rule in rules:
            matches, details = rule_allows_traffic(rule, protocol, from_port, to_port,
                                                   direction, source_type)
            if matches:
                matching_rules.append(f"{sg_name}({sg_id}): {details}")
                matching_objects.append({
                    "security_group_name": sg_name,
                    "security_group_id": sg_id,
                    "rule": rule
                })

    if matching_rules:
        return True, "; ".join(matching_rules), matching_objects
    else:
        return False, "No matching rules found", []


# ============================================================================
# API / Control Plane Tests
# ============================================================================

@pytest.mark.security_groups
def test_api_server_access(cluster_data: ClusterData, is_private_cluster: bool):
    """Kubernetes API Server must be accessible on port 6443.

    Why: Port 6443 is the standard Kubernetes API server port. kubectl, oc, and all
    cluster management tools require access to this port to manage the cluster.

    Failure indicates: The API load balancer security group is not allowing inbound traffic
    on port 6443, which would prevent all cluster management operations.
    
    Documentation: https://docs.redhat.com/en/documentation/red_hat_openshift_service_on_aws/4/html/prepare_your_environment/rosa-sts-aws-prereqs#rosa-security-groups
    """
    sgs = cluster_data.get_security_groups_by_infra_id()
    infra_id = cluster_data.infra_id

    api_lb_sgs = [f"{infra_id}-lb", f"{infra_id}-apiserver-lb"]
    source_type = "vpc" if is_private_cluster else "public"

    found, details, matching_objects = find_rule_for_traffic(
        sgs, api_lb_sgs, "tcp", 6443, 6443, "ingress", source_type
    )

    if found:
        print(f"\n✓ Found matching security group rules for Kubernetes API Server (tcp/6443 ingress from {source_type}):")
        print(json.dumps(matching_objects, indent=2))
    else:
        print(f"\n✗ Expected security group rule for Kubernetes API Server:")
        print(json.dumps({
            "expected": {
                "security_groups": api_lb_sgs,
                "rule_type": "ingress",
                "protocol": "tcp",
                "port": 6443,
                "source_type": source_type,
                "description": "Must allow tcp/6443 from " + ("VPC CIDR" if source_type == "vpc" else "0.0.0.0/0 (public)")
            },
            "actual": f"No matching rules found in security groups: {list(sgs.keys())}"
        }, indent=2))

    assert found, f"Kubernetes API Server (tcp/6443 ingress from {source_type}): {details}"


@pytest.mark.security_groups
def test_machine_config_server_access(cluster_data: ClusterData, is_private_cluster: bool):
    """Machine Config Server must be accessible on port 22623.

    Why: The Machine Config Server (MCS) on port 22623 provides Ignition configs
    and machine configuration to nodes during bootstrap and updates.

    Failure indicates: Security group rules are blocking MCS access, which would prevent
    nodes from retrieving configuration and joining the cluster properly.

    Note: MCS should only be accessible via security groups (from cluster nodes),
    never publicly accessible, regardless of cluster type.
    
    Documentation: https://docs.openshift.com/container-platform/latest/architecture/control-plane.html#architecture-machine-config-operator_control-plane
    """
    sgs = cluster_data.get_security_groups_by_infra_id()
    infra_id = cluster_data.infra_id

    api_lb_sgs = [f"{infra_id}-lb", f"{infra_id}-apiserver-lb"]
    # MCS should always be accessible via security groups, not public
    source_type = "sg"

    found, details, matching_objects = find_rule_for_traffic(
        sgs, api_lb_sgs, "tcp", 22623, 22623, "ingress", source_type
    )

    if found:
        print(f"\n✓ Found matching security group rules for Machine Config Server (tcp/22623 ingress from security groups):")
        print(json.dumps(matching_objects, indent=2))
    else:
        print(f"\n✗ Expected security group rule for Machine Config Server:")
        print(json.dumps({
            "expected": {
                "security_groups": api_lb_sgs,
                "rule_type": "ingress",
                "protocol": "tcp",
                "port": 22623,
                "source_type": "security groups (sg-*)",
                "description": "Must allow tcp/22623 from cluster node security groups"
            },
            "actual": f"No matching rules found in security groups: {list(sgs.keys())}"
        }, indent=2))

    assert found, f"Machine Config Server (tcp/22623 ingress from security groups): {details}"


@pytest.mark.security_groups
def test_control_plane_api_access(cluster_data: ClusterData):
    """Control plane must accept API traffic on port 6443
    Documentation: https://docs.redhat.com/en/documentation/red_hat_openshift_service_on_aws/4/html/prepare_your_environment/rosa-sts-aws-prereqs#rosa-security-groups
    """
    sgs = cluster_data.get_security_groups_by_infra_id()
    infra_id = cluster_data.infra_id

    cp_sg = [f"{infra_id}-controlplane"]

    found, details, matching_objects = find_rule_for_traffic(
        sgs, cp_sg, "tcp", 6443, 6443, "ingress", "sg"
    )

    if found:
        print(f"\n✓ Found matching rules for Control plane API access (tcp/6443 ingress):")
        print(json.dumps(matching_objects, indent=2))
    else:
        print(f"\n✗ Expected: Control plane security group must allow tcp/6443 ingress from security groups")

    assert found, f"Control plane API access (tcp/6443 ingress): {details}"


@pytest.mark.security_groups
def test_control_plane_mcs_access(cluster_data: ClusterData):
    """Control plane must accept MCS traffic on port 22623
    Documentation: https://docs.redhat.com/en/documentation/red_hat_openshift_service_on_aws/4/html/prepare_your_environment/rosa-sts-aws-prereqs#rosa-security-groups
    """
    sgs = cluster_data.get_security_groups_by_infra_id()
    infra_id = cluster_data.infra_id

    cp_sg = [f"{infra_id}-controlplane"]

    found, details, matching_objects = find_rule_for_traffic(
        sgs, cp_sg, "tcp", 22623, 22623, "ingress", "sg"
    )

    if found:
        print(f"\n✓ Found matching rules for Control plane MCS access (tcp/22623 ingress):")
        print(json.dumps(matching_objects, indent=2))
    else:
        print(f"\n✗ Expected: Control plane security group must allow tcp/22623 ingress from security groups")

    assert found, f"Control plane MCS access (tcp/22623 ingress): {details}"


# ============================================================================
# Worker Node Tests
# ============================================================================

@pytest.mark.security_groups
def test_worker_ssh_access(cluster_data: ClusterData):
    """Worker nodes must allow SSH access on port 22
    Documentation: https://docs.redhat.com/en/documentation/red_hat_openshift_service_on_aws/4/html/prepare_your_environment/rosa-sts-aws-prereqs#rosa-security-groups
    """
    sgs = cluster_data.get_security_groups_by_infra_id()
    infra_id = cluster_data.infra_id

    worker_sg = [f"{infra_id}-node"]

    found, details, matching_objects = find_rule_for_traffic(
        sgs, worker_sg, "tcp", 22, 22, "ingress", "sg"
    )

    if found:
        print(f"\n✓ Found matching rules for Worker SSH access (tcp/22 ingress):")
        print(json.dumps(matching_objects, indent=2))
    else:
        print(f"\n✗ Expected: Worker node security group must allow tcp/22 ingress from security groups")

    assert found, f"Worker SSH access (tcp/22 ingress): {details}"


@pytest.mark.security_groups
def test_worker_kubelet_access(cluster_data: ClusterData):
    """Worker nodes must allow kubelet API access on port 10250.

    Why: The kubelet API on port 10250 is used by the control plane to monitor node
    health, execute commands in pods (exec/logs), and manage container lifecycle.

    Failure indicates: Security group is blocking kubelet access, which would prevent
    pod operations like kubectl exec, kubectl logs, and health monitoring.
    
    Documentation: https://kubernetes.io/docs/reference/command-line-tools-reference/kubelet/
    """
    sgs = cluster_data.get_security_groups_by_infra_id()
    infra_id = cluster_data.infra_id

    worker_sg = [f"{infra_id}-node"]

    found, details, matching_objects = find_rule_for_traffic(
        sgs, worker_sg, "tcp", 10250, 10250, "ingress", "sg"
    )

    if found:
        print(f"\n✓ Found matching rules for Worker kubelet access (tcp/10250 ingress):")
        print(json.dumps(matching_objects, indent=2))
    else:
        print(f"\n✗ Expected: Worker node security group must allow tcp/10250 ingress from control plane security group")

    assert found, f"Worker kubelet access (tcp/10250 ingress): {details}"


@pytest.mark.security_groups
def test_worker_nodeport_access(cluster_data: ClusterData):
    """Worker nodes must allow NodePort services (30000-32767)
    Documentation: https://docs.redhat.com/en/documentation/red_hat_openshift_service_on_aws/4/html/prepare_your_environment/rosa-sts-aws-prereqs#rosa-security-groups
    """
    sgs = cluster_data.get_security_groups_by_infra_id()
    infra_id = cluster_data.infra_id

    worker_sg = [f"{infra_id}-node"]

    found, details, matching_objects = find_rule_for_traffic(
        sgs, worker_sg, "tcp", 30000, 32767, "ingress", "sg"
    )

    if found:
        print(f"\n✓ Found matching rules for Worker NodePort services (tcp/30000-32767 ingress):")
        print(json.dumps(matching_objects, indent=2))
    else:
        print(f"\n✗ Expected: Worker node security group must allow tcp/30000-32767 ingress from security groups")

    assert found, f"Worker NodePort services (tcp/30000-32767 ingress): {details}"


@pytest.mark.security_groups
def test_worker_vxlan_overlay(cluster_data: ClusterData):
    """Worker nodes must allow VXLAN overlay network on UDP port 4789.

    Why: VXLAN (UDP 4789) is used by OpenShift SDN for pod-to-pod networking across nodes.
    This is essential for container network overlay functionality.

    Failure indicates: The overlay network cannot function, preventing pod-to-pod communication
    across different nodes and breaking application connectivity.
    
    Documentation: https://docs.openshift.com/container-platform/latest/networking/ovn_kubernetes_network_provider/about-ovn-kubernetes.html
    """
    sgs = cluster_data.get_security_groups_by_infra_id()
    infra_id = cluster_data.infra_id

    worker_sg = [f"{infra_id}-node"]

    found, details, matching_objects = find_rule_for_traffic(
        sgs, worker_sg, "udp", 4789, 4789, "ingress", "sg"
    )

    if found:
        print(f"\n✓ Found matching rules for Worker VXLAN overlay (udp/4789 ingress):")
        print(json.dumps(matching_objects, indent=2))
    else:
        print(f"\n✗ Expected: Worker node security group must allow udp/4789 ingress for VXLAN overlay networking")

    assert found, f"Worker VXLAN overlay (udp/4789 ingress): {details}"


@pytest.mark.security_groups
def test_worker_geneve_overlay(cluster_data: ClusterData):
    """Worker nodes must allow Geneve overlay network on UDP port 6081.

    Why: Geneve (UDP 6081) is used by OVN-Kubernetes for pod networking. It provides
    the network overlay for pod-to-pod communication in OVN-based clusters.

    Failure indicates: OVN overlay networking is blocked, preventing pod-to-pod communication
    across nodes and breaking network connectivity for workloads.
    
    Documentation: https://docs.openshift.com/container-platform/latest/networking/ovn_kubernetes_network_provider/about-ovn-kubernetes.html
    """
    sgs = cluster_data.get_security_groups_by_infra_id()
    infra_id = cluster_data.infra_id

    worker_sg = [f"{infra_id}-node"]

    found, details, matching_objects = find_rule_for_traffic(
        sgs, worker_sg, "udp", 6081, 6081, "ingress", "sg"
    )

    if found:
        print(f"\n✓ Found matching rules for Worker Geneve overlay (udp/6081 ingress):")
        print(json.dumps(matching_objects, indent=2))
    else:
        print(f"\n✗ Expected: Worker node security group must allow udp/6081 ingress for Geneve (OVN) overlay networking")

    assert found, f"Worker Geneve overlay (udp/6081 ingress): {details}"


@pytest.mark.security_groups
def test_worker_internal_communication(cluster_data: ClusterData):
    """Worker nodes must allow internal cluster communication (9000-9999)
    Documentation: https://docs.redhat.com/en/documentation/red_hat_openshift_service_on_aws/4/html/prepare_your_environment/rosa-sts-aws-prereqs#rosa-security-groups
    """
    sgs = cluster_data.get_security_groups_by_infra_id()
    infra_id = cluster_data.infra_id

    worker_sg = [f"{infra_id}-node"]

    found, details, matching_objects = find_rule_for_traffic(
        sgs, worker_sg, "tcp", 9000, 9999, "ingress", "sg"
    )

    if found:
        print(f"\n✓ Found matching rules for Worker internal communication (tcp/9000-9999 ingress):")
        print(json.dumps(matching_objects, indent=2))
    else:
        print(f"\n✗ Expected: Worker node security group must allow tcp/9000-9999 ingress for internal cluster communication")

    assert found, f"Worker internal communication (tcp/9000-9999 ingress): {details}"


# ============================================================================
# Egress Tests
# ============================================================================

@pytest.mark.security_groups
def test_all_egress_allowed(cluster_data: ClusterData):
    """All security groups must allow outbound traffic.

    Why: Cluster nodes need outbound connectivity to pull container images, access AWS APIs,
    communicate with external services, and download updates.

    Failure indicates: Egress rules are too restrictive, which would prevent nodes from pulling
    images, accessing cloud APIs, or communicating with external dependencies.
    
    Documentation: https://docs.redhat.com/en/documentation/red_hat_openshift_service_on_aws/4/html/prepare_your_environment/rosa-sts-aws-prereqs#rosa-security-groups
    """
    sgs = cluster_data.get_security_groups_by_infra_id()

    all_sg_names = list(sgs.keys())

    found, details, matching_objects = find_rule_for_traffic(
        sgs, all_sg_names, "-1", 0, 65535, "egress", "any"
    )

    if found:
        print(f"\n✓ Found matching rules for outbound traffic (all protocols egress):")
        print(json.dumps(matching_objects, indent=2))
    else:
        print(f"\n✗ Expected: All security groups must allow unrestricted egress traffic")

    assert found, f"Outbound traffic (all protocols egress): {details}"


# ============================================================================
# etcd Tests (optional)
# ============================================================================

@pytest.mark.security_groups
def test_etcd_client_port(cluster_data: ClusterData):
    """etcd client port (2379) should be accessible (optional)
    Documentation: https://docs.redhat.com/en/documentation/red_hat_openshift_service_on_aws/4/html/prepare_your_environment/rosa-sts-aws-prereqs#rosa-security-groups
    """
    sgs = cluster_data.get_security_groups_by_infra_id()
    infra_id = cluster_data.infra_id

    cp_sg = [f"{infra_id}-controlplane"]

    found, details, matching_objects = find_rule_for_traffic(
        sgs, cp_sg, "tcp", 2379, 2379, "ingress", "sg"
    )

    # This is optional, so we don't fail if not found
    if not found:
        pytest.skip("etcd client port not exposed (optional)")


@pytest.mark.security_groups
def test_etcd_peer_port(cluster_data: ClusterData):
    """etcd peer port (2380) should be accessible (optional)
    Documentation: https://docs.redhat.com/en/documentation/red_hat_openshift_service_on_aws/4/html/prepare_your_environment/rosa-sts-aws-prereqs#rosa-security-groups
    """
    sgs = cluster_data.get_security_groups_by_infra_id()
    infra_id = cluster_data.infra_id

    cp_sg = [f"{infra_id}-controlplane"]

    found, details, matching_objects = find_rule_for_traffic(
        sgs, cp_sg, "tcp", 2380, 2380, "ingress", "sg"
    )

    # This is optional, so we don't fail if not found
    if not found:
        pytest.skip("etcd peer port not exposed (optional)")
