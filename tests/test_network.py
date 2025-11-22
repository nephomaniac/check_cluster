"""
Network Infrastructure Tests

This module validates network infrastructure components:
- Subnets (public/private configuration)
- Route Tables (IGW and NAT routing)
- Internet Gateways (public connectivity)
- NAT Gateways (private subnet egress)
- Elastic IPs (NAT gateway addressing)
- Network ACLs (additional network filtering)
- VPC Peering (cross-VPC connectivity)
- VPC Flow Logs (network monitoring)
"""

import pytest
import json
from pathlib import Path
from typing import Dict, List, Any
from models.cluster import ClusterData


@pytest.mark.network
def test_subnets_exist(cluster_data: ClusterData, infra_id: str):
    """Cluster should have at least one subnet"""
    subnets_file = cluster_data.data_dir / f"{cluster_data.cluster_id}_subnets.json"

    if not subnets_file.exists():
        pytest.skip(f"Subnets file not found: {subnets_file}")

    with open(subnets_file) as f:
        subnets_data = json.load(f)

    subnets = subnets_data.get('Subnets', [])
    assert len(subnets) > 0, f"No subnets found for cluster {infra_id}"


@pytest.mark.network
def test_subnets_in_available_state(cluster_data: ClusterData, infra_id: str):
    """All cluster subnets should be in 'available' state"""
    subnets_file = cluster_data.data_dir / f"{cluster_data.cluster_id}_subnets.json"

    if not subnets_file.exists():
        pytest.skip(f"Subnets file not found: {subnets_file}")

    with open(subnets_file) as f:
        subnets_data = json.load(f)

    subnets = subnets_data.get('Subnets', [])

    # Filter to cluster subnets
    cluster_subnets = [s for s in subnets if any(
        tag.get('Key') == 'Name' and infra_id in tag.get('Value', '')
        for tag in s.get('Tags', [])
    )]

    unavailable_subnets = [
        s['SubnetId'] for s in cluster_subnets
        if s.get('State') != 'available'
    ]

    assert len(unavailable_subnets) == 0, \
        f"Subnets not in 'available' state: {unavailable_subnets}"


@pytest.mark.network
def test_public_and_private_subnets(cluster_data: ClusterData, infra_id: str):
    """Cluster should have both public and private subnets"""
    subnets_file = cluster_data.data_dir / f"{cluster_data.cluster_id}_subnets.json"

    if not subnets_file.exists():
        pytest.skip(f"Subnets file not found: {subnets_file}")

    with open(subnets_file) as f:
        subnets_data = json.load(f)

    subnets = subnets_data.get('Subnets', [])

    # Filter to cluster subnets
    cluster_subnets = [s for s in subnets if any(
        tag.get('Key') == 'Name' and infra_id in tag.get('Value', '')
        for tag in s.get('Tags', [])
    )]

    public_subnets = [s for s in cluster_subnets if s.get('MapPublicIpOnLaunch', False)]
    private_subnets = [s for s in cluster_subnets if not s.get('MapPublicIpOnLaunch', False)]

    assert len(public_subnets) > 0, f"No public subnets found (expected subnets with MapPublicIpOnLaunch=true)"
    assert len(private_subnets) > 0, f"No private subnets found (expected subnets with MapPublicIpOnLaunch=false)"


@pytest.mark.network
def test_subnet_kubernetes_role_tags(cluster_data: ClusterData, infra_id: str):
    """Public subnets should have kubernetes.io/role/elb tag, private should have kubernetes.io/role/internal-elb"""
    subnets_file = cluster_data.data_dir / f"{cluster_data.cluster_id}_subnets.json"

    if not subnets_file.exists():
        pytest.skip(f"Subnets file not found: {subnets_file}")

    with open(subnets_file) as f:
        subnets_data = json.load(f)

    subnets = subnets_data.get('Subnets', [])

    # Filter to cluster subnets
    cluster_subnets = [s for s in subnets if any(
        tag.get('Key') == 'Name' and infra_id in tag.get('Value', '')
        for tag in s.get('Tags', [])
    )]

    issues = []
    for subnet in cluster_subnets:
        subnet_id = subnet.get('SubnetId')
        tags = {tag['Key']: tag['Value'] for tag in subnet.get('Tags', [])}
        is_public = subnet.get('MapPublicIpOnLaunch', False)

        if is_public:
            if 'kubernetes.io/role/elb' not in tags:
                issues.append(f"Public subnet {subnet_id} missing 'kubernetes.io/role/elb' tag")
        else:
            if 'kubernetes.io/role/internal-elb' not in tags:
                issues.append(f"Private subnet {subnet_id} missing 'kubernetes.io/role/internal-elb' tag")

    assert len(issues) == 0, f"Subnet tagging issues: {'; '.join(issues)}"


@pytest.mark.network
def test_internet_gateway_exists(cluster_data: ClusterData, infra_id: str, is_private_cluster: bool):
    """Public clusters should have an Internet Gateway"""
    if is_private_cluster:
        pytest.skip("Private clusters do not require internet gateway for public access")

    igw_file = cluster_data.data_dir / f"{cluster_data.cluster_id}_internet_gateways.json"

    if not igw_file.exists():
        pytest.skip(f"Internet gateway file not found: {igw_file}")

    with open(igw_file) as f:
        igw_data = json.load(f)

    igws = igw_data.get('InternetGateways', [])

    # Filter to cluster IGWs
    cluster_igws = [igw for igw in igws if any(
        tag.get('Key') == 'Name' and infra_id in tag.get('Value', '')
        for tag in igw.get('Tags', [])
    )]

    assert len(cluster_igws) > 0, f"No internet gateway found for public cluster {infra_id}"


@pytest.mark.network
def test_internet_gateway_attached(cluster_data: ClusterData, infra_id: str, is_private_cluster: bool):
    """Internet Gateway should be attached to VPC with 'available' state"""
    if is_private_cluster:
        pytest.skip("Private clusters do not require internet gateway")

    igw_file = cluster_data.data_dir / f"{cluster_data.cluster_id}_internet_gateways.json"

    if not igw_file.exists():
        pytest.skip(f"Internet gateway file not found: {igw_file}")

    with open(igw_file) as f:
        igw_data = json.load(f)

    igws = igw_data.get('InternetGateways', [])

    # Filter to cluster IGWs
    cluster_igws = [igw for igw in igws if any(
        tag.get('Key') == 'Name' and infra_id in tag.get('Value', '')
        for tag in igw.get('Tags', [])
    )]

    issues = []
    for igw in cluster_igws:
        igw_id = igw.get('InternetGatewayId')
        attachments = igw.get('Attachments', [])

        if len(attachments) == 0:
            issues.append(f"IGW {igw_id} has no VPC attachments")
            continue

        for attachment in attachments:
            if attachment.get('State') != 'available':
                issues.append(f"IGW {igw_id} attachment state is '{attachment.get('State')}', expected 'available'")

    assert len(issues) == 0, f"Internet gateway issues: {'; '.join(issues)}"


@pytest.mark.network
def test_nat_gateway_exists(cluster_data: ClusterData, infra_id: str):
    """Cluster should have at least one NAT Gateway for private subnet egress"""
    nat_file = cluster_data.data_dir / f"{cluster_data.cluster_id}_nat_gateways.json"

    if not nat_file.exists():
        pytest.skip(f"NAT gateway file not found: {nat_file}")

    with open(nat_file) as f:
        nat_data = json.load(f)

    nat_gws = nat_data.get('NatGateways', [])

    # Filter to cluster NAT gateways
    cluster_nat_gws = [nat for nat in nat_gws if any(
        tag.get('Key') == 'Name' and infra_id in tag.get('Value', '')
        for tag in nat.get('Tags', [])
    )]

    assert len(cluster_nat_gws) > 0, f"No NAT gateway found for cluster {infra_id}"


@pytest.mark.network
def test_nat_gateway_available(cluster_data: ClusterData, infra_id: str):
    """NAT Gateways should be in 'available' state"""
    nat_file = cluster_data.data_dir / f"{cluster_data.cluster_id}_nat_gateways.json"

    if not nat_file.exists():
        pytest.skip(f"NAT gateway file not found: {nat_file}")

    with open(nat_file) as f:
        nat_data = json.load(f)

    nat_gws = nat_data.get('NatGateways', [])

    # Filter to cluster NAT gateways
    cluster_nat_gws = [nat for nat in nat_gws if any(
        tag.get('Key') == 'Name' and infra_id in tag.get('Value', '')
        for tag in nat.get('Tags', [])
    )]

    unavailable_nats = [
        nat['NatGatewayId'] for nat in cluster_nat_gws
        if nat.get('State') != 'available'
    ]

    assert len(unavailable_nats) == 0, \
        f"NAT gateways not in 'available' state: {unavailable_nats}"


@pytest.mark.network
def test_nat_gateway_has_public_ip(cluster_data: ClusterData, infra_id: str):
    """NAT Gateways should have public IP addresses assigned"""
    nat_file = cluster_data.data_dir / f"{cluster_data.cluster_id}_nat_gateways.json"

    if not nat_file.exists():
        pytest.skip(f"NAT gateway file not found: {nat_file}")

    with open(nat_file) as f:
        nat_data = json.load(f)

    nat_gws = nat_data.get('NatGateways', [])

    # Filter to cluster NAT gateways
    cluster_nat_gws = [nat for nat in nat_gws if any(
        tag.get('Key') == 'Name' and infra_id in tag.get('Value', '')
        for tag in nat.get('Tags', [])
    )]

    issues = []
    for nat in cluster_nat_gws:
        nat_id = nat.get('NatGatewayId')
        addresses = nat.get('NatGatewayAddresses', [])

        if len(addresses) == 0:
            issues.append(f"NAT gateway {nat_id} has no addresses")
            continue

        # Check for public IP in addresses
        has_public_ip = any(addr.get('PublicIp') for addr in addresses)
        if not has_public_ip:
            issues.append(f"NAT gateway {nat_id} has no public IP address")

    assert len(issues) == 0, f"NAT gateway IP issues: {'; '.join(issues)}"


@pytest.mark.network
def test_elastic_ips_for_nat(cluster_data: ClusterData, infra_id: str):
    """Elastic IPs should be allocated for NAT gateways"""
    eip_file = cluster_data.data_dir / f"{cluster_data.cluster_id}_elastic_ips.json"

    if not eip_file.exists():
        pytest.skip(f"Elastic IPs file not found: {eip_file}")

    with open(eip_file) as f:
        eip_data = json.load(f)

    addresses = eip_data.get('Addresses', [])

    # Filter to cluster EIPs
    cluster_eips = [addr for addr in addresses if any(
        tag.get('Key') == 'Name' and infra_id in tag.get('Value', '')
        for tag in addr.get('Tags', [])
    )]

    # Should have at least one EIP for NAT gateway
    assert len(cluster_eips) > 0, f"No Elastic IPs found for cluster {infra_id} NAT gateways"


@pytest.mark.network
def test_route_tables_exist(cluster_data: ClusterData, infra_id: str):
    """Cluster should have route tables configured"""
    rt_file = cluster_data.data_dir / f"{cluster_data.cluster_id}_route_tables.json"

    if not rt_file.exists():
        pytest.skip(f"Route tables file not found: {rt_file}")

    with open(rt_file) as f:
        rt_data = json.load(f)

    route_tables = rt_data.get('RouteTables', [])

    # Filter to cluster route tables
    cluster_rts = [rt for rt in route_tables if any(
        tag.get('Key') == 'Name' and infra_id in tag.get('Value', '')
        for tag in rt.get('Tags', [])
    )]

    assert len(cluster_rts) > 0, f"No route tables found for cluster {infra_id}"


@pytest.mark.network
def test_public_route_to_internet_gateway(cluster_data: ClusterData, infra_id: str, is_private_cluster: bool):
    """Public subnets should have route to internet gateway (0.0.0.0/0)"""
    if is_private_cluster:
        pytest.skip("Private clusters do not require IGW routes")

    rt_file = cluster_data.data_dir / f"{cluster_data.cluster_id}_route_tables.json"

    if not rt_file.exists():
        pytest.skip(f"Route tables file not found: {rt_file}")

    with open(rt_file) as f:
        rt_data = json.load(f)

    route_tables = rt_data.get('RouteTables', [])

    # Filter to cluster route tables for public subnets
    public_rts = [rt for rt in route_tables if any(
        tag.get('Key') == 'Name' and infra_id in tag.get('Value', '') and 'public' in tag.get('Value', '').lower()
        for tag in rt.get('Tags', [])
    )]

    if len(public_rts) == 0:
        pytest.skip("No public route tables found")

    issues = []
    for rt in public_rts:
        rt_id = rt.get('RouteTableId')
        routes = rt.get('Routes', [])

        # Check for default route (0.0.0.0/0) to IGW
        has_igw_route = any(
            route.get('DestinationCidrBlock') == '0.0.0.0/0' and
            route.get('GatewayId', '').startswith('igw-')
            for route in routes
        )

        if not has_igw_route:
            issues.append(f"Public route table {rt_id} missing 0.0.0.0/0 route to internet gateway")

    assert len(issues) == 0, f"Public route table issues: {'; '.join(issues)}"


@pytest.mark.network
def test_private_route_to_nat_gateway(cluster_data: ClusterData, infra_id: str):
    """Private subnets should have route to NAT gateway (0.0.0.0/0)"""
    rt_file = cluster_data.data_dir / f"{cluster_data.cluster_id}_route_tables.json"

    if not rt_file.exists():
        pytest.skip(f"Route tables file not found: {rt_file}")

    with open(rt_file) as f:
        rt_data = json.load(f)

    route_tables = rt_data.get('RouteTables', [])

    # Filter to cluster route tables for private subnets
    private_rts = [rt for rt in route_tables if any(
        tag.get('Key') == 'Name' and infra_id in tag.get('Value', '') and 'private' in tag.get('Value', '').lower()
        for tag in rt.get('Tags', [])
    )]

    if len(private_rts) == 0:
        pytest.skip("No private route tables found")

    issues = []
    for rt in private_rts:
        rt_id = rt.get('RouteTableId')
        routes = rt.get('Routes', [])

        # Check for default route (0.0.0.0/0) to NAT gateway
        has_nat_route = any(
            route.get('DestinationCidrBlock') == '0.0.0.0/0' and
            route.get('NatGatewayId', '').startswith('nat-')
            for route in routes
        )

        if not has_nat_route:
            issues.append(f"Private route table {rt_id} missing 0.0.0.0/0 route to NAT gateway")

    assert len(issues) == 0, f"Private route table issues: {'; '.join(issues)}"


@pytest.mark.network
def test_network_acls_exist(cluster_data: ClusterData, infra_id: str):
    """Cluster VPC should have Network ACLs configured (informational check)"""
    nacl_file = cluster_data.data_dir / f"{cluster_data.cluster_id}_network_acls.json"

    if not nacl_file.exists():
        pytest.skip(f"Network ACLs file not found: {nacl_file}")

    with open(nacl_file) as f:
        nacl_data = json.load(f)

    nacls = nacl_data.get('NetworkAcls', [])

    # NACLs may not be tagged with infra_id (default VPC NACLs)
    # This is an informational check - empty array is acceptable
    if len(nacls) == 0:
        pytest.skip("No network ACLs found (may not be tagged with infra_id, this is acceptable)")


@pytest.mark.network
def test_vpc_flow_logs_configured(cluster_data: ClusterData, infra_id: str):
    """Check if VPC Flow Logs are configured (optional but recommended)"""
    flow_logs_file = cluster_data.data_dir / f"{cluster_data.cluster_id}_vpc_flow_logs.json"

    if not flow_logs_file.exists():
        pytest.skip(f"VPC Flow Logs file not found: {flow_logs_file}")

    with open(flow_logs_file) as f:
        flow_logs_data = json.load(f)

    flow_logs = flow_logs_data.get('FlowLogs', [])

    # This is informational - flow logs are optional but recommended
    # We don't fail the test, just report the status
    if len(flow_logs) == 0:
        pytest.skip("VPC Flow Logs not configured (optional feature)")

    # If flow logs exist, check they're in active state
    active_flow_logs = [fl for fl in flow_logs if fl.get('FlowLogStatus') == 'ACTIVE']

    assert len(active_flow_logs) > 0, \
        f"VPC Flow Logs exist but none are in 'ACTIVE' state"
