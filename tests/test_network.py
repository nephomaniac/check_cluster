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
def test_subnets_exist(cluster_data: ClusterData, infra_id: str, request):
    """Cluster should have at least one subnet

    Why: Subnets provide IP address ranges for cluster resources and enable network isolation.

    Failure indicates: No subnet data was collected or subnets don't exist in AWS.

    Success indicates: Subnet data exists and was successfully collected.
    """
    subnets_file = cluster_data.aws_dir / f"{cluster_data.cluster_id}_subnets.json"

    if not subnets_file.exists():
        # Import diagnostic helper
        from utils.aws_resource_diagnostics import diagnose_missing_aws_resource

        # Get comprehensive diagnostics
        diagnostics = diagnose_missing_aws_resource(
            cluster_data=cluster_data,
            resource_type="Subnets",
            expected_file=f"{cluster_data.cluster_id}_subnets.json",
            api_service="ec2",
            api_operation="describe_subnets",
            resource_identifier=infra_id
        )

        # Correlate CloudTrail events for deleted subnets
        from utils.test_helpers import correlate_cloudtrail_events_for_resources

        ct_result = correlate_cloudtrail_events_for_resources(
            cluster_data=cluster_data,
            resource_identifiers=[infra_id],
            resource_type="Subnet",
            event_types=["Delete", "DeleteSubnet"],
            pytest_request=request
        )

        # If only installer role events, treat as informational (expected behavior)
        if ct_result['only_installer_events']:
            pytest.skip(
                f"INFORMATIONAL: No subnets data found, but CloudTrail shows "
                f"only installer role activity (expected during cluster installation).\n\n"
                f"{diagnostics}\n\n{ct_result['formatted_message']}"
            )

        pytest.fail(f"No subnets data found.\n\n{diagnostics}")

    with open(subnets_file) as f:
        subnets_data = json.load(f)

    subnets = subnets_data.get('Subnets', [])

    if not subnets:
        # Import diagnostic helper
        from utils.aws_resource_diagnostics import diagnose_missing_aws_resource

        # File exists but contains no subnets - get diagnostics
        diagnostics = diagnose_missing_aws_resource(
            cluster_data=cluster_data,
            resource_type="Subnets",
            expected_file=f"{cluster_data.cluster_id}_subnets.json",
            api_service="ec2",
            api_operation="describe_subnets",
            resource_identifier=infra_id
        )

        # Correlate CloudTrail events for deleted subnets
        from utils.test_helpers import correlate_cloudtrail_events_for_resources

        ct_result = correlate_cloudtrail_events_for_resources(
            cluster_data=cluster_data,
            resource_identifiers=[infra_id],
            resource_type="Subnet",
            event_types=["Delete", "DeleteSubnet"],
            pytest_request=request
        )

        pytest.fail(f"No subnets found for cluster {infra_id}.\n\n{diagnostics}")

    print(f"\n✓ Found {len(subnets)} subnets:")
    subnet_summary = [{
        "SubnetId": s.get("SubnetId"),
        "AvailabilityZone": s.get("AvailabilityZone"),
        "CidrBlock": s.get("CidrBlock"),
        "MapPublicIpOnLaunch": s.get("MapPublicIpOnLaunch", False)
    } for s in subnets]
    print(json.dumps(subnet_summary, indent=2))

    assert len(subnets) > 0, f"No subnets found for cluster {infra_id}"


@pytest.mark.network
def test_subnets_in_available_state(cluster_data: ClusterData, infra_id: str):
    """All cluster subnets should be in 'available' state"""
    subnets_file = cluster_data.aws_dir / f"{cluster_data.cluster_id}_subnets.json"

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

    if len(unavailable_subnets) == 0:
        print(f"\n✓ All {len(cluster_subnets)} subnets in available state:")
        subnet_states = [{
            "SubnetId": s.get("SubnetId"),
            "State": s.get("State")
        } for s in cluster_subnets]
        print(json.dumps(subnet_states, indent=2))
    else:
        print(f"\n✗ Subnets not in available state:")
        print(json.dumps(unavailable_subnets, indent=2))

    assert len(unavailable_subnets) == 0, \
        f"Subnets not in 'available' state: {unavailable_subnets}"


@pytest.mark.network
def test_public_and_private_subnets(cluster_data: ClusterData, infra_id: str):
    """Cluster should have both public and private subnets"""
    subnets_file = cluster_data.aws_dir / f"{cluster_data.cluster_id}_subnets.json"

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

    print(f"\n✓ Subnet configuration:")
    print(json.dumps({
        "PublicSubnets": [{
            "SubnetId": s.get("SubnetId"),
            "CidrBlock": s.get("CidrBlock"),
            "AvailabilityZone": s.get("AvailabilityZone")
        } for s in public_subnets],
        "PrivateSubnets": [{
            "SubnetId": s.get("SubnetId"),
            "CidrBlock": s.get("CidrBlock"),
            "AvailabilityZone": s.get("AvailabilityZone")
        } for s in private_subnets],
        "PublicCount": len(public_subnets),
        "PrivateCount": len(private_subnets)
    }, indent=2))

    assert len(public_subnets) > 0, f"No public subnets found (expected subnets with MapPublicIpOnLaunch=true)"
    assert len(private_subnets) > 0, f"No private subnets found (expected subnets with MapPublicIpOnLaunch=false)"


@pytest.mark.network
def test_subnet_kubernetes_role_tags(cluster_data: ClusterData, infra_id: str):
    """Public subnets should have kubernetes.io/role/elb tag, private should have kubernetes.io/role/internal-elb"""
    subnets_file = cluster_data.aws_dir / f"{cluster_data.cluster_id}_subnets.json"

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
    subnet_role_tags = []

    for subnet in cluster_subnets:
        subnet_id = subnet.get('SubnetId')
        tags = {tag['Key']: tag['Value'] for tag in subnet.get('Tags', [])}
        is_public = subnet.get('MapPublicIpOnLaunch', False)

        expected_tag = 'kubernetes.io/role/elb' if is_public else 'kubernetes.io/role/internal-elb'
        has_tag = expected_tag in tags

        subnet_role_tags.append({
            "SubnetId": subnet_id,
            "IsPublic": is_public,
            "ExpectedTag": expected_tag,
            "HasTag": has_tag
        })

        if is_public:
            if 'kubernetes.io/role/elb' not in tags:
                issues.append(f"Public subnet {subnet_id} missing 'kubernetes.io/role/elb' tag")
        else:
            if 'kubernetes.io/role/internal-elb' not in tags:
                issues.append(f"Private subnet {subnet_id} missing 'kubernetes.io/role/internal-elb' tag")

    if len(issues) == 0:
        print(f"\n✓ All subnets have correct Kubernetes role tags:")
        print(json.dumps(subnet_role_tags, indent=2))
    else:
        print(f"\n✗ Subnet tagging issues:")
        print(json.dumps([tag for tag in subnet_role_tags if not tag["HasTag"]], indent=2))

    assert len(issues) == 0, f"Subnet tagging issues: {'; '.join(issues)}"


@pytest.mark.network
def test_internet_gateway_exists(cluster_data: ClusterData, infra_id: str, is_private_cluster: bool, request):
    """Public clusters should have an Internet Gateway"""
    if is_private_cluster:
        pytest.skip("Private clusters do not require internet gateway for public access")

    igw_file = cluster_data.aws_dir / f"{cluster_data.cluster_id}_internet_gateways.json"

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

    if cluster_igws:
        print(f"\n✓ Found {len(cluster_igws)} internet gateway(s):")
        igw_summary = [{
            "InternetGatewayId": igw.get("InternetGatewayId"),
            "Attachments": igw.get("Attachments", [])
        } for igw in cluster_igws]
        print(json.dumps(igw_summary, indent=2))
    else:
        print(f"\n✗ No internet gateway found for cluster {infra_id}")

        # Correlate CloudTrail events for deleted internet gateways
        from utils.test_helpers import correlate_cloudtrail_events_for_resources

        ct_result = correlate_cloudtrail_events_for_resources(
            cluster_data=cluster_data,
            resource_identifiers=[infra_id],
            resource_type="Internet Gateway",
            event_types=["Delete", "DeleteInternetGateway", "Detach", "DetachInternetGateway"],
            pytest_request=request
        )

    assert len(cluster_igws) > 0, f"No internet gateway found for public cluster {infra_id}"


@pytest.mark.network
def test_internet_gateway_attached(cluster_data: ClusterData, infra_id: str, is_private_cluster: bool):
    """Internet Gateway should be attached to VPC with 'available' state"""
    if is_private_cluster:
        pytest.skip("Private clusters do not require internet gateway")

    igw_file = cluster_data.aws_dir / f"{cluster_data.cluster_id}_internet_gateways.json"

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
    igw_attachment_status = []

    for igw in cluster_igws:
        igw_id = igw.get('InternetGatewayId')
        attachments = igw.get('Attachments', [])

        if len(attachments) == 0:
            issues.append(f"IGW {igw_id} has no VPC attachments")
            igw_attachment_status.append({
                "InternetGatewayId": igw_id,
                "AttachmentCount": 0,
                "Status": "No attachments"
            })
            continue

        for attachment in attachments:
            state = attachment.get('State')
            igw_attachment_status.append({
                "InternetGatewayId": igw_id,
                "VpcId": attachment.get('VpcId'),
                "State": state
            })

            if state != 'available':
                issues.append(f"IGW {igw_id} attachment state is '{state}', expected 'available'")

    if len(issues) == 0:
        print(f"\n✓ All internet gateways properly attached:")
        print(json.dumps(igw_attachment_status, indent=2))
    else:
        print(f"\n✗ Internet gateway attachment issues:")
        print(json.dumps(igw_attachment_status, indent=2))

    assert len(issues) == 0, f"Internet gateway issues: {'; '.join(issues)}"


@pytest.mark.network
def test_nat_gateway_exists(cluster_data: ClusterData, infra_id: str, request):
    """Cluster should have at least one NAT Gateway for private subnet egress"""
    nat_file = cluster_data.aws_dir / f"{cluster_data.cluster_id}_nat_gateways.json"

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

    if cluster_nat_gws:
        print(f"\n✓ Found {len(cluster_nat_gws)} NAT gateway(s):")
        nat_summary = [{
            "NatGatewayId": nat.get("NatGatewayId"),
            "SubnetId": nat.get("SubnetId"),
            "State": nat.get("State")
        } for nat in cluster_nat_gws]
        print(json.dumps(nat_summary, indent=2))
    else:
        print(f"\n✗ No NAT gateway found for cluster {infra_id}")

        # Correlate CloudTrail events for deleted NAT gateways
        from utils.test_helpers import correlate_cloudtrail_events_for_resources

        ct_result = correlate_cloudtrail_events_for_resources(
            cluster_data=cluster_data,
            resource_identifiers=[infra_id],
            resource_type="NAT Gateway",
            event_types=["Delete", "DeleteNatGateway"],
            pytest_request=request
        )

    assert len(cluster_nat_gws) > 0, f"No NAT gateway found for cluster {infra_id}"


@pytest.mark.network
def test_nat_gateway_available(cluster_data: ClusterData, infra_id: str):
    """NAT Gateways should be in 'available' state"""
    nat_file = cluster_data.aws_dir / f"{cluster_data.cluster_id}_nat_gateways.json"

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

    if len(unavailable_nats) == 0:
        print(f"\n✓ All {len(cluster_nat_gws)} NAT gateways in available state:")
        nat_states = [{
            "NatGatewayId": nat.get("NatGatewayId"),
            "State": nat.get("State"),
            "SubnetId": nat.get("SubnetId")
        } for nat in cluster_nat_gws]
        print(json.dumps(nat_states, indent=2))
    else:
        print(f"\n✗ NAT gateways not in available state:")
        print(json.dumps(unavailable_nats, indent=2))

    assert len(unavailable_nats) == 0, \
        f"NAT gateways not in 'available' state: {unavailable_nats}"


@pytest.mark.network
def test_nat_gateway_has_public_ip(cluster_data: ClusterData, infra_id: str):
    """NAT Gateways should have public IP addresses assigned"""
    nat_file = cluster_data.aws_dir / f"{cluster_data.cluster_id}_nat_gateways.json"

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
    nat_ip_details = []

    for nat in cluster_nat_gws:
        nat_id = nat.get('NatGatewayId')
        addresses = nat.get('NatGatewayAddresses', [])

        if len(addresses) == 0:
            issues.append(f"NAT gateway {nat_id} has no addresses")
            nat_ip_details.append({
                "NatGatewayId": nat_id,
                "AddressCount": 0,
                "HasPublicIP": False
            })
            continue

        # Check for public IP in addresses
        public_ips = [addr.get('PublicIp') for addr in addresses if addr.get('PublicIp')]
        has_public_ip = len(public_ips) > 0

        nat_ip_details.append({
            "NatGatewayId": nat_id,
            "PublicIPs": public_ips,
            "PrivateIPs": [addr.get('PrivateIp') for addr in addresses if addr.get('PrivateIp')],
            "HasPublicIP": has_public_ip
        })

        if not has_public_ip:
            issues.append(f"NAT gateway {nat_id} has no public IP address")

    if len(issues) == 0:
        print(f"\n✓ All NAT gateways have public IP addresses:")
        print(json.dumps(nat_ip_details, indent=2))
    else:
        print(f"\n✗ NAT gateway IP issues:")
        print(json.dumps([detail for detail in nat_ip_details if not detail["HasPublicIP"]], indent=2))

    assert len(issues) == 0, f"NAT gateway IP issues: {'; '.join(issues)}"


@pytest.mark.network
def test_elastic_ips_for_nat(cluster_data: ClusterData, infra_id: str):
    """Elastic IPs should be allocated for NAT gateways"""
    eip_file = cluster_data.aws_dir / f"{cluster_data.cluster_id}_elastic_ips.json"

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

    if cluster_eips:
        print(f"\n✓ Found {len(cluster_eips)} Elastic IPs for NAT gateways:")
        eip_summary = [{
            "AllocationId": addr.get("AllocationId"),
            "PublicIp": addr.get("PublicIp"),
            "AssociationId": addr.get("AssociationId"),
            "NetworkInterfaceId": addr.get("NetworkInterfaceId")
        } for addr in cluster_eips]
        print(json.dumps(eip_summary, indent=2))
    else:
        print(f"\n✗ No Elastic IPs found for cluster {infra_id}")

    # Should have at least one EIP for NAT gateway
    assert len(cluster_eips) > 0, f"No Elastic IPs found for cluster {infra_id} NAT gateways"


@pytest.mark.network
def test_route_tables_exist(cluster_data: ClusterData, infra_id: str):
    """Cluster should have route tables configured"""
    rt_file = cluster_data.aws_dir / f"{cluster_data.cluster_id}_route_tables.json"

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

    if cluster_rts:
        print(f"\n✓ Found {len(cluster_rts)} route tables:")
        rt_summary = [{
            "RouteTableId": rt.get("RouteTableId"),
            "VpcId": rt.get("VpcId"),
            "AssociationCount": len(rt.get("Associations", [])),
            "RouteCount": len(rt.get("Routes", []))
        } for rt in cluster_rts]
        print(json.dumps(rt_summary, indent=2))
    else:
        print(f"\n✗ No route tables found for cluster {infra_id}")

    assert len(cluster_rts) > 0, f"No route tables found for cluster {infra_id}"


@pytest.mark.network
def test_public_route_to_internet_gateway(cluster_data: ClusterData, infra_id: str, is_private_cluster: bool):
    """Public subnets should have route to internet gateway (0.0.0.0/0)"""
    if is_private_cluster:
        pytest.skip("Private clusters do not require IGW routes")

    rt_file = cluster_data.aws_dir / f"{cluster_data.cluster_id}_route_tables.json"

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
    public_rt_routes = []

    for rt in public_rts:
        rt_id = rt.get('RouteTableId')
        routes = rt.get('Routes', [])

        # Check for default route (0.0.0.0/0) to IGW
        igw_routes = [r for r in routes if r.get('DestinationCidrBlock') == '0.0.0.0/0' and r.get('GatewayId', '').startswith('igw-')]
        has_igw_route = len(igw_routes) > 0

        public_rt_routes.append({
            "RouteTableId": rt_id,
            "HasIGWRoute": has_igw_route,
            "Routes": [{
                "Destination": r.get("DestinationCidrBlock"),
                "Gateway": r.get("GatewayId", r.get("NatGatewayId", "local"))
            } for r in routes]
        })

        if not has_igw_route:
            issues.append(f"Public route table {rt_id} missing 0.0.0.0/0 route to internet gateway")

    if len(issues) == 0:
        print(f"\n✓ All public route tables have IGW routes:")
        print(json.dumps(public_rt_routes, indent=2))
    else:
        print(f"\n✗ Public route table issues:")
        print(json.dumps([rt for rt in public_rt_routes if not rt["HasIGWRoute"]], indent=2))

    assert len(issues) == 0, f"Public route table issues: {'; '.join(issues)}"


@pytest.mark.network
def test_private_route_to_nat_gateway(cluster_data: ClusterData, infra_id: str):
    """Private subnets should have route to NAT gateway (0.0.0.0/0)"""
    rt_file = cluster_data.aws_dir / f"{cluster_data.cluster_id}_route_tables.json"

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
    private_rt_routes = []

    for rt in private_rts:
        rt_id = rt.get('RouteTableId')
        routes = rt.get('Routes', [])

        # Check for default route (0.0.0.0/0) to NAT gateway
        nat_routes = [r for r in routes if r.get('DestinationCidrBlock') == '0.0.0.0/0' and r.get('NatGatewayId', '').startswith('nat-')]
        has_nat_route = len(nat_routes) > 0

        private_rt_routes.append({
            "RouteTableId": rt_id,
            "HasNATRoute": has_nat_route,
            "Routes": [{
                "Destination": r.get("DestinationCidrBlock"),
                "Target": r.get("NatGatewayId", r.get("GatewayId", "local"))
            } for r in routes]
        })

        if not has_nat_route:
            issues.append(f"Private route table {rt_id} missing 0.0.0.0/0 route to NAT gateway")

    if len(issues) == 0:
        print(f"\n✓ All private route tables have NAT gateway routes:")
        print(json.dumps(private_rt_routes, indent=2))
    else:
        print(f"\n✗ Private route table issues:")
        print(json.dumps([rt for rt in private_rt_routes if not rt["HasNATRoute"]], indent=2))

    assert len(issues) == 0, f"Private route table issues: {'; '.join(issues)}"


@pytest.mark.network
def test_network_acls_exist(cluster_data: ClusterData, infra_id: str):
    """Cluster VPC should have Network ACLs configured (informational check)"""
    nacl_file = cluster_data.aws_dir / f"{cluster_data.cluster_id}_network_acls.json"

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
    flow_logs_file = cluster_data.aws_dir / f"{cluster_data.cluster_id}_vpc_flow_logs.json"

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
