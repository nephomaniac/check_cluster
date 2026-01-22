"""
PrivateLink Infrastructure Tests

This module validates PrivateLink-specific infrastructure for ROSA clusters:
- VPC Endpoints (Interface and Gateway types)
- VPC Endpoint Services
- VPC Endpoint Connections
- Private DNS configuration
- Security group rules for endpoint access
- Route table entries for gateway endpoints

Documentation:
- ROSA PrivateLink Overview: https://docs.redhat.com/en/documentation/red_hat_openshift_service_on_aws/4/html/architecture/rosa-architecture-models#rosa-architecture-privatelink
- AWS PrivateLink Prerequisites: https://docs.redhat.com/en/documentation/red_hat_openshift_service_on_aws/4/html/prepare_your_environment/rosa-sts-aws-prereqs#rosa-privatelink-aws-vpc-requirements
- VPC Endpoint Configuration: https://docs.redhat.com/en/documentation/red_hat_openshift_service_on_aws/4/html/install_rosa_classic_clusters/rosa-sts-creating-a-cluster-quickly#rosa-sts-creating-cluster-using-customizations_rosa-sts-creating-a-cluster-quickly
"""

import pytest
import json
from pathlib import Path
from typing import Dict, List, Any
from models.cluster import ClusterData


# Required VPC endpoints for ROSA PrivateLink clusters
REQUIRED_INTERFACE_ENDPOINTS = {
    'ec2': 'com.amazonaws.{region}.ec2',
    'elasticloadbalancing': 'com.amazonaws.{region}.elasticloadbalancing',
    'sts': 'com.amazonaws.{region}.sts',
}

REQUIRED_GATEWAY_ENDPOINTS = {
    's3': 'com.amazonaws.{region}.s3',
}

# Optional but recommended endpoints
OPTIONAL_ENDPOINTS = {
    'ecr.api': 'com.amazonaws.{region}.ecr.api',
    'ecr.dkr': 'com.amazonaws.{region}.ecr.dkr',
}


def get_vpc_endpoints(cluster_data: ClusterData) -> List[Dict[str, Any]]:
    """Load VPC endpoints from cluster data"""
    vpc_endpoints_file = cluster_data.aws_dir / f"{cluster_data.cluster_id}_vpc_endpoints.json"

    if not vpc_endpoints_file.exists():
        return []

    with open(vpc_endpoints_file) as f:
        data = json.load(f)

    return data.get('VpcEndpoints', [])


def get_vpc_endpoint_service(cluster_data: ClusterData) -> Dict[str, Any]:
    """Load VPC endpoint service configuration"""
    service_file = cluster_data.aws_dir / f"{cluster_data.cluster_id}_vpc_endpoint_service.json"

    if not service_file.exists():
        return {}

    with open(service_file) as f:
        data = json.load(f)

    return data


def get_vpc_endpoint_connections(cluster_data: ClusterData) -> List[Dict[str, Any]]:
    """Load VPC endpoint service connections"""
    conn_file = cluster_data.aws_dir / f"{cluster_data.cluster_id}_vpc_endpoint_service_conns.json"

    if not conn_file.exists():
        return []

    with open(conn_file) as f:
        data = json.load(f)

    return data.get('VpcEndpointConnections', [])


@pytest.mark.network
def test_privatelink_requires_vpc_endpoints(cluster_data: ClusterData, is_privatelink: bool):
    """PrivateLink clusters must have VPC endpoints for AWS services in the cluster VPC

    Why: PrivateLink clusters use VPC endpoints instead of NAT gateways to access AWS services.
    Without VPC endpoints, cluster instances cannot reach S3 (for ignition configs), EC2 API, ELB API, etc.

    IMPORTANT DISTINCTION:
    - VPC Endpoint SERVICE (customer → cluster API): Managed by ROSA, shown in VPC endpoint service connections
    - VPC Endpoints for AWS services (cluster → S3, EC2, etc.): Must be created in the cluster's VPC

    Failure indicates: Cluster VPC lacks VPC endpoints for AWS services. This is a critical configuration error.

    Success indicates: VPC endpoints exist in the cluster VPC (further tests validate which endpoints are present).

    Reference: https://docs.redhat.com/en/documentation/red_hat_openshift_service_on_aws/4/html/prepare_your_environment/rosa-sts-aws-prereqs#rosa-privatelink-aws-vpc-requirements
    
    Documentation: https://docs.redhat.com/en/documentation/red_hat_openshift_service_on_aws/4/html/architecture/rosa-architecture-models#rosa-architecture-privatelink
    """
    if not is_privatelink:
        pytest.skip("Not a PrivateLink cluster")

    vpc_endpoints = get_vpc_endpoints(cluster_data)

    # Check VPC endpoint service connections (customer → cluster)
    vpc_endpoint_conns = get_vpc_endpoint_connections(cluster_data)

    print("\n" + "="*80)
    print("PrivateLink Architecture Check")
    print("="*80)

    if vpc_endpoint_conns:
        print(f"\n✓ VPC Endpoint Service has {len(vpc_endpoint_conns)} customer connection(s):")
        for conn in vpc_endpoint_conns:
            conn_info = {
                "Purpose": "Customer VPC → Cluster API",
                "VpcEndpointId": conn.get("VpcEndpointId"),
                "VpcEndpointOwner": conn.get("VpcEndpointOwner"),
                "State": conn.get("VpcEndpointState"),
                "Note": "This is for customer access TO the cluster, not cluster access to AWS"
            }
            print(json.dumps(conn_info, indent=2))
    else:
        print("\n⚠ No VPC endpoint service connections found (customer connections)")

    print("\n" + "-"*80)

    if not vpc_endpoints:
        print("\n✗ Cluster VPC has NO VPC endpoints for AWS services")
        print("\nThis is a CRITICAL configuration error!")
        print("\nPrivateLink clusters require VPC endpoints IN THE CLUSTER VPC for:")
        print("  - S3 (gateway endpoint) - for ignition configs and image registry")
        print("  - EC2 (interface endpoint) - for EC2 API operations")
        print("  - Elastic Load Balancing (interface endpoint) - for NLB operations")
        print("  - STS (interface endpoint) - for IAM role assumption")
        print("\nThese are SEPARATE from the VPC endpoint service connection shown above.")
        print("The service connection is for customer → cluster API connectivity.")
        print("These endpoints are for cluster → AWS services connectivity.")
        print("\nWithout these endpoints, cluster instances cannot access AWS services,")
        print("preventing bootstrap and installation from completing.")
    else:
        print(f"\n✓ Found {len(vpc_endpoints)} VPC endpoint(s) for AWS services:")
        endpoint_summary = [{
            "Purpose": "Cluster VPC → AWS Services",
            "VpcEndpointId": ep.get("VpcEndpointId"),
            "ServiceName": ep.get("ServiceName"),
            "VpcEndpointType": ep.get("VpcEndpointType"),
            "State": ep.get("State")
        } for ep in vpc_endpoints]
        print(json.dumps(endpoint_summary, indent=2))

    print("="*80 + "\n")

    assert len(vpc_endpoints) > 0, \
        "Cluster VPC has NO VPC endpoints for AWS services. This will cause cluster installation failure. " \
        "Create required VPC endpoints in the cluster's VPC: S3 (gateway), EC2, ELB, STS (interface). " \
        "Note: VPC endpoint service connections for customer access exist, but are separate from AWS service endpoints."


@pytest.mark.network
def test_privatelink_has_required_interface_endpoints(cluster_data: ClusterData, is_privatelink: bool):
    """PrivateLink clusters must have required interface endpoints (EC2, ELB, STS)

    Why: Interface endpoints provide private connectivity to AWS services without requiring
    internet gateway or NAT gateway. These are essential for cluster operations.

    Failure indicates: One or more required interface endpoints are missing.

    Success indicates: All required interface endpoints are present.

    Reference: https://docs.redhat.com/en/documentation/red_hat_openshift_service_on_aws/4/html/prepare_your_environment/rosa-sts-aws-prereqs#rosa-privatelink-aws-vpc-requirements
    
    Documentation: https://docs.redhat.com/en/documentation/red_hat_openshift_service_on_aws/4/html/architecture/rosa-architecture-models#rosa-architecture-privatelink
    """
    if not is_privatelink:
        pytest.skip("Not a PrivateLink cluster")

    vpc_endpoints = get_vpc_endpoints(cluster_data)

    if not vpc_endpoints:
        pytest.fail("No VPC endpoints found - see test_privatelink_requires_vpc_endpoints")

    region = cluster_data.region

    # Map service names to endpoint IDs
    interface_endpoints = [ep for ep in vpc_endpoints if ep.get('VpcEndpointType') == 'Interface']
    endpoint_services = {ep.get('ServiceName') for ep in interface_endpoints}

    missing_endpoints = []
    found_endpoints = []

    for service_key, service_template in REQUIRED_INTERFACE_ENDPOINTS.items():
        expected_service = service_template.format(region=region)

        if expected_service in endpoint_services:
            # Find the endpoint
            ep = next(ep for ep in interface_endpoints if ep.get('ServiceName') == expected_service)
            found_endpoints.append({
                "Service": service_key,
                "ServiceName": expected_service,
                "VpcEndpointId": ep.get("VpcEndpointId"),
                "State": ep.get("State")
            })
        else:
            missing_endpoints.append({
                "Service": service_key,
                "RequiredServiceName": expected_service
            })

    if not missing_endpoints:
        print(f"\n✓ All required interface endpoints present:")
        print(json.dumps(found_endpoints, indent=2))
    else:
        print(f"\n✗ Missing required interface endpoints:")
        print(json.dumps(missing_endpoints, indent=2))

        if found_endpoints:
            print(f"\nFound endpoints:")
            print(json.dumps(found_endpoints, indent=2))

    assert len(missing_endpoints) == 0, \
        f"Missing {len(missing_endpoints)} required interface endpoint(s). " \
        f"Create these VPC endpoints: {', '.join(ep['Service'] for ep in missing_endpoints)}"


@pytest.mark.network
def test_privatelink_has_s3_gateway_endpoint(cluster_data: ClusterData, is_privatelink: bool):
    """PrivateLink clusters must have S3 gateway endpoint

    Why: S3 gateway endpoint is required for downloading ignition configs and container images.
    Gateway endpoints are more efficient than interface endpoints for S3.

    Failure indicates: S3 gateway endpoint is missing.

    Success indicates: S3 gateway endpoint exists.
    
    Documentation: https://docs.redhat.com/en/documentation/red_hat_openshift_service_on_aws/4/html/architecture/rosa-architecture-models#rosa-architecture-privatelink
    """
    if not is_privatelink:
        pytest.skip("Not a PrivateLink cluster")

    vpc_endpoints = get_vpc_endpoints(cluster_data)

    if not vpc_endpoints:
        pytest.fail("No VPC endpoints found - see test_privatelink_requires_vpc_endpoints")

    region = cluster_data.region
    expected_s3_service = f"com.amazonaws.{region}.s3"

    # Find S3 gateway endpoint
    gateway_endpoints = [ep for ep in vpc_endpoints if ep.get('VpcEndpointType') == 'Gateway']
    s3_endpoints = [ep for ep in gateway_endpoints if ep.get('ServiceName') == expected_s3_service]

    if s3_endpoints:
        print(f"\n✓ S3 gateway endpoint found:")
        endpoint_info = {
            "VpcEndpointId": s3_endpoints[0].get("VpcEndpointId"),
            "ServiceName": s3_endpoints[0].get("ServiceName"),
            "State": s3_endpoints[0].get("State"),
            "RouteTableIds": s3_endpoints[0].get("RouteTableIds", [])
        }
        print(json.dumps(endpoint_info, indent=2))
    else:
        print(f"\n✗ S3 gateway endpoint NOT found")
        print(f"Expected service name: {expected_s3_service}")

        if gateway_endpoints:
            print(f"\nFound other gateway endpoints:")
            other_endpoints = [{
                "VpcEndpointId": ep.get("VpcEndpointId"),
                "ServiceName": ep.get("ServiceName")
            } for ep in gateway_endpoints]
            print(json.dumps(other_endpoints, indent=2))

    assert len(s3_endpoints) > 0, \
        f"S3 gateway endpoint missing. Create VPC endpoint for service: {expected_s3_service}"


@pytest.mark.network
def test_vpc_endpoints_available(cluster_data: ClusterData, is_privatelink: bool):
    """All VPC endpoints should be in 'available' state

    Why: Only available endpoints can route traffic. Pending or failed endpoints will not work.

    Failure indicates: One or more endpoints are not fully provisioned.

    Success indicates: All endpoints are operational.
    
    Documentation: https://docs.redhat.com/en/documentation/red_hat_openshift_service_on_aws/4/html/architecture/rosa-architecture-models#rosa-architecture-privatelink
    """
    if not is_privatelink:
        pytest.skip("Not a PrivateLink cluster")

    vpc_endpoints = get_vpc_endpoints(cluster_data)

    if not vpc_endpoints:
        pytest.fail("No VPC endpoints found - see test_privatelink_requires_vpc_endpoints")

    unavailable_endpoints = [
        ep for ep in vpc_endpoints
        if ep.get('State') != 'available'
    ]

    if not unavailable_endpoints:
        print(f"\n✓ All {len(vpc_endpoints)} VPC endpoints in 'available' state:")
        endpoint_states = [{
            "VpcEndpointId": ep.get("VpcEndpointId"),
            "ServiceName": ep.get("ServiceName"),
            "State": ep.get("State")
        } for ep in vpc_endpoints]
        print(json.dumps(endpoint_states, indent=2))
    else:
        print(f"\n✗ {len(unavailable_endpoints)} VPC endpoint(s) not in 'available' state:")
        unavailable_info = [{
            "VpcEndpointId": ep.get("VpcEndpointId"),
            "ServiceName": ep.get("ServiceName"),
            "State": ep.get("State"),
            "StateMessage": ep.get("StateMessage", "")
        } for ep in unavailable_endpoints]
        print(json.dumps(unavailable_info, indent=2))

    assert len(unavailable_endpoints) == 0, \
        f"{len(unavailable_endpoints)} VPC endpoint(s) not in 'available' state. " \
        "Check AWS console for endpoint status and error messages."


@pytest.mark.network
def test_interface_endpoints_have_private_dns_enabled(cluster_data: ClusterData, is_privatelink: bool):
    """Interface endpoints should have private DNS enabled

    Why: Private DNS allows services to use standard AWS service hostnames
    (e.g., ec2.us-west-2.amazonaws.com) which resolve to the VPC endpoint's private IP.
    Without this, applications would need to use the VPC endpoint-specific DNS names.

    Failure indicates: Private DNS is disabled on one or more interface endpoints.

    Success indicates: All interface endpoints have private DNS properly configured.
    
    Documentation: https://docs.redhat.com/en/documentation/red_hat_openshift_service_on_aws/4/html/architecture/rosa-architecture-models#rosa-architecture-privatelink
    """
    if not is_privatelink:
        pytest.skip("Not a PrivateLink cluster")

    vpc_endpoints = get_vpc_endpoints(cluster_data)

    if not vpc_endpoints:
        pytest.fail("No VPC endpoints found - see test_privatelink_requires_vpc_endpoints")

    interface_endpoints = [ep for ep in vpc_endpoints if ep.get('VpcEndpointType') == 'Interface']

    if not interface_endpoints:
        pytest.skip("No interface endpoints found")

    endpoints_without_private_dns = [
        ep for ep in interface_endpoints
        if not ep.get('PrivateDnsEnabled', False)
    ]

    if not endpoints_without_private_dns:
        print(f"\n✓ All {len(interface_endpoints)} interface endpoints have private DNS enabled:")
        endpoint_dns = [{
            "VpcEndpointId": ep.get("VpcEndpointId"),
            "ServiceName": ep.get("ServiceName"),
            "PrivateDnsEnabled": ep.get("PrivateDnsEnabled")
        } for ep in interface_endpoints]
        print(json.dumps(endpoint_dns, indent=2))
    else:
        print(f"\n✗ {len(endpoints_without_private_dns)} interface endpoint(s) without private DNS:")
        no_dns_info = [{
            "VpcEndpointId": ep.get("VpcEndpointId"),
            "ServiceName": ep.get("ServiceName"),
            "PrivateDnsEnabled": ep.get("PrivateDnsEnabled", False)
        } for ep in endpoints_without_private_dns]
        print(json.dumps(no_dns_info, indent=2))

    assert len(endpoints_without_private_dns) == 0, \
        f"{len(endpoints_without_private_dns)} interface endpoint(s) do not have private DNS enabled. " \
        "Enable private DNS for these endpoints in AWS console."


@pytest.mark.network
def test_interface_endpoints_in_all_availability_zones(cluster_data: ClusterData, is_privatelink: bool, infra_id: str):
    """Interface endpoints should have ENIs in all cluster availability zones

    Why: For high availability, interface endpoints should have network interfaces
    in all AZs where the cluster is deployed.

    Failure indicates: Endpoints may not be reachable from all AZs.

    Success indicates: Endpoints are properly distributed across all cluster AZs.
    
    Documentation: https://docs.redhat.com/en/documentation/red_hat_openshift_service_on_aws/4/html/architecture/rosa-architecture-models#rosa-architecture-privatelink
    """
    if not is_privatelink:
        pytest.skip("Not a PrivateLink cluster")

    vpc_endpoints = get_vpc_endpoints(cluster_data)

    if not vpc_endpoints:
        pytest.fail("No VPC endpoints found - see test_privatelink_requires_vpc_endpoints")

    # Get cluster subnets to determine AZs
    subnets_file = cluster_data.aws_dir / f"{cluster_data.cluster_id}_subnets.json"
    if not subnets_file.exists():
        pytest.skip("Subnets file not found")

    with open(subnets_file) as f:
        subnets_data = json.load(f)

    subnets = subnets_data.get('Subnets', [])
    cluster_subnets = [s for s in subnets if any(
        tag.get('Key') == 'Name' and infra_id in tag.get('Value', '')
        for tag in s.get('Tags', [])
    )]

    if not cluster_subnets:
        pytest.skip("No cluster subnets found")

    cluster_azs = set(s.get('AvailabilityZone') for s in cluster_subnets)

    interface_endpoints = [ep for ep in vpc_endpoints if ep.get('VpcEndpointType') == 'Interface']

    if not interface_endpoints:
        pytest.skip("No interface endpoints found")

    issues = []
    endpoint_az_coverage = []

    for ep in interface_endpoints:
        ep_id = ep.get('VpcEndpointId')
        service_name = ep.get('ServiceName')

        # Get subnet IDs for this endpoint
        ep_subnets = ep.get('SubnetIds', [])

        # Find AZs for these subnets
        ep_azs = set()
        for subnet_id in ep_subnets:
            subnet = next((s for s in subnets if s.get('SubnetId') == subnet_id), None)
            if subnet:
                ep_azs.add(subnet.get('AvailabilityZone'))

        missing_azs = cluster_azs - ep_azs

        endpoint_az_coverage.append({
            "VpcEndpointId": ep_id,
            "ServiceName": service_name,
            "ClusterAZs": sorted(list(cluster_azs)),
            "EndpointAZs": sorted(list(ep_azs)),
            "MissingAZs": sorted(list(missing_azs)) if missing_azs else [],
            "FullCoverage": len(missing_azs) == 0
        })

        if missing_azs:
            issues.append(f"Endpoint {ep_id} ({service_name}) missing in AZs: {', '.join(sorted(missing_azs))}")

    if not issues:
        print(f"\n✓ All interface endpoints have full AZ coverage:")
        print(json.dumps(endpoint_az_coverage, indent=2))
    else:
        print(f"\n✗ Interface endpoints with incomplete AZ coverage:")
        incomplete = [ep for ep in endpoint_az_coverage if not ep['FullCoverage']]
        print(json.dumps(incomplete, indent=2))

    assert len(issues) == 0, \
        f"Interface endpoints missing in some AZs: {'; '.join(issues)}"


@pytest.mark.network
def test_s3_gateway_endpoint_has_route_table_associations(cluster_data: ClusterData, is_privatelink: bool):
    """S3 gateway endpoint should be associated with route tables

    Why: Gateway endpoints work by adding routes to route tables. Without route table
    associations, the endpoint won't be used.

    Failure indicates: S3 gateway endpoint exists but is not associated with any route tables.

    Success indicates: S3 gateway endpoint is properly configured with route tables.
    
    Documentation: https://docs.redhat.com/en/documentation/red_hat_openshift_service_on_aws/4/html/architecture/rosa-architecture-models#rosa-architecture-privatelink
    """
    if not is_privatelink:
        pytest.skip("Not a PrivateLink cluster")

    vpc_endpoints = get_vpc_endpoints(cluster_data)

    if not vpc_endpoints:
        pytest.fail("No VPC endpoints found - see test_privatelink_requires_vpc_endpoints")

    region = cluster_data.region
    expected_s3_service = f"com.amazonaws.{region}.s3"

    # Find S3 gateway endpoint
    gateway_endpoints = [ep for ep in vpc_endpoints if ep.get('VpcEndpointType') == 'Gateway']
    s3_endpoints = [ep for ep in gateway_endpoints if ep.get('ServiceName') == expected_s3_service]

    if not s3_endpoints:
        pytest.fail("S3 gateway endpoint not found - see test_privatelink_has_s3_gateway_endpoint")

    s3_endpoint = s3_endpoints[0]
    route_table_ids = s3_endpoint.get('RouteTableIds', [])

    if route_table_ids:
        print(f"\n✓ S3 gateway endpoint associated with {len(route_table_ids)} route table(s):")
        rt_info = {
            "VpcEndpointId": s3_endpoint.get("VpcEndpointId"),
            "ServiceName": s3_endpoint.get("ServiceName"),
            "RouteTableIds": route_table_ids
        }
        print(json.dumps(rt_info, indent=2))
    else:
        print(f"\n✗ S3 gateway endpoint has NO route table associations")
        print(f"VpcEndpointId: {s3_endpoint.get('VpcEndpointId')}")
        print(f"ServiceName: {s3_endpoint.get('ServiceName')}")
        print("\nWithout route table associations, instances cannot reach S3 via this endpoint.")

    assert len(route_table_ids) > 0, \
        "S3 gateway endpoint has no route table associations. " \
        "Associate the endpoint with your VPC's route tables."


@pytest.mark.network
def test_vpc_endpoint_service_exists(cluster_data: ClusterData, is_privatelink: bool, infra_id: str):
    """PrivateLink clusters should have a VPC endpoint service for customer connectivity

    Why: The VPC endpoint service allows customer VPCs to connect to the cluster's
    internal NLB via PrivateLink. This is for CUSTOMER → CLUSTER API connectivity,
    separate from cluster → AWS services connectivity.

    Failure indicates: VPC endpoint service was not created or not tagged properly.

    Success indicates: VPC endpoint service exists and is properly configured for customer access.
    
    Documentation: https://docs.redhat.com/en/documentation/red_hat_openshift_service_on_aws/4/html/architecture/rosa-architecture-models#rosa-architecture-privatelink
    """
    if not is_privatelink:
        pytest.skip("Not a PrivateLink cluster")

    service_data = get_vpc_endpoint_service(cluster_data)

    if not service_data:
        print(f"\n✗ No VPC endpoint service configuration found")
        print(f"Expected file: {cluster_data.cluster_id}_vpc_endpoint_service.json")
        print("\nVPC endpoint service is required for PrivateLink clusters to allow")
        print("customer VPCs to connect to the cluster's internal load balancer.")
        pytest.fail("VPC endpoint service configuration not found")

    service_configs = service_data.get('ServiceConfigurations', [])

    if not service_configs:
        print(f"\n✗ VPC endpoint service file exists but contains no service configurations")
        pytest.fail("No VPC endpoint service configurations found")

    # Should typically be just one service configuration
    service_config = service_configs[0]

    print(f"\n✓ VPC endpoint service found (CUSTOMER → CLUSTER connectivity):")
    service_info = {
        "Purpose": "Customer VPC connections to cluster API",
        "ServiceName": service_config.get("ServiceName"),
        "ServiceId": service_config.get("ServiceId"),
        "ServiceState": service_config.get("ServiceState"),
        "AcceptanceRequired": service_config.get("AcceptanceRequired"),
        "AvailabilityZones": service_config.get("AvailabilityZones", []),
        "NetworkLoadBalancerArns": service_config.get("NetworkLoadBalancerArns", [])
    }
    print(json.dumps(service_info, indent=2))

    # Verify service is available
    service_state = service_config.get("ServiceState")
    assert service_state == "Available", \
        f"VPC endpoint service state is '{service_state}', expected 'Available'"


@pytest.mark.network
def test_vpc_endpoint_service_has_connections(cluster_data: ClusterData, is_privatelink: bool):
    """VPC endpoint service should have customer VPC endpoint connections

    Why: Customer VPC endpoints connect to the cluster's VPC endpoint service to access
    the cluster API. These connections show that customer access is properly configured.

    Note: These are CUSTOMER connections TO the cluster, not cluster connections to AWS services.

    Failure indicates: No customer VPC endpoints are connected to the service.

    Success indicates: Customer VPC endpoint(s) are connected and available.
    
    Documentation: https://docs.redhat.com/en/documentation/red_hat_openshift_service_on_aws/4/html/architecture/rosa-architecture-models#rosa-architecture-privatelink
    """
    if not is_privatelink:
        pytest.skip("Not a PrivateLink cluster")

    vpc_endpoint_conns = get_vpc_endpoint_connections(cluster_data)

    if not vpc_endpoint_conns:
        print("\n⚠ No VPC endpoint service connections found")
        print("This means no customer VPC endpoints are connected to the cluster.")
        print("For cluster installation, customer connections are not required.")
        print("However, customers will need to create VPC endpoints to access the cluster API.")
        # Don't fail - this is informational
        return

    print(f"\n✓ Found {len(vpc_endpoint_conns)} VPC endpoint service connection(s):")

    for conn in vpc_endpoint_conns:
        conn_state = conn.get("VpcEndpointState")
        conn_info = {
            "VpcEndpointId": conn.get("VpcEndpointId"),
            "VpcEndpointOwner": conn.get("VpcEndpointOwner"),
            "State": conn_state,
            "CreationTimestamp": str(conn.get("CreationTimestamp")),
            "DnsEntries": len(conn.get("DnsEntries", [])),
            "Note": "This endpoint is in the customer's VPC for accessing the cluster API"
        }
        print(json.dumps(conn_info, indent=2))

    # Check if any connections are not in available state
    unavailable = [c for c in vpc_endpoint_conns if c.get("VpcEndpointState") != "available"]

    if unavailable:
        print(f"\n⚠ {len(unavailable)} connection(s) not in 'available' state:")
        for conn in unavailable:
            print(f"  - {conn.get('VpcEndpointId')}: {conn.get('VpcEndpointState')}")

    # This is informational - don't fail if connections aren't available
    # The cluster can install without customer connections


@pytest.mark.network
def test_privatelink_no_nat_gateways_required(cluster_data: ClusterData, is_privatelink: bool, infra_id: str):
    """PrivateLink clusters should not require NAT gateways

    Why: This test confirms that PrivateLink is working as expected - there should
    be no NAT gateways since all AWS service traffic goes through VPC endpoints.

    Failure indicates: NAT gateways exist, which suggests mixed configuration
    (both PrivateLink and traditional egress).

    Success indicates: Cluster is using pure PrivateLink architecture.
    
    Documentation: https://docs.redhat.com/en/documentation/red_hat_openshift_service_on_aws/4/html/architecture/rosa-architecture-models#rosa-architecture-privatelink
    """
    if not is_privatelink:
        pytest.skip("Not a PrivateLink cluster")

    nat_file = cluster_data.aws_dir / f"{cluster_data.cluster_id}_nat_gateways.json"

    if not nat_file.exists():
        print("\n✓ NAT gateways file not found (expected for PrivateLink cluster)")
        return

    with open(nat_file) as f:
        nat_data = json.load(f)

    nat_gws = nat_data.get('NatGateways', [])

    # Filter to cluster NAT gateways
    cluster_nat_gws = [nat for nat in nat_gws if any(
        tag.get('Key') == 'Name' and infra_id in tag.get('Value', '')
        for tag in nat.get('Tags', [])
    )]

    if not cluster_nat_gws:
        print(f"\n✓ No NAT gateways found (expected for PrivateLink cluster)")
        print("Cluster is using VPC endpoints for all AWS service connectivity.")
    else:
        print(f"\n⚠ Found {len(cluster_nat_gws)} NAT gateway(s) for PrivateLink cluster:")
        nat_summary = [{
            "NatGatewayId": nat.get("NatGatewayId"),
            "State": nat.get("State"),
            "SubnetId": nat.get("SubnetId")
        } for nat in cluster_nat_gws]
        print(json.dumps(nat_summary, indent=2))
        print("\nNote: PrivateLink clusters typically don't need NAT gateways.")
        print("This may indicate a mixed configuration or customer-specific setup.")

    # This is informational - don't fail if NAT gateways exist
    # (customer may have their own reasons for having them)
