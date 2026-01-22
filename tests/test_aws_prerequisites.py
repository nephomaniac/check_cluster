"""
AWS Prerequisites Tests

This module validates AWS prerequisites for ROSA clusters based on Red Hat documentation:
- https://docs.redhat.com/en/documentation/red_hat_openshift_service_on_aws/4/html/prepare_your_environment/rosa-hcp-prereqs
- https://docs.redhat.com/en/documentation/red_hat_openshift_service_on_aws/4/html/prepare_your_environment/rosa-sts-required-aws-service-quotas

Validates:
- S3 gateway endpoint configuration
- VPC and subnet requirements
- CIDR configuration
- AWS Marketplace permissions
- Minimum resource counts
"""

import pytest
import json
from pathlib import Path
from typing import Dict, List, Any
from models.cluster import ClusterData


@pytest.mark.aws
@pytest.mark.network
def test_s3_gateway_endpoint_exists_in_vpc(cluster_data: ClusterData):
    """S3 gateway endpoint must be configured in the VPC

    Why: You must configure an Amazon S3 gateway endpoint in your AWS Virtual Private Cloud (VPC).
    This endpoint is required to complete requests from the cluster to the Amazon S3 service.

    Failure indicates: S3 gateway endpoint is missing. Create it before installing ROSA.

    Success indicates: S3 gateway endpoint exists in the cluster VPC.

    Reference: https://docs.redhat.com/en/documentation/red_hat_openshift_service_on_aws/4/html/prepare_your_environment/rosa-hcp-prereqs
    
    Documentation: https://docs.redhat.com/en/documentation/red_hat_openshift_service_on_aws/4/html/prepare_your_environment/rosa-sts-aws-prereqs
    """
    vpc_endpoints_file = cluster_data.aws_dir / f"{cluster_data.cluster_id}_vpc_endpoints.json"

    if not vpc_endpoints_file.exists():
        pytest.skip("VPC endpoints file not found - run check_cluster.py <cluster-id> --collect")

    with open(vpc_endpoints_file) as f:
        endpoints_data = json.load(f)

    vpc_endpoints = endpoints_data.get('VpcEndpoints', [])
    region = cluster_data.region

    # Find S3 gateway endpoint
    expected_s3_service = f"com.amazonaws.{region}.s3"
    gateway_endpoints = [ep for ep in vpc_endpoints if ep.get('VpcEndpointType') == 'Gateway']
    s3_endpoints = [ep for ep in gateway_endpoints if ep.get('ServiceName') == expected_s3_service]

    if s3_endpoints:
        s3_ep = s3_endpoints[0]
        print(f"\n✓ S3 gateway endpoint exists (REQUIRED)")
        endpoint_info = {
            "VpcEndpointId": s3_ep.get("VpcEndpointId"),
            "ServiceName": s3_ep.get("ServiceName"),
            "State": s3_ep.get("State"),
            "RouteTableIds": len(s3_ep.get("RouteTableIds", [])),
            "VpcId": s3_ep.get("VpcId")
        }
        print(json.dumps(endpoint_info, indent=2))

        # Verify it's in available state
        if s3_ep.get('State') != 'available':
            print(f"\n⚠ S3 endpoint state is '{s3_ep.get('State')}', expected 'available'")
    else:
        print(f"\n✗ S3 gateway endpoint NOT found (REQUIRED)")
        print(f"Expected service name: {expected_s3_service}")
        print("\nThis is a REQUIRED prerequisite for ROSA clusters.")
        print("\nTo create the S3 gateway endpoint:")
        print(f"  aws ec2 create-vpc-endpoint \\")
        print(f"    --vpc-id <vpc-id> \\")
        print(f"    --service-name {expected_s3_service} \\")
        print(f"    --route-table-ids <route-table-ids> \\")
        print(f"    --region {region}")

    assert len(s3_endpoints) > 0, \
        f"REQUIRED: S3 gateway endpoint ({expected_s3_service}) not found in VPC. " \
        "You must configure an Amazon S3 gateway endpoint in your VPC. " \
        "This endpoint is required to complete requests from the cluster to the Amazon S3 service."


@pytest.mark.aws
@pytest.mark.network
def test_minimum_private_subnets_per_az(cluster_data: ClusterData, infra_id: str):
    """Cluster should have minimum required private subnets per AZ

    Why: Every cluster requires a minimum of one private subnet for every availability zone.
    - Single-AZ cluster: 1 private subnet required
    - Multi-AZ cluster (3 AZs): 3 private subnets required

    Failure indicates: Insufficient private subnets for cluster availability zones.

    Success indicates: Sufficient private subnets exist.

    Reference: https://docs.redhat.com/en/documentation/red_hat_openshift_service_on_aws/4/html/prepare_your_environment/rosa-hcp-prereqs
    
    Documentation: https://docs.redhat.com/en/documentation/red_hat_openshift_service_on_aws/4/html/prepare_your_environment/rosa-sts-aws-prereqs
    """
    subnets_file = cluster_data.aws_dir / f"{cluster_data.cluster_id}_subnets.json"

    if not subnets_file.exists():
        pytest.skip("Subnets file not found")

    with open(subnets_file) as f:
        subnets_data = json.load(f)

    all_subnets = subnets_data.get('Subnets', [])

    # Filter to cluster subnets
    cluster_subnets = [s for s in all_subnets if any(
        tag.get('Key') == 'Name' and infra_id in tag.get('Value', '')
        for tag in s.get('Tags', [])
    )]

    if not cluster_subnets:
        # Try to get subnets from cluster.json
        cluster_file = cluster_data.ocm_dir / f"{cluster_data.cluster_id}_cluster.json"
        if cluster_file.exists():
            with open(cluster_file) as f:
                cluster_json = json.load(f)
                subnet_ids = cluster_json.get('aws', {}).get('subnet_ids', [])
                if subnet_ids:
                    cluster_subnets = [s for s in all_subnets if s.get('SubnetId') in subnet_ids]

    if not cluster_subnets:
        pytest.skip("Could not identify cluster subnets")

    # Count private subnets per AZ
    private_subnets = [s for s in cluster_subnets if not s.get('MapPublicIpOnLaunch', False)]
    azs = set(s.get('AvailabilityZone') for s in cluster_subnets)

    subnets_per_az = {}
    for az in azs:
        subnets_per_az[az] = len([s for s in private_subnets if s.get('AvailabilityZone') == az])

    total_private = len(private_subnets)
    num_azs = len(azs)
    required_private = num_azs  # At least 1 private subnet per AZ

    print(f"\n{'='*80}")
    print(f"Subnet Analysis")
    print(f"{'='*80}")
    print(f"\nAvailability Zones: {num_azs}")
    print(f"Total subnets: {len(cluster_subnets)}")
    print(f"Private subnets: {total_private}")
    print(f"Required private subnets: {required_private} (1 per AZ)")

    print(f"\nPrivate subnets per AZ:")
    for az, count in sorted(subnets_per_az.items()):
        status = "✓" if count >= 1 else "✗"
        print(f"  {status} {az}: {count} private subnet(s)")

    missing_azs = [az for az, count in subnets_per_az.items() if count < 1]

    if missing_azs:
        print(f"\n✗ {len(missing_azs)} AZ(s) missing private subnets:")
        for az in missing_azs:
            print(f"  - {az}")
    else:
        print(f"\n✓ All AZs have at least one private subnet")

    print(f"{'='*80}\n")

    assert len(missing_azs) == 0, \
        f"{len(missing_azs)} availability zone(s) missing private subnets. " \
        f"Every cluster requires a minimum of one private subnet for every availability zone."


@pytest.mark.aws
@pytest.mark.network
def test_machine_cidr_matches_vpc_cidr(cluster_data: ClusterData):
    """Machine CIDR must match VPC CIDR

    Why: With AWS PrivateLink, your machine's classless inter-domain routing (CIDR)
    must match your virtual private cloud's CIDR.

    Failure indicates: CIDR mismatch between cluster configuration and VPC.

    Success indicates: Machine CIDR matches VPC CIDR.

    Reference: https://docs.redhat.com/en/documentation/red_hat_openshift_service_on_aws/4/html/prepare_your_environment/rosa-hcp-prereqs
    
    Documentation: https://docs.redhat.com/en/documentation/red_hat_openshift_service_on_aws/4/html/prepare_your_environment/rosa-sts-aws-prereqs
    """
    # Get machine CIDR from cluster.json
    cluster_file = cluster_data.ocm_dir / f"{cluster_data.cluster_id}_cluster.json"

    if not cluster_file.exists():
        pytest.skip("Cluster configuration file not found")

    with open(cluster_file) as f:
        cluster_json = json.load(f)

    machine_cidr = cluster_json.get('network', {}).get('machine_cidr')

    if not machine_cidr:
        pytest.skip("Machine CIDR not found in cluster configuration")

    # Get VPC CIDR
    subnet_ids = cluster_json.get('aws', {}).get('subnet_ids', [])

    if not subnet_ids:
        pytest.skip("Subnet IDs not found in cluster configuration")

    # Get VPC ID from subnet
    subnets_file = cluster_data.aws_dir / f"{cluster_data.cluster_id}_subnets.json"

    if not subnets_file.exists():
        pytest.skip("Subnets file not found")

    with open(subnets_file) as f:
        subnets_data = json.load(f)

    subnet = next((s for s in subnets_data.get('Subnets', []) if s.get('SubnetId') in subnet_ids), None)

    if not subnet:
        pytest.skip("Could not find cluster subnet in subnets data")

    vpc_id = subnet.get('VpcId')

    # Get VPC details
    vpc_file = cluster_data.aws_dir / f"{cluster_data.cluster_id}_{vpc_id}.json"

    if not vpc_file.exists():
        pytest.skip(f"VPC details file not found: {vpc_file}")

    with open(vpc_file) as f:
        vpc_data = json.load(f)

    vpc_cidr = vpc_data.get('CidrBlock')

    print(f"\n{'='*80}")
    print(f"CIDR Configuration Check")
    print(f"{'='*80}")
    print(f"\nMachine CIDR (cluster): {machine_cidr}")
    print(f"VPC CIDR (VPC {vpc_id}): {vpc_cidr}")

    if machine_cidr == vpc_cidr:
        print(f"\n✓ Machine CIDR matches VPC CIDR")
    else:
        print(f"\n✗ Machine CIDR does NOT match VPC CIDR")
        print(f"\nThis is required for AWS PrivateLink clusters.")
        print(f"The machine CIDR must match the VPC CIDR.")

    print(f"{'='*80}\n")

    assert machine_cidr == vpc_cidr, \
        f"Machine CIDR ({machine_cidr}) does not match VPC CIDR ({vpc_cidr}). " \
        "For AWS PrivateLink clusters, machine CIDR must match VPC CIDR."


@pytest.mark.aws
def test_privatelink_requires_existing_vpc(cluster_data: ClusterData, is_privatelink: bool):
    """PrivateLink clusters must use existing (BYO) VPCs

    Why: AWS PrivateLink is supported on existing VPCs only. You cannot create
    a new VPC during PrivateLink cluster installation.

    Failure indicates: Attempting to use PrivateLink without providing an existing VPC.

    Success indicates: Cluster is using an existing VPC (as required for PrivateLink).

    Reference: https://docs.redhat.com/en/documentation/red_hat_openshift_service_on_aws/4/html/prepare_your_environment/rosa-hcp-prereqs
    
    Documentation: https://docs.redhat.com/en/documentation/red_hat_openshift_service_on_aws/4/html/prepare_your_environment/rosa-sts-aws-prereqs
    """
    if not is_privatelink:
        pytest.skip("Not a PrivateLink cluster")

    cluster_file = cluster_data.ocm_dir / f"{cluster_data.cluster_id}_cluster.json"

    if not cluster_file.exists():
        pytest.skip("Cluster configuration file not found")

    with open(cluster_file) as f:
        cluster_json = json.load(f)

    subnet_ids = cluster_json.get('aws', {}).get('subnet_ids', [])

    if not subnet_ids:
        print(f"\n✗ PrivateLink cluster has no subnet_ids in configuration")
        print("\nPrivateLink clusters MUST use existing VPCs with pre-configured subnets.")
        print("Cluster cannot be created.")
        pytest.fail("PrivateLink cluster missing subnet_ids - existing VPC required")

    print(f"\n✓ PrivateLink cluster using existing VPC")
    print(f"Subnet IDs provided: {len(subnet_ids)}")

    # Check if subnets exist and get VPC tagging
    subnets_file = cluster_data.aws_dir / f"{cluster_data.cluster_id}_subnets.json"

    if subnets_file.exists():
        with open(subnets_file) as f:
            subnets_data = json.load(f)

        cluster_subnets = [s for s in subnets_data.get('Subnets', []) if s.get('SubnetId') in subnet_ids]

        if cluster_subnets:
            subnet = cluster_subnets[0]
            vpc_id = subnet.get('VpcId')

            # Check subnet tagging
            for s in cluster_subnets:
                tags = {tag.get('Key'): tag.get('Value') for tag in s.get('Tags', [])}
                cluster_tag = tags.get(f'kubernetes.io/cluster/{cluster_data.infra_id}')

                if cluster_tag == 'owned':
                    print(f"\n⚠ Subnet {s.get('SubnetId')} tagged as 'owned'")
                    print("For existing VPCs, subnets should be tagged as 'shared', not 'owned'")
                elif cluster_tag == 'shared':
                    print(f"\n✓ Subnet {s.get('SubnetId')} correctly tagged as 'shared'")

            print(f"\nUsing VPC: {vpc_id}")


@pytest.mark.aws
@pytest.mark.network
def test_route_tables_per_private_subnet(cluster_data: ClusterData, infra_id: str):
    """Each private subnet should have an associated route table

    Why: Proper routing is required for subnet connectivity. Each private subnet
    typically has its own route table or shares a common one.

    Failure indicates: Private subnets missing route table associations.

    Success indicates: All private subnets have route table associations.

    Reference: ROSA networking requirements
    
    Documentation: https://docs.redhat.com/en/documentation/red_hat_openshift_service_on_aws/4/html/prepare_your_environment/rosa-sts-aws-prereqs
    """
    subnets_file = cluster_data.aws_dir / f"{cluster_data.cluster_id}_subnets.json"
    route_tables_file = cluster_data.aws_dir / f"{cluster_data.cluster_id}_route_tables.json"

    if not subnets_file.exists() or not route_tables_file.exists():
        pytest.skip("Subnet or route table data not available")

    with open(subnets_file) as f:
        subnets_data = json.load(f)

    with open(route_tables_file) as f:
        rt_data = json.load(f)

    all_subnets = subnets_data.get('Subnets', [])
    route_tables = rt_data.get('RouteTables', [])

    # Get cluster subnets
    cluster_file = cluster_data.ocm_dir / f"{cluster_data.cluster_id}_cluster.json"
    if not cluster_file.exists():
        pytest.skip("Cluster configuration not found")

    with open(cluster_file) as f:
        cluster_json = json.load(f)

    subnet_ids = cluster_json.get('aws', {}).get('subnet_ids', [])
    cluster_subnets = [s for s in all_subnets if s.get('SubnetId') in subnet_ids]

    if not cluster_subnets:
        pytest.skip("Could not identify cluster subnets")

    # Check route table associations
    private_subnets = [s for s in cluster_subnets if not s.get('MapPublicIpOnLaunch', False)]

    subnets_without_routes = []
    for subnet in private_subnets:
        subnet_id = subnet.get('SubnetId')

        # Find route table association
        associated = False
        for rt in route_tables:
            for assoc in rt.get('Associations', []):
                if assoc.get('SubnetId') == subnet_id:
                    associated = True
                    break
            if associated:
                break

        if not associated:
            subnets_without_routes.append(subnet_id)

    if subnets_without_routes:
        print(f"\n⚠ {len(subnets_without_routes)} private subnet(s) without explicit route table associations:")
        for subnet_id in subnets_without_routes:
            print(f"  - {subnet_id}")
        print("\nThese may be using the VPC's main route table.")
    else:
        print(f"\n✓ All {len(private_subnets)} private subnets have route table associations")

    # This is informational - subnets can use main route table
    # assert len(subnets_without_routes) == 0


@pytest.mark.aws
def test_privatelink_no_public_subnets_required(cluster_data: ClusterData, is_privatelink: bool, infra_id: str):
    """PrivateLink clusters do not require public subnets

    Why: With AWS PrivateLink, internet gateways, NAT gateways, and public subnets
    are not required. However, private subnets must have connectivity to install
    required components.

    This test is informational - documents PrivateLink architecture.

    Reference: https://docs.redhat.com/en/documentation/red_hat_openshift_service_on_aws/4/html/prepare_your_environment/rosa-hcp-prereqs
    
    Documentation: https://docs.redhat.com/en/documentation/red_hat_openshift_service_on_aws/4/html/prepare_your_environment/rosa-sts-aws-prereqs
    """
    if not is_privatelink:
        pytest.skip("Not a PrivateLink cluster")

    subnets_file = cluster_data.aws_dir / f"{cluster_data.cluster_id}_subnets.json"

    if not subnets_file.exists():
        pytest.skip("Subnets file not found")

    with open(subnets_file) as f:
        subnets_data = json.load(f)

    all_subnets = subnets_data.get('Subnets', [])

    # Get cluster subnets
    cluster_file = cluster_data.ocm_dir / f"{cluster_data.cluster_id}_cluster.json"

    if cluster_file.exists():
        with open(cluster_file) as f:
            cluster_json = json.load(f)

        subnet_ids = cluster_json.get('aws', {}).get('subnet_ids', [])
        cluster_subnets = [s for s in all_subnets if s.get('SubnetId') in subnet_ids]
    else:
        cluster_subnets = [s for s in all_subnets if any(
            tag.get('Key') == 'Name' and infra_id in tag.get('Value', '')
            for tag in s.get('Tags', [])
        )]

    if not cluster_subnets:
        pytest.skip("Could not identify cluster subnets")

    public_subnets = [s for s in cluster_subnets if s.get('MapPublicIpOnLaunch', False)]
    private_subnets = [s for s in cluster_subnets if not s.get('MapPublicIpOnLaunch', False)]

    print(f"\n{'='*80}")
    print(f"PrivateLink Subnet Architecture")
    print(f"{'='*80}")
    print(f"\nTotal cluster subnets: {len(cluster_subnets)}")
    print(f"Private subnets: {len(private_subnets)}")
    print(f"Public subnets: {len(public_subnets)}")

    if public_subnets:
        print(f"\n⚠ PrivateLink cluster has {len(public_subnets)} public subnet(s)")
        print("Public subnets are not required for PrivateLink clusters.")
        print("These may be from a pre-existing VPC architecture.")
    else:
        print(f"\n✓ PrivateLink cluster has no public subnets (as expected)")

    print(f"\nNote: PrivateLink clusters do not require:")
    print("  - Public subnets")
    print("  - Internet gateways")
    print("  - NAT gateways")
    print(f"{'='*80}\n")

    # This is informational only
