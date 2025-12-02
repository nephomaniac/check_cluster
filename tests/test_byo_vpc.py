"""
Tests for BYO (Bring Your Own) VPC configurations.

These tests validate clusters where subnet IDs are provided in cluster.json
at aws.subnet_ids, indicating a customer-provided VPC configuration.
"""

import pytest
from pathlib import Path
import json
from models.cluster import ClusterData


def has_byo_vpc_subnets(cluster_data: ClusterData) -> bool:
    """Check if cluster has BYO VPC subnet configuration."""
    subnet_ids = cluster_data.cluster_json.get('aws', {}).get('subnet_ids', [])
    return len(subnet_ids) > 0


@pytest.fixture
def byo_subnet_ids(cluster_data: ClusterData):
    """Get subnet IDs from cluster.json if available."""
    return cluster_data.cluster_json.get('aws', {}).get('subnet_ids', [])


@pytest.fixture
def byo_subnet_files(cluster_data: ClusterData, byo_subnet_ids):
    """Load individual subnet files for BYO VPC subnets."""
    subnet_files = {}
    for subnet_id in byo_subnet_ids:
        subnet_file = cluster_data.data_dir / f"{cluster_data.cluster_id}_{subnet_id}.json"
        if subnet_file.exists():
            with open(subnet_file) as f:
                subnet_files[subnet_id] = json.load(f)
    return subnet_files


@pytest.mark.network
def test_byo_vpc_subnets_configuration_exists(cluster_data: ClusterData, byo_subnet_ids):
    """Check if BYO VPC subnet configuration exists in cluster.json.

    Why: BYO VPC clusters specify subnet IDs in the cluster configuration at
    aws.subnet_ids. This indicates customer-provided VPC infrastructure.

    Failure indicates: This is not a BYO VPC cluster, or subnet configuration
    is missing from cluster metadata.
    """
    if not byo_subnet_ids:
        pytest.skip("Not a BYO VPC cluster (no aws.subnet_ids in cluster.json)")

    assert isinstance(byo_subnet_ids, list), "subnet_ids should be a list"
    assert len(byo_subnet_ids) > 0, "subnet_ids list is empty"


@pytest.mark.network
def test_byo_vpc_all_subnets_fetched(cluster_data: ClusterData, byo_subnet_ids):
    """All BYO VPC subnets must be successfully fetched from AWS.

    Why: If subnet IDs are provided in cluster.json, they must exist in AWS
    and be accessible. Missing subnets indicate deleted infrastructure or
    permission issues.

    Failure indicates: One or more subnets specified in cluster.json could not
    be found in AWS. This could mean the subnet was deleted, the cluster is in
    a different AWS account, or permissions are insufficient.
    """
    if not byo_subnet_ids:
        pytest.skip("Not a BYO VPC cluster")

    missing_subnets = []

    for subnet_id in byo_subnet_ids:
        subnet_file = cluster_data.data_dir / f"{cluster_data.cluster_id}_{subnet_id}.json"
        if not subnet_file.exists():
            missing_subnets.append(subnet_id)

    assert not missing_subnets, \
        f"Subnet files not found for: {', '.join(missing_subnets)}. " \
        f"Run get_install_artifacts.py to fetch missing subnets."


@pytest.mark.network
def test_byo_vpc_subnets_in_same_vpc(cluster_data: ClusterData, byo_subnet_ids, byo_subnet_files):
    """All BYO VPC subnets must be in the same VPC.

    Why: ROSA clusters require all subnets to be in the same VPC for proper
    networking. Subnets in different VPCs would prevent cluster communication.

    Failure indicates: Subnets are spread across multiple VPCs, which is an
    invalid configuration. Verify the subnet IDs in cluster.json are correct.
    """
    if not byo_subnet_ids:
        pytest.skip("Not a BYO VPC cluster")

    if not byo_subnet_files:
        pytest.skip("No BYO subnet files available")

    vpc_ids = set()
    subnet_vpc_map = {}

    for subnet_id, subnet_data in byo_subnet_files.items():
        subnets = subnet_data.get('Subnets', [])
        if subnets:
            vpc_id = subnets[0].get('VpcId')
            vpc_ids.add(vpc_id)
            subnet_vpc_map[subnet_id] = vpc_id

    assert len(vpc_ids) == 1, \
        f"Subnets are in {len(vpc_ids)} different VPCs: " \
        f"{', '.join(f'{sid}→{vpc}' for sid, vpc in subnet_vpc_map.items())}"


@pytest.mark.network
def test_byo_vpc_subnets_have_cluster_tags(cluster_data: ClusterData, byo_subnet_ids, byo_subnet_files):
    """BYO VPC subnets should have required cluster tags.

    Why: ROSA requires subnets to be tagged with the cluster infrastructure ID
    for resource discovery and management. The kubernetes.io/cluster/<infra-id>
    tag identifies resources belonging to the cluster.

    Failure indicates: Subnets are missing required cluster tags. This may cause
    issues with cluster networking, load balancer provisioning, or resource cleanup.
    Check subnet tags in AWS console or via AWS CLI.
    """
    if not byo_subnet_ids:
        pytest.skip("Not a BYO VPC cluster")

    if not byo_subnet_files:
        pytest.skip("No BYO subnet files available")

    infra_id = cluster_data.infra_id
    required_tag_key = f"kubernetes.io/cluster/{infra_id}"

    subnets_without_tag = []

    for subnet_id, subnet_data in byo_subnet_files.items():
        subnets = subnet_data.get('Subnets', [])
        if subnets:
            subnet = subnets[0]
            tags = {tag['Key']: tag['Value'] for tag in subnet.get('Tags', [])}

            if required_tag_key not in tags:
                subnets_without_tag.append(subnet_id)

    if subnets_without_tag:
        pytest.fail(
            f"Subnets missing required tag '{required_tag_key}': "
            f"{', '.join(subnets_without_tag)}"
        )


@pytest.mark.network
def test_byo_vpc_subnets_have_role_tags(cluster_data: ClusterData, byo_subnet_ids, byo_subnet_files):
    """BYO VPC subnets should have kubernetes role tags.

    Why: Kubernetes uses role tags (kubernetes.io/role/elb for public subnets,
    kubernetes.io/role/internal-elb for private subnets) to determine where to
    provision load balancers.

    Failure indicates: Subnets are missing role tags, which may cause issues with
    load balancer provisioning. Public subnets should have kubernetes.io/role/elb,
    private subnets should have kubernetes.io/role/internal-elb.
    """
    if not byo_subnet_ids:
        pytest.skip("Not a BYO VPC cluster")

    if not byo_subnet_files:
        pytest.skip("No BYO subnet files available")

    subnets_without_role = []

    for subnet_id, subnet_data in byo_subnet_files.items():
        subnets = subnet_data.get('Subnets', [])
        if subnets:
            subnet = subnets[0]
            tags = {tag['Key']: tag['Value'] for tag in subnet.get('Tags', [])}

            has_elb_role = 'kubernetes.io/role/elb' in tags
            has_internal_elb_role = 'kubernetes.io/role/internal-elb' in tags

            if not (has_elb_role or has_internal_elb_role):
                subnets_without_role.append(subnet_id)

    if subnets_without_role:
        pytest.fail(
            f"Subnets missing kubernetes role tags (elb or internal-elb): "
            f"{', '.join(subnets_without_role)}"
        )


@pytest.mark.network
def test_byo_vpc_has_correct_tags(cluster_data: ClusterData, byo_subnet_ids, byo_subnet_files):
    """BYO VPC should have required cluster tags.

    Why: The VPC must be tagged with the cluster infrastructure ID for resource
    discovery. The kubernetes.io/cluster/<infra-id> tag identifies the VPC as
    belonging to the cluster.

    Failure indicates: VPC is missing required cluster tags. This may cause issues
    with cluster networking or resource management.
    """
    if not byo_subnet_ids:
        pytest.skip("Not a BYO VPC cluster")

    if not byo_subnet_files:
        pytest.skip("No BYO subnet files available")

    # Get VPC ID from first subnet
    first_subnet_data = list(byo_subnet_files.values())[0]
    subnets = first_subnet_data.get('Subnets', [])
    if not subnets:
        pytest.skip("No subnet data available")

    vpc_id = subnets[0].get('VpcId')
    if not vpc_id:
        pytest.skip("VPC ID not found in subnet data")

    # Load VPC file
    vpc_file = cluster_data.data_dir / f"{cluster_data.cluster_id}_{vpc_id}_VPC.json"
    if not vpc_file.exists():
        pytest.skip(f"VPC file not found: {vpc_file.name}")

    with open(vpc_file) as f:
        vpc_data = json.load(f)

    vpcs = vpc_data.get('Vpcs', [])
    if not vpcs:
        pytest.fail("VPC data is empty")

    vpc = vpcs[0]
    tags = {tag['Key']: tag['Value'] for tag in vpc.get('Tags', [])}

    infra_id = cluster_data.infra_id
    required_tag_key = f"kubernetes.io/cluster/{infra_id}"

    assert required_tag_key in tags, \
        f"VPC {vpc_id} missing required tag: {required_tag_key}"


@pytest.mark.network
def test_byo_vpc_subnets_available(cluster_data: ClusterData, byo_subnet_ids, byo_subnet_files):
    """All BYO VPC subnets must be in 'available' state.

    Why: Subnets must be in the 'available' state to be usable by the cluster.
    Subnets in other states may not function correctly.

    Failure indicates: One or more subnets are not available. This could indicate
    infrastructure issues or pending changes in AWS.
    """
    if not byo_subnet_ids:
        pytest.skip("Not a BYO VPC cluster")

    if not byo_subnet_files:
        pytest.skip("No BYO subnet files available")

    unavailable_subnets = []

    for subnet_id, subnet_data in byo_subnet_files.items():
        subnets = subnet_data.get('Subnets', [])
        if subnets:
            subnet = subnets[0]
            state = subnet.get('State')
            if state != 'available':
                unavailable_subnets.append(f"{subnet_id} (state: {state})")

    assert not unavailable_subnets, \
        f"Subnets not in 'available' state: {', '.join(unavailable_subnets)}"


@pytest.mark.network
def test_byo_vpc_subnet_cidr_within_vpc_cidr(cluster_data: ClusterData, byo_subnet_ids, byo_subnet_files):
    """BYO VPC subnet CIDR blocks must be within VPC CIDR.

    Why: All subnet CIDR blocks must be subnets of the VPC CIDR block. This is
    an AWS requirement for proper IP routing.

    Failure indicates: Subnet CIDR blocks are not properly contained within the
    VPC CIDR, which would be an invalid AWS configuration.
    """
    if not byo_subnet_ids:
        pytest.skip("Not a BYO VPC cluster")

    if not byo_subnet_files:
        pytest.skip("No BYO subnet files available")

    # Get VPC ID and CIDR from first subnet
    first_subnet_data = list(byo_subnet_files.values())[0]
    subnets = first_subnet_data.get('Subnets', [])
    if not subnets:
        pytest.skip("No subnet data available")

    vpc_id = subnets[0].get('VpcId')

    # Load VPC file
    vpc_file = cluster_data.data_dir / f"{cluster_data.cluster_id}_{vpc_id}_VPC.json"
    if not vpc_file.exists():
        pytest.skip(f"VPC file not found")

    with open(vpc_file) as f:
        vpc_data = json.load(f)

    vpcs = vpc_data.get('Vpcs', [])
    if not vpcs:
        pytest.skip("VPC data is empty")

    vpc = vpcs[0]
    vpc_cidr = vpc.get('CidrBlock')

    if not vpc_cidr:
        pytest.skip("VPC CIDR not found")

    # Import ipaddress for CIDR validation
    import ipaddress

    vpc_network = ipaddress.ip_network(vpc_cidr)
    invalid_subnets = []

    for subnet_id, subnet_data in byo_subnet_files.items():
        subnets = subnet_data.get('Subnets', [])
        if subnets:
            subnet = subnets[0]
            subnet_cidr = subnet.get('CidrBlock')

            if subnet_cidr:
                try:
                    subnet_network = ipaddress.ip_network(subnet_cidr)
                    if not subnet_network.subnet_of(vpc_network):
                        invalid_subnets.append(
                            f"{subnet_id} ({subnet_cidr} not in VPC {vpc_cidr})"
                        )
                except ValueError as e:
                    invalid_subnets.append(f"{subnet_id} (invalid CIDR: {e})")

    assert not invalid_subnets, \
        f"Subnets with CIDR blocks outside VPC CIDR: {', '.join(invalid_subnets)}"
