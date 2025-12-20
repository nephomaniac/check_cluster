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
        subnet_file = cluster_data.aws_dir / f"{cluster_data.cluster_id}_{subnet_id}.json"
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
        subnet_file = cluster_data.aws_dir / f"{cluster_data.cluster_id}_{subnet_id}.json"
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
@pytest.mark.severity("CRITICAL")
@pytest.mark.blocks_install
def test_byo_vpc_subnets_have_role_tags(cluster_data: ClusterData, byo_subnet_ids, byo_subnet_files):
    """BYO VPC subnets must have Kubernetes role tags for load balancer provisioning.

    Why: Kubernetes Cloud Controller Manager (CCM) uses these tags to identify which
    subnets can be used for provisioning Elastic Load Balancers. Without these tags,
    the cluster cannot create load balancers for the API server, ingress controllers,
    or services with type=LoadBalancer.

    Failure indicates: Subnets are missing role tags, which will cause:
    - Cluster installation to fail during bootstrap (BootstrapFailed)
    - API load balancer cannot be created
    - Ingress controllers cannot provision load balancers
    - Service type=LoadBalancer resources will remain in pending state

    Success indicates: Subnets are properly tagged and Kubernetes CCM can successfully
    provision load balancers for cluster services.

    Remediation:
      For private/internal subnets (private clusters):
        $ aws ec2 create-tags --resources <subnet-id> \\
            --tags Key=kubernetes.io/role/internal-elb,Value=1 \\
            --region <region>

      For public subnets (public clusters):
        $ aws ec2 create-tags --resources <subnet-id> \\
            --tags Key=kubernetes.io/role/elb,Value=1 \\
            --region <region>

      Verify tags applied:
        $ aws ec2 describe-subnets --subnet-ids <subnet-id> \\
            --query 'Subnets[0].Tags' --region <region>

    Documentation: https://docs.openshift.com/rosa/rosa_planning/rosa-sts-aws-prereqs.html#rosa-vpc_prerequisites

    Severity: CRITICAL - Will prevent cluster installation
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
    vpc_file = cluster_data.aws_dir / f"{cluster_data.cluster_id}_{vpc_id}_VPC.json"
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
@pytest.mark.severity("CRITICAL")
@pytest.mark.blocks_install
def test_byo_vpc_subnet_cidr_within_vpc_cidr(cluster_data: ClusterData, byo_subnet_ids, byo_subnet_files):
    """BYO VPC subnet CIDR blocks must be within VPC CIDR range.

    Why: AWS requires all subnet CIDR blocks to be subnets (subdivisions) of the
    VPC CIDR block. This is fundamental to IP routing - packets destined for subnet
    IPs must be routable within the VPC network.

    Failure indicates: Subnet CIDR is not within VPC CIDR, which causes:
    - Routing failures - instances cannot communicate
    - AWS will reject subnet creation if CIDR is outside VPC CIDR
    - Cluster installation will fail due to network unreachability
    - BootstrapFailed errors during installation

    Success indicates: Subnet CIDRs are properly contained within VPC CIDR and
    routing will function correctly.

    Remediation:
      Option 1 - Add secondary CIDR to VPC (if subnet already exists):
        # Associate additional CIDR block to VPC
        $ aws ec2 associate-vpc-cidr-block \\
            --vpc-id <vpc-id> \\
            --cidr-block <larger-cidr-that-includes-subnet> \\
            --region <region>

        # Wait for association to complete
        $ aws ec2 describe-vpcs --vpc-ids <vpc-id> \\
            --query 'Vpcs[0].CidrBlockAssociationSet' \\
            --region <region>

      Option 2 - Use subnet within existing VPC CIDR (preferred):
        # Create new subnet within VPC CIDR range
        $ aws ec2 create-subnet \\
            --vpc-id <vpc-id> \\
            --cidr-block <cidr-within-vpc-range> \\
            --availability-zone <az> \\
            --region <region>

        # Tag the new subnet
        $ aws ec2 create-tags --resources <new-subnet-id> \\
            --tags Key=Name,Value=<name> \\
                   Key=kubernetes.io/role/internal-elb,Value=1 \\
                   Key=kubernetes.io/cluster/<infra-id>,Value=shared

      Verify CIDR relationships:
        $ aws ec2 describe-vpcs --vpc-ids <vpc-id> \\
            --query 'Vpcs[0].{VpcCidr:CidrBlock,AdditionalCidrs:CidrBlockAssociationSet[*].CidrBlock}' \\
            --region <region>

        $ aws ec2 describe-subnets --subnet-ids <subnet-id> \\
            --query 'Subnets[0].CidrBlock' \\
            --region <region>

    Documentation: https://docs.aws.amazon.com/vpc/latest/userguide/configure-subnets.html

    Severity: CRITICAL - Will prevent cluster installation
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
    vpc_file = cluster_data.aws_dir / f"{cluster_data.cluster_id}_{vpc_id}_VPC.json"
    if not vpc_file.exists():
        pytest.skip(f"VPC file not found")

    with open(vpc_file) as f:
        vpc_data = json.load(f)

    vpcs = vpc_data.get('Vpcs', [])
    if not vpcs:
        pytest.skip("VPC data is empty")

    vpc = vpcs[0]

    # Get ALL VPC CIDR blocks (primary + all associations)
    # VPCs can have multiple CIDR blocks via CidrBlockAssociationSet
    vpc_cidr_blocks = []

    # Add primary CIDR block if present
    primary_cidr = vpc.get('CidrBlock')
    if primary_cidr:
        vpc_cidr_blocks.append(primary_cidr)

    # Add all associated CIDR blocks
    cidr_associations = vpc.get('CidrBlockAssociationSet', [])
    for assoc in cidr_associations:
        # Only include CIDRs in 'associated' state
        if assoc.get('CidrBlockState', {}).get('State') == 'associated':
            cidr_block = assoc.get('CidrBlock')
            if cidr_block and cidr_block not in vpc_cidr_blocks:
                vpc_cidr_blocks.append(cidr_block)

    if not vpc_cidr_blocks:
        pytest.skip("VPC has no CIDR blocks configured")

    # Import ipaddress for CIDR validation
    import ipaddress

    # Convert VPC CIDRs to network objects
    vpc_networks = []
    for cidr in vpc_cidr_blocks:
        try:
            vpc_networks.append(ipaddress.ip_network(cidr))
        except ValueError as e:
            pytest.fail(f"Invalid VPC CIDR block {cidr}: {e}")

    # Validate each subnet is within at least one VPC CIDR
    invalid_subnets = []

    for subnet_id, subnet_data in byo_subnet_files.items():
        subnets = subnet_data.get('Subnets', [])
        if subnets:
            subnet = subnets[0]
            subnet_cidr = subnet.get('CidrBlock')

            if subnet_cidr:
                try:
                    subnet_network = ipaddress.ip_network(subnet_cidr)

                    # Check if subnet is within ANY of the VPC CIDR blocks
                    is_valid = False
                    for vpc_network in vpc_networks:
                        if subnet_network.subnet_of(vpc_network):
                            is_valid = True
                            break

                    if not is_valid:
                        # Subnet not within any VPC CIDR
                        vpc_cidrs_str = ', '.join(vpc_cidr_blocks)
                        invalid_subnets.append(
                            f"{subnet_id} ({subnet_cidr} not within any VPC CIDR: {vpc_cidrs_str})"
                        )
                except ValueError as e:
                    invalid_subnets.append(f"{subnet_id} (invalid CIDR: {e})")

    if invalid_subnets:
        # Show all VPC CIDRs in error message for context
        vpc_cidrs_display = '\n  '.join(f"- {cidr}" for cidr in vpc_cidr_blocks)
        pytest.fail(
            f"Subnets with CIDR blocks outside all VPC CIDRs:\n"
            f"  VPC CIDRs:\n  {vpc_cidrs_display}\n"
            f"  Invalid subnets: {', '.join(invalid_subnets)}"
        )
