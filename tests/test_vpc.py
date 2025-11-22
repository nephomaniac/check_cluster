"""
VPC Configuration Tests

Validates VPC DNS settings, DHCP options, and network configuration for ROSA clusters.
"""

import pytest
from models.cluster import ClusterData


@pytest.mark.vpc
def test_vpc_exists(cluster_data: ClusterData):
    """VPC must exist and be configured"""
    vpcs = cluster_data.vpcs
    assert vpcs, "No VPC data found"

    vpc_data = vpcs.get('Vpcs', [])
    assert vpc_data, "VPC list is empty"
    assert len(vpc_data) > 0, "No VPCs configured"


@pytest.mark.vpc
def test_vpc_dns_hostnames_enabled(cluster_data: ClusterData):
    """VPC must have DNS hostnames enabled for internal hostname resolution"""
    vpcs = cluster_data.vpcs.get('Vpcs', [])

    if not vpcs:
        pytest.skip("No VPC data available")

    vpc = vpcs[0]
    dns_hostnames = vpc.get('EnableDnsHostnames', False)
    vpc_id = vpc.get('VpcId', 'unknown')

    assert dns_hostnames, f"VPC {vpc_id} does not have DNS hostnames enabled"


@pytest.mark.vpc
def test_vpc_dns_support_enabled(cluster_data: ClusterData):
    """VPC must have DNS support enabled for DNS resolution"""
    vpcs = cluster_data.vpcs.get('Vpcs', [])

    if not vpcs:
        pytest.skip("No VPC data available")

    vpc = vpcs[0]
    dns_support = vpc.get('EnableDnsSupport', False)
    vpc_id = vpc.get('VpcId', 'unknown')

    assert dns_support, f"VPC {vpc_id} does not have DNS support enabled"


@pytest.mark.vpc
def test_vpc_cidr_block_configured(cluster_data: ClusterData):
    """VPC must have a CIDR block configured"""
    vpcs = cluster_data.vpcs.get('Vpcs', [])

    if not vpcs:
        pytest.skip("No VPC data available")

    vpc = vpcs[0]
    cidr_block = vpc.get('CidrBlock', '')
    vpc_id = vpc.get('VpcId', 'unknown')

    assert cidr_block, f"VPC {vpc_id} has no CIDR block configured"
    assert '/' in cidr_block, f"VPC {vpc_id} CIDR block is malformed: {cidr_block}"


@pytest.mark.vpc
def test_vpc_state_available(cluster_data: ClusterData):
    """VPC must be in available state"""
    vpcs = cluster_data.vpcs.get('Vpcs', [])

    if not vpcs:
        pytest.skip("No VPC data available")

    vpc = vpcs[0]
    state = vpc.get('State', 'unknown')
    vpc_id = vpc.get('VpcId', 'unknown')

    assert state == 'available', f"VPC {vpc_id} is not available (state: {state})"


@pytest.mark.vpc
def test_dhcp_options_associated(cluster_data: ClusterData):
    """VPC must have DHCP options set associated"""
    vpcs = cluster_data.vpcs.get('Vpcs', [])

    if not vpcs:
        pytest.skip("No VPC data available")

    vpc = vpcs[0]
    dhcp_options_id = vpc.get('DhcpOptionsId', '')
    vpc_id = vpc.get('VpcId', 'unknown')

    assert dhcp_options_id, f"VPC {vpc_id} has no DHCP options set associated"
