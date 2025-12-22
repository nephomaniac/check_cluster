"""
VPC Configuration Tests

Validates VPC DNS settings, DHCP options, and network configuration for ROSA clusters.
"""

import json
import pytest
from models.cluster import ClusterData
from utils.test_helpers import check_resource_in_api_requests


def format_api_request_error(cluster_data: ClusterData, operation: str, service: str = "ec2") -> str:
    """
    Format API request error information for display.

    Args:
        cluster_data: ClusterData instance
        operation: AWS API operation name (e.g., "describe_vpcs")
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


@pytest.mark.vpc
def test_vpc_exists(cluster_data: ClusterData, request):
    """VPC must exist and be configured.

    Why: The VPC provides network isolation and contains all cluster networking resources
    including subnets, route tables, and network ACLs.

    Failure indicates: VPC data is missing or incomplete, suggesting the cluster has no
    network infrastructure or data collection failed.

    Success indicates: VPC exists and was successfully collected from AWS.
    """
    vpcs = cluster_data.vpcs

    vpc_data = vpcs.get('Vpcs', [])

    if not vpc_data:
        # Import diagnostic helper
        from utils.aws_resource_diagnostics import diagnose_missing_aws_resource

        # Try to get VPC ID from cluster.json
        vpc_id = cluster_data.cluster_json.get('network', {}).get('vpc_id', 'unknown')

        # Get comprehensive diagnostics
        diagnostics = diagnose_missing_aws_resource(
            cluster_data=cluster_data,
            resource_type="VPC",
            expected_file=f"{cluster_data.cluster_id}_vpcs.json",
            api_service="ec2",
            api_operation="describe_vpcs",
            resource_identifier=vpc_id if vpc_id != 'unknown' else None
        )

        # Correlate CloudTrail events for missing VPC
        from utils.test_helpers import correlate_cloudtrail_events_for_resources

        if vpc_id and vpc_id != 'unknown':
            ct_result = correlate_cloudtrail_events_for_resources(
                cluster_data=cluster_data,
                resource_identifiers=[vpc_id],
                resource_type="VPC",
                event_types=["Delete", "DeleteVpc"],
                pytest_request=request
            )

        pytest.fail(f"No VPC data found.\n\n{diagnostics}")

    print(f"\n✓ Found {len(vpc_data)} VPC(s):")

    # Include CidrBlockAssociationSet in summary
    vpc_summary = []
    for vpc in vpc_data:
        summary = {
            "VpcId": vpc.get("VpcId"),
            "CidrBlock": vpc.get("CidrBlock"),
            "State": vpc.get("State")
        }
        # Add CidrBlockAssociationSet if present
        cidr_assoc = vpc.get("CidrBlockAssociationSet", [])
        if cidr_assoc:
            summary["CidrBlockAssociations"] = [
                {
                    "CidrBlock": assoc.get("CidrBlock"),
                    "State": assoc.get("CidrBlockState", {}).get("State")
                }
                for assoc in cidr_assoc
            ]
        vpc_summary.append(summary)

    print("\n" + "─"*80)
    print("EC2 DESCRIBE-VPCS OUTPUT - Showing VPC Configuration")
    print("Shows VPC ID, CIDR block, and state for cluster networking")
    print("Relevance: Verifies VPC exists and is active for cluster network isolation")
    print("─"*80)
    print(json.dumps(vpc_summary, indent=2))
    print("─"*80)

    if len(vpc_data) == 0:
        # Show AWS API request error details
        print(f"\n{'─'*80}")
        print("AWS API REQUEST INFORMATION")
        print(f"{'─'*80}")
        print(format_api_request_error(cluster_data, "describe_vpcs", "ec2"))
        print(f"{'─'*80}\n")

    assert len(vpc_data) > 0, "No VPCs configured - see AWS API request error details above"


@pytest.mark.vpc
def test_vpc_dns_hostnames_enabled(cluster_data: ClusterData):
    """VPC must have DNS hostnames enabled for internal hostname resolution.

    Why: DNS hostnames allow EC2 instances to receive DNS names, enabling service
    discovery and internal communication using hostnames instead of IPs.

    Failure indicates: The VPC is not configured for DNS hostnames, which could prevent
    proper service discovery and internal DNS resolution within the cluster.
    """
    vpcs = cluster_data.vpcs.get('Vpcs', [])

    if not vpcs:
        print("\n✗ No VPC data available")
        pytest.skip("No VPC data available")

    vpc = vpcs[0]
    dns_hostnames = vpc.get('EnableDnsHostnames', False)
    vpc_id = vpc.get('VpcId', 'unknown')

    print(f"\n✓ VPC DNS configuration:")

    print("\n" + "─"*80)
    if dns_hostnames:
        print("EC2 DESCRIBE-VPC-ATTRIBUTE OUTPUT - Showing DNS Hostnames is ENABLED")
    else:
        print("EC2 DESCRIBE-VPC-ATTRIBUTE OUTPUT - Showing DNS Hostnames is DISABLED")
    print("Relevance: DNS hostnames must be enabled for EC2 instances to receive DNS names")
    print("Impact: Required for internal service discovery and hostname-based communication")
    print("─"*80)
    print(json.dumps({
        "VpcId": vpc_id,
        "EnableDnsHostnames": dns_hostnames
    }, indent=2))
    print("─"*80)

    assert dns_hostnames, f"VPC {vpc_id} does not have DNS hostnames enabled"


@pytest.mark.vpc
def test_vpc_dns_support_enabled(cluster_data: ClusterData):
    """VPC must have DNS support enabled for DNS resolution.

    Why: DNS support enables the Amazon-provided DNS server at the VPC CIDR +2 address,
    which is required for resolving internal and external DNS queries.

    Failure indicates: DNS resolution within the VPC is disabled, which would prevent
    nodes from resolving DNS names and break critical cluster functionality.
    """
    vpcs = cluster_data.vpcs.get('Vpcs', [])

    if not vpcs:
        print("\n✗ No VPC data available")
        pytest.skip("No VPC data available")

    vpc = vpcs[0]
    dns_support = vpc.get('EnableDnsSupport', False)
    vpc_id = vpc.get('VpcId', 'unknown')

    print(f"\n✓ VPC DNS support:")

    print("\n" + "─"*80)
    if dns_support:
        print("EC2 DESCRIBE-VPC-ATTRIBUTE OUTPUT - Showing DNS Support is ENABLED")
    else:
        print("EC2 DESCRIBE-VPC-ATTRIBUTE OUTPUT - Showing DNS Support is DISABLED")
    print("Relevance: DNS support enables Amazon DNS server at VPC CIDR +2 address")
    print("Impact: Required for DNS resolution of internal and external hostnames")
    print("─"*80)
    print(json.dumps({
        "VpcId": vpc_id,
        "EnableDnsSupport": dns_support
    }, indent=2))
    print("─"*80)

    assert dns_support, f"VPC {vpc_id} does not have DNS support enabled"


@pytest.mark.vpc
def test_vpc_cidr_block_configured(cluster_data: ClusterData):
    """VPC must have a CIDR block configured

    Why: The VPC CIDR block defines the IP address range for the VPC network,
    which all subnets and resources must be allocated from.

    Failure indicates: VPC has no CIDR block configuration, which means
    no IP addresses can be allocated and the network cannot function.
    """
    vpcs = cluster_data.vpcs.get('Vpcs', [])

    if not vpcs:
        print("\n✗ No VPC data available")
        pytest.skip("No VPC data available")

    vpc = vpcs[0]
    vpc_id = vpc.get('VpcId', 'unknown')

    # Try to get CIDR block from top-level attribute first
    cidr_block = vpc.get('CidrBlock', '')

    # If not present, try CidrBlockAssociationSet
    cidr_associations = vpc.get('CidrBlockAssociationSet', [])

    print(f"\n✓ VPC CIDR configuration:")

    print("\n" + "─"*80)
    print("EC2 DESCRIBE-VPCS OUTPUT - Showing VPC CIDR Block Configuration")
    print("Shows VPC CIDR block (IP address range) for cluster networking")
    print("Relevance: CIDR block defines available IP addresses for cluster resources")
    print("─"*80)

    output = {
        "VpcId": vpc_id,
        "CidrBlock": cidr_block
    }

    # Include CidrBlockAssociationSet if present
    if cidr_associations:
        output["CidrBlockAssociationSet"] = [
            {
                "CidrBlock": assoc.get("CidrBlock"),
                "AssociationId": assoc.get("AssociationId"),
                "State": assoc.get("CidrBlockState", {}).get("State")
            }
            for assoc in cidr_associations
        ]

    print(json.dumps(output, indent=2))
    print("─"*80)

    # Validate CIDR block exists (from either source)
    if not cidr_block and cidr_associations:
        # Get CIDR from CidrBlockAssociationSet
        associated_cidrs = [
            assoc.get('CidrBlock')
            for assoc in cidr_associations
            if assoc.get('CidrBlockState', {}).get('State') == 'associated'
        ]
        if associated_cidrs:
            cidr_block = associated_cidrs[0]
        elif cidr_associations:
            cidr_block = cidr_associations[0].get('CidrBlock', '')

    assert cidr_block, f"VPC {vpc_id} has no CIDR block configured (checked both CidrBlock and CidrBlockAssociationSet)"
    assert '/' in cidr_block, f"VPC {vpc_id} CIDR block is malformed: {cidr_block}"

    # If CidrBlockAssociationSet is present, validate all associations are in 'associated' state
    if cidr_associations:
        for assoc in cidr_associations:
            state = assoc.get('CidrBlockState', {}).get('State', 'unknown')
            assoc_id = assoc.get('AssociationId', 'unknown')
            assoc_cidr = assoc.get('CidrBlock', 'unknown')
            assert state == 'associated', \
                f"VPC {vpc_id} CIDR association {assoc_id} ({assoc_cidr}) is in state '{state}', expected 'associated'"


@pytest.mark.vpc
def test_vpc_state_available(cluster_data: ClusterData):
    """VPC must be in available state"""
    vpcs = cluster_data.vpcs.get('Vpcs', [])

    if not vpcs:
        print("\n✗ No VPC data available")
        pytest.skip("No VPC data available")

    vpc = vpcs[0]
    state = vpc.get('State', 'unknown')
    vpc_id = vpc.get('VpcId', 'unknown')

    print(f"\n✓ VPC state:")

    print("\n" + "─"*80)
    if state == 'available':
        print("EC2 DESCRIBE-VPCS OUTPUT - Showing VPC State is AVAILABLE")
    else:
        print(f"EC2 DESCRIBE-VPCS OUTPUT - Showing VPC State is {state.upper()}")
    print("Relevance: VPC must be in 'available' state for cluster to function")
    print("─"*80)
    print(json.dumps({
        "VpcId": vpc_id,
        "State": state
    }, indent=2))
    print("─"*80)

    assert state == 'available', f"VPC {vpc_id} is not available (state: {state})"


@pytest.mark.vpc
def test_dhcp_options_associated(cluster_data: ClusterData):
    """VPC must have DHCP options set associated"""
    vpcs = cluster_data.vpcs.get('Vpcs', [])

    if not vpcs:
        print("\n✗ No VPC data available")
        pytest.skip("No VPC data available")

    vpc = vpcs[0]
    dhcp_options_id = vpc.get('DhcpOptionsId', '')
    vpc_id = vpc.get('VpcId', 'unknown')

    print(f"\n✓ VPC DHCP options:")

    print("\n" + "─"*80)
    print("EC2 DESCRIBE-VPCS OUTPUT - Showing DHCP Options Set Association")
    print("Shows DHCP Options Set ID associated with VPC for DNS and domain configuration")
    print("Relevance: DHCP options control DNS servers and domain names for EC2 instances")
    print("─"*80)
    print(json.dumps({
        "VpcId": vpc_id,
        "DhcpOptionsId": dhcp_options_id
    }, indent=2))
    print("─"*80)

    assert dhcp_options_id, f"VPC {vpc_id} has no DHCP options set associated"
