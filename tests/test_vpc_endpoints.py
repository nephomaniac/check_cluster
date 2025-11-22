"""
VPC Endpoints Tests

Validates VPC endpoint configuration for service connectivity.
Tests interface and gateway endpoints for AWS services.
"""

import pytest
import json
from pathlib import Path
from models.cluster import ClusterData


@pytest.mark.network
def test_vpc_endpoints_exist(cluster_data: ClusterData, infra_id: str):
    """Cluster may have VPC endpoints for AWS services"""
    endpoints_file = cluster_data.data_dir / f"{cluster_data.cluster_id}_vpc_endpoints.json"

    if not endpoints_file.exists():
        pytest.skip(f"VPC endpoints file not found: {endpoints_file}")

    with open(endpoints_file) as f:
        endpoints_data = json.load(f)

    endpoints = endpoints_data.get('VpcEndpoints', [])

    # VPC endpoints are optional, this is informational
    if len(endpoints) == 0:
        pytest.skip("No VPC endpoints found (this is acceptable)")

    # If endpoints exist, report for informational purposes
    print(f"Found {len(endpoints)} VPC endpoint(s)")


@pytest.mark.network
def test_vpc_endpoints_available_state(cluster_data: ClusterData, infra_id: str):
    """VPC endpoints should be in 'available' state"""
    endpoints_file = cluster_data.data_dir / f"{cluster_data.cluster_id}_vpc_endpoints.json"

    if not endpoints_file.exists():
        pytest.skip(f"VPC endpoints file not found: {endpoints_file}")

    with open(endpoints_file) as f:
        endpoints_data = json.load(f)

    endpoints = endpoints_data.get('VpcEndpoints', [])

    if len(endpoints) == 0:
        pytest.skip("No VPC endpoints found")

    unavailable_endpoints = []
    for endpoint in endpoints:
        endpoint_id = endpoint.get('VpcEndpointId', 'unknown')
        state = endpoint.get('State', 'unknown')

        if state not in ['available', 'pending']:
            unavailable_endpoints.append(f"{endpoint_id} (state: {state})")

    assert len(unavailable_endpoints) == 0, \
        f"VPC endpoints not in available/pending state: {', '.join(unavailable_endpoints)}"


@pytest.mark.network
def test_vpc_endpoints_have_service_name(cluster_data: ClusterData, infra_id: str):
    """VPC endpoints should have service name configured"""
    endpoints_file = cluster_data.data_dir / f"{cluster_data.cluster_id}_vpc_endpoints.json"

    if not endpoints_file.exists():
        pytest.skip(f"VPC endpoints file not found: {endpoints_file}")

    with open(endpoints_file) as f:
        endpoints_data = json.load(f)

    endpoints = endpoints_data.get('VpcEndpoints', [])

    if len(endpoints) == 0:
        pytest.skip("No VPC endpoints found")

    endpoints_without_service = []
    for endpoint in endpoints:
        endpoint_id = endpoint.get('VpcEndpointId', 'unknown')
        service_name = endpoint.get('ServiceName', '')

        if not service_name:
            endpoints_without_service.append(endpoint_id)

    assert len(endpoints_without_service) == 0, \
        f"VPC endpoints without service name: {', '.join(endpoints_without_service)}"


@pytest.mark.network
def test_interface_endpoints_have_security_groups(cluster_data: ClusterData, infra_id: str):
    """Interface VPC endpoints should have security groups attached"""
    endpoints_file = cluster_data.data_dir / f"{cluster_data.cluster_id}_vpc_endpoints.json"

    if not endpoints_file.exists():
        pytest.skip(f"VPC endpoints file not found: {endpoints_file}")

    with open(endpoints_file) as f:
        endpoints_data = json.load(f)

    endpoints = endpoints_data.get('VpcEndpoints', [])

    if len(endpoints) == 0:
        pytest.skip("No VPC endpoints found")

    # Filter to interface endpoints only
    interface_endpoints = [
        ep for ep in endpoints
        if ep.get('VpcEndpointType') == 'Interface'
    ]

    if len(interface_endpoints) == 0:
        pytest.skip("No interface VPC endpoints found")

    endpoints_without_sgs = []
    for endpoint in interface_endpoints:
        endpoint_id = endpoint.get('VpcEndpointId', 'unknown')
        security_groups = endpoint.get('Groups', [])

        if len(security_groups) == 0:
            endpoints_without_sgs.append(endpoint_id)

    assert len(endpoints_without_sgs) == 0, \
        f"Interface VPC endpoints without security groups: {', '.join(endpoints_without_sgs)}"


@pytest.mark.network
def test_interface_endpoints_have_subnets(cluster_data: ClusterData, infra_id: str):
    """Interface VPC endpoints should be deployed in subnets"""
    endpoints_file = cluster_data.data_dir / f"{cluster_data.cluster_id}_vpc_endpoints.json"

    if not endpoints_file.exists():
        pytest.skip(f"VPC endpoints file not found: {endpoints_file}")

    with open(endpoints_file) as f:
        endpoints_data = json.load(f)

    endpoints = endpoints_data.get('VpcEndpoints', [])

    if len(endpoints) == 0:
        pytest.skip("No VPC endpoints found")

    # Filter to interface endpoints only
    interface_endpoints = [
        ep for ep in endpoints
        if ep.get('VpcEndpointType') == 'Interface'
    ]

    if len(interface_endpoints) == 0:
        pytest.skip("No interface VPC endpoints found")

    endpoints_without_subnets = []
    for endpoint in interface_endpoints:
        endpoint_id = endpoint.get('VpcEndpointId', 'unknown')
        subnet_ids = endpoint.get('SubnetIds', [])

        if len(subnet_ids) == 0:
            endpoints_without_subnets.append(endpoint_id)

    assert len(endpoints_without_subnets) == 0, \
        f"Interface VPC endpoints without subnets: {', '.join(endpoints_without_subnets)}"


@pytest.mark.network
def test_s3_gateway_endpoint_exists(cluster_data: ClusterData, infra_id: str):
    """Check if S3 gateway endpoint exists (common for private clusters)"""
    endpoints_file = cluster_data.data_dir / f"{cluster_data.cluster_id}_vpc_endpoints.json"

    if not endpoints_file.exists():
        pytest.skip(f"VPC endpoints file not found: {endpoints_file}")

    with open(endpoints_file) as f:
        endpoints_data = json.load(f)

    endpoints = endpoints_data.get('VpcEndpoints', [])

    if len(endpoints) == 0:
        pytest.skip("No VPC endpoints found")

    # Look for S3 gateway endpoint
    s3_endpoints = [
        ep for ep in endpoints
        if ep.get('VpcEndpointType') == 'Gateway' and
        's3' in ep.get('ServiceName', '').lower()
    ]

    # S3 endpoints are optional, this is informational
    if len(s3_endpoints) == 0:
        pytest.skip("No S3 gateway endpoint found (this is acceptable)")

    # If found, just report for informational purposes
    print(f"Found {len(s3_endpoints)} S3 gateway endpoint(s)")
