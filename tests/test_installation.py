"""
Installation Status Tests

Validates ROSA cluster installation status and configuration.
"""

import pytest
from models.cluster import ClusterData


@pytest.mark.installation
def test_cluster_has_id(cluster_data: ClusterData):
    """Cluster must have a cluster ID"""
    assert cluster_data.cluster_id, "Cluster ID not found"


@pytest.mark.installation
def test_cluster_has_infra_id(cluster_data: ClusterData):
    """Cluster must have an infrastructure ID"""
    infra_id = cluster_data.infra_id
    assert infra_id, "Infrastructure ID not found"


@pytest.mark.installation
def test_cluster_state(cluster_data: ClusterData):
    """Cluster should be in ready/installed state"""
    state = cluster_data.cluster_json.get('state', '').lower()

    if not state:
        pytest.skip("Cluster state not available")

    valid_states = ['ready', 'installed', 'active']

    if state not in valid_states:
        pytest.fail(f"Cluster state is '{state}', expected one of {valid_states}")


@pytest.mark.installation
def test_cluster_version(cluster_data: ClusterData):
    """Cluster must have OpenShift version specified"""
    version = cluster_data.cluster_json.get('openshift_version', '')

    if not version:
        version = cluster_data.cluster_json.get('version', {}).get('raw_id', '')

    assert version, "OpenShift version not found"
    assert version.startswith('4.'), f"Unexpected OpenShift version format: {version}"


@pytest.mark.installation
def test_cluster_region(cluster_data: ClusterData):
    """Cluster must be deployed in an AWS region"""
    region = cluster_data.cluster_json.get('region', {}).get('id', '')

    if not region:
        region = cluster_data.cluster_json.get('aws', {}).get('region', '')

    assert region, "AWS region not configured"
    assert region.startswith('us-') or region.startswith('eu-') or region.startswith('ap-'), \
        f"Unexpected AWS region format: {region}"


@pytest.mark.installation
def test_cluster_api_url(cluster_data: ClusterData):
    """Cluster must have API URL configured"""
    api_url = cluster_data.cluster_json.get('api', {}).get('url', '')

    assert api_url, "API URL not configured"
    assert api_url.startswith('https://'), f"API URL should use HTTPS: {api_url}"


@pytest.mark.installation
def test_cluster_console_url(cluster_data: ClusterData):
    """Cluster should have console URL configured"""
    console_url = cluster_data.cluster_json.get('console', {}).get('url', '')

    if not console_url:
        pytest.skip("Console URL not available")

    assert console_url.startswith('https://'), f"Console URL should use HTTPS: {console_url}"


@pytest.mark.installation
def test_cluster_has_nodes(cluster_data: ClusterData):
    """Cluster must have nodes configured"""
    nodes = cluster_data.cluster_json.get('nodes', {})

    if not nodes:
        pytest.skip("Node information not available")

    # Check for compute nodes
    compute = nodes.get('compute', 0)
    if isinstance(compute, list) and compute:
        compute = compute[0].get('replicas', 0)

    assert compute > 0, f"No compute nodes configured (compute: {compute})"


@pytest.mark.installation
def test_cluster_network_configured(cluster_data: ClusterData):
    """Cluster must have network configuration"""
    network = cluster_data.cluster_json.get('network', {})

    if not network:
        pytest.skip("Network configuration not available")

    # Check for pod CIDR
    pod_cidr = network.get('pod_cidr', '') or network.get('clusterNetwork', [{}])[0].get('cidr', '')
    service_cidr = network.get('service_cidr', '') or network.get('serviceNetwork', [''])[0]

    assert pod_cidr, "Pod CIDR not configured"
    assert service_cidr, "Service CIDR not configured"


@pytest.mark.installation
def test_cluster_multi_az(cluster_data: ClusterData):
    """Cluster should be multi-AZ for production"""
    nodes = cluster_data.cluster_json.get('nodes', {})

    if not nodes:
        pytest.skip("Node information not available")

    availability_zones = nodes.get('availability_zones', [])

    if not availability_zones:
        pytest.skip("Availability zone information not available")

    # Production clusters should span multiple AZs
    if len(availability_zones) < 3:
        pytest.fail(
            f"Cluster only spans {len(availability_zones)} AZ(s), " +
            "recommended 3 for high availability"
        )


@pytest.mark.installation
def test_cluster_subscription_type(cluster_data: ClusterData):
    """Cluster should have valid subscription"""
    subscription = cluster_data.cluster_json.get('subscription', {})

    if not subscription:
        pytest.skip("Subscription information not available")

    sub_type = subscription.get('type', '')

    assert sub_type, "Subscription type not found"
