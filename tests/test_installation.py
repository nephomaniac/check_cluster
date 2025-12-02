"""
Installation Status Tests

Validates ROSA cluster installation status and configuration.
"""

import pytest
from models.cluster import ClusterData


@pytest.mark.installation
def test_cluster_has_id(cluster_data: ClusterData):
    """Cluster must have a cluster ID.

    Why: The cluster ID is a unique identifier used by ROSA for cluster management,
    billing, and API operations. All cluster resources reference this ID.

    Failure indicates: Critical cluster metadata is missing from the configuration,
    suggesting incomplete installation or corrupted cluster data.
    """
    assert cluster_data.cluster_id, "Cluster ID not found"


@pytest.mark.installation
def test_cluster_has_infra_id(cluster_data: ClusterData):
    """Cluster must have an infrastructure ID.

    Why: The infrastructure ID (infra_id) prefixes all AWS resource names and tags
    for cluster ownership. It's essential for resource discovery and lifecycle management.

    Failure indicates: Critical infrastructure metadata is missing, preventing proper
    resource identification and potentially causing resource management failures.
    """
    infra_id = cluster_data.infra_id
    assert infra_id, "Infrastructure ID not found"


@pytest.mark.installation
def test_cluster_state(cluster_data: ClusterData):
    """Cluster should be in ready/installed state.

    Why: The cluster state reflects the overall health and lifecycle stage. Only
    clusters in 'ready', 'installed', or 'active' state are fully operational.

    Failure indicates: The cluster is not in an operational state. It may be installing,
    upgrading, degraded, or in error state requiring investigation of cluster operators.
    """
    state = cluster_data.cluster_json.get('state', '').lower()

    if not state:
        pytest.skip("Cluster state not available")

    valid_states = ['ready', 'installed', 'active']

    if state not in valid_states:
        pytest.fail(f"Cluster state is '{state}', expected one of {valid_states}")


@pytest.mark.installation
def test_cluster_version(cluster_data: ClusterData):
    """Cluster must have OpenShift version specified.

    Why: The OpenShift version determines available features, API compatibility,
    and supported configurations. Version information is required for upgrades and support.

    Failure indicates: Version metadata is missing or malformed, which could indicate
    incomplete installation or data collection issues.
    """
    version = cluster_data.cluster_json.get('openshift_version', '')

    if not version:
        version = cluster_data.cluster_json.get('version', {}).get('raw_id', '')

    assert version, "OpenShift version not found"
    assert version.startswith('4.'), f"Unexpected OpenShift version format: {version}"


@pytest.mark.installation
def test_cluster_region(cluster_data: ClusterData):
    """Cluster must be deployed in an AWS region.

    Why: The AWS region defines where cluster resources are located and affects
    availability, compliance, and performance characteristics.

    Failure indicates: Region metadata is missing or invalid, which could prevent
    proper resource management and regional service configurations.
    """
    region = cluster_data.cluster_json.get('region', {}).get('id', '')

    if not region:
        region = cluster_data.cluster_json.get('aws', {}).get('region', '')

    assert region, "AWS region not configured"
    assert region.startswith('us-') or region.startswith('eu-') or region.startswith('ap-'), \
        f"Unexpected AWS region format: {region}"


@pytest.mark.installation
def test_cluster_api_url(cluster_data: ClusterData):
    """Cluster must have API URL configured.

    Why: The API URL is the primary endpoint for cluster management via kubectl
    and oc commands. Without it, cluster administration is impossible.

    Failure indicates: The Kubernetes API endpoint is not configured or DNS records
    are missing, preventing cluster access and management operations.
    """
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
    """Cluster must have nodes configured.

    Why: Compute nodes are required to run workloads. A cluster without compute
    capacity cannot schedule or execute any pods or applications.

    Failure indicates: No compute nodes are configured in the cluster specification,
    suggesting incomplete installation or severe cluster degradation.
    """
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
    """Cluster must have network configuration.

    Why: Pod and service CIDR blocks define the IP address space for container networking.
    These are fundamental requirements for pod-to-pod and service communication.

    Failure indicates: Core networking configuration is missing, which would prevent
    pod networking from functioning and make the cluster inoperable.
    """
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
    """Cluster multi-AZ configuration should match deployment (configuration consistency check)"""
    # Get the configured multi-AZ setting
    is_multi_az = cluster_data.cluster_json.get('multi_az', False)

    nodes = cluster_data.cluster_json.get('nodes', {})
    if not nodes:
        pytest.skip("Node information not available")

    availability_zones = nodes.get('availability_zones', [])

    # If no AZ info available, cannot validate
    if not availability_zones:
        pytest.skip("Availability zone information not available")

    az_count = len(availability_zones)

    # Only validate configuration consistency, not make recommendations
    if is_multi_az:
        # Multi-AZ clusters MUST span multiple availability zones
        assert az_count >= 2, \
            f"Configuration error: Cluster configured as multi-AZ but only spans {az_count} AZ(s)"
    else:
        # Single-AZ is a valid configuration - only fail if there's a mismatch
        if az_count > 1:
            pytest.fail(
                f"Configuration error: Cluster configured as single-AZ but spans {az_count} AZ(s)"
            )
        # Single-AZ cluster correctly configured - this is valid
        pytest.skip(f"Cluster correctly configured as single-AZ (spans {az_count} AZ)")


@pytest.mark.installation
def test_cluster_subscription_type(cluster_data: ClusterData):
    """Cluster should have valid subscription.

    Why: The subscription type determines billing, support entitlements, and
    available features for the ROSA cluster.

    Failure indicates: Subscription metadata is missing, which may indicate issues
    with cluster registration or incomplete provisioning through Red Hat.
    """
    subscription = cluster_data.cluster_json.get('subscription', {})

    if not subscription:
        pytest.skip("Subscription information not available")

    sub_type = subscription.get('type', '')

    if not sub_type:
        # Subscription may be a link (SubscriptionLink) without full details
        if subscription.get('kind') == 'SubscriptionLink':
            pytest.skip("Subscription details not expanded (SubscriptionLink only)")
        else:
            pytest.fail("Subscription type not found")

    # If we have a type, verify it's not empty
    assert sub_type, "Subscription type is empty"
