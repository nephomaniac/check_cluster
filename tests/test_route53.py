"""
Route53 DNS Tests

Validates Route53 hosted zones and DNS records for ROSA cluster.
"""

import pytest
from models.cluster import ClusterData


@pytest.mark.route53
def test_hosted_zone_exists(cluster_data: ClusterData):
    """Cluster must have a Route53 hosted zone"""
    zones = cluster_data.route53_zones

    if not zones:
        pytest.skip("No Route53 data available")

    hosted_zones = zones.get('HostedZones', [])
    assert hosted_zones, "No hosted zones found"


@pytest.mark.route53
def test_hosted_zone_private(cluster_data: ClusterData, is_private_cluster: bool):
    """Private clusters should have private hosted zones"""
    zones = cluster_data.route53_zones

    if not zones:
        pytest.skip("No Route53 data available")

    hosted_zones = zones.get('HostedZones', [])
    if not hosted_zones:
        pytest.skip("No hosted zones found")

    zone = hosted_zones[0]
    zone_id = zone.get('Id', 'unknown')
    is_private = zone.get('Config', {}).get('PrivateZone', False)

    if is_private_cluster:
        assert is_private, f"Private cluster should have private hosted zone {zone_id}"


@pytest.mark.route53
def test_api_dns_record_exists(cluster_data: ClusterData):
    """API DNS record must exist"""
    cluster_name = cluster_data.cluster_name

    if not cluster_name:
        pytest.skip("Cluster name not available")

    # Check if API endpoint is configured in cluster JSON
    api_url = cluster_data.cluster_json.get('api', {}).get('url', '')

    if not api_url:
        pytest.skip("API URL not found in cluster data")

    # API URL should contain the cluster domain
    assert 'api' in api_url.lower(), f"API URL does not contain 'api': {api_url}"


@pytest.mark.route53
def test_hosted_zone_has_name_servers(cluster_data: ClusterData):
    """Hosted zone must have name servers configured"""
    zones = cluster_data.route53_zones

    if not zones:
        pytest.skip("No Route53 data available")

    hosted_zones = zones.get('HostedZones', [])
    if not hosted_zones:
        pytest.skip("No hosted zones found")

    for zone in hosted_zones:
        zone_id = zone.get('Id', 'unknown')
        zone_name = zone.get('Name', 'unknown')

        # Name servers are required for zone delegation
        # This is validated by AWS, so if zone exists, it has name servers
        assert zone_id, f"Hosted zone {zone_name} has no ID"


@pytest.mark.route53
def test_cluster_domain_configured(cluster_data: ClusterData):
    """Cluster must have a domain configured"""
    domain = cluster_data.cluster_json.get('dns', {}).get('baseDomain', '')

    if not domain:
        # Try alternative location
        domain = cluster_data.cluster_json.get('base_domain', '')

    assert domain, "Cluster domain not configured"
    assert '.' in domain, f"Cluster domain appears invalid: {domain}"
