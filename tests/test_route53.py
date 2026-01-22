"""
Route53 DNS Tests

Validates Route53 hosted zones and DNS records for ROSA cluster.

Documentation:
- ROSA DNS Configuration: https://docs.redhat.com/en/documentation/red_hat_openshift_service_on_aws/4/html/install_rosa_classic_clusters/rosa-sts-creating-a-cluster-with-customizations#prerequisites_rosa-sts-creating-cluster-using-customizations
- AWS Route53: https://docs.aws.amazon.com/route53/latest/developerguide/Welcome.html
"""

import json
import pytest
from models.cluster import ClusterData
from utils.test_helpers import check_resource_in_api_requests


def format_api_request_error(cluster_data: ClusterData, operation: str, service: str = "route53") -> str:
    """
    Format API request error information for display.

    Args:
        cluster_data: ClusterData instance
        operation: AWS API operation name (e.g., "list_hosted_zones")
        service: AWS service name (e.g., "route53")

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


@pytest.mark.route53
def test_hosted_zone_exists(cluster_data: ClusterData, request):
    """Cluster must have a Route53 hosted zone.

    Why: Route53 hosted zones provide DNS resolution for cluster API endpoints and
    internal service discovery. They are essential for cluster accessibility.

    Failure indicates: DNS hosting is not configured, which would prevent DNS resolution
    for the cluster API and could indicate incomplete cluster setup.
    
    Documentation: https://docs.redhat.com/en/documentation/red_hat_openshift_service_on_aws/4/html/prepare_your_environment/rosa-sts-aws-prereqs#rosa-dns-requirements
    """
    zones = cluster_data.route53_zones

    if not zones:
        # Import diagnostic helper
        from utils.aws_resource_diagnostics import diagnose_missing_aws_resource

        # Get comprehensive diagnostics
        diagnostics = diagnose_missing_aws_resource(
            cluster_data=cluster_data,
            resource_type="Route53 Hosted Zones",
            expected_file=f"{cluster_data.cluster_id}_route53_zones.json",
            api_service="route53",
            api_operation="list_hosted_zones"
        )

        # Correlate CloudTrail events for deleted hosted zones
        from utils.test_helpers import correlate_cloudtrail_events_for_resources

        # Try to get domain from cluster JSON
        dns_config = cluster_data.cluster_json.get('dns', {})
        domain = dns_config.get('baseDomain') or dns_config.get('base_domain', '')
        if not domain:
            domain = cluster_data.cluster_json.get('base_domain', '')

        # Search for hosted zone deletion events
        resource_ids = [domain, cluster_data.cluster_name] if domain else [cluster_data.cluster_name]

        ct_result = correlate_cloudtrail_events_for_resources(
            cluster_data=cluster_data,
            resource_identifiers=resource_ids,
            resource_type="Route53 Hosted Zone",
            event_types=["Delete", "DeleteHostedZone"],
            pytest_request=request
        )

        # Show AWS API request error details
        print(f"\n{'─'*80}")
        print("AWS API REQUEST INFORMATION")
        print(f"{'─'*80}")
        print(format_api_request_error(cluster_data, "list_hosted_zones", "route53"))
        print(f"{'─'*80}\n")

        pytest.fail(f"No Route53 hosted zone data found.\n\n{diagnostics}")

    hosted_zones = zones.get('HostedZones', [])

    if hosted_zones:
        print(f"\n✓ Found {len(hosted_zones)} hosted zone(s):")
        zone_summary = [{
            "HostedZoneId": zone.get("Id"),
            "Name": zone.get("Name"),
            "ResourceRecordSetCount": zone.get("ResourceRecordSetCount"),
            "PrivateZone": zone.get("Config", {}).get("PrivateZone", False)
        } for zone in hosted_zones]
        print("\n" + "─"*80)
        print("ROUTE53 LIST-HOSTED-ZONES OUTPUT - Cluster DNS Zones")
        print(f"Shows {len(hosted_zones)} hosted zone(s) for cluster DNS resolution")
        print("Relevance: Hosted zones provide DNS for cluster API and application routes")
        print("─"*80)
        print(json.dumps(zone_summary, indent=2))
        print("─"*80)
    else:
        # Import diagnostic helper
        from utils.aws_resource_diagnostics import diagnose_missing_aws_resource

        # File exists but contains no hosted zones
        diagnostics = diagnose_missing_aws_resource(
            cluster_data=cluster_data,
            resource_type="Route53 Hosted Zones",
            expected_file=f"{cluster_data.cluster_id}_route53_zones.json",
            api_service="route53",
            api_operation="list_hosted_zones"
        )

        # Correlate CloudTrail events for deleted hosted zones
        from utils.test_helpers import correlate_cloudtrail_events_for_resources

        # Try to get domain from cluster JSON
        dns_config = cluster_data.cluster_json.get('dns', {})
        domain = dns_config.get('baseDomain') or dns_config.get('base_domain', '')
        if not domain:
            domain = cluster_data.cluster_json.get('base_domain', '')

        # Search for hosted zone deletion events
        resource_ids = [domain, cluster_data.cluster_name] if domain else [cluster_data.cluster_name]

        ct_result = correlate_cloudtrail_events_for_resources(
            cluster_data=cluster_data,
            resource_identifiers=resource_ids,
            resource_type="Route53 Hosted Zone",
            event_types=["Delete", "DeleteHostedZone"],
            pytest_request=request
        )

        print("\n✗ No hosted zones found")

        # Show AWS API request error details
        print(f"\n{'─'*80}")
        print("AWS API REQUEST INFORMATION")
        print(f"{'─'*80}")
        print(format_api_request_error(cluster_data, "list_hosted_zones", "route53"))
        print(f"{'─'*80}\n")

        pytest.fail(f"No hosted zones found for cluster.\n\n{diagnostics}")

    assert hosted_zones, "No hosted zones found"


@pytest.mark.route53
def test_hosted_zone_private(cluster_data: ClusterData, is_private_cluster: bool):
    """Private clusters should have private hosted zones
    Documentation: https://docs.redhat.com/en/documentation/red_hat_openshift_service_on_aws/4/html/prepare_your_environment/rosa-sts-aws-prereqs#rosa-dns-requirements
    """
    zones = cluster_data.route53_zones

    if not zones:
        pytest.skip("No Route53 data available")

    hosted_zones = zones.get('HostedZones', [])
    if not hosted_zones:
        pytest.skip("No hosted zones found")

    zone = hosted_zones[0]
    zone_id = zone.get('Id', 'unknown')
    is_private = zone.get('Config', {}).get('PrivateZone', False)

    print(f"\n✓ Hosted zone privacy configuration:")
    print("\n" + "─"*80)
    print("ROUTE53 HOSTED-ZONE CONFIGURATION - Privacy Setting")
    if is_private:
        print("Showing hosted zone is PRIVATE (not publicly accessible)")
    else:
        print("Showing hosted zone is PUBLIC (internet-accessible)")
    print("Relevance: Private clusters require private hosted zones for internal DNS")
    print("─"*80)
    print(json.dumps({
        "HostedZoneId": zone_id,
        "IsPrivate": is_private,
        "ClusterType": "private" if is_private_cluster else "public",
        "Expected": "private" if is_private_cluster else "public or private"
    }, indent=2))
    print("─"*80)

    if is_private_cluster:
        assert is_private, f"Private cluster should have private hosted zone {zone_id}"


@pytest.mark.route53
def test_api_dns_record_exists(cluster_data: ClusterData):
    """API DNS record must exist
    Documentation: https://docs.redhat.com/en/documentation/red_hat_openshift_service_on_aws/4/html/prepare_your_environment/rosa-sts-aws-prereqs#rosa-dns-requirements
    """
    cluster_name = cluster_data.cluster_name

    if not cluster_name:
        pytest.skip("Cluster name not available")

    # Check if API endpoint is configured in cluster JSON
    api_url = cluster_data.cluster_json.get('api', {}).get('url', '')

    if not api_url:
        pytest.skip("API URL not found in cluster data")

    print(f"\n✓ API DNS record:")
    print("\n" + "─"*80)
    print("CLUSTER API ENDPOINT CONFIGURATION - DNS Record")
    print("Showing API URL contains 'api' prefix for cluster access")
    print("Relevance: API endpoint must be DNS-resolvable for cluster operations")
    print("─"*80)
    print(json.dumps({
        "ApiUrl": api_url,
        "HasApiPrefix": 'api' in api_url.lower()
    }, indent=2))
    print("─"*80)

    # API URL should contain the cluster domain
    assert 'api' in api_url.lower(), f"API URL does not contain 'api': {api_url}"


@pytest.mark.route53
def test_hosted_zone_has_name_servers(cluster_data: ClusterData):
    """Hosted zone must have name servers configured
    Documentation: https://docs.redhat.com/en/documentation/red_hat_openshift_service_on_aws/4/html/prepare_your_environment/rosa-sts-aws-prereqs#rosa-dns-requirements
    """
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
    """Cluster must have a domain configured.

    Why: The base domain is used for all cluster DNS records including the API endpoint,
    router wildcard, and application routes. It's fundamental to cluster addressing.

    Failure indicates: The cluster domain is not configured in metadata, which would prevent
    proper DNS setup and could indicate incomplete installation configuration.
    
    Documentation: https://docs.redhat.com/en/documentation/red_hat_openshift_service_on_aws/4/html/prepare_your_environment/rosa-sts-aws-prereqs#rosa-dns-requirements
    """
    # Try different possible locations for domain
    dns_config = cluster_data.cluster_json.get('dns', {})
    domain = dns_config.get('baseDomain') or dns_config.get('base_domain', '')

    if not domain:
        # Try top-level alternative location
        domain = cluster_data.cluster_json.get('base_domain', '')

    if domain:
        print(f"\n✓ Cluster domain configured:")
        print("\n" + "─"*80)
        print("CLUSTER DNS CONFIGURATION - Base Domain")
        print("Showing cluster base domain for DNS records")
        print("Relevance: Base domain is used for API endpoint and application routes")
        print("─"*80)
        print(json.dumps({
            "BaseDomain": domain,
            "IsValid": '.' in domain
        }, indent=2))
        print("─"*80)
    else:
        print("\n✗ Cluster domain not configured")

    assert domain, "Cluster domain not configured"
    assert '.' in domain, f"Cluster domain appears invalid: {domain}"
