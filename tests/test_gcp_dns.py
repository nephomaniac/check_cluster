"""
GCP DNS Configuration Tests

Validates Cloud DNS zones and records for OpenShift cluster.

Documentation:
- Cloud DNS: https://cloud.google.com/dns/docs
- OpenShift DNS Requirements: https://docs.redhat.com/en/documentation/openshift_container_platform/4.19/html/installing_on_gcp/index
"""

import json
import pytest


# Mark all tests as GCP-specific
pytestmark = pytest.mark.gcp


@pytest.mark.dns
def test_dns_zones_file_exists(gcp_cluster_data):
    """DNS zones file must exist.

    Documentation: https://cloud.google.com/dns/docs/zones
    """
    dns_zones_file = gcp_cluster_data.gcp_dir / f"{gcp_cluster_data.cluster_id}_dns_zones.json"

    if not dns_zones_file.exists():
        pytest.skip(f"DNS zones file not found - run check_cluster.py {gcp_cluster_data.cluster_id} --collect --resources=network")

    print(f"\n✓ Found DNS zones: {dns_zones_file}")


@pytest.mark.dns
def test_private_dns_zone_exists(gcp_cluster_data):
    """Private DNS zone must exist for cluster.

    The zone name should be: {infra_id}-private-zone

    Documentation: https://cloud.google.com/dns/docs/zones#create-private-zone
    """
    dns_zones_file = gcp_cluster_data.gcp_dir / f"{gcp_cluster_data.cluster_id}_dns_zones.json"

    if not dns_zones_file.exists():
        pytest.skip("DNS zones file not found")

    with open(dns_zones_file) as f:
        zones_data = json.load(f)

    # Expected private zone name
    expected_zone_name = f"{gcp_cluster_data.infra_id}-private-zone"

    # Find private zone
    private_zone = None
    for zone in zones_data.get('managedZones', []):
        if zone.get('name') == expected_zone_name:
            private_zone = zone
            break

    print(f"\n✓ Private DNS Zone:")
    if private_zone:
        print(f"  Name: {private_zone.get('name')}")
        print(f"  DNS name: {private_zone.get('dnsName')}")
        print(f"  Visibility: {private_zone.get('visibility')}")
        print(f"  Description: {private_zone.get('description', 'N/A')}")
    else:
        print(f"  ✗ Not found: {expected_zone_name}")

    assert private_zone is not None, \
        f"Private DNS zone '{expected_zone_name}' not found"


@pytest.mark.dns
def test_dns_zone_visibility(gcp_cluster_data):
    """DNS zone visibility must be 'private'.

    Documentation: https://cloud.google.com/dns/docs/zones#create-private-zone
    """
    dns_zones_file = gcp_cluster_data.gcp_dir / f"{gcp_cluster_data.cluster_id}_dns_zones.json"

    if not dns_zones_file.exists():
        pytest.skip("DNS zones file not found")

    with open(dns_zones_file) as f:
        zones_data = json.load(f)

    expected_zone_name = f"{gcp_cluster_data.infra_id}-private-zone"

    # Find private zone
    private_zone = None
    for zone in zones_data.get('managedZones', []):
        if zone.get('name') == expected_zone_name:
            private_zone = zone
            break

    if not private_zone:
        pytest.skip("Private DNS zone not found")

    visibility = private_zone.get('visibility')

    print(f"\n✓ DNS Zone Visibility:")
    print(f"  Zone: {expected_zone_name}")
    print(f"  Visibility: {visibility}")

    assert visibility == 'private', \
        f"DNS zone visibility must be 'private', got '{visibility}'"


@pytest.mark.dns
def test_dns_zone_attached_to_vpc(gcp_cluster_data):
    """DNS zone must be attached to cluster VPC.

    Documentation: https://cloud.google.com/dns/docs/zones#create-private-zone
    """
    dns_zones_file = gcp_cluster_data.gcp_dir / f"{gcp_cluster_data.cluster_id}_dns_zones.json"

    if not dns_zones_file.exists():
        pytest.skip("DNS zones file not found")

    with open(dns_zones_file) as f:
        zones_data = json.load(f)

    expected_zone_name = f"{gcp_cluster_data.infra_id}-private-zone"

    # Find private zone
    private_zone = None
    for zone in zones_data.get('managedZones', []):
        if zone.get('name') == expected_zone_name:
            private_zone = zone
            break

    if not private_zone:
        pytest.skip("Private DNS zone not found")

    # Check private visibility config
    private_visibility_config = private_zone.get('privateVisibilityConfig', {})
    networks = private_visibility_config.get('networks', [])

    print(f"\n✓ DNS Zone VPC Attachment:")
    print(f"  Expected VPC: {gcp_cluster_data.vpc_name}")
    print(f"  Attached networks: {len(networks)}")

    attached_to_cluster_vpc = False
    for network in networks:
        network_url = network.get('networkUrl', '')
        print(f"    - {network_url}")
        if gcp_cluster_data.vpc_name in network_url:
            attached_to_cluster_vpc = True

    assert attached_to_cluster_vpc, \
        f"DNS zone must be attached to cluster VPC '{gcp_cluster_data.vpc_name}'"


@pytest.mark.dns
def test_dns_records_file_exists(gcp_cluster_data):
    """DNS records file must exist.

    Documentation: https://cloud.google.com/dns/docs/records
    """
    dns_records_file = gcp_cluster_data.gcp_dir / f"{gcp_cluster_data.cluster_id}_dns_records.json"

    if not dns_records_file.exists():
        pytest.skip(f"DNS records file not found - run check_cluster.py {gcp_cluster_data.cluster_id} --collect --resources=network")

    print(f"\n✓ Found DNS records: {dns_records_file}")


@pytest.mark.dns
def test_api_dns_record_exists(gcp_cluster_data):
    """API A record must exist for cluster.

    The record should be: api.{cluster_name}.{base_domain}

    Documentation: https://cloud.google.com/dns/docs/records
    """
    dns_records_file = gcp_cluster_data.gcp_dir / f"{gcp_cluster_data.cluster_id}_dns_records.json"

    if not dns_records_file.exists():
        pytest.skip("DNS records file not found")

    with open(dns_records_file) as f:
        records_data = json.load(f)

    # Look for API record (api.cluster-name.base-domain)
    # The record name pattern varies, so we look for records containing 'api'
    api_records = []
    for record in records_data.get('rrsets', []):
        name = record.get('name', '')
        if 'api' in name.lower() and record.get('type') == 'A':
            api_records.append(record)

    print(f"\n✓ API DNS Records:")
    print(f"  Found: {len(api_records)}")

    if api_records:
        for record in api_records[:3]:  # Show first 3
            print(f"    - {record.get('name')}")
            print(f"      Type: {record.get('type')}")
            print(f"      TTL: {record.get('ttl')}")
            rrdatas = record.get('rrdatas', [])
            if rrdatas:
                print(f"      IP: {rrdatas[0]}")
    else:
        print(f"  ✗ No API A records found")

    assert len(api_records) > 0, \
        "API A record not found in DNS zone"


@pytest.mark.dns
def test_api_int_dns_record_exists(gcp_cluster_data):
    """Internal API A record must exist for cluster.

    The record should be: api-int.{cluster_name}.{base_domain}

    Documentation: https://cloud.google.com/dns/docs/records
    """
    dns_records_file = gcp_cluster_data.gcp_dir / f"{gcp_cluster_data.cluster_id}_dns_records.json"

    if not dns_records_file.exists():
        pytest.skip("DNS records file not found")

    with open(dns_records_file) as f:
        records_data = json.load(f)

    # Look for internal API record (api-int.cluster-name.base-domain)
    api_int_records = []
    for record in records_data.get('rrsets', []):
        name = record.get('name', '')
        if 'api-int' in name.lower() and record.get('type') == 'A':
            api_int_records.append(record)

    print(f"\n✓ Internal API DNS Records:")
    print(f"  Found: {len(api_int_records)}")

    if api_int_records:
        for record in api_int_records[:3]:  # Show first 3
            print(f"    - {record.get('name')}")
            print(f"      Type: {record.get('type')}")
            print(f"      TTL: {record.get('ttl')}")
            rrdatas = record.get('rrdatas', [])
            if rrdatas:
                print(f"      IP: {rrdatas[0]}")
    else:
        print(f"  ✗ No internal API A records found")

    assert len(api_int_records) > 0, \
        "Internal API (api-int) A record not found in DNS zone"


@pytest.mark.dns
def test_dns_configuration_summary(gcp_cluster_data):
    """Summary of DNS configuration.

    Documentation: https://cloud.google.com/dns/docs
    """
    dns_zones_file = gcp_cluster_data.gcp_dir / f"{gcp_cluster_data.cluster_id}_dns_zones.json"
    dns_records_file = gcp_cluster_data.gcp_dir / f"{gcp_cluster_data.cluster_id}_dns_records.json"

    if not dns_zones_file.exists() or not dns_records_file.exists():
        pytest.skip("DNS configuration files not found")

    with open(dns_zones_file) as f:
        zones_data = json.load(f)

    with open(dns_records_file) as f:
        records_data = json.load(f)

    expected_zone_name = f"{gcp_cluster_data.infra_id}-private-zone"

    # Find private zone
    private_zone = None
    for zone in zones_data.get('managedZones', []):
        if zone.get('name') == expected_zone_name:
            private_zone = zone
            break

    # Count record types
    a_records = [r for r in records_data.get('rrsets', []) if r.get('type') == 'A']
    cname_records = [r for r in records_data.get('rrsets', []) if r.get('type') == 'CNAME']
    srv_records = [r for r in records_data.get('rrsets', []) if r.get('type') == 'SRV']

    print(f"\n✓ DNS Configuration Summary:")

    if private_zone:
        print(f"\n  DNS Zone:")
        print(f"    Name: {private_zone.get('name')}")
        print(f"    DNS Name: {private_zone.get('dnsName')}")
        print(f"    Visibility: {private_zone.get('visibility')}")

    print(f"\n  DNS Records:")
    print(f"    A records: {len(a_records)}")
    print(f"    CNAME records: {len(cname_records)}")
    print(f"    SRV records: {len(srv_records)}")
    print(f"    Total: {len(records_data.get('rrsets', []))}")

    # Look for critical records
    has_api = any('api' in r.get('name', '').lower() for r in a_records)
    has_api_int = any('api-int' in r.get('name', '').lower() for r in a_records)

    print(f"\n  Critical Records:")
    print(f"    API record: {'✓' if has_api else '✗'}")
    print(f"    API-INT record: {'✓' if has_api_int else '✗'}")

    assert private_zone is not None, "Private DNS zone not found"
    assert has_api, "API DNS record not found"
    assert has_api_int, "Internal API DNS record not found"
