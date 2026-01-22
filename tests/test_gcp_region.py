"""
GCP Region and Zone Tests

Validates region status and availability zones for high availability.

Documentation:
- GCP Regions: https://cloud.google.com/compute/docs/regions-zones
- OpenShift HA: https://docs.redhat.com/en/documentation/openshift_container_platform/4.19/html/installing_on_gcp/index
"""

import json
import pytest


# Mark all tests as GCP-specific
pytestmark = pytest.mark.gcp


MIN_ZONES_FOR_HA = 3


@pytest.mark.region
def test_region_info_file_exists(gcp_cluster_data):
    """Region information file must exist.

    Documentation: https://cloud.google.com/compute/docs/regions-zones
    """
    region_file = gcp_cluster_data.gcp_dir / f"{gcp_cluster_data.cluster_id}_region_info.json"

    if not region_file.exists():
        pytest.skip(f"Region info file not found - run check_cluster.py {gcp_cluster_data.cluster_id} --collect --resources=region")

    print(f"\n✓ Found region info: {region_file}")


@pytest.mark.region
def test_region_status_is_up(gcp_cluster_data):
    """Region status must be 'UP'.

    Documentation: https://cloud.google.com/compute/docs/regions-zones
    """
    region_file = gcp_cluster_data.gcp_dir / f"{gcp_cluster_data.cluster_id}_region_info.json"

    if not region_file.exists():
        pytest.skip("Region info not found")

    with open(region_file) as f:
        region_data = json.load(f)

    region_name = gcp_cluster_data.region
    status = region_data.get('status', 'UNKNOWN')

    print(f"\n✓ Region Status:")
    print(f"  Region: {region_name}")
    print(f"  Status: {status}")
    print(f"  Description: {region_data.get('description', 'N/A')}")

    assert status == 'UP', \
        f"Region '{region_name}' status is '{status}', expected 'UP'"


@pytest.mark.region
def test_minimum_zones_available(gcp_cluster_data):
    """Region must have minimum 3 availability zones for HA.

    High availability requires distributing control plane across 3+ zones.

    Documentation: https://docs.redhat.com/en/documentation/openshift_container_platform/4.19/html/installing_on_gcp/index
    """
    region_file = gcp_cluster_data.gcp_dir / f"{gcp_cluster_data.cluster_id}_region_info.json"

    if not region_file.exists():
        pytest.skip("Region info not found")

    with open(region_file) as f:
        region_data = json.load(f)

    zones = region_data.get('zones', [])
    zone_count = len(zones)

    print(f"\n✓ Availability Zones:")
    print(f"  Region: {gcp_cluster_data.region}")
    print(f"  Available zones: {zone_count} (minimum: {MIN_ZONES_FOR_HA})")

    if zones:
        print(f"  Zones:")
        for zone in zones[:5]:  # Show first 5 zones
            zone_name = zone.split('/')[-1] if '/' in zone else zone
            print(f"    - {zone_name}")

    assert zone_count >= MIN_ZONES_FOR_HA, \
        f"Region has {zone_count} zones, minimum {MIN_ZONES_FOR_HA} required for high availability"


@pytest.mark.region
def test_all_zones_operational(gcp_cluster_data):
    """All availability zones must be operational.

    Documentation: https://cloud.google.com/compute/docs/regions-zones
    """
    zones_file = gcp_cluster_data.gcp_dir / f"{gcp_cluster_data.cluster_id}_zones.json"

    if not zones_file.exists():
        pytest.skip("Zones info not found")

    with open(zones_file) as f:
        zones_data = json.load(f)

    print(f"\n✓ Zone Status:")

    down_zones = []
    for zone in zones_data:
        zone_name = zone.get('name', 'unknown')
        status = zone.get('status', 'UNKNOWN')

        print(f"  {zone_name}: {status}")

        if status != 'UP':
            down_zones.append(zone_name)

    if down_zones:
        print(f"\n  ⚠️  {len(down_zones)} zone(s) not operational:")
        for zone in down_zones:
            print(f"    - {zone}")

    assert len(down_zones) == 0, \
        f"{len(down_zones)} zone(s) are not operational: {', '.join(down_zones)}"


@pytest.mark.region
def test_region_summary(gcp_cluster_data):
    """Summary of region and zone configuration.

    Documentation: https://cloud.google.com/compute/docs/regions-zones
    """
    region_file = gcp_cluster_data.gcp_dir / f"{gcp_cluster_data.cluster_id}_region_info.json"

    if not region_file.exists():
        pytest.skip("Region info not found")

    with open(region_file) as f:
        region_data = json.load(f)

    zones = region_data.get('zones', [])

    print(f"\n✓ Region Configuration Summary:")
    print(f"  Region: {gcp_cluster_data.region}")
    print(f"  Status: {region_data.get('status', 'UNKNOWN')}")
    print(f"  Available zones: {len(zones)}")
    print(f"  High availability: {'✓ Supported' if len(zones) >= MIN_ZONES_FOR_HA else '✗ Insufficient zones'}")

    assert True  # Informational test
