"""
GCP Project Quotas Tests

Validates that GCP project has sufficient quotas for OpenShift cluster installation.

Documentation:
- GCP Quotas: https://cloud.google.com/docs/quotas
- OpenShift on GCP Requirements: https://docs.redhat.com/en/documentation/openshift_container_platform/4.19/html/installing_on_gcp/index
"""

import json
import pytest
from pathlib import Path


# Mark all tests as GCP-specific
pytestmark = pytest.mark.gcp


REQUIRED_QUOTAS = {
    "CPUS": 24,  # Minimum for 3 control plane + 2 workers
    "IN_USE_ADDRESSES": 10,
    "STATIC_ADDRESSES": 4,
    "SSD_TOTAL_GB": 500,
    "PERSISTENT_DISK_SSD_GB": 500,
    "FORWARDING_RULES": 4,
    "TARGET_POOLS": 2,
    "HEALTH_CHECKS": 4,
    "FIREWALLS": 11,
    "ROUTES": 20,
}


@pytest.mark.quotas
def test_project_quotas_file_exists(gcp_cluster_data):
    """Project quotas file must exist.

    Documentation: https://cloud.google.com/compute/quotas
    """
    quotas_file = gcp_cluster_data.gcp_dir / f"{gcp_cluster_data.cluster_id}_project_quotas.json"

    if not quotas_file.exists():
        pytest.skip(f"Project quotas file not found - run check_cluster.py {gcp_cluster_data.cluster_id} --collect --resources=quotas")

    print(f"\n✓ Found project quotas: {quotas_file}")


@pytest.mark.quotas
def test_cpu_quota_sufficient(gcp_cluster_data):
    """Project must have sufficient CPU quota.

    Documentation: https://docs.redhat.com/en/documentation/openshift_container_platform/4.19/html/installing_on_gcp/index#installation-gcp-limits_installing-gcp-customizations
    """
    quotas_file = gcp_cluster_data.gcp_dir / f"{gcp_cluster_data.cluster_id}_project_quotas.json"

    if not quotas_file.exists():
        pytest.skip("Project quotas file not found")

    with open(quotas_file) as f:
        quotas_data = json.load(f)

    region = gcp_cluster_data.region

    # Get CPU quota
    cpu_quota = None
    for quota in quotas_data.get('quotas', []):
        if quota.get('metric') == 'CPUS':
            # Check if regional or global
            quota_region = quota.get('region')
            if quota_region == region or quota_region is None:
                cpu_quota = quota
                break

    if not cpu_quota:
        pytest.fail(f"CPUS quota not found for region {region}")

    limit = int(cpu_quota.get('limit', 0))
    usage = int(cpu_quota.get('usage', 0))
    available = limit - usage
    required = REQUIRED_QUOTAS['CPUS']

    print(f"\n✓ CPU Quota:")
    print(f"  Limit: {limit}")
    print(f"  Used: {usage}")
    print(f"  Available: {available}")
    print(f"  Required: {required}")

    assert available >= required, \
        f"Insufficient CPU quota: {available} available, {required} required (limit: {limit}, used: {usage})"


@pytest.mark.quotas
def test_address_quota_sufficient(gcp_cluster_data):
    """Project must have sufficient IP address quota.

    Documentation: https://cloud.google.com/compute/quotas#checking_your_quota
    """
    quotas_file = gcp_cluster_data.gcp_dir / f"{gcp_cluster_data.cluster_id}_project_quotas.json"

    if not quotas_file.exists():
        pytest.skip("Project quotas file not found")

    with open(quotas_file) as f:
        quotas_data = json.load(f)

    region = gcp_cluster_data.region
    required = REQUIRED_QUOTAS['IN_USE_ADDRESSES']

    # Get address quota
    for quota in quotas_data.get('quotas', []):
        if quota.get('metric') == 'IN_USE_ADDRESSES':
            quota_region = quota.get('region')
            if quota_region == region or quota_region is None:
                limit = int(quota.get('limit', 0))
                usage = int(quota.get('usage', 0))
                available = limit - usage

                print(f"\n✓ IP Address Quota:")
                print(f"  Available: {available}, Required: {required}")

                assert available >= required, \
                    f"Insufficient address quota: {available} available, {required} required"
                return

    pytest.skip("IN_USE_ADDRESSES quota not found")


@pytest.mark.quotas
def test_static_address_quota(gcp_cluster_data):
    """Project must have sufficient static IP address quota.

    Documentation: https://cloud.google.com/compute/quotas
    """
    quotas_file = gcp_cluster_data.gcp_dir / f"{gcp_cluster_data.cluster_id}_project_quotas.json"

    if not quotas_file.exists():
        pytest.skip("Project quotas file not found")

    with open(quotas_file) as f:
        quotas_data = json.load(f)

    region = gcp_cluster_data.region
    required = REQUIRED_QUOTAS['STATIC_ADDRESSES']

    for quota in quotas_data.get('quotas', []):
        if quota.get('metric') == 'STATIC_ADDRESSES':
            quota_region = quota.get('region')
            if quota_region == region or quota_region is None:
                limit = int(quota.get('limit', 0))
                usage = int(quota.get('usage', 0))
                available = limit - usage

                print(f"\n✓ Static IP Quota:")
                print(f"  Available: {available}, Required: {required}")

                assert available >= required, \
                    f"Insufficient static address quota: {available} available, {required} required"
                return

    pytest.skip("STATIC_ADDRESSES quota not found")


@pytest.mark.quotas
def test_ssd_storage_quota(gcp_cluster_data):
    """Project must have sufficient SSD storage quota.

    Documentation: https://cloud.google.com/compute/docs/disks
    """
    quotas_file = gcp_cluster_data.gcp_dir / f"{gcp_cluster_data.cluster_id}_project_quotas.json"

    if not quotas_file.exists():
        pytest.skip("Project quotas file not found")

    with open(quotas_file) as f:
        quotas_data = json.load(f)

    region = gcp_cluster_data.region
    required = REQUIRED_QUOTAS['SSD_TOTAL_GB']

    # Try both quota names
    for metric in ['SSD_TOTAL_GB', 'PERSISTENT_DISK_SSD_GB']:
        for quota in quotas_data.get('quotas', []):
            if quota.get('metric') == metric:
                quota_region = quota.get('region')
                if quota_region == region or quota_region is None:
                    limit = int(quota.get('limit', 0))
                    usage = int(quota.get('usage', 0))
                    available = limit - usage

                    print(f"\n✓ SSD Storage Quota ({metric}):")
                    print(f"  Available: {available}GB, Required: {required}GB")

                    assert available >= required, \
                        f"Insufficient SSD storage quota: {available}GB available, {required}GB required"
                    return

    pytest.skip("SSD storage quota not found")


@pytest.mark.quotas
def test_firewall_rules_quota(gcp_cluster_data):
    """Project must have sufficient firewall rules quota.

    Documentation: https://cloud.google.com/vpc/docs/firewalls
    """
    quotas_file = gcp_cluster_data.gcp_dir / f"{gcp_cluster_data.cluster_id}_project_quotas.json"

    if not quotas_file.exists():
        pytest.skip("Project quotas file not found")

    with open(quotas_file) as f:
        quotas_data = json.load(f)

    required = REQUIRED_QUOTAS['FIREWALLS']

    for quota in quotas_data.get('quotas', []):
        if quota.get('metric') == 'FIREWALLS':
            limit = int(quota.get('limit', 0))
            usage = int(quota.get('usage', 0))
            available = limit - usage

            print(f"\n✓ Firewall Rules Quota:")
            print(f"  Available: {available}, Required: {required}")

            assert available >= required, \
                f"Insufficient firewall quota: {available} available, {required} required"
            return

    pytest.skip("FIREWALLS quota not found")


@pytest.mark.quotas
def test_forwarding_rules_quota(gcp_cluster_data):
    """Project must have sufficient forwarding rules quota for load balancers.

    Documentation: https://cloud.google.com/load-balancing/docs/quotas
    """
    quotas_file = gcp_cluster_data.gcp_dir / f"{gcp_cluster_data.cluster_id}_project_quotas.json"

    if not quotas_file.exists():
        pytest.skip("Project quotas file not found")

    with open(quotas_file) as f:
        quotas_data = json.load(f)

    region = gcp_cluster_data.region
    required = REQUIRED_QUOTAS['FORWARDING_RULES']

    for quota in quotas_data.get('quotas', []):
        if quota.get('metric') == 'FORWARDING_RULES':
            quota_region = quota.get('region')
            if quota_region == region or quota_region is None:
                limit = int(quota.get('limit', 0))
                usage = int(quota.get('usage', 0))
                available = limit - usage

                print(f"\n✓ Forwarding Rules Quota:")
                print(f"  Available: {available}, Required: {required}")

                assert available >= required, \
                    f"Insufficient forwarding rules quota: {available} available, {required} required"
                return

    pytest.skip("FORWARDING_RULES quota not found")


@pytest.mark.quotas
def test_routes_quota(gcp_cluster_data):
    """Project must have sufficient routes quota.

    Documentation: https://cloud.google.com/vpc/docs/quota
    """
    quotas_file = gcp_cluster_data.gcp_dir / f"{gcp_cluster_data.cluster_id}_project_quotas.json"

    if not quotas_file.exists():
        pytest.skip("Project quotas file not found")

    with open(quotas_file) as f:
        quotas_data = json.load(f)

    required = REQUIRED_QUOTAS['ROUTES']

    for quota in quotas_data.get('quotas', []):
        if quota.get('metric') == 'ROUTES':
            limit = int(quota.get('limit', 0))
            usage = int(quota.get('usage', 0))
            available = limit - usage

            print(f"\n✓ Routes Quota:")
            print(f"  Available: {available}, Required: {required}")

            assert available >= required, \
                f"Insufficient routes quota: {available} available, {required} required"
            return

    pytest.skip("ROUTES quota not found")
