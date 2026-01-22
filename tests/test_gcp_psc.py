"""
GCP Private Service Connect (PSC) Tests

Validates Private Service Connect configuration for private clusters.

Documentation:
- GCP PSC: https://cloud.google.com/vpc/docs/private-service-connect
- OpenShift Private Clusters: https://docs.redhat.com/en/documentation/openshift_container_platform/4.19/html/installing_on_gcp/index
"""

import json
import pytest
import ipaddress


# Mark all tests as GCP-specific
pytestmark = [pytest.mark.gcp, pytest.mark.psc]


MIN_PSC_SUBNET_PREFIX = 29  # /29 provides 8 IPs (3 usable)


@pytest.mark.psc
def test_psc_enabled(gcp_cluster_data):
    """Check if Private Service Connect is enabled for this cluster.

    Documentation: https://cloud.google.com/vpc/docs/private-service-connect
    """
    is_psc = gcp_cluster_data.is_psc

    print(f"\n✓ Private Service Connect:")
    print(f"  Enabled: {is_psc}")

    if not is_psc:
        pytest.skip("Private Service Connect is not enabled for this cluster")


@pytest.mark.psc
def test_psc_subnet_exists(gcp_cluster_data):
    """PSC subnet must exist when PSC is enabled.

    Documentation: https://cloud.google.com/vpc/docs/private-service-connect
    """
    if not gcp_cluster_data.is_psc:
        pytest.skip("PSC not enabled")

    subnets_file = gcp_cluster_data.gcp_dir / f"{gcp_cluster_data.cluster_id}_subnets.json"

    if not subnets_file.exists():
        pytest.skip("Subnets file not found")

    with open(subnets_file) as f:
        subnets_data = json.load(f)

    # Find PSC subnet (purpose = PRIVATE_SERVICE_CONNECT)
    psc_subnet = None
    for subnet in subnets_data:
        if subnet.get('purpose') == 'PRIVATE_SERVICE_CONNECT':
            psc_subnet = subnet
            break

    print(f"\n✓ PSC Subnet:")
    if psc_subnet:
        print(f"  Name: {psc_subnet.get('name')}")
        print(f"  CIDR: {psc_subnet.get('ipCidrRange')}")
        print(f"  Purpose: {psc_subnet.get('purpose')}")
        print(f"  Region: {psc_subnet.get('region', '').split('/')[-1]}")
    else:
        print(f"  ✗ PSC subnet not found")

    assert psc_subnet is not None, \
        "Private Service Connect subnet not found"


@pytest.mark.psc
def test_psc_subnet_purpose(gcp_cluster_data):
    """PSC subnet must have purpose 'PRIVATE_SERVICE_CONNECT'.

    Documentation: https://cloud.google.com/vpc/docs/private-service-connect
    """
    if not gcp_cluster_data.is_psc:
        pytest.skip("PSC not enabled")

    subnets_file = gcp_cluster_data.gcp_dir / f"{gcp_cluster_data.cluster_id}_subnets.json"

    if not subnets_file.exists():
        pytest.skip("Subnets file not found")

    with open(subnets_file) as f:
        subnets_data = json.load(f)

    # Find PSC subnet
    psc_subnet = None
    for subnet in subnets_data:
        if subnet.get('purpose') == 'PRIVATE_SERVICE_CONNECT':
            psc_subnet = subnet
            break

    if not psc_subnet:
        pytest.skip("PSC subnet not found")

    purpose = psc_subnet.get('purpose')

    print(f"\n✓ PSC Subnet Purpose:")
    print(f"  Purpose: {purpose}")

    assert purpose == 'PRIVATE_SERVICE_CONNECT', \
        f"PSC subnet purpose must be 'PRIVATE_SERVICE_CONNECT', got '{purpose}'"


@pytest.mark.psc
def test_psc_subnet_size(gcp_cluster_data):
    """PSC subnet must have adequate size (minimum /29).

    A /29 provides 8 IP addresses (3 usable after GCP reservations).

    Documentation: https://cloud.google.com/vpc/docs/private-service-connect
    """
    if not gcp_cluster_data.is_psc:
        pytest.skip("PSC not enabled")

    subnets_file = gcp_cluster_data.gcp_dir / f"{gcp_cluster_data.cluster_id}_subnets.json"

    if not subnets_file.exists():
        pytest.skip("Subnets file not found")

    with open(subnets_file) as f:
        subnets_data = json.load(f)

    # Find PSC subnet
    psc_subnet = None
    for subnet in subnets_data:
        if subnet.get('purpose') == 'PRIVATE_SERVICE_CONNECT':
            psc_subnet = subnet
            break

    if not psc_subnet:
        pytest.skip("PSC subnet not found")

    cidr = psc_subnet.get('ipCidrRange')
    network = ipaddress.ip_network(cidr)
    prefix_len = network.prefixlen

    print(f"\n✓ PSC Subnet Size:")
    print(f"  CIDR: {cidr}")
    print(f"  Prefix length: /{prefix_len}")
    print(f"  Total IPs: {network.num_addresses}")
    print(f"  Usable IPs: {network.num_addresses - 5}")  # GCP reserves some IPs

    if prefix_len > MIN_PSC_SUBNET_PREFIX:
        print(f"\n  ⚠️  WARNING: Subnet is smaller than /{MIN_PSC_SUBNET_PREFIX} minimum")

    assert prefix_len <= MIN_PSC_SUBNET_PREFIX, \
        f"PSC subnet /{prefix_len} is too small. Minimum /{MIN_PSC_SUBNET_PREFIX} required."


@pytest.mark.psc
def test_psc_service_attachments_exist(gcp_cluster_data):
    """Service attachments must be configured for PSC.

    Documentation: https://cloud.google.com/vpc/docs/configure-private-service-connect-services
    """
    if not gcp_cluster_data.is_psc:
        pytest.skip("PSC not enabled")

    psc_file = gcp_cluster_data.gcp_dir / f"{gcp_cluster_data.cluster_id}_psc_config.json"

    if not psc_file.exists():
        pytest.skip("PSC configuration file not found")

    with open(psc_file) as f:
        psc_data = json.load(f)

    service_attachments = psc_data.get('serviceAttachments', [])

    print(f"\n✓ PSC Service Attachments:")
    print(f"  Count: {len(service_attachments)}")

    if service_attachments:
        for sa in service_attachments[:3]:  # Show first 3
            print(f"    - {sa.get('name')}")
            print(f"      Target service: {sa.get('targetService', 'N/A')}")
    else:
        print(f"  ✗ No service attachments found")

    assert len(service_attachments) > 0, \
        "No Private Service Connect service attachments found"


@pytest.mark.psc
def test_psc_summary(gcp_cluster_data):
    """Summary of Private Service Connect configuration.

    Documentation: https://cloud.google.com/vpc/docs/private-service-connect
    """
    if not gcp_cluster_data.is_psc:
        pytest.skip("PSC not enabled")

    print(f"\n✓ Private Service Connect Summary:")
    print(f"  PSC enabled: {gcp_cluster_data.is_psc}")
    print(f"  Private cluster: {gcp_cluster_data.is_private}")

    subnets_file = gcp_cluster_data.gcp_dir / f"{gcp_cluster_data.cluster_id}_subnets.json"
    if subnets_file.exists():
        with open(subnets_file) as f:
            subnets_data = json.load(f)

        psc_subnet = None
        for subnet in subnets_data:
            if subnet.get('purpose') == 'PRIVATE_SERVICE_CONNECT':
                psc_subnet = subnet
                break

        if psc_subnet:
            print(f"\n  PSC Subnet:")
            print(f"    Name: {psc_subnet.get('name')}")
            print(f"    CIDR: {psc_subnet.get('ipCidrRange')}")

    assert True  # Informational test
