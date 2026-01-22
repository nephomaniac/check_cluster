"""
GCP Network Configuration Tests

Validates VPC, subnets, Cloud NAT, and routing configuration for OpenShift.

Documentation:
- OpenShift on GCP Network: https://docs.redhat.com/en/documentation/openshift_container_platform/4.19/html/installing_on_gcp/index#installation-gcp-network-config_installing-gcp-customizations
- GCP VPC: https://cloud.google.com/vpc/docs
"""

import json
import pytest
import ipaddress


# Mark all tests as GCP-specific
pytestmark = pytest.mark.gcp


@pytest.mark.network
def test_vpc_config_file_exists(gcp_cluster_data):
    """VPC configuration file must exist.

    Documentation: https://cloud.google.com/vpc/docs
    """
    vpc_file = gcp_cluster_data.gcp_dir / f"{gcp_cluster_data.cluster_id}_vpc.json"

    if not vpc_file.exists():
        pytest.skip(f"VPC config file not found - run check_cluster.py {gcp_cluster_data.cluster_id} --collect --resources=network")

    print(f"\n✓ Found VPC config: {vpc_file}")


@pytest.mark.network
def test_vpc_exists(gcp_cluster_data):
    """VPC must exist and be accessible.

    Documentation: https://cloud.google.com/vpc/docs
    """
    vpc_file = gcp_cluster_data.gcp_dir / f"{gcp_cluster_data.cluster_id}_vpc.json"

    if not vpc_file.exists():
        pytest.skip("VPC config not found")

    with open(vpc_file) as f:
        vpc_data = json.load(f)

    vpc_name = gcp_cluster_data.vpc_name

    print(f"\n✓ VPC Configuration:")
    print(f"  Name: {vpc_name}")
    print(f"  Auto-create subnets: {vpc_data.get('autoCreateSubnetworks', False)}")
    print(f"  Routing mode: {vpc_data.get('routingConfig', {}).get('routingMode', 'REGIONAL')}")

    assert vpc_data, "VPC configuration is empty"
    assert vpc_data.get('name') == vpc_name, \
        f"VPC name mismatch: expected {vpc_name}, got {vpc_data.get('name')}"


@pytest.mark.network
def test_subnets_config_exists(gcp_cluster_data):
    """Subnets configuration file must exist.

    Documentation: https://cloud.google.com/vpc/docs/subnets
    """
    subnets_file = gcp_cluster_data.gcp_dir / f"{gcp_cluster_data.cluster_id}_subnets.json"

    if not subnets_file.exists():
        pytest.skip(f"Subnets config file not found - run check_cluster.py {gcp_cluster_data.cluster_id} --collect --resources=network")

    print(f"\n✓ Found subnets config: {subnets_file}")


@pytest.mark.network
def test_control_plane_subnet_exists(gcp_cluster_data):
    """Control plane subnet must exist.

    Documentation: https://docs.redhat.com/en/documentation/openshift_container_platform/4.19/html/installing_on_gcp/index#installation-gcp-network-config_installing-gcp-customizations
    """
    subnets_file = gcp_cluster_data.gcp_dir / f"{gcp_cluster_data.cluster_id}_subnets.json"

    if not subnets_file.exists():
        pytest.skip("Subnets config not found")

    with open(subnets_file) as f:
        subnets_data = json.load(f)

    cp_subnet_name = gcp_cluster_data.cp_subnet

    # Find control plane subnet
    cp_subnet = None
    for subnet in subnets_data:
        if subnet.get('name') == cp_subnet_name:
            cp_subnet = subnet
            break

    print(f"\n✓ Control Plane Subnet:")
    if cp_subnet:
        print(f"  Name: {cp_subnet.get('name')}")
        print(f"  CIDR: {cp_subnet.get('ipCidrRange')}")
        print(f"  Region: {cp_subnet.get('region', '').split('/')[-1]}")
    else:
        print(f"  ✗ Not found: {cp_subnet_name}")

    assert cp_subnet is not None, \
        f"Control plane subnet '{cp_subnet_name}' not found"


@pytest.mark.network
def test_control_plane_subnet_size(gcp_cluster_data):
    """Control plane subnet must have adequate size (minimum /28, recommended /27).

    A /28 provides 16 IP addresses (11 usable).
    A /27 provides 32 IP addresses (27 usable) - recommended.

    Documentation: https://docs.redhat.com/en/documentation/openshift_container_platform/4.19/html/installing_on_gcp/index#installation-gcp-network-config_installing-gcp-customizations
    """
    subnets_file = gcp_cluster_data.gcp_dir / f"{gcp_cluster_data.cluster_id}_subnets.json"

    if not subnets_file.exists():
        pytest.skip("Subnets config not found")

    with open(subnets_file) as f:
        subnets_data = json.load(f)

    cp_subnet_name = gcp_cluster_data.cp_subnet

    # Find control plane subnet
    cp_subnet = None
    for subnet in subnets_data:
        if subnet.get('name') == cp_subnet_name:
            cp_subnet = subnet
            break

    if not cp_subnet:
        pytest.skip("Control plane subnet not found")

    cidr = cp_subnet.get('ipCidrRange')
    network = ipaddress.ip_network(cidr)
    prefix_len = network.prefixlen

    print(f"\n✓ Control Plane Subnet Size:")
    print(f"  CIDR: {cidr}")
    print(f"  Prefix length: /{prefix_len}")
    print(f"  Total IPs: {network.num_addresses}")
    print(f"  Usable IPs: {network.num_addresses - 5}")  # GCP reserves 4 IPs + broadcast

    if prefix_len > 28:
        print(f"\n  ⚠️  WARNING: Subnet is smaller than /28 minimum")

    assert prefix_len <= 28, \
        f"Control plane subnet /{prefix_len} is too small. Minimum /28 required (recommended /27)."


@pytest.mark.network
def test_worker_subnet_exists(gcp_cluster_data):
    """Worker subnet must exist.

    Documentation: https://docs.redhat.com/en/documentation/openshift_container_platform/4.19/html/installing_on_gcp/index#installation-gcp-network-config_installing-gcp-customizations
    """
    subnets_file = gcp_cluster_data.gcp_dir / f"{gcp_cluster_data.cluster_id}_subnets.json"

    if not subnets_file.exists():
        pytest.skip("Subnets config not found")

    with open(subnets_file) as f:
        subnets_data = json.load(f)

    worker_subnet_name = gcp_cluster_data.worker_subnet

    # Find worker subnet
    worker_subnet = None
    for subnet in subnets_data:
        if subnet.get('name') == worker_subnet_name:
            worker_subnet = subnet
            break

    print(f"\n✓ Worker Subnet:")
    if worker_subnet:
        print(f"  Name: {worker_subnet.get('name')}")
        print(f"  CIDR: {worker_subnet.get('ipCidrRange')}")
        print(f"  Region: {worker_subnet.get('region', '').split('/')[-1]}")
    else:
        print(f"  ✗ Not found: {worker_subnet_name}")

    assert worker_subnet is not None, \
        f"Worker subnet '{worker_subnet_name}' not found"


@pytest.mark.network
def test_worker_subnet_size(gcp_cluster_data):
    """Worker subnet must have adequate size (minimum /24, recommended /23).

    A /24 provides 256 IP addresses (251 usable) - limited scalability.
    A /23 provides 512 IP addresses (507 usable) - recommended for production.

    Documentation: https://docs.redhat.com/en/documentation/openshift_container_platform/4.19/html/installing_on_gcp/index#installation-gcp-network-config_installing-gcp-customizations
    """
    subnets_file = gcp_cluster_data.gcp_dir / f"{gcp_cluster_data.cluster_id}_subnets.json"

    if not subnets_file.exists():
        pytest.skip("Subnets config not found")

    with open(subnets_file) as f:
        subnets_data = json.load(f)

    worker_subnet_name = gcp_cluster_data.worker_subnet

    # Find worker subnet
    worker_subnet = None
    for subnet in subnets_data:
        if subnet.get('name') == worker_subnet_name:
            worker_subnet = subnet
            break

    if not worker_subnet:
        pytest.skip("Worker subnet not found")

    cidr = worker_subnet.get('ipCidrRange')
    network = ipaddress.ip_network(cidr)
    prefix_len = network.prefixlen

    print(f"\n✓ Worker Subnet Size:")
    print(f"  CIDR: {cidr}")
    print(f"  Prefix length: /{prefix_len}")
    print(f"  Total IPs: {network.num_addresses}")
    print(f"  Usable IPs: {network.num_addresses - 5}")  # GCP reserves 4 IPs + broadcast

    if prefix_len > 24:
        print(f"\n  ⚠️  WARNING: Subnet is smaller than /24 minimum")
    elif prefix_len == 24:
        print(f"\n  ⚠️  NOTE: /24 subnet limits scalability. /23 recommended for production.")

    assert prefix_len <= 24, \
        f"Worker subnet /{prefix_len} is too small. Minimum /24 required (recommended /23)."


@pytest.mark.network
def test_private_google_access_enabled(gcp_cluster_data):
    """Private Google Access must be enabled for private clusters.

    Allows instances without external IPs to access Google APIs.

    Documentation: https://cloud.google.com/vpc/docs/private-google-access
    """
    subnets_file = gcp_cluster_data.gcp_dir / f"{gcp_cluster_data.cluster_id}_subnets.json"

    if not subnets_file.exists():
        pytest.skip("Subnets config not found")

    with open(subnets_file) as f:
        subnets_data = json.load(f)

    # Check both control plane and worker subnets
    cp_subnet_name = gcp_cluster_data.cp_subnet
    worker_subnet_name = gcp_cluster_data.worker_subnet

    print(f"\n✓ Private Google Access:")

    issues = []
    for subnet in subnets_data:
        subnet_name = subnet.get('name')
        if subnet_name in [cp_subnet_name, worker_subnet_name]:
            pga_enabled = subnet.get('privateIpGoogleAccess', False)
            print(f"  {subnet_name}: {pga_enabled}")

            if not pga_enabled and gcp_cluster_data.is_private:
                issues.append(subnet_name)

    if issues:
        print(f"\n  ⚠️  Private Google Access should be enabled for private clusters")
        print(f"  Subnets without PGA: {', '.join(issues)}")

    # Only fail if this is a private cluster
    if gcp_cluster_data.is_private:
        assert len(issues) == 0, \
            f"Private Google Access must be enabled for private cluster subnets: {', '.join(issues)}"


@pytest.mark.network
def test_cloud_nat_exists(gcp_cluster_data):
    """Cloud NAT must exist for private clusters.

    Cloud NAT allows instances without external IPs to access the internet.

    Documentation: https://cloud.google.com/nat/docs/overview
    """
    nat_file = gcp_cluster_data.gcp_dir / f"{gcp_cluster_data.cluster_id}_cloud_nat.json"

    # Only check for private clusters
    if not gcp_cluster_data.is_private:
        pytest.skip("Cloud NAT only required for private clusters")

    if not nat_file.exists():
        print(f"\n  ⚠️  Cloud NAT config not found for private cluster")
        print(f"  Private clusters require Cloud NAT for internet access")
        pytest.fail("Cloud NAT configuration not found for private cluster")

    with open(nat_file) as f:
        nat_data = json.load(f)

    print(f"\n✓ Cloud NAT Configuration:")
    if isinstance(nat_data, list) and len(nat_data) > 0:
        nat = nat_data[0]
        print(f"  Name: {nat.get('name')}")
        print(f"  NAT IP allocation: {nat.get('natIpAllocateOption')}")
        print(f"  Source subnet ranges: {nat.get('sourceSubnetworkIpRangesToNat')}")
    else:
        print(f"  ✗ No Cloud NAT configuration found")
        pytest.fail("Cloud NAT must be configured for private clusters")


@pytest.mark.network
def test_routes_exist(gcp_cluster_data):
    """VPC routes must exist, including default internet route.

    Documentation: https://cloud.google.com/vpc/docs/routes
    """
    routes_file = gcp_cluster_data.gcp_dir / f"{gcp_cluster_data.cluster_id}_routes.json"

    if not routes_file.exists():
        pytest.skip("Routes config not found")

    with open(routes_file) as f:
        routes_data = json.load(f)

    # Check for default internet route (0.0.0.0/0)
    default_route = None
    for route in routes_data:
        if route.get('destRange') == '0.0.0.0/0':
            default_route = route
            break

    print(f"\n✓ VPC Routes:")
    print(f"  Total routes: {len(routes_data)}")
    print(f"  Default internet route: {'Found' if default_route else 'Not found'}")

    if default_route:
        print(f"    Next hop: {default_route.get('nextHopGateway', default_route.get('nextHopInstance', 'Unknown'))}")

    assert len(routes_data) > 0, "No VPC routes found"


@pytest.mark.network
def test_network_summary(gcp_cluster_data):
    """Summary of network configuration.

    Documentation: https://docs.redhat.com/en/documentation/openshift_container_platform/4.19/html/installing_on_gcp/index#installation-gcp-network-config_installing-gcp-customizations
    """
    subnets_file = gcp_cluster_data.gcp_dir / f"{gcp_cluster_data.cluster_id}_subnets.json"

    if not subnets_file.exists():
        pytest.skip("Subnets config not found")

    with open(subnets_file) as f:
        subnets_data = json.load(f)

    print(f"\n✓ Network Configuration Summary:")
    print(f"  VPC: {gcp_cluster_data.vpc_name}")
    print(f"  Region: {gcp_cluster_data.region}")
    print(f"  Private cluster: {gcp_cluster_data.is_private}")

    # Find subnets
    cp_subnet = None
    worker_subnet = None
    for subnet in subnets_data:
        if subnet.get('name') == gcp_cluster_data.cp_subnet:
            cp_subnet = subnet
        if subnet.get('name') == gcp_cluster_data.worker_subnet:
            worker_subnet = subnet

    if cp_subnet:
        print(f"\n  Control Plane Subnet:")
        print(f"    Name: {cp_subnet.get('name')}")
        print(f"    CIDR: {cp_subnet.get('ipCidrRange')}")
        print(f"    Private Google Access: {cp_subnet.get('privateIpGoogleAccess', False)}")

    if worker_subnet:
        print(f"\n  Worker Subnet:")
        print(f"    Name: {worker_subnet.get('name')}")
        print(f"    CIDR: {worker_subnet.get('ipCidrRange')}")
        print(f"    Private Google Access: {worker_subnet.get('privateIpGoogleAccess', False)}")

    # Validate basic requirements
    assert cp_subnet is not None, "Control plane subnet not found"
    assert worker_subnet is not None, "Worker subnet not found"
