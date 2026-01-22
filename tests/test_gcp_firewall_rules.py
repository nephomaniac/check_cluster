"""
GCP Firewall Rules Tests

Validates firewall rules required for OpenShift cluster networking.

CRITICAL: Port 22623 must be accessible from GCP health check IPs for bootstrap to succeed.

Documentation:
- OpenShift Firewall: https://docs.redhat.com/en/documentation/openshift_container_platform/4.16/html/installation_configuration/configuring-firewall
- GCP Firewall: https://cloud.google.com/vpc/docs/firewalls
- GCP Health Checks: https://cloud.google.com/load-balancing/docs/health-check-concepts#ip-ranges
"""

import json
import pytest
import ipaddress


# Mark all tests as GCP-specific
pytestmark = pytest.mark.gcp


# GCP health check IP ranges (required for port 22623 access)
GCP_HEALTH_CHECK_RANGES = [
    "35.191.0.0/16",
    "130.211.0.0/22",
]


def _get_firewall_rules(gcp_cluster_data):
    """Load firewall rules from collected data."""
    firewall_file = gcp_cluster_data.gcp_dir / f"{gcp_cluster_data.cluster_id}_firewall_rules.json"

    if not firewall_file.exists():
        return None

    with open(firewall_file) as f:
        return json.load(f)


def _check_port_allowed(firewall_rules, port, protocol, source_ranges=None, target_tags=None):
    """
    Check if a port is allowed in firewall rules.

    Args:
        firewall_rules: List of firewall rules
        port: Port number to check
        protocol: Protocol (tcp, udp, icmp)
        source_ranges: Optional list of source IP ranges to check
        target_tags: Optional list of target tags to filter rules

    Returns:
        tuple: (allowed, matching_rules)
    """
    if not firewall_rules:
        return False, []

    matching_rules = []

    for rule in firewall_rules:
        # Skip if not allowed rule
        if rule.get('direction') != 'INGRESS':
            continue

        # Check target tags if specified
        if target_tags:
            rule_tags = rule.get('targetTags', [])
            if not any(tag in rule_tags for tag in target_tags):
                continue

        # Check if rule allows this protocol
        allowed = rule.get('allowed', [])
        for allow in allowed:
            if allow.get('IPProtocol').lower() != protocol.lower():
                continue

            # For ICMP, no port check needed
            if protocol.lower() == 'icmp':
                # Check source ranges if specified
                if source_ranges:
                    rule_sources = rule.get('sourceRanges', [])
                    if any(sr in rule_sources for sr in source_ranges):
                        matching_rules.append(rule)
                else:
                    matching_rules.append(rule)
                continue

            # Check ports
            ports = allow.get('ports', [])

            # If no ports specified, all ports are allowed
            if not ports:
                matching_rules.append(rule)
                continue

            # Check if our port is in the allowed ports
            for port_spec in ports:
                if '-' in str(port_spec):
                    # Port range
                    start, end = map(int, port_spec.split('-'))
                    if start <= port <= end:
                        # Check source ranges if specified
                        if source_ranges:
                            rule_sources = rule.get('sourceRanges', [])
                            if any(sr in rule_sources for sr in source_ranges):
                                matching_rules.append(rule)
                        else:
                            matching_rules.append(rule)
                        break
                else:
                    # Single port
                    if int(port_spec) == port:
                        # Check source ranges if specified
                        if source_ranges:
                            rule_sources = rule.get('sourceRanges', [])
                            if any(sr in rule_sources for sr in source_ranges):
                                matching_rules.append(rule)
                        else:
                            matching_rules.append(rule)
                        break

    return len(matching_rules) > 0, matching_rules


@pytest.mark.firewall
def test_firewall_rules_file_exists(gcp_cluster_data):
    """Firewall rules file must exist.

    Documentation: https://cloud.google.com/vpc/docs/firewalls
    """
    firewall_file = gcp_cluster_data.gcp_dir / f"{gcp_cluster_data.cluster_id}_firewall_rules.json"

    if not firewall_file.exists():
        pytest.skip(f"Firewall rules file not found - run check_cluster.py {gcp_cluster_data.cluster_id} --collect --resources=network")

    print(f"\n✓ Found firewall rules: {firewall_file}")


@pytest.mark.firewall
def test_icmp_allowed(gcp_cluster_data):
    """ICMP must be allowed for internal cluster communication.

    ICMP is required for node-to-node communication and health checks.

    Documentation: https://docs.redhat.com/en/documentation/openshift_container_platform/4.16/html/installation_configuration/configuring-firewall
    """
    firewall_rules = _get_firewall_rules(gcp_cluster_data)

    if not firewall_rules:
        pytest.skip("Firewall rules not found")

    allowed, rules = _check_port_allowed(firewall_rules, 0, 'icmp')

    print(f"\n✓ ICMP Protocol:")
    print(f"  Allowed: {allowed}")
    if rules:
        print(f"  Matching rules: {len(rules)}")
        for rule in rules[:3]:  # Show first 3 rules
            print(f"    - {rule.get('name')}")

    assert allowed, \
        "ICMP protocol is not allowed. OpenShift requires ICMP for node communication."


@pytest.mark.firewall
def test_port_22623_allowed_from_health_checks(gcp_cluster_data):
    """Port 22623/TCP must be accessible from GCP health check IPs.

    CRITICAL: This port is required for the Machine Config Server during bootstrap.
    Without access from GCP health check IPs (35.191.0.0/16, 130.211.0.0/22),
    the bootstrap process will fail.

    Documentation:
    - OpenShift: https://docs.redhat.com/en/documentation/openshift_container_platform/4.16/html/installation_configuration/configuring-firewall
    - GCP Health Checks: https://cloud.google.com/load-balancing/docs/health-check-concepts#ip-ranges
    """
    firewall_rules = _get_firewall_rules(gcp_cluster_data)

    if not firewall_rules:
        pytest.skip("Firewall rules not found")

    # Check if port 22623 is allowed from health check IPs
    allowed, rules = _check_port_allowed(
        firewall_rules,
        22623,
        'tcp',
        source_ranges=GCP_HEALTH_CHECK_RANGES
    )

    print(f"\n✓ Port 22623/TCP (Machine Config Server):")
    print(f"  Allowed from GCP health check IPs: {allowed}")
    print(f"  Required source ranges:")
    for cidr in GCP_HEALTH_CHECK_RANGES:
        print(f"    - {cidr}")

    if rules:
        print(f"  Matching rules: {len(rules)}")
        for rule in rules[:3]:
            print(f"    - {rule.get('name')}: {rule.get('sourceRanges', [])}")
    else:
        print(f"\n  ⚠️  CRITICAL: No firewall rule allows port 22623 from health check IPs")
        print(f"  Bootstrap will fail without this rule!")
        print(f"\n  Create firewall rule:")
        print(f"    gcloud compute firewall-rules create {gcp_cluster_data.infra_id}-mcs-health \\")
        print(f"      --network={gcp_cluster_data.vpc_name} \\")
        print(f"      --allow=tcp:22623 \\")
        print(f"      --source-ranges=35.191.0.0/16,130.211.0.0/22 \\")
        print(f"      --target-tags={gcp_cluster_data.infra_id}-master")

    assert allowed, \
        f"Port 22623/TCP must be accessible from GCP health check IPs {GCP_HEALTH_CHECK_RANGES}. " \
        f"This is CRITICAL for bootstrap to succeed."


@pytest.mark.firewall
def test_port_6443_allowed(gcp_cluster_data):
    """Port 6443/TCP must be allowed for Kubernetes API Server.

    Documentation: https://docs.redhat.com/en/documentation/openshift_container_platform/4.16/html/installation_configuration/configuring-firewall
    """
    firewall_rules = _get_firewall_rules(gcp_cluster_data)

    if not firewall_rules:
        pytest.skip("Firewall rules not found")

    allowed, rules = _check_port_allowed(firewall_rules, 6443, 'tcp')

    print(f"\n✓ Port 6443/TCP (Kubernetes API):")
    print(f"  Allowed: {allowed}")
    if rules:
        print(f"  Matching rules: {len(rules)}")

    assert allowed, \
        "Port 6443/TCP (Kubernetes API Server) is not allowed."


@pytest.mark.firewall
def test_etcd_ports_allowed(gcp_cluster_data):
    """Ports 2379-2380/TCP must be allowed for etcd.

    Documentation: https://docs.redhat.com/en/documentation/openshift_container_platform/4.16/html/installation_configuration/configuring-firewall
    """
    firewall_rules = _get_firewall_rules(gcp_cluster_data)

    if not firewall_rules:
        pytest.skip("Firewall rules not found")

    # Check both ports
    port_2379_allowed, _ = _check_port_allowed(firewall_rules, 2379, 'tcp')
    port_2380_allowed, _ = _check_port_allowed(firewall_rules, 2380, 'tcp')

    print(f"\n✓ etcd Ports:")
    print(f"  Port 2379/TCP: {port_2379_allowed}")
    print(f"  Port 2380/TCP: {port_2380_allowed}")

    assert port_2379_allowed, "Port 2379/TCP (etcd) is not allowed"
    assert port_2380_allowed, "Port 2380/TCP (etcd) is not allowed"


@pytest.mark.firewall
def test_vxlan_port_allowed(gcp_cluster_data):
    """Port 4789/UDP must be allowed for VXLAN overlay network.

    Documentation: https://docs.redhat.com/en/documentation/openshift_container_platform/4.16/html/installation_configuration/configuring-firewall
    """
    firewall_rules = _get_firewall_rules(gcp_cluster_data)

    if not firewall_rules:
        pytest.skip("Firewall rules not found")

    allowed, rules = _check_port_allowed(firewall_rules, 4789, 'udp')

    print(f"\n✓ Port 4789/UDP (VXLAN):")
    print(f"  Allowed: {allowed}")

    assert allowed, \
        "Port 4789/UDP (VXLAN overlay) is not allowed."


@pytest.mark.firewall
def test_geneve_port_allowed(gcp_cluster_data):
    """Port 6081/UDP must be allowed for Geneve overlay (OVN-Kubernetes).

    Documentation: https://docs.redhat.com/en/documentation/openshift_container_platform/4.16/html/installation_configuration/configuring-firewall
    """
    firewall_rules = _get_firewall_rules(gcp_cluster_data)

    if not firewall_rules:
        pytest.skip("Firewall rules not found")

    allowed, rules = _check_port_allowed(firewall_rules, 6081, 'udp')

    print(f"\n✓ Port 6081/UDP (Geneve/OVN):")
    print(f"  Allowed: {allowed}")

    assert allowed, \
        "Port 6081/UDP (Geneve overlay for OVN-Kubernetes) is not allowed."


@pytest.mark.firewall
def test_host_services_ports_allowed(gcp_cluster_data):
    """Ports 9000-9999/TCP must be allowed for host services.

    Documentation: https://docs.redhat.com/en/documentation/openshift_container_platform/4.16/html/installation_configuration/configuring-firewall
    """
    firewall_rules = _get_firewall_rules(gcp_cluster_data)

    if not firewall_rules:
        pytest.skip("Firewall rules not found")

    # Check a port in the range
    allowed, rules = _check_port_allowed(firewall_rules, 9000, 'tcp')

    print(f"\n✓ Ports 9000-9999/TCP (Host services):")
    print(f"  Allowed: {allowed}")

    assert allowed, \
        "Ports 9000-9999/TCP (host services) are not allowed."


@pytest.mark.firewall
def test_kubelet_port_allowed(gcp_cluster_data):
    """Port 10250/TCP must be allowed for kubelet.

    Documentation: https://docs.redhat.com/en/documentation/openshift_container_platform/4.16/html/installation_configuration/configuring-firewall
    """
    firewall_rules = _get_firewall_rules(gcp_cluster_data)

    if not firewall_rules:
        pytest.skip("Firewall rules not found")

    allowed, rules = _check_port_allowed(firewall_rules, 10250, 'tcp')

    print(f"\n✓ Port 10250/TCP (kubelet):")
    print(f"  Allowed: {allowed}")

    assert allowed, \
        "Port 10250/TCP (kubelet) is not allowed."


@pytest.mark.firewall
def test_openshift_sdn_port_allowed(gcp_cluster_data):
    """Port 10256/TCP must be allowed for openshift-sdn.

    Documentation: https://docs.redhat.com/en/documentation/openshift_container_platform/4.16/html/installation_configuration/configuring-firewall
    """
    firewall_rules = _get_firewall_rules(gcp_cluster_data)

    if not firewall_rules:
        pytest.skip("Firewall rules not found")

    allowed, rules = _check_port_allowed(firewall_rules, 10256, 'tcp')

    print(f"\n✓ Port 10256/TCP (openshift-sdn):")
    print(f"  Allowed: {allowed}")

    assert allowed, \
        "Port 10256/TCP (openshift-sdn) is not allowed."


@pytest.mark.firewall
def test_control_plane_ports_allowed(gcp_cluster_data):
    """Ports 10257-10259/TCP must be allowed for Kubernetes control plane.

    Documentation: https://docs.redhat.com/en/documentation/openshift_container_platform/4.16/html/installation_configuration/configuring-firewall
    """
    firewall_rules = _get_firewall_rules(gcp_cluster_data)

    if not firewall_rules:
        pytest.skip("Firewall rules not found")

    # Check all three ports
    port_10257_allowed, _ = _check_port_allowed(firewall_rules, 10257, 'tcp')
    port_10258_allowed, _ = _check_port_allowed(firewall_rules, 10258, 'tcp')
    port_10259_allowed, _ = _check_port_allowed(firewall_rules, 10259, 'tcp')

    print(f"\n✓ Control Plane Ports:")
    print(f"  Port 10257/TCP: {port_10257_allowed}")
    print(f"  Port 10258/TCP: {port_10258_allowed}")
    print(f"  Port 10259/TCP: {port_10259_allowed}")

    assert port_10257_allowed, "Port 10257/TCP (kube-scheduler) is not allowed"
    assert port_10258_allowed, "Port 10258/TCP (kube-controller-manager) is not allowed"
    assert port_10259_allowed, "Port 10259/TCP (cloud-controller-manager) is not allowed"


@pytest.mark.firewall
def test_nodeport_tcp_range_allowed(gcp_cluster_data):
    """Ports 30000-32767/TCP must be allowed for NodePort services.

    Documentation: https://docs.redhat.com/en/documentation/openshift_container_platform/4.16/html/installation_configuration/configuring-firewall
    """
    firewall_rules = _get_firewall_rules(gcp_cluster_data)

    if not firewall_rules:
        pytest.skip("Firewall rules not found")

    # Check a port in the NodePort range
    allowed, rules = _check_port_allowed(firewall_rules, 30000, 'tcp')

    print(f"\n✓ Ports 30000-32767/TCP (NodePort):")
    print(f"  Allowed: {allowed}")

    assert allowed, \
        "Ports 30000-32767/TCP (NodePort services) are not allowed."


@pytest.mark.firewall
def test_nodeport_udp_range_allowed(gcp_cluster_data):
    """Ports 30000-32767/UDP must be allowed for NodePort services.

    Documentation: https://docs.redhat.com/en/documentation/openshift_container_platform/4.16/html/installation_configuration/configuring-firewall
    """
    firewall_rules = _get_firewall_rules(gcp_cluster_data)

    if not firewall_rules:
        pytest.skip("Firewall rules not found")

    # Check a port in the NodePort range
    allowed, rules = _check_port_allowed(firewall_rules, 30000, 'udp')

    print(f"\n✓ Ports 30000-32767/UDP (NodePort):")
    print(f"  Allowed: {allowed}")

    assert allowed, \
        "Ports 30000-32767/UDP (NodePort services) are not allowed."


@pytest.mark.firewall
def test_all_critical_ports_summary(gcp_cluster_data):
    """Summary of all critical firewall rules for OpenShift.

    Documentation: https://docs.redhat.com/en/documentation/openshift_container_platform/4.16/html/installation_configuration/configuring-firewall
    """
    firewall_rules = _get_firewall_rules(gcp_cluster_data)

    if not firewall_rules:
        pytest.skip("Firewall rules not found")

    critical_ports = [
        (22623, 'tcp', 'Machine Config Server (CRITICAL for bootstrap)'),
        (6443, 'tcp', 'Kubernetes API Server'),
        (2379, 'tcp', 'etcd'),
        (2380, 'tcp', 'etcd'),
        (10250, 'tcp', 'kubelet'),
    ]

    print(f"\n✓ Critical Firewall Rules Status:")

    all_allowed = True
    for port, protocol, description in critical_ports:
        allowed, _ = _check_port_allowed(firewall_rules, port, protocol)
        status = "✓" if allowed else "✗"
        print(f"  {status} Port {port}/{protocol.upper()}: {description}")
        if not allowed:
            all_allowed = False

    assert all_allowed, \
        "Not all critical firewall rules are configured. See summary above."
