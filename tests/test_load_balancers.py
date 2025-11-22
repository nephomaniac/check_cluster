"""
Load Balancer Tests

Validates load balancer configuration for ROSA cluster API and ingress.
"""

import pytest
from models.cluster import ClusterData


def get_load_balancers_by_infra_id(cluster_data: ClusterData) -> list:
    """Get load balancers that belong to this cluster"""
    infra_id = cluster_data.infra_id
    lbs = []

    lb_data = cluster_data.load_balancers.get('LoadBalancers', [])
    for lb in lb_data:
        lb_name = lb.get('LoadBalancerName', '')
        if infra_id in lb_name:
            lbs.append(lb)

    return lbs


def get_api_load_balancer(cluster_data: ClusterData) -> dict:
    """Get the API/control plane load balancer"""
    lbs = get_load_balancers_by_infra_id(cluster_data)

    for lb in lbs:
        lb_name = lb.get('LoadBalancerName', '')
        # API LB typically contains 'ext' or 'api' in name
        if 'ext' in lb_name.lower() or 'api' in lb_name.lower():
            return lb

    return {}


def get_ingress_load_balancer(cluster_data: ClusterData) -> dict:
    """Get the ingress/router load balancer"""
    lbs = get_load_balancers_by_infra_id(cluster_data)

    for lb in lbs:
        lb_name = lb.get('LoadBalancerName', '')
        # Ingress LB typically contains 'int' or 'router' in name
        if 'int' in lb_name.lower() or 'router' in lb_name.lower():
            return lb

    return {}


@pytest.mark.load_balancers
def test_load_balancers_exist(cluster_data: ClusterData):
    """Cluster must have load balancers configured"""
    lbs = get_load_balancers_by_infra_id(cluster_data)
    assert lbs, "No load balancers found for cluster"


@pytest.mark.load_balancers
def test_api_load_balancer_exists(cluster_data: ClusterData):
    """API load balancer must exist"""
    api_lb = get_api_load_balancer(cluster_data)
    assert api_lb, "API load balancer not found"


@pytest.mark.load_balancers
def test_api_load_balancer_healthy(cluster_data: ClusterData):
    """API load balancer must be in active state"""
    api_lb = get_api_load_balancer(cluster_data)

    if not api_lb:
        pytest.skip("API load balancer not found")

    lb_name = api_lb.get('LoadBalancerName', 'unknown')
    state = api_lb.get('State', {}).get('Code', 'unknown')

    assert state == 'active', f"API load balancer {lb_name} is not active (state: {state})"


@pytest.mark.load_balancers
def test_api_load_balancer_scheme(cluster_data: ClusterData, is_private_cluster: bool):
    """API load balancer scheme must match cluster type (public/private)"""
    api_lb = get_api_load_balancer(cluster_data)

    if not api_lb:
        pytest.skip("API load balancer not found")

    lb_name = api_lb.get('LoadBalancerName', 'unknown')
    scheme = api_lb.get('Scheme', '')

    expected_scheme = 'internal' if is_private_cluster else 'internet-facing'

    assert scheme == expected_scheme, \
        f"API load balancer {lb_name} has scheme '{scheme}', expected '{expected_scheme}'"


@pytest.mark.load_balancers
def test_api_load_balancer_has_listeners(cluster_data: ClusterData):
    """API load balancer must have listeners configured"""
    api_lb = get_api_load_balancer(cluster_data)

    if not api_lb:
        pytest.skip("API load balancer not found")

    lb_name = api_lb.get('LoadBalancerName', 'unknown')
    listeners = api_lb.get('ListenerDescriptions', [])

    assert listeners, f"API load balancer {lb_name} has no listeners configured"


@pytest.mark.load_balancers
def test_api_load_balancer_port_6443(cluster_data: ClusterData):
    """API load balancer must listen on port 6443"""
    api_lb = get_api_load_balancer(cluster_data)

    if not api_lb:
        pytest.skip("API load balancer not found")

    lb_name = api_lb.get('LoadBalancerName', 'unknown')
    listeners = api_lb.get('ListenerDescriptions', [])

    ports = []
    for listener_desc in listeners:
        listener = listener_desc.get('Listener', {})
        port = listener.get('LoadBalancerPort')
        if port:
            ports.append(port)

    assert 6443 in ports, f"API load balancer {lb_name} not listening on port 6443 (ports: {ports})"


@pytest.mark.load_balancers
def test_api_load_balancer_port_22623(cluster_data: ClusterData):
    """API load balancer must listen on port 22623 (MCS)"""
    api_lb = get_api_load_balancer(cluster_data)

    if not api_lb:
        pytest.skip("API load balancer not found")

    lb_name = api_lb.get('LoadBalancerName', 'unknown')
    listeners = api_lb.get('ListenerDescriptions', [])

    ports = []
    for listener_desc in listeners:
        listener = listener_desc.get('Listener', {})
        port = listener.get('LoadBalancerPort')
        if port:
            ports.append(port)

    assert 22623 in ports, f"API load balancer {lb_name} not listening on port 22623 (ports: {ports})"


@pytest.mark.load_balancers
def test_load_balancers_have_security_groups(cluster_data: ClusterData):
    """Load balancers must have security groups attached"""
    lbs = get_load_balancers_by_infra_id(cluster_data)

    lbs_without_sgs = []
    for lb in lbs:
        lb_name = lb.get('LoadBalancerName', 'unknown')
        security_groups = lb.get('SecurityGroups', [])

        if not security_groups:
            lbs_without_sgs.append(lb_name)

    assert not lbs_without_sgs, f"Load balancers without security groups: {', '.join(lbs_without_sgs)}"


@pytest.mark.load_balancers
def test_load_balancers_in_multiple_azs(cluster_data: ClusterData):
    """Load balancers should be in multiple availability zones for HA"""
    lbs = get_load_balancers_by_infra_id(cluster_data)

    for lb in lbs:
        lb_name = lb.get('LoadBalancerName', 'unknown')
        azs = lb.get('AvailabilityZones', [])

        if len(azs) < 2:
            pytest.fail(f"Load balancer {lb_name} only in {len(azs)} AZ(s), expected multiple for HA")


@pytest.mark.load_balancers
def test_api_load_balancer_has_dns_name(cluster_data: ClusterData):
    """API load balancer must have DNS name"""
    api_lb = get_api_load_balancer(cluster_data)

    if not api_lb:
        pytest.skip("API load balancer not found")

    lb_name = api_lb.get('LoadBalancerName', 'unknown')
    dns_name = api_lb.get('DNSName', '')

    assert dns_name, f"API load balancer {lb_name} has no DNS name"
    assert '.elb.' in dns_name, f"API load balancer DNS name appears invalid: {dns_name}"
