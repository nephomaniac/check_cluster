"""
GCP Load Balancer Tests

Validates load balancer configuration for OpenShift cluster.

Documentation:
- GCP Load Balancing: https://cloud.google.com/load-balancing/docs
- OpenShift on GCP: https://docs.redhat.com/en/documentation/openshift_container_platform/4.19/html/installing_on_gcp/index
"""

import json
import pytest


# Mark all tests as GCP-specific
pytestmark = pytest.mark.gcp


@pytest.mark.loadbalancer
def test_load_balancers_file_exists(gcp_cluster_data):
    """Load balancers configuration file must exist.

    Documentation: https://cloud.google.com/load-balancing/docs
    """
    lb_file = gcp_cluster_data.gcp_dir / f"{gcp_cluster_data.cluster_id}_load_balancers.json"

    if not lb_file.exists():
        pytest.skip(f"Load balancers file not found - run check_cluster.py {gcp_cluster_data.cluster_id} --collect --resources=loadbalancer")

    print(f"\n✓ Found load balancers: {lb_file}")


@pytest.mark.loadbalancer
def test_forwarding_rules_exist(gcp_cluster_data):
    """Forwarding rules must exist for load balancers.

    Documentation: https://cloud.google.com/load-balancing/docs/forwarding-rule-concepts
    """
    lb_file = gcp_cluster_data.gcp_dir / f"{gcp_cluster_data.cluster_id}_load_balancers.json"

    if not lb_file.exists():
        pytest.skip("Load balancers file not found")

    with open(lb_file) as f:
        lb_data = json.load(f)

    forwarding_rules = lb_data.get('forwardingRules', [])

    print(f"\n✓ Forwarding Rules:")
    print(f"  Count: {len(forwarding_rules)}")

    if forwarding_rules:
        for rule in forwarding_rules[:5]:  # Show first 5
            print(f"    - {rule.get('name')}")
            print(f"      IP: {rule.get('IPAddress', 'N/A')}")
            print(f"      Port range: {rule.get('portRange', 'N/A')}")
            print(f"      Load balancing scheme: {rule.get('loadBalancingScheme', 'N/A')}")
    else:
        print(f"  ✗ No forwarding rules found")

    assert len(forwarding_rules) > 0, \
        "No forwarding rules found for cluster load balancers"


@pytest.mark.loadbalancer
def test_internal_load_balancer_exists(gcp_cluster_data):
    """Internal load balancer must exist for API access.

    Documentation: https://cloud.google.com/load-balancing/docs/internal
    """
    lb_file = gcp_cluster_data.gcp_dir / f"{gcp_cluster_data.cluster_id}_load_balancers.json"

    if not lb_file.exists():
        pytest.skip("Load balancers file not found")

    with open(lb_file) as f:
        lb_data = json.load(f)

    forwarding_rules = lb_data.get('forwardingRules', [])

    # Find internal load balancer
    internal_lb = None
    for rule in forwarding_rules:
        scheme = rule.get('loadBalancingScheme', '')
        if 'INTERNAL' in scheme:
            internal_lb = rule
            break

    print(f"\n✓ Internal Load Balancer:")
    if internal_lb:
        print(f"  Name: {internal_lb.get('name')}")
        print(f"  IP: {internal_lb.get('IPAddress', 'N/A')}")
        print(f"  Scheme: {internal_lb.get('loadBalancingScheme')}")
        print(f"  Backend: {internal_lb.get('backendService', 'N/A')}")
    else:
        print(f"  ✗ No internal load balancer found")

    assert internal_lb is not None, \
        "Internal load balancer not found"


@pytest.mark.loadbalancer
def test_backend_services_exist(gcp_cluster_data):
    """Backend services must be configured.

    Documentation: https://cloud.google.com/load-balancing/docs/backend-service
    """
    lb_file = gcp_cluster_data.gcp_dir / f"{gcp_cluster_data.cluster_id}_load_balancers.json"

    if not lb_file.exists():
        pytest.skip("Load balancers file not found")

    with open(lb_file) as f:
        lb_data = json.load(f)

    backend_services = lb_data.get('backendServices', [])

    print(f"\n✓ Backend Services:")
    print(f"  Count: {len(backend_services)}")

    if backend_services:
        for service in backend_services[:3]:  # Show first 3
            print(f"    - {service.get('name')}")
            print(f"      Protocol: {service.get('protocol', 'N/A')}")
            print(f"      Health checks: {len(service.get('healthChecks', []))}")
    else:
        print(f"  ✗ No backend services found")

    assert len(backend_services) > 0, \
        "No backend services configured"


@pytest.mark.loadbalancer
def test_health_checks_configured(gcp_cluster_data):
    """Health checks must be configured for backend services.

    Documentation: https://cloud.google.com/load-balancing/docs/health-checks
    """
    lb_file = gcp_cluster_data.gcp_dir / f"{gcp_cluster_data.cluster_id}_load_balancers.json"

    if not lb_file.exists():
        pytest.skip("Load balancers file not found")

    with open(lb_file) as f:
        lb_data = json.load(f)

    health_checks = lb_data.get('healthChecks', [])

    print(f"\n✓ Health Checks:")
    print(f"  Count: {len(health_checks)}")

    if health_checks:
        for hc in health_checks[:3]:  # Show first 3
            print(f"    - {hc.get('name')}")
            hc_type = 'HTTPS' if hc.get('httpsHealthCheck') else 'HTTP' if hc.get('httpHealthCheck') else 'TCP' if hc.get('tcpHealthCheck') else 'Unknown'
            print(f"      Type: {hc_type}")
            if hc.get('httpsHealthCheck'):
                print(f"      Port: {hc.get('httpsHealthCheck', {}).get('port', 'N/A')}")
            elif hc.get('httpHealthCheck'):
                print(f"      Port: {hc.get('httpHealthCheck', {}).get('port', 'N/A')}")
    else:
        print(f"  ✗ No health checks found")

    assert len(health_checks) > 0, \
        "No health checks configured"


@pytest.mark.loadbalancer
def test_load_balancer_summary(gcp_cluster_data):
    """Summary of load balancer configuration.

    Documentation: https://cloud.google.com/load-balancing/docs
    """
    lb_file = gcp_cluster_data.gcp_dir / f"{gcp_cluster_data.cluster_id}_load_balancers.json"

    if not lb_file.exists():
        pytest.skip("Load balancers file not found")

    with open(lb_file) as f:
        lb_data = json.load(f)

    forwarding_rules = lb_data.get('forwardingRules', [])
    backend_services = lb_data.get('backendServices', [])
    health_checks = lb_data.get('healthChecks', [])

    print(f"\n✓ Load Balancer Configuration Summary:")
    print(f"  Forwarding rules: {len(forwarding_rules)}")
    print(f"  Backend services: {len(backend_services)}")
    print(f"  Health checks: {len(health_checks)}")

    # Count internal vs external
    internal_count = sum(1 for r in forwarding_rules if 'INTERNAL' in r.get('loadBalancingScheme', ''))
    external_count = len(forwarding_rules) - internal_count

    print(f"\n  Load Balancing Schemes:")
    print(f"    Internal: {internal_count}")
    print(f"    External: {external_count}")

    assert True  # Informational test
