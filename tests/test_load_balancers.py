"""
Load Balancer Tests

Validates load balancer configuration for ROSA cluster API and ingress.
Includes target groups and target health validation.
"""

import pytest
import json
from pathlib import Path
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
    """API load balancer must have listeners configured (Classic LB only)"""
    api_lb = get_api_load_balancer(cluster_data)

    if not api_lb:
        pytest.skip("API load balancer not found")

    lb_type = api_lb.get('Type', 'classic')

    # Network Load Balancers store listeners separately, not in describe-load-balancers output
    if lb_type == 'network':
        pytest.skip("Network Load Balancers require separate listener API call (not in load balancer data)")

    lb_name = api_lb.get('LoadBalancerName', 'unknown')
    listeners = api_lb.get('ListenerDescriptions', [])

    assert listeners, f"API load balancer {lb_name} has no listeners configured"


@pytest.mark.load_balancers
def test_api_load_balancer_port_6443(cluster_data: ClusterData):
    """API load balancer must listen on port 6443 (Classic LB only)"""
    api_lb = get_api_load_balancer(cluster_data)

    if not api_lb:
        pytest.skip("API load balancer not found")

    lb_type = api_lb.get('Type', 'classic')

    # Network Load Balancers store listeners separately
    if lb_type == 'network':
        pytest.skip("Network Load Balancers require separate listener API call (not in load balancer data)")

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
    """API load balancer must listen on port 22623 (MCS - Classic LB only)"""
    api_lb = get_api_load_balancer(cluster_data)

    if not api_lb:
        pytest.skip("API load balancer not found")

    lb_type = api_lb.get('Type', 'classic')

    # Network Load Balancers store listeners separately
    if lb_type == 'network':
        pytest.skip("Network Load Balancers require separate listener API call (not in load balancer data)")

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
    """Load balancers should be in multiple availability zones for HA (multi-AZ clusters only)"""
    lbs = get_load_balancers_by_infra_id(cluster_data)

    # Check if this is a multi-AZ cluster
    multi_az = cluster_data.cluster_json.get('multi_az', False)

    for lb in lbs:
        lb_name = lb.get('LoadBalancerName', 'unknown')
        azs = lb.get('AvailabilityZones', [])

        # For multi-AZ clusters, expect LBs in multiple AZs
        if multi_az and len(azs) < 2:
            pytest.fail(f"Multi-AZ cluster: Load balancer {lb_name} only in {len(azs)} AZ(s), expected multiple for HA")

        # For single-AZ clusters, just verify at least one AZ
        if not multi_az and len(azs) < 1:
            pytest.fail(f"Load balancer {lb_name} has no availability zones configured")


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


# ========================================
# Target Group Tests
# ========================================


@pytest.mark.load_balancers
def test_target_groups_exist(cluster_data: ClusterData, infra_id: str):
    """Cluster should have target groups for load balancers"""
    tg_file = cluster_data.data_dir / f"{cluster_data.cluster_id}_target_groups.json"

    if not tg_file.exists():
        pytest.skip(f"Target groups file not found: {tg_file}")

    with open(tg_file) as f:
        tg_data = json.load(f)

    target_groups = tg_data.get('TargetGroups', [])

    # Filter to cluster target groups
    cluster_tgs = [tg for tg in target_groups
                   if tg.get('VpcId') and infra_id in tg.get('TargetGroupName', '')]

    # Also check VPC ID match (may not have infra_id in name for all TGs)
    if len(cluster_tgs) == 0:
        # Try to match by VPC
        vpc_file = cluster_data.data_dir / f"{cluster_data.cluster_id}_VPC_IDS.json"
        if vpc_file.exists():
            with open(vpc_file) as f:
                vpc_ids = json.load(f)
            cluster_tgs = [tg for tg in target_groups if tg.get('VpcId') in vpc_ids]

    assert len(cluster_tgs) > 0, f"No target groups found for cluster {infra_id}"


@pytest.mark.load_balancers
def test_api_target_group_exists(cluster_data: ClusterData, infra_id: str):
    """API load balancer should have target group on port 6443"""
    tg_file = cluster_data.data_dir / f"{cluster_data.cluster_id}_target_groups.json"

    if not tg_file.exists():
        pytest.skip(f"Target groups file not found: {tg_file}")

    with open(tg_file) as f:
        tg_data = json.load(f)

    target_groups = tg_data.get('TargetGroups', [])

    # Find API target group (port 6443)
    api_tgs = [tg for tg in target_groups
               if tg.get('Port') == 6443 and
               ('apiserver' in tg.get('TargetGroupName', '').lower() or
                infra_id in tg.get('TargetGroupName', ''))]

    assert len(api_tgs) > 0, f"No API target group found (port 6443)"


@pytest.mark.load_balancers
def test_mcs_target_group_exists(cluster_data: ClusterData, infra_id: str):
    """Cluster should have target group for Machine Config Server (port 22623)"""
    tg_file = cluster_data.data_dir / f"{cluster_data.cluster_id}_target_groups.json"

    if not tg_file.exists():
        pytest.skip(f"Target groups file not found: {tg_file}")

    with open(tg_file) as f:
        tg_data = json.load(f)

    target_groups = tg_data.get('TargetGroups', [])

    # Find MCS target group (port 22623)
    mcs_tgs = [tg for tg in target_groups
               if tg.get('Port') == 22623]

    assert len(mcs_tgs) > 0, f"No MCS target group found (port 22623)"


@pytest.mark.load_balancers
def test_target_groups_have_health_checks(cluster_data: ClusterData, infra_id: str):
    """All target groups should have health checks enabled"""
    tg_file = cluster_data.data_dir / f"{cluster_data.cluster_id}_target_groups.json"

    if not tg_file.exists():
        pytest.skip(f"Target groups file not found: {tg_file}")

    with open(tg_file) as f:
        tg_data = json.load(f)

    target_groups = tg_data.get('TargetGroups', [])

    # Filter to cluster target groups
    vpc_file = cluster_data.data_dir / f"{cluster_data.cluster_id}_VPC_IDS.json"
    vpc_ids = []
    if vpc_file.exists():
        with open(vpc_file) as f:
            vpc_ids = json.load(f)

    cluster_tgs = [tg for tg in target_groups if tg.get('VpcId') in vpc_ids] if vpc_ids else target_groups

    tgs_without_health_checks = []
    for tg in cluster_tgs:
        tg_name = tg.get('TargetGroupName', 'unknown')
        if not tg.get('HealthCheckEnabled', False):
            tgs_without_health_checks.append(tg_name)

    assert len(tgs_without_health_checks) == 0, \
        f"Target groups without health checks: {', '.join(tgs_without_health_checks)}"


@pytest.mark.load_balancers
def test_api_target_group_health_check_path(cluster_data: ClusterData, infra_id: str):
    """API target group should use /readyz health check path"""
    tg_file = cluster_data.data_dir / f"{cluster_data.cluster_id}_target_groups.json"

    if not tg_file.exists():
        pytest.skip(f"Target groups file not found: {tg_file}")

    with open(tg_file) as f:
        tg_data = json.load(f)

    target_groups = tg_data.get('TargetGroups', [])

    # Find API target group (port 6443)
    api_tgs = [tg for tg in target_groups
               if tg.get('Port') == 6443 and
               ('apiserver' in tg.get('TargetGroupName', '').lower() or
                infra_id in tg.get('TargetGroupName', ''))]

    if len(api_tgs) == 0:
        pytest.skip("No API target group found")

    for api_tg in api_tgs:
        tg_name = api_tg.get('TargetGroupName', 'unknown')
        health_check_path = api_tg.get('HealthCheckPath', '')

        # API server should use /readyz for health checks
        assert health_check_path == '/readyz', \
            f"API target group {tg_name} using '{health_check_path}', expected '/readyz'"


@pytest.mark.load_balancers
def test_mcs_target_group_health_check_path(cluster_data: ClusterData, infra_id: str):
    """MCS target group should use /healthz health check path"""
    tg_file = cluster_data.data_dir / f"{cluster_data.cluster_id}_target_groups.json"

    if not tg_file.exists():
        pytest.skip(f"Target groups file not found: {tg_file}")

    with open(tg_file) as f:
        tg_data = json.load(f)

    target_groups = tg_data.get('TargetGroups', [])

    # Find MCS target group (port 22623)
    mcs_tgs = [tg for tg in target_groups
               if tg.get('Port') == 22623]

    if len(mcs_tgs) == 0:
        pytest.skip("No MCS target group found")

    for mcs_tg in mcs_tgs:
        tg_name = mcs_tg.get('TargetGroupName', 'unknown')
        health_check_path = mcs_tg.get('HealthCheckPath', '')

        # MCS should use /healthz for health checks
        assert health_check_path == '/healthz', \
            f"MCS target group {tg_name} using '{health_check_path}', expected '/healthz'"


@pytest.mark.load_balancers
def test_target_health_no_unhealthy_targets(cluster_data: ClusterData, infra_id: str):
    """Target groups should not have unhealthy targets (best effort check)"""
    # Look for target health files
    target_health_files = list(cluster_data.data_dir.glob(f"{cluster_data.cluster_id}_*_target_health.json"))

    if len(target_health_files) == 0:
        pytest.skip("No target health files found")

    unhealthy_targets = []
    for health_file in target_health_files:
        tg_name = health_file.stem.replace(f"{cluster_data.cluster_id}_", "").replace("_target_health", "")

        with open(health_file) as f:
            health_data = json.load(f)

        target_health_descriptions = health_data.get('TargetHealthDescriptions', [])

        for target_desc in target_health_descriptions:
            target = target_desc.get('Target', {})
            target_health = target_desc.get('TargetHealth', {})

            target_id = target.get('Id', 'unknown')
            health_state = target_health.get('State', 'unknown')
            health_reason = target_health.get('Reason', '')

            if health_state not in ['healthy', 'initial', 'unused']:
                unhealthy_targets.append(
                    f"{tg_name}: {target_id} (state: {health_state}, reason: {health_reason})"
                )

    assert len(unhealthy_targets) == 0, \
        f"Unhealthy targets found: {'; '.join(unhealthy_targets)}"


@pytest.mark.load_balancers
def test_target_groups_have_targets_registered(cluster_data: ClusterData, infra_id: str):
    """Target groups should have targets registered"""
    # Look for target health files
    target_health_files = list(cluster_data.data_dir.glob(f"{cluster_data.cluster_id}_*_target_health.json"))

    if len(target_health_files) == 0:
        pytest.skip("No target health files found")

    tgs_without_targets = []
    for health_file in target_health_files:
        tg_name = health_file.stem.replace(f"{cluster_data.cluster_id}_", "").replace("_target_health", "")

        with open(health_file) as f:
            health_data = json.load(f)

        target_health_descriptions = health_data.get('TargetHealthDescriptions', [])

        if len(target_health_descriptions) == 0:
            tgs_without_targets.append(tg_name)

    assert len(tgs_without_targets) == 0, \
        f"Target groups with no registered targets: {', '.join(tgs_without_targets)}"


# ========================================
# Load Balancer Listener Tests
# ========================================


@pytest.mark.load_balancers
def test_nlb_listeners_exist(cluster_data: ClusterData, infra_id: str):
    """Network Load Balancers should have listeners configured"""
    # Look for listener files
    listener_files = list(cluster_data.data_dir.glob(f"{cluster_data.cluster_id}_*_listeners.json"))

    if len(listener_files) == 0:
        pytest.skip("No listener files found")

    # Verify each listener file has listeners
    lbs_without_listeners = []
    for listener_file in listener_files:
        lb_name = listener_file.stem.replace(f"{cluster_data.cluster_id}_", "").replace("_listeners", "")

        with open(listener_file) as f:
            listener_data = json.load(f)

        listeners = listener_data.get('Listeners', [])

        if len(listeners) == 0:
            lbs_without_listeners.append(lb_name)

    assert len(lbs_without_listeners) == 0, \
        f"Load balancers without listeners: {', '.join(lbs_without_listeners)}"


@pytest.mark.load_balancers
def test_api_nlb_listener_port_6443(cluster_data: ClusterData, infra_id: str):
    """API NLB should have listener on port 6443"""
    # Look for API load balancer listener file
    api_lb_pattern = f"{cluster_data.cluster_id}_*ext*_listeners.json"
    listener_files = list(cluster_data.data_dir.glob(api_lb_pattern))

    if len(listener_files) == 0:
        pytest.skip("No API load balancer listener files found")

    for listener_file in listener_files:
        lb_name = listener_file.stem.replace(f"{cluster_data.cluster_id}_", "").replace("_listeners", "")

        with open(listener_file) as f:
            listener_data = json.load(f)

        listeners = listener_data.get('Listeners', [])
        ports = [listener.get('Port') for listener in listeners]

        assert 6443 in ports, \
            f"API load balancer {lb_name} not listening on port 6443 (ports: {ports})"


@pytest.mark.load_balancers
def test_api_nlb_listener_port_22623(cluster_data: ClusterData, infra_id: str):
    """API NLB should have listener on port 22623 (MCS)"""
    # Look for internal load balancer listener file (has MCS)
    int_lb_pattern = f"{cluster_data.cluster_id}_*int*_listeners.json"
    listener_files = list(cluster_data.data_dir.glob(int_lb_pattern))

    if len(listener_files) == 0:
        pytest.skip("No internal load balancer listener files found")

    found_mcs_port = False
    for listener_file in listener_files:
        lb_name = listener_file.stem.replace(f"{cluster_data.cluster_id}_", "").replace("_listeners", "")

        with open(listener_file) as f:
            listener_data = json.load(f)

        listeners = listener_data.get('Listeners', [])
        ports = [listener.get('Port') for listener in listeners]

        if 22623 in ports:
            found_mcs_port = True
            break

    assert found_mcs_port, \
        "No load balancer found with MCS port 22623 listener"


@pytest.mark.load_balancers
def test_nlb_listeners_have_default_actions(cluster_data: ClusterData, infra_id: str):
    """NLB listeners should have default actions configured"""
    listener_files = list(cluster_data.data_dir.glob(f"{cluster_data.cluster_id}_*_listeners.json"))

    if len(listener_files) == 0:
        pytest.skip("No listener files found")

    listeners_without_actions = []
    for listener_file in listener_files:
        lb_name = listener_file.stem.replace(f"{cluster_data.cluster_id}_", "").replace("_listeners", "")

        with open(listener_file) as f:
            listener_data = json.load(f)

        for listener in listener_data.get('Listeners', []):
            listener_arn = listener.get('ListenerArn', 'unknown')
            default_actions = listener.get('DefaultActions', [])

            if len(default_actions) == 0:
                listeners_without_actions.append(f"{lb_name}:{listener_arn}")

    assert len(listeners_without_actions) == 0, \
        f"Listeners without default actions: {', '.join(listeners_without_actions)}"
