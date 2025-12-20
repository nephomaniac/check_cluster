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
def test_load_balancers_exist(cluster_data: ClusterData, request):
    """Cluster must have load balancers configured

    Why: Load balancers provide access to cluster API and application ingress.

    Failure indicates: Load balancers are missing, not created, or were deleted.

    Success indicates: Load balancers exist and were successfully collected.
    """
    lbs = get_load_balancers_by_infra_id(cluster_data)

    if not lbs:
        # Import diagnostic helper
        from utils.aws_resource_diagnostics import diagnose_missing_aws_resource

        # Get infra ID for resource identification
        infra_id = cluster_data.infra_id

        # Get comprehensive diagnostics
        diagnostics = diagnose_missing_aws_resource(
            cluster_data=cluster_data,
            resource_type="Load Balancers",
            expected_file=f"{cluster_data.cluster_id}_load_balancers.json",
            api_service="elbv2",
            api_operation="describe_load_balancers",
            resource_identifier=infra_id
        )

        # Correlate CloudTrail events for missing load balancers
        from utils.test_helpers import correlate_cloudtrail_events_for_resources

        # Expected load balancer names based on infra_id
        expected_lb_names = [f"{infra_id}-ext", f"{infra_id}-int"]

        ct_result = correlate_cloudtrail_events_for_resources(
            cluster_data=cluster_data,
            resource_identifiers=expected_lb_names,
            resource_type="Load Balancer",
            event_types=["Delete", "DeleteLoadBalancer"],
            pytest_request=request
        )

        pytest.fail(f"No load balancers found for cluster.\n\n{diagnostics}")

    print(f"\n✓ Found {len(lbs)} load balancers:")
    lb_summary = [{"LoadBalancerName": lb.get("LoadBalancerName"), "DNSName": lb.get("DNSName"), "Scheme": lb.get("Scheme"), "Type": lb.get("Type")} for lb in lbs]
    print(json.dumps(lb_summary, indent=2))

    assert len(lbs) > 0, "No load balancers found for cluster"


@pytest.mark.load_balancers
def test_api_load_balancer_exists(cluster_data: ClusterData, request):
    """API load balancer must exist

    Why: API load balancer provides access to the cluster API server.

    Failure indicates: API load balancer was not created or was deleted.

    Success indicates: API load balancer exists and is accessible.
    """
    api_lb = get_api_load_balancer(cluster_data)

    if api_lb:
        print(f"\n✓ API load balancer found:")
        print(json.dumps({
            "LoadBalancerName": api_lb.get("LoadBalancerName"),
            "LoadBalancerArn": api_lb.get("LoadBalancerArn"),
            "DNSName": api_lb.get("DNSName"),
            "Scheme": api_lb.get("Scheme"),
            "Type": api_lb.get("Type")
        }, indent=2))
    else:
        # Import diagnostic helper
        from utils.aws_resource_diagnostics import diagnose_missing_aws_resource

        # Construct expected load balancer name
        infra_id = cluster_data.infra_id
        expected_lb_name = f"{infra_id}-ext"  # External API LB pattern

        print(f"\n✗ API load balancer not found")
        print(f"   Expected name pattern: {expected_lb_name}")

        # Get comprehensive diagnostics
        diagnostics = diagnose_missing_aws_resource(
            cluster_data=cluster_data,
            resource_type="API Load Balancer (matching pattern {expected_lb_name})",
            expected_file=f"{cluster_data.cluster_id}_load_balancers.json",
            api_service="elbv2",
            api_operation="describe_load_balancers",
            resource_identifier=expected_lb_name
        )

        # Correlate CloudTrail events for missing API load balancer
        from utils.test_helpers import correlate_cloudtrail_events_for_resources

        ct_result = correlate_cloudtrail_events_for_resources(
            cluster_data=cluster_data,
            resource_identifiers=[expected_lb_name],
            resource_type="Load Balancer",
            event_types=["Delete", "DeleteLoadBalancer"],
            pytest_request=request
        )

        pytest.fail(f"API load balancer not found.\n\n{diagnostics}")

    assert api_lb is not None, "API load balancer not found"


@pytest.mark.load_balancers
def test_api_load_balancer_healthy(cluster_data: ClusterData):
    """API load balancer must be in active state"""
    api_lb = get_api_load_balancer(cluster_data)

    if not api_lb:
        pytest.skip("API load balancer not found")

    lb_name = api_lb.get('LoadBalancerName', 'unknown')
    state = api_lb.get('State', {}).get('Code', 'unknown')

    print(f"\n✓ API load balancer state:")
    print(json.dumps({
        "LoadBalancerName": lb_name,
        "State": state,
        "Expected": "active"
    }, indent=2))

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

    print(f"\n✓ API load balancer scheme:")
    print(json.dumps({
        "LoadBalancerName": lb_name,
        "Scheme": scheme,
        "Expected": expected_scheme,
        "ClusterType": "private" if is_private_cluster else "public"
    }, indent=2))

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

    if not lbs_without_sgs:
        print(f"\n✓ All load balancers have security groups:")
        lb_sg_summary = [{"LoadBalancerName": lb.get("LoadBalancerName"), "SecurityGroups": lb.get("SecurityGroups", [])} for lb in lbs]
        print(json.dumps(lb_sg_summary, indent=2))
    else:
        print(f"\n✗ Load balancers without security groups: {lbs_without_sgs}")

    assert not lbs_without_sgs, f"Load balancers without security groups: {', '.join(lbs_without_sgs)}"


@pytest.mark.load_balancers
def test_load_balancers_in_multiple_azs(cluster_data: ClusterData):
    """Load balancers should be in multiple availability zones for HA (multi-AZ clusters only)"""
    lbs = get_load_balancers_by_infra_id(cluster_data)

    # Check if this is a multi-AZ cluster
    multi_az = cluster_data.cluster_json.get('multi_az', False)

    print(f"\n✓ Load balancer AZ distribution:")
    lb_az_summary = [{
        "LoadBalancerName": lb.get("LoadBalancerName"),
        "AvailabilityZones": lb.get("AvailabilityZones", []),
        "AZCount": len(lb.get("AvailabilityZones", [])),
        "MultiAZCluster": multi_az
    } for lb in lbs]
    print(json.dumps(lb_az_summary, indent=2))

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

    if dns_name:
        print(f"\n✓ API load balancer DNS name:")
        print(json.dumps({
            "LoadBalancerName": lb_name,
            "DNSName": dns_name,
            "IsValid": '.elb.' in dns_name
        }, indent=2))
    else:
        print(f"\n✗ API load balancer has no DNS name:")
        print(json.dumps({
            "LoadBalancerName": lb_name
        }, indent=2))

    assert dns_name, f"API load balancer {lb_name} has no DNS name"
    assert '.elb.' in dns_name, f"API load balancer DNS name appears invalid: {dns_name}"


# ========================================
# Target Group Tests
# ========================================


@pytest.mark.load_balancers
def test_target_groups_exist(cluster_data: ClusterData, infra_id: str):
    """Cluster should have target groups for load balancers"""
    tg_file = cluster_data.aws_dir / f"{cluster_data.cluster_id}_target_groups.json"

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
        vpc_file = cluster_data.aws_dir / f"{cluster_data.cluster_id}_VPC_IDS.json"
        if vpc_file.exists():
            with open(vpc_file) as f:
                vpc_ids = json.load(f)
            cluster_tgs = [tg for tg in target_groups if tg.get('VpcId') in vpc_ids]

    if cluster_tgs:
        print(f"\n✓ Found {len(cluster_tgs)} target groups:")
        tg_summary = [{
            "TargetGroupName": tg.get("TargetGroupName"),
            "TargetGroupArn": tg.get("TargetGroupArn"),
            "Port": tg.get("Port"),
            "Protocol": tg.get("Protocol"),
            "VpcId": tg.get("VpcId")
        } for tg in cluster_tgs]
        print(json.dumps(tg_summary, indent=2))
    else:
        print(f"\n✗ No target groups found for cluster {infra_id}")

    assert len(cluster_tgs) > 0, f"No target groups found for cluster {infra_id}"


@pytest.mark.load_balancers
def test_api_target_group_exists(cluster_data: ClusterData, infra_id: str):
    """API load balancer should have target group on port 6443"""
    tg_file = cluster_data.aws_dir / f"{cluster_data.cluster_id}_target_groups.json"

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

    if api_tgs:
        print(f"\n✓ Found {len(api_tgs)} API target group(s) (port 6443):")
        api_tg_summary = [{
            "TargetGroupName": tg.get("TargetGroupName"),
            "TargetGroupArn": tg.get("TargetGroupArn"),
            "Port": tg.get("Port"),
            "Protocol": tg.get("Protocol"),
            "HealthCheckPath": tg.get("HealthCheckPath")
        } for tg in api_tgs]
        print(json.dumps(api_tg_summary, indent=2))
    else:
        print(f"\n✗ No API target group found (port 6443)")

    assert len(api_tgs) > 0, f"No API target group found (port 6443)"


@pytest.mark.load_balancers
def test_mcs_target_group_exists(cluster_data: ClusterData, infra_id: str):
    """Cluster should have target group for Machine Config Server (port 22623)"""
    tg_file = cluster_data.aws_dir / f"{cluster_data.cluster_id}_target_groups.json"

    if not tg_file.exists():
        pytest.skip(f"Target groups file not found: {tg_file}")

    with open(tg_file) as f:
        tg_data = json.load(f)

    target_groups = tg_data.get('TargetGroups', [])

    # Find MCS target group (port 22623)
    mcs_tgs = [tg for tg in target_groups
               if tg.get('Port') == 22623]

    if mcs_tgs:
        print(f"\n✓ Found {len(mcs_tgs)} MCS target group(s) (port 22623):")
        mcs_tg_summary = [{
            "TargetGroupName": tg.get("TargetGroupName"),
            "TargetGroupArn": tg.get("TargetGroupArn"),
            "Port": tg.get("Port"),
            "Protocol": tg.get("Protocol"),
            "HealthCheckPath": tg.get("HealthCheckPath")
        } for tg in mcs_tgs]
        print(json.dumps(mcs_tg_summary, indent=2))
    else:
        print(f"\n✗ No MCS target group found (port 22623)")

    assert len(mcs_tgs) > 0, f"No MCS target group found (port 22623)"


@pytest.mark.load_balancers
def test_target_groups_have_health_checks(cluster_data: ClusterData, infra_id: str):
    """All target groups should have health checks enabled"""
    tg_file = cluster_data.aws_dir / f"{cluster_data.cluster_id}_target_groups.json"

    if not tg_file.exists():
        pytest.skip(f"Target groups file not found: {tg_file}")

    with open(tg_file) as f:
        tg_data = json.load(f)

    target_groups = tg_data.get('TargetGroups', [])

    # Filter to cluster target groups
    vpc_file = cluster_data.aws_dir / f"{cluster_data.cluster_id}_VPC_IDS.json"
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

    if len(tgs_without_health_checks) == 0:
        print(f"\n✓ All {len(cluster_tgs)} target groups have health checks enabled:")
        health_check_summary = [{
            "TargetGroupName": tg.get("TargetGroupName"),
            "HealthCheckEnabled": tg.get("HealthCheckEnabled", False),
            "HealthCheckPath": tg.get("HealthCheckPath"),
            "HealthCheckProtocol": tg.get("HealthCheckProtocol")
        } for tg in cluster_tgs]
        print(json.dumps(health_check_summary, indent=2))
    else:
        print(f"\n✗ Target groups without health checks:")
        print(json.dumps(tgs_without_health_checks, indent=2))

    assert len(tgs_without_health_checks) == 0, \
        f"Target groups without health checks: {', '.join(tgs_without_health_checks)}"


@pytest.mark.load_balancers
def test_api_target_group_health_check_path(cluster_data: ClusterData, infra_id: str):
    """API target group should use /readyz health check path"""
    tg_file = cluster_data.aws_dir / f"{cluster_data.cluster_id}_target_groups.json"

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

        print(f"\n✓ API target group health check configuration:")
        print(json.dumps({
            "TargetGroupName": tg_name,
            "HealthCheckPath": health_check_path,
            "Expected": "/readyz",
            "IsValid": health_check_path == '/readyz'
        }, indent=2))

        # API server should use /readyz for health checks
        assert health_check_path == '/readyz', \
            f"API target group {tg_name} using '{health_check_path}', expected '/readyz'"


@pytest.mark.load_balancers
def test_mcs_target_group_health_check_path(cluster_data: ClusterData, infra_id: str):
    """MCS target group should use /healthz health check path"""
    tg_file = cluster_data.aws_dir / f"{cluster_data.cluster_id}_target_groups.json"

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

        print(f"\n✓ MCS target group health check configuration:")
        print(json.dumps({
            "TargetGroupName": tg_name,
            "HealthCheckPath": health_check_path,
            "Expected": "/healthz",
            "IsValid": health_check_path == '/healthz'
        }, indent=2))

        # MCS should use /healthz for health checks
        assert health_check_path == '/healthz', \
            f"MCS target group {tg_name} using '{health_check_path}', expected '/healthz'"


@pytest.mark.load_balancers
def test_target_health_no_unhealthy_targets(cluster_data: ClusterData, infra_id: str):
    """Target groups should not have unhealthy targets (best effort check)"""
    # Look for target health files
    target_health_files = list(cluster_data.aws_dir.glob(f"{cluster_data.cluster_id}_*_target_health.json"))

    if len(target_health_files) == 0:
        pytest.skip("No target health files found")

    unhealthy_targets = []
    all_targets = []

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

            all_targets.append({
                "TargetGroup": tg_name,
                "TargetId": target_id,
                "State": health_state,
                "Reason": health_reason if health_reason else "N/A"
            })

            if health_state not in ['healthy', 'initial', 'unused']:
                unhealthy_targets.append(
                    f"{tg_name}: {target_id} (state: {health_state}, reason: {health_reason})"
                )

    if len(unhealthy_targets) == 0:
        print(f"\n✓ All targets healthy (checked {len(all_targets)} targets):")
        print(json.dumps(all_targets, indent=2))
    else:
        print(f"\n✗ Unhealthy targets found:")
        unhealthy_details = [t for t in all_targets if t["State"] not in ['healthy', 'initial', 'unused']]
        print(json.dumps(unhealthy_details, indent=2))

    assert len(unhealthy_targets) == 0, \
        f"Unhealthy targets found: {'; '.join(unhealthy_targets)}"


@pytest.mark.load_balancers
def test_target_groups_have_targets_registered(cluster_data: ClusterData, infra_id: str):
    """Target groups should have targets registered"""
    # Look for target health files
    target_health_files = list(cluster_data.aws_dir.glob(f"{cluster_data.cluster_id}_*_target_health.json"))

    if len(target_health_files) == 0:
        pytest.skip("No target health files found")

    tgs_without_targets = []
    tg_target_counts = []

    for health_file in target_health_files:
        tg_name = health_file.stem.replace(f"{cluster_data.cluster_id}_", "").replace("_target_health", "")

        with open(health_file) as f:
            health_data = json.load(f)

        target_health_descriptions = health_data.get('TargetHealthDescriptions', [])
        target_count = len(target_health_descriptions)

        tg_target_counts.append({
            "TargetGroup": tg_name,
            "TargetCount": target_count
        })

        if target_count == 0:
            tgs_without_targets.append(tg_name)

    if len(tgs_without_targets) == 0:
        print(f"\n✓ All target groups have registered targets:")
        print(json.dumps(tg_target_counts, indent=2))
    else:
        print(f"\n✗ Target groups with no registered targets:")
        print(json.dumps(tgs_without_targets, indent=2))

    assert len(tgs_without_targets) == 0, \
        f"Target groups with no registered targets: {', '.join(tgs_without_targets)}"


# ========================================
# Load Balancer Listener Tests
# ========================================


@pytest.mark.load_balancers
def test_nlb_listeners_exist(cluster_data: ClusterData, infra_id: str):
    """Network Load Balancers should have listeners configured"""
    # Look for listener files
    listener_files = list(cluster_data.aws_dir.glob(f"{cluster_data.cluster_id}_*_listeners.json"))

    if len(listener_files) == 0:
        pytest.skip("No listener files found")

    # Verify each listener file has listeners
    lbs_without_listeners = []
    lb_listener_summary = []

    for listener_file in listener_files:
        lb_name = listener_file.stem.replace(f"{cluster_data.cluster_id}_", "").replace("_listeners", "")

        with open(listener_file) as f:
            listener_data = json.load(f)

        listeners = listener_data.get('Listeners', [])
        listener_count = len(listeners)

        lb_listener_summary.append({
            "LoadBalancer": lb_name,
            "ListenerCount": listener_count,
            "Ports": [listener.get('Port') for listener in listeners]
        })

        if listener_count == 0:
            lbs_without_listeners.append(lb_name)

    if len(lbs_without_listeners) == 0:
        print(f"\n✓ All load balancers have listeners configured:")
        print(json.dumps(lb_listener_summary, indent=2))
    else:
        print(f"\n✗ Load balancers without listeners:")
        print(json.dumps(lbs_without_listeners, indent=2))

    assert len(lbs_without_listeners) == 0, \
        f"Load balancers without listeners: {', '.join(lbs_without_listeners)}"


@pytest.mark.load_balancers
def test_api_nlb_listener_port_6443(cluster_data: ClusterData, infra_id: str):
    """API NLB should have listener on port 6443"""
    # Look for API load balancer listener file
    api_lb_pattern = f"{cluster_data.cluster_id}_*ext*_listeners.json"
    listener_files = list(cluster_data.aws_dir.glob(api_lb_pattern))

    if len(listener_files) == 0:
        pytest.skip("No API load balancer listener files found")

    for listener_file in listener_files:
        lb_name = listener_file.stem.replace(f"{cluster_data.cluster_id}_", "").replace("_listeners", "")

        with open(listener_file) as f:
            listener_data = json.load(f)

        listeners = listener_data.get('Listeners', [])
        ports = [listener.get('Port') for listener in listeners]

        print(f"\n✓ API load balancer listener configuration:")
        print(json.dumps({
            "LoadBalancer": lb_name,
            "Listeners": [{
                "Port": l.get("Port"),
                "Protocol": l.get("Protocol"),
                "DefaultActions": len(l.get("DefaultActions", []))
            } for l in listeners],
            "Has6443": 6443 in ports
        }, indent=2))

        assert 6443 in ports, \
            f"API load balancer {lb_name} not listening on port 6443 (ports: {ports})"


@pytest.mark.load_balancers
def test_api_nlb_listener_port_22623(cluster_data: ClusterData, infra_id: str):
    """API NLB should have listener on port 22623 (MCS)"""
    # Look for internal load balancer listener file (has MCS)
    int_lb_pattern = f"{cluster_data.cluster_id}_*int*_listeners.json"
    listener_files = list(cluster_data.aws_dir.glob(int_lb_pattern))

    if len(listener_files) == 0:
        pytest.skip("No internal load balancer listener files found")

    found_mcs_port = False
    mcs_lb_info = []

    for listener_file in listener_files:
        lb_name = listener_file.stem.replace(f"{cluster_data.cluster_id}_", "").replace("_listeners", "")

        with open(listener_file) as f:
            listener_data = json.load(f)

        listeners = listener_data.get('Listeners', [])
        ports = [listener.get('Port') for listener in listeners]

        mcs_lb_info.append({
            "LoadBalancer": lb_name,
            "Ports": ports,
            "Has22623": 22623 in ports
        })

        if 22623 in ports:
            found_mcs_port = True

    if found_mcs_port:
        print(f"\n✓ MCS port 22623 listener found:")
        print(json.dumps([info for info in mcs_lb_info if info["Has22623"]], indent=2))
    else:
        print(f"\n✗ No MCS port 22623 listener found:")
        print(json.dumps(mcs_lb_info, indent=2))

    assert found_mcs_port, \
        "No load balancer found with MCS port 22623 listener"


@pytest.mark.load_balancers
def test_nlb_listeners_have_default_actions(cluster_data: ClusterData, infra_id: str):
    """NLB listeners should have default actions configured"""
    listener_files = list(cluster_data.aws_dir.glob(f"{cluster_data.cluster_id}_*_listeners.json"))

    if len(listener_files) == 0:
        pytest.skip("No listener files found")

    listeners_without_actions = []
    all_listener_actions = []

    for listener_file in listener_files:
        lb_name = listener_file.stem.replace(f"{cluster_data.cluster_id}_", "").replace("_listeners", "")

        with open(listener_file) as f:
            listener_data = json.load(f)

        for listener in listener_data.get('Listeners', []):
            listener_arn = listener.get('ListenerArn', 'unknown')
            listener_port = listener.get('Port')
            default_actions = listener.get('DefaultActions', [])
            action_count = len(default_actions)

            all_listener_actions.append({
                "LoadBalancer": lb_name,
                "Port": listener_port,
                "Protocol": listener.get('Protocol'),
                "DefaultActionCount": action_count,
                "ActionTypes": [action.get('Type') for action in default_actions]
            })

            if action_count == 0:
                listeners_without_actions.append(f"{lb_name}:{listener_arn}")

    if len(listeners_without_actions) == 0:
        print(f"\n✓ All listeners have default actions configured:")
        print(json.dumps(all_listener_actions, indent=2))
    else:
        print(f"\n✗ Listeners without default actions:")
        print(json.dumps(listeners_without_actions, indent=2))

    assert len(listeners_without_actions) == 0, \
        f"Listeners without default actions: {', '.join(listeners_without_actions)}"
