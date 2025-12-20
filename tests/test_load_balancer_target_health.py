"""
Load Balancer Target Health Tests

Validates that load balancer targets (EC2 instances) are properly registered
and healthy in their target groups.
"""

import pytest
import json
from pathlib import Path
from models.cluster import ClusterData


def get_target_health_files(cluster_data: ClusterData) -> dict:
    """Get all target health files for the cluster"""
    target_health_files = {}

    # Look for target health files matching pattern: {cluster_id}_{tg_name}_target_health.json
    pattern = f"{cluster_data.cluster_id}_*_target_health.json"
    for file_path in cluster_data.aws_dir.glob(pattern):
        with open(file_path) as f:
            data = json.load(f)
            tg_name = file_path.stem.replace(f"{cluster_data.cluster_id}_", "").replace("_target_health", "")
            target_health_files[tg_name] = data

    return target_health_files


@pytest.mark.load_balancers
def test_target_health_data_collected(cluster_data: ClusterData):
    """Target health data should be collected for load balancers

    Why: Target health data is critical for understanding whether load balancer
    targets (EC2 instances) are properly registered and responding to health checks.
    Without this data, we cannot determine if API server instances are reachable.

    Failure indicates: Target health data was not collected during artifact
    gathering. This is expected for failed cluster installations where target
    groups may not have been created yet.

    Success indicates: Target health data is available for analysis.
    """
    target_health_files = get_target_health_files(cluster_data)

    if not target_health_files:
        pytest.skip("No target health data collected (expected for failed installations)")


@pytest.mark.load_balancers
@pytest.mark.severity("CRITICAL")
@pytest.mark.blocks_install
def test_api_server_targets_healthy(cluster_data: ClusterData, request):
    """API server targets must be healthy in load balancer

    Why: The load balancer performs health checks on API server instances to
    determine which instances can receive traffic. If all targets are unhealthy,
    the load balancer cannot route traffic to the API server, and the cluster
    cannot be accessed.

    Failure indicates: API server targets are unhealthy or not registered, which causes:
    - Cluster API is unreachable
    - kubectl/oc commands fail
    - Cluster operators cannot run
    - Bootstrap process hangs waiting for API availability
    - Cluster installation fails with BootstrapFailed

    Common failure reasons:
    - Target.FailedHealthChecks: API server not responding on port 6443
    - Target.Timeout: Health check requests timing out
    - Target.ResponseCodeMismatch: API server returning unexpected HTTP codes
    - Initial: Targets recently registered, still in initial health check phase
    - Unused: Target group has no listeners configured

    Success indicates: API server instances are healthy and receiving traffic
    from the load balancer. The cluster API is accessible.

    Remediation:
      Check API server logs on master instances:
        $ ssh core@<master-ip> sudo journalctl -u kubelet -u crio | grep apiserver

      Verify API server is listening on port 6443:
        $ ssh core@<master-ip> sudo ss -tlnp | grep 6443

      Check target health in AWS:
        $ aws elbv2 describe-target-health --target-group-arn <arn> \\
            --region <region>

      If targets are not registered:
        $ aws elbv2 describe-target-groups --region <region> | \\
            jq '.TargetGroups[] | select(.TargetGroupName | contains("apiserver"))'

    Documentation: https://docs.aws.amazon.com/elasticloadbalancing/latest/network/target-group-health-checks.html

    Severity: CRITICAL - Prevents cluster API access and installation
    """
    target_health_files = get_target_health_files(cluster_data)

    if not target_health_files:
        pytest.skip("No target health data collected")

    # Find API server target groups (names typically contain 'apiserver' or 'api-target')
    api_target_groups = []
    for tg_name in target_health_files.keys():
        if 'apiserver' in tg_name.lower() or 'api-target' in tg_name.lower():
            api_target_groups.append(tg_name)

    if not api_target_groups:
        pytest.skip("No API server target groups found")

    # Check health of each API server target group
    unhealthy_targets = []
    for tg_name in api_target_groups:
        tg_data = target_health_files[tg_name]
        target_health_descriptions = tg_data.get('TargetHealthDescriptions', [])

        for target in target_health_descriptions:
            target_id = target.get('Target', {}).get('Id', 'unknown')
            target_port = target.get('Target', {}).get('Port', 'unknown')
            health = target.get('TargetHealth', {})
            state = health.get('State', 'unknown')
            reason = health.get('Reason', '')
            description = health.get('Description', '')

            if state != 'healthy':
                unhealthy_targets.append({
                    'target_group': tg_name,
                    'instance_id': target_id,
                    'port': target_port,
                    'state': state,
                    'reason': reason,
                    'description': description
                })

    if unhealthy_targets:
        details = []
        resource_ids = []

        for target in unhealthy_targets[:10]:  # Show first 10
            details.append(
                f"\nTarget Group: {target['target_group']}\n"
                f"  Instance: {target['instance_id']}\n"
                f"  Port: {target['port']}\n"
                f"  State: {target['state']}\n"
                f"  Reason: {target['reason']}\n"
                f"  Description: {target['description']}"
            )
            # Collect instance IDs and target group names for CloudTrail correlation
            resource_ids.append(target['instance_id'])
            resource_ids.append(target['target_group'])

        # Correlate CloudTrail events for unhealthy/deregistered targets
        from utils.test_helpers import correlate_cloudtrail_events_for_resources

        if resource_ids:
            ct_result = correlate_cloudtrail_events_for_resources(
                cluster_data=cluster_data,
                resource_identifiers=resource_ids,
                resource_type="Load Balancer Target",
                event_types=["Deregister", "DeregisterTargets", "Terminate", "Stop"],
                pytest_request=request
            )

        pytest.fail(
            f"Found {len(unhealthy_targets)} unhealthy API server targets:\n" +
            "".join(details)
        )


@pytest.mark.load_balancers
@pytest.mark.severity("HIGH")
def test_machine_config_server_targets_healthy(cluster_data: ClusterData, request):
    """Machine Config Server (MCS) targets must be healthy in load balancer

    Why: The Machine Config Server (MCS) listens on port 22623 and serves ignition
    configs to nodes during bootstrap. If MCS targets are unhealthy, new nodes
    cannot retrieve their configuration and the cluster cannot scale.

    Failure indicates: MCS targets are unhealthy, which causes:
    - Bootstrap process fails to retrieve ignition configs
    - Master nodes cannot join the cluster
    - Worker nodes cannot join the cluster
    - Machine Config Operator cannot apply node configurations

    Success indicates: MCS instances are healthy and serving ignition configs.

    Remediation:
      Check MCS logs on master instances:
        $ ssh core@<master-ip> sudo journalctl -u machine-config-server

      Verify MCS is listening on port 22623:
        $ ssh core@<master-ip> sudo ss -tlnp | grep 22623

      Check target health in AWS:
        $ aws elbv2 describe-target-health --target-group-arn <arn> \\
            --region <region>

    Severity: HIGH - Prevents node provisioning and scaling
    """
    target_health_files = get_target_health_files(cluster_data)

    if not target_health_files:
        pytest.skip("No target health data collected")

    # Find MCS target groups (names typically contain 'additional-listener')
    mcs_target_groups = []
    for tg_name in target_health_files.keys():
        if 'additional-listener' in tg_name.lower() or 'mcs' in tg_name.lower():
            mcs_target_groups.append(tg_name)

    if not mcs_target_groups:
        pytest.skip("No Machine Config Server target groups found")

    # Check health of each MCS target group
    unhealthy_targets = []
    for tg_name in mcs_target_groups:
        tg_data = target_health_files[tg_name]
        target_health_descriptions = tg_data.get('TargetHealthDescriptions', [])

        for target in target_health_descriptions:
            target_id = target.get('Target', {}).get('Id', 'unknown')
            target_port = target.get('Target', {}).get('Port', 'unknown')
            health = target.get('TargetHealth', {})
            state = health.get('State', 'unknown')
            reason = health.get('Reason', '')
            description = health.get('Description', '')

            if state != 'healthy':
                unhealthy_targets.append({
                    'target_group': tg_name,
                    'instance_id': target_id,
                    'port': target_port,
                    'state': state,
                    'reason': reason,
                    'description': description
                })

    if unhealthy_targets:
        details = []
        resource_ids = []

        for target in unhealthy_targets[:10]:  # Show first 10
            details.append(
                f"\nTarget Group: {target['target_group']}\n"
                f"  Instance: {target['instance_id']}\n"
                f"  Port: {target['port']}\n"
                f"  State: {target['state']}\n"
                f"  Reason: {target['reason']}\n"
                f"  Description: {target['description']}"
            )
            # Collect instance IDs and target group names for CloudTrail correlation
            resource_ids.append(target['instance_id'])
            resource_ids.append(target['target_group'])

        # Correlate CloudTrail events for unhealthy/deregistered targets
        from utils.test_helpers import correlate_cloudtrail_events_for_resources

        if resource_ids:
            ct_result = correlate_cloudtrail_events_for_resources(
                cluster_data=cluster_data,
                resource_identifiers=resource_ids,
                resource_type="Load Balancer Target",
                event_types=["Deregister", "DeregisterTargets", "Terminate", "Stop"],
                pytest_request=request
            )

        pytest.fail(
            f"Found {len(unhealthy_targets)} unhealthy MCS targets:\n" +
            "".join(details)
        )


@pytest.mark.load_balancers
def test_all_targets_registered(cluster_data: ClusterData):
    """All expected master instances should be registered as targets

    Why: Master instances must be registered in load balancer target groups to
    receive traffic. If instances are not registered, they cannot serve API
    requests or ignition configs.

    Failure indicates: Some master instances are not registered in target groups,
    which could indicate:
    - Instance launch failures
    - Security group blocking target registration
    - Subnet misconfiguration
    - Auto-scaling issues

    Success indicates: All expected master instances are registered as targets.
    """
    target_health_files = get_target_health_files(cluster_data)

    if not target_health_files:
        pytest.skip("No target health data collected")

    # Get all registered instance IDs from target health data
    registered_instances = set()
    for tg_name, tg_data in target_health_files.items():
        target_health_descriptions = tg_data.get('TargetHealthDescriptions', [])
        for target in target_health_descriptions:
            instance_id = target.get('Target', {}).get('Id')
            if instance_id:
                registered_instances.add(instance_id)

    if not registered_instances:
        pytest.skip("No instances registered in target groups")

    # Get all master instances from cluster data
    master_instances = []
    for instance in cluster_data.instances:
        # Check if instance is a master by looking at tags or name
        tags = {tag['Key']: tag['Value'] for tag in instance.get('Tags', [])}
        name = tags.get('Name', '')

        if 'master' in name.lower():
            master_instances.append(instance.get('InstanceId'))

    if not master_instances:
        pytest.skip("No master instances found in cluster data")

    # Check if all master instances are registered
    unregistered_instances = []
    for instance_id in master_instances:
        if instance_id not in registered_instances:
            unregistered_instances.append(instance_id)

    if unregistered_instances:
        pytest.fail(
            f"Found {len(unregistered_instances)} master instances not registered in target groups:\n" +
            "\n".join(f"  - {inst}" for inst in unregistered_instances)
        )
