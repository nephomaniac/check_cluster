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
        # Enhanced diagnostics with root cause analysis
        # Build message for both print and pytest.fail() to ensure visibility
        message_parts = []
        message_parts.append("\n" + "="*80)
        message_parts.append(f"CRITICAL: Found {len(unhealthy_targets)} unhealthy API server targets")
        message_parts.append("="*80)

        details = []
        resource_ids = []
        instance_diagnostics = {}

        # Get instance data for diagnostics
        instances_by_id = {inst.get('InstanceId'): inst for inst in cluster_data.ec2_instances}

        # Get security groups for analysis
        security_groups_by_id = {}
        if cluster_data.security_groups:
            for sg in cluster_data.security_groups.get('SecurityGroups', []):
                security_groups_by_id[sg.get('GroupId')] = sg

        for target in unhealthy_targets:
            instance_id = target['instance_id']
            resource_ids.append(instance_id)
            resource_ids.append(target['target_group'])

            # Get instance details
            instance = instances_by_id.get(instance_id, {})
            instance_state = instance.get('State', {}).get('Name', 'unknown') if isinstance(instance.get('State'), dict) else instance.get('State', 'unknown')

            # Analyze root cause
            root_causes = []

            # 1. Check instance state
            if instance_state != 'running':
                root_causes.append(f"Instance is {instance_state} (must be running)")

            # 2. Check security groups
            sg_ids = [sg['GroupId'] for sg in instance.get('SecurityGroups', [])]
            port_6443_open = False
            sg_issues = []

            for sg_id in sg_ids:
                sg = security_groups_by_id.get(sg_id, {})
                ingress_rules = sg.get('IpPermissions', [])

                for rule in ingress_rules:
                    from_port = rule.get('FromPort')
                    to_port = rule.get('ToPort')
                    protocol = rule.get('IpProtocol', '')

                    # Check if port 6443 is allowed
                    if protocol == 'tcp' and from_port and to_port:
                        if from_port <= 6443 <= to_port:
                            port_6443_open = True
                            break
                    elif protocol == '-1':  # All protocols
                        port_6443_open = True
                        break

            if not port_6443_open and sg_ids:
                root_causes.append(f"Security groups may be blocking port 6443 (API server)")

            # 3. Analyze failure reason
            reason = target['reason']
            if reason == 'Target.FailedHealthChecks':
                root_causes.append("Health checks failing - API server may not be responding on port 6443")
                if instance_state == 'running':
                    root_causes.append("  Possible causes: API server not started, certificate issues, etcd unavailable")
            elif reason == 'Target.Timeout':
                root_causes.append("Health check timeout - network connectivity issue or API server overloaded")
            elif reason == 'Target.ResponseCodeMismatch':
                root_causes.append("API server returning unexpected HTTP response code")
            elif reason == 'Target.DeregistrationInProgress':
                root_causes.append("Target is being deregistered (instance terminating or auto-scaling)")

            instance_diagnostics[instance_id] = {
                'state': instance_state,
                'security_groups': sg_ids,
                'port_6443_open': port_6443_open,
                'root_causes': root_causes
            }

            # Format detailed output
            details.append(f"\n{'─'*80}")
            details.append(f"Target Group: {target['target_group']}")
            details.append(f"Instance ID: {instance_id}")
            details.append(f"Port: {target['port']}")
            details.append(f"Health State: {target['state']}")
            details.append(f"Failure Reason: {target['reason']}")
            if target['description']:
                details.append(f"Description: {target['description']}")
            details.append(f"\nInstance State: {instance_state}")
            details.append(f"Security Groups: {', '.join(sg_ids) if sg_ids else 'None'}")
            details.append(f"Port 6443 Open: {'Yes' if port_6443_open else 'No'}")

            if root_causes:
                details.append(f"\nROOT CAUSE ANALYSIS:")
                for cause in root_causes:
                    details.append(f"  ❌ {cause}")

        # Add details to message
        message_parts.extend(details)
        message_parts.append("\n" + "="*80)

        # Correlate CloudTrail events for unhealthy/deregistered targets
        from utils.test_helpers import correlate_cloudtrail_events_for_resources

        cloudtrail_message = []
        if resource_ids:
            ct_result = correlate_cloudtrail_events_for_resources(
                cluster_data=cluster_data,
                resource_identifiers=resource_ids,
                resource_type="Load Balancer Target",
                event_types=["Deregister", "DeregisterTargets", "Terminate", "Stop", "RevokeSecurityGroupIngress"],
                pytest_request=request
            )

            # Add CloudTrail findings to message
            if ct_result['found_events']:
                cloudtrail_message.append("\n" + "="*80)
                cloudtrail_message.append("CloudTrail Analysis - Events Related to Unhealthy Targets")
                cloudtrail_message.append("="*80)
                cloudtrail_message.append(ct_result['formatted_message'])
                cloudtrail_message.append("="*80 + "\n")
                message_parts.extend(cloudtrail_message)

            # If only installer role events, treat as informational
            if ct_result.get('only_installer_events'):
                # Build full message for skip
                full_message = "\n".join(message_parts)
                pytest.skip(
                    f"INFORMATIONAL: API server targets unhealthy, but CloudTrail shows "
                    f"only installer role activity (expected during cluster installation).\n\n"
                    f"{full_message}"
                )

        # Summary of common issues
        remediation = []
        remediation.append("\n" + "="*80)
        remediation.append("COMMON CAUSES AND REMEDIATION")
        remediation.append("="*80)
        remediation.append("""
1. Instance Not Running
   - Check instance state in EC2 console
   - Review CloudTrail for Stop/Terminate events
   - Check for auto-scaling terminations

2. Security Group Blocking Port 6443
   - Verify security group rules allow TCP 6443 from load balancer subnets
   - Check for RevokeSecurityGroupIngress events in CloudTrail
   - Review security group changes during installation

3. API Server Not Responding
   - SSH to instance: ssh core@<instance-ip>
   - Check API server status: sudo crictl ps | grep kube-apiserver
   - View API server logs: sudo crictl logs <container-id>
   - Check for certificate issues: sudo journalctl -u kubelet | grep certificate

4. etcd Not Available
   - API server requires etcd to function
   - Check etcd status: sudo crictl ps | grep etcd
   - View etcd logs: sudo crictl logs <etcd-container-id>

5. Network Connectivity
   - Verify route tables allow traffic from load balancer subnets
   - Check Network ACLs aren't blocking traffic
   - Verify subnet configuration

For detailed diagnostics, see the Root Cause Analysis section above for each instance.
        """)
        remediation.append("="*80 + "\n")
        message_parts.extend(remediation)

        # Build final message and fail
        full_message = "\n".join(message_parts)
        pytest.fail(full_message)


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
        # Enhanced diagnostics with root cause analysis
        # Build message for both print and pytest.fail() to ensure visibility
        message_parts = []
        message_parts.append("\n" + "="*80)
        message_parts.append(f"HIGH: Found {len(unhealthy_targets)} unhealthy MCS targets")
        message_parts.append("="*80)

        details = []
        resource_ids = []
        instance_diagnostics = {}

        # Get instance data for diagnostics
        instances_by_id = {inst.get('InstanceId'): inst for inst in cluster_data.ec2_instances}

        # Get security groups for analysis
        security_groups_by_id = {}
        if cluster_data.security_groups:
            for sg in cluster_data.security_groups.get('SecurityGroups', []):
                security_groups_by_id[sg.get('GroupId')] = sg

        for target in unhealthy_targets:
            instance_id = target['instance_id']
            resource_ids.append(instance_id)
            resource_ids.append(target['target_group'])

            # Get instance details
            instance = instances_by_id.get(instance_id, {})
            instance_state = instance.get('State', {}).get('Name', 'unknown') if isinstance(instance.get('State'), dict) else instance.get('State', 'unknown')

            # Analyze root cause
            root_causes = []

            # 1. Check instance state
            if instance_state != 'running':
                root_causes.append(f"Instance is {instance_state} (must be running)")

            # 2. Check security groups for port 22623 (MCS port)
            sg_ids = [sg['GroupId'] for sg in instance.get('SecurityGroups', [])]
            port_22623_open = False
            sg_issues = []

            for sg_id in sg_ids:
                sg = security_groups_by_id.get(sg_id, {})
                ingress_rules = sg.get('IpPermissions', [])

                for rule in ingress_rules:
                    from_port = rule.get('FromPort')
                    to_port = rule.get('ToPort')
                    protocol = rule.get('IpProtocol', '')

                    # Check if port 22623 is allowed
                    if protocol == 'tcp' and from_port and to_port:
                        if from_port <= 22623 <= to_port:
                            port_22623_open = True
                            break
                    elif protocol == '-1':  # All protocols
                        port_22623_open = True
                        break

            if not port_22623_open and sg_ids:
                root_causes.append(f"Security groups may be blocking port 22623 (MCS)")

            # 3. Analyze failure reason
            reason = target['reason']
            if reason == 'Target.FailedHealthChecks':
                root_causes.append("Health checks failing - MCS may not be responding on port 22623")
                if instance_state == 'running':
                    root_causes.append("  Possible causes: MCS not started, certificate issues, bootstrap incomplete")
            elif reason == 'Target.Timeout':
                root_causes.append("Health check timeout - network connectivity issue or MCS overloaded")
            elif reason == 'Target.ResponseCodeMismatch':
                root_causes.append("MCS returning unexpected HTTP response code")
            elif reason == 'Target.DeregistrationInProgress':
                root_causes.append("Target is being deregistered (instance terminating or auto-scaling)")

            instance_diagnostics[instance_id] = {
                'state': instance_state,
                'security_groups': sg_ids,
                'port_22623_open': port_22623_open,
                'root_causes': root_causes
            }

            # Format detailed output
            details.append(f"\n{'─'*80}")
            details.append(f"Target Group: {target['target_group']}")
            details.append(f"Instance ID: {instance_id}")
            details.append(f"Port: {target['port']}")
            details.append(f"Health State: {target['state']}")
            details.append(f"Failure Reason: {target['reason']}")
            if target['description']:
                details.append(f"Description: {target['description']}")
            details.append(f"\nInstance State: {instance_state}")
            details.append(f"Security Groups: {', '.join(sg_ids) if sg_ids else 'None'}")
            details.append(f"Port 22623 Open: {'Yes' if port_22623_open else 'No'}")

            if root_causes:
                details.append(f"\nROOT CAUSE ANALYSIS:")
                for cause in root_causes:
                    details.append(f"  ❌ {cause}")

        # Add details to message
        message_parts.extend(details)
        message_parts.append("\n" + "="*80)

        # Correlate CloudTrail events for unhealthy/deregistered targets
        from utils.test_helpers import correlate_cloudtrail_events_for_resources

        cloudtrail_message = []
        if resource_ids:
            ct_result = correlate_cloudtrail_events_for_resources(
                cluster_data=cluster_data,
                resource_identifiers=resource_ids,
                resource_type="Load Balancer Target",
                event_types=["Deregister", "DeregisterTargets", "Terminate", "Stop", "RevokeSecurityGroupIngress"],
                pytest_request=request
            )

            # Add CloudTrail findings to message
            if ct_result['found_events']:
                cloudtrail_message.append("\n" + "="*80)
                cloudtrail_message.append("CloudTrail Analysis - Events Related to Unhealthy Targets")
                cloudtrail_message.append("="*80)
                cloudtrail_message.append(ct_result['formatted_message'])
                cloudtrail_message.append("="*80 + "\n")
                message_parts.extend(cloudtrail_message)

            # If only installer role events, treat as informational
            if ct_result.get('only_installer_events'):
                # Build full message for skip
                full_message = "\n".join(message_parts)
                pytest.skip(
                    f"INFORMATIONAL: MCS targets unhealthy, but CloudTrail shows "
                    f"only installer role activity (expected during cluster installation).\n\n"
                    f"{full_message}"
                )

        # Summary of common issues
        remediation = []
        remediation.append("\n" + "="*80)
        remediation.append("COMMON CAUSES AND REMEDIATION")
        remediation.append("="*80)
        remediation.append("""
1. Instance Not Running
   - Check instance state in EC2 console
   - Review CloudTrail for Stop/Terminate events
   - Check for auto-scaling terminations

2. Security Group Blocking Port 22623
   - Verify security group rules allow TCP 22623 from load balancer subnets
   - Check for RevokeSecurityGroupIngress events in CloudTrail
   - Review security group changes during installation

3. MCS Not Responding
   - SSH to instance: ssh core@<instance-ip>
   - Check MCS status: sudo systemctl status machine-config-server
   - View MCS logs: sudo journalctl -u machine-config-server
   - Check for certificate issues: sudo journalctl -u kubelet | grep certificate

4. Bootstrap Not Complete
   - MCS requires bootstrap to complete before becoming healthy
   - Check bootstrap status: sudo systemctl status bootkube.service
   - View bootstrap logs: sudo journalctl -u bootkube.service

5. Network Connectivity
   - Verify route tables allow traffic from load balancer subnets
   - Check Network ACLs aren't blocking traffic
   - Verify subnet configuration

For detailed diagnostics, see the Root Cause Analysis section above for each instance.
        """)
        remediation.append("="*80 + "\n")
        message_parts.extend(remediation)

        # Build final message and fail
        full_message = "\n".join(message_parts)
        pytest.fail(full_message)


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
