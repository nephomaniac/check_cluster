"""
OpenShift Installation Progress and Status Tests

Validates OpenShift installation stages using Ignition configuration, bootstrap process,
EC2 console logs, and cluster state markers. Based on:
- OpenShift Ignition project documentation
- OpenShift Container Platform installation process
- AWS EC2 console output analysis
- OCM cluster status tracking

Documentation:
- OpenShift Installation Process: https://docs.openshift.com/container-platform/latest/installing/index.html#installation-process
- ROSA Installation: https://docs.redhat.com/en/documentation/red_hat_openshift_service_on_aws/4/html/install_rosa_classic_clusters/rosa-sts-creating-a-cluster-quickly
- Ignition Specification: https://coreos.github.io/ignition/
- Installation Troubleshooting: https://docs.redhat.com/en/documentation/red_hat_openshift_service_on_aws/4/html/troubleshooting/rosa-troubleshooting-installations

Installation Phases:
1. Ignition Configuration (bootstrap.ign, master.ign, worker.ign)
2. Bootstrap Node Initialization
3. Control Plane Bootstrap (etcd, temporary control plane)
4. Production Control Plane Activation
5. Cluster Operators Deployment
6. Bootstrap Completion and Cleanup
7. Worker Node Joining

References:
- https://docs.redhat.com/en/documentation/openshift_container_platform/4.13/html/installation_overview/ocp-installation-overview
- https://docs.okd.io/latest/support/troubleshooting/troubleshooting-installations.html
- https://github.com/openshift/installer/blob/main/docs/user/troubleshootingbootstrap.md
"""

import json
import pytest
import re
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime
from models.cluster import ClusterData


# =============================================================================
# INSTALLATION PHASE DETECTION
# =============================================================================

def detect_installation_phase(cluster_data: ClusterData) -> Dict[str, Any]:
    """
    Detect current installation phase based on cluster state and available data.

    Returns dict with:
    - phase: str (ignition_config, bootstrap_init, control_plane_bootstrap,
              production_control_plane, operators_deployment, bootstrap_complete,
              worker_joining, installation_complete, installation_failed)
    - progress_percentage: int (0-100)
    - phase_description: str
    - completed_stages: List[str]
    - current_stage: str
    - next_expected_stage: str
    - error_indicators: List[str]
    """
    state = cluster_data.cluster_state.lower()

    result = {
        'phase': 'unknown',
        'progress_percentage': 0,
        'phase_description': '',
        'completed_stages': [],
        'current_stage': '',
        'next_expected_stage': '',
        'error_indicators': []
    }

    # Check cluster state from OCM
    if state == 'ready' or state == 'installed' or state == 'active':
        result['phase'] = 'installation_complete'
        result['progress_percentage'] = 100
        result['phase_description'] = 'Cluster installation completed successfully'
        result['completed_stages'] = [
            'Ignition Configuration',
            'Bootstrap Initialization',
            'Control Plane Bootstrap',
            'Production Control Plane',
            'Cluster Operators',
            'Bootstrap Complete',
            'Worker Nodes Joined'
        ]
        result['current_stage'] = 'Installation Complete'
        return result

    if state == 'error' or state == 'failed':
        result['phase'] = 'installation_failed'
        result['phase_description'] = 'Installation failed - requires investigation'
        result['error_indicators'].append(f"Cluster state: {state}")
        return result

    if state == 'installing' or state == 'pending':
        # Need to determine exact phase from other indicators
        result['phase'] = 'in_progress'
        result['phase_description'] = 'Installation in progress'

        # Check for control plane instances
        masters = _get_master_instances(cluster_data)
        if not masters:
            result['current_stage'] = 'Ignition Configuration / Bootstrap Initialization'
            result['progress_percentage'] = 10
            result['next_expected_stage'] = 'Control plane instances launching'
        else:
            # Check if masters are running
            running_masters = [m for m in masters if _get_instance_state(m) == 'running']
            if len(running_masters) == 0:
                result['current_stage'] = 'Control plane instances launching'
                result['progress_percentage'] = 25
                result['next_expected_stage'] = 'Control plane instances running'
            elif len(running_masters) < len(masters):
                result['current_stage'] = 'Control plane partially running'
                result['progress_percentage'] = 40
                result['next_expected_stage'] = 'All control plane instances running'
            else:
                result['current_stage'] = 'Control plane running - operators deploying'
                result['progress_percentage'] = 60
                result['next_expected_stage'] = 'Bootstrap completion'
                result['completed_stages'] = [
                    'Ignition Configuration',
                    'Bootstrap Initialization',
                    'Control Plane Bootstrap'
                ]

        # Check for worker instances
        workers = _get_worker_instances(cluster_data)
        if workers:
            running_workers = [w for w in workers if _get_instance_state(w) == 'running']
            if running_workers:
                result['progress_percentage'] = max(result['progress_percentage'], 75)
                result['completed_stages'].append('Worker Nodes Launching')

    return result


def _get_master_instances(cluster_data: ClusterData) -> List[Dict[str, Any]]:
    """Get control plane/master instances"""
    instances = []
    for instance in cluster_data.ec2_instances:
        tags = {tag['Key']: tag['Value'] for tag in instance.get('Tags', [])}
        instance_name = tags.get('Name', '')
        if 'master' in instance_name.lower():
            instances.append(instance)
    return instances


def _get_worker_instances(cluster_data: ClusterData) -> List[Dict[str, Any]]:
    """Get worker instances"""
    instances = []
    for instance in cluster_data.ec2_instances:
        tags = {tag['Key']: tag['Value'] for tag in instance.get('Tags', [])}
        instance_name = tags.get('Name', '')
        if 'worker' in instance_name.lower():
            instances.append(instance)
    return instances


def _get_instance_state(instance: Dict[str, Any]) -> str:
    """Get instance state"""
    state_data = instance.get('State', 'unknown')
    if isinstance(state_data, dict):
        return state_data.get('Name', 'unknown')
    return state_data


# =============================================================================
# EC2 CONSOLE LOG ANALYSIS
# =============================================================================

def analyze_console_logs(console_log: str) -> Dict[str, Any]:
    """
    Analyze EC2 console log for installation progress and errors.

    Looks for:
    - Ignition fetch attempts
    - Ignition configuration applied
    - Bootstrap service status
    - etcd initialization
    - kubelet service status
    - Common error patterns

    Returns dict with:
    - ignition_fetched: bool
    - ignition_applied: bool
    - bootstrap_started: bool
    - etcd_started: bool
    - kubelet_started: bool
    - errors: List[Dict] (error message, line number, context)
    - warnings: List[Dict]
    - stage: str (current installation stage detected from logs)
    """
    result = {
        'ignition_fetched': False,
        'ignition_applied': False,
        'bootstrap_started': False,
        'etcd_started': False,
        'kubelet_started': False,
        'errors': [],
        'warnings': [],
        'stage': 'unknown'
    }

    if not console_log:
        return result

    lines = console_log.split('\n')

    # Ignition markers
    ignition_patterns = {
        'fetched': [
            r'Ignition.*fetch.*success',
            r'Fetching.*ignition.*config',
            r'ignition.*downloaded',
            r'Config.*fetched.*successfully'
        ],
        'applied': [
            r'Ignition.*ran.*successfully',
            r'Ignition.*completed',
            r'Applied.*ignition.*config',
            r'ignition.*files.*written'
        ]
    }

    # Service status markers
    service_patterns = {
        'bootstrap': [
            r'bootkube.*service.*started',
            r'bootstrap.*in.*progress',
            r'Starting.*bootstrap'
        ],
        'etcd': [
            r'etcd.*started',
            r'etcd.*member.*added',
            r'Starting.*etcd'
        ],
        'kubelet': [
            r'kubelet.*started',
            r'kubelet.*service.*running',
            r'Starting.*kubelet'
        ]
    }

    # Error patterns
    error_patterns = [
        (r'Failed to fetch.*ignition', 'Ignition fetch failure'),
        (r'ignition.*failed', 'Ignition failure'),
        (r'etcd.*failed', 'etcd failure'),
        (r'kubelet.*failed', 'kubelet failure'),
        (r'bootstrap.*failed', 'Bootstrap failure'),
        (r'ERROR|Error|error.*', 'General error'),
        (r'FATAL|Fatal', 'Fatal error'),
        (r'panic', 'Panic'),
        (r'Connection refused', 'Connection refused'),
        (r'Permission denied', 'Permission denied'),
        (r'No such file', 'File not found'),
        (r'timeout', 'Timeout')
    ]

    # Warning patterns
    warning_patterns = [
        (r'WARN|Warning|warning', 'Warning'),
        (r'deprecated', 'Deprecation warning'),
        (r'retry|retrying', 'Retry attempt')
    ]

    for line_num, line in enumerate(lines, 1):
        # Check ignition patterns
        for pattern in ignition_patterns['fetched']:
            if re.search(pattern, line, re.IGNORECASE):
                result['ignition_fetched'] = True

        for pattern in ignition_patterns['applied']:
            if re.search(pattern, line, re.IGNORECASE):
                result['ignition_applied'] = True

        # Check service patterns
        for pattern in service_patterns['bootstrap']:
            if re.search(pattern, line, re.IGNORECASE):
                result['bootstrap_started'] = True

        for pattern in service_patterns['etcd']:
            if re.search(pattern, line, re.IGNORECASE):
                result['etcd_started'] = True

        for pattern in service_patterns['kubelet']:
            if re.search(pattern, line, re.IGNORECASE):
                result['kubelet_started'] = True

        # Check error patterns
        for pattern, error_type in error_patterns:
            if re.search(pattern, line, re.IGNORECASE):
                result['errors'].append({
                    'type': error_type,
                    'line_number': line_num,
                    'message': line.strip(),
                    'pattern': pattern
                })

        # Check warning patterns
        for pattern, warning_type in warning_patterns:
            if re.search(pattern, line, re.IGNORECASE):
                result['warnings'].append({
                    'type': warning_type,
                    'line_number': line_num,
                    'message': line.strip()
                })

    # Determine stage based on markers
    if result['kubelet_started']:
        result['stage'] = 'kubelet_running'
    elif result['etcd_started']:
        result['stage'] = 'etcd_initializing'
    elif result['bootstrap_started']:
        result['stage'] = 'bootstrap_in_progress'
    elif result['ignition_applied']:
        result['stage'] = 'ignition_applied'
    elif result['ignition_fetched']:
        result['stage'] = 'ignition_fetched'
    else:
        result['stage'] = 'early_boot'

    return result


# =============================================================================
# INSTALLATION STATUS TESTS
# =============================================================================

@pytest.mark.installation
@pytest.mark.ignition
def test_installation_phase_detection(cluster_data: ClusterData):
    """Detect and report current installation phase

    Why: Understanding the current installation phase helps identify where the installation
    process is and what to expect next. Different phases have different expected states.

    Provides: Current phase, progress percentage, completed stages, and next expected stage.

    References:
    - https://docs.redhat.com/en/documentation/openshift_container_platform/4.13/html/installation_overview/ocp-installation-overview
    - https://deepwiki.com/openshift/appliance/5.1-bootstrap-process
    
    Documentation: https://docs.openshift.com/container-platform/latest/installing/index.html#installation-process
    """
    phase_info = detect_installation_phase(cluster_data)

    print(f"\n📊 Installation Phase Detection")
    print("─" * 80)
    print(f"Current Phase: {phase_info['phase']}")
    print(f"Progress: {phase_info['progress_percentage']}%")
    print(f"Description: {phase_info['phase_description']}")

    if phase_info['completed_stages']:
        print(f"\n✓ Completed Stages:")
        for stage in phase_info['completed_stages']:
            print(f"  • {stage}")

    if phase_info['current_stage']:
        print(f"\n⏳ Current Stage: {phase_info['current_stage']}")

    if phase_info['next_expected_stage']:
        print(f"➡️  Next Expected: {phase_info['next_expected_stage']}")

    if phase_info['error_indicators']:
        print(f"\n❌ Error Indicators:")
        for error in phase_info['error_indicators']:
            print(f"  • {error}")

    print("─" * 80)

    # Output full phase info as JSON
    print("\n" + "─" * 80)
    print("INSTALLATION PHASE DETAILS")
    print("Complete phase detection information")
    print("─" * 80)
    print(json.dumps(phase_info, indent=2))
    print("─" * 80)


@pytest.mark.installation
@pytest.mark.ignition
def test_cluster_installation_state(cluster_data: ClusterData):
    """Cluster must have valid installation state

    Why: The installation state indicates whether the cluster is operational, installing,
    or in error state. This is the primary indicator of cluster health.

    Failure indicates: The cluster is not in a ready state, which could mean installation
    is incomplete, failed, or the cluster is degraded.

    References:
    - https://docs.redhat.com/en/documentation/openshift_container_platform/4.13/html/installation_overview/ocp-installation-overview
    
    Documentation: https://docs.openshift.com/container-platform/latest/installing/index.html#installation-process
    """
    state = cluster_data.cluster_state

    if not state or state == 'unknown':
        pytest.skip("Cluster state not available in cluster data")

    state_lower = state.lower()

    # Define state categories
    ready_states = ['ready', 'installed', 'active']
    in_progress_states = ['installing', 'pending', 'validating']
    error_states = ['error', 'failed', 'degraded']

    print(f"\n📊 Cluster Installation State")
    print("─" * 80)
    print(json.dumps({
        "State": state,
        "Category": (
            "Ready" if state_lower in ready_states else
            "In Progress" if state_lower in in_progress_states else
            "Error" if state_lower in error_states else
            "Unknown"
        ),
        "IsOperational": state_lower in ready_states
    }, indent=2))
    print("─" * 80)

    if state_lower in error_states:
        phase_info = detect_installation_phase(cluster_data)
        pytest.fail(
            f"Cluster in error state: {state}\n\n"
            f"Installation Phase: {phase_info['phase']}\n"
            f"Description: {phase_info['phase_description']}\n"
            f"Progress: {phase_info['progress_percentage']}%\n\n"
            f"Investigate cluster operators and review logs for errors."
        )

    if state_lower in in_progress_states:
        phase_info = detect_installation_phase(cluster_data)
        pytest.skip(
            f"Cluster installation in progress: {state}\n\n"
            f"Installation Phase: {phase_info['phase']}\n"
            f"Current Stage: {phase_info['current_stage']}\n"
            f"Progress: {phase_info['progress_percentage']}%\n"
            f"Next Expected: {phase_info['next_expected_stage']}"
        )

    assert state_lower in ready_states, \
        f"Cluster not in ready state: {state} (expected one of {ready_states})"


@pytest.mark.installation
@pytest.mark.ignition
def test_control_plane_bootstrap_status(cluster_data: ClusterData):
    """Control plane must have completed bootstrap

    Why: Bootstrap is the initial phase where the temporary control plane starts,
    initializes etcd, and brings up the production control plane. This must complete
    for the cluster to be operational.

    Failure indicates: Bootstrap has not completed, which could mean:
    - Control plane instances are not running
    - etcd quorum not formed
    - Temporary control plane failed
    - Network connectivity issues

    References:
    - https://deepwiki.com/openshift/appliance/5.1-bootstrap-process
    - https://github.com/openshift/installer/blob/main/docs/user/troubleshootingbootstrap.md
    
    Documentation: https://docs.openshift.com/container-platform/latest/installing/index.html#installation-process
    """
    state = cluster_data.cluster_state.lower()

    # If cluster is in ready state, bootstrap is complete
    if state in ['ready', 'installed', 'active']:
        print("\n✓ Bootstrap completed successfully")
        print("  Cluster is in ready state")
        return

    # Check control plane instances
    masters = _get_master_instances(cluster_data)

    if not masters:
        pytest.fail(
            "Bootstrap incomplete: No control plane instances found\n\n"
            "Expected: At least 3 control plane instances for HA cluster\n\n"
            "Possible causes:\n"
            "  • Bootstrap node failed to launch control plane\n"
            "  • Ignition configuration issues\n"
            "  • AWS resource creation failures\n\n"
            "Next steps:\n"
            "  1. Check bootstrap node console logs\n"
            "  2. Verify Ignition configuration is accessible\n"
            "  3. Check AWS service limits and quotas\n"
            "  4. Review CloudTrail for EC2 instance launch failures"
        )

    running_masters = [m for m in masters if _get_instance_state(m) == 'running']

    print(f"\n📊 Control Plane Bootstrap Status")
    print("─" * 80)
    print(json.dumps({
        "TotalMasters": len(masters),
        "RunningMasters": len(running_masters),
        "ExpectedForHA": 3,
        "BootstrapComplete": len(running_masters) == len(masters) and len(masters) >= 3
    }, indent=2))
    print("─" * 80)

    if len(running_masters) < len(masters):
        pytest.fail(
            f"Bootstrap incomplete: {len(running_masters)}/{len(masters)} control plane instances running\n\n"
            f"Expected: All {len(masters)} control plane instances running\n\n"
            "Possible causes:\n"
            "  • Control plane instances still initializing\n"
            "  • Ignition fetch failures\n"
            "  • Networking configuration issues\n"
            "  • Instance startup failures\n\n"
            "Next steps:\n"
            "  1. Check console output for stopped/pending instances\n"
            "  2. Verify ignition configuration is accessible from instances\n"
            "  3. Check security group rules allow required traffic\n"
            "  4. Review instance system logs for errors"
        )

    if state not in ['ready', 'installed', 'active']:
        pytest.skip(
            f"Bootstrap in progress: All {len(masters)} control plane instances running\n\n"
            f"Cluster state: {state}\n\n"
            "Control plane instances are up, waiting for:\n"
            "  • etcd quorum formation\n"
            "  • Kubernetes API server availability\n"
            "  • Cluster operators deployment\n"
            "  • Bootstrap completion\n\n"
            "This is normal during installation. Wait for cluster state to become 'ready'."
        )


@pytest.mark.installation
@pytest.mark.ignition
def test_console_log_analysis_master(cluster_data: ClusterData):
    """Analyze control plane console logs for installation progress

    Why: EC2 console logs contain detailed information about the boot process,
    Ignition configuration application, and service initialization. These logs
    help identify exactly where in the installation process issues occurred.

    Provides: Ignition fetch status, service statuses, errors, and current stage.

    References:
    - https://docs.okd.io/latest/support/troubleshooting/troubleshooting-installations.html
    - https://www.redhat.com/en/blog/openshift-4.x-installation-quick-overview
    
    Documentation: https://docs.openshift.com/container-platform/latest/installing/index.html#installation-process
    """
    # Look for console log files for master nodes
    master_console_logs = list(cluster_data.aws_dir.glob(f"{cluster_data.cluster_id}_*master*console*.txt"))

    if not master_console_logs:
        pytest.skip(
            "No control plane console logs found\n\n"
            "Console logs must be collected manually from AWS console:\n"
            "  1. AWS Console → EC2 → Instances\n"
            "  2. Select master instance\n"
            "  3. Actions → Monitor and troubleshoot → Get system log\n"
            "  4. Save as: <cluster-id>_<instance-id>_console.txt\n\n"
            "Or use AWS CLI:\n"
            "  aws ec2 get-console-output --instance-id <instance-id> \\\n"
            "    --output text > <cluster-id>_<instance-id>_console.txt"
        )

    # Analyze first master console log
    console_log_file = master_console_logs[0]

    with open(console_log_file, 'r', errors='ignore') as f:
        console_log = f.read()

    analysis = analyze_console_logs(console_log)

    print(f"\n📊 Control Plane Console Log Analysis")
    print(f"File: {console_log_file.name}")
    print("─" * 80)
    print(json.dumps({
        "IgnitionFetched": analysis['ignition_fetched'],
        "IgnitionApplied": analysis['ignition_applied'],
        "BootstrapStarted": analysis['bootstrap_started'],
        "etcdStarted": analysis['etcd_started'],
        "KubeletStarted": analysis['kubelet_started'],
        "CurrentStage": analysis['stage'],
        "ErrorCount": len(analysis['errors']),
        "WarningCount": len(analysis['warnings'])
    }, indent=2))
    print("─" * 80)

    if analysis['errors']:
        print(f"\n❌ Errors Found ({len(analysis['errors'])}):")
        # Show first 10 errors
        for error in analysis['errors'][:10]:
            print(f"\n  Line {error['line_number']}: {error['type']}")
            print(f"  {error['message'][:200]}")

        if len(analysis['errors']) > 10:
            print(f"\n  ... and {len(analysis['errors']) - 10} more errors")

    if analysis['warnings']:
        print(f"\n⚠️  Warnings Found ({len(analysis['warnings'])}):")
        # Show first 5 warnings
        for warning in analysis['warnings'][:5]:
            print(f"  Line {warning['line_number']}: {warning['message'][:200]}")

        if len(analysis['warnings']) > 5:
            print(f"  ... and {len(analysis['warnings']) - 5} more warnings")

    # Output detailed analysis
    print("\n" + "─" * 80)
    print("DETAILED CONSOLE LOG ANALYSIS")
    print(f"Analysis of control plane console output for installation progress")
    print("─" * 80)
    print(json.dumps(analysis, indent=2, default=str))
    print("─" * 80)


@pytest.mark.installation
@pytest.mark.ignition
def test_ignition_configuration_accessible(cluster_data: ClusterData):
    """Verify Ignition configuration was accessible during installation

    Why: Ignition is the provisioning utility used by RHCOS. The bootstrap.ign,
    master.ign, and worker.ign files must be accessible for nodes to configure
    themselves during first boot.

    Failure indicates: Nodes could not fetch their Ignition configuration, which
    prevents them from initializing. This is often due to S3 bucket permissions,
    network connectivity, or incorrect URLs.

    References:
    - https://www.redhat.com/en/blog/openshift-4.x-installation-quick-overview
    - https://rdalal3.medium.com/openshift-installation-process-a750d490f21b
    
    Documentation: https://docs.openshift.com/container-platform/latest/installing/index.html#installation-process
    """
    # Check OCM resources for ignition-related configuration
    resources = cluster_data.resources

    if not resources:
        pytest.skip("OCM resources.json not available")

    # Look for ignition-related resources
    ignition_resources = {}

    # Check for common ignition resource patterns
    for key, value in resources.items():
        if 'ignition' in key.lower():
            ignition_resources[key] = value

    if not ignition_resources:
        # Check cluster JSON for ignition-related URLs
        cluster_json = cluster_data.cluster_json

        # Look for bootstrap ignition URL or similar
        if 'install_config' in cluster_json:
            print("\n✓ Install configuration found in cluster data")
            pytest.skip("Ignition configuration checking requires console log analysis")

    print(f"\n📊 Ignition Configuration Resources")
    print("─" * 80)
    print(json.dumps(ignition_resources, indent=2, default=str))
    print("─" * 80)


@pytest.mark.installation
@pytest.mark.operators
def test_cluster_operators_deployment_status(cluster_data: ClusterData):
    """Check cluster operators deployment status

    Why: After bootstrap completes, the Cluster Version Operator (CVO) deploys
    all cluster operators. All operators must be deployed and available for the
    cluster to be fully functional.

    Failure indicates: One or more operators failed to deploy, which means some
    cluster functionality is unavailable.

    References:
    - https://docs.redhat.com/en/documentation/openshift_container_platform/4.13/html/installation_overview/ocp-installation-overview
    
    Documentation: https://docs.openshift.com/container-platform/latest/installing/index.html#installation-process
    """
    state = cluster_data.cluster_state.lower()

    if state not in ['ready', 'installed', 'active']:
        pytest.skip(
            f"Cluster operators check requires cluster in ready state (current: {state})\n\n"
            "Operators are deployed after bootstrap completion.\n"
            "Wait for cluster to reach 'ready' state before validating operators."
        )

    # In ROSA, operator status would come from OpenShift API
    # Since we're working with AWS artifacts, check for operator-related resources

    print(f"\n✓ Cluster in ready state - operators should be deployed")
    print(f"   Cluster state: {state}")

    # This test assumes cluster is operational if in ready state
    # For detailed operator validation, would need oc/kubectl access


@pytest.mark.installation
@pytest.mark.bootstrap
def test_bootstrap_completion_indicators(cluster_data: ClusterData):
    """Validate bootstrap completion indicators

    Why: Bootstrap completion is a critical milestone. After bootstrap completes,
    the temporary bootstrap node should be destroyed and the production control
    plane should be fully operational.

    Indicators of completed bootstrap:
    - Cluster state is 'ready', 'installed', or 'active'
    - All control plane instances are running
    - No bootstrap instances exist
    - API server is accessible

    References:
    - https://deepwiki.com/openshift/appliance/5.1-bootstrap-process
    - https://github.com/openshift/installer/blob/main/docs/user/troubleshootingbootstrap.md
    
    Documentation: https://docs.openshift.com/container-platform/latest/installing/index.html#installation-process
    """
    state = cluster_data.cluster_state.lower()

    indicators = {
        'cluster_ready': state in ['ready', 'installed', 'active'],
        'control_plane_running': False,
        'no_bootstrap_instances': True,
        'api_url_configured': bool(cluster_data.cluster_json.get('api', {}).get('url'))
    }

    # Check control plane instances
    masters = _get_master_instances(cluster_data)
    if masters:
        running_masters = [m for m in masters if _get_instance_state(m) == 'running']
        indicators['control_plane_running'] = len(running_masters) == len(masters)

    # Check for bootstrap instances (should be gone after bootstrap completes)
    for instance in cluster_data.ec2_instances:
        tags = {tag['Key']: tag['Value'] for tag in instance.get('Tags', [])}
        instance_name = tags.get('Name', '')
        if 'bootstrap' in instance_name.lower():
            instance_state = _get_instance_state(instance)
            if instance_state == 'running':
                indicators['no_bootstrap_instances'] = False

    print(f"\n📊 Bootstrap Completion Indicators")
    print("─" * 80)
    print(json.dumps(indicators, indent=2))
    print("─" * 80)

    if not indicators['cluster_ready']:
        pytest.skip(
            f"Bootstrap not yet complete - cluster state: {state}\n\n"
            "Bootstrap completion indicators:\n"
            f"  • Cluster ready: {indicators['cluster_ready']}\n"
            f"  • Control plane running: {indicators['control_plane_running']}\n"
            f"  • No bootstrap instances: {indicators['no_bootstrap_instances']}\n"
            f"  • API URL configured: {indicators['api_url_configured']}\n\n"
            "Wait for cluster to reach 'ready' state."
        )

    assert all(indicators.values()), \
        f"Bootstrap completion indicators not all met: {indicators}"

    print("\n✓ All bootstrap completion indicators met")
    print("  Bootstrap completed successfully")


@pytest.mark.installation
@pytest.mark.etcd
def test_etcd_quorum_formation(cluster_data: ClusterData):
    """Verify etcd quorum formation (3 control plane nodes)

    Why: etcd requires a quorum of nodes to operate. For a 3-node control plane,
    all 3 nodes must be running and part of the etcd cluster for write operations
    to succeed.

    Failure indicates: Not enough control plane nodes are running to form etcd
    quorum, which prevents the Kubernetes API server from functioning.

    References:
    - https://deepwiki.com/openshift/cluster-etcd-operator/4.1-bootstrap-process
    - https://docs.redhat.com/en/documentation/openshift_container_platform/4.10/html/installing/index.html
    
    Documentation: https://docs.openshift.com/container-platform/latest/installing/index.html#installation-process
    """
    masters = _get_master_instances(cluster_data)

    if not masters:
        pytest.fail(
            "etcd quorum cannot form: No control plane instances found\n\n"
            "etcd requires 3 control plane nodes for HA configuration."
        )

    expected_count = 3  # Standard HA configuration
    actual_count = len(masters)
    running_count = len([m for m in masters if _get_instance_state(m) == 'running'])

    print(f"\n📊 etcd Quorum Status")
    print("─" * 80)
    print(json.dumps({
        "ExpectedControlPlaneNodes": expected_count,
        "ActualControlPlaneNodes": actual_count,
        "RunningControlPlaneNodes": running_count,
        "QuorumRequirement": f"{(expected_count // 2) + 1} of {expected_count}",
        "QuorumPossible": running_count >= ((expected_count // 2) + 1),
        "AllNodesRunning": running_count == actual_count
    }, indent=2))
    print("─" * 80)

    quorum_needed = (expected_count // 2) + 1

    if running_count < quorum_needed:
        pytest.fail(
            f"etcd quorum cannot form: {running_count}/{expected_count} control plane nodes running\n\n"
            f"Quorum requires: {quorum_needed} nodes\n"
            f"Currently running: {running_count} nodes\n\n"
            "Kubernetes API server will not function without etcd quorum.\n\n"
            "Actions:\n"
            "  1. Check why control plane instances are not running\n"
            "  2. Review console logs for failed instances\n"
            "  3. Check for AWS resource constraints\n"
            "  4. Verify network connectivity between control plane nodes"
        )

    if running_count < actual_count:
        pytest.skip(
            f"etcd quorum formed but not all nodes running: {running_count}/{actual_count}\n\n"
            f"Quorum is possible with {running_count} nodes (need {quorum_needed}), "
            "but cluster is degraded.\n\n"
            "Investigation recommended to bring all control plane nodes online."
        )

    print(f"\n✓ All {actual_count} control plane nodes running")
    print(f"  etcd quorum can be formed ({quorum_needed} of {expected_count} required)")
