"""
Installation Diagnostics Tests

Deep diagnostic analysis of OpenShift/ROSA cluster installations using:
- EC2 instance console logs
- OCM resources and installation logs
- Embedded OpenShift installation knowledge

Provides detailed failure analysis with automated remediation suggestions.
"""

import pytest
from pathlib import Path
from models.cluster import ClusterData
from utils.installation_diagnostics import (
    BootstrapDiagnostics,
    InstallationKnowledge
)


@pytest.mark.installation
@pytest.mark.severity("INFO")
def test_bootstrap_detailed_analysis(cluster_data: ClusterData, request):
    """Analyze bootstrap process from master instance console logs

    Provides deep diagnostic analysis of bootstrap progress:
    - Current bootstrap stage and progress percentage (0-100%)
    - Completed steps vs remaining steps
    - Ignition fetch and apply status
    - Bootstrap service status
    - etcd initialization progress
    - Detailed failure analysis with remediation suggestions

    Why: Understanding bootstrap progress helps identify where installation
    is stuck or failing, enabling targeted troubleshooting.

    Failure indicates: Bootstrap has encountered errors or is not progressing.
    Common issues include Ignition fetch failures (S3 permissions), systemd
    unit failures, disk space issues, or network connectivity problems.

    Success indicates: Bootstrap process is progressing normally or has
    completed successfully.

    Severity: INFO - Provides diagnostic information even when tests pass
    """
    # Get master instances for bootstrap analysis
    master_instances = []
    for instance in cluster_data.ec2_instances:
        tags = {tag['Key']: tag['Value'] for tag in instance.get('Tags', [])}
        name = tags.get('Name', '')
        if 'master' in name.lower():
            # Handle State being either dict or string
            state = instance.get('State', {})
            if isinstance(state, dict):
                state_name = state.get('Name', 'unknown')
            else:
                state_name = state if state else 'unknown'

            master_instances.append({
                'instance_id': instance.get('InstanceId'),
                'name': name,
                'state': state_name
            })

    if not master_instances:
        pytest.skip("No master instances found for bootstrap analysis")

    # Track analysis results for all instances
    all_analyses = {}
    failures_found = []

    # Analyze each master instance's console log
    for instance in master_instances:
        instance_id = instance['instance_id']
        instance_name = instance['name']

        # Try to load console log
        console_log = cluster_data.get_console_log(instance_id)

        if not console_log:
            # Console log not available - skip this instance
            continue

        # Perform deep analysis using BootstrapDiagnostics
        diagnostics = BootstrapDiagnostics(console_log, instance_name)
        analysis = diagnostics.analyze()

        # Store in all_analyses for HTML rendering
        all_analyses[instance_id] = analysis

        # If failures found, track them
        if analysis.get('failures'):
            failures_found.append({
                'instance_id': instance_id,
                'instance_name': instance_name,
                'analysis': analysis
            })

        # Store in user_properties for HTML rendering
        # Use instance_id as key to keep analyses separate
        request.node.user_properties.append((
            f"bootstrap_analysis_{instance_id}",
            analysis
        ))

    # If no console logs were available, skip the test
    if not all_analyses:
        pytest.skip("No console logs available for bootstrap analysis")

    # Generate console output for user visibility
    print("\n" + "="*80)
    print("BOOTSTRAP DETAILED ANALYSIS")
    print("="*80)

    for instance_id, analysis in all_analyses.items():
        instance_name = analysis.get('instance_name', instance_id)
        stage = analysis.get('stage', 'unknown')
        progress = analysis.get('progress_percentage', 0)
        current_step = analysis.get('current_step', 'Unknown')
        completed_steps = analysis.get('completed_steps', [])
        timeline = analysis.get('timeline', [])

        print(f"\nInstance: {instance_name} ({instance_id})")
        print(f"  Stage: {stage} ({progress}% complete)")
        print(f"  Current: {current_step}")

        if completed_steps:
            print(f"  Completed: {' → '.join(completed_steps)}")

        # Show timeline summary
        if timeline and len(timeline) > 0:
            first_event = timeline[0]
            last_event = timeline[-1]
            print(f"  Timeline: {len(timeline)} events from {first_event.get('timestamp', 'N/A')} to {last_event.get('timestamp', 'N/A')}")

    # If failures found, provide detailed output
    if failures_found:
        print("\n" + "="*80)
        print("FAILURES DETECTED")
        print("="*80)

        for failure_info in failures_found:
            instance_name = failure_info['instance_name']
            instance_id = failure_info['instance_id']
            analysis = failure_info['analysis']

            print(f"\nInstance: {instance_name} ({instance_id})")
            print(f"Found {len(analysis['failures'])} failures:")

            for failure in analysis['failures']:
                failure_type = failure.get('type', 'unknown')
                message = failure.get('message', 'No message')
                line = failure.get('line', 'N/A')
                timestamp = failure.get('timestamp', 'N/A')

                print(f"\n  • {failure_type} (line {line}, time: {timestamp})")
                print(f"    {message}")

                # Show remediation if available
                if failure.get('remediation'):
                    print(f"    Remediation:")
                    for step in failure['remediation']:
                        print(f"      - {step}")

        # Show remediation suggestions
        remediation_suggestions = []
        for failure_info in failures_found:
            analysis = failure_info['analysis']
            suggestions = analysis.get('remediation_suggestions', [])
            for suggestion in suggestions:
                if suggestion not in remediation_suggestions:
                    remediation_suggestions.append(suggestion)

        if remediation_suggestions:
            print("\n" + "="*80)
            print("REMEDIATION SUGGESTIONS")
            print("="*80)

            for suggestion in remediation_suggestions:
                print(f"\n{suggestion['symptom']}")
                print(f"Root Cause: {suggestion['root_cause']}")
                print(f"Severity: {suggestion['severity']}")
                print(f"\nRemediation Steps:")
                for idx, step in enumerate(suggestion['steps'], 1):
                    print(f"  {idx}. {step}")

                if suggestion.get('related_tests'):
                    print(f"\nRelated Tests:")
                    for test in suggestion['related_tests']:
                        print(f"  → {test}")

        print("\n" + "="*80 + "\n")

        # Fail the test with summary
        pytest.fail(
            f"Bootstrap analysis detected {len(failures_found)} instance(s) with failures. "
            f"See detailed analysis above and HTML report for full remediation guidance."
        )

    # No failures - test passes
    print("\n✓ Bootstrap analysis complete - no critical failures detected")
    print("="*80 + "\n")


@pytest.mark.installation
@pytest.mark.severity("INFO")
def test_api_server_initialization_diagnostics(cluster_data: ClusterData, request):
    """Analyze API server startup and health from console logs

    Provides deep diagnostic analysis of API server initialization:
    - API server startup status and timing
    - etcd connection status
    - Certificate validity
    - Binding and port status
    - Startup errors with remediation

    Why: The API server is critical for cluster operation. Understanding
    startup failures helps identify certificate issues, etcd problems,
    or network connectivity issues.

    Failure indicates: API server failed to start or is unhealthy.

    Success indicates: API server initialized successfully.

    Severity: INFO - Diagnostic information
    """
    # TODO: Implement API server diagnostics parser
    # For now, skip as placeholder
    pytest.skip("API server diagnostics not yet implemented - coming in next phase")


@pytest.mark.installation
@pytest.mark.severity("CRITICAL")
def test_machine_health_check_diagnostics(cluster_data: ClusterData, request):
    """Analyze machine health check failures from console logs and OCM data

    Provides deep diagnostic analysis of machine health:
    - Unhealthy machines with specific conditions
    - Node conditions (NotReady, MemoryPressure, DiskPressure, PIDPressure)
    - Health check timeout/failure patterns
    - Remediation steps based on condition types

    Why: Machine health checks determine if nodes are ready to run workloads.
    Understanding why nodes are unhealthy is critical for cluster stability.

    Failure indicates: One or more machines are unhealthy or unready.

    Success indicates: All machines are healthy and ready.

    Severity: CRITICAL - Unhealthy machines prevent cluster operation
    """
    # TODO: Implement machine health check diagnostics
    # For now, skip as placeholder
    pytest.skip("Machine health check diagnostics not yet implemented - coming in next phase")


@pytest.mark.installation
@pytest.mark.severity("CRITICAL")
def test_ignition_detailed_diagnostics(cluster_data: ClusterData, request):
    """Analyze Ignition configuration fetch and apply from console logs

    Provides deep diagnostic analysis of Ignition process:
    - Fetch status (success/failed/not attempted)
    - Fetch URL and S3 bucket details
    - Fetch errors (403 Forbidden, 404 Not Found, timeout, network)
    - Apply status (success/partial/failed)
    - systemd unit failures during apply
    - File write errors (permission denied, disk full)

    Why: Ignition is the first step in instance initialization. Failures
    here prevent instances from joining the cluster.

    Failure indicates: Ignition configuration could not be fetched or applied.
    Common causes include S3 permissions (403), missing files (404), network
    issues (timeout), or disk space problems.

    Success indicates: Ignition configuration was fetched and applied successfully.

    Severity: CRITICAL - Ignition failures prevent instance initialization
    """
    # TODO: Implement Ignition diagnostics parser
    # For now, skip as placeholder
    pytest.skip("Ignition diagnostics not yet implemented - coming in next phase")


@pytest.mark.installation
def test_console_logs_available(cluster_data: ClusterData):
    """Verify console logs are available for diagnostic analysis

    Why: Console logs are required for deep diagnostic analysis of bootstrap,
    API server, and ignition failures.

    Failure indicates: Console logs were not collected during artifact gathering.
    This is expected for older cluster data or if collection was interrupted.

    Success indicates: Console logs are available for analysis.
    """
    # Check if hosts directory exists
    hosts_dir = cluster_data.hosts_dir

    if not hosts_dir.exists():
        pytest.skip(
            "Console logs directory not found (sources/hosts/). "
            "Console logs are required for deep diagnostic analysis but may not "
            "be available for older cluster data."
        )

    # Try to get console logs
    console_logs = cluster_data.get_all_console_logs()

    if not console_logs:
        pytest.skip(
            "No console logs found in sources/hosts/ directory. "
            "Console logs are required for bootstrap and API server diagnostics."
        )

    # Console logs available
    print(f"\n✓ Found {len(console_logs)} console logs")
    for instance_id, log_content in console_logs.items():
        print(f"  - {instance_id}: {len(log_content):,} bytes")
