"""
IAM Permission Tests

Validates AWS IAM permissions by checking API request logs for permission errors.
These tests help diagnose cluster installation/support issues related to IAM permissions.
"""

import pytest
import json
from typing import List, Dict, Any
from models.cluster import ClusterData


@pytest.mark.aws_resources
@pytest.mark.severity("CRITICAL")
def test_no_permission_errors_in_api_requests(cluster_data: ClusterData):
    """All AWS API requests should succeed without permission errors

    Why: Permission errors prevent cluster data collection and indicate missing IAM permissions.

    Failure indicates: The IAM user/role lacks required permissions for AWS operations.

    Success indicates: All required IAM permissions are present for data collection.

    Remediation: Review permission errors below and add missing IAM permissions to the user/role.
    Check the AWS IAM policy attached to the credentials used for data collection.

    Severity: CRITICAL - Permission errors prevent complete cluster diagnostics
    """
    if not cluster_data.api_requests:
        pytest.skip("API request log not available")

    requests = cluster_data.api_requests.get('requests', [])

    # Find all permission errors
    permission_errors = []
    for req in requests:
        if not req.get('success', True):
            error = req.get('error', {})
            error_code = error.get('code', '')

            # Check for permission-related error codes
            if error_code in ['AccessDenied', 'UnauthorizedOperation', 'Forbidden', 'AccessDeniedException']:
                error_entry = {
                    'service': req.get('service'),
                    'operation': req.get('operation'),
                    'error_code': error_code,
                    'error_message': error.get('message', 'No message'),
                    'timestamp': req.get('timestamp'),
                    'parameters': req.get('parameters', {})
                }

                # Add response code if available
                if req.get('response_code'):
                    error_entry['response_code'] = req['response_code']

                # Add duration if available
                if req.get('duration_ms'):
                    error_entry['duration_ms'] = req['duration_ms']

                permission_errors.append(error_entry)

    if permission_errors:
        print(f"\n✗ Found {len(permission_errors)} permission error(s) in API requests:")
        print(json.dumps(permission_errors, indent=2))

        # Group by service for summary
        by_service = {}
        for err in permission_errors:
            service = err['service']
            if service not in by_service:
                by_service[service] = []
            by_service[service].append(err['operation'])

        print(f"\n📋 Permission Errors by Service:")
        for service, operations in by_service.items():
            print(f"  {service}: {', '.join(set(operations))}")

        # Extract permission list to avoid f-string backslash issue
        missing_perms = ', '.join([f'{e["service"]}.{e["operation"]}' for e in permission_errors[:3]])
        pytest.fail(
            f"Found {len(permission_errors)} permission error(s). "
            f"IAM permissions missing for: {missing_perms}"
        )
    else:
        print(f"\n✓ All {len(requests)} API requests succeeded without permission errors")


@pytest.mark.aws_resources
@pytest.mark.severity("HIGH")
def test_no_failed_api_requests(cluster_data: ClusterData):
    """AWS API requests should complete successfully

    Why: Failed API requests prevent complete cluster data collection.

    Failure indicates: Some AWS API operations failed, possibly due to permissions, rate limiting, or service issues.

    Success indicates: All AWS API operations completed successfully.

    Remediation: Review failed requests below and address the root cause (permissions, throttling, etc.).

    Severity: HIGH - Failed requests may indicate incomplete cluster diagnostics
    """
    if not cluster_data.api_requests:
        pytest.skip("API request log not available")

    requests = cluster_data.api_requests.get('requests', [])

    # Find all failed requests
    failed_requests = [req for req in requests if not req.get('success', True)]

    if failed_requests:
        print(f"\n✗ Found {len(failed_requests)} failed API request(s):")

        # Show summary of failures
        failure_summary = []
        for req in failed_requests:
            error = req.get('error', {})
            summary_entry = {
                'service': req.get('service'),
                'operation': req.get('operation'),
                'error_code': error.get('code', 'Unknown'),
                'error_message': error.get('message', 'No message')[:100],
                'timestamp': req.get('timestamp')
            }

            # Add response code if available
            if req.get('response_code'):
                summary_entry['response_code'] = req['response_code']

            # Add duration if available
            if req.get('duration_ms'):
                summary_entry['duration_ms'] = req['duration_ms']

            failure_summary.append(summary_entry)

        print(json.dumps(failure_summary, indent=2))

        # Categorize errors
        by_error_code = {}
        for req in failed_requests:
            error_code = req.get('error', {}).get('code', 'Unknown')
            if error_code not in by_error_code:
                by_error_code[error_code] = 0
            by_error_code[error_code] += 1

        print(f"\n📋 Failures by Error Code:")
        for code, count in sorted(by_error_code.items(), key=lambda x: x[1], reverse=True):
            print(f"  {code}: {count} occurrence(s)")

        pytest.fail(f"Found {len(failed_requests)} failed API request(s)")
    else:
        total_requests = len(requests)
        print(f"\n✓ All {total_requests} API requests completed successfully")


@pytest.mark.aws_resources
@pytest.mark.severity("MEDIUM")
def test_ec2_permissions_available(cluster_data: ClusterData):
    """EC2 describe permissions should be available

    Why: EC2 permissions are required to collect instance, VPC, and network data.

    Failure indicates: IAM permissions missing for EC2 operations.

    Success indicates: Required EC2 permissions are available.

    Remediation: Add missing EC2 permissions to the IAM policy:
        ec2:DescribeInstances
        ec2:DescribeVpcs
        ec2:DescribeSubnets
        ec2:DescribeSecurityGroups
        ec2:DescribeVolumes
        ec2:DescribeNetworkInterfaces
        ec2:DescribeRouteTables
        ec2:DescribeInternetGateways
        ec2:DescribeNatGateways

    Severity: MEDIUM - EC2 data is important for cluster diagnostics
    """
    if not cluster_data.api_requests:
        pytest.skip("API request log not available")

    requests = cluster_data.api_requests.get('requests', [])

    # Check for EC2 operations
    ec2_requests = [req for req in requests if req.get('service') == 'ec2']

    if not ec2_requests:
        pytest.skip("No EC2 API requests found in log")

    # Check for failed EC2 permission requests
    ec2_permission_errors = []
    for req in ec2_requests:
        if not req.get('success', True):
            error = req.get('error', {})
            error_code = error.get('code', '')

            if error_code in ['AccessDenied', 'UnauthorizedOperation', 'Forbidden']:
                ec2_permission_errors.append({
                    'operation': req.get('operation'),
                    'error': error.get('message', 'No message')
                })

    if ec2_permission_errors:
        print(f"\n✗ Found {len(ec2_permission_errors)} EC2 permission error(s):")
        print(json.dumps(ec2_permission_errors, indent=2))

        missing_operations = list(set([err['operation'] for err in ec2_permission_errors]))
        pytest.fail(
            f"EC2 permissions missing for: {', '.join(missing_operations)}"
        )
    else:
        print(f"\n✓ EC2 permissions validated - {len(ec2_requests)} operations succeeded")


@pytest.mark.aws_resources
@pytest.mark.severity("MEDIUM")
def test_elb_permissions_available(cluster_data: ClusterData):
    """ELB/ELBv2 describe permissions should be available

    Why: ELB permissions are required to collect load balancer data.

    Failure indicates: IAM permissions missing for ELB operations.

    Success indicates: Required ELB permissions are available.

    Remediation: Add missing ELB permissions to the IAM policy:
        elasticloadbalancing:DescribeLoadBalancers
        elasticloadbalancing:DescribeTargetGroups
        elasticloadbalancing:DescribeTargetHealth
        elasticloadbalancing:DescribeListeners

    Severity: MEDIUM - Load balancer data is important for cluster access diagnostics
    """
    if not cluster_data.api_requests:
        pytest.skip("API request log not available")

    requests = cluster_data.api_requests.get('requests', [])

    # Check for ELB/ELBv2 operations
    elb_requests = [req for req in requests if req.get('service') in ['elb', 'elbv2', 'elasticloadbalancing']]

    if not elb_requests:
        pytest.skip("No ELB API requests found in log")

    # Check for failed ELB permission requests
    elb_permission_errors = []
    for req in elb_requests:
        if not req.get('success', True):
            error = req.get('error', {})
            error_code = error.get('code', '')

            if error_code in ['AccessDenied', 'UnauthorizedOperation', 'Forbidden']:
                elb_permission_errors.append({
                    'operation': req.get('operation'),
                    'error': error.get('message', 'No message')
                })

    if elb_permission_errors:
        print(f"\n✗ Found {len(elb_permission_errors)} ELB permission error(s):")
        print(json.dumps(elb_permission_errors, indent=2))

        missing_operations = list(set([err['operation'] for err in elb_permission_errors]))
        pytest.fail(
            f"ELB permissions missing for: {', '.join(missing_operations)}"
        )
    else:
        print(f"\n✓ ELB permissions validated - {len(elb_requests)} operations succeeded")


@pytest.mark.aws_resources
@pytest.mark.severity("MEDIUM")
def test_route53_permissions_available(cluster_data: ClusterData):
    """Route53 permissions should be available

    Why: Route53 permissions are required to collect DNS data.

    Failure indicates: IAM permissions missing for Route53 operations.

    Success indicates: Required Route53 permissions are available.

    Remediation: Add missing Route53 permissions to the IAM policy:
        route53:ListHostedZones
        route53:ListResourceRecordSets
        route53:GetHostedZone

    Severity: MEDIUM - DNS data is important for cluster access diagnostics
    """
    if not cluster_data.api_requests:
        pytest.skip("API request log not available")

    requests = cluster_data.api_requests.get('requests', [])

    # Check for Route53 operations
    route53_requests = [req for req in requests if req.get('service') == 'route53']

    if not route53_requests:
        pytest.skip("No Route53 API requests found in log")

    # Check for failed Route53 permission requests
    route53_permission_errors = []
    for req in route53_requests:
        if not req.get('success', True):
            error = req.get('error', {})
            error_code = error.get('code', '')

            if error_code in ['AccessDenied', 'UnauthorizedOperation', 'Forbidden']:
                route53_permission_errors.append({
                    'operation': req.get('operation'),
                    'error': error.get('message', 'No message')
                })

    if route53_permission_errors:
        print(f"\n✗ Found {len(route53_permission_errors)} Route53 permission error(s):")
        print(json.dumps(route53_permission_errors, indent=2))

        missing_operations = list(set([err['operation'] for err in route53_permission_errors]))
        pytest.fail(
            f"Route53 permissions missing for: {', '.join(missing_operations)}"
        )
    else:
        print(f"\n✓ Route53 permissions validated - {len(route53_requests)} operations succeeded")


@pytest.mark.aws_resources
@pytest.mark.severity("LOW")
def test_iam_permissions_available(cluster_data: ClusterData):
    """IAM permissions should be available

    Why: IAM permissions are required to collect instance profile and role data.

    Failure indicates: IAM permissions missing for IAM operations.

    Success indicates: Required IAM permissions are available.

    Remediation: Add missing IAM permissions to the IAM policy:
        iam:ListInstanceProfiles
        iam:GetRole
        iam:GetInstanceProfile

    Severity: LOW - IAM data is helpful but not critical for cluster diagnostics
    """
    if not cluster_data.api_requests:
        pytest.skip("API request log not available")

    requests = cluster_data.api_requests.get('requests', [])

    # Check for IAM operations
    iam_requests = [req for req in requests if req.get('service') == 'iam']

    if not iam_requests:
        pytest.skip("No IAM API requests found in log")

    # Check for failed IAM permission requests
    iam_permission_errors = []
    for req in iam_requests:
        if not req.get('success', True):
            error = req.get('error', {})
            error_code = error.get('code', '')

            if error_code in ['AccessDenied', 'UnauthorizedOperation', 'Forbidden']:
                iam_permission_errors.append({
                    'operation': req.get('operation'),
                    'error': error.get('message', 'No message')
                })

    if iam_permission_errors:
        print(f"\n✗ Found {len(iam_permission_errors)} IAM permission error(s):")
        print(json.dumps(iam_permission_errors, indent=2))

        missing_operations = list(set([err['operation'] for err in iam_permission_errors]))
        pytest.fail(
            f"IAM permissions missing for: {', '.join(missing_operations)}"
        )
    else:
        print(f"\n✓ IAM permissions validated - {len(iam_requests)} operations succeeded")


@pytest.mark.aws_resources
@pytest.mark.severity("INFO")
def test_api_request_summary(cluster_data: ClusterData):
    """Display summary of all API requests

    Why: Provides overview of data collection operations.

    Severity: INFO - Informational test only
    """
    if not cluster_data.api_requests:
        pytest.skip("API request log not available")

    summary = cluster_data.api_requests.get('summary', {})
    requests = cluster_data.api_requests.get('requests', [])

    print(f"\n📊 API Request Summary:")
    print(f"  Total Requests: {summary.get('total_requests', len(requests))}")
    print(f"  Successful: {summary.get('successful_requests', 0)}")
    print(f"  Failed: {summary.get('failed_requests', 0)}")

    # Group by service
    by_service = {}
    for req in requests:
        service = req.get('service', 'unknown')
        if service not in by_service:
            by_service[service] = {'total': 0, 'success': 0, 'failed': 0}

        by_service[service]['total'] += 1
        if req.get('success', True):
            by_service[service]['success'] += 1
        else:
            by_service[service]['failed'] += 1

    print(f"\n📋 Requests by Service:")
    for service, counts in sorted(by_service.items()):
        print(f"  {service}: {counts['total']} total, {counts['success']} success, {counts['failed']} failed")

    # Show error categories if present
    error_categories = summary.get('errors_by_category', {})
    if error_categories:
        print(f"\n⚠️  Errors by Category:")
        for category, count in sorted(error_categories.items(), key=lambda x: x[1], reverse=True):
            print(f"  {category}: {count}")


@pytest.mark.aws_resources
@pytest.mark.severity("HIGH")
def test_critical_operations_succeeded(cluster_data: ClusterData):
    """Critical AWS operations should have succeeded

    Why: Some operations are critical for cluster diagnostics.

    Failure indicates: Critical data collection operations failed.

    Success indicates: All critical operations completed successfully.

    Remediation: Ensure IAM permissions are available for critical operations.

    Severity: HIGH - Critical operations are required for comprehensive diagnostics
    """
    if not cluster_data.api_requests:
        pytest.skip("API request log not available")

    requests = cluster_data.api_requests.get('requests', [])

    # Define critical operations
    critical_operations = [
        ('ec2', 'describe_instances'),
        ('ec2', 'describe_vpcs'),
        ('ec2', 'describe_subnets'),
        ('ec2', 'describe_security_groups'),
        ('elbv2', 'describe_load_balancers'),
        ('elbv2', 'describe_target_groups'),
    ]

    # Check if critical operations succeeded
    failed_critical = []
    for service, operation in critical_operations:
        # Find requests for this operation
        operation_requests = [
            req for req in requests
            if req.get('service') == service and req.get('operation') == operation
        ]

        if operation_requests:
            # Check if any succeeded
            succeeded = any(req.get('success', False) for req in operation_requests)
            if not succeeded:
                errors = [req.get('error', {}) for req in operation_requests if not req.get('success', True)]
                failed_critical.append({
                    'service': service,
                    'operation': operation,
                    'errors': errors
                })

    if failed_critical:
        print(f"\n✗ Critical operations that failed:")
        print(json.dumps(failed_critical, indent=2))

        operations_list = [f"{op['service']}.{op['operation']}" for op in failed_critical]
        pytest.fail(
            f"{len(failed_critical)} critical operation(s) failed: {', '.join(operations_list)}"
        )
    else:
        print(f"\n✓ All critical operations succeeded")


@pytest.mark.aws_resources
@pytest.mark.severity("MEDIUM")
def test_no_throttling_errors(cluster_data: ClusterData):
    """API requests should not be throttled

    Why: Throttling errors indicate rate limits were exceeded during data collection.

    Failure indicates: AWS API rate limits were exceeded, some data may be incomplete.

    Success indicates: No throttling occurred during data collection.

    Remediation: Retry data collection or request AWS API rate limit increase.

    Severity: MEDIUM - Throttling may result in incomplete data
    """
    if not cluster_data.api_requests:
        pytest.skip("API request log not available")

    requests = cluster_data.api_requests.get('requests', [])

    # Find throttling errors
    throttled_requests = []
    for req in requests:
        if not req.get('success', True):
            error = req.get('error', {})
            error_code = error.get('code', '')

            if error_code in ['Throttling', 'RequestLimitExceeded', 'TooManyRequestsException', 'ThrottlingException']:
                throttled_requests.append({
                    'service': req.get('service'),
                    'operation': req.get('operation'),
                    'error_code': error_code,
                    'timestamp': req.get('timestamp')
                })

    if throttled_requests:
        print(f"\n✗ Found {len(throttled_requests)} throttled request(s):")
        print(json.dumps(throttled_requests, indent=2))

        # Group by service
        by_service = {}
        for req in throttled_requests:
            service = req['service']
            if service not in by_service:
                by_service[service] = 0
            by_service[service] += 1

        print(f"\n📋 Throttling by Service:")
        for service, count in sorted(by_service.items(), key=lambda x: x[1], reverse=True):
            print(f"  {service}: {count} occurrence(s)")

        pytest.fail(f"Found {len(throttled_requests)} throttled API request(s)")
    else:
        print(f"\n✓ No throttling errors - all {len(requests)} requests completed without rate limiting")
