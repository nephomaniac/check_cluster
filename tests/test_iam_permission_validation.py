"""
IAM Permission Validation Tests

Individual permission checks with checkbox-style output for HTML reports.
Each permission or group of related permissions gets its own test.
"""

import pytest
import json
from typing import List, Dict, Any, Set
from models.cluster import ClusterData


def check_api_requests_available(cluster_data: ClusterData) -> Dict[str, Any]:
    """Check if API request log is available with diagnostics"""
    result = {
        'available': False,
        'reason': 'unknown',
        'request_count': 0
    }

    if not cluster_data.api_requests:
        result['reason'] = 'no_api_request_log'
        return result

    requests = cluster_data.api_requests.get('requests', [])
    result['request_count'] = len(requests)

    if not requests:
        result['reason'] = 'api_log_empty'
        return result

    result['available'] = True
    result['reason'] = 'available'
    return result


def get_permission_errors(cluster_data: ClusterData, service: str = None, operation: str = None) -> List[Dict[str, Any]]:
    """Get permission errors from API request log"""
    if not cluster_data.api_requests:
        return []

    requests = cluster_data.api_requests.get('requests', [])
    permission_errors = []

    for req in requests:
        # Filter by service if specified
        if service and req.get('service') != service:
            continue

        # Filter by operation if specified
        if operation and req.get('operation') != operation:
            continue

        if not req.get('success', True):
            error = req.get('error', {})
            error_code = error.get('code', '')

            if error_code in ['AccessDenied', 'UnauthorizedOperation', 'Forbidden', 'AccessDeniedException']:
                permission_errors.append({
                    'service': req.get('service'),
                    'operation': req.get('operation'),
                    'error_code': error_code,
                    'error_message': error.get('message', ''),
                    'timestamp': req.get('timestamp')
                })

    return permission_errors


def format_permission_checklist(permissions: Dict[str, bool], title: str) -> str:
    """Format permissions as checkbox-style list for output"""
    output = f"\n{title}\n"
    output += "─" * 80 + "\n"

    for permission, has_permission in sorted(permissions.items()):
        checkbox = "☑" if has_permission else "☐"
        status = "GRANTED" if has_permission else "MISSING"
        output += f"  {checkbox} {permission:50s} [{status}]\n"

    granted_count = sum(1 for v in permissions.values() if v)
    total_count = len(permissions)
    output += "─" * 80 + "\n"
    output += f"  Summary: {granted_count}/{total_count} permissions verified\n"

    return output


# ============================================================================
# EC2 Permissions
# ============================================================================

@pytest.mark.aws_resources
@pytest.mark.iam_permissions
@pytest.mark.severity("CRITICAL")
def test_ec2_describe_instances_permission(cluster_data: ClusterData):
    """EC2 DescribeInstances permission must be available

    Why: Required to list and describe EC2 instances for cluster nodes.

    Failure indicates: Cannot retrieve instance information.

    Success indicates: Permission is available.

    Severity: CRITICAL - Required for cluster diagnostics
    """
    api_status = check_api_requests_available(cluster_data)

    if not api_status['available']:
        if api_status['reason'] == 'no_api_request_log':
            pytest.skip("API request log not available - cannot validate permissions")
        elif api_status['reason'] == 'api_log_empty':
            pytest.skip("API request log is empty - no requests to validate")

    errors = get_permission_errors(cluster_data, service='ec2', operation='describe_instances')

    permissions = {
        'ec2:DescribeInstances': len(errors) == 0
    }

    print(format_permission_checklist(permissions, "EC2 Instance Permissions"))

    if errors:
        error_details = json.dumps(errors, indent=2)
        pytest.fail(
            f"Missing permission: ec2:DescribeInstances\n"
            f"Error details:\n{error_details}\n\n"
            f"Remediation: Add ec2:DescribeInstances to IAM policy"
        )


@pytest.mark.aws_resources
@pytest.mark.iam_permissions
@pytest.mark.severity("HIGH")
def test_ec2_vpc_permissions(cluster_data: ClusterData):
    """EC2 VPC permissions must be available

    Why: Required to retrieve VPC, subnet, and network configuration.

    Failure indicates: Cannot retrieve network information.

    Success indicates: VPC permissions are available.

    Severity: HIGH - Required for network diagnostics
    """
    api_status = check_api_requests_available(cluster_data)

    if not api_status['available']:
        pytest.skip("API request log not available")

    # Check multiple VPC-related operations
    vpc_permissions = {
        'ec2:DescribeVpcs': 'describe_vpcs',
        'ec2:DescribeSubnets': 'describe_subnets',
        'ec2:DescribeRouteTables': 'describe_route_tables',
        'ec2:DescribeSecurityGroups': 'describe_security_groups',
        'ec2:DescribeNetworkInterfaces': 'describe_network_interfaces'
    }

    permissions_status = {}
    all_errors = []

    for permission, operation in vpc_permissions.items():
        errors = get_permission_errors(cluster_data, service='ec2', operation=operation)
        permissions_status[permission] = len(errors) == 0
        all_errors.extend(errors)

    print(format_permission_checklist(permissions_status, "EC2 VPC Permissions"))

    if all_errors:
        missing_perms = [perm for perm, status in permissions_status.items() if not status]
        error_details = json.dumps(all_errors, indent=2)

        pytest.fail(
            f"Missing VPC permissions: {', '.join(missing_perms)}\n"
            f"Error details:\n{error_details}\n\n"
            f"Remediation: Add missing permissions to IAM policy"
        )


@pytest.mark.aws_resources
@pytest.mark.iam_permissions
@pytest.mark.severity("HIGH")
def test_ec2_volume_permissions(cluster_data: ClusterData):
    """EC2 volume permissions must be available

    Why: Required to retrieve EBS volume information for persistent storage.

    Failure indicates: Cannot retrieve volume information.

    Success indicates: Volume permissions are available.

    Severity: HIGH - Required for storage diagnostics
    """
    api_status = check_api_requests_available(cluster_data)

    if not api_status['available']:
        pytest.skip("API request log not available")

    volume_permissions = {
        'ec2:DescribeVolumes': 'describe_volumes',
        'ec2:DescribeSnapshots': 'describe_snapshots'
    }

    permissions_status = {}
    all_errors = []

    for permission, operation in volume_permissions.items():
        errors = get_permission_errors(cluster_data, service='ec2', operation=operation)
        permissions_status[permission] = len(errors) == 0
        all_errors.extend(errors)

    print(format_permission_checklist(permissions_status, "EC2 Volume Permissions"))

    if all_errors:
        missing_perms = [perm for perm, status in permissions_status.items() if not status]
        pytest.fail(f"Missing volume permissions: {', '.join(missing_perms)}")


# ============================================================================
# ELB Permissions
# ============================================================================

@pytest.mark.aws_resources
@pytest.mark.iam_permissions
@pytest.mark.severity("HIGH")
def test_elb_describe_permissions(cluster_data: ClusterData):
    """ELB describe permissions must be available

    Why: Required to retrieve load balancer information for cluster access.

    Failure indicates: Cannot retrieve load balancer information.

    Success indicates: ELB permissions are available.

    Severity: HIGH - Required for load balancer diagnostics
    """
    api_status = check_api_requests_available(cluster_data)

    if not api_status['available']:
        pytest.skip("API request log not available")

    elb_permissions = {
        'elasticloadbalancing:DescribeLoadBalancers': 'describe_load_balancers',
        'elasticloadbalancing:DescribeTargetGroups': 'describe_target_groups',
        'elasticloadbalancing:DescribeTargetHealth': 'describe_target_health',
        'elasticloadbalancing:DescribeListeners': 'describe_listeners'
    }

    permissions_status = {}
    all_errors = []

    for permission, operation in elb_permissions.items():
        # Check both elb and elbv2 services
        errors_elb = get_permission_errors(cluster_data, service='elb', operation=operation)
        errors_elbv2 = get_permission_errors(cluster_data, service='elbv2', operation=operation)
        errors = errors_elb + errors_elbv2

        permissions_status[permission] = len(errors) == 0
        all_errors.extend(errors)

    print(format_permission_checklist(permissions_status, "ELB Permissions"))

    if all_errors:
        missing_perms = [perm for perm, status in permissions_status.items() if not status]
        pytest.fail(f"Missing ELB permissions: {', '.join(missing_perms)}")


# ============================================================================
# Route53 Permissions
# ============================================================================

@pytest.mark.aws_resources
@pytest.mark.iam_permissions
@pytest.mark.severity("MEDIUM")
def test_route53_permissions(cluster_data: ClusterData):
    """Route53 permissions must be available

    Why: Required to retrieve DNS zone and record information.

    Failure indicates: Cannot retrieve DNS information.

    Success indicates: Route53 permissions are available.

    Severity: MEDIUM - Required for DNS diagnostics
    """
    api_status = check_api_requests_available(cluster_data)

    if not api_status['available']:
        pytest.skip("API request log not available")

    route53_permissions = {
        'route53:ListHostedZones': 'list_hosted_zones',
        'route53:ListResourceRecordSets': 'list_resource_record_sets',
        'route53:GetHostedZone': 'get_hosted_zone'
    }

    permissions_status = {}
    all_errors = []

    for permission, operation in route53_permissions.items():
        errors = get_permission_errors(cluster_data, service='route53', operation=operation)
        permissions_status[permission] = len(errors) == 0
        all_errors.extend(errors)

    print(format_permission_checklist(permissions_status, "Route53 Permissions"))

    if all_errors:
        missing_perms = [perm for perm, status in permissions_status.items() if not status]
        pytest.fail(f"Missing Route53 permissions: {', '.join(missing_perms)}")


# ============================================================================
# IAM Permissions
# ============================================================================

@pytest.mark.aws_resources
@pytest.mark.iam_permissions
@pytest.mark.severity("MEDIUM")
def test_iam_read_permissions(cluster_data: ClusterData):
    """IAM read permissions must be available

    Why: Required to retrieve IAM role and policy information.

    Failure indicates: Cannot retrieve IAM information.

    Success indicates: IAM read permissions are available.

    Severity: MEDIUM - Required for IAM diagnostics
    """
    api_status = check_api_requests_available(cluster_data)

    if not api_status['available']:
        pytest.skip("API request log not available")

    iam_permissions = {
        'iam:GetRole': 'get_role',
        'iam:ListRoles': 'list_roles',
        'iam:ListAttachedRolePolicies': 'list_attached_role_policies',
        'iam:GetInstanceProfile': 'get_instance_profile'
    }

    permissions_status = {}
    all_errors = []

    for permission, operation in iam_permissions.items():
        errors = get_permission_errors(cluster_data, service='iam', operation=operation)
        permissions_status[permission] = len(errors) == 0
        all_errors.extend(errors)

    print(format_permission_checklist(permissions_status, "IAM Read Permissions"))

    if all_errors:
        missing_perms = [perm for perm, status in permissions_status.items() if not status]
        pytest.fail(f"Missing IAM permissions: {', '.join(missing_perms)}")


# ============================================================================
# S3 Permissions
# ============================================================================

@pytest.mark.aws_resources
@pytest.mark.iam_permissions
@pytest.mark.severity("LOW")
def test_s3_permissions(cluster_data: ClusterData):
    """S3 permissions (if S3 operations were performed)

    Why: S3 may be used for image registry or backup storage.

    Severity: LOW - Optional depending on cluster configuration
    """
    api_status = check_api_requests_available(cluster_data)

    if not api_status['available']:
        pytest.skip("API request log not available")

    # Check if any S3 operations were attempted
    requests = cluster_data.api_requests.get('requests', [])
    s3_requests = [req for req in requests if req.get('service') == 's3']

    if not s3_requests:
        pytest.skip("No S3 operations found in API log")

    s3_permissions = {
        's3:ListBucket': 'list_bucket',
        's3:GetObject': 'get_object',
        's3:PutObject': 'put_object'
    }

    permissions_status = {}
    all_errors = []

    for permission, operation in s3_permissions.items():
        errors = get_permission_errors(cluster_data, service='s3', operation=operation)
        permissions_status[permission] = len(errors) == 0
        all_errors.extend(errors)

    print(format_permission_checklist(permissions_status, "S3 Permissions"))

    if all_errors:
        print(f"\n⚠ Some S3 permissions are missing (may be expected)")


# ============================================================================
# CloudTrail Permissions
# ============================================================================

@pytest.mark.aws_resources
@pytest.mark.iam_permissions
@pytest.mark.severity("LOW")
def test_cloudtrail_permissions(cluster_data: ClusterData):
    """CloudTrail permissions (if CloudTrail operations were performed)

    Why: CloudTrail provides audit logs for diagnostic analysis.

    Severity: LOW - Optional for diagnostics
    """
    api_status = check_api_requests_available(cluster_data)

    if not api_status['available']:
        pytest.skip("API request log not available")

    # Check if any CloudTrail operations were attempted
    requests = cluster_data.api_requests.get('requests', [])
    cloudtrail_requests = [req for req in requests if req.get('service') == 'cloudtrail']

    if not cloudtrail_requests:
        pytest.skip("No CloudTrail operations found in API log")

    cloudtrail_permissions = {
        'cloudtrail:LookupEvents': 'lookup_events',
        'cloudtrail:DescribeTrails': 'describe_trails'
    }

    permissions_status = {}
    all_errors = []

    for permission, operation in cloudtrail_permissions.items():
        errors = get_permission_errors(cluster_data, service='cloudtrail', operation=operation)
        permissions_status[permission] = len(errors) == 0
        all_errors.extend(errors)

    print(format_permission_checklist(permissions_status, "CloudTrail Permissions"))

    if all_errors:
        print(f"\n⚠ Some CloudTrail permissions are missing (may be expected)")


# ============================================================================
# Comprehensive Permission Summary
# ============================================================================

@pytest.mark.aws_resources
@pytest.mark.iam_permissions
@pytest.mark.severity("INFO")
def test_all_permissions_summary(cluster_data: ClusterData):
    """Display comprehensive summary of all permission checks

    Why: Provides complete overview of IAM permission status.

    Severity: INFO - Informational test only
    """
    api_status = check_api_requests_available(cluster_data)

    if not api_status['available']:
        pytest.skip("API request log not available")

    requests = cluster_data.api_requests.get('requests', [])

    # Categorize all permission errors by service
    all_errors = get_permission_errors(cluster_data)

    errors_by_service = {}
    for error in all_errors:
        service = error['service']
        if service not in errors_by_service:
            errors_by_service[service] = []
        errors_by_service[service].append(error)

    # Build comprehensive permission status
    print("\n" + "=" * 80)
    print("COMPREHENSIVE IAM PERMISSION SUMMARY")
    print("=" * 80)

    print(f"\n📊 API Request Statistics:")
    print(f"  Total requests: {len(requests)}")
    print(f"  Permission errors: {len(all_errors)}")
    print(f"  Services with errors: {len(errors_by_service)}")

    if errors_by_service:
        print(f"\n❌ Permission Errors by Service:")
        for service, errors in sorted(errors_by_service.items()):
            print(f"\n  {service.upper()} ({len(errors)} errors):")
            operations = {}
            for error in errors:
                op = error['operation']
                if op not in operations:
                    operations[op] = 0
                operations[op] += 1

            for operation, count in sorted(operations.items()):
                print(f"    ☐ {operation:40s} [{count} error(s)]")

        print("\n" + "=" * 80)
        print("RECOMMENDATION: Address permission errors above")
        print("=" * 80)

    else:
        print(f"\n✓ No permission errors detected")
        print(f"  All {len(requests)} API requests completed successfully")

        # Show which services were accessed successfully
        services_used = {}
        for req in requests:
            service = req.get('service', 'unknown')
            if service not in services_used:
                services_used[service] = set()
            services_used[service].add(req.get('operation', 'unknown'))

        print(f"\n✓ Successfully accessed services:")
        for service, operations in sorted(services_used.items()):
            print(f"  {service}: {len(operations)} operation(s)")

        print("\n" + "=" * 80)
