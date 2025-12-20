"""
IAM Data Diagnostics Helper

Provides comprehensive diagnostics for missing IAM data by analyzing:
1. API request logs
2. File existence and validity
3. AWS API responses
4. Resource availability
"""

import json
from pathlib import Path
from typing import Dict, Any, List, Optional
from models.cluster import ClusterData


def diagnose_missing_iam_data(
    cluster_data: ClusterData,
    resource_type: str,
    expected_file_pattern: str = None,
    api_service: str = "iam",
    api_operations: List[str] = None
) -> Dict[str, Any]:
    """
    Comprehensive diagnostics for missing IAM data.

    Args:
        cluster_data: ClusterData instance
        resource_type: Human-readable resource type (e.g., "installer role")
        expected_file_pattern: Glob pattern for expected files (e.g., "*_iam_role_installer_*.json")
        api_service: AWS service name (default: "iam")
        api_operations: List of API operations to check (e.g., ["get_role", "list_roles"])

    Returns:
        Dict with comprehensive diagnostic information:
        {
            'data_available': bool,
            'reason': str,  # High-level reason
            'diagnostic_message': str,  # Detailed formatted message
            'found_files': List[str],
            'api_request_status': Dict,
            'file_status': Dict,
            'remediation': str
        }
    """
    result = {
        'data_available': False,
        'reason': 'unknown',
        'diagnostic_message': '',
        'found_files': [],
        'api_request_status': {},
        'file_status': {},
        'remediation': ''
    }

    # Step 1: Check if files exist
    if expected_file_pattern:
        found_files = list(cluster_data.aws_dir.glob(expected_file_pattern))
        result['found_files'] = [str(f) for f in found_files]

        if found_files:
            # Files exist - check if they're valid
            file_status = _check_file_validity(found_files[0])
            result['file_status'] = file_status

            if file_status['valid']:
                result['data_available'] = True
                result['reason'] = 'data_found'
                return result
            else:
                # File exists but is invalid
                result['reason'] = file_status['reason']
                result['diagnostic_message'] = _format_file_error_message(
                    resource_type, found_files[0], file_status
                )
                result['remediation'] = _get_file_error_remediation(file_status)
                return result

    # Step 2: Check API request log
    api_status = _check_api_request_log(cluster_data, api_service, api_operations)
    result['api_request_status'] = api_status

    if api_status['log_available']:
        if api_status['operations_attempted']:
            if api_status['operations_failed']:
                # API calls were made but failed
                result['reason'] = 'api_call_failed'
                result['diagnostic_message'] = _format_api_failure_message(
                    resource_type, expected_file_pattern, api_status
                )
                result['remediation'] = _get_api_failure_remediation(api_status)
            else:
                # API calls succeeded but resource not found
                result['reason'] = 'resource_not_found_in_aws'
                result['diagnostic_message'] = _format_resource_not_found_message(
                    resource_type, expected_file_pattern, api_status
                )
                result['remediation'] = _get_resource_not_found_remediation(resource_type)
        else:
            # No API calls attempted
            result['reason'] = 'no_api_calls_attempted'
            result['diagnostic_message'] = _format_no_api_calls_message(
                resource_type, api_service, api_operations
            )
            result['remediation'] = _get_no_api_calls_remediation(api_service)
    else:
        # No API request log
        result['reason'] = 'no_api_request_log'
        result['diagnostic_message'] = _format_no_api_log_message(resource_type)
        result['remediation'] = _get_no_api_log_remediation()

    return result


def _check_file_validity(file_path: Path) -> Dict[str, Any]:
    """Check if file is valid JSON and not empty"""
    status = {
        'valid': False,
        'reason': 'unknown',
        'error': None
    }

    try:
        file_size = file_path.stat().st_size
        if file_size == 0:
            status['reason'] = 'file_empty'
            status['error'] = 'File exists but is empty (0 bytes)'
            return status

        with open(file_path) as f:
            data = json.load(f)

        if not data:
            status['reason'] = 'file_empty_json'
            status['error'] = 'File contains empty JSON object/array'
            return status

        status['valid'] = True
        status['reason'] = 'file_valid'
        return status

    except json.JSONDecodeError as e:
        status['reason'] = 'invalid_json'
        status['error'] = f'Invalid JSON: {str(e)}'
        return status

    except Exception as e:
        status['reason'] = 'file_read_error'
        status['error'] = f'Cannot read file: {str(e)}'
        return status


def _check_api_request_log(
    cluster_data: ClusterData,
    service: str,
    operations: List[str] = None
) -> Dict[str, Any]:
    """Check API request log for service operations"""
    status = {
        'log_available': False,
        'total_requests': 0,
        'service_requests': [],
        'operations_attempted': False,
        'operations_failed': False,
        'failed_operations': [],
        'successful_operations': []
    }

    if not cluster_data.api_requests:
        return status

    status['log_available'] = True
    requests = cluster_data.api_requests.get('requests', [])
    status['total_requests'] = len(requests)

    # Filter requests for this service
    service_requests = [req for req in requests if req.get('service') == service]
    status['service_requests'] = service_requests

    if not service_requests:
        return status

    status['operations_attempted'] = True

    # If specific operations provided, filter to those
    if operations:
        relevant_requests = [
            req for req in service_requests
            if req.get('operation') in operations
        ]
    else:
        relevant_requests = service_requests

    # Categorize by success/failure
    for req in relevant_requests:
        operation = req.get('operation', 'unknown')
        if req.get('success', True):
            status['successful_operations'].append({
                'operation': operation,
                'timestamp': req.get('timestamp'),
                'duration_ms': req.get('duration_ms')
            })
        else:
            status['operations_failed'] = True
            error = req.get('error', {})
            status['failed_operations'].append({
                'operation': operation,
                'error_code': error.get('code', 'Unknown'),
                'error_message': error.get('message', 'No error message'),
                'timestamp': req.get('timestamp'),
                'parameters': req.get('parameters', {})
            })

    return status


def _format_file_error_message(resource_type: str, file_path: Path, file_status: Dict) -> str:
    """Format diagnostic message for file errors"""
    msg = f"{resource_type} data file has issues.\n\n"
    msg += "📋 Diagnostic Information:\n"
    msg += f"  • File location: {file_path}\n"
    msg += f"  • File size: {file_path.stat().st_size} bytes\n"

    if file_status['reason'] == 'file_empty':
        msg += "  • Issue: File exists but is completely empty (0 bytes)\n"
        msg += "\n💡 Possible Causes:\n"
        msg += "  1. Data collection script failed while writing file\n"
        msg += "  2. Disk full or I/O error during write\n"
        msg += "  3. Script was interrupted before completing write\n"

    elif file_status['reason'] == 'file_empty_json':
        msg += "  • Issue: File contains empty JSON object or array\n"
        msg += "\n💡 Possible Causes:\n"
        msg += "  1. AWS API returned empty response\n"
        msg += "  2. Response parsing removed all data\n"
        msg += "  3. Filter conditions excluded all results\n"

    elif file_status['reason'] == 'invalid_json':
        msg += f"  • Issue: File contains invalid JSON\n"
        msg += f"  • Error: {file_status['error']}\n"
        msg += "\n💡 Possible Causes:\n"
        msg += "  1. File was corrupted during write\n"
        msg += "  2. File was manually edited incorrectly\n"
        msg += "  3. Script bug caused malformed JSON output\n"

    elif file_status['reason'] == 'file_read_error':
        msg += f"  • Issue: Cannot read file\n"
        msg += f"  • Error: {file_status['error']}\n"
        msg += "\n💡 Possible Causes:\n"
        msg += "  1. File permissions prevent reading\n"
        msg += "  2. File is locked by another process\n"
        msg += "  3. Filesystem error\n"

    return msg


def _format_api_failure_message(resource_type: str, file_pattern: str, api_status: Dict) -> str:
    """Format diagnostic message for API failures"""
    msg = f"{resource_type} data collection failed.\n\n"
    msg += "📋 Diagnostic Information:\n"
    msg += f"  • Total API requests: {api_status['total_requests']}\n"
    msg += f"  • Service requests: {len(api_status['service_requests'])}\n"
    msg += f"  • Failed operations: {len(api_status['failed_operations'])}\n"

    if file_pattern:
        msg += f"  • Expected file pattern: {file_pattern}\n"
        msg += "  • File was NOT created because API call(s) failed\n"

    msg += "\n❌ Failed API Operations:\n"
    for failed in api_status['failed_operations']:
        msg += f"\n  Operation: {failed['operation']}\n"
        msg += f"  Error Code: {failed['error_code']}\n"
        msg += f"  Error Message: {failed['error_message']}\n"
        msg += f"  Timestamp: {failed['timestamp']}\n"

        # Add parameter context if available
        if failed.get('parameters'):
            msg += f"  Parameters: {json.dumps(failed['parameters'], indent=4)}\n"

    msg += "\n💡 Possible Causes:\n"

    # Categorize by error code
    error_codes = [f['error_code'] for f in api_status['failed_operations']]

    if 'AccessDenied' in error_codes or 'UnauthorizedOperation' in error_codes or 'Forbidden' in error_codes:
        msg += "  1. IAM user/role lacks required permissions\n"
        msg += "  2. IAM policy does not include necessary actions\n"
        msg += "  3. Service Control Policy (SCP) blocking access\n"
        msg += "  4. Resource-based policy denying access\n"

    elif 'NoSuchEntity' in error_codes or 'NotFound' in error_codes:
        msg += "  1. Resource does not exist in AWS account\n"
        msg += "  2. Resource was deleted before data collection\n"
        msg += "  3. Wrong AWS account or region\n"

    elif 'InvalidParameterValue' in error_codes or 'ValidationException' in error_codes:
        msg += "  1. Invalid parameter passed to API\n"
        msg += "  2. Malformed resource identifier\n"
        msg += "  3. Script bug in parameter construction\n"

    elif 'Throttling' in error_codes or 'RequestLimitExceeded' in error_codes:
        msg += "  1. AWS API rate limit exceeded\n"
        msg += "  2. Too many requests in short time period\n"
        msg += "  3. Need to implement backoff/retry logic\n"

    else:
        msg += "  1. AWS service error\n"
        msg += "  2. Network connectivity issue\n"
        msg += "  3. Temporary AWS service disruption\n"

    return msg


def _format_resource_not_found_message(resource_type: str, file_pattern: str, api_status: Dict) -> str:
    """Format diagnostic message when API succeeds but resource not found"""
    msg = f"{resource_type} not found in AWS account.\n\n"
    msg += "📋 Diagnostic Information:\n"
    msg += f"  • API requests completed: {len(api_status['successful_operations'])}\n"
    msg += "  • All API calls succeeded without errors\n"

    if file_pattern:
        msg += f"  • Expected file pattern: {file_pattern}\n"
        msg += "  • File was NOT created because resource does not exist in AWS\n"

    msg += "\n✓ Successful API Operations:\n"
    for success in api_status['successful_operations']:
        msg += f"  • {success['operation']} completed in {success.get('duration_ms', 'N/A')}ms\n"

    msg += "\n💡 Analysis:\n"
    msg += "  • AWS API calls succeeded (no permission errors)\n"
    msg += "  • AWS returned successful response (no service errors)\n"
    msg += f"  • However, {resource_type} was not included in the response\n"
    msg += "\n💡 Possible Causes:\n"
    msg += f"  1. {resource_type} was never created\n"
    msg += f"  2. {resource_type} was deleted after cluster creation\n"
    msg += "  3. Resource exists but has different name/tags than expected\n"
    msg += "  4. Resource is in different AWS region\n"
    msg += "  5. Resource belongs to different AWS account\n"

    return msg


def _format_no_api_calls_message(resource_type: str, service: str, operations: List[str]) -> str:
    """Format diagnostic message when no API calls were attempted"""
    msg = f"{resource_type} data was not collected.\n\n"
    msg += "📋 Diagnostic Information:\n"
    msg += f"  • API request log is available\n"
    msg += f"  • However, no {service} API calls were found in the log\n"

    if operations:
        msg += f"  • Expected operations: {', '.join(operations)}\n"

    msg += "\n💡 Possible Causes:\n"
    msg += f"  1. Data collection script does not retrieve {service} resources\n"
    msg += "  2. IAM resource collection was disabled/skipped\n"
    msg += "  3. Script version is outdated and missing this collection step\n"
    msg += "  4. Collection script failed before reaching this step\n"
    msg += "  5. Script was run with flags that skip IAM collection\n"

    return msg


def _format_no_api_log_message(resource_type: str) -> str:
    """Format diagnostic message when API request log is not available"""
    msg = f"{resource_type} data cannot be validated.\n\n"
    msg += "📋 Diagnostic Information:\n"
    msg += "  • API request log file does not exist\n"
    msg += "  • Cannot determine if data collection was attempted\n"
    msg += "  • Cannot diagnose why data is missing\n"
    msg += "\n💡 Possible Causes:\n"
    msg += "  1. Data was collected with old version of collection script\n"
    msg += "  2. API request logging was not enabled\n"
    msg += "  3. API request log file was deleted or moved\n"
    msg += "  4. Data was collected manually without using collection script\n"

    return msg


def _get_file_error_remediation(file_status: Dict) -> str:
    """Get remediation steps for file errors"""
    if file_status['reason'] in ['file_empty', 'invalid_json', 'file_read_error']:
        return (
            "🔧 Remediation:\n"
            "  1. Delete the corrupted/empty file\n"
            "  2. Re-run data collection: ./get_install_artifacts.sh -c <cluster-id>\n"
            "  3. Or: python get_install_artifacts.py -c <cluster-id>\n"
            "  4. Ensure disk has sufficient space\n"
            "  5. Check filesystem permissions\n"
        )
    elif file_status['reason'] == 'file_empty_json':
        return (
            "🔧 Remediation:\n"
            "  1. Verify resource exists in AWS console\n"
            "  2. Check if resource has expected tags/filters\n"
            "  3. Re-run collection with verbose logging\n"
            "  4. Review collection script filters/conditions\n"
        )
    return ""


def _get_api_failure_remediation(api_status: Dict) -> str:
    """Get remediation steps for API failures"""
    error_codes = [f['error_code'] for f in api_status['failed_operations']]

    if 'AccessDenied' in error_codes or 'UnauthorizedOperation' in error_codes:
        return (
            "🔧 Remediation:\n"
            "  1. Review IAM policy attached to data collection user/role\n"
            "  2. Add required IAM permissions (see error messages above)\n"
            "  3. Verify no Service Control Policies (SCPs) blocking access\n"
            "  4. Test permissions: aws iam simulate-principal-policy\n"
            "  5. Re-run data collection after adding permissions\n"
        )
    elif 'Throttling' in error_codes or 'RequestLimitExceeded' in error_codes:
        return (
            "🔧 Remediation:\n"
            "  1. Wait a few minutes and retry\n"
            "  2. Implement exponential backoff in collection script\n"
            "  3. Request AWS API rate limit increase if needed\n"
            "  4. Spread collection over longer time period\n"
        )
    else:
        return (
            "🔧 Remediation:\n"
            "  1. Check AWS service health dashboard\n"
            "  2. Verify network connectivity to AWS\n"
            "  3. Review error messages above for specific guidance\n"
            "  4. Retry data collection\n"
            "  5. Contact AWS support if issue persists\n"
        )


def _get_resource_not_found_remediation(resource_type: str) -> str:
    """Get remediation steps when resource not found in AWS"""
    return (
        "🔧 Remediation:\n"
        f"  1. Check AWS IAM console for {resource_type}\n"
        f"  2. Verify resource name matches expected pattern\n"
        "  3. Check resource tags if collection uses tag filtering\n"
        "  4. Verify correct AWS region is being queried\n"
        "  5. Confirm correct AWS account\n"
        f"  6. Create {resource_type} if missing:\n"
        "     rosa create account-roles (for ROSA clusters)\n"
        "     rosa create operator-roles --cluster <name>\n"
    )


def _get_no_api_calls_remediation(service: str) -> str:
    """Get remediation steps when no API calls attempted"""
    return (
        "🔧 Remediation:\n"
        "  1. Verify data collection script version is up to date\n"
        f"  2. Ensure {service} resource collection is enabled\n"
        "  3. Check for script errors/warnings during collection\n"
        "  4. Run collection with verbose logging:\n"
        "     ./get_install_artifacts.sh -c <cluster-id> --verbose\n"
        "  5. Review script documentation for IAM collection options\n"
    )


def _get_no_api_log_remediation() -> str:
    """Get remediation steps when API log missing"""
    return (
        "🔧 Remediation:\n"
        "  1. Use updated collection script with API logging\n"
        "  2. Re-run: python get_install_artifacts.py -c <cluster-id>\n"
        "  3. Verify API request log file is created:\n"
        "     <cluster-id>/<cluster-id>_api_requests.json\n"
        "  4. Update to latest version of collection script\n"
    )
