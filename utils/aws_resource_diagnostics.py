"""
AWS Resource Diagnostics Helper

Generic diagnostics for missing AWS resource data (EC2, VPC, ELB, Route53, etc.)
Analyzes API request logs, file existence, and provides comprehensive error messages.
"""

import json
from pathlib import Path
from typing import Dict, Any, List, Optional
from models.cluster import ClusterData


def diagnose_missing_aws_resource(
    cluster_data: ClusterData,
    resource_type: str,
    expected_file: str,
    api_service: str,
    api_operation: str,
    resource_identifier: Optional[str] = None
) -> str:
    """
    Comprehensive diagnostics for missing AWS resource data.

    Args:
        cluster_data: ClusterData instance
        resource_type: Human-readable resource type (e.g., "VPC", "EC2 instances", "Load Balancers")
        expected_file: Expected file name (e.g., "cluster123_vpcs.json")
        api_service: AWS service name (e.g., "ec2", "elbv2", "route53")
        api_operation: AWS API operation (e.g., "describe_vpcs", "describe_instances")
        resource_identifier: Specific resource ID/name if known (e.g., "vpc-123abc")

    Returns:
        Formatted diagnostic message string explaining why data is missing
    """
    msg = ""

    # Step 1: Check if file exists
    file_path = cluster_data.aws_dir / expected_file
    file_exists = file_path.exists()

    if file_exists:
        # Check if file is valid
        file_status = _check_file_status(file_path)

        if file_status['has_error']:
            msg += _format_file_error(resource_type, expected_file, file_status)
            return msg
        else:
            # File exists and is valid but empty response
            msg += _format_empty_response(resource_type, expected_file, file_status)
            return msg

    # Step 2: File doesn't exist - check API request log
    if not cluster_data.api_requests:
        msg += _format_no_api_log(resource_type, expected_file)
        return msg

    # Step 3: Check if API call was attempted
    api_status = _check_api_call_status(
        cluster_data,
        api_service,
        api_operation
    )

    if not api_status['called']:
        msg += _format_api_not_called(resource_type, expected_file, api_service, api_operation)
        return msg

    # Step 4: API was called - check if it succeeded or failed
    if api_status['failed']:
        msg += _format_api_failed(resource_type, expected_file, api_status, resource_identifier)
        return msg

    # Step 5: API succeeded but file not created
    msg += _format_api_succeeded_no_file(resource_type, expected_file, api_status, resource_identifier)
    return msg


def _check_file_status(file_path: Path) -> Dict[str, Any]:
    """Check file validity"""
    status = {
        'has_error': False,
        'error_type': None,
        'error_message': None,
        'file_size': 0,
        'is_empty_json': False
    }

    try:
        file_size = file_path.stat().st_size
        status['file_size'] = file_size

        if file_size == 0:
            status['has_error'] = True
            status['error_type'] = 'empty_file'
            status['error_message'] = 'File is 0 bytes'
            return status

        with open(file_path) as f:
            data = json.load(f)

        # Check if JSON is empty
        if not data or (isinstance(data, dict) and not any(data.values())):
            status['is_empty_json'] = True

    except json.JSONDecodeError as e:
        status['has_error'] = True
        status['error_type'] = 'invalid_json'
        status['error_message'] = str(e)
    except Exception as e:
        status['has_error'] = True
        status['error_type'] = 'read_error'
        status['error_message'] = str(e)

    return status


def _check_api_call_status(
    cluster_data: ClusterData,
    service: str,
    operation: str
) -> Dict[str, Any]:
    """Check if API call was made and its status"""
    status = {
        'called': False,
        'failed': False,
        'success_count': 0,
        'failure_count': 0,
        'errors': [],
        'successful_calls': []
    }

    requests = cluster_data.api_requests.get('requests', [])

    # Find requests matching this service and operation
    matching_requests = [
        req for req in requests
        if req.get('service') == service and req.get('operation') == operation
    ]

    if not matching_requests:
        return status

    status['called'] = True

    for req in matching_requests:
        if req.get('success', True):
            status['success_count'] += 1
            status['successful_calls'].append({
                'timestamp': req.get('timestamp'),
                'duration_ms': req.get('duration_ms'),
                'parameters': req.get('parameters', {})
            })
        else:
            status['failed'] = True
            status['failure_count'] += 1
            error = req.get('error', {})
            status['errors'].append({
                'error_code': error.get('code', 'Unknown'),
                'error_message': error.get('message', 'No message'),
                'timestamp': req.get('timestamp'),
                'parameters': req.get('parameters', {})
            })

    return status


def _format_file_error(resource_type: str, expected_file: str, file_status: Dict) -> str:
    """Format message for file errors"""
    msg = f"📋 Diagnostic Information:\n"
    msg += f"  • Expected file: {expected_file}\n"
    msg += f"  • File status: EXISTS but has errors\n"
    msg += f"  • File size: {file_status['file_size']} bytes\n"

    if file_status['error_type'] == 'empty_file':
        msg += "  • Issue: File is completely empty (0 bytes)\n"
        msg += "\n💡 Possible Causes:\n"
        msg += "  1. Data collection script failed while writing file\n"
        msg += "  2. Disk full or I/O error during write\n"
        msg += "  3. Script interrupted before completing write\n"
        msg += "  4. File system error\n"
        msg += "\n🔧 Remediation:\n"
        msg += f"  1. Delete the empty file: rm {expected_file}\n"
        msg += "  2. Re-run data collection: ./get_install_artifacts.sh -c <cluster-id>\n"
        msg += "  3. Check disk space: df -h\n"
        msg += "  4. Check file system permissions\n"

    elif file_status['error_type'] == 'invalid_json':
        msg += f"  • Issue: File contains invalid JSON\n"
        msg += f"  • Parse error: {file_status['error_message']}\n"
        msg += "\n💡 Possible Causes:\n"
        msg += "  1. File corrupted during write\n"
        msg += "  2. File manually edited incorrectly\n"
        msg += "  3. Script bug caused malformed output\n"
        msg += "  4. Incomplete write before script termination\n"
        msg += "\n🔧 Remediation:\n"
        msg += f"  1. Delete corrupted file: rm {expected_file}\n"
        msg += "  2. Re-run data collection\n"
        msg += "  3. Review collection script logs for errors\n"

    elif file_status['error_type'] == 'read_error':
        msg += f"  • Issue: Cannot read file\n"
        msg += f"  • Error: {file_status['error_message']}\n"
        msg += "\n💡 Possible Causes:\n"
        msg += "  1. File permissions prevent reading\n"
        msg += "  2. File locked by another process\n"
        msg += "  3. File system error\n"
        msg += "\n🔧 Remediation:\n"
        msg += f"  1. Check file permissions: ls -l {expected_file}\n"
        msg += f"  2. Fix permissions: chmod 644 {expected_file}\n"
        msg += "  3. Check if file is in use: lsof {expected_file}\n"

    return msg


def _format_empty_response(resource_type: str, expected_file: str, file_status: Dict) -> str:
    """Format message when file exists but contains empty/no data"""
    msg = f"📋 Diagnostic Information:\n"
    msg += f"  • Expected file: {expected_file}\n"
    msg += f"  • File status: EXISTS and is valid JSON\n"
    msg += f"  • File size: {file_status['file_size']} bytes\n"
    msg += f"  • Issue: File contains empty response or no {resource_type}\n"
    msg += "\n💡 Analysis:\n"
    msg += "  • AWS API call succeeded (file was created)\n"
    msg += f"  • However, AWS returned no {resource_type} data\n"
    msg += "\n💡 Possible Causes:\n"
    msg += f"  1. {resource_type} does not exist in AWS account\n"
    msg += f"  2. {resource_type} was deleted before data collection\n"
    msg += f"  3. {resource_type} exists but with different filters/tags\n"
    msg += "  4. Wrong AWS region queried\n"
    msg += "  5. Wrong AWS account\n"
    msg += "\n🔧 Remediation:\n"
    msg += f"  1. Verify {resource_type} exists in AWS console\n"
    msg += "  2. Check AWS region matches cluster region\n"
    msg += "  3. Verify AWS account ID\n"
    msg += "  4. Review collection script filters\n"

    return msg


def _format_no_api_log(resource_type: str, expected_file: str) -> str:
    """Format message when API request log doesn't exist"""
    msg = f"📋 Diagnostic Information:\n"
    msg += f"  • Expected file: {expected_file}\n"
    msg += "  • File status: DOES NOT EXIST\n"
    msg += "  • API request log: NOT AVAILABLE\n"
    msg += "\n💡 Analysis:\n"
    msg += "  • Cannot determine if data collection was attempted\n"
    msg += "  • Cannot diagnose why data is missing\n"
    msg += "\n💡 Possible Causes:\n"
    msg += "  1. Data collected with old version of script (no API logging)\n"
    msg += "  2. API request logging disabled\n"
    msg += "  3. API request log file deleted or moved\n"
    msg += "  4. Data collected manually without script\n"
    msg += "\n🔧 Remediation:\n"
    msg += "  1. Use updated collection script with API logging\n"
    msg += "  2. Re-run: python get_install_artifacts.py -c <cluster-id>\n"
    msg += "  3. Verify API request log is created: <cluster-id>_api_requests.json\n"

    return msg


def _format_api_not_called(resource_type: str, expected_file: str, service: str, operation: str) -> str:
    """Format message when API call was not attempted"""
    msg = f"📋 Diagnostic Information:\n"
    msg += f"  • Expected file: {expected_file}\n"
    msg += "  • File status: DOES NOT EXIST\n"
    msg += "  • API request log: Available\n"
    msg += f"  • API call: {service}.{operation}\n"
    msg += f"  • Call status: NOT ATTEMPTED\n"
    msg += "\n💡 Analysis:\n"
    msg += f"  • Data collection script did NOT attempt to collect {resource_type}\n"
    msg += f"  • No {service}.{operation} calls found in API log\n"
    msg += "\n💡 Possible Causes:\n"
    msg += f"  1. Data collection script does not include {resource_type} collection\n"
    msg += "  2. Resource collection was skipped or disabled\n"
    msg += "  3. Script version outdated - missing this collection step\n"
    msg += "  4. Script failed before reaching this step\n"
    msg += f"  5. Script run with flags that skip {service} collection\n"
    msg += "\n🔧 Remediation:\n"
    msg += "  1. Verify collection script version is up to date\n"
    msg += f"  2. Ensure {resource_type} collection is enabled\n"
    msg += "  3. Check for script errors during collection\n"
    msg += "  4. Run with verbose logging: ./get_install_artifacts.sh -c <cluster-id> --verbose\n"
    msg += f"  5. Update script to include {service}.{operation}\n"

    return msg


def _format_api_failed(resource_type: str, expected_file: str, api_status: Dict, resource_id: str = None) -> str:
    """Format message when API call failed"""
    msg = f"📋 Diagnostic Information:\n"
    msg += f"  • Expected file: {expected_file}\n"
    msg += "  • File status: DOES NOT EXIST (API call failed)\n"
    msg += f"  • API calls attempted: {api_status['success_count'] + api_status['failure_count']}\n"
    msg += f"  • Successful: {api_status['success_count']}\n"
    msg += f"  • Failed: {api_status['failure_count']}\n"

    if resource_id:
        msg += f"  • Resource identifier: {resource_id}\n"

    msg += "\n❌ API Call Failures:\n"
    for error in api_status['errors']:
        msg += f"\n  Error Code: {error['error_code']}\n"
        msg += f"  Error Message: {error['error_message']}\n"
        msg += f"  Timestamp: {error['timestamp']}\n"
        if error.get('parameters'):
            msg += f"  Parameters: {json.dumps(error['parameters'], indent=4)}\n"

    # Categorize error
    error_codes = [e['error_code'] for e in api_status['errors']]

    msg += "\n💡 Root Cause:\n"

    if any(code in error_codes for code in ['AccessDenied', 'UnauthorizedOperation', 'Forbidden', 'AccessDeniedException']):
        msg += "  AWS API call DENIED due to insufficient permissions\n"
        msg += "\n💡 Specific Issue:\n"
        msg += "  IAM user/role lacks required permissions\n"
        msg += "\n🔧 Remediation:\n"
        msg += "  1. Review IAM policy attached to data collection user/role\n"
        msg += "  2. Add required permissions (see error message above)\n"
        msg += "  3. Example permissions needed:\n"

        # Suggest specific permissions based on error
        for error in api_status['errors']:
            operation = error['parameters'].get('operation', 'unknown')
            msg += f"      - Allow {operation} action\n"

        msg += "  4. Verify no Service Control Policies (SCPs) blocking access\n"
        msg += "  5. Re-run data collection after adding permissions\n"

    elif any(code in error_codes for code in ['Throttling', 'RequestLimitExceeded', 'TooManyRequestsException']):
        msg += "  AWS API rate limit EXCEEDED\n"
        msg += "\n🔧 Remediation:\n"
        msg += "  1. Wait a few minutes before retrying\n"
        msg += "  2. Implement exponential backoff in collection script\n"
        msg += "  3. Reduce request frequency\n"
        msg += "  4. Request AWS API rate limit increase if persistent\n"

    elif any(code in error_codes for code in ['InvalidParameterValue', 'ValidationException', 'InvalidInput']):
        msg += "  AWS API call REJECTED due to invalid parameters\n"
        msg += "\n💡 Specific Issue:\n"
        msg += "  Malformed request parameters or resource identifiers\n"
        msg += "\n🔧 Remediation:\n"
        msg += "  1. Review parameter values in error message above\n"
        msg += "  2. Verify resource identifiers are correct\n"
        msg += "  3. Check for script bugs in parameter construction\n"
        msg += "  4. Update collection script if parameters are incorrect\n"

    else:
        msg += "  AWS service error or connectivity issue\n"
        msg += "\n🔧 Remediation:\n"
        msg += "  1. Check AWS service health dashboard\n"
        msg += "  2. Verify network connectivity to AWS\n"
        msg += "  3. Review error messages above\n"
        msg += "  4. Retry data collection\n"
        msg += "  5. Contact AWS support if persists\n"

    return msg


def _format_api_succeeded_no_file(resource_type: str, expected_file: str, api_status: Dict, resource_id: str = None) -> str:
    """Format message when API succeeded but file wasn't created"""
    msg = f"📋 Diagnostic Information:\n"
    msg += f"  • Expected file: {expected_file}\n"
    msg += "  • File status: DOES NOT EXIST\n"
    msg += f"  • API calls made: {api_status['success_count']}\n"
    msg += f"  • All API calls: SUCCEEDED\n"

    if resource_id:
        msg += f"  • Resource identifier: {resource_id}\n"

    msg += "\n✓ Successful API Calls:\n"
    for call in api_status['successful_calls']:
        msg += f"  • Completed in {call.get('duration_ms', 'N/A')}ms at {call['timestamp']}\n"

    msg += "\n💡 Analysis:\n"
    msg += "  • AWS API calls completed successfully (no errors)\n"
    msg += f"  • However, file was not created for {resource_type}\n"
    msg += "\n💡 Possible Causes:\n"
    msg += f"  1. AWS returned empty response - {resource_type} does not exist\n"
    msg += f"  2. {resource_type} was deleted between API call and file write\n"
    msg += "  3. File write failed after successful API call\n"
    msg += "  4. Script bug in file creation logic\n"
    msg += "  5. Response filtering excluded all results\n"

    if resource_id:
        msg += f"  6. Resource {resource_id} not found in AWS account\n"

    msg += "\n🔧 Remediation:\n"
    msg += f"  1. Verify {resource_type} exists in AWS console\n"
    if resource_id:
        msg += f"  2. Search for resource ID: {resource_id}\n"
    msg += "  3. Check AWS region matches cluster region\n"
    msg += "  4. Review collection script logs for file write errors\n"
    msg += "  5. Check disk space: df -h\n"
    msg += "  6. Re-run data collection with verbose logging\n"

    return msg
