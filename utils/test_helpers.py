"""
Test Helper Functions

Provides utility functions for tests to correlate missing resources with
CloudTrail events and format diagnostic messages.
"""

from typing import Dict, Any, List, Optional
from models.cluster import ClusterData
from utils.cloudtrail_correlator import create_correlator_from_cluster_data


def check_missing_resource_with_cloudtrail(
    cluster_data: ClusterData,
    resource_identifier: str,
    resource_type: str = "resource",
    expected_file: str = ""
) -> Dict[str, Any]:
    """
    Check if a missing resource has related CloudTrail events.

    This function should be called when a test expects a resource to exist
    but cannot find it. It will search CloudTrail for events that might
    explain why the resource is missing.

    Args:
        cluster_data: ClusterData instance
        resource_identifier: Resource ID, name, or ARN (e.g., "vpc-123abc")
        resource_type: Human-readable type (e.g., "VPC", "Load Balancer")
        expected_file: Expected file where resource should have been found

    Returns:
        Dictionary with:
        {
            'missing': bool,  # Always True (resource is missing)
            'cloudtrail_explanation': str,  # Explanation from CloudTrail
            'cloudtrail_events': List[Dict],  # Related events
            'has_cloudtrail_events': bool,  # Whether any events were found
            'expected_file': str,  # File where resource was expected
            'diagnostic_message': str  # Formatted message for test output
        }
    """
    # Create CloudTrail correlator
    correlator = create_correlator_from_cluster_data(cluster_data)

    if not correlator:
        # No CloudTrail data available
        return {
            'missing': True,
            'cloudtrail_explanation': (
                f"No CloudTrail data available to diagnose missing {resource_type}. "
                f"CloudTrail events may not have been collected."
            ),
            'cloudtrail_events': [],
            'has_cloudtrail_events': False,
            'expected_file': expected_file,
            'diagnostic_message': (
                f"{resource_type} '{resource_identifier}' not found.\n"
                f"Expected in: {expected_file}\n"
                f"No CloudTrail data available for diagnosis."
            )
        }

    # Search for related events
    result = correlator.explain_missing_resource(resource_identifier, resource_type)

    # Build diagnostic message
    diagnostic_parts = [
        f"{resource_type} '{resource_identifier}' not found."
    ]

    if expected_file:
        diagnostic_parts.append(f"Expected in: {expected_file}")

    diagnostic_parts.append(f"\nCloudTrail Analysis: {result['explanation']}")

    if result['event_summaries']:
        diagnostic_parts.append("\nRelated CloudTrail Events:")
        for event_summary in result['event_summaries'][:3]:  # Show top 3
            diagnostic_parts.append(
                f"  - [{event_summary['category']}] {event_summary['summary']}"
            )
        if len(result['event_summaries']) > 3:
            diagnostic_parts.append(
                f"  ... and {len(result['event_summaries']) - 3} more event(s)"
            )

    return {
        'missing': True,
        'cloudtrail_explanation': result['explanation'],
        'cloudtrail_events': result['event_summaries'],
        'has_cloudtrail_events': result['found_events'],
        'expected_file': expected_file,
        'diagnostic_message': "\n".join(diagnostic_parts)
    }


def format_cloudtrail_events_for_test(
    events: List[Dict[str, Any]],
    max_events: int = 5
) -> str:
    """
    Format CloudTrail events for test output.

    Args:
        events: List of event summary dictionaries
        max_events: Maximum number of events to display

    Returns:
        Formatted string for test output
    """
    if not events:
        return "No related CloudTrail events found."

    lines = [f"Found {len(events)} related CloudTrail event(s):"]

    for i, event in enumerate(events[:max_events]):
        lines.append(
            f"\n  {i+1}. [{event.get('category', 'Unknown')}] "
            f"{event.get('event_name', 'Unknown')} at {event.get('event_time', 'Unknown')}"
        )
        lines.append(f"     Summary: {event.get('summary', 'No summary')}")
        if event.get('file'):
            lines.append(f"     Location: {event['file']} (event #{event.get('index', 0)})")

    if len(events) > max_events:
        lines.append(f"\n  ... and {len(events) - max_events} more event(s)")

    return "\n".join(lines)


def add_cloudtrail_context_to_test_result(
    test_result: Dict[str, Any],
    cluster_data: ClusterData,
    resource_identifier: str,
    resource_type: str = "resource"
) -> Dict[str, Any]:
    """
    Add CloudTrail context to a test result dictionary.

    This is used by the test framework to add CloudTrail event data to
    test results for display in HTML reports.

    Args:
        test_result: Existing test result dictionary
        cluster_data: ClusterData instance
        resource_identifier: Resource being checked
        resource_type: Type of resource

    Returns:
        Updated test result dictionary with cloudtrail_context field
    """
    correlator = create_correlator_from_cluster_data(cluster_data)

    if not correlator:
        test_result['cloudtrail_context'] = {
            'available': False,
            'message': 'CloudTrail data not available'
        }
        return test_result

    # Find related events
    result = correlator.explain_missing_resource(resource_identifier, resource_type)

    test_result['cloudtrail_context'] = {
        'available': True,
        'found_events': result['found_events'],
        'explanation': result['explanation'],
        'events': result['event_summaries'],
        'resource_identifier': resource_identifier,
        'resource_type': resource_type
    }

    return test_result


def check_resource_in_api_requests(
    cluster_data: ClusterData,
    operation: str,
    service: str = "ec2"
) -> Optional[Dict[str, Any]]:
    """
    Check if an AWS API operation succeeded or failed.

    Args:
        cluster_data: ClusterData instance
        operation: Operation name (e.g., "describe_instances")
        service: Service name (e.g., "ec2", "elbv2")

    Returns:
        Dictionary with request details if found, None otherwise:
        {
            'success': bool,
            'error': Dict or None,
            'duration_ms': int,
            'timestamp': str
        }
    """
    if not cluster_data.api_requests:
        return None

    requests = cluster_data.api_requests.get('requests', [])

    # Find matching request
    for req in requests:
        if req.get('service') == service and req.get('operation') == operation:
            return {
                'success': req.get('success', False),
                'error': req.get('error'),
                'duration_ms': req.get('duration_ms', 0),
                'timestamp': req.get('timestamp', ''),
                'output_file': req.get('output_file')
            }

    return None


def explain_missing_data(
    cluster_data: ClusterData,
    resource_type: str,
    expected_file: str,
    api_operation: Optional[str] = None,
    api_service: str = "ec2",
    resource_identifier: Optional[str] = None
) -> str:
    """
    Generate comprehensive explanation for missing data.

    This combines API request tracking and CloudTrail analysis to explain
    why expected data is not present.

    Args:
        cluster_data: ClusterData instance
        resource_type: Type of resource (e.g., "VPC", "Security Group")
        expected_file: File where data was expected
        api_operation: Optional API operation that fetches this data
        api_service: Service for the API operation
        resource_identifier: Optional specific resource ID/name

    Returns:
        Formatted explanation string
    """
    explanations = []

    # Check API request log
    if api_operation:
        req_info = check_resource_in_api_requests(cluster_data, api_operation, api_service)
        if req_info:
            if not req_info['success']:
                error = req_info.get('error', {})
                explanations.append(
                    f"Data collection failed: {api_service}.{api_operation} "
                    f"returned error: {error.get('code', 'Unknown')} - "
                    f"{error.get('message', 'No message')}"
                )
            else:
                explanations.append(
                    f"Data collection succeeded ({api_service}.{api_operation} completed in "
                    f"{req_info['duration_ms']}ms) but {resource_type} not found in results."
                )
        else:
            explanations.append(
                f"No API request log found for {api_service}.{api_operation}. "
                f"Data collection may not have attempted to fetch this resource."
            )

    # Check CloudTrail if specific resource identified
    if resource_identifier:
        correlator = create_correlator_from_cluster_data(cluster_data)
        if correlator:
            ct_result = correlator.explain_missing_resource(resource_identifier, resource_type)
            explanations.append(f"CloudTrail: {ct_result['explanation']}")
        else:
            explanations.append("CloudTrail data not available for additional diagnosis.")

    # Build final explanation
    if not explanations:
        explanations.append(
            f"{resource_type} data not found in {expected_file}. "
            f"No additional diagnostic information available."
        )

    return "\n".join(explanations)


def correlate_cloudtrail_events_for_resources(
    cluster_data: ClusterData,
    resource_identifiers: List[str],
    resource_type: str,
    event_types: Optional[List[str]] = None,
    pytest_request: Any = None
) -> Dict[str, Any]:
    """
    Find and attach CloudTrail events for specific resources to test results.

    This is the PRIMARY function tests should use to correlate CloudTrail events
    with missing, deleted, terminated, or revoked AWS resources.

    Args:
        cluster_data: ClusterData instance
        resource_identifiers: List of resource IDs/names/ARNs to find events for
        resource_type: Human-readable resource type (e.g., "Security Group", "EC2 Instance")
        event_types: Optional list of event patterns to filter (e.g., ["Delete", "Terminate", "Revoke"])
        pytest_request: pytest request fixture (for attaching events to user_properties)

    Returns:
        Dictionary with 'events' (list of event dicts) and 'formatted_message' (str)

    Example:
        # In a test that finds deleted security groups:
        result = correlate_cloudtrail_events_for_resources(
            cluster_data=cluster_data,
            resource_identifiers=["sg-abc123", "sg-def456"],
            resource_type="Security Group",
            event_types=["Revoke", "Delete"],
            pytest_request=request
        )

        # Include in failure message:
        pytest.fail(f"Found deleted security groups:\\n{result['formatted_message']}")
    """
    from utils.cloudtrail_correlator import create_correlator_from_cluster_data

    correlator = create_correlator_from_cluster_data(cluster_data)

    if not correlator:
        return {
            'events': [],
            'formatted_message': 'CloudTrail data not available for correlation',
            'found_events': False
        }

    all_events = []
    event_summaries = []

    # Find events for each resource
    for resource_id in resource_identifiers:
        events = correlator.find_events_for_resource(
            resource_identifier=resource_id,
            event_types=event_types,
            limit=5
        )

        for event in events:
            # Extract ARN from userIdentity
            user_arn = ''
            if event.cloud_trail_event:
                user_identity = event.cloud_trail_event.get('userIdentity', {})
                user_arn = user_identity.get('arn', '') or user_identity.get('principalId', '')

            # Determine status code
            status_code = 'Success'
            if event.error_code:
                status_code = f'Error: {event.error_code}'
            elif event.cloud_trail_event:
                # Some successful events may have explicit response codes
                error_code = event.cloud_trail_event.get('errorCode')
                if error_code:
                    status_code = f'Error: {error_code}'

            # Create event summary for HTML display
            event_summary = {
                'category': event.get_event_category(),
                'event_name': event.event_name,
                'event_time': event.event_time,
                'username': event.username,
                'user_arn': user_arn,
                'status_code': status_code,
                'requested_action': event.event_name,
                'resource_id': resource_id,
                'summary': _format_event_summary(event, resource_id, resource_type),
                'file': event.source_file,
                'index': event.event_index,
                'full_event': event.cloud_trail_event if event.cloud_trail_event else event.raw_event
            }
            event_summaries.append(event_summary)
            all_events.append(event)

    # Format message for test failure output
    if not all_events:
        formatted_message = f"No CloudTrail events found for {len(resource_identifiers)} {resource_type}(s)"
    else:
        lines = [f"CloudTrail Analysis - Found {len(all_events)} event(s):"]
        for i, summary in enumerate(event_summaries[:10], 1):  # Show first 10
            lines.append(
                f"\n{i}. [{summary['category']}] {summary['event_name']}"
            )
            lines.append(f"   Time: {summary['event_time']}")
            lines.append(f"   User: {summary['username']}")
            lines.append(f"   Resource: {summary['resource_id']}")
            lines.append(f"   Details: {summary['summary']}")

        if len(all_events) > 10:
            lines.append(f"\n... and {len(all_events) - 10} more event(s)")

        formatted_message = "\n".join(lines)

    # Attach to pytest user_properties for HTML display
    if pytest_request and event_summaries:
        pytest_request.node.user_properties.append(("cloudtrail_events", event_summaries))

    return {
        'events': all_events,
        'event_summaries': event_summaries,
        'formatted_message': formatted_message,
        'found_events': len(all_events) > 0
    }


def _format_event_summary(event: Any, resource_id: str, resource_type: str) -> str:
    """
    Format a CloudTrail event into a human-readable summary.

    Args:
        event: CloudTrailEvent instance
        resource_id: Resource identifier
        resource_type: Resource type name

    Returns:
        Formatted summary string
    """
    category = event.get_event_category()

    if category == "Deletion":
        return f"{resource_type} {resource_id} was deleted"
    elif category == "Revocation":
        # Try to extract what was revoked
        if hasattr(event, 'request_parameters') and event.request_parameters:
            ip_perms = event.request_parameters.get('ipPermissions', {})
            if ip_perms:
                items = ip_perms.get('items', [])
                if items:
                    return f"{resource_type} {resource_id} had {len(items)} rule(s) revoked"
        return f"{resource_type} {resource_id} had permissions revoked"
    elif category == "Creation Failed":
        error_msg = event.error_message or event.error_code or "Unknown error"
        return f"Failed to create {resource_type}: {error_msg}"
    elif "Terminate" in event.event_name:
        return f"{resource_type} {resource_id} was terminated"
    elif "Detach" in event.event_name:
        return f"{resource_type} {resource_id} was detached"
    elif "Disassociate" in event.event_name:
        return f"{resource_type} {resource_id} was disassociated"
    else:
        return f"{event.event_name} performed on {resource_type} {resource_id}"
