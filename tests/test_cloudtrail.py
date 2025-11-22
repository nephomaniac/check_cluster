"""
CloudTrail Event Analysis Tests

Analyzes CloudTrail events for security group changes and other critical operations.
"""

import pytest
from datetime import datetime
from models.cluster import ClusterData


def get_security_group_events(cluster_data: ClusterData) -> list:
    """Get all security group related events"""
    sg_events = []

    for event in cluster_data.cloudtrail_events:
        event_name = event.get('EventName', '')

        if any(sg_term in event_name for sg_term in [
            'AuthorizeSecurityGroupIngress',
            'AuthorizeSecurityGroupEgress',
            'RevokeSecurityGroupIngress',
            'RevokeSecurityGroupEgress',
            'CreateSecurityGroup',
            'DeleteSecurityGroup',
            'ModifySecurityGroup'
        ]):
            sg_events.append(event)

    return sg_events


def get_revoke_events(cluster_data: ClusterData) -> list:
    """Get security group rule revoke events"""
    revoke_events = []

    for event in cluster_data.cloudtrail_events:
        event_name = event.get('EventName', '')

        if 'Revoke' in event_name and 'SecurityGroup' in event_name:
            revoke_events.append(event)

    return revoke_events


def get_error_events(cluster_data: ClusterData) -> list:
    """Get events with errors"""
    error_events = []

    for event in cluster_data.cloudtrail_events:
        error_code = event.get('ErrorCode', '')
        error_message = event.get('ErrorMessage', '')

        if error_code or error_message:
            error_events.append(event)

    return error_events


@pytest.mark.cloudtrail
def test_cloudtrail_events_exist(cluster_data: ClusterData):
    """CloudTrail events should be available"""
    if not cluster_data.cloudtrail_events:
        pytest.skip("No CloudTrail events available")

    assert len(cluster_data.cloudtrail_events) > 0, "CloudTrail events list is empty"


@pytest.mark.cloudtrail
def test_no_security_group_revocations(cluster_data: ClusterData):
    """Security group rules should not be revoked (indicates potential issues)"""
    if not cluster_data.cloudtrail_events:
        pytest.skip("No CloudTrail events available")

    revoke_events = get_revoke_events(cluster_data)

    if revoke_events:
        details = []
        for event in revoke_events[:5]:  # Show first 5
            event_name = event.get('EventName', 'unknown')
            event_time = event.get('EventTime', 'unknown')
            user = event.get('Username', 'unknown')
            details.append(f"{event_time} - {event_name} by {user}")

        pytest.fail(
            f"Found {len(revoke_events)} security group revoke events:\n" +
            "\n".join(details)
        )


@pytest.mark.cloudtrail
def test_no_api_errors(cluster_data: ClusterData):
    """CloudTrail should not show excessive API errors"""
    if not cluster_data.cloudtrail_events:
        pytest.skip("No CloudTrail events available")

    error_events = get_error_events(cluster_data)

    if not error_events:
        return  # No errors, test passes

    # Allow some errors (< 10% of total events)
    error_rate = len(error_events) / len(cluster_data.cloudtrail_events)

    if error_rate > 0.10:
        details = []
        for event in error_events[:5]:  # Show first 5
            event_name = event.get('EventName', 'unknown')
            error_code = event.get('ErrorCode', 'unknown')
            error_msg = event.get('ErrorMessage', 'unknown')
            details.append(f"{event_name}: {error_code} - {error_msg}")

        pytest.fail(
            f"High error rate: {len(error_events)}/{len(cluster_data.cloudtrail_events)} " +
            f"({error_rate:.1%}) events have errors:\n" +
            "\n".join(details)
        )


@pytest.mark.cloudtrail
def test_security_group_modifications_tracked(cluster_data: ClusterData):
    """Security group modifications should be tracked in CloudTrail"""
    if not cluster_data.cloudtrail_events:
        pytest.skip("No CloudTrail events available")

    sg_events = get_security_group_events(cluster_data)

    # This is informational - we want to know if SG changes happened
    if not sg_events:
        pytest.skip("No security group modification events found")


@pytest.mark.cloudtrail
def test_events_have_timestamps(cluster_data: ClusterData):
    """All CloudTrail events must have timestamps"""
    if not cluster_data.cloudtrail_events:
        pytest.skip("No CloudTrail events available")

    events_without_time = []

    for i, event in enumerate(cluster_data.cloudtrail_events):
        event_time = event.get('EventTime', '')

        if not event_time:
            event_name = event.get('EventName', 'unknown')
            events_without_time.append(f"Event {i}: {event_name}")

    assert not events_without_time, \
        f"Events without timestamps: {', '.join(events_without_time[:10])}"


@pytest.mark.cloudtrail
def test_events_have_user_identity(cluster_data: ClusterData):
    """CloudTrail events should have user identity information"""
    if not cluster_data.cloudtrail_events:
        pytest.skip("No CloudTrail events available")

    events_without_identity = []

    for i, event in enumerate(cluster_data.cloudtrail_events):
        username = event.get('Username', '')
        user_identity = event.get('UserIdentity', {})

        if not username and not user_identity:
            event_name = event.get('EventName', 'unknown')
            events_without_identity.append(f"Event {i}: {event_name}")

    # Some events may not have user identity (service events), so we allow some
    if len(events_without_identity) > len(cluster_data.cloudtrail_events) * 0.5:
        pytest.fail(
            f"Too many events without user identity: " +
            f"{len(events_without_identity)}/{len(cluster_data.cloudtrail_events)}"
        )
