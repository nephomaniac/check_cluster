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
    """Security group rules should not be revoked (indicates potential issues)

    Why: Security group rule revocations during cluster installation can break
    critical network communication between cluster components.

    Failure indicates: Security group rules were revoked during the cluster
    installation window. This can cause:
    - Loss of API server access (port 6443)
    - Loss of Machine Config Server access (port 22623)
    - Loss of etcd communication (ports 2379, 2380)
    - Loss of kubelet access (port 10250)
    - Loss of overlay network connectivity (ports 4789, 6081)

    Success indicates: No security group rules were revoked during installation.

    Remediation:
      Review the revoked rules details in the failure output to understand what
      was removed. Check if any critical ports for cluster communication were affected.

      To restore missing critical rules:
        $ aws ec2 authorize-security-group-ingress --group-id <sg-id> \\
            --protocol tcp --port 6443 --source-group <sg-id> \\
            --region <region>

      To view current security group rules:
        $ aws ec2 describe-security-groups --group-ids <sg-id> \\
            --region <region>

    Severity: HIGH - Can break cluster communication
    """
    if not cluster_data.cloudtrail_events:
        pytest.skip("No CloudTrail events available")

    revoke_events = get_revoke_events(cluster_data)

    if revoke_events:
        details = []
        for event in revoke_events[:10]:  # Show first 10
            event_name = event.get('EventName', 'unknown')
            event_time = event.get('EventTime', 'unknown')
            user = event.get('Username', 'unknown')

            # Parse CloudTrailEvent JSON to get request parameters
            import json
            cloud_trail_event_str = event.get('CloudTrailEvent', '{}')
            try:
                cloud_trail_event = json.loads(cloud_trail_event_str)
                request_params = cloud_trail_event.get('requestParameters', {})

                # Extract details about what was revoked
                group_id = request_params.get('groupId', 'unknown')
                ip_permissions = request_params.get('ipPermissions', {})

                # Build a summary of what was revoked
                revoked_details = []
                for item in ip_permissions.get('items', []):
                    protocol = item.get('ipProtocol', 'unknown')
                    from_port = item.get('fromPort', 'N/A')
                    to_port = item.get('toPort', 'N/A')

                    # Get CIDR ranges
                    cidrs = []
                    for ip_range in item.get('ipRanges', {}).get('items', []):
                        cidrs.append(ip_range.get('cidrIp', 'unknown'))

                    # Get security groups
                    groups = []
                    for group in item.get('groups', {}).get('items', []):
                        groups.append(group.get('groupId', 'unknown'))

                    if protocol == '-1':
                        rule_desc = "All protocols"
                    else:
                        rule_desc = f"Protocol {protocol}, Ports {from_port}-{to_port}"

                    if cidrs:
                        rule_desc += f", CIDR: {', '.join(cidrs)}"
                    if groups:
                        rule_desc += f", Source SG: {', '.join(groups)}"

                    revoked_details.append(rule_desc)

                if revoked_details:
                    details.append(
                        f"{event_time} - {event_name} by {user}\n" +
                        f"  Security Group: {group_id}\n" +
                        f"  Revoked Rules:\n    - " + "\n    - ".join(revoked_details)
                    )
                else:
                    details.append(
                        f"{event_time} - {event_name} by {user} (Group: {group_id})"
                    )
            except (json.JSONDecodeError, KeyError) as e:
                # Fallback to basic info if parsing fails
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
