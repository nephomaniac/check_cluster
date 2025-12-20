"""
CloudTrail Event Correlator

Correlates missing AWS resources with CloudTrail events to determine why resources
don't exist (failed to create, deleted, etc.).
"""

import json
import re
from typing import List, Dict, Any, Optional, Set
from datetime import datetime
from pathlib import Path


class CloudTrailEvent:
    """Represents a CloudTrail event with parsed details"""

    def __init__(self, event: Dict[str, Any], source_file: str, event_index: int):
        self.raw_event = event
        self.source_file = source_file
        self.event_index = event_index

        # Parse CloudTrailEvent JSON if present
        self.cloud_trail_event = {}
        if 'CloudTrailEvent' in event:
            try:
                self.cloud_trail_event = json.loads(event['CloudTrailEvent'])
            except (json.JSONDecodeError, TypeError):
                pass

        # Extract common fields
        self.event_name = event.get('EventName', '')
        self.event_time = event.get('EventTime', '')
        self.username = event.get('Username', '')
        self.event_source = event.get('EventSource', '')

        # Extract from CloudTrailEvent
        self.request_parameters = self.cloud_trail_event.get('requestParameters', {})
        self.response_elements = self.cloud_trail_event.get('responseElements', {})
        self.error_code = self.cloud_trail_event.get('errorCode')
        self.error_message = self.cloud_trail_event.get('errorMessage')

        # Extract resource information
        self.resources = event.get('Resources', [])
        self.resource_names = self._extract_resource_names()

    def _extract_resource_names(self) -> Set[str]:
        """Extract all resource identifiers from the event"""
        names = set()

        # From Resources field
        for resource in self.resources:
            if isinstance(resource, dict):
                if 'ResourceName' in resource:
                    names.add(resource['ResourceName'])
                if 'ARN' in resource:
                    names.add(resource['ARN'])

        # From request parameters
        if self.request_parameters:
            # VPC resources
            for key in ['vpcId', 'VpcId', 'subnetId', 'SubnetId', 'groupId', 'GroupId']:
                if key in self.request_parameters:
                    names.add(self.request_parameters[key])

            # Instance IDs
            if 'instancesSet' in self.request_parameters:
                for item in self.request_parameters.get('instancesSet', {}).get('items', []):
                    if 'instanceId' in item:
                        names.add(item['instanceId'])

            # Load balancer names/ARNs
            for key in ['loadBalancerName', 'LoadBalancerName', 'loadBalancerArn', 'LoadBalancerArn']:
                if key in self.request_parameters:
                    names.add(self.request_parameters[key])

        # From response elements
        if self.response_elements:
            # Created resource IDs
            for key in ['instanceId', 'vpcId', 'subnetId', 'groupId', 'loadBalancerArn']:
                if key in self.response_elements:
                    names.add(self.response_elements[key])

        return names

    def matches_resource(self, resource_identifier: str) -> bool:
        """
        Check if this event is related to a specific resource.

        Args:
            resource_identifier: Resource ID, name, or ARN to search for

        Returns:
            True if event is related to the resource
        """
        # Direct match in resource names
        if resource_identifier in self.resource_names:
            return True

        # Check in event name (e.g., tag keys/values)
        if resource_identifier in self.event_name:
            return True

        # Check in raw JSON (deep search)
        event_json = json.dumps(self.raw_event)
        if resource_identifier in event_json:
            return True

        # Check for partial matches (e.g., load balancer name in ARN)
        for name in self.resource_names:
            if resource_identifier in name or name in resource_identifier:
                return True

        return False

    def get_summary(self) -> str:
        """Get a brief summary of the event"""
        summary_parts = []

        # Event name and time
        summary_parts.append(f"{self.event_name} at {self.event_time}")

        # User
        if self.username:
            summary_parts.append(f"by {self.username}")

        # Error information
        if self.error_code or self.error_message:
            error_info = self.error_code or "Error"
            if self.error_message:
                error_info += f": {self.error_message[:100]}"
            summary_parts.append(f"[{error_info}]")

        return " ".join(summary_parts)

    def is_creation_failure(self) -> bool:
        """Check if this event represents a failed resource creation"""
        creation_events = [
            'CreateVpc', 'CreateSubnet', 'CreateSecurityGroup', 'CreateLoadBalancer',
            'RunInstances', 'CreateTargetGroup', 'CreateVolume', 'CreateNetworkInterface'
        ]

        return (
            any(create in self.event_name for create in creation_events) and
            (self.error_code or self.error_message)
        )

    def is_deletion(self) -> bool:
        """Check if this event represents a resource deletion"""
        deletion_events = [
            'Delete', 'Terminate', 'Remove', 'Revoke', 'Detach', 'Disassociate'
        ]

        return any(delete in self.event_name for delete in deletion_events)

    def get_event_category(self) -> str:
        """Categorize the event type"""
        if self.is_creation_failure():
            return "Creation Failed"
        elif self.is_deletion():
            return "Deletion"
        elif 'Create' in self.event_name:
            return "Creation"
        elif 'Modify' in self.event_name or 'Update' in self.event_name:
            return "Modification"
        elif 'Authorize' in self.event_name:
            return "Authorization"
        elif 'Revoke' in self.event_name:
            return "Revocation"
        else:
            return "Other"


class CloudTrailCorrelator:
    """Correlates AWS resources with CloudTrail events"""

    def __init__(self, cloudtrail_events: List[Dict[str, Any]], source_file: str = ""):
        """
        Initialize correlator with CloudTrail events.

        Args:
            cloudtrail_events: List of CloudTrail event dictionaries
            source_file: Path to source CloudTrail file
        """
        self.source_file = source_file
        self.events = [
            CloudTrailEvent(event, source_file, idx)
            for idx, event in enumerate(cloudtrail_events)
        ]

    def find_events_for_resource(
        self,
        resource_identifier: str,
        event_types: Optional[List[str]] = None,
        limit: int = 10
    ) -> List[CloudTrailEvent]:
        """
        Find CloudTrail events related to a specific resource.

        Args:
            resource_identifier: Resource ID, name, or ARN (e.g., "vpc-123abc", "my-cluster-int")
            event_types: Optional list of event name patterns to filter (e.g., ["Delete", "Create"])
            limit: Maximum number of events to return

        Returns:
            List of related CloudTrail events, most recent first
        """
        matching_events = []

        for event in self.events:
            # Check if event matches resource
            if not event.matches_resource(resource_identifier):
                continue

            # Check if event type matches filter
            if event_types:
                if not any(event_type in event.event_name for event_type in event_types):
                    continue

            matching_events.append(event)

        # Sort by time (most recent first) and limit
        matching_events.sort(key=lambda e: e.event_time, reverse=True)
        return matching_events[:limit]

    def find_creation_failures(self, resource_pattern: str = "") -> List[CloudTrailEvent]:
        """
        Find failed resource creation events.

        Args:
            resource_pattern: Optional pattern to filter resources (e.g., "vpc-", "i-")

        Returns:
            List of creation failure events
        """
        failures = []

        for event in self.events:
            if event.is_creation_failure():
                if resource_pattern:
                    # Check if any resource name matches pattern
                    if any(resource_pattern in name for name in event.resource_names):
                        failures.append(event)
                else:
                    failures.append(event)

        return failures

    def find_deletions(self, resource_identifier: str = "") -> List[CloudTrailEvent]:
        """
        Find resource deletion events.

        Args:
            resource_identifier: Optional resource ID to filter

        Returns:
            List of deletion events
        """
        deletions = []

        for event in self.events:
            if event.is_deletion():
                if resource_identifier:
                    if event.matches_resource(resource_identifier):
                        deletions.append(event)
                else:
                    deletions.append(event)

        return deletions

    def explain_missing_resource(
        self,
        resource_identifier: str,
        resource_type: str = "resource"
    ) -> Dict[str, Any]:
        """
        Explain why a resource might be missing by searching CloudTrail.

        Args:
            resource_identifier: Resource ID, name, or ARN
            resource_type: Human-readable resource type (e.g., "VPC", "Load Balancer")

        Returns:
            Dictionary with explanation and related events:
            {
                'found_events': bool,
                'explanation': str,
                'events': List[CloudTrailEvent],
                'event_summaries': List[str]
            }
        """
        # Search for related events
        related_events = self.find_events_for_resource(resource_identifier, limit=5)

        if not related_events:
            return {
                'found_events': False,
                'explanation': (
                    f"No CloudTrail events found for {resource_type} '{resource_identifier}'. "
                    f"Possible reasons: resource never created, created before CloudTrail "
                    f"collection window, or created by a different AWS account/process."
                ),
                'events': [],
                'event_summaries': []
            }

        # Categorize events
        creation_failures = [e for e in related_events if e.is_creation_failure()]
        deletions = [e for e in related_events if e.is_deletion()]
        creations = [e for e in related_events if 'Create' in e.event_name and not e.is_creation_failure()]

        # Build explanation
        explanations = []
        if creation_failures:
            explanations.append(
                f"Found {len(creation_failures)} failed creation attempt(s). "
                f"Resource may have failed to create due to: {creation_failures[0].error_code or 'error'}."
            )
        if deletions:
            explanations.append(
                f"Found {len(deletions)} deletion event(s). "
                f"Resource may have been deleted after creation."
            )
        if creations and not deletions:
            explanations.append(
                f"Found {len(creations)} creation event(s) but resource not present. "
                f"Resource may have been created then deleted outside CloudTrail collection window."
            )

        if not explanations:
            explanations.append(
                f"Found {len(related_events)} related event(s) but unable to determine "
                f"specific reason for missing resource."
            )

        # Build event summaries with file links
        event_summaries = []
        for event in related_events:
            summary = {
                'summary': event.get_summary(),
                'category': event.get_event_category(),
                'file': event.source_file,
                'index': event.event_index,
                'event_name': event.event_name,
                'event_time': event.event_time
            }
            event_summaries.append(summary)

        return {
            'found_events': True,
            'explanation': " ".join(explanations),
            'events': related_events,
            'event_summaries': event_summaries
        }


def create_correlator_from_cluster_data(cluster_data) -> Optional[CloudTrailCorrelator]:
    """
    Create CloudTrailCorrelator from ClusterData object.

    Args:
        cluster_data: ClusterData instance with cloudtrail_events

    Returns:
        CloudTrailCorrelator instance or None if no events available
    """
    if not cluster_data.cloudtrail_events:
        return None

    # Find source file for CloudTrail events
    source_file = ""
    if hasattr(cluster_data, '_attribute_to_files'):
        files = cluster_data._attribute_to_files.get('cloudtrail_events', [])
        if files:
            source_file = files[0]

    return CloudTrailCorrelator(cluster_data.cloudtrail_events, source_file)
