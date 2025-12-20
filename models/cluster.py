"""Cluster data model"""

from dataclasses import dataclass, field
from typing import Dict, Any, Optional, List
from pathlib import Path
import os


@dataclass
class ClusterData:
    """
    Represents ROSA cluster data loaded from JSON files.

    This is the central data model that contains all cluster information
    loaded from the various JSON files in the data directory.
    """
    cluster_id: str
    data_dir: Path

    # Core cluster info
    cluster_json: Dict[str, Any] = field(default_factory=dict)

    # Infrastructure resources
    security_groups: Dict[str, Any] = field(default_factory=dict)
    ec2_instances: List[Dict[str, Any]] = field(default_factory=list)
    load_balancers: Dict[str, Any] = field(default_factory=dict)
    vpcs: Dict[str, Any] = field(default_factory=dict)
    route53_zones: Dict[str, Any] = field(default_factory=dict)
    cloudtrail_events: List[Dict[str, Any]] = field(default_factory=list)
    api_requests: Dict[str, Any] = field(default_factory=dict)  # AWS API request tracking log

    # Additional data
    cluster_context: Dict[str, Any] = field(default_factory=dict)
    resources: Dict[str, Any] = field(default_factory=dict)

    # File tracking for test reporting
    files_loaded: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    files_missing: List[str] = field(default_factory=list)

    # Per-test file access tracking
    _files_accessed_in_current_test: Dict[str, Dict[str, Any]] = field(default_factory=dict, init=False, repr=False)
    _files_expected_but_missing: Dict[str, str] = field(default_factory=dict, init=False, repr=False)  # path -> filename
    _attributes_accessed_with_no_files: List[str] = field(default_factory=list, init=False, repr=False)
    _attribute_to_files: Dict[str, List[str]] = field(default_factory=dict, init=False, repr=False)
    _tracking_enabled: bool = field(default=True, init=False, repr=False)

    # Console log cache to avoid re-parsing large files
    _console_logs_cache: Dict[str, str] = field(default_factory=dict, init=False, repr=False)

    @property
    def aws_dir(self) -> Path:
        """
        Get directory containing AWS data files.

        Returns sources/aws/ if new directory structure exists, otherwise data_dir.
        """
        # Import here to avoid circular dependency
        from utils.tracked_path import TrackedPath

        sources_aws = Path(self.data_dir) / "sources" / "aws"
        if sources_aws.exists() and sources_aws.is_dir():
            return TrackedPath(sources_aws, self)
        # Legacy flat structure - AWS files in data_dir
        return TrackedPath(self.data_dir, self)

    @property
    def ocm_dir(self) -> Path:
        """
        Get directory containing OCM data files.

        Returns sources/ocm/ if new directory structure exists, otherwise data_dir.
        """
        # Import here to avoid circular dependency
        from utils.tracked_path import TrackedPath

        sources_ocm = Path(self.data_dir) / "sources" / "ocm"
        if sources_ocm.exists() and sources_ocm.is_dir():
            return TrackedPath(sources_ocm, self)
        # Legacy flat structure - OCM files in data_dir
        return TrackedPath(self.data_dir, self)

    @property
    def hosts_dir(self) -> Path:
        """
        Get directory containing EC2 instance console logs.

        Returns sources/hosts/ if new directory structure exists, otherwise None.
        Console logs follow pattern: {cluster_id}_{instance_id}_console.log
        """
        # Import here to avoid circular dependency
        from utils.tracked_path import TrackedPath

        sources_hosts = Path(self.data_dir) / "sources" / "hosts"
        if sources_hosts.exists() and sources_hosts.is_dir():
            return TrackedPath(sources_hosts, self)
        # No hosts directory - console logs not collected
        return TrackedPath(Path(self.data_dir) / "sources" / "hosts", self)

    @property
    def infra_id(self) -> str:
        """Get infrastructure ID"""
        return self.cluster_json.get('infra_id', self.cluster_id.split('_')[0])

    @property
    def cluster_name(self) -> str:
        """Get cluster name"""
        return self.cluster_json.get('name', 'unknown')

    @property
    def cluster_uuid(self) -> str:
        """Get cluster UUID"""
        return self.cluster_json.get('id', self.cluster_id)

    @property
    def region(self) -> str:
        """Get AWS region"""
        return self.cluster_json.get('region', {}).get('id', 'unknown')

    @property
    def openshift_version(self) -> str:
        """Get OpenShift version"""
        return self.cluster_json.get('openshift_version', 'unknown')

    @property
    def cluster_state(self) -> str:
        """Get cluster state (ready, error, installing, etc.)"""
        return self.cluster_json.get('state', 'unknown')

    @property
    def is_private(self) -> bool:
        """Check if cluster has private API"""
        return self.cluster_json.get('api', {}).get('listening') == 'internal'

    @property
    def is_privatelink(self) -> bool:
        """Check if cluster uses AWS PrivateLink"""
        return self.cluster_json.get('aws', {}).get('private_link', False)

    @property
    def network_type(self) -> str:
        """Get network type (OVNKubernetes, etc.)"""
        if self.cluster_context:
            return self.cluster_context.get('NetworkType', 'unknown')
        return 'unknown'

    @property
    def machine_cidr(self) -> Optional[str]:
        """Get machine CIDR"""
        if self.cluster_context:
            return self.cluster_context.get('MachineCIDR')
        return None

    @property
    def vpc_cidr(self) -> Optional[str]:
        """Get VPC CIDR from cluster context or VPC data"""
        if self.machine_cidr:
            return self.machine_cidr

        # Try to get from VPC data
        vpcs = self.vpcs.get('Vpcs', [])
        if vpcs:
            vpc = vpcs[0]
            # First try the top-level CidrBlock
            cidr = vpc.get('CidrBlock')
            if cidr:
                return cidr

            # If not present, try CidrBlockAssociationSet
            cidr_associations = vpc.get('CidrBlockAssociationSet', [])
            if cidr_associations:
                # Return the first associated CIDR block that is in 'associated' state
                for assoc in cidr_associations:
                    state = assoc.get('CidrBlockState', {}).get('State')
                    if state == 'associated':
                        return assoc.get('CidrBlock')
                # If no associated state found, return the first one
                return cidr_associations[0].get('CidrBlock')

        return None

    def get_security_groups_by_infra_id(self) -> Dict[str, Dict[str, Any]]:
        """Get security groups filtered by infrastructure ID"""
        sgs = {}
        for sg in self.security_groups.get('SecurityGroups', []):
            sg_name = sg.get('GroupName', '')
            if self.infra_id in sg_name:
                sgs[sg_name] = sg
        return sgs

    def get_instances_by_infra_id(self) -> List[Dict[str, Any]]:
        """Get EC2 instances filtered by infrastructure ID"""
        instances = []
        for inst in self.ec2_instances:
            tags = inst.get('Tags', [])
            if any(self.infra_id in tag.get('Value', '') for tag in tags):
                instances.append(inst)
        return instances

    def __getattribute__(self, name: str) -> Any:
        """Override to track attribute access for per-test file tracking"""
        # Get the value using the parent implementation
        value = object.__getattribute__(self, name)

        # Track file access if this is a data attribute and tracking is enabled
        if object.__getattribute__(self, '_tracking_enabled'):
            # Track data attributes
            if name in ['cluster_json', 'security_groups', 'ec2_instances', 'load_balancers',
                       'vpcs', 'route53_zones', 'cloudtrail_events', 'cluster_context', 'resources']:
                self._mark_attribute_accessed(name)
            # Track when tests access data_dir or cluster_id (they depend on cluster.json)
            elif name == 'cluster_id':
                self._mark_attribute_accessed('cluster_json')
            # Wrap data_dir in TrackedPath for automatic file tracking
            elif name == 'data_dir':
                self._mark_attribute_accessed('cluster_json')
                # Import here to avoid circular dependency
                from utils.tracked_path import TrackedPath
                return TrackedPath(value, self)

        return value

    def _mark_attribute_accessed(self, attr_name: str) -> None:
        """Mark that a data attribute was accessed in the current test"""
        # Temporarily disable tracking to avoid infinite recursion
        object.__setattr__(self, '_tracking_enabled', False)

        try:
            # Get the mapping of attributes to files
            attr_to_files = object.__getattribute__(self, '_attribute_to_files')
            files_accessed = object.__getattribute__(self, '_files_accessed_in_current_test')
            files_loaded = object.__getattribute__(self, 'files_loaded')
            attrs_no_files = object.__getattribute__(self, '_attributes_accessed_with_no_files')

            # Get the files associated with this attribute
            file_paths = attr_to_files.get(attr_name, [])

            if file_paths:
                # Add these files to the current test's accessed files
                for file_path in file_paths:
                    if file_path in files_loaded:
                        files_accessed[file_path] = files_loaded[file_path]
            else:
                # Attribute was accessed but has no registered files
                # Track this so we can show "expected but not found"
                if attr_name not in attrs_no_files:
                    attrs_no_files.append(attr_name)
        finally:
            # Re-enable tracking
            object.__setattr__(self, '_tracking_enabled', True)

    def register_attribute_file(self, attr_name: str, file_path: str) -> None:
        """Register which file(s) provide data for a specific attribute"""
        if attr_name not in self._attribute_to_files:
            self._attribute_to_files[attr_name] = []
        if file_path not in self._attribute_to_files[attr_name]:
            self._attribute_to_files[attr_name].append(file_path)

    def reset_test_file_tracking(self) -> None:
        """Reset per-test file access tracking (called at start of each test)"""
        self._files_accessed_in_current_test = {}
        self._files_expected_but_missing = {}
        self._attributes_accessed_with_no_files = []

    def get_test_files_accessed(self) -> Dict[str, Dict[str, Any]]:
        """Get files accessed during the current test"""
        return self._files_accessed_in_current_test.copy()

    def get_test_attributes_with_no_files(self) -> List[str]:
        """Get attributes that were accessed but have no registered files"""
        return self._attributes_accessed_with_no_files.copy()

    def get_test_files_expected_but_missing(self) -> Dict[str, str]:
        """Get files that were expected (checked) but don't exist"""
        return self._files_expected_but_missing.copy()

    def _track_direct_file_access(self, file_path: Path, exists: bool = True) -> None:
        """
        Track direct file access (files opened/checked outside of ClusterData attributes).

        This is called by TrackedPath when tests use cluster_data.data_dir to:
        - Construct file paths
        - Glob for files
        - Check file existence
        - Open files directly

        Args:
            file_path: Path to file being accessed
            exists: Whether the file exists (False when checked but not found)
        """
        # Temporarily disable tracking to avoid recursion
        object.__setattr__(self, '_tracking_enabled', False)

        try:
            file_path = Path(file_path)
            files_accessed = object.__getattribute__(self, '_files_accessed_in_current_test')
            files_missing = object.__getattribute__(self, '_files_expected_but_missing')
            files_loaded = object.__getattribute__(self, 'files_loaded')

            # Convert to string for consistent key format
            file_path_str = str(file_path)

            if exists:
                # File exists - track it with metadata
                # If this file was loaded at session startup, use that metadata
                if file_path_str in files_loaded:
                    files_accessed[file_path_str] = files_loaded[file_path_str]
                elif file_path.exists():
                    # File exists but wasn't loaded at session startup - get metadata now
                    stat = file_path.stat()
                    files_accessed[file_path_str] = {
                        'size': stat.st_size,
                        'created': stat.st_ctime,
                        'modified': stat.st_mtime,
                        'name': file_path.name
                    }
            else:
                # File was checked but doesn't exist - track as expected but missing
                files_missing[file_path_str] = file_path.name
        finally:
            # Re-enable tracking
            object.__setattr__(self, '_tracking_enabled', True)

    # =========================================================================
    # API Request Log Helper Methods
    # =========================================================================

    def get_api_requests(self) -> List[Dict[str, Any]]:
        """
        Get all API requests from the request log.

        Returns:
            List of API request dictionaries, or empty list if no request log
        """
        if not self.api_requests:
            return []
        return self.api_requests.get('requests', [])

    def get_failed_requests(self, service: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Get all failed API requests, optionally filtered by service.

        Args:
            service: Filter by AWS service (e.g., "ec2", "iam", "elbv2")

        Returns:
            List of failed requests
        """
        requests = self.get_api_requests()
        failed = [req for req in requests if not req.get('success', False)]

        if service:
            failed = [req for req in failed if req.get('service') == service]

        return failed

    def get_permission_errors(self) -> List[Dict[str, Any]]:
        """
        Get all API requests that failed due to permission issues.

        Returns:
            List of requests that failed with permission/authorization errors
        """
        requests = self.get_api_requests()
        permission_errors = []

        for req in requests:
            if not req.get('success', False) and req.get('error'):
                error = req['error']
                error_code = error.get('code', '').lower()
                error_type = error.get('type', '').lower()

                # Check for permission-related error codes
                if any(perm in error_code or perm in error_type for perm in
                       ['unauthorized', 'accessdenied', 'forbidden', 'permission']):
                    permission_errors.append(req)

        return permission_errors

    def get_request_for_operation(self, operation: str, service: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """
        Get the most recent request for a specific operation.

        Args:
            operation: AWS operation name (e.g., "describe_instances", "get_role")
            service: Optional service filter (e.g., "ec2", "iam")

        Returns:
            Most recent request dict for that operation, or None
        """
        requests = self.get_api_requests()

        # Filter by operation
        matching = [req for req in requests if req.get('operation') == operation]

        # Further filter by service if specified
        if service:
            matching = [req for req in matching if req.get('service') == service]

        # Return most recent (last in list)
        return matching[-1] if matching else None

    def get_request_summary(self) -> Dict[str, Any]:
        """
        Get summary statistics from the API request log.

        Returns:
            Summary dict with counts, or empty dict if no request log
        """
        if not self.api_requests:
            return {}
        return self.api_requests.get('summary', {})

    def get_collection_metadata(self) -> Dict[str, Any]:
        """
        Get metadata about when and how data was collected.

        Returns:
            Metadata dict with collection timestamps and identifiers
        """
        if not self.api_requests:
            return {}
        return self.api_requests.get('collection_metadata', {})

    # =========================================================================
    # Console Log Helper Methods (for deep diagnostic analysis)
    # =========================================================================

    def get_console_log(self, instance_id: str) -> Optional[str]:
        """
        Lazy load console log for a specific EC2 instance.

        Console logs are large (50KB-500KB) so we load them on-demand and cache.

        Args:
            instance_id: EC2 instance ID (e.g., "i-0abc123def456789")

        Returns:
            Console log content as string, or None if not found

        Example:
            >>> log = cluster_data.get_console_log("i-0abc123def456789")
            >>> if log:
            >>>     # Analyze log for bootstrap progress
        """
        # Check cache first
        if instance_id in self._console_logs_cache:
            return self._console_logs_cache[instance_id]

        # Construct expected file path
        log_file = self.hosts_dir / f"{self.cluster_id}_{instance_id}_console.log"

        # Check if file exists and read it
        if log_file.exists():
            try:
                with open(log_file, 'r', encoding='utf-8', errors='replace') as f:
                    content = f.read()
                    # Cache for future access
                    self._console_logs_cache[instance_id] = content
                    return content
            except Exception as e:
                # Log read error but don't fail - return None
                import sys
                print(f"Warning: Failed to read console log {log_file}: {e}", file=sys.stderr)
                return None

        return None

    def get_all_console_logs(self) -> Dict[str, str]:
        """
        Load all available console logs for the cluster.

        Returns:
            Dict mapping instance_id -> log_content

        Example:
            >>> logs = cluster_data.get_all_console_logs()
            >>> for instance_id, log in logs.items():
            >>>     print(f"Instance {instance_id}: {len(log)} bytes")
        """
        console_logs = {}

        # Check if hosts directory exists
        if not self.hosts_dir.exists():
            return console_logs

        # Find all console log files matching pattern
        pattern = f"{self.cluster_id}_*_console.log"
        for log_file in self.hosts_dir.glob(pattern):
            # Extract instance ID from filename
            # Pattern: {cluster_id}_{instance_id}_console.log
            filename = log_file.stem  # Remove .log
            parts = filename.split('_')
            if len(parts) >= 2:
                # Join all parts except first (cluster_id) and last (console)
                # This handles cluster IDs that contain underscores
                instance_id = '_'.join(parts[1:-1]) if len(parts) > 2 else parts[1]

                # Load the log (will use cache if already loaded)
                log_content = self.get_console_log(instance_id)
                if log_content:
                    console_logs[instance_id] = log_content

        return console_logs

    def get_ocm_install_logs(self) -> List[Dict[str, Any]]:
        """
        Parse OCM resources.json for installation log entries.

        OCM resources may contain installation logs with timestamps, events,
        and status information that complements console logs.

        Returns:
            List of log entry dicts, or empty list if no logs found

        Example:
            >>> logs = cluster_data.get_ocm_install_logs()
            >>> for entry in logs:
            >>>     print(f"{entry['timestamp']}: {entry['message']}")
        """
        # Check if resources dict has logs
        if not self.resources:
            return []

        # OCM resources.json structure varies, but commonly has:
        # - logs: List of log entries
        # - events: List of events
        # - messages: Installation messages

        logs = []

        # Try to extract logs from resources
        if isinstance(self.resources, dict):
            # Direct logs array
            if 'logs' in self.resources:
                logs_data = self.resources['logs']
                if isinstance(logs_data, list):
                    logs.extend(logs_data)

            # Events that may contain log-like information
            if 'events' in self.resources:
                events_data = self.resources['events']
                if isinstance(events_data, list):
                    # Convert events to log format
                    for event in events_data:
                        if isinstance(event, dict):
                            logs.append({
                                'timestamp': event.get('timestamp'),
                                'message': event.get('message', event.get('description', '')),
                                'type': 'event',
                                'severity': event.get('severity', 'INFO')
                            })

            # Installation messages
            if 'messages' in self.resources:
                messages_data = self.resources['messages']
                if isinstance(messages_data, list):
                    for msg in messages_data:
                        if isinstance(msg, dict):
                            logs.append({
                                'timestamp': msg.get('timestamp'),
                                'message': msg.get('message', str(msg)),
                                'type': 'message',
                                'severity': msg.get('severity', 'INFO')
                            })

        return logs
