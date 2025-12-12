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
            return vpcs[0].get('CidrBlock')

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
