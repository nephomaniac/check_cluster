"""Cluster data model"""

from dataclasses import dataclass, field
from typing import Dict, Any, Optional, List
from pathlib import Path


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
