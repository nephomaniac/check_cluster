"""
GCP Cluster Data Model

Provides structured access to GCP OpenShift cluster data collected from:
- OCM (OpenShift Cluster Manager)
- gcloud CLI (GCP resources)
"""

import json
from pathlib import Path
from typing import Dict, Any, Optional


class GCPClusterData:
    """Container for GCP OpenShift cluster data"""

    def __init__(self, cluster_dir: Path):
        """
        Initialize GCP cluster data from directory.

        Args:
            cluster_dir: Path to cluster data directory
        """
        self.cluster_dir = Path(cluster_dir)
        self.sources_dir = self.cluster_dir / "sources"
        self.gcp_dir = self.sources_dir / "gcp"
        self.ocm_dir = self.sources_dir / "ocm"

        # Find cluster ID from directory name
        self.cluster_id = self.cluster_dir.name

        # Load cluster JSON from OCM
        cluster_file = self.ocm_dir / f"{self.cluster_id}_cluster.json"
        if not cluster_file.exists():
            raise FileNotFoundError(f"Cluster file not found: {cluster_file}")

        with open(cluster_file) as f:
            self.cluster_json = json.load(f)

        # Extract key information
        self.project_id = self.cluster_json.get('gcp', {}).get('project_id')
        self.region = self.cluster_json.get('region', {}).get('id')
        self.infra_id = self.cluster_json.get('infra_id')
        self.cluster_name = self.cluster_json.get('name')
        self.state = self.cluster_json.get('state')

        # Network configuration
        self.vpc_name = self.cluster_json.get('gcp_network', {}).get('vpc_name')
        self.cp_subnet = self.cluster_json.get('gcp_network', {}).get('control_plane_subnet')
        self.worker_subnet = self.cluster_json.get('gcp_network', {}).get('compute_subnet')

        # Authentication type
        auth_kind = self.cluster_json.get('gcp', {}).get('authentication', {}).get('kind', 'ServiceAccountKey')
        self.auth_type = 'WIF' if auth_kind == 'WifConfig' else 'ServiceAccountKey'

        # Private cluster flag
        api_listening = self.cluster_json.get('api', {}).get('listening', 'external')
        self.is_private = (api_listening == 'internal')

        # PSC configuration
        psc_subnet = self.cluster_json.get('gcp', {}).get('private_service_connect', {}).get('service_attachment_subnet')
        self.is_psc = (psc_subnet is not None and psc_subnet != 'null')

    def load_json_file(self, filename: str, directory: str = 'gcp') -> Optional[Dict[str, Any]]:
        """
        Load a JSON file from the cluster data directory.

        Args:
            filename: Name of the JSON file
            directory: Subdirectory ('gcp' or 'ocm')

        Returns:
            Parsed JSON data or None if file doesn't exist
        """
        if directory == 'gcp':
            file_path = self.gcp_dir / filename
        elif directory == 'ocm':
            file_path = self.ocm_dir / filename
        else:
            raise ValueError(f"Unknown directory: {directory}")

        if not file_path.exists():
            return None

        with open(file_path) as f:
            return json.load(f)

    def __repr__(self):
        return f"GCPClusterData(cluster_id={self.cluster_id}, project={self.project_id}, region={self.region})"
