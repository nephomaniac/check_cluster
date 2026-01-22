"""
GCP OpenShift Cluster Data Collection

Collects cluster configuration and GCP resource data for validation and diagnostics.
Uses gcloud CLI to gather information about:
- Project quotas
- Enabled APIs
- Network configuration (VPC, subnets, firewall rules)
- DNS zones and records
- Compute instances
- Machine types
- Service accounts and IAM
- Load balancers
- Storage configuration
- WIF (Workload Identity Federation) configuration
"""

import json
import subprocess
import sys
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional, Any


class GCPDataCollector:
    """Collects GCP OpenShift cluster data for validation"""

    def __init__(self, cluster_id: str, work_dir: str = ".",
                 force_update: bool = False, debug: bool = False,
                 resources: list = None):
        """
        Initialize GCP data collector.

        Args:
            cluster_id: OCM cluster ID
            work_dir: Working directory for output
            force_update: Force re-collection of data
            debug: Enable debug output
            resources: List of resources to collect (None = all)
        """
        self.cluster_id = cluster_id
        self.work_dir = Path(work_dir) / cluster_id
        self.sources_dir = self.work_dir / "sources"
        self.gcp_dir = self.sources_dir / "gcp"
        self.ocm_dir = self.sources_dir / "ocm"
        self.force_update = force_update
        self.debug = debug

        # Parse resources to collect
        if resources is None or 'all' in resources:
            self.resources = ['all']
        else:
            self.resources = resources

        # Create output directories
        self.work_dir.mkdir(parents=True, exist_ok=True)
        self.sources_dir.mkdir(exist_ok=True)
        self.gcp_dir.mkdir(exist_ok=True)
        self.ocm_dir.mkdir(exist_ok=True)

        # Cluster configuration (loaded from OCM)
        self.cluster_json = {}
        self.project_id = None
        self.region = None
        self.infra_id = None
        self.vpc_name = None
        self.auth_type = None

    def _should_collect(self, resource_type: str) -> bool:
        """Check if a resource type should be collected"""
        if 'all' in self.resources:
            return True
        return resource_type in self.resources

    def _run_gcloud(self, args: List[str], output_file: Path,
                    description: str = "") -> bool:
        """
        Run gcloud command and save output.

        Args:
            args: gcloud command arguments
            output_file: File to save output
            description: Description for logging

        Returns:
            True if successful, False otherwise
        """
        if not self.force_update and output_file.exists():
            if self.debug:
                print(f"Skipping {description} (file exists): {output_file.name}")
            return True

        cmd = ["gcloud"] + args
        if self.debug:
            print(f"Running: {' '.join(cmd)}")

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60
            )

            # Save output (even on error for diagnostics)
            output_file.write_text(result.stdout if result.returncode == 0 else result.stderr)

            if result.returncode != 0:
                print(f"Warning: {description} failed: {result.stderr[:200]}", file=sys.stderr)
                return False

            return True

        except subprocess.TimeoutExpired:
            print(f"Error: {description} timed out", file=sys.stderr)
            return False
        except Exception as e:
            print(f"Error: {description} failed: {e}", file=sys.stderr)
            return False

    def _run_ocm(self, endpoint: str, output_file: Path,
                 description: str = "") -> bool:
        """Run OCM command and save output"""
        if not self.force_update and output_file.exists():
            if self.debug:
                print(f"Skipping {description} (file exists): {output_file.name}")
            return True

        if self.debug:
            print(f"Running: ocm get {endpoint}")

        try:
            result = subprocess.run(
                ["ocm", "get", endpoint],
                capture_output=True,
                text=True,
                timeout=30
            )

            output_file.write_text(result.stdout if result.returncode == 0 else result.stderr)

            if result.returncode != 0:
                print(f"Warning: {description} failed: {result.stderr[:200]}", file=sys.stderr)
                return False

            return True

        except Exception as e:
            print(f"Error: {description} failed: {e}", file=sys.stderr)
            return False

    def _fetch_cluster_info(self):
        """Fetch cluster information from OCM"""
        print("\nFetching cluster information from OCM...")

        # Get cluster details
        cluster_file = self.ocm_dir / f"{self.cluster_id}_cluster.json"
        if not self._run_ocm(f"cluster {self.cluster_id}", cluster_file, "cluster details"):
            raise Exception("Failed to fetch cluster details from OCM")

        # Load cluster JSON
        self.cluster_json = json.loads(cluster_file.read_text())

        # Extract key information
        self.project_id = self.cluster_json.get('gcp', {}).get('project_id')
        self.region = self.cluster_json.get('region', {}).get('id')
        self.infra_id = self.cluster_json.get('infra_id')

        # Network configuration
        self.vpc_name = self.cluster_json.get('gcp_network', {}).get('vpc_name')

        # Authentication type
        auth_kind = self.cluster_json.get('gcp', {}).get('authentication', {}).get('kind', 'ServiceAccountKey')
        self.auth_type = 'WIF' if auth_kind == 'WifConfig' else 'ServiceAccountKey'

        if not self.project_id or not self.region:
            raise Exception("Missing required cluster information (project_id or region)")

        print(f"  Project: {self.project_id}")
        print(f"  Region: {self.region}")
        print(f"  Infra ID: {self.infra_id}")
        print(f"  Auth Type: {self.auth_type}")

        # Get cluster resources/logs
        resources_file = self.ocm_dir / f"{self.cluster_id}_resources.json"
        self._run_ocm(
            f"/api/clusters_mgmt/v1/clusters/{self.cluster_id}/resources",
            resources_file,
            "cluster resources"
        )

    def _fetch_quotas(self):
        """Fetch GCP project quotas"""
        print("\nFetching GCP project quotas...")

        self._run_gcloud(
            ["compute", "project-info", "describe",
             f"--project={self.project_id}", "--format=json"],
            self.gcp_dir / f"{self.cluster_id}_project_quotas.json",
            "project quotas"
        )

    def _fetch_apis(self):
        """Fetch enabled GCP APIs"""
        print("\nFetching enabled GCP APIs...")

        self._run_gcloud(
            ["services", "list", "--enabled",
             f"--project={self.project_id}", "--format=json"],
            self.gcp_dir / f"{self.cluster_id}_enabled_apis.json",
            "enabled APIs"
        )

    def _fetch_region_info(self):
        """Fetch region and zone information"""
        print(f"\nFetching region information for {self.region}...")

        self._run_gcloud(
            ["compute", "regions", "describe", self.region,
             f"--project={self.project_id}", "--format=json"],
            self.gcp_dir / f"{self.cluster_id}_region_{self.region}.json",
            f"region {self.region}"
        )

    def _fetch_machine_types(self):
        """Fetch machine type information"""
        print("\nFetching machine type information...")

        # Get control plane machine type
        cp_machine_type = self.cluster_json.get('nodes', {}).get('master_machine_type', 'n2-standard-4')
        if isinstance(cp_machine_type, dict):
            cp_machine_type = cp_machine_type.get('id', 'n2-standard-4')

        self._run_gcloud(
            ["compute", "machine-types", "describe", cp_machine_type,
             f"--zone={self.region}-a", f"--project={self.project_id}", "--format=json"],
            self.gcp_dir / f"{self.cluster_id}_machine_type_control_plane.json",
            f"machine type {cp_machine_type}"
        )

        # Get worker machine type
        worker_machine_type = self.cluster_json.get('nodes', {}).get('compute_machine_type', 'n2-standard-4')
        if isinstance(worker_machine_type, dict):
            worker_machine_type = worker_machine_type.get('id', 'n2-standard-4')

        self._run_gcloud(
            ["compute", "machine-types", "describe", worker_machine_type,
             f"--zone={self.region}-a", f"--project={self.project_id}", "--format=json"],
            self.gcp_dir / f"{self.cluster_id}_machine_type_worker.json",
            f"machine type {worker_machine_type}"
        )

    def _fetch_network_config(self):
        """Fetch network configuration"""
        print("\nFetching network configuration...")

        # Get VPC info if using existing VPC
        if self.vpc_name:
            # Get subnets
            cp_subnet = self.cluster_json.get('gcp_network', {}).get('control_plane_subnet')
            worker_subnet = self.cluster_json.get('gcp_network', {}).get('compute_subnet')

            if cp_subnet:
                self._run_gcloud(
                    ["compute", "networks", "subnets", "describe", cp_subnet,
                     f"--region={self.region}", f"--project={self.project_id}", "--format=json"],
                    self.gcp_dir / f"{self.cluster_id}_subnet_control_plane.json",
                    f"control plane subnet {cp_subnet}"
                )

            if worker_subnet:
                self._run_gcloud(
                    ["compute", "networks", "subnets", "describe", worker_subnet,
                     f"--region={self.region}", f"--project={self.project_id}", "--format=json"],
                    self.gcp_dir / f"{self.cluster_id}_subnet_worker.json",
                    f"worker subnet {worker_subnet}"
                )

            # Get Cloud Routers (for NAT)
            self._run_gcloud(
                ["compute", "routers", "list",
                 f"--project={self.project_id}", f"--regions={self.region}", "--format=json"],
                self.gcp_dir / f"{self.cluster_id}_cloud_routers.json",
                "cloud routers"
            )

            # Get VPC routes
            self._run_gcloud(
                ["compute", "routes", "list",
                 f"--project={self.project_id}", f"--filter=network:{self.vpc_name}", "--format=json"],
                self.gcp_dir / f"{self.cluster_id}_vpc_routes.json",
                "VPC routes"
            )

    def _fetch_firewall_rules(self):
        """Fetch firewall rules"""
        print("\nFetching firewall rules...")

        if self.vpc_name:
            self._run_gcloud(
                ["compute", "firewall-rules", "list",
                 f"--project={self.project_id}", f"--filter=network:{self.vpc_name}", "--format=json"],
                self.gcp_dir / f"{self.cluster_id}_firewall_rules.json",
                "firewall rules"
            )
        else:
            # Get all firewall rules for installer-provisioned
            self._run_gcloud(
                ["compute", "firewall-rules", "list",
                 f"--project={self.project_id}", "--format=json"],
                self.gcp_dir / f"{self.cluster_id}_firewall_rules_all.json",
                "all firewall rules"
            )

    def _fetch_dns_config(self):
        """Fetch DNS configuration"""
        print("\nFetching DNS configuration...")

        if self.infra_id:
            private_zone = f"{self.infra_id}-private-zone"

            # Get managed zone
            if self._run_gcloud(
                ["dns", "managed-zones", "describe", private_zone,
                 f"--project={self.project_id}", "--format=json"],
                self.gcp_dir / f"{self.cluster_id}_dns_zone.json",
                f"DNS zone {private_zone}"
            ):
                # Get DNS records
                self._run_gcloud(
                    ["dns", "record-sets", "list",
                     f"--zone={private_zone}", f"--project={self.project_id}", "--format=json"],
                    self.gcp_dir / f"{self.cluster_id}_dns_records.json",
                    "DNS records"
                )

    def _fetch_iam_config(self):
        """Fetch IAM configuration"""
        print("\nFetching IAM configuration...")

        # Get IAM policy
        self._run_gcloud(
            ["projects", "get-iam-policy", self.project_id, "--format=json"],
            self.gcp_dir / f"{self.cluster_id}_iam_policy.json",
            "IAM policy"
        )

        # If WIF, get WIF configuration
        if self.auth_type == 'WIF':
            wif_config_id = self.cluster_json.get('gcp', {}).get('authentication', {}).get('id')
            if wif_config_id:
                wif_file = self.ocm_dir / f"{self.cluster_id}_wif_config.json"
                if self._run_ocm(
                    f"/api/clusters_mgmt/v1/gcp/wif_configs/{wif_config_id}",
                    wif_file,
                    "WIF configuration"
                ):
                    # Verify WIF config
                    verify_file = self.gcp_dir / f"{self.cluster_id}_wif_verify.txt"
                    subprocess.run(
                        ["ocm", "gcp", "verify", "wif-config", wif_config_id],
                        capture_output=True,
                        text=True,
                        stdout=verify_file.open('w')
                    )

    def _fetch_instances(self):
        """Fetch compute instances"""
        print("\nFetching compute instances...")

        if self.infra_id:
            self._run_gcloud(
                ["compute", "instances", "list",
                 f"--project={self.project_id}", f"--filter=name~{self.infra_id}", "--format=json"],
                self.gcp_dir / f"{self.cluster_id}_instances.json",
                "compute instances"
            )

    def _fetch_load_balancers(self):
        """Fetch load balancer configuration"""
        print("\nFetching load balancer configuration...")

        # Get forwarding rules
        self._run_gcloud(
            ["compute", "forwarding-rules", "list",
             f"--project={self.project_id}", f"--regions={self.region}", "--format=json"],
            self.gcp_dir / f"{self.cluster_id}_forwarding_rules.json",
            "forwarding rules"
        )

        # Get backend services
        self._run_gcloud(
            ["compute", "backend-services", "list",
             f"--project={self.project_id}", "--format=json"],
            self.gcp_dir / f"{self.cluster_id}_backend_services.json",
            "backend services"
        )

    def _fetch_storage_config(self):
        """Fetch storage configuration"""
        print("\nFetching storage configuration...")

        # Get disk types
        self._run_gcloud(
            ["compute", "disk-types", "list",
             f"--filter=zone:{self.region}-a", f"--project={self.project_id}", "--format=json"],
            self.gcp_dir / f"{self.cluster_id}_disk_types.json",
            "disk types"
        )

        # Get images
        self._run_gcloud(
            ["compute", "images", "list",
             f"--project={self.project_id}", "--filter=name:rhcos", "--format=json"],
            self.gcp_dir / f"{self.cluster_id}_rhcos_images.json",
            "RHCOS images"
        )

    def _fetch_psc_config(self):
        """Fetch Private Service Connect configuration"""
        psc_subnet = self.cluster_json.get('gcp', {}).get('private_service_connect', {}).get('service_attachment_subnet')

        if psc_subnet:
            print("\nFetching Private Service Connect configuration...")

            # Get PSC subnet
            self._run_gcloud(
                ["compute", "networks", "subnets", "describe", psc_subnet,
                 f"--region={self.region}", f"--project={self.project_id}", "--format=json"],
                self.gcp_dir / f"{self.cluster_id}_subnet_psc.json",
                f"PSC subnet {psc_subnet}"
            )

            # Get service attachments
            if self.infra_id:
                self._run_gcloud(
                    ["compute", "service-attachments", "list",
                     f"--project={self.project_id}", f"--regions={self.region}",
                     f"--filter=name~{self.infra_id}", "--format=json"],
                    self.gcp_dir / f"{self.cluster_id}_service_attachments.json",
                    "service attachments"
                )

    def run(self):
        """Main execution flow for GCP data collection"""
        print("="*80)
        print(f"GCP OpenShift Cluster Data Collection: {self.cluster_id}")
        print("="*80)

        # Always fetch cluster info first
        self._fetch_cluster_info()

        # Fetch resources based on --resources argument
        if self._should_collect('quotas'):
            self._fetch_quotas()

        if self._should_collect('apis'):
            self._fetch_apis()

        if self._should_collect('region'):
            self._fetch_region_info()

        if self._should_collect('compute'):
            self._fetch_machine_types()
            self._fetch_instances()

        if self._should_collect('network'):
            self._fetch_network_config()
            self._fetch_firewall_rules()
            self._fetch_dns_config()

        if self._should_collect('iam'):
            self._fetch_iam_config()

        if self._should_collect('loadbalancer'):
            self._fetch_load_balancers()

        if self._should_collect('storage'):
            self._fetch_storage_config()

        if self._should_collect('psc'):
            self._fetch_psc_config()

        print("\n" + "="*80)
        print("Data collection complete!")
        print("="*80)
        print(f"\nData saved to: {self.work_dir}")
        print(f"  GCP resources: {self.gcp_dir}")
        print(f"  OCM data: {self.ocm_dir}")
