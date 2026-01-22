# GCP OpenShift Cluster Validations

## Summary

This document summarizes GCP checks.

## What's Implemented

### 1. ✅ GCP Data Collection Module (`lib/gcp_data_collection.py`)
- Collects GCP cluster data using `gcloud` CLI
- Fetches OCM cluster configuration
- Resources collected:
  - Project quotas
  - Enabled APIs
  - Region/zone information
  - Machine types
  - Network configuration (VPC, subnets, routes, Cloud NAT)
  - Firewall rules
  - DNS zones and records
  - IAM policies and WIF configuration
  - Compute instances
  - Load balancers
  - Storage configuration
  - Private Service Connect (PSC) configuration
- Supports selective resource collection via `--resources` flag

### 2. ✅ Platform Detection (`check_cluster.py`)
- Auto-detects cluster platform (AWS vs GCP) from OCM metadata
- Uses appropriate data collector based on platform
- Backward compatible with existing AWS/ROSA clusters

### 3. ✅ GCP Cluster Data Model (`models/gcp_cluster.py`)
- Structured access to GCP cluster data
- Provides convenient properties for:
  - Project ID, region, infra ID
  - VPC and subnet configuration
  - Authentication type (WIF vs Service Account)
  - Private cluster and PSC flags

### 4. ✅ Pytest Integration
- GCP-specific fixture: `gcp_cluster_data`
- New pytest markers:
  - `@pytest.mark.gcp` - All GCP tests
  - `@pytest.mark.quotas` - Quota validation
  - `@pytest.mark.apis` - API enablement
  - `@pytest.mark.firewall` - Firewall rules
  - `@pytest.mark.dns` - DNS configuration
  - `@pytest.mark.wif` - Workload Identity Federation
  - `@pytest.mark.psc` - Private Service Connect

### 5. ✅ GCP Quotas Tests (`tests/test_gcp_quotas.py`)
Complete quota validation for:
- CPUs (minimum 24 for 3 control plane + 2 workers)
- IP addresses (IN_USE_ADDRESSES, STATIC_ADDRESSES)
- SSD storage (500GB minimum)
- Firewall rules
- Forwarding rules (load balancers)
- Routes

## Remaining Work

### Test Files to Create

Based on `gcp_cluster_validator.sh`, the following test files should be created:

#### 1. `tests/test_gcp_apis.py`
Validate required GCP APIs are enabled:
- compute.googleapis.com
- cloudapis.googleapis.com
- cloudresourcemanager.googleapis.com
- dns.googleapis.com
- iamcredentials.googleapis.com
- iam.googleapis.com
- servicemanagement.googleapis.com
- serviceusage.googleapis.com
- storage-api.googleapis.com
- storage-component.googleapis.com

**Template:**
```python
@pytest.mark.gcp
@pytest.mark.apis
def test_compute_api_enabled(gcp_cluster_data):
    """Compute Engine API must be enabled.

    Documentation: https://cloud.google.com/compute/docs/api/libraries
    """
    apis_file = gcp_cluster_data.gcp_dir / f"{gcp_cluster_data.cluster_id}_enabled_apis.json"
    # Check if compute.googleapis.com is in enabled APIs
```

#### 2. `tests/test_gcp_firewall_rules.py` ⚠️ CRITICAL
Validate comprehensive firewall rules for OpenShift:
1. ICMP (internal cluster communication)
2. Port 22623/TCP (Machine Config Server) - **CRITICAL FOR BOOTSTRAP**
3. Port 22624/TCP (MCS alternate)
4. Port 6443/TCP (Kubernetes API Server)
5. Ports 2379-2380/TCP (etcd)
6. Port 4789/UDP (VXLAN overlay)
7. Port 6081/UDP (Geneve overlay - OVN)
8. Ports 9000-9999/TCP (host services)
9. Port 10250/TCP (kubelet)
10. Port 10256/TCP (openshift-sdn)
11. Ports 10257-10259/TCP (Kubernetes control plane)
12. Ports 30000-32767/TCP+UDP (NodePort services)

**Reference:** https://docs.redhat.com/en/documentation/openshift_container_platform/4.16/html/installation_configuration/configuring-firewall

#### 3. `tests/test_gcp_network.py`
Network configuration validation:
- VPC exists and is accessible
- Control plane subnet (minimum /27, /28 acceptable)
- Worker subnet (minimum /23, /24 limited)
- Private Google Access enabled
- Cloud NAT configured (for private clusters)
- VPC routes (default internet route)

#### 4. `tests/test_gcp_dns.py`
DNS configuration:
- Private DNS zone exists (`{infra_id}-private-zone`)
- Zone visibility is `private`
- Zone attached to cluster VPC
- API A record exists (`api.{cluster_name}.{base_domain}`)

#### 5. `tests/test_gcp_iam.py`
IAM configuration based on auth type:

**For WIF (Workload Identity Federation):**
- WIF config exists and is valid
- Service accounts have required permissions
- `ocm gcp verify wif-config` passes

**For Service Account Key:**
- Service account has required roles:
  - roles/compute.admin
  - roles/iam.securityAdmin
  - roles/iam.serviceAccountAdmin
  - roles/iam.serviceAccountUser
  - roles/iam.serviceAccountKeyAdmin
  - roles/storage.admin
  - roles/dns.admin

#### 6. `tests/test_gcp_machine_types.py`
Machine type validation:
- Control plane: Minimum 4 vCPUs, 16GB RAM
- Worker nodes: Minimum 4 vCPUs, 16GB RAM
- Common types: n2-standard-4, n2-standard-8, etc.

#### 7. `tests/test_gcp_region.py`
Region and zone validation:
- Region status is 'UP'
- Minimum 3 availability zones for HA
- All zones are operational

#### 8. `tests/test_gcp_psc.py`
Private Service Connect validation (if enabled):
- PSC subnet exists
- Subnet purpose is PRIVATE_SERVICE_CONNECT
- Subnet CIDR is minimum /29
- Service attachments configured

#### 9. `tests/test_gcp_load_balancers.py`
Load balancer configuration:
- Internal load balancer exists
- Load balancer IP matches DNS
- Backend services configured
- Health checks configured

#### 10. `tests/test_gcp_instances.py`
Compute instances:
- Expected number of instances
- Instance status
- Bootstrap instance diagnostics (serial port output)

#### 11. `tests/test_gcp_storage.py`
Storage configuration:
- pd-ssd (SSD Persistent Disk) available
- pd-standard available
- pd-balanced available

#### 12. `tests/test_gcp_rhcos.py`
RHCOS image validation:
- RHCOS images available in project (or installer will import)

## Usage

### Collect GCP Cluster Data
```bash
./check_cluster.py <gcp-cluster-id> --collect
```

### Collect Specific Resources
```bash
./check_cluster.py <gcp-cluster-id> --collect --resources=quotas,apis,network
```

Available resources:
- `quotas` - Project quotas
- `apis` - Enabled APIs
- `region` - Region/zone information
- `compute` - Machine types and instances
- `network` - VPC, subnets, firewall, DNS
- `iam` - IAM policies and WIF config
- `loadbalancer` - Load balancers
- `storage` - Disk types and images
- `psc` - Private Service Connect
- `all` - All resources (default)

### Run GCP Tests
```bash
./check_cluster.py <gcp-cluster-id> --test
```

### Run Specific GCP Test Categories
```bash
# Run only quota tests
pytest tests/ --cluster-dir=<cluster-id> -m quotas

# Run only firewall tests
pytest tests/ --cluster-dir=<cluster-id> -m firewall

# Run all GCP tests
pytest tests/ --cluster-dir=<cluster-id> -m gcp
```

### Generate Report
```bash
./check_cluster.py <gcp-cluster-id> --report
```

### End-to-End
```bash
./check_cluster.py <gcp-cluster-id> --all
```

## GCP Documentation Mapping

For the documentation URL mapping script (`scripts/test_documentation_mapping.py`), add:

```python
DOCUMENTATION_MAPPING = {
    # ... existing AWS mappings ...

    # GCP-specific
    "gcp_quotas": "https://cloud.google.com/compute/quotas",
    "gcp_apis": "https://cloud.google.com/apis/docs/getting-started",
    "gcp_firewall_rules": "https://docs.redhat.com/en/documentation/openshift_container_platform/4.16/html/installation_configuration/configuring-firewall",
    "gcp_network": "https://docs.redhat.com/en/documentation/openshift_container_platform/4.19/html/installing_on_gcp/index#installation-gcp-network-config_installing-gcp-customizations",
    "gcp_dns": "https://cloud.google.com/dns/docs",
    "gcp_iam": "https://docs.redhat.com/en/documentation/openshift_container_platform/4.19/html/installing_on_gcp/index#installation-gcp-permissions_installing-gcp-customizations",
    "gcp_wif": "https://docs.redhat.com/en/documentation/openshift_container_platform/4.19/html/installing_on_gcp/index#using-gcp-workload-identity",
    "gcp_psc": "https://cloud.google.com/vpc/docs/private-service-connect",
    "gcp_machine_types": "https://docs.redhat.com/en/documentation/openshift_container_platform/4.19/html/installing_on_gcp/index#installation-gcp-limits_installing-gcp-customizations",
}
```

## Key Differences from AWS/ROSA

1. **Authentication**: GCP uses WIF (Workload Identity Federation) or Service Account Keys, not IAM roles like AWS
2. **Networking**: GCP uses Cloud NAT instead of NAT Gateways
3. **DNS**: Cloud DNS managed zones instead of Route53
4. **Firewall**: Firewall rules instead of Security Groups
5. **Load Balancers**: GCP forwarding rules and backend services
6. **Quotas**: Different quota system with regional vs global quotas
7. **Port 22623**: Critical for bootstrap - must allow from GCP health check IPs (35.191.0.0/16, 130.211.0.0/22)

## Critical Validations

Based on the bash script, these are the most critical validations that prevent installation:

1. **Port 22623 accessibility from GCP health checks** - Bootstrap will fail without this
2. **Sufficient CPU quota** - Installation cannot proceed
3. **Required APIs enabled** - Installation will fail immediately
4. **VPC subnets sized correctly** - IP exhaustion will cause failures
5. **DNS zone configured** - API access depends on this
6. **Machine types meet minimums** - Nodes won't function properly

## Testing Strategy

1. Create GCP test cluster data from real GCP cluster
2. Test with both WIF and Service Account authentication
3. Test with installer-provisioned and BYO VPC
4. Test private and public clusters
5. Test with and without PSC

## Migration Path from Bash Script

For teams currently using `gcp_cluster_validator.sh`:

1. Install check_cluster.py and dependencies
2. Run data collection: `./check_cluster.py <cluster-id> --collect`
3. Run tests: `./check_cluster.py <cluster-id> --test`
4. View HTML report with detailed diagnostics

Benefits:
- Structured test framework with pytest
- HTML reports with documentation links
- Selective resource collection
- Better error messages
- Integration with CI/CD

## References

- OpenShift on GCP Installation: https://docs.redhat.com/en/documentation/openshift_container_platform/4.19/html/installing_on_gcp/index
- GCP Firewall Configuration: https://docs.redhat.com/en/documentation/openshift_container_platform/4.16/html/installation_configuration/configuring-firewall
- GCP Prerequisites: https://docs.redhat.com/en/documentation/openshift_container_platform/4.19/html/installing_on_gcp/index#installation-gcp-network-config_installing-gcp-customizations
- Workload Identity Federation: https://cloud.google.com/iam/docs/workload-identity-federation
