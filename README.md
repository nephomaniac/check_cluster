# OpenShift Cluster Health Check

Automated data collection, validation, and reporting for OpenShift clusters on AWS (ROSA) and GCP.

## Quick Start

### AWS/ROSA Clusters

```bash
# Set AWS credentials
eval $(ocm backplane cloud credentials <cluster-id> -o env)

# Run health check
./check_cluster.py <cluster-id>
```

### GCP Clusters

```bash
# Set GCP credentials
gcloud auth login
gcloud config set project <project-id>

# Run health check
./check_cluster.py <cluster-id>
```

## Documentation

**👉 See [CHECK_README.md](CHECK_README.md) for complete usage documentation**

**👉 See [GCP_PORT_SUMMARY.md](GCP_PORT_SUMMARY.md) for GCP-specific information**

---

## Overview

`check_cluster.py` is a unified tool that validates OpenShift clusters on AWS and GCP:

1. **Auto-detects** platform (AWS or GCP) from cluster metadata
2. **Collects** cluster data from OCM and cloud provider APIs
3. **Validates** configuration with 99+ comprehensive tests
4. **Reports** findings in detailed HTML and JSON formats

All in a single command.

## Supported Platforms

- ✅ **AWS** - Red Hat OpenShift Service on AWS (ROSA)
- ✅ **GCP** - OpenShift on Google Cloud Platform

## What It Checks

### AWS/ROSA Clusters (43 tests)
- ✅ AWS prerequisites (VPC endpoints, subnets, CIDR)
- ✅ AWS service quotas (vCPUs, IPs, VPCs)
- ✅ PrivateLink configuration
- ✅ Network infrastructure (VPCs, routes, security groups, NAT)
- ✅ IAM resources and permissions (installer role, operator roles, worker role)
- ✅ Load balancer target health
- ✅ Route53 DNS configuration
- ✅ EC2 instances and volumes
- ✅ Installation diagnostics
- ✅ CloudTrail analysis

### GCP Clusters (56 tests)
- ✅ GCP project quotas (CPUs, IPs, storage, firewall rules)
- ✅ Required APIs enabled (10 APIs)
- ✅ **Firewall rules (CRITICAL: port 22623 for bootstrap)**
- ✅ Network configuration (VPC, subnets, Cloud NAT)
- ✅ Subnet sizing (control plane /28, worker /24)
- ✅ Private Google Access
- ✅ Cloud DNS zones and records (API, API-INT)
- ✅ IAM configuration (WIF or Service Account)
- ✅ Machine types (vCPU/memory requirements)
- ✅ Region and availability zones (3+ for HA)
- ✅ Private Service Connect (PSC)
- ✅ Load balancers and health checks
- ✅ Compute instances
- ✅ Storage disk types (pd-ssd, pd-standard, pd-balanced)
- ✅ RHCOS images

---

## Installation

### Prerequisites

#### Required for All Platforms

```bash
# OCM CLI
ocm login --token=<your-token>

# Python 3.9+ with packages
pip install boto3 pytest pytest-html pytest-json-report

# uv (Python package runner - recommended)
curl -LsSf https://astral.sh/uv/install.sh | sh
```

#### AWS/ROSA Specific

```bash
# AWS CLI v2
aws --version  # Should show AWS CLI 2.x
```

#### GCP Specific

```bash
# gcloud CLI
gcloud --version

# Authenticate
gcloud auth login
gcloud config set project <project-id>
```

### Credentials Setup

#### AWS Credentials

Before each run:

```bash
eval $(ocm backplane cloud credentials <cluster-id> -o env)
```

#### GCP Credentials

```bash
# Option 1: User credentials
gcloud auth login

# Option 2: Service account
gcloud auth activate-service-account --key-file=<path-to-key.json>

# Set project
gcloud config set project <project-id>
```

---

## Usage Examples

```bash
# Full health check (auto-detects platform)
./check_cluster.py <cluster-id>

# Collect data only
./check_cluster.py <cluster-id> --collect

# Test existing data
./check_cluster.py <cluster-id> --test

# Generate report from existing results
./check_cluster.py <cluster-id> --report

# Collect specific resources (AWS)
./check_cluster.py <cluster-id> --collect --resources=instances,vpc,iam

# Collect specific resources (GCP)
./check_cluster.py <cluster-id> --collect --resources=quotas,apis,network

# With custom time window (AWS CloudTrail)
./check_cluster.py <cluster-id> --collect --start 2025-01-20T14:00:00Z --elapsed 6h

# Verbose + debug mode
./check_cluster.py <cluster-id> --verbose --debug

# Run specific test category
pytest tests/ --cluster-dir=<cluster-id> -m firewall

# Run all GCP tests
pytest tests/ --cluster-dir=<cluster-id> -m gcp

# Run all AWS tests
pytest tests/ --cluster-dir=<cluster-id> -m instances
```

---

## Output Structure

```
<cluster-id>/
├── sources/              # Raw data from OCM and cloud provider
│   ├── ocm/             # Cluster configuration from OCM
│   ├── aws/             # AWS resources (ROSA clusters)
│   └── gcp/             # GCP resources (GCP clusters)
└── results/             # Test results and reports
    ├── test_results.json
    └── report_<timestamp>.html
```

---

## Project Structure

```
check_cluster.py          # Main executable - unified health check tool
CHECK_README.md           # Complete usage documentation
GCP_PORT_SUMMARY.md       # GCP-specific documentation
conftest.py               # Pytest configuration and fixtures
pyproject.toml            # Project metadata and pytest markers

├── lib/                  # Data collection modules
│   ├── __init__.py
│   ├── data_collection.py      # AWS/ROSA data collector
│   └── gcp_data_collection.py  # GCP data collector

├── models/               # Data models
│   ├── __init__.py
│   ├── cluster.py             # AWS cluster data model
│   ├── gcp_cluster.py         # GCP cluster data model
│   └── test_result.py

├── tests/                # Pytest validation tests (56 files)
│   ├── __init__.py
│   │
│   ├── # AWS/ROSA Tests (43 tests across 30 files)
│   ├── test_aws_prerequisites.py
│   ├── test_aws_service_quotas.py
│   ├── test_instances.py
│   ├── test_network.py
│   ├── test_vpc.py
│   ├── test_vpc_endpoints.py
│   ├── test_security_groups.py
│   ├── test_privatelink.py
│   ├── test_iam.py
│   ├── test_rosa_iam_resources.py
│   ├── test_rosa_installer_role.py
│   ├── test_rosa_operator_roles.py
│   ├── test_rosa_worker_role.py
│   ├── test_iam_permissions.py
│   ├── test_load_balancers.py
│   ├── test_route53.py
│   ├── test_storage.py
│   ├── test_installation.py
│   ├── test_cloudtrail.py
│   └── ... (more AWS tests)
│   │
│   └── # GCP Tests (56 tests across 13 files)
│       ├── test_gcp_quotas.py         # Project quotas (8 tests)
│       ├── test_gcp_apis.py           # API enablement (11 tests)
│       ├── test_gcp_firewall_rules.py # Firewall rules (15 tests) ⚠️ CRITICAL
│       ├── test_gcp_network.py        # VPC and subnets (11 tests)
│       ├── test_gcp_dns.py            # Cloud DNS (8 tests)
│       ├── test_gcp_iam.py            # IAM and WIF (8 tests)
│       ├── test_gcp_machine_types.py  # Machine types (4 tests)
│       ├── test_gcp_region.py         # Region and zones (5 tests)
│       ├── test_gcp_psc.py            # Private Service Connect (6 tests)
│       ├── test_gcp_load_balancers.py # Load balancers (6 tests)
│       ├── test_gcp_instances.py      # Compute instances (7 tests)
│       ├── test_gcp_storage.py        # Storage types (5 tests)
│       └── test_gcp_rhcos.py          # RHCOS images (5 tests)

├── reporters/            # Report generation
│   ├── __init__.py
│   └── html_generator.py      # HTML report generator

├── utils/                # Utility modules
│   ├── __init__.py
│   ├── data_loader.py
│   ├── request_tracker.py     # AWS API request tracking
│   ├── cloudtrail_correlator.py
│   ├── iam_diagnostics.py
│   ├── installation_diagnostics.py
│   └── test_helpers.py

└── scripts/              # Development scripts
    ├── add_test_documentation.py
    ├── fix_documentation_placement.py
    └── test_documentation_mapping.py
```

---

## Contributing

### Adding New Tests

#### 1. Create Test File

Place test files in the `tests/` directory following naming conventions:

**AWS tests:**
```python
# tests/test_<category>.py
import pytest

@pytest.mark.<marker>
def test_feature_name(cluster_data):
    """Brief description.

    Documentation: <link-to-docs>
    """
    # Test implementation
    assert condition, "Error message"
```

**GCP tests:**
```python
# tests/test_gcp_<category>.py
import pytest

pytestmark = pytest.mark.gcp  # Mark all tests as GCP-specific

@pytest.mark.<marker>
def test_feature_name(gcp_cluster_data):
    """Brief description.

    Documentation: <link-to-docs>
    """
    # Test implementation
    assert condition, "Error message"
```

#### 2. Use Appropriate Fixtures

**AWS/ROSA tests:**
- `cluster_data` - Full AWS cluster data
- `infra_id` - Infrastructure ID
- `is_private_cluster` - Private cluster flag
- `is_privatelink` - PrivateLink flag
- `vpc_cidr` - VPC CIDR

**GCP tests:**
- `gcp_cluster_data` - Full GCP cluster data
- Access: `gcp_cluster_data.project_id`, `gcp_cluster_data.region`, etc.

#### 3. Add Pytest Markers

Available markers (defined in `pyproject.toml`):

**AWS markers:**
- `@pytest.mark.instances` - EC2 instances
- `@pytest.mark.vpc` - VPC configuration
- `@pytest.mark.network` - Network infrastructure
- `@pytest.mark.security_groups` - Security groups
- `@pytest.mark.iam` - IAM roles and policies
- `@pytest.mark.iam_permissions` - IAM permission validation
- `@pytest.mark.privatelink` - PrivateLink configuration
- `@pytest.mark.load_balancers` - Load balancers
- `@pytest.mark.route53` - Route53 DNS
- `@pytest.mark.storage` - EBS storage
- `@pytest.mark.installation` - Installation status
- `@pytest.mark.cloudtrail` - CloudTrail analysis

**GCP markers:**
- `@pytest.mark.gcp` - All GCP tests
- `@pytest.mark.quotas` - Project quotas
- `@pytest.mark.apis` - API enablement
- `@pytest.mark.firewall` - Firewall rules
- `@pytest.mark.dns` - Cloud DNS
- `@pytest.mark.wif` - Workload Identity Federation
- `@pytest.mark.psc` - Private Service Connect

#### 4. Include Documentation Links

Every test should include a docstring with:
- Brief description of what's being tested
- Link to relevant documentation

Example:
```python
def test_control_plane_subnet_size(gcp_cluster_data):
    """Control plane subnet must have adequate size (minimum /28).

    Documentation: https://docs.redhat.com/en/documentation/openshift_container_platform/4.19/html/installing_on_gcp/index#installation-gcp-network-config_installing-gcp-customizations
    """
```

#### 5. Register New Markers

Add new markers to `pyproject.toml`:

```toml
[tool.pytest.ini_options]
markers = [
    "new_marker: Description of what this marker tests",
]
```

### Running Tests During Development

```bash
# Run all tests
pytest tests/ --cluster-dir=<cluster-id>

# Run specific test file
pytest tests/test_gcp_firewall_rules.py --cluster-dir=<cluster-id>

# Run tests with specific marker
pytest tests/ --cluster-dir=<cluster-id> -m firewall

# Run with verbose output
pytest tests/ --cluster-dir=<cluster-id> -v

# Run with debug output
pytest tests/ --cluster-dir=<cluster-id> -vv

# Generate HTML report during development
pytest tests/ --cluster-dir=<cluster-id> --html=report.html --self-contained-html
```

### Adding New Platform Support

To add support for a new cloud platform:

1. **Create data collector**: `lib/<platform>_data_collection.py`
   - Implement `<Platform>DataCollector` class
   - Add methods to collect platform-specific resources
   - Follow pattern from `lib/gcp_data_collection.py`

2. **Create data model**: `models/<platform>_cluster.py`
   - Implement `<Platform>ClusterData` class
   - Provide properties for accessing cluster configuration

3. **Update platform detection**: `check_cluster.py`
   - Add platform detection logic to `detect_platform()`
   - Add platform-specific collector to `run_collection()`

4. **Add pytest fixture**: `conftest.py`
   - Create session-scoped fixture: `<platform>_cluster_data`

5. **Create test files**: `tests/test_<platform>_*.py`
   - Add comprehensive validation tests
   - Use platform-specific markers

6. **Add pytest markers**: `pyproject.toml`
   - Register platform-specific markers

### Code Style

- **Python**: Follow PEP 8
- **Line length**: 120 characters (configured in `pyproject.toml`)
- **Formatting**: Use `black` (optional)
- **Linting**: Use `ruff` (optional)

```bash
# Format code
black check_cluster.py lib/ tests/

# Lint code
ruff check lib/ tests/
```

---

## Development Workflow

### 1. Data Collection Development

```bash
# Test data collection for AWS
./check_cluster.py <cluster-id> --collect --debug

# Test data collection for GCP
./check_cluster.py <gcp-cluster-id> --collect --debug

# Test selective resource collection
./check_cluster.py <cluster-id> --collect --resources=vpc,iam --debug
```

### 2. Test Development

```bash
# Create test file
# tests/test_new_feature.py

# Run new test
pytest tests/test_new_feature.py --cluster-dir=<cluster-id> -v

# Debug test failures
pytest tests/test_new_feature.py --cluster-dir=<cluster-id> -vv --tb=short
```

### 3. Report Generation Development

```bash
# Generate report from existing test results
./check_cluster.py <cluster-id> --report

# View report
open <cluster-id>/results/report_*.html
```

---

## Test Organization

### Test Categories

Tests are organized by:

1. **Platform** (AWS or GCP)
2. **Category** (network, IAM, storage, etc.)
3. **Severity** (critical, high, medium, low)

### Naming Conventions

- **AWS tests**: `test_<category>.py`
- **GCP tests**: `test_gcp_<category>.py`
- **Test functions**: `test_<descriptive_name>`

### Test Documentation

Each test includes:
- Descriptive docstring
- Documentation URL
- Clear assertion messages
- Helpful output on failure

---

## Troubleshooting

### Common Issues

**"Cluster directory does not exist"**
- Run data collection first: `./check_cluster.py <cluster-id> --collect`

**"No AWS credentials found"**
- Set credentials: `eval $(ocm backplane cloud credentials <cluster-id> -o env)`

**"gcloud command not found" (GCP)**
- Install gcloud CLI: https://cloud.google.com/sdk/docs/install

**"Project quotas file not found" (GCP)**
- Run: `./check_cluster.py <cluster-id> --collect --resources=quotas`

**Test failures**
- Check HTML report for detailed diagnostics
- Review CloudTrail events (AWS) or activity logs (GCP)
- Verify cluster is in expected state

### Debug Mode

```bash
# Enable debug output
./check_cluster.py <cluster-id> --debug

# Enable verbose test output
./check_cluster.py <cluster-id> --test --verbose

# Both
./check_cluster.py <cluster-id> --debug --verbose
```

---

## Support

- **Usage help**: See [CHECK_README.md](CHECK_README.md)
- **GCP information**: See [GCP_PORT_SUMMARY.md](GCP_PORT_SUMMARY.md)
- **Troubleshooting**: Check HTML report diagnostics
- **Issues**: Review test results and cloud provider activity logs

---

## License

Internal Red Hat tool for OpenShift cluster diagnostics.
