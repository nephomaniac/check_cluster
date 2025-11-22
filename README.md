# ROSA Cluster Health Check Tools

Automated data collection and health validation tools for Red Hat OpenShift Service on AWS (ROSA) clusters.

---

## 📑 Table of Contents

- [Overview](#overview)
- [Installation](#installation)
- [Quick Start](#quick-start)
- **Tools & Features**
  - [Tool 1: get_install_artifacts.py](#tool-1-get_install_artifactspy-python-version---recommended)
  - [Tool 2: check_cluster_artifacts.py](#tool-2-check_cluster_artifactspy)
  - [Validation Coverage](#validation-coverage)
- **Usage & Integration**
  - [Workflow Examples](#workflow)
  - [Integration with Test Framework](#integration)
  - [Common Use Cases](#common-use-cases)
- **Reference**
  - [Documentation](#documentation)
  - [Requirements](#requirements)
  - [Troubleshooting](#troubleshooting)
  - [Contributing](#contributing)
- **Additional Resources**
  - [Related Documentation](#related-documentation)
  - [Version History](#version-history)
  - [Support](#support)

---

## Overview

This repository contains two complementary tools for ROSA cluster troubleshooting and analysis:

1. **`get_install_artifacts.py`** - Python-based data collection script using boto3
2. **`check_cluster_artifacts.py`** - Health validation and analysis script with interactive HTML reports
3. **`run_tests.py`** - Modern pytest-based health check framework with interactive HTML reporting

Together, these tools provide comprehensive cluster diagnostics for installation failures, networking issues, and post-mortem analysis.

**Note**: A bash version `get_install_artifacts.sh` is also available for environments without Python, but the Python version is recommended for better error handling and additional features.

---

## Installation

### Using uv (Recommended - Fast!)

```bash
# Install uv if you haven't already
curl -LsSf https://astral.sh/uv/install.sh | sh

# Create a virtual environment and install dependencies
uv venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install dependencies
uv pip install -r requirements.txt
```

### Using pip (Traditional)

```bash
# Create a virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### Using uv run (No venv needed!)

```bash
# Run directly with uv (automatically manages dependencies)
uv run get_install_artifacts.py -c <cluster-id>
uv run check_cluster_artifacts.py -d .
```

---

## Quick Start

### With uv (recommended):

```bash
# 1. Refresh AWS credentials
eval $(ocm backplane cloud credentials <cluster-id> -o env)

# 2. Collect cluster data (Python version - recommended)
uv run get_install_artifacts.py -c <cluster-id>

# 3. Run health check analysis (new pytest-based tool)
python run_tests.py --cluster-dir .

# OR: Legacy script (still available)
uv run check_cluster_artifacts.py -d .
```

### Traditional method:

```bash
# 1. Refresh AWS credentials
eval $(ocm backplane cloud credentials <cluster-id> -o env)

# 2. Collect cluster data
python3 get_install_artifacts.py -c <cluster-id>

# 3. Run health check analysis
# New pytest-based tool (recommended):
python3 run_tests.py --cluster-dir /path/to/cluster/data

# OR: Legacy monolithic script:
python3 check_cluster_artifacts.py -d /path/to/cluster/data
```

---

## Tool 1: get_install_artifacts.py (Python Version - Recommended)

### Purpose

Automated data collection script using boto3 for AWS API calls. Gathers comprehensive AWS infrastructure and OpenShift cluster installation artifacts with better error handling and extensibility than the bash version.

### What It Collects

**Core Resources:**
- **OCM cluster metadata** (`cluster.json`, `resources.json`, `cluster_context.json`)
- **VPC details and DNS attributes** (`vpc-*.json`, DNS attribute files)
- **DHCP Options Sets** (`dhcp_*.json`)
- **VPC Endpoint Services** (PrivateLink clusters)
- **EC2 instances and console logs** (`ec2_instances.json`, console logs)
- **Security Groups** (`security_groups.json`)
- **CloudTrail audit logs** (configurable time window, default 2 hours)

**Network Infrastructure (New):**
- **Subnets** (overall and per-zone for multi-AZ)
- **Route Tables** (IGW and NAT routes)
- **Internet Gateways** (public cluster connectivity)
- **NAT Gateways** (overall and per-zone for multi-AZ)
- **Network Interfaces** (ENI details)
- **Network ACLs** (additional filtering layer)
- **Elastic IPs** (NAT and LB public IPs)
- **VPC Peering Connections**
- **VPC Flow Logs**

**Load Balancers:**
- **Application Load Balancers (ALBv2)** with tags
- **Classic Load Balancers (ELB)**
- **Target Groups** (backend configuration)
- **Target Health** (per target group health checks)

**Storage & DNS:**
- **EBS Volumes** (overall and per-zone for multi-AZ)
- **Route53 Hosted Zones** (private and public)
- **Route53 Record Sets** (API and apps DNS)

**Multi-AZ Support:**
- When `multi_az=true`, collects zone-specific artifacts for each availability zone

### Key Advantages Over Bash Version

- **Uses boto3** for AWS operations instead of AWS CLI
- **Prints AWS CLI equivalents** before each boto3 call for transparency
- **Better error handling** with detailed exception messages
- **Object-oriented design** for maintainability
- **Type hints** for better code clarity
- **Automatic retry logic** for CloudWatch metrics (3 attempts, 1 second delay)

### Usage

```bash
# Display help
./get_install_artifacts.py --help
# Or with uv
uv run get_install_artifacts.py --help

# Basic collection (default 2-hour window)
uv run get_install_artifacts.py -c <cluster-id>

# Custom time window
uv run get_install_artifacts.py -c <cluster-id> -s 2025-01-15T10:30:00Z -e 3h

# Collect in specific directory
uv run get_install_artifacts.py -c <cluster-id> -d /path/to/data

# Force recalculation of time range
uv run get_install_artifacts.py -c <cluster-id> --force-update
```

### Options

- `-c, --cluster <cluster-id>` - ROSA cluster ID (required)
- `-d, --dir <directory>` - Working directory (default: current directory)
- `-s, --start <date>` - Start date (YYYY-MM-DDTHH:MM:SSZ)
- `-e, --elapsed <time>` - Time window (e.g., "3h", "2days", "30m")
- `-p, --period <seconds>` - CloudWatch metrics period (default: 300)
- `-f, --force-update` - Force recalculation of time range
- `--debug` - Enable debug output (proxy config, AWS commands, etc.)
- `-h, --help` - Display help message

### Prerequisites

- **Python 3.8+**
- **boto3**: `pip install boto3` or `uv pip install boto3`
- **OCM CLI** (authenticated)
- **AWS credentials**: `eval $(ocm backplane cloud credentials <cluster-id> -o env)`
- **osdctl** (optional): For cluster context

### Example AWS CLI Command Printing

Before each boto3 call, the equivalent AWS CLI command is printed:

```bash
aws cloudwatch get-metric-statistics --namespace AWS/EC2 --metric-name CPUUtilization --dimensions Name=InstanceId,Value=i-1234567890abcdef0 --start-time 2025-01-15T10:00:00Z --end-time 2025-01-15T12:00:00Z --period 300 --statistics Average --output json
```

This makes it easy to:
- Understand what operations are being performed
- Debug AWS API issues
- Manually rerun commands if needed

### Time Range Behavior

#### Automatic Reuse
If `last_run.json` exists and no time arguments are provided, automatically reuses the previous time range.

#### Ready vs Non-Ready Clusters
- **Ready clusters**: Uses current time window (now - elapsed to now)
- **Non-ready clusters**: Uses cluster creation time + elapsed window

#### Custom Time Windows
- `3h` or `3hours` - 3 hours
- `30m` or `30minutes` - 30 minutes
- `2d` or `2days` - 2 days

---

## Tool 2: check_cluster_artifacts.py

### Purpose

Automated health validation script that analyzes collected AWS data and identifies cluster issues.

### What It Validates

#### 1. **Installation Status**
- Cluster state (ready, error, installing)
- ProvisionFailed conditions
- Bootstrap instance status

#### 2. **VPC DNS Attributes**
- `enableDnsHostnames` must be `true`
- `enableDnsSupport` must be `true`
- Required for private Route53 zones

#### 3. **DHCP Options**
- Domain name must be lowercase (Kubernetes requirement)
- Domain name must not contain spaces (CoreOS bug #1934)

#### 4. **VPC Endpoint Service (PrivateLink)**
- Exactly 1 VPC Endpoint Service must exist
- Service state must be "Available"
- At least 1 available VPC Endpoint connection required

#### 5. **Security Groups**
- Required security groups present (lb, node, controlplane)
- Required ingress rules (ports 6443, 22623, etc.)
- Public/Private cluster configuration mismatch detection
- Access validation based on cluster type

#### 6. **EC2 Instances**
- Instance states (running, stopped, terminated)
- Role identification (bootstrap, master, worker, infra)

#### 7. **Load Balancers**
- Load balancer states (active, provisioning, failed)
- Cluster-specific load balancers

#### 8. **Route53 DNS**
- Hosted zones exist
- API and apps DNS records configured

#### 9. **CloudTrail Logs**
- Delete/Revoke/Stop/Terminate events
- Cluster-impacting operations
- Event correlation with failures

### Usage

```bash
# Run in current directory (default)
python3 check_aws_health.py

# Run on cluster data in a specific directory
python3 check_aws_health.py -d /path/to/cluster/data
python3 check_aws_health.py --directory ~/clusters/my-cluster

# Display help
python3 check_aws_health.py --help
```

The script automatically:
1. Detects cluster ID from local files (or specified directory)
2. Loads cluster metadata
3. Runs all health checks
4. Generates markdown report

**Options**:
- `-d, --directory` - Source directory containing cluster JSON and log files (default: current directory)
- `-h, --help` - Display help message with examples

### Output

**Terminal Output**:
- Color-coded status messages (✓ OK, ⚠ WARNING, ✗ ERROR)
- Detailed validation results
- Remediation commands for failures
- CloudTrail event correlation

**Markdown Report**: `results_<timestamp>.md`
- Complete health check summary
- Collapsible sections for detailed analysis
- AWS CLI commands for missing data
- Cluster impact analysis

### Example Output

```
================================================================================
                    VPC DNS Attributes Health Check
================================================================================

✓ OK: enableDnsHostnames is enabled for vpc-0c103a233aa875f9b
✓ OK: enableDnsSupport is enabled for vpc-0c103a233aa875f9b
✓ OK: All VPC DNS attributes are correctly configured
```

### Features

- **Comprehensive validation** - Based on mirrosa cluster validation patterns
- **Smart resource correlation** - Links CloudTrail events to specific failures
- **Missing data detection** - Provides AWS CLI commands to collect missing files
- **Context-aware analysis** - Understands PrivateLink vs. public clusters
- **Offline analysis** - Works entirely from local JSON files

---

## Validation Coverage

### Implemented ✅

1. **VPC DNS Attributes** - `enableDnsHostnames`, `enableDnsSupport`
2. **DHCP Options** - Domain-name lowercase and space validation
3. **VPC Endpoint Service** - PrivateLink cluster endpoint validation
4. **Security Groups** - Required rules and public/private mismatch detection
5. **EC2 Instances** - State and role validation
6. **Load Balancers** - State validation
7. **Route53** - DNS record presence
8. **CloudTrail** - Destructive operation detection and correlation
9. **Installation Status** - Cluster state and failure conditions

### Based on mirrosa

The validations are based on the [mirrosa](https://github.com/openshift/mirrosa) tool patterns:
- `vpc.go` - VPC DNS attributes (lines 52-118)
- `dhcp_option_set.go` - DHCP domain-name validation (lines 45-88)
- `vpcendpointservice.go` - VPC Endpoint Service validation (lines 49-146)
- `securitygroup.go` - Security group rules validation
- `instances.go` - EC2 instance validation

---

## Workflow

### Standard Troubleshooting Workflow

```bash
# Step 1: Authenticate with OCM
ocm login --token <your-token>

# Step 2: Get cluster ID
ocm list clusters | grep <cluster-name>

# Step 3: Refresh AWS credentials
eval $(ocm backplane cloud credentials <cluster-id> -o env)

# Step 4: Collect cluster data
mkdir -p ~/troubleshooting/<cluster-name>
cd ~/troubleshooting/<cluster-name>
python3 /path/to/get_install_artifacts.py -c <cluster-id>

# Step 5: Run health check (two options)

# Option A: New pytest-based framework (recommended)
python3 /path/to/run_tests.py --cluster-dir .
# View interactive HTML report: open test_report.html

# Option B: Legacy monolithic script
python3 /path/to/check_cluster_artifacts.py
# View markdown report: cat results_*.md
```

### Failed Installation Workflow

```bash
# 1. Collect data immediately after failure
eval $(ocm backplane cloud credentials <cluster-id> -o env)
python3 get_install_artifacts.py -c <cluster-id>

# 2. Run automated health check
python3 run_tests.py --cluster-dir .

# 3. View interactive HTML report
open test_report.html

# 4. Review bootstrap instance logs
cat <cluster-id>_i-*_console.log | grep -i error

# 5. Check CloudTrail events JSON
cat <cluster-id>_*.cloudtrail.json | jq '.[] | select(.EventName | contains("Revoke", "Delete", "Terminate"))'
```

---

## Integration

### With check_aws_health.py

`get_install_artifacts.py` collects **all data files** that `check_aws_health.py` analyzes:

| check_aws_health.py Function | Files Required | Provided by get_install_artifacts.py |
|------------------------------|----------------|--------------------------------------|
| `check_vpc_dns_attributes()` | VPC files, DNS attributes | ✅ `_populate_vpc_info_files()` |
| `check_dhcp_options()` | VPC files, DHCP options | ✅ `_populate_vpc_info_files()` |
| `check_vpc_endpoint_service()` | VPC endpoint service, connections | ✅ `_get_vpc_endpoint_service_info()` |
| `check_security_groups()` | Security groups JSON | ✅ `_get_security_groups_info()` |
| `check_instances()` | EC2 instances JSON | ✅ `_get_ec2_instance_info()` |
| `check_load_balancers()` | Load balancer JSON files | ✅ `_get_load_balancers_info()` |
| `check_route53()` | Hosted zones, record sets | ✅ `_get_route53_info()` |
| `check_cloudtrail_logs()` | CloudTrail events JSON | ✅ `_get_cloud_trail_logs()` |
| `check_installation_status()` | Cluster JSON, resources JSON | ✅ `_get_ocm_cluster_info()` |

### With Pytest Test Framework

`get_install_artifacts.py` also collects **all data files** that the pytest test framework requires:

| Test Module | Files Required | Provided by get_install_artifacts.py |
|-------------|----------------|--------------------------------------|
| `test_security_groups.py` | Security groups JSON | ✅ `_get_security_groups_info()` |
| `test_vpc.py` | VPC files, DNS attributes, DHCP options | ✅ `_populate_vpc_info_files()`, `_get_network_infrastructure()` |
| `test_instances.py` | EC2 instances JSON, zone-specific instances | ✅ `_get_ec2_instance_info()`, `_collect_zone_specific_artifacts()` |
| `test_load_balancers.py` | Load balancers, target groups, target health | ✅ `_get_load_balancers_info()` |
| `test_route53.py` | Hosted zones, record sets | ✅ `_get_route53_info()` |
| `test_cloudtrail.py` | CloudTrail events JSON | ✅ `_get_cloud_trail_logs()` |
| `test_installation.py` | Cluster JSON, resources JSON | ✅ `_get_ocm_cluster_info()` |

### Additional Infrastructure Data (New)

Beyond the legacy checks, `get_install_artifacts.py` now collects comprehensive infrastructure data:

| Resource Type | Collection Method | Use Case |
|--------------|-------------------|----------|
| Subnets | `_get_network_infrastructure()` | Multi-AZ subnet validation |
| Route Tables | `_get_network_infrastructure()` | IGW and NAT routing validation |
| Internet Gateways | `_get_network_infrastructure()` | Public cluster connectivity |
| NAT Gateways | `_get_network_infrastructure()` | Private subnet egress |
| Network Interfaces | `_get_network_infrastructure()` | ENI attachment details |
| Network ACLs | `_get_network_infrastructure()` | Network filtering layer |
| Elastic IPs | `_get_network_infrastructure()` | NAT gateway IPs |
| VPC Peering | `_get_network_infrastructure()` | VPC peering validation |
| VPC Flow Logs | `_get_network_infrastructure()` | Network monitoring |
| EBS Volumes | `_get_network_infrastructure()` | etcd volume validation |
| Target Groups | `_get_load_balancers_info()` | LB backend health |
| Target Health | `_get_load_balancers_info()` | Backend instance health |
| Classic ELBs | `_get_load_balancers_info()` | Legacy load balancer support |
| Zone-specific artifacts* | `_collect_zone_specific_artifacts()` | Multi-AZ HA validation |

\* **Multi-AZ clusters only**: When `multi_az=true`, collects per-zone subnets, NAT gateways, instances, and volumes

---

## Documentation

### 📚 Main Documentation

This repository contains comprehensive documentation for different use cases and tools:

| Document | Description | Audience |
|----------|-------------|----------|
| **[README.md](README.md)** (this file) | Main documentation covering data collection tools and validation framework | All users |
| **[PYTEST_README.md](PYTEST_README.md)** | Comprehensive pytest-based health check framework guide | Developers, SREs running health checks |
| **[QUICKSTART_UV.md](QUICKSTART_UV.md)** | Quick start guide using `uv` for fast dependency management | New users, those wanting fastest setup |

### 🔧 Component Documentation

For implementation details and extending the tools:

| Component | Location | Purpose |
|-----------|----------|---------|
| **Data Collection** | `get_install_artifacts.py` | Boto3-based AWS resource collection with 30+ resource types |
| **Test Framework** | `tests/` directory | 63 pytest tests across 7 categories (security groups, VPC, instances, etc.) |
| **Data Models** | `models/cluster.py` | ClusterData model for unified artifact access |
| **HTML Reports** | `reporters/html_generator.py` | Interactive HTML report generation from pytest JSON results |
| **Test Fixtures** | `conftest.py` | Session-scoped pytest fixtures for efficient data loading |

### 📖 Quick Reference Guides

**For New Users:**
1. Start with [QUICKSTART_UV.md](QUICKSTART_UV.md) for the fastest setup using `uv`
2. Use the [Quick Start](#quick-start) section below for traditional Python setup
3. Review [Workflow Examples](#workflow) for common troubleshooting scenarios

**For Developers:**
1. Read [PYTEST_README.md](PYTEST_README.md) for test framework architecture
2. See [Contributing](#contributing) section for adding new validations or data collection
3. Review [Integration](#integration) section for understanding data flow

**For SREs:**
1. Use [Workflow Examples](#workflow) for operational procedures
2. Check [Troubleshooting](#troubleshooting) for common issues
3. See [Common Use Cases](#common-use-cases) for specific scenarios

### 🗂️ Legacy Documentation

The following documentation is for legacy bash-based tools (deprecated):

- **`claude_updates/get_install_artifacts_SUMMARY.md`** - Bash script reference (use Python version instead)
- **Generated reports** - HTML/Markdown reports are created in working directory after running health checks

---

## Common Use Cases

### 1. Cluster Installation Failure Investigation
Collects all resources involved in cluster creation to identify bootstrap failures, network issues, or permission problems.

### 2. Post-Mortem Analysis
Provides complete snapshot of cluster state at creation time, including CloudTrail audit trail showing who did what.

### 3. Network Troubleshooting
Gathers VPC, security group, load balancer, and DNS data to diagnose connectivity issues.

### 4. Public/Private Configuration Mismatch
Detects when public clusters have restrictive security groups or private clusters have public access rules.

### 5. PrivateLink Validation
Validates VPC Endpoint Service configuration required for Hive/backplane management of PrivateLink clusters.

### 6. Compliance Auditing
CloudTrail logs show all API calls during cluster creation for security and compliance review.

---

## Requirements

### System Requirements
- macOS or Linux
- Python 3.8+ (for get_install_artifacts.py and run_tests.py)
- Bash 4.0+ (optional, only for legacy get_install_artifacts.sh)

### CLI Tools
- `ocm` - OpenShift Cluster Manager CLI (required)
- `aws` - AWS CLI v2 (optional, only for manual queries)
- `jq` - JSON processor (recommended for manual data analysis)
- `python3` - Python 3 interpreter
- `pytest` - Python testing framework (install via `uv pip install pytest pytest-json-report`)

### AWS Permissions

**OCM API**:
- Read cluster metadata
- Read cluster resources/logs

**AWS API**:
- `ec2:DescribeVpcs`
- `ec2:DescribeVpcAttribute`
- `ec2:DescribeDhcpOptions`
- `ec2:DescribeInstances`
- `ec2:DescribeSecurityGroups`
- `ec2:DescribeVpcEndpointServiceConfigurations`
- `ec2:DescribeVpcEndpointConnections`
- `ec2:GetConsoleOutput`
- `elasticloadbalancing:DescribeLoadBalancers`
- `elasticloadbalancing:DescribeTags`
- `route53:ListHostedZones`
- `route53:ListResourceRecordSets`
- `cloudtrail:LookupEvents`

---

## Troubleshooting

### Issue: "missing cluster id?" or "Cluster ID is required"
**Solution**: Use `-c` or `--cluster` flag:
```bash
python3 get_install_artifacts.py -c <cluster-id>
```

### Issue: "Failed to get cluster from ocm?"
**Solutions**:
1. Check OCM authentication: `ocm whoami`
2. Verify cluster ID: `ocm list clusters`
3. Check permissions

### Issue: AWS API errors or "UnauthorizedOperation"
**Solutions**:
1. Refresh credentials: `eval $(ocm backplane cloud credentials <cluster-id> -o env)`
2. Verify credentials: `aws sts get-caller-identity`
3. Check AWS permissions (see AWS Permissions section above)
4. Enable debug mode: `python3 get_install_artifacts.py -c <cluster-id> --debug`

### Issue: "No cluster files found" (pytest tests)
**Solution**: Run `get_install_artifacts.py` first to collect data files:
```bash
python3 get_install_artifacts.py -c <cluster-id>
```

### Issue: Missing boto3 module
**Solution**: Install Python dependencies:
```bash
uv pip install -r requirements.txt
# or
pip install boto3
```

### Issue: Proxy or SSL certificate errors
**Solution**: Configure proxy settings in `~/.aws/config`:
```ini
[default]
https_proxy = http://proxy.example.com:8080
ca_bundle = /path/to/ca-bundle.crt
```

---

## Contributing

### Adding New Validations

To add a new validation to `check_aws_health.py`:

1. **Add validation function**:
   ```python
   def check_new_resource(cluster_id: str, infra_id: str = None) -> Tuple[str, List[str]]:
       """
       Check new resource health
       """
       print_header("New Resource Health Check")
       issues = []

       # Validation logic here

       if not issues:
           return ("OK", [])
       else:
           return ("ERROR", issues)
   ```

2. **Update main() function**:
   ```python
   results['new_resource'] = check_new_resource(cluster_id, infra_id)
   ```

3. **Update markdown TOC**:
   ```python
   full_markdown.append("X. [New Resource Health Check](#new-resource-health-check)\n")
   ```

### Adding Data Collection to get_install_artifacts.py

To collect new AWS resources:

1. Add a new `describe_*` method to the `AWSCollector` class:
   ```python
   def describe_new_resource(self, filters: List[Dict] = None) -> Dict:
       """Describe new resource"""
       params = {}
       if filters:
           params['Filters'] = filters

       print(format_aws_cli_command('ec2', 'describe-new-resource', params))
       try:
           return self.ec2.describe_new_resource(**params)
       except (self.ClientError, self.BotoCoreError) as e:
           self._handle_aws_error(e, 'describe new resource')
   ```

2. Add collection logic to `ClusterDataCollector` (e.g., in `_get_network_infrastructure()`):
   ```python
   new_resource_file = f"{self.file_prefix}_new_resource.json"
   if Path(new_resource_file).exists():
       Colors.green(f"Using existing file: {new_resource_file}")
   else:
       Colors.blue("Fetching new resource from AWS...")
       try:
           response = self.aws.describe_new_resource(
               filters=[{'Name': 'tag:Name', 'Values': [f'*{self.infra_id}*']}]
           )
           with open(new_resource_file, 'w') as f:
               json.dump(response, f, indent=2, default=str)
       except Exception as e:
           Colors.perr(f"Failed to fetch new resource: {str(e)}")
   ```

3. File naming pattern: `{cluster_id}_{resource_type}.json`
4. Always check for existing file before fetching (idempotent)
5. Update README.md Integration section and PYTEST_README.md

---

## Related Documentation

### Getting Started
- **[Quick Start with uv](QUICKSTART_UV.md)** - Fastest way to get started with automatic dependency management
  - No virtual environment setup needed
  - 10-100x faster than pip
  - Automatic dependency resolution
  - Complete workflow examples

### Testing and Validation
- **[Pytest Health Check Framework](PYTEST_README.md)** - Modern pytest-based validation framework
  - 63 individual tests across 7 categories
  - Interactive HTML report generation
  - Modular test organization
  - How to add new tests and extend the framework
  - Test results interpretation guide

### Development References
- **Test Modules**: See `tests/` directory for individual test implementations
  - `test_security_groups.py` - Traffic flow validation (13 tests)
  - `test_vpc.py` - Network configuration (6 tests)
  - `test_instances.py` - EC2 instance health (10 tests)
  - `test_load_balancers.py` - Load balancer validation (11 tests)
  - `test_route53.py` - DNS configuration (5 tests)
  - `test_cloudtrail.py` - Event analysis (6 tests)
  - `test_installation.py` - Cluster status (12 tests)

- **Data Collection**: `get_install_artifacts.py`
  - 30+ AWS resource types
  - Multi-AZ zone-specific collection
  - Automatic time range management
  - Proxy and CA bundle support

- **Models**: `models/` directory
  - `cluster.py` - ClusterData model
  - `test_result.py` - Test result structures

---

## License

See repository license file.

---

## Support

For issues, questions, or contributions:
- File an issue in the repository
- Contact the ROSA SRE team

---

## Version History

### v2.0.0 (2025-11-21) - Pytest Framework & Enhanced Collection
- **NEW**: Pytest-based health check framework
  - 63 individual tests across 7 categories
  - Session-scoped fixtures for efficient data loading
  - Interactive HTML report generation
  - Modular test organization (separate files per category)
  - See PYTEST_README.md for details

- **Enhanced Data Collection** (get_install_artifacts.py):
  - Added 13 new AWS resource types (subnets, route tables, NAT gateways, target groups, etc.)
  - Multi-AZ zone-specific artifact collection
  - Automatic time range reuse from last_run.json
  - Proxy and CA bundle support from ~/.aws/config
  - Debug mode with detailed credential information
  - AWS CLI command printing before each boto3 call

- **Improved Validation**:
  - Directory argument for check_cluster_artifacts.py
  - Cluster context integration (network config, Jira issues)
  - VPC DNS attributes, DHCP options, VPC Endpoint Service checks
  - CloudTrail event correlation with resource-specific filtering
  - Enhanced security group validation with public/private mismatch detection

### v1.0.0 - Initial Release
- Basic health checks in monolithic script (check_cluster_artifacts.py)
- Bash-based data collection (get_install_artifacts.sh)
- CloudTrail log collection
- Security group, EC2, Load Balancer, Route53 validation
- Installation status validation
