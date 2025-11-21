# ROSA Cluster Health Check Tools

Automated data collection and health validation tools for Red Hat OpenShift Service on AWS (ROSA) clusters.

## Overview

This repository contains two complementary tools for ROSA cluster troubleshooting and analysis:

1. **`get_install_artifacts.sh`** - Data collection script
2. **`check_aws_health.py`** - Health validation and analysis script

Together, these tools provide comprehensive cluster diagnostics for installation failures, networking issues, and post-mortem analysis.

---

## Quick Start

```bash
# 1. Refresh AWS credentials
eval $(ocm backplane cloud credentials <cluster-id> -o env)

# 2. Collect cluster data
./get_install_artifacts.sh -c <cluster-id>

# 3. Run health check analysis
python3 check_aws_health.py

# OR: Run health check from anywhere with explicit directory
python3 check_aws_health.py -d /path/to/cluster/data
```

---

## Tool 1: get_install_artifacts.sh

### Purpose

Automated data collection script that gathers comprehensive AWS infrastructure and OpenShift cluster installation artifacts.

### What It Collects

- **OCM cluster metadata** (`cluster.json`, `resources.json`)
- **VPC details and DNS attributes** (`vpc-*.json`, DNS attribute files)
- **DHCP Options Sets** (`dhcp_*.json`)
- **VPC Endpoint Services** (PrivateLink clusters)
- **EC2 instances and console logs** (`ec2_instances.json`, console logs)
- **Load Balancers** (`LB_*.json`)
- **Route53 DNS records** (API and apps record sets)
- **Security Groups** (`security_groups.json`)
- **CloudTrail audit logs** (2-hour window from cluster creation)

### Usage

```bash
# Display help
./get_install_artifacts.sh --help

# Collect data for a cluster
./get_install_artifacts.sh -c <clusterid>
```

### Options

- `-c, --cluster <cluster-id>` - Specify cluster ID to collect data for
- `-h, --help` - Display help message

### Prerequisites

- `ocm` CLI (authenticated)
- `aws` CLI v2
- Valid AWS credentials: `eval $(ocm backplane cloud credentials <cluster-id> -o env)`
- Required tools: `jq`, `python3`, `gdate` (macOS: `brew install coreutils`)

### Output Files

All files created in current directory with naming pattern:
```
{cluster_id}_{resource_type}.json
{cluster_id}_{resource_id}_{resource_type}.json
```

Examples:
```
<clusterid>_cluster.json
<clusterid>_vpc-0c103a233aa875f9b_VPC.json
<clusterid>_ec2_instances.json
<clusterid>_cloudtrail.json
```

### Features

- **Idempotent** - Safe to run multiple times
- **Efficient** - Reuses existing files (no redundant API calls)
- **Self-documenting** - Echoes all commands before execution
- **Error-tolerant** - Continues on individual failures

---

## Tool 2: check_aws_health.py

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
/path/to/get_install_artifacts.sh -c <cluster-id>

# Step 5: Run health check (two options)

# Option A: Run from cluster data directory
python3 /path/to/check_aws_health.py

# Option B: Run from anywhere with directory argument
python3 /path/to/check_aws_health.py -d ~/troubleshooting/<cluster-name>

# Step 6: Review results
cat results_*.md
```

### Failed Installation Workflow

```bash
# 1. Collect data immediately after failure
eval $(ocm backplane cloud credentials <cluster-id> -o env)
./get_install_artifacts.sh -c <cluster-id>

# 2. Run automated health check
python3 check_aws_health.py

# 3. Check for critical issues
grep "ERROR" results_*.md

# 4. Analyze CloudTrail events
grep "Cluster-Impacting" results_*.md

# 5. Review bootstrap instance logs
cat <cluster-id>_i-*_console.log | grep -i error
```

---

## Integration

### With check_aws_health.py

`get_install_artifacts.sh` collects **all data files** that `check_aws_health.py` analyzes:

| check_aws_health.py Function | Files Required | Provided by get_install_artifacts.sh |
|------------------------------|----------------|--------------------------------------|
| `check_vpc_dns_attributes()` | VPC files, DNS attributes | ✅ Lines 52-98 |
| `check_dhcp_options()` | VPC files, DHCP options | ✅ Lines 88-96 |
| `check_vpc_endpoint_service()` | VPC endpoint service, connections | ✅ Lines 267-312 |
| `check_security_groups()` | Security groups JSON | ✅ Lines 436-452 |
| `check_instances()` | EC2 instances JSON | ✅ Lines 324-351 |
| `check_load_balancers()` | Load balancer JSON files | ✅ Lines 202-257, 454-481 |
| `check_route53()` | Hosted zones, record sets | ✅ Lines 390-434 |
| `check_cloudtrail_logs()` | CloudTrail events JSON | ✅ Lines 369-388 |
| `check_installation_status()` | Cluster JSON, resources JSON | ✅ Lines 20-44 |

---

## Documentation

### Available Documentation Files

- **`README.md`** (this file) - Overview and quick start
- **`get_install_artifacts_SUMMARY.md`** - Detailed get_install_artifacts.sh documentation
- **`get_install_artifacts_UPDATES.md`** - Recent updates and changes to get_install_artifacts.sh

### Future Documentation

See individual validation functions in `check_aws_health.py` for detailed implementation notes and validation logic.

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
- Bash 4.0+
- Python 3.7+

### CLI Tools
- `ocm` - OpenShift Cluster Manager CLI
- `aws` - AWS CLI v2
- `jq` - JSON processor
- `python3` - Python 3 interpreter
- `gdate` - GNU date (macOS: `brew install coreutils`)

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

### Issue: "missing cluster id?"
**Solution**: Use `-c` or `--cluster` flag:
```bash
./get_install_artifacts.sh -c <cluster-id>
```

### Issue: "Failed to get cluster from ocm?"
**Solutions**:
1. Check OCM authentication: `ocm whoami`
2. Verify cluster ID: `ocm list clusters`
3. Check permissions

### Issue: AWS API errors
**Solutions**:
1. Refresh credentials: `eval $(ocm backplane cloud credentials <cluster-id> -o env)`
2. Verify credentials: `aws sts get-caller-identity`
3. Check AWS permissions

### Issue: "No cluster files found"
**Solution**: Run `get_install_artifacts.sh` first to collect data files

### Issue: Missing DHCP/VPC endpoint data
**Solution**: The script will provide AWS CLI commands to collect missing data:
```bash
aws ec2 describe-dhcp-options --dhcp-options-ids <dhcp-id> > <file>
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

### Adding Data Collection to get_install_artifacts.sh

To collect new AWS resources:

1. Add AWS CLI command in appropriate section
2. Save to file with naming pattern: `{cluster_id}_{resource_type}.json`
3. Check for existing file before fetching (idempotent)
4. Update documentation

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

### Current Version (2025-11-20)
- **NEW**: Added directory argument (`-d/--directory`) to check_aws_health.py
  - Run health checks from any directory
  - Specify source directory for cluster data files
  - Maintains backward compatibility (default: current directory)
- Added cluster_context.json integration
  - Network configuration validation
  - Jira issues tracking
  - Handover announcements display
  - Support exceptions and PD alerts monitoring
- Added VPC DNS attributes validation
- Added DHCP Options validation
- Added VPC Endpoint Service validation (PrivateLink)
- Added argument parsing to get_install_artifacts.sh
- Added comprehensive help functionality
- Added CloudTrail event correlation with resource-specific filtering
- Enhanced security group validation with public/private mismatch detection

### Previous Features
- Initial release with basic health checks
- CloudTrail log collection
- Security group validation
- EC2 instance validation
- Load balancer validation
- Route53 validation
- Installation status validation
