# ROSA Cluster Health Check Tool

Unified tool for collecting, validating, and reporting on ROSA cluster health.

## Table of Contents

- [Quick Start](#quick-start)
- [Overview](#overview)
- [Prerequisites](#prerequisites)
- [Usage](#usage)
- [Common Workflows](#common-workflows)
- [Command Reference](#command-reference)
- [What Gets Tested](#what-gets-tested)
- [Output Structure](#output-structure)
- [Troubleshooting](#troubleshooting)
- [Examples](#examples)

---

## Quick Start

```bash
# 1. Set AWS credentials
eval $(ocm backplane cloud credentials <cluster-id> -o env)

# 2. Run complete health check
./check_cluster.py <cluster-id>
```

This will:
1. ✅ Collect cluster data from OCM and AWS
2. ✅ Run all validation tests
3. ✅ Generate HTML and JSON reports
4. ✅ Save everything to `<cluster-id>/` directory

---

## Overview

`check_cluster.py` consolidates three operations into a single unified tool:

1. **Data Collection** - Fetches cluster configuration and AWS resources
2. **Validation Testing** - Runs comprehensive health checks
3. **Report Generation** - Creates detailed HTML and JSON reports

By default, all three operations run in sequence. Individual operations can be run separately using `--collect`, `--test`, or `--report` flags.

---

## Prerequisites

Before running, ensure you have:

### Required Tools

1. **OCM CLI** (logged in)
   ```bash
   ocm login --token=<your-token>
   ```

2. **AWS CLI v2**
   ```bash
   aws --version  # Should show AWS CLI 2.x
   ```

3. **Python 3.9+** with required packages
   ```bash
   pip install boto3 pytest pytest-html pytest-json-report
   ```

4. **uv** (Python package runner)
   ```bash
   curl -LsSf https://astral.sh/uv/install.sh | sh
   ```

### AWS Credentials

Before each run, set AWS credentials for the cluster's account:

```bash
eval $(ocm backplane cloud credentials <cluster-id> -o env)
```

This sets the required environment variables:
- `AWS_ACCESS_KEY_ID`
- `AWS_SECRET_ACCESS_KEY`
- `AWS_SESSION_TOKEN`
- `AWS_REGION`

---

## Usage

### Basic Syntax

```bash
./check_cluster.py <cluster-id> [options]
```

### Default Behavior (All Operations)

Running without operation flags executes all three phases:

```bash
./check_cluster.py <cluster-id>
```

Equivalent to:
```bash
./check_cluster.py <cluster-id> --collect --test --report
```

### Individual Operations

Run specific operations:

```bash
# Collect data only
./check_cluster.py <cluster-id> --collect

# Test existing data
./check_cluster.py <cluster-id> --test

# Generate report from existing results
./check_cluster.py <cluster-id> --report
```

---

## Common Workflows

### 1. First-Time Health Check

```bash
eval $(ocm backplane cloud credentials <cluster-id> -o env)
./check_cluster.py <cluster-id>
```

### 2. Collect Data with Custom Time Window

Specify CloudTrail time range for investigation:

```bash
./check_cluster.py <cluster-id> --collect \
  --start 2025-01-20T14:00:00Z \
  --elapsed 6h
```

### 3. Re-run Tests on Existing Data

After collecting data once, you can re-run tests without re-collecting:

```bash
./check_cluster.py <cluster-id> --test
```

### 4. Update Report Only

Regenerate HTML report from existing test results:

```bash
./check_cluster.py <cluster-id> --report
```

### 5. Test Different Cluster Data

Test data from a different location:

```bash
./check_cluster.py <cluster-id> --test --output-dir /path/to/cluster/data
```

### 6. Verbose + Debug Mode

Get detailed output for troubleshooting:

```bash
./check_cluster.py <cluster-id> --verbose --debug
```

---

## Command Reference

### Operations

| Flag | Description |
|------|-------------|
| `--collect` | Collect cluster data from OCM and AWS |
| `--test` | Run validation tests |
| `--report` | Generate HTML report |
| `--all` | Run all operations (default) |

### Collection Options

| Flag | Description |
|------|-------------|
| `-r, --region <region>` | AWS region (default: from cluster.json) |
| `-s, --start <date>` | CloudTrail start date (YYYY-MM-DDTHH:MM:SSZ) |
| `-e, --elapsed <time>` | CloudTrail window (e.g., "3h", "2d", "4days") |
| `-p, --period <seconds>` | CloudWatch metrics period (default: 300) |
| `--force-update` | Force recalculation of time range |
| `--debug` | Enable debug output (AWS commands, proxy config) |

### Test Options

| Flag | Description |
|------|-------------|
| `--tests-only` | Run tests without HTML report generation |
| `-v, --verbose` | Verbose test output |

### Output Options

| Flag | Description |
|------|-------------|
| `-d, --output-dir <dir>` | Output directory (default: `<cluster-id>/`) |
| `--json-output <file>` | JSON results path |
| `--html-output <file>` | HTML report path |

---

## What Gets Tested?

The tool runs **43 test files** covering comprehensive cluster health validation:

### ✅ AWS Prerequisites
- S3 gateway endpoint exists in VPC
- Minimum private subnets per availability zone
- Machine CIDR matches VPC CIDR
- Route table associations
- PrivateLink VPC requirements

### ✅ Service Quotas
- EC2 vCPU quotas (32 for HCP, 100 for Classic)
- EBS storage quotas (300 TiB)
- ELB service role exists
- Network bandwidth requirements (120 Mbps)

### ✅ PrivateLink Configuration (if applicable)
- VPC endpoint service exists
- Required VPC endpoints (S3, EC2, ELB, STS)
- Interface endpoints have private DNS enabled
- Endpoints in all availability zones
- S3 gateway endpoint route table associations

### ✅ Network Infrastructure
- VPC configuration and CIDR blocks
- Subnet configuration (public/private)
- NAT gateways (non-PrivateLink clusters)
- Internet gateways
- Route tables and routes
- Security groups and traffic rules

### ✅ IAM Resources
- ROSA IAM roles exist
- Installer role permissions
- Worker node role permissions
- Operator roles configuration
- OIDC provider setup

### ✅ Load Balancers
- Load balancer configuration
- Target group health
- Listener configuration
- Registered targets

### ✅ EC2 Instances
- Master node health
- Worker node health
- Bootstrap node status
- Instance configuration

### ✅ Installation Diagnostics
- Cluster status
- Bootstrap progress
- API server availability
- Installation error detection
- Console log analysis

### ✅ CloudTrail Analysis
- AWS API errors
- Permission issues
- Event timeline correlation
- Failed API calls

### ✅ Storage
- EBS volumes
- Storage configuration

### ✅ Route53
- DNS configuration
- Hosted zones

### ✅ Autoscaling
- Auto Scaling Groups
- Launch templates

---

## Output Structure

After running, you'll find:

```
<cluster-id>/
├── sources/                        # Raw data from OCM and AWS
│   ├── ocm/                       # OCM cluster configuration
│   │   ├── <cluster-id>_cluster.json
│   │   ├── <cluster-id>_install_logs.json
│   │   └── ...
│   └── aws/                       # AWS resource data
│       ├── <cluster-id>_vpc_*.json
│       ├── <cluster-id>_subnets.json
│       ├── <cluster-id>_instances.json
│       ├── <cluster-id>_security_groups.json
│       ├── <cluster-id>_service_quotas.json
│       ├── <cluster-id>_vpc_endpoints.json
│       ├── <cluster-id>_cloudtrail_*.json
│       └── ... (many more resources)
└── results/                       # Test results and reports
    ├── test_results.json          # Detailed test results (JSON)
    └── report_<timestamp>.html    # HTML report
```

### Key Files

- **`sources/ocm/<cluster-id>_cluster.json`** - Complete cluster configuration from OCM
- **`sources/aws/<cluster-id>_vpc_endpoints.json`** - VPC endpoints (critical for PrivateLink)
- **`sources/aws/<cluster-id>_service_quotas.json`** - AWS service quotas
- **`results/test_results.json`** - All test results with metadata
- **`results/report_<timestamp>.html`** - Formatted HTML report with diagnostics

---

## Troubleshooting

### "No AWS credentials found"

**Problem**: AWS credentials not set

**Solution**:
```bash
eval $(ocm backplane cloud credentials <cluster-id> -o env)
```

### "Permission denied" errors

**Problem**: AWS credentials lack required permissions

**Solutions**:
1. Verify you're using the correct cluster account
2. Check credentials haven't expired
3. Try refreshing credentials:
   ```bash
   eval $(ocm backplane cloud credentials <cluster-id> -o env)
   ```

### "VPC endpoints file not found"

**Problem**: Trying to run tests without collecting data first

**Solution**:
```bash
./check_cluster.py <cluster-id> --collect
```

### "'uv' command not found"

**Problem**: uv package runner not installed

**Solution**:
```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
```

### Tests are skipped

**This is normal**. Tests skip when features aren't applicable:
- PrivateLink tests skip for non-PrivateLink clusters
- NAT gateway tests skip for PrivateLink clusters
- Some tests skip if data files aren't available

Check the HTML report for skip reasons.

### Import errors

**Problem**: Missing Python dependencies

**Solution**:
```bash
pip install boto3 pytest pytest-html pytest-json-report
```

### Proxy issues

**Problem**: Corporate proxy blocking AWS API calls

**Solution**: Use `--debug` to see proxy configuration:
```bash
./check_cluster.py <cluster-id> --collect --debug
```

Check `~/.aws/config` for proxy settings.

---

## Examples

### Example 1: Quick Health Check

```bash
# Most common use case
eval $(ocm backplane cloud credentials abc123xyz -o env)
./check_cluster.py abc123xyz
```

**Output**:
- Data in `abc123xyz/sources/`
- Tests in `abc123xyz/results/test_results.json`
- Report in `abc123xyz/results/report_<timestamp>.html`

### Example 2: Investigation with Custom Time Range

```bash
# Collect data for specific incident time
eval $(ocm backplane cloud credentials abc123xyz -o env)
./check_cluster.py abc123xyz --collect \
  --start 2025-01-20T14:00:00Z \
  --elapsed 6h
```

### Example 3: Re-run Tests After Code Changes

```bash
# Don't re-collect data, just re-run tests
./check_cluster.py abc123xyz --test
```

### Example 4: Test Data from Different Location

```bash
# Test data stored elsewhere
./check_cluster.py abc123xyz --test \
  --output-dir /shared/clusters/abc123xyz
```

### Example 5: Regenerate Report with Custom Path

```bash
# Generate new report from existing results
./check_cluster.py abc123xyz --report \
  --json-output abc123xyz/results/test_results.json \
  --html-output /tmp/cluster_report.html
```

### Example 6: Debug Mode for Troubleshooting

```bash
# Verbose test output + debug collection
./check_cluster.py abc123xyz --verbose --debug
```

### Example 7: Collect Only for Offline Analysis

```bash
# Collect data to analyze later on different system
eval $(ocm backplane cloud credentials abc123xyz -o env)
./check_cluster.py abc123xyz --collect

# Later, on different system:
./check_cluster.py abc123xyz --test --output-dir ./abc123xyz
```

---

## Understanding Test Results

### Test Status Meanings

- **PASSED** ✅ - Configuration is correct
- **FAILED** ❌ - Configuration issue detected
- **SKIPPED** ⊘ - Test not applicable (e.g., PrivateLink test on non-PrivateLink cluster)

### HTML Report Sections

1. **Summary** - Overall test statistics
2. **Failed Tests** - Issues requiring attention
3. **Test Results** - All test details
4. **AWS API Errors** - Failed API calls with diagnostics
5. **CloudTrail Events** - Timeline of AWS actions
6. **Resource Details** - Raw data inspection

### JSON Test Results

The JSON file contains:
- Test outcomes with metadata
- AWS API errors encountered
- CloudTrail events
- User properties (custom test data)

Access programmatically:
```python
import json

with open('results/test_results.json') as f:
    data = json.load(f)

print(f"Total tests: {data['summary']['total']}")
print(f"Passed: {data['summary']['passed']}")
print(f"Failed: {data['summary']['failed']}")
```

---

## Support and Next Steps

### Getting Help

1. Check the HTML report for detailed diagnostics
2. Review JSON test results for raw data
3. Run with `--debug` for troubleshooting
4. Examine CloudTrail events in the report

### Common Next Steps After Health Check

1. **For PrivateLink cluster installation failures**:
   - Check for missing S3 gateway endpoint
   - Verify EC2, ELB, STS interface endpoints exist
   - Ensure endpoints have Private DNS enabled

2. **For service quota issues**:
   - Request quota increases via AWS Service Quotas console
   - Focus on EC2 vCPU quotas first (most common blocker)

3. **For IAM permission issues**:
   - Review IAM role policies in test results
   - Check CloudTrail for `AccessDenied` errors
   - Validate OIDC provider configuration

4. **For network issues**:
   - Verify route table configurations
   - Check security group rules
   - Ensure NAT gateways exist (non-PrivateLink) or VPC endpoints (PrivateLink)

### Further Reading

- ROSA Documentation: https://docs.redhat.com/en/documentation/red_hat_openshift_service_on_aws
- AWS Service Quotas: https://docs.aws.amazon.com/servicequotas/
- PrivateLink Architecture: See test output for endpoint requirements

---

## Project Structure

```
check_cluster.py           # Main executable
CHECK_README.md           # This file
├── lib/                  # Supporting libraries
│   └── data_collection.py
├── tests/                # Pytest validation tests (43 files)
├── reporters/            # HTML report generation
├── utils/                # Utility modules
├── models/               # Data models
└── old_scripts/          # Archived legacy scripts (not maintained)
```

**Note**: Files in `old_scripts/` are deprecated and will be removed. All functionality is now in `check_cluster.py`.
