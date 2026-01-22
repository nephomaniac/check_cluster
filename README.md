# ROSA Cluster Health Check

Automated data collection, validation, and reporting for Red Hat OpenShift Service on AWS (ROSA) clusters.

## Quick Start

```bash
# Set AWS credentials
eval $(ocm backplane cloud credentials <cluster-id> -o env)

# Run health check
./check_cluster.py <cluster-id>
```

## Documentation

**👉 See [CHECK_README.md](CHECK_README.md) for complete usage documentation**

## Overview

`check_cluster.py` is a unified tool that:

1. **Collects** cluster data from OCM and AWS APIs
2. **Validates** configuration with 43 comprehensive tests
3. **Reports** findings in detailed HTML and JSON formats

All in a single command.

## What It Checks

- ✅ AWS prerequisites (VPC endpoints, subnets, CIDR, quotas)
- ✅ PrivateLink configuration
- ✅ Network infrastructure (VPCs, routes, security groups)
- ✅ IAM resources and permissions
- ✅ Installation diagnostics
- ✅ CloudTrail analysis

## Installation

### Prerequisites

```bash
# OCM CLI
ocm login --token=<your-token>

# Python packages
pip install boto3 pytest pytest-html pytest-json-report

# uv (Python package runner)
curl -LsSf https://astral.sh/uv/install.sh | sh
```

### AWS Credentials

Before each run:

```bash
eval $(ocm backplane cloud credentials <cluster-id> -o env)
```

## Usage Examples

```bash
# Full health check (collect + test + report)
./check_cluster.py <cluster-id>

# Collect data only
./check_cluster.py <cluster-id> --collect

# Test existing data
./check_cluster.py <cluster-id> --test

# With custom time window
./check_cluster.py <cluster-id> --collect --start 2025-01-20T14:00:00Z --elapsed 6h

# Verbose + debug mode
./check_cluster.py <cluster-id> --verbose --debug
```

## Output

```
<cluster-id>/
├── sources/           # Raw data from OCM and AWS
│   ├── ocm/          # Cluster configuration
│   └── aws/          # AWS resources
└── results/          # Test results and reports
    ├── test_results.json
    └── report_<timestamp>.html
```

## Project Structure

```
check_cluster.py       # Main executable - unified health check tool
CHECK_README.md        # Complete usage documentation
├── lib/              # Supporting libraries
│   └── data_collection.py
├── tests/            # Pytest validation tests (43 files)
├── reporters/        # HTML report generation
├── utils/            # Utility modules
├── models/           # Data models
└── old_scripts/      # Archived legacy scripts (deprecated)
```

## Support

- **Usage help**: See [CHECK_README.md](CHECK_README.md)
- **Troubleshooting**: Check HTML report diagnostics
- **Issues**: Review test results and CloudTrail events

## License

Internal Red Hat tool for ROSA cluster diagnostics.
