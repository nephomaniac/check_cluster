# ROSA Cluster Health Check Tool - Pytest Architecture

A modern pytest-based health check tool for validating ROSA (Red Hat OpenShift Service on AWS) cluster configurations.

## Overview

This tool analyzes ROSA cluster artifacts collected from AWS and validates the cluster configuration against expected best practices and requirements. It generates detailed test reports in both JSON and interactive HTML formats.

**Note**: This is the new pytest-based architecture that replaces the legacy `check_cluster_artifacts.py` monolithic script.

## Architecture

The project follows a clean separation of concerns:

```
check_cluster/
├── models/                     # Data models
│   ├── cluster.py             # ClusterData model for all cluster information
│   └── test_result.py         # Test result data models
├── tests/                      # Pytest test modules
│   ├── test_security_groups.py   # Security group traffic validation (13 tests)
│   ├── test_vpc.py               # VPC DNS and network configuration (6 tests)
│   ├── test_instances.py         # EC2 instance health checks (10 tests)
│   ├── test_load_balancers.py    # Load balancer configuration (11 tests)
│   ├── test_route53.py           # Route53 DNS validation (5 tests)
│   ├── test_cloudtrail.py        # CloudTrail event analysis (6 tests)
│   └── test_installation.py      # Cluster installation status (12 tests)
├── reporters/                  # Report generation
│   └── html_generator.py      # HTMLReportGenerator class
├── utils/                      # Utility functions
│   └── data_loader.py         # Load cluster JSON files
├── conftest.py                 # Pytest fixtures and configuration
├── run_tests.py                # Main entry point
└── requirements.txt            # Python dependencies
```

## Features

### Test Categories

1. **Security Groups** (`test_security_groups.py`) - 13 tests
   - Validates required traffic flows for cluster operation
   - Checks API server access (tcp/6443)
   - Verifies Machine Config Server access (tcp/22623)
   - Validates worker node communication (SSH, kubelet, NodePorts)
   - Checks overlay networking (VXLAN, Geneve)
   - Validates egress traffic
   - Optional etcd port checks

2. **VPC Configuration** (`test_vpc.py`) - 6 tests
   - Validates VPC existence and state
   - Checks DNS hostname and DNS support settings
   - Verifies CIDR block configuration
   - Validates DHCP options association

3. **EC2 Instances** (`test_instances.py`) - 10 tests
   - Validates instance existence and running state
   - Checks control plane HA (3 instances)
   - Verifies worker node health
   - Validates private IPs and VPC membership
   - Checks security group attachments
   - Validates cluster ownership tags
   - Verifies IAM instance profiles

4. **Load Balancers** (`test_load_balancers.py`) - 11 tests
   - Validates API load balancer existence and health
   - Checks load balancer scheme (public/private)
   - Verifies listener configuration (ports 6443, 22623)
   - Validates multi-AZ deployment
   - Checks security group attachments
   - Verifies DNS name configuration

5. **Route53 DNS** (`test_route53.py`) - 5 tests
   - Validates hosted zone existence
   - Checks private zone configuration for private clusters
   - Verifies API DNS record
   - Validates name server configuration
   - Checks cluster domain configuration

6. **CloudTrail Events** (`test_cloudtrail.py`) - 6 tests
   - Analyzes security group modification events
   - Detects security group rule revocations
   - Checks for excessive API errors
   - Validates event timestamps and user identity

7. **Installation Status** (`test_installation.py`) - 12 tests
   - Validates cluster ID and infrastructure ID
   - Checks cluster state (ready/installed/active)
   - Verifies OpenShift version
   - Validates AWS region configuration
   - Checks API and console URLs
   - Verifies node configuration
   - Validates network configuration
   - Checks multi-AZ deployment

### Pytest Fixtures

All tests use session-scoped fixtures for efficient data loading:

- `cluster_dir`: Path to cluster data directory (from --cluster-dir argument)
- `cluster_data`: Loaded ClusterData object with all artifacts
- `infra_id`: Infrastructure ID for the cluster
- `is_private_cluster`: Boolean indicating if cluster has private API
- `vpc_cidr`: VPC CIDR block

### HTML Report Generator

The `HTMLReportGenerator` class creates interactive HTML reports with:

- Summary dashboard showing total/passed/failed/skipped counts
- Pass rate calculation
- Category-based organization with collapsible sections
- Color-coded status indicators
- Test duration metrics
- Detailed failure messages
- Responsive design with modern UI

## Installation

### Prerequisites

```bash
# Install dependencies using uv (recommended)
uv pip install -r requirements.txt

# Or using pip
pip install -r requirements.txt
```

### Required Packages

- pytest>=7.0.0
- pytest-json-report>=1.5.0
- boto3>=1.26.0 (for data collection)

## Usage

### Running Tests with run_tests.py

The main entry point provides a convenient interface for running tests and generating reports.

#### Basic usage:
```bash
python run_tests.py --cluster-dir <path-to-cluster-data>
```

#### Examples:
```bash
# Run tests for broken cluster
python run_tests.py --cluster-dir broken

# Run with verbose output
python run_tests.py --cluster-dir new_good --verbose

# Custom output paths
python run_tests.py --cluster-dir broken \
  --json-output results/broken.json \
  --html-output reports/broken.html

# Run tests only (no HTML report)
python run_tests.py --cluster-dir broken --tests-only

# Generate HTML from existing JSON results
python run_tests.py --cluster-dir broken --report-only
```

### Using Pytest Directly

For more control, you can run pytest directly:

```bash
# Run all tests
pytest tests/ --cluster-dir broken -v

# Run specific test module
pytest tests/test_security_groups.py --cluster-dir broken -v

# Run tests with specific marker
pytest -m security_groups --cluster-dir broken -v

# Run tests matching pattern
pytest -k "api_server" --cluster-dir broken -v

# Generate JSON report manually
pytest tests/ --cluster-dir broken \
  --json-report --json-report-file=results.json -v
```

### Output Files

- `test_results.json`: Pytest JSON report with detailed test results
- `test_report.html`: Interactive HTML report with visualizations

## Test Results Examples

### Broken Cluster
```
22 failed, 24 passed, 14 skipped

Key failures detected:
- Cluster state: error
- Missing API security group rules (tcp/6443, tcp/22623)
- VPC DNS settings disabled
- Load balancer configuration issues
```

### Good Cluster
```
16 failed, 31 passed, 13 skipped

Failures are mostly related to:
- Data format compatibility
- Optional configuration checks
- Single-AZ test cluster (not production HA)
```

## Data Collection

This tool expects cluster data to be collected using the companion `get_install_artifacts.py` script. Required files:

- `<cluster-id>_cluster.json` - Core cluster configuration
- `<cluster-id>_security_groups.json` - Security group rules
- `<cluster-id>_ec2_instances.json` - EC2 instance data
- `<cluster-id>_load_balancers_all.json` - Load balancer configuration
- `<cluster-id>_VPC_IDS.json` - VPC configuration
- `<cluster-id>_hosted_zones.json` - Route53 zones (optional)
- `<cluster-id>_*.cloudtrail.json` - CloudTrail events (optional)

## Extending the Tests

### Adding New Tests

1. Create new test function in appropriate test module:
```python
@pytest.mark.security_groups
def test_my_new_check(cluster_data: ClusterData):
    """Description of what this test validates"""
    # Get data
    sgs = cluster_data.get_security_groups_by_infra_id()

    # Validate
    assert condition, "Failure message with details"
```

2. Use existing fixtures for data access:
```python
def test_example(cluster_data: ClusterData, infra_id: str, is_private_cluster: bool):
    # Access cluster data
    infra_id = cluster_data.infra_id
    is_private = cluster_data.is_private

    # Perform validation
    assert condition, "Error message"
```

### Adding New Test Categories

1. Create new test module: `tests/test_<category>.py`
2. Add pytest marker in `conftest.py`:
```python
config.addinivalue_line("markers", "category: Description")
```
3. Implement tests using existing patterns
4. Tests will automatically appear in HTML report

### Adding Custom Fixtures

Add fixtures to `conftest.py`:

```python
@pytest.fixture(scope="session")
def my_custom_fixture(cluster_data: ClusterData) -> Any:
    """Custom fixture description"""
    return cluster_data.some_data
```

## HTML Report Features

The generated HTML report includes:

### Summary Section
- Total tests count
- Pass/fail/skip breakdown
- Overall pass rate percentage
- Visual summary cards with color coding

### Category Sections
- Collapsible sections for each test category
- Per-category statistics (passed/failed/skipped)
- Color-coded headers (green=pass, red=fail)
- Individual test results in table format

### Test Details
- Test name (human-readable)
- Status badge (PASS/FAIL/SKIP)
- Duration for each test
- Detailed failure messages
- Hover effects for better readability

### Interactive Features
- Click category headers to expand/collapse
- All categories expanded by default
- Smooth animations
- Responsive design

## Development

### Project Dependencies

- **pytest**: Testing framework
- **pytest-json-report**: JSON report generation
- **boto3**: AWS SDK (for data collection only)

### Code Organization

- **models/**: Data classes for cluster artifacts and test results
- **tests/**: Individual pytest test modules organized by category
- **reporters/**: HTML and report generation logic
- **utils/**: Data loading and utility functions
- **conftest.py**: Pytest configuration and shared test fixtures
- **run_tests.py**: Command-line interface for running tests

### Running Tests During Development

```bash
# Run tests with immediate output
pytest tests/ --cluster-dir broken -v -s

# Run specific test
pytest tests/test_security_groups.py::test_api_server_access --cluster-dir broken -v

# Run with debugger on failure
pytest tests/ --cluster-dir broken --pdb

# Show local variables in tracebacks
pytest tests/ --cluster-dir broken --tb=long
```

## Migration from Legacy Script

This pytest-based architecture replaces the monolithic `check_cluster_artifacts.py` script with:

### Benefits

- ✅ **Modular organization**: Each category in its own file
- ✅ **Standard framework**: Uses pytest conventions
- ✅ **Reusable fixtures**: Shared data loading across tests
- ✅ **Clean separation**: Models, tests, reporters separated
- ✅ **Extensible**: Easy to add new test categories
- ✅ **Better reporting**: Detailed failure messages with context
- ✅ **Interactive HTML**: Modern, responsive web interface
- ✅ **Individual tests**: Each check is a separate test function
- ✅ **Parallel execution**: Tests can run in parallel (future)
- ✅ **Standard tooling**: Works with pytest plugins

### Migration Notes

- No backward compatibility with old script format
- Same validation logic, cleaner implementation
- Test coverage expanded (63 total tests vs ~40 checks)
- Better error messages with specific file/line references
- HTML report more interactive than previous version

## Troubleshooting

### Common Issues

#### "No cluster files found"
**Solution**: Run `get_install_artifacts.py` first to collect cluster data

#### "AttributeError: 'list' object has no attribute 'get'"
**Cause**: Data format mismatch between expected dict and actual list
**Solution**: Tests handle this gracefully with skip messages

#### Tests taking too long
**Cause**: Session-scoped fixtures load data once, so should be fast
**Solution**: Check for network issues or large CloudTrail files

#### HTML report not generated
**Cause**: JSON report file missing or malformed
**Solution**: Check pytest-json-report is installed and JSON file exists

### Debug Mode

Enable debug output:
```bash
# Verbose pytest output
pytest tests/ --cluster-dir broken -vv

# Show all output (including print statements)
pytest tests/ --cluster-dir broken -v -s

# Debug specific test
pytest tests/test_security_groups.py::test_api_server_access --cluster-dir broken -vv -s
```

## Examples

### Example 1: Quick Health Check

```bash
# Collect data
python get_install_artifacts.py -c <cluster-id>

# Run tests
python run_tests.py --cluster-dir .

# View report
open test_report.html
```

### Example 2: Compare Two Clusters

```bash
# Test broken cluster
python run_tests.py --cluster-dir broken \
  --html-output reports/broken.html

# Test good cluster
python run_tests.py --cluster-dir new_good \
  --html-output reports/good.html

# Compare reports side-by-side
open reports/broken.html reports/good.html
```

### Example 3: CI/CD Integration

```bash
#!/bin/bash
# Run tests and check exit code
python run_tests.py --cluster-dir "$CLUSTER_DATA" --verbose

# Exit code 0 = all passed
# Exit code 1 = some failed
if [ $? -eq 0 ]; then
  echo "All health checks passed"
else
  echo "Health check failures detected"
  exit 1
fi
```

## Contributing

### Adding New Validators

1. Create test in appropriate module
2. Use descriptive test names: `test_<what_is_validated>`
3. Add docstring explaining what and why
4. Use existing helper functions when possible
5. Include detailed assertion messages
6. Handle missing data gracefully with `pytest.skip()`

### Code Style

- Follow existing patterns in test modules
- Use type hints for function parameters
- Add docstrings to all test functions
- Keep tests focused (one thing per test)
- Use helper functions for complex logic

## Version History

### v2.0.0 (2025-11-21) - Pytest Architecture

- Complete rewrite using pytest framework
- Modular test organization (7 categories, 63 tests)
- Session-scoped fixtures for efficient data loading
- Interactive HTML report generator
- ClusterData model for unified data access
- Command-line interface with run_tests.py
- JSON and HTML report outputs
- Category-based test markers
- Comprehensive test coverage across all cluster components

### v1.0.0 - Legacy Script

- Single-file monolithic script (check_cluster_artifacts.py)
- ~40 individual checks
- Basic HTML report generation
- Manual test execution

## License

See repository license file.

## Support

For issues, questions, or contributions:
- File an issue in the repository
- Contact the ROSA SRE team
