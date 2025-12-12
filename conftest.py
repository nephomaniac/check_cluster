"""
Pytest configuration and fixtures for cluster health checks.

This file provides pytest fixtures that are automatically available
to all test modules.
"""

import json
import sys
import pytest
from pathlib import Path
from models.cluster import ClusterData
from utils.data_loader import load_cluster_data


def pytest_addoption(parser):
    """Add custom command-line options for pytest"""
    parser.addoption(
        "--cluster-dir",
        action="store",
        default=None,
        help="Path to directory containing cluster data files"
    )


@pytest.fixture(scope="session")
def cluster_dir(request) -> Path:
    """
    Get the cluster data directory from command line.

    Usage:
        pytest --cluster-dir=/path/to/cluster/data
    """
    dir_path = request.config.getoption("--cluster-dir")
    if not dir_path:
        pytest.skip("No --cluster-dir provided")

    path = Path(dir_path).resolve()
    if not path.exists():
        pytest.fail(f"Cluster directory does not exist: {path}")

    return path


@pytest.fixture(scope="session")
def cluster_data(cluster_dir) -> ClusterData:
    """
    Load all cluster data from the specified directory.

    This fixture is session-scoped, so data is loaded once
    and shared across all tests.
    """
    import traceback
    try:
        return load_cluster_data(cluster_dir)
    except json.JSONDecodeError as e:
        # JSONDecodeError is already handled with detailed output in data_loader.py
        # Just fail the test session with a brief message
        pytest.fail(
            f"Cannot run tests: Corrupted JSON file in cluster data directory.\n"
            f"See error details above for the specific file and how to fix it."
        )
    except Exception as e:
        # For other unexpected errors, show full stack trace
        print(f"\n{'='*80}", file=sys.stderr)
        print(f"❌ ERROR: Failed to load cluster data", file=sys.stderr)
        print(f"{'='*80}", file=sys.stderr)
        print(f"Directory: {cluster_dir}", file=sys.stderr)
        print(f"Error: {type(e).__name__}: {e}", file=sys.stderr)
        print(f"\nStack trace:", file=sys.stderr)
        traceback.print_exc(file=sys.stderr)
        print(f"{'='*80}\n", file=sys.stderr)
        pytest.fail(f"Failed to load cluster data: {e}")


@pytest.fixture(scope="session")
def infra_id(cluster_data: ClusterData) -> str:
    """Get infrastructure ID"""
    return cluster_data.infra_id


@pytest.fixture(scope="session")
def is_private_cluster(cluster_data: ClusterData) -> bool:
    """Check if cluster is private"""
    return cluster_data.is_private


@pytest.fixture(scope="session")
def vpc_cidr(cluster_data: ClusterData) -> str:
    """Get VPC CIDR"""
    cidr = cluster_data.vpc_cidr
    if not cidr:
        pytest.skip("VPC CIDR not available")
    return cidr


def pytest_configure(config):
    """Configure pytest with custom markers"""
    config.addinivalue_line(
        "markers", "security_groups: Security group validation tests"
    )
    config.addinivalue_line(
        "markers", "vpc: VPC configuration tests"
    )
    config.addinivalue_line(
        "markers", "network: Network infrastructure tests (subnets, NAT, IGW, routing)"
    )
    config.addinivalue_line(
        "markers", "storage: Storage infrastructure tests (EBS volumes)"
    )
    config.addinivalue_line(
        "markers", "instances: EC2 instance tests"
    )
    config.addinivalue_line(
        "markers", "load_balancers: Load balancer tests"
    )
    config.addinivalue_line(
        "markers", "route53: Route53 DNS tests"
    )
    config.addinivalue_line(
        "markers", "cloudtrail: CloudTrail event analysis tests"
    )
    config.addinivalue_line(
        "markers", "installation: Installation status tests"
    )
    config.addinivalue_line(
        "markers", "aws_resources: AWS IAM resources and OIDC provider tests"
    )


def pytest_runtest_setup(item):
    """Hook called before each test runs - reset per-test file tracking"""
    # This hook runs BEFORE setup phase, so we can reset tracking here
    # We need to manually get the cluster_data from the fixture manager if it exists
    if 'cluster_data' in item.fixturenames:
        try:
            # Try to get the cluster_data fixture if it's already been created
            # (it's session-scoped, so it exists after the first test)
            from _pytest.fixtures import FixtureLookupError
            try:
                fixture_def = item.session._fixturemanager._arg2fixturedefs.get('cluster_data')
                if fixture_def and fixture_def[0].cached_result:
                    cluster_data = fixture_def[0].cached_result[0]
                    cluster_data.reset_test_file_tracking()
            except (AttributeError, IndexError, KeyError):
                # Fixture not created yet, will reset later
                pass
        except ImportError:
            pass


def pytest_runtest_makereport(item, call):
    """Hook to capture test docstrings and output for HTML/JSON report"""
    # Get the pytest report
    outcome = pytest.TestReport.from_item_and_call(item, call)

    # Capture files accessed during call phase (the actual test execution)
    if call.when == "call":
        # Get the test function's docstring
        if item.function.__doc__:
            # Store docstring as user property for JSON report
            item.user_properties.append(("test_doc", item.function.__doc__))

        # Capture stdout/stderr for HTML report
        if hasattr(outcome, 'capstdout'):
            item.user_properties.append(("captured_output", outcome.capstdout))

        # Capture file sources from cluster_data fixture (only files accessed by this test)
        if 'cluster_data' in item.funcargs:
            cluster_data = item.funcargs['cluster_data']
            files_accessed = cluster_data.get_test_files_accessed()
            files_expected_but_missing = cluster_data.get_test_files_expected_but_missing()
            attrs_no_files = cluster_data.get_test_attributes_with_no_files()
            item.user_properties.append(("files_accessed", files_accessed))
            item.user_properties.append(("files_expected_but_missing", files_expected_but_missing))
            item.user_properties.append(("attributes_no_files", attrs_no_files))

    return outcome
