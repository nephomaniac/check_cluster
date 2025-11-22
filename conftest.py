"""
Pytest configuration and fixtures for cluster health checks.

This file provides pytest fixtures that are automatically available
to all test modules.
"""

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
    try:
        return load_cluster_data(cluster_dir)
    except Exception as e:
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
