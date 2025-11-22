"""Data models for cluster health checks"""

from .cluster import ClusterData
from .test_result import TestResult, TestResultSet

__all__ = ['ClusterData', 'TestResult', 'TestResultSet']
