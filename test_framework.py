#!/usr/bin/env python3
"""
Test Framework for Cluster Health Checks

Provides base classes for implementing system tests with proper result tracking.
"""

from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any
from enum import Enum


class TestStatus(Enum):
    """Test execution status"""
    PASS = "PASS"
    FAIL = "FAIL"
    WARNING = "WARNING"
    ERROR = "ERROR"
    SKIP = "SKIP"


@dataclass
class TestResult:
    """Result of a single test case"""
    description: str
    status: TestStatus
    details: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def is_failure(self) -> bool:
        """Check if this result represents a failure"""
        return self.status in [TestStatus.FAIL, TestStatus.ERROR]

    def is_success(self) -> bool:
        """Check if this result represents success"""
        return self.status == TestStatus.PASS


@dataclass
class TestSuiteResult:
    """Results for a test suite (category)"""
    suite_name: str
    tests: List[TestResult] = field(default_factory=list)

    def add_result(self, result: TestResult):
        """Add a test result to this suite"""
        self.tests.append(result)

    def get_overall_status(self) -> TestStatus:
        """Calculate overall status based on all test results"""
        if not self.tests:
            return TestStatus.SKIP

        if any(t.status == TestStatus.ERROR for t in self.tests):
            return TestStatus.ERROR
        if any(t.status == TestStatus.FAIL for t in self.tests):
            return TestStatus.FAIL
        if any(t.status == TestStatus.WARNING for t in self.tests):
            return TestStatus.WARNING

        return TestStatus.PASS

    def get_failure_count(self) -> int:
        """Count failures (FAIL or ERROR)"""
        return sum(1 for t in self.tests if t.is_failure())

    def get_success_count(self) -> int:
        """Count successes"""
        return sum(1 for t in self.tests if t.is_success())


class TestCase:
    """Base class for test cases"""

    def __init__(self, name: str, cluster_data: Dict[str, Any]):
        self.name = name
        self.cluster_data = cluster_data
        self.results = TestSuiteResult(suite_name=name)

    def run(self) -> TestSuiteResult:
        """Execute the test case and return results"""
        raise NotImplementedError("Subclasses must implement run()")

    def add_pass(self, description: str, details: Optional[str] = None, **metadata):
        """Add a passing test result"""
        self.results.add_result(TestResult(
            description=description,
            status=TestStatus.PASS,
            details=details,
            metadata=metadata
        ))

    def add_fail(self, description: str, details: str, **metadata):
        """Add a failing test result"""
        self.results.add_result(TestResult(
            description=description,
            status=TestStatus.FAIL,
            details=details,
            metadata=metadata
        ))

    def add_warning(self, description: str, details: str, **metadata):
        """Add a warning test result"""
        self.results.add_result(TestResult(
            description=description,
            status=TestStatus.WARNING,
            details=details,
            metadata=metadata
        ))

    def add_error(self, description: str, details: str, **metadata):
        """Add an error test result"""
        self.results.add_result(TestResult(
            description=description,
            status=TestStatus.ERROR,
            details=details,
            metadata=metadata
        ))

    def add_skip(self, description: str, reason: str, **metadata):
        """Add a skipped test result"""
        self.results.add_result(TestResult(
            description=description,
            status=TestStatus.SKIP,
            details=f"Skipped: {reason}",
            metadata=metadata
        ))


class TestRunner:
    """Test runner that executes test cases and collects results"""

    def __init__(self):
        self.test_suites: Dict[str, TestSuiteResult] = {}

    def run_test(self, test_case: TestCase) -> TestSuiteResult:
        """Run a single test case and store results"""
        result = test_case.run()
        self.test_suites[test_case.name] = result
        return result

    def get_results(self) -> Dict[str, TestSuiteResult]:
        """Get all test results"""
        return self.test_suites

    def get_summary(self) -> Dict[str, Any]:
        """Get summary statistics"""
        total_tests = sum(len(suite.tests) for suite in self.test_suites.values())
        total_pass = sum(suite.get_success_count() for suite in self.test_suites.values())
        total_fail = sum(suite.get_failure_count() for suite in self.test_suites.values())

        return {
            'total_suites': len(self.test_suites),
            'total_tests': total_tests,
            'total_pass': total_pass,
            'total_fail': total_fail,
            'suites': {
                name: {
                    'status': suite.get_overall_status().value,
                    'tests': len(suite.tests),
                    'pass': suite.get_success_count(),
                    'fail': suite.get_failure_count()
                }
                for name, suite in self.test_suites.items()
            }
        }
