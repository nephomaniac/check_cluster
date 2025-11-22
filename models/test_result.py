"""Test result models"""

from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional
from enum import Enum


class TestStatus(Enum):
    """Test result status"""
    PASS = "pass"
    FAIL = "fail"
    WARNING = "warning"
    ERROR = "error"
    SKIP = "skip"


@dataclass
class TestResult:
    """
    Represents the result of a single test.

    This is the fundamental unit of test results that pytest generates.
    """
    test_id: str  # Unique test identifier (e.g., "test_security_groups.py::test_api_access")
    category: str  # Category (e.g., "security_groups", "vpc", etc.)
    description: str  # Human-readable description
    status: TestStatus
    details: Optional[str] = None  # Additional details (especially for failures)
    metadata: Dict[str, Any] = field(default_factory=dict)  # Extra data for rendering

    @property
    def is_passing(self) -> bool:
        """Check if test passed"""
        return self.status == TestStatus.PASS

    @property
    def is_failing(self) -> bool:
        """Check if test failed (includes warnings and errors)"""
        return self.status in [TestStatus.FAIL, TestStatus.WARNING, TestStatus.ERROR]


@dataclass
class TestResultSet:
    """
    Collection of test results organized by category.

    This represents all test results from a pytest run, organized
    for easy reporting and HTML generation.
    """
    results: List[TestResult] = field(default_factory=list)

    def add_result(self, result: TestResult):
        """Add a test result"""
        self.results.append(result)

    def get_by_category(self, category: str) -> List[TestResult]:
        """Get all results for a specific category"""
        return [r for r in self.results if r.category == category]

    def get_categories(self) -> List[str]:
        """Get list of all categories"""
        return list(set(r.category for r in self.results))

    def get_category_status(self, category: str) -> TestStatus:
        """Get overall status for a category"""
        cat_results = self.get_by_category(category)
        if not cat_results:
            return TestStatus.SKIP

        # Determine worst status in category
        if any(r.status == TestStatus.ERROR for r in cat_results):
            return TestStatus.ERROR
        if any(r.status == TestStatus.FAIL for r in cat_results):
            return TestStatus.FAIL
        if any(r.status == TestStatus.WARNING for r in cat_results):
            return TestStatus.WARNING

        return TestStatus.PASS

    def get_summary(self) -> Dict[str, Any]:
        """Get summary statistics"""
        total = len(self.results)
        passed = sum(1 for r in self.results if r.status == TestStatus.PASS)
        failed = sum(1 for r in self.results if r.status == TestStatus.FAIL)
        warnings = sum(1 for r in self.results if r.status == TestStatus.WARNING)
        errors = sum(1 for r in self.results if r.status == TestStatus.ERROR)
        skipped = sum(1 for r in self.results if r.status == TestStatus.SKIP)

        return {
            'total': total,
            'passed': passed,
            'failed': failed,
            'warnings': warnings,
            'errors': errors,
            'skipped': skipped,
            'categories': {
                cat: {
                    'status': self.get_category_status(cat).value,
                    'count': len(self.get_by_category(cat))
                }
                for cat in self.get_categories()
            }
        }
