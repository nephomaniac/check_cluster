"""
HTML Report Generator

Generates interactive HTML reports from pytest results.
"""

import json
from pathlib import Path
from typing import Dict, List, Any, Optional
from datetime import datetime


class HTMLReportGenerator:
    """Generates interactive HTML reports from pytest JSON results"""

    def __init__(self, json_report_path: Path, cluster_data_dir: Path):
        """
        Initialize HTML report generator.

        Args:
            json_report_path: Path to pytest JSON report
            cluster_data_dir: Path to cluster data directory
        """
        self.json_report_path = Path(json_report_path)
        self.cluster_data_dir = Path(cluster_data_dir)
        self.report_data = self._load_json_report()

    def _load_json_report(self) -> Dict[str, Any]:
        """Load pytest JSON report"""
        if not self.json_report_path.exists():
            raise FileNotFoundError(f"JSON report not found: {self.json_report_path}")

        with open(self.json_report_path, 'r') as f:
            return json.load(f)

    def _get_test_summary(self) -> Dict[str, int]:
        """Get test count summary"""
        summary = self.report_data.get('summary', {})
        return {
            'total': summary.get('total', 0),
            'passed': summary.get('passed', 0),
            'failed': summary.get('failed', 0),
            'skipped': summary.get('skipped', 0),
            'error': summary.get('error', 0)
        }

    def _organize_tests_by_category(self) -> Dict[str, List[Dict[str, Any]]]:
        """Organize tests by category (marker)"""
        categories = {}
        tests = self.report_data.get('tests', [])

        for test in tests:
            # Extract category from test nodeid (e.g., tests/test_security_groups.py -> security_groups)
            nodeid = test.get('nodeid', '')
            if '::' in nodeid:
                file_path = nodeid.split('::')[0]
                if '/' in file_path:
                    file_name = file_path.split('/')[-1]
                    category = file_name.replace('test_', '').replace('.py', '')
                else:
                    category = 'uncategorized'
            else:
                category = 'uncategorized'

            if category not in categories:
                categories[category] = []

            categories[category].append(test)

        return categories

    def _get_status_class(self, outcome: str) -> str:
        """Get CSS class for test outcome"""
        outcome_map = {
            'passed': 'status-pass',
            'failed': 'status-fail',
            'skipped': 'status-skip',
            'error': 'status-error'
        }
        return outcome_map.get(outcome, 'status-unknown')

    def _format_test_duration(self, duration: float) -> str:
        """Format test duration in human-readable format"""
        if duration < 1:
            return f"{duration*1000:.0f}ms"
        return f"{duration:.2f}s"

    def generate_html(self, output_path: Path) -> None:
        """
        Generate HTML report and save to file.

        Args:
            output_path: Path where HTML report will be saved
        """
        summary = self._get_test_summary()
        categories = self._organize_tests_by_category()

        # Calculate pass rate
        pass_rate = 0
        if summary['total'] > 0:
            pass_rate = (summary['passed'] / summary['total']) * 100

        # Generate HTML
        html = self._generate_html_content(summary, categories, pass_rate)

        # Write to file
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        with open(output_path, 'w') as f:
            f.write(html)

    def _generate_html_content(self, summary: Dict[str, int],
                               categories: Dict[str, List[Dict[str, Any]]],
                               pass_rate: float) -> str:
        """Generate complete HTML content"""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ROSA Cluster Health Check Report</title>
    {self._generate_css()}
</head>
<body>
    <div class="container">
        <header>
            <h1>ROSA Cluster Health Check Report</h1>
            <div class="metadata">
                <div class="metadata-item">
                    <span class="label">Cluster Data:</span>
                    <span class="value">{self.cluster_data_dir.name}</span>
                </div>
                <div class="metadata-item">
                    <span class="label">Generated:</span>
                    <span class="value">{timestamp}</span>
                </div>
            </div>
        </header>

        <section class="summary">
            <h2>Summary</h2>
            <div class="summary-cards">
                <div class="summary-card total">
                    <div class="card-value">{summary['total']}</div>
                    <div class="card-label">Total Tests</div>
                </div>
                <div class="summary-card passed">
                    <div class="card-value">{summary['passed']}</div>
                    <div class="card-label">Passed</div>
                </div>
                <div class="summary-card failed">
                    <div class="card-value">{summary['failed']}</div>
                    <div class="card-label">Failed</div>
                </div>
                <div class="summary-card skipped">
                    <div class="card-value">{summary['skipped']}</div>
                    <div class="card-label">Skipped</div>
                </div>
                <div class="summary-card rate">
                    <div class="card-value">{pass_rate:.1f}%</div>
                    <div class="card-label">Pass Rate</div>
                </div>
            </div>
        </section>

        <section class="categories">
            <h2>Test Results by Category</h2>
            {self._generate_categories_html(categories)}
        </section>
    </div>
    {self._generate_javascript()}
</body>
</html>"""
        return html

    def _generate_categories_html(self, categories: Dict[str, List[Dict[str, Any]]]) -> str:
        """Generate HTML for all test categories"""
        html_parts = []

        # Sort categories alphabetically
        sorted_categories = sorted(categories.items())

        for category, tests in sorted_categories:
            # Count outcomes for this category
            passed = sum(1 for t in tests if t.get('outcome') == 'passed')
            failed = sum(1 for t in tests if t.get('outcome') == 'failed')
            skipped = sum(1 for t in tests if t.get('outcome') == 'skipped')
            total = len(tests)

            category_status = 'status-pass' if failed == 0 else 'status-fail'

            html_parts.append(f"""
            <div class="category">
                <div class="category-header {category_status}" onclick="toggleCategory('{category}')">
                    <h3>{category.replace('_', ' ').title()}</h3>
                    <div class="category-stats">
                        <span class="stat stat-passed">{passed} passed</span>
                        <span class="stat stat-failed">{failed} failed</span>
                        <span class="stat stat-skipped">{skipped} skipped</span>
                        <span class="stat stat-total">{total} total</span>
                        <span class="toggle-icon">▼</span>
                    </div>
                </div>
                <div class="category-content" id="category-{category}">
                    <table class="test-table">
                        <thead>
                            <tr>
                                <th>Test</th>
                                <th>Status</th>
                                <th>Duration</th>
                                <th>Details</th>
                            </tr>
                        </thead>
                        <tbody>
                            {self._generate_tests_html(tests)}
                        </tbody>
                    </table>
                </div>
            </div>""")

        return '\n'.join(html_parts)

    def _generate_tests_html(self, tests: List[Dict[str, Any]]) -> str:
        """Generate HTML for test results"""
        html_parts = []

        for test in tests:
            # Extract test name from nodeid
            nodeid = test.get('nodeid', '')
            test_name = nodeid.split('::')[-1] if '::' in nodeid else nodeid

            outcome = test.get('outcome', 'unknown')
            duration = test.get('duration', 0)
            status_class = self._get_status_class(outcome)

            # Get failure message if test failed
            call_info = test.get('call', {})
            longrepr = call_info.get('longrepr', '')

            details = ''
            if outcome == 'failed' and longrepr:
                # Extract assertion message
                if 'AssertionError: ' in longrepr:
                    details = longrepr.split('AssertionError: ')[-1].split('\n')[0]
                else:
                    details = longrepr.split('\n')[0] if '\n' in longrepr else longrepr[:200]
            elif outcome == 'skipped':
                # Get skip reason
                details = call_info.get('longrepr', 'Skipped')

            # Get test docstring
            test_doc = test_name.replace('test_', '').replace('_', ' ').title()

            html_parts.append(f"""
                        <tr class="{status_class}">
                            <td class="test-name">{test_doc}</td>
                            <td class="test-status">
                                <span class="status-badge {status_class}">{outcome.upper()}</span>
                            </td>
                            <td class="test-duration">{self._format_test_duration(duration)}</td>
                            <td class="test-details">{details}</td>
                        </tr>""")

        return '\n'.join(html_parts)

    def _generate_css(self) -> str:
        """Generate CSS styles"""
        return """
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            background: #f5f5f5;
            color: #333;
            line-height: 1.6;
        }

        .container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 20px;
        }

        header {
            background: white;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            margin-bottom: 30px;
        }

        header h1 {
            color: #2c3e50;
            margin-bottom: 15px;
        }

        .metadata {
            display: flex;
            gap: 30px;
            color: #666;
            font-size: 14px;
        }

        .metadata-item {
            display: flex;
            gap: 8px;
        }

        .metadata-item .label {
            font-weight: 600;
        }

        section {
            background: white;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            margin-bottom: 30px;
        }

        section h2 {
            color: #2c3e50;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 2px solid #e0e0e0;
        }

        .summary-cards {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 20px;
            margin-top: 20px;
        }

        .summary-card {
            background: #f8f9fa;
            padding: 25px;
            border-radius: 8px;
            text-align: center;
            border-left: 4px solid #ddd;
        }

        .summary-card.total {
            border-left-color: #3498db;
        }

        .summary-card.passed {
            border-left-color: #27ae60;
        }

        .summary-card.failed {
            border-left-color: #e74c3c;
        }

        .summary-card.skipped {
            border-left-color: #f39c12;
        }

        .summary-card.rate {
            border-left-color: #9b59b6;
        }

        .card-value {
            font-size: 36px;
            font-weight: bold;
            color: #2c3e50;
        }

        .card-label {
            margin-top: 8px;
            color: #666;
            font-size: 14px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        .category {
            margin-bottom: 20px;
            border: 1px solid #e0e0e0;
            border-radius: 8px;
            overflow: hidden;
        }

        .category-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 20px;
            cursor: pointer;
            transition: background 0.2s;
        }

        .category-header:hover {
            background: #f8f9fa;
        }

        .category-header.status-pass {
            border-left: 4px solid #27ae60;
        }

        .category-header.status-fail {
            border-left: 4px solid #e74c3c;
        }

        .category-header h3 {
            color: #2c3e50;
            font-size: 18px;
        }

        .category-stats {
            display: flex;
            gap: 15px;
            align-items: center;
            font-size: 14px;
        }

        .stat {
            padding: 4px 10px;
            border-radius: 12px;
            background: #f0f0f0;
        }

        .stat-passed {
            background: #d4edda;
            color: #155724;
        }

        .stat-failed {
            background: #f8d7da;
            color: #721c24;
        }

        .stat-skipped {
            background: #fff3cd;
            color: #856404;
        }

        .toggle-icon {
            margin-left: 10px;
            transition: transform 0.2s;
        }

        .category-header.collapsed .toggle-icon {
            transform: rotate(-90deg);
        }

        .category-content {
            max-height: 2000px;
            overflow: hidden;
            transition: max-height 0.3s ease-in-out;
        }

        .category-content.hidden {
            max-height: 0;
        }

        .test-table {
            width: 100%;
            border-collapse: collapse;
        }

        .test-table thead {
            background: #f8f9fa;
        }

        .test-table th {
            padding: 12px;
            text-align: left;
            font-weight: 600;
            color: #555;
            border-bottom: 2px solid #e0e0e0;
        }

        .test-table td {
            padding: 12px;
            border-bottom: 1px solid #f0f0f0;
        }

        .test-table tr:hover {
            background: #f8f9fa;
        }

        .test-name {
            font-weight: 500;
        }

        .status-badge {
            display: inline-block;
            padding: 4px 12px;
            border-radius: 12px;
            font-size: 12px;
            font-weight: 600;
        }

        .status-pass .status-badge {
            background: #d4edda;
            color: #155724;
        }

        .status-fail .status-badge {
            background: #f8d7da;
            color: #721c24;
        }

        .status-skip .status-badge {
            background: #fff3cd;
            color: #856404;
        }

        .test-duration {
            color: #666;
            font-size: 14px;
        }

        .test-details {
            color: #666;
            font-size: 14px;
            max-width: 500px;
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
        }

        .status-fail .test-details {
            color: #721c24;
        }
    </style>"""

    def _generate_javascript(self) -> str:
        """Generate JavaScript for interactivity"""
        return """
    <script>
        function toggleCategory(categoryId) {
            const content = document.getElementById('category-' + categoryId);
            const header = content.previousElementSibling;

            if (content.classList.contains('hidden')) {
                content.classList.remove('hidden');
                header.classList.remove('collapsed');
            } else {
                content.classList.add('hidden');
                header.classList.add('collapsed');
            }
        }

        // Initialize - expand all categories by default
        document.addEventListener('DOMContentLoaded', function() {
            // All categories start expanded, no action needed
        });
    </script>"""
