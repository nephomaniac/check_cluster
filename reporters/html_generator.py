"""
HTML Report Generator

Generates interactive HTML reports from pytest results.
"""

import json
import sys
from pathlib import Path
from typing import Dict, List, Any, Optional
from datetime import datetime
import traceback


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

        try:
            with open(self.json_report_path, 'r') as f:
                return json.load(f)
        except json.JSONDecodeError as e:
            # Provide detailed error information
            print(f"\n❌ Error: Failed to parse JSON report file: {self.json_report_path}", file=sys.stderr)
            print(f"   JSONDecodeError: {e.msg}", file=sys.stderr)
            print(f"   Location: line {e.lineno}, column {e.colno} (char {e.pos})", file=sys.stderr)
            print(f"\n   The JSON report file may be incomplete or corrupted.", file=sys.stderr)
            print(f"   This can happen if pytest was interrupted or failed to complete.", file=sys.stderr)
            print(f"\n   Try running the tests again with: ./run_tests.py --cluster-dir <cluster-dir>", file=sys.stderr)
            raise
        except Exception as e:
            print(f"\n❌ Error: Unexpected error reading JSON report: {self.json_report_path}", file=sys.stderr)
            print(f"   {type(e).__name__}: {e}", file=sys.stderr)
            raise

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

    def _extract_status_reason(self, test: Dict[str, Any]) -> str:
        """Extract status reason from test output"""
        outcome = test.get('outcome', 'unknown')
        call_info = test.get('call', {})
        stdout = call_info.get('stdout', '')

        if outcome == 'passed':
            # Look for ✓ success message
            if stdout:
                lines = stdout.split('\n')
                success_lines = [line for line in lines if line.startswith('✓')]
                if success_lines:
                    return success_lines[0]
            return 'All validations passed'

        elif outcome == 'failed':
            # Look for ✗ failure message
            if stdout:
                lines = stdout.split('\n')
                failure_lines = [line for line in lines if line.startswith('✗')]
                if failure_lines:
                    return failure_lines[0]
            # Fallback to longrepr
            longrepr = call_info.get('longrepr', '')
            if 'AssertionError: ' in longrepr:
                return longrepr.split('AssertionError: ')[-1].split('\n')[0]
            return longrepr.split('\n')[0] if '\n' in longrepr else longrepr[:200]

        elif outcome == 'skipped':
            longrepr = call_info.get('longrepr', 'Skipped')
            if isinstance(longrepr, str) and 'Skipped:' in longrepr:
                reason = longrepr.split('Skipped:')[1].strip()
                # Remove trailing quote and paren from tuple representation
                if reason.endswith("')"):
                    reason = reason[:-2]
                elif reason.endswith("'"):
                    reason = reason[:-1]
                return f'Skipped: {reason}'
            return str(longrepr)

        return 'Unknown status'

    def _extract_json_output(self, test: Dict[str, Any]) -> List[str]:
        """Extract JSON blocks from test stdout"""
        call_info = test.get('call', {})
        stdout = call_info.get('stdout', '')

        if not stdout:
            return []

        json_blocks = []
        lines = stdout.split('\n')
        current_json = []
        in_json = False
        bracket_depth = 0
        brace_depth = 0

        for line in lines:
            stripped = line.strip()

            # Detect start of JSON (array or object at start of line)
            if not in_json and (stripped.startswith('[') or stripped.startswith('{')):
                in_json = True
                current_json = [line]
                # Count brackets/braces in this line
                bracket_depth = line.count('[') - line.count(']')
                brace_depth = line.count('{') - line.count('}')
            elif in_json:
                current_json.append(line)
                # Update depth counts
                bracket_depth += line.count('[') - line.count(']')
                brace_depth += line.count('{') - line.count('}')

                # Check if we've closed all brackets and braces
                if bracket_depth == 0 and brace_depth == 0:
                    # Try to parse the complete JSON
                    try:
                        json_str = '\n'.join(current_json)
                        json.loads(json_str)
                        # Valid JSON - save it
                        json_blocks.append(json_str)
                        in_json = False
                        current_json = []
                    except json.JSONDecodeError:
                        # Invalid JSON, reset and continue
                        in_json = False
                        current_json = []
                        bracket_depth = 0
                        brace_depth = 0

        return json_blocks

    def _generate_tests_html(self, tests: List[Dict[str, Any]]) -> str:
        """Generate HTML for test results with collapsible details"""
        html_parts = []

        for idx, test in enumerate(tests):
            # Extract test information
            nodeid = test.get('nodeid', '')
            test_name = nodeid.split('::')[-1] if '::' in nodeid else nodeid
            test_id = f"test-{idx}-{test_name.replace('_', '-')}"

            # Extract module and line number
            module_path = nodeid.split('::')[0] if '::' in nodeid else ''
            lineno = test.get('lineno', 'N/A')

            outcome = test.get('outcome', 'unknown')
            duration = test.get('duration', 0)
            status_class = self._get_status_class(outcome)

            # Get docstring from user_properties (stored by pytest hook)
            test_doc = None
            user_properties = test.get('user_properties', [])
            if user_properties and isinstance(user_properties, list):
                for prop in user_properties:
                    if isinstance(prop, dict) and 'test_doc' in prop:
                        test_doc = prop['test_doc']
                        break

            # Fallback to generated title if no docstring found
            if not test_doc:
                test_doc = test_name.replace('test_', '').replace('_', ' ').title()

            # Parse docstring for description parts
            description_html = self._parse_test_description(test_doc)

            # Extract status reason and JSON output
            status_reason = self._extract_status_reason(test)
            json_blocks = self._extract_json_output(test)

            # Get short display name
            display_name = test_name.replace('test_', '').replace('_', ' ').title()

            # Import escape at the top of the method
            from html import escape

            # Generate JSON output HTML
            json_output_html = ''
            if json_blocks:
                json_output_html = '<div class="detail-section"><h4>Test Output</h4>'
                for json_block in json_blocks:
                    # Escape HTML entities
                    escaped_json = escape(json_block)
                    json_output_html += f'<pre class="json-output"><code>{escaped_json}</code></pre>'
                json_output_html += '</div>'

            # Escape status reason for safe HTML display
            escaped_status_reason = escape(status_reason)

            html_parts.append(f"""
                        <tr class="{status_class}">
                            <td class="test-name">{display_name}</td>
                            <td class="test-status">
                                <span class="status-badge {status_class}">{outcome.upper()}</span>
                            </td>
                            <td class="test-duration">{self._format_test_duration(duration)}</td>
                            <td class="test-details-cell">
                                <button class="details-toggle" onclick="toggleTestDetails('{test_id}')">
                                    <span class="toggle-arrow">►</span> View Details
                                </button>
                            </td>
                        </tr>
                        <tr class="test-details-row hidden" id="{test_id}">
                            <td colspan="4">
                                <div class="test-details-content">
                                    <div class="detail-section">
                                        <h4>Test Information</h4>
                                        <div class="detail-grid">
                                            <div class="detail-item">
                                                <span class="detail-label">Module:</span>
                                                <span class="detail-value"><code>{module_path}</code></span>
                                            </div>
                                            <div class="detail-item">
                                                <span class="detail-label">Line:</span>
                                                <span class="detail-value">{lineno}</span>
                                            </div>
                                            <div class="detail-item">
                                                <span class="detail-label">Status:</span>
                                                <span class="detail-value status-{outcome}">{outcome.upper()}</span>
                                            </div>
                                        </div>
                                    </div>
                                    <div class="detail-section">
                                        <h4>Status Reason</h4>
                                        <div class="status-reason {status_class}">{escaped_status_reason}</div>
                                    </div>
                                    {json_output_html}
                                    <div class="detail-section">
                                        <h4>Test Description</h4>
                                        {description_html}
                                    </div>
                                </div>
                            </td>
                        </tr>""")

        return '\n'.join(html_parts)

    def _parse_test_description(self, docstring: str) -> str:
        """Parse test docstring into structured HTML"""
        if not docstring:
            return '<p class="no-description">No description available</p>'

        # Split docstring into parts
        lines = docstring.split('\n')
        brief = lines[0].strip() if lines else 'No description'

        # Look for Why: and Failure indicates: sections
        why_text = ''
        failure_text = ''

        for i, line in enumerate(lines):
            line = line.strip()
            if line.startswith('Why:'):
                why_text = line[4:].strip()
                # Collect continuation lines
                j = i + 1
                while j < len(lines) and lines[j].strip() and not lines[j].strip().startswith('Failure'):
                    why_text += ' ' + lines[j].strip()
                    j += 1
            elif line.startswith('Failure indicates:'):
                failure_text = line[18:].strip()
                # Collect continuation lines
                j = i + 1
                while j < len(lines) and lines[j].strip():
                    failure_text += ' ' + lines[j].strip()
                    j += 1

        html = f'<p class="test-brief"><strong>{brief}</strong></p>'

        if why_text:
            html += f'<p class="test-why"><strong>Why:</strong> {why_text}</p>'

        if failure_text:
            html += f'<p class="test-failure"><strong>Failure indicates:</strong> {failure_text}</p>'

        return html

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
            max-height: none;
            overflow: visible;
            transition: max-height 0.3s ease-in-out;
        }

        .category-content.hidden {
            max-height: 0;
            overflow: hidden;
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

        /* Collapsible test details */
        .test-details-cell {
            text-align: center;
        }

        .details-toggle {
            background: #007bff;
            color: white;
            border: none;
            padding: 6px 14px;
            border-radius: 4px;
            cursor: pointer;
            font-size: 13px;
            font-weight: 500;
            transition: background 0.2s;
            display: inline-flex;
            align-items: center;
            gap: 6px;
        }

        .details-toggle:hover {
            background: #0056b3;
        }

        .toggle-arrow {
            transition: transform 0.2s;
            font-size: 10px;
        }

        .details-toggle.expanded .toggle-arrow {
            transform: rotate(90deg);
        }

        .test-details-row {
            background: #f8f9fa;
        }

        .test-details-row.hidden {
            display: none;
        }

        .test-details-content {
            padding: 20px;
            border-left: 4px solid #007bff;
            max-height: 800px;
            overflow-y: auto;
        }

        .detail-section {
            margin-bottom: 20px;
        }

        .detail-section:last-child {
            margin-bottom: 0;
        }

        /* Ensure individual detail sections are scrollable if content is too long */
        .detail-section pre {
            max-height: 400px;
            overflow-y: auto;
        }

        .detail-section h4 {
            color: #2c3e50;
            font-size: 14px;
            font-weight: 600;
            margin-bottom: 10px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        .detail-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
        }

        .detail-item {
            display: flex;
            flex-direction: column;
            gap: 4px;
        }

        .detail-label {
            font-size: 12px;
            font-weight: 600;
            color: #666;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        .detail-value {
            font-size: 14px;
            color: #333;
        }

        .detail-value code {
            background: #e9ecef;
            padding: 2px 6px;
            border-radius: 3px;
            font-family: 'Courier New', monospace;
            font-size: 13px;
        }

        .detail-value.status-passed {
            color: #27ae60;
            font-weight: 600;
        }

        .detail-value.status-failed {
            color: #e74c3c;
            font-weight: 600;
        }

        .detail-value.status-skipped {
            color: #f39c12;
            font-weight: 600;
        }

        .status-reason {
            background: #fff;
            border: 1px solid #e0e0e0;
            border-radius: 4px;
            padding: 12px;
            font-size: 14px;
            line-height: 1.6;
            color: #333;
        }

        .status-reason.status-fail {
            background: #fff5f5;
            border-color: #f8d7da;
            color: #721c24;
        }

        .status-reason.status-skip {
            background: #fffef5;
            border-color: #fff3cd;
            color: #856404;
        }

        .test-brief {
            font-size: 15px;
            line-height: 1.6;
            margin-bottom: 10px;
        }

        .test-why {
            font-size: 14px;
            line-height: 1.6;
            margin-bottom: 10px;
            color: #555;
        }

        .test-failure {
            font-size: 14px;
            line-height: 1.6;
            color: #555;
        }

        .no-description {
            font-size: 14px;
            color: #999;
            font-style: italic;
        }

        /* JSON Output Styling */
        .json-output {
            background: #2d2d2d !important;
            color: #f8f8f2 !important;
            font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', 'Consolas', monospace;
            font-size: 12px;
            line-height: 1.5;
            border: 1px solid #444;
            border-radius: 4px;
            padding: 15px;
            margin: 10px 0;
            max-height: 400px;
            overflow-y: auto;
            overflow-x: auto;
        }

        .json-output code {
            color: #f8f8f2;
            background: transparent;
            padding: 0;
        }

        /* Enhanced Status Reason Styling */
        .status-reason.status-pass {
            background: #d4edda;
            border-color: #c3e6cb;
            color: #155724;
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

        function toggleTestDetails(testId) {
            const detailsRow = document.getElementById(testId);
            const button = event.target.closest('button');

            if (detailsRow.classList.contains('hidden')) {
                detailsRow.classList.remove('hidden');
                button.classList.add('expanded');
                button.querySelector('.toggle-arrow').textContent = '▼';
                button.innerHTML = button.innerHTML.replace('View Details', 'Hide Details');
            } else {
                detailsRow.classList.add('hidden');
                button.classList.remove('expanded');
                button.querySelector('.toggle-arrow').textContent = '►';
                button.innerHTML = button.innerHTML.replace('Hide Details', 'View Details');
            }
        }

        // Initialize - expand all categories by default
        document.addEventListener('DOMContentLoaded', function() {
            // All categories start expanded, no action needed
        });
    </script>"""
