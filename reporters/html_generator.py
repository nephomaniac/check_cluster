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
            error = sum(1 for t in tests if t.get('outcome') == 'error')
            skipped = sum(1 for t in tests if t.get('outcome') == 'skipped')
            total = len(tests)

            # Determine category status: error takes precedence over fail
            if error > 0:
                category_status = 'status-error'
            elif failed > 0:
                category_status = 'status-fail'
            else:
                category_status = 'status-pass'

            html_parts.append(f"""
            <div class="category">
                <div class="category-header {category_status}" onclick="toggleCategory('{category}')">
                    <h3>{category.replace('_', ' ').title()}</h3>
                    <div class="category-stats">
                        <span class="stat stat-passed">{passed} passed</span>
                        <span class="stat stat-failed">{failed} failed</span>
                        <span class="stat stat-error">{error} error</span>
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
            # Look for ✗ failure message in stdout
            if stdout:
                lines = stdout.split('\n')
                failure_lines = [line for line in lines if line.startswith('✗')]
                if failure_lines:
                    return failure_lines[0]

            # Fallback to longrepr
            longrepr = call_info.get('longrepr', '')

            # Look for AssertionError message
            if 'AssertionError: ' in longrepr:
                return longrepr.split('AssertionError: ')[-1].split('\n')[0]

            # Look for Failed: message (from pytest.fail())
            if 'Failed: ' in longrepr:
                # Get the message after "Failed: " and find the first meaningful line
                failure_message = longrepr.split('Failed: ')[-1]
                for line in failure_message.split('\n'):
                    line = line.strip()
                    # Skip empty lines and separator lines
                    if line:
                        # Skip if line is all separator characters (=, ─, -, etc.)
                        if all(c in '=─-' for c in line):
                            continue
                        # This is a meaningful line, return it
                        return line
                # If no meaningful line found, return error indicator
                return 'Test failed - see details below'

            # Look for E   lines which mark actual error in pytest output
            lines = longrepr.split('\n')
            for line in lines:
                if line.startswith('E   '):
                    # Extract error message without the E prefix
                    return line[4:].strip()

            # Last resort: take first non-empty line that doesn't look like code or separators
            for line in lines:
                line = line.strip()
                # Skip empty, code markers, separators, and lines with assignments
                if (line and
                    not line.startswith('>') and
                    not line.startswith('def ') and
                    not line.startswith('===') and
                    not line.startswith('---') and
                    not all(c in '=─' for c in line) and  # Skip lines of just separators
                    '=' not in line[:50]):
                    return line[:200]

            return longrepr[:200]

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

    def _extract_full_failure_message(self, test: Dict[str, Any]) -> str:
        """
        Extract the FULL multi-line failure message from a failed test.

        This shows complete details including all items in lists, unlike
        _extract_status_reason() which only returns a one-line summary.

        Returns empty string if test didn't fail or no details available.
        """
        outcome = test.get('outcome', 'unknown')
        if outcome != 'failed':
            return ''

        call_info = test.get('call', {})
        longrepr = call_info.get('longrepr', '')

        if not longrepr:
            return ''

        # Look for AssertionError message (FULL multi-line version)
        if 'AssertionError: ' in longrepr:
            full_message = longrepr.split('AssertionError: ')[-1]
            # Clean up: remove stack trace lines that start with specific patterns
            lines = full_message.split('\n')
            message_lines = []
            for line in lines:
                # Stop at stack trace markers
                if line.startswith('Traceback') or line.startswith('  File ') or line.startswith('    '):
                    break
                message_lines.append(line)
            return '\n'.join(message_lines).strip()

        # Look for Failed: message (FULL multi-line version from pytest.fail())
        if 'Failed: ' in longrepr:
            full_message = longrepr.split('Failed: ')[-1]
            # Clean up: remove stack trace lines
            lines = full_message.split('\n')
            message_lines = []
            for line in lines:
                # Stop at stack trace markers
                if line.startswith('Traceback') or line.startswith('  File ') or line.startswith('    '):
                    break
                message_lines.append(line)
            return '\n'.join(message_lines).strip()

        # Look for E   lines and collect all consecutive ones
        lines = longrepr.split('\n')
        error_lines = []
        in_error_section = False
        for line in lines:
            if line.startswith('E   '):
                in_error_section = True
                error_lines.append(line[4:])  # Remove 'E   ' prefix
            elif in_error_section and not line.strip():
                # Empty line, continue collecting
                error_lines.append('')
            elif in_error_section:
                # Non-E line after E section started, stop
                break

        if error_lines:
            return '\n'.join(error_lines).strip()

        return ''

    def _generate_stack_trace_html(self, test: Dict[str, Any]) -> str:
        """Generate stack trace section for failed tests"""
        from html import escape

        outcome = test.get('outcome', 'unknown')
        if outcome != 'failed':
            return ''

        call_info = test.get('call', {})
        longrepr = call_info.get('longrepr', '')

        if not longrepr or len(longrepr) < 50:
            return ''

        # Don't show stack trace if we already have a clean ✗ message
        stdout = call_info.get('stdout', '')
        if stdout and any(line.startswith('✗') for line in stdout.split('\n')):
            # Only show stack trace if longrepr has additional useful info
            if len(longrepr) < 200:
                return ''

        html = '<div class="detail-section">'
        html += '<details style="margin: 10px 0;">'
        html += '<summary style="cursor: pointer; font-weight: bold; color: #e74c3c; padding: 8px; background: #fff5f5; border: 1px solid #f8d7da; border-radius: 4px; user-select: none;">'
        html += '⚠️ Error Trace'
        html += '</summary>'
        html += '<div style="margin-top: 10px; padding: 15px; background: #fff; border: 1px solid #f8d7da; border-radius: 4px;">'
        html += '<pre style="background: #2d2d2d; color: #f8f8f2; padding: 15px; border-radius: 4px; overflow-x: auto; font-family: monospace; font-size: 12px; line-height: 1.5; margin: 0;">'
        html += f'<code>{escape(longrepr)}</code>'
        html += '</pre>'
        html += '</div>'
        html += '</details>'
        html += '</div>'

        return html

    def _extract_json_output(self, test: Dict[str, Any]) -> List[Dict[str, str]]:
        """
        Extract JSON blocks with their headers from test stdout.

        Returns list of dicts with 'header' and 'json' keys.
        """
        call_info = test.get('call', {})
        stdout = call_info.get('stdout', '')

        if not stdout:
            return []

        json_blocks = []
        lines = stdout.split('\n')
        current_json = []
        current_header = []
        in_json = False
        in_header = False
        bracket_depth = 0
        brace_depth = 0

        for i, line in enumerate(lines):
            stripped = line.strip()

            # Detect header separator line (starts with ─)
            if '─' * 10 in line and not in_json:
                # Start or end of header section
                if not in_header:
                    # Beginning of header section
                    in_header = True
                    current_header = []
                else:
                    # End of header section - next should be JSON
                    in_header = False
                continue

            # Collect header lines (between ─ separators)
            if in_header:
                if stripped:  # Only collect non-empty lines
                    current_header.append(stripped)
                continue

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
                        parsed_json = json.loads(json_str)

                        # Determine if this is CloudTrail data
                        is_cloudtrail = self._is_cloudtrail_data(current_header, parsed_json)

                        # Save JSON block with header
                        json_blocks.append({
                            'header': '\n'.join(current_header) if current_header else '',
                            'json': json_str,
                            'parsed': parsed_json,
                            'is_cloudtrail': is_cloudtrail
                        })

                        in_json = False
                        current_json = []
                        current_header = []
                    except json.JSONDecodeError:
                        # Invalid JSON, reset and continue
                        in_json = False
                        current_json = []
                        current_header = []
                        bracket_depth = 0
                        brace_depth = 0

        return json_blocks

    def _is_cloudtrail_data(self, header_lines: List[str], parsed_json: Any) -> bool:
        """Determine if JSON data is CloudTrail events"""
        # Check header for "CLOUDTRAIL" keyword
        header_text = '\n'.join(header_lines).upper()
        if 'CLOUDTRAIL' in header_text:
            return True

        # Check if JSON structure matches CloudTrail events
        if isinstance(parsed_json, list) and len(parsed_json) > 0:
            first_item = parsed_json[0]
            if isinstance(first_item, dict):
                # CloudTrail events have EventName, EventTime, Username fields
                cloudtrail_fields = ['EventName', 'EventTime', 'Username']
                if all(field in first_item for field in cloudtrail_fields):
                    return True

        return False

    def _format_cloudtrail_simplified(self, events: List[Dict[str, Any]]) -> str:
        """Format CloudTrail events to show only: eventName, username, date, result code"""
        from html import escape

        if not events:
            return '<p style="color: #666; font-style: italic;">No CloudTrail events found</p>'

        html = '<table style="width: 100%; border-collapse: collapse; font-size: 13px; margin-top: 10px;">'
        html += '<thead>'
        html += '<tr style="background: #34495e; color: #ffffff;">'
        html += '<th style="padding: 8px; text-align: left; border: 1px solid #ddd;">Event Name</th>'
        html += '<th style="padding: 8px; text-align: left; border: 1px solid #ddd;">Username</th>'
        html += '<th style="padding: 8px; text-align: left; border: 1px solid #ddd;">Date/Time</th>'
        html += '<th style="padding: 8px; text-align: left; border: 1px solid #ddd;">Result</th>'
        html += '</tr>'
        html += '</thead>'
        html += '<tbody>'

        for event in events:
            event_name = event.get('EventName', 'N/A')
            username = event.get('Username', 'N/A')
            event_time = event.get('EventTime', 'N/A')

            # Result code - check ErrorCode or assume success
            error_code = event.get('ErrorCode', '')
            if error_code:
                result = f'Error: {error_code}'
                result_color = '#e74c3c'
            else:
                result = 'Success'
                result_color = '#27ae60'

            html += '<tr style="background: white;">'
            html += f'<td style="padding: 8px; border: 1px solid #ddd; font-family: monospace;">{escape(str(event_name))}</td>'
            html += f'<td style="padding: 8px; border: 1px solid #ddd;">{escape(str(username))}</td>'
            html += f'<td style="padding: 8px; border: 1px solid #ddd;">{escape(str(event_time))}</td>'
            html += f'<td style="padding: 8px; border: 1px solid #ddd; color: {result_color}; font-weight: 600;">{escape(result)}</td>'
            html += '</tr>'

        html += '</tbody>'
        html += '</table>'

        return html

    def _generate_tests_html(self, tests: List[Dict[str, Any]]) -> str:
        """Generate HTML for test results with collapsible details"""
        html_parts = []

        for idx, test in enumerate(tests):
            # Extract test information
            nodeid = test.get('nodeid', '')
            test_name = nodeid.split('::')[-1] if '::' in nodeid else nodeid
            # Use nodeid-based ID for uniqueness and linkability
            # Convert nodeid like 'tests/test_instances.py::test_control_plane_instances_running'
            # to 'test-tests-test-instances-py-test-control-plane-instances-running'
            test_id = 'test-' + nodeid.replace('/', '-').replace('.', '-').replace('::', '-').replace('_', '-')

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
                for idx, block in enumerate(json_blocks):
                    # Each block is a dict with 'header', 'json', 'parsed', 'is_cloudtrail'
                    header = block.get('header', '')
                    json_str = block.get('json', '')
                    parsed = block.get('parsed')
                    is_cloudtrail = block.get('is_cloudtrail', False)

                    # Add header if present
                    if header:
                        json_output_html += f'''
                        <div style="background: #e8f4f8; border-left: 4px solid #3498db; padding: 12px; margin: 15px 0 5px 0; border-radius: 4px;">
                            <div style="font-weight: 600; color: #2c3e50; font-size: 13px; white-space: pre-wrap;">{escape(header)}</div>
                        </div>'''

                    # Display CloudTrail data in simplified table format
                    if is_cloudtrail and isinstance(parsed, list):
                        json_output_html += self._format_cloudtrail_simplified(parsed)
                    else:
                        # Display regular JSON
                        escaped_json = escape(json_str)
                        json_output_html += f'<pre class="json-output"><code>{escaped_json}</code></pre>'

                json_output_html += '</div>'

            # Escape status reason for safe HTML display and preserve newlines
            # Handle both actual newlines and escaped newline sequences
            escaped_status_reason = escape(status_reason).replace('\\n', '<br>').replace('\n', '<br>')

            # Generate stack trace section for failed tests
            stack_trace_html = self._generate_stack_trace_html(test)

            # Generate sources section
            sources_html = self._generate_sources_html(test)

            # Generate CloudTrail events section (for failed/skipped tests)
            cloudtrail_html = ''
            if outcome in ['failed', 'skipped']:
                cloudtrail_html = self._generate_cloudtrail_events_html(test)

            # Generate API requests section (for failed/skipped tests)
            api_requests_html = ''
            if outcome in ['failed', 'skipped']:
                api_requests_html = self._generate_api_requests_html(test)

            # Generate remediation checklist section (for failed/skipped tests)
            remediation_checklist_html = ''
            if outcome in ['failed', 'skipped']:
                remediation_checklist_html = self._generate_remediation_checklist_html(test)

            # Extract full failure message for failed tests
            full_failure_message = ''
            if outcome == 'failed':
                full_msg = self._extract_full_failure_message(test)
                if full_msg:
                    # Override status_reason to direct users to the full details
                    status_reason = 'See failure details below'
                    escaped_status_reason = escape(status_reason).replace('\\n', '<br>').replace('\n', '<br>')

                    # Escape for HTML and preserve formatting
                    escaped_msg = escape(full_msg)
                    full_failure_message = f'''
                    <div class="detail-section failure-details-section">
                        <details open style="margin: 10px 0;">
                            <summary style="cursor: pointer; font-weight: bold; color: #e74c3c; padding: 8px; background: #fff5f5; border: 1px solid #f8d7da; border-radius: 4px; user-select: none;">
                                ⚠️ Failure Details
                            </summary>
                            <div style="margin-top: 10px; padding: 15px; background: #fff; border: 1px solid #f8d7da; border-radius: 4px;">
                                <pre style="white-space: pre-wrap; font-family: monospace; font-size: 13px; line-height: 1.6; margin: 0; color: #2c3e50; background: #fff5f5; padding: 15px; border-radius: 4px;">{escaped_msg}</pre>
                            </div>
                        </details>
                    </div>'''

            # Generate installation phase analysis section (for all test outcomes)
            # This shows bootstrap progress visualization even for passing tests
            installation_phase_html = self._generate_installation_phase_section_html(test)

            html_parts.append(f"""
                        <tr class="{status_class}">
                            <td class="test-name">{display_name}</td>
                            <td class="test-status">
                                <span class="status-badge {status_class}">{outcome.upper()}</span>
                            </td>
                            <td class="test-duration">{self._format_test_duration(duration)}</td>
                            <td class="test-details-cell">
                                <button class="details-toggle" onclick="toggleTestDetails('{test_id}')">
                                    <span class="toggle-arrow">►</span>
                                    <span class="toggle-text">View Details</span>
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
                                    {full_failure_message}
                                    {installation_phase_html}
                                    {remediation_checklist_html}
                                    {api_requests_html}
                                    {cloudtrail_html}
                                    {stack_trace_html}
                                    {json_output_html}
                                    <div class="detail-section">
                                        <h4>Test Description</h4>
                                        {description_html}
                                    </div>
                                    {sources_html}
                                </div>
                            </td>
                        </tr>""")

        return '\n'.join(html_parts)

    def _generate_sources_html(self, test: Dict[str, Any]) -> str:
        """Generate Sources section HTML with file tracking information"""
        from html import escape
        import os

        # Extract file sources from user_properties
        files_accessed = {}
        files_expected_but_missing = {}

        user_properties = test.get('user_properties', [])
        if user_properties and isinstance(user_properties, list):
            for prop in user_properties:
                if isinstance(prop, dict):
                    if 'files_accessed' in prop:
                        files_accessed = prop['files_accessed']
                    elif 'files_expected_but_missing' in prop:
                        files_expected_but_missing = prop['files_expected_but_missing']

        if not files_accessed and not files_expected_but_missing:
            return ''

        html = '<div class="detail-section sources-section">'
        html += '<details style="margin: 10px 0;">'
        html += '<summary style="cursor: pointer; font-weight: bold; color: #2c3e50; padding: 8px; background: #ecf0f1; border-radius: 4px; user-select: none;">'
        html += '📁 Source files used to determine test status'
        html += '</summary>'
        html += '<div style="margin-top: 10px; padding: 10px; background: #f8f9fa; border-radius: 4px;">'

        if files_accessed:
            html += '<table class="sources-table" style="width: 100%; border-collapse: collapse; font-size: 0.85em; margin-bottom: 10px;">'
            html += '<thead>'
            html += '<tr style="background: #34495e; color: #ffffff; font-weight: 600;">'
            html += '<th style="padding: 8px; text-align: left; border: 1px solid #ddd; color: #ffffff;">File Name</th>'
            html += '<th style="padding: 8px; text-align: left; border: 1px solid #ddd; color: #ffffff;">Size</th>'
            html += '<th style="padding: 8px; text-align: left; border: 1px solid #ddd; color: #ffffff;">Created</th>'
            html += '<th style="padding: 8px; text-align: left; border: 1px solid #ddd; color: #ffffff;">Modified</th>'
            html += '</tr>'
            html += '</thead>'
            html += '<tbody>'

            for file_path, metadata in sorted(files_accessed.items()):
                file_name = metadata.get('name', os.path.basename(file_path))
                size_bytes = metadata.get('size', 0)

                # Format size
                if size_bytes < 1024:
                    size_str = f"{size_bytes} B"
                elif size_bytes < 1024 * 1024:
                    size_str = f"{size_bytes / 1024:.1f} KB"
                else:
                    size_str = f"{size_bytes / (1024 * 1024):.1f} MB"

                # Format timestamps
                created_ts = metadata.get('created', 0)
                modified_ts = metadata.get('modified', 0)
                created_str = datetime.fromtimestamp(created_ts).strftime('%Y-%m-%d %H:%M:%S') if created_ts else 'N/A'
                modified_str = datetime.fromtimestamp(modified_ts).strftime('%Y-%m-%d %H:%M:%S') if modified_ts else 'N/A'

                html += '<tr style="background: white;">'
                html += f'<td style="padding: 6px; border: 1px solid #ddd; font-family: monospace; font-size: 0.9em;" title="{escape(file_path)}">{escape(file_name)}</td>'
                html += f'<td style="padding: 6px; border: 1px solid #ddd; text-align: right;">{size_str}</td>'
                html += f'<td style="padding: 6px; border: 1px solid #ddd;">{created_str}</td>'
                html += f'<td style="padding: 6px; border: 1px solid #ddd;">{modified_str}</td>'
                html += '</tr>'

            html += '</tbody>'
            html += '</table>'

        # Show files that were expected but not found (directly checked by test)
        if files_expected_but_missing:
            html += '<div style="margin-top: 10px; padding: 10px; background: #fff3cd; border: 1px solid #ffc107; border-radius: 4px;">'
            html += '<strong style="color: #856404;">⚠ Expected Files Not Found:</strong>'
            html += '<ul style="margin: 5px 0; padding-left: 20px;">'
            for file_path, file_name in sorted(files_expected_but_missing.items()):
                html += f'<li style="font-family: monospace; font-size: 0.85em; color: #856404;" title="{escape(file_path)}">{escape(file_name)}</li>'
            html += '</ul>'
            html += '</div>'

        html += '</div>'  # Close details content
        html += '</details>'
        html += '</div>'  # Close sources-section

        return html

    def _generate_cloudtrail_events_html(self, test: Dict[str, Any]) -> str:
        """
        Generate HTML for CloudTrail events section.

        This should be called for failed/skipped tests to show related CloudTrail events.

        Args:
            test: Test result dictionary from JSON report

        Returns:
            HTML string for CloudTrail events section
        """
        from html import escape
        import os

        # Check if test has CloudTrail data
        user_properties = test.get('user_properties', [])
        cloudtrail_available = False
        cloudtrail_events = []
        cloudtrail_event_count = 0

        # Extract CloudTrail info from user_properties
        if user_properties and isinstance(user_properties, list):
            for prop in user_properties:
                if isinstance(prop, dict):
                    if 'cloudtrail_available' in prop:
                        cloudtrail_available = prop['cloudtrail_available']
                    elif 'cloudtrail_event_count' in prop:
                        cloudtrail_event_count = prop['cloudtrail_event_count']
                    elif 'cloudtrail_events' in prop:
                        cloudtrail_events = prop['cloudtrail_events']

        if not cloudtrail_available:
            return ''  # No CloudTrail data available

        # If no specific events but CloudTrail is available, show availability message
        if not cloudtrail_events:
            if cloudtrail_event_count > 0:
                return f'''
                <div class="cloudtrail-section">
                    <div class="cloudtrail-header">
                        <span class="cloudtrail-icon">📋</span>
                        <span class="cloudtrail-available-message">
                            CloudTrail data available ({cloudtrail_event_count} events collected)
                            but no specific resource correlation performed by test.
                        </span>
                    </div>
                </div>
                '''
            return ''

        # Generate HTML for CloudTrail events
        html_parts = []

        html_parts.append(f'''
        <div class="cloudtrail-section">
            <button class="cloudtrail-toggle" onclick="this.nextElementSibling.style.display = this.nextElementSibling.style.display === 'none' ? 'block' : 'none'">
                <span class="cloudtrail-icon">📋</span>
                Related CloudTrail Events ({len(cloudtrail_events)})
                <span class="toggle-indicator">▼</span>
            </button>
            <div class="cloudtrail-content" style="display: none;">
        ''')

        # Add each event
        for i, event in enumerate(cloudtrail_events):
            category = event.get('category', 'Other')
            summary = event.get('summary', 'No summary available')
            event_name = event.get('event_name', 'Unknown')
            event_time = event.get('event_time', 'Unknown')
            source_file = event.get('file', '')
            event_index = event.get('index', 0)

            # Get enhanced fields
            username = event.get('username', 'Unknown')
            user_arn = event.get('user_arn', '')
            status_code = event.get('status_code', 'Unknown')
            requested_action = event.get('requested_action', event_name)
            resource_id = event.get('resource_id', '')
            full_event = event.get('full_event', {})
            is_installer_role = event.get('is_installer_role', False)

            # Determine badge class based on category
            badge_class = {
                'Creation Failed': 'badge-creation-failed',
                'Deletion': 'badge-deletion',
                'Creation': 'badge-creation',
                'Modification': 'badge-modification',
                'Authorization': 'badge-authorization',
                'Revocation': 'badge-revocation',
                'Other': 'badge-other'
            }.get(category, 'badge-other')

            # Determine status badge color
            status_badge_class = 'status-success' if 'Success' in status_code else 'status-error'

            # Create installer role badge if applicable
            installer_badge = ''
            if is_installer_role:
                installer_badge = '<span class="badge badge-installer" style="margin-left: 8px;">INSTALLER ROLE</span>'

            # Create link to event in CloudTrail file
            event_link = ''
            if source_file:
                filename = os.path.basename(source_file)
                event_link = f'<a href="{escape(filename)}" class="event-link" title="Open {escape(filename)} and search for event #{event_index}">📄 {escape(filename)} (Event #{event_index})</a>'

            # Format full event JSON for dropdown
            import json as json_module
            full_event_json = json_module.dumps(full_event, indent=2) if full_event else '{}'

            html_parts.append(f'''
                <div class="cloudtrail-event">
                    <div class="event-header">
                        <span class="badge {badge_class}">{escape(category)}</span>
                        <strong>{escape(requested_action)}</strong>
                        <span class="badge {status_badge_class}" style="margin-left: 8px;">{escape(status_code)}</span>
                        {installer_badge}
                        <span class="event-time">{escape(str(event_time))}</span>
                    </div>
                    <div class="event-details" style="margin: 8px 0; font-size: 13px; color: #555;">
                        <div><strong>User:</strong> {escape(username)}</div>
                        {f'<div><strong>ARN:</strong> <code style="font-size: 11px; background: #f5f5f5; padding: 2px 4px; border-radius: 2px;">{escape(user_arn)}</code></div>' if user_arn else ''}
                        {f'<div><strong>Resource:</strong> {escape(resource_id)}</div>' if resource_id else ''}
                        <div style="margin-top: 4px;"><strong>Summary:</strong> {escape(summary)}</div>
                    </div>
                    {f'<div class="event-link-container" style="margin-top: 8px;">{event_link}</div>' if event_link else ''}
                    <details style="margin-top: 10px; border-top: 1px solid #e9ecef; padding-top: 10px;">
                        <summary style="cursor: pointer; font-weight: 600; color: #495057; padding: 6px; background: #f8f9fa; border-radius: 3px; user-select: none;">
                            🔍 View Full CloudTrail Event JSON
                        </summary>
                        <div style="margin-top: 10px;">
                            <pre style="background: #2d2d2d; color: #f8f8f2; padding: 15px; border-radius: 4px; overflow-x: auto; font-family: monospace; font-size: 12px; line-height: 1.5; margin: 0; max-height: 400px; overflow-y: auto;"><code>{escape(full_event_json)}</code></pre>
                        </div>
                    </details>
                </div>
            ''')

        html_parts.append('''
            </div>
        </div>
        ''')

        return '\n'.join(html_parts)

    def _generate_test_anchor_id(self, test_file: str, test_name: str) -> str:
        """
        Generate test anchor ID matching the format used in _generate_tests_html.

        Args:
            test_file: Test file path (e.g., 'tests/test_instances.py')
            test_name: Test name (e.g., 'test_control_plane_instances_running')

        Returns:
            Anchor ID matching the test's HTML element ID
        """
        # Reconstruct nodeid format: 'tests/test_instances.py::test_control_plane_instances_running'
        nodeid = f"{test_file}::{test_name}"
        # Convert to ID format matching _generate_tests_html
        return 'test-' + nodeid.replace('/', '-').replace('.', '-').replace('::', '-').replace('_', '-')

    def _generate_remediation_checklist_html(self, test: Dict[str, Any]) -> str:
        """
        Generate HTML for interactive remediation checklist.

        Shows remediation steps with status indicators (✓/✗/?) and links to related tests.

        Args:
            test: Test result dictionary from JSON report

        Returns:
            HTML string for remediation checklist section
        """
        from html import escape

        # Check if test has remediation checklist data
        user_properties = test.get('user_properties', [])
        remediation_checklist = None

        # Extract remediation checklist from user_properties
        if user_properties and isinstance(user_properties, list):
            for prop in user_properties:
                if isinstance(prop, dict) and 'remediation_checklist' in prop:
                    remediation_checklist = prop['remediation_checklist']
                    break

        if not remediation_checklist:
            return ''  # No remediation checklist available

        resource_type = remediation_checklist.get('resource_type', 'Resource')
        port = remediation_checklist.get('port', 'N/A')
        checklist = remediation_checklist.get('checklist', [])

        if not checklist:
            return ''

        html_parts = []
        html_parts.append(f'''
        <div class="detail-section remediation-checklist-section">
            <h4 style="color: #2c3e50; margin-bottom: 15px;">🔧 Interactive Remediation Checklist for {escape(resource_type)}</h4>
            <div style="background: #f8f9fa; border: 1px solid #dee2e6; border-radius: 4px; padding: 15px;">
        ''')

        for category_data in checklist:
            category = category_data.get('category', 'Unknown Category')
            checks = category_data.get('checks', [])

            html_parts.append(f'''
                <div style="margin-bottom: 20px;">
                    <h5 style="color: #495057; margin-bottom: 10px; font-size: 14px; font-weight: 600;">{escape(category)}</h5>
                    <ul style="list-style: none; padding-left: 0; margin: 0;">
            ''')

            for check in checks:
                description = check.get('description', 'No description')
                test_name = check.get('test')
                test_file = check.get('test_file', '')
                can_validate = check.get('can_validate', False)
                status = check.get('status', 'unknown')
                manual_command = check.get('manual_command', '')
                note = check.get('note', '')

                # Determine status indicator and color
                if status == 'passed':
                    status_icon = '✓'
                    status_color = '#28a745'
                    status_bg = '#d4edda'
                    status_text = 'PASSED'
                elif status == 'failed':
                    status_icon = '✗'
                    status_color = '#dc3545'
                    status_bg = '#f8d7da'
                    status_text = 'FAILED'
                elif status == 'error':
                    status_icon = '⚠'
                    status_color = '#ff6b35'
                    status_bg = '#ffe5d9'
                    status_text = 'ERROR'
                elif status == 'skipped':
                    status_icon = '○'
                    status_color = '#ffc107'
                    status_bg = '#fff3cd'
                    status_text = 'SKIPPED'
                elif status == 'manual':
                    status_icon = '⚙'
                    status_color = '#6c757d'
                    status_bg = '#e9ecef'
                    status_text = 'MANUAL'
                else:  # unknown
                    status_icon = '?'
                    status_color = '#6c757d'
                    status_bg = '#e9ecef'
                    status_text = 'UNKNOWN'

                # Build check HTML
                html_parts.append(f'''
                    <li style="margin-bottom: 12px; padding: 10px; background: white; border-left: 4px solid {status_color}; border-radius: 3px;">
                        <div style="display: flex; align-items: start; gap: 10px;">
                            <div style="flex-shrink: 0; width: 24px; height: 24px; border-radius: 50%; background: {status_bg}; color: {status_color}; display: flex; align-items: center; justify-content: center; font-weight: bold; font-size: 14px;">
                                {status_icon}
                            </div>
                            <div style="flex-grow: 1;">
                                <div style="font-size: 13px; color: #2c3e50; margin-bottom: 4px;">
                                    {escape(description)}
                                </div>
                ''')

                # Add test link if available
                if can_validate and test_name and test_file:
                    # Generate matching anchor ID using helper function
                    test_anchor = self._generate_test_anchor_id(test_file, test_name)
                    html_parts.append(f'''
                                <div style="font-size: 12px; margin-top: 4px;">
                                    <span style="background: {status_bg}; color: {status_color}; padding: 2px 6px; border-radius: 3px; font-weight: 600; font-size: 10px; margin-right: 6px;">{status_text}</span>
                                    <a href="#{test_anchor}" style="color: #007bff; text-decoration: none; font-family: monospace; font-size: 11px;" title="Jump to test: {escape(test_file)}">
                                        → {escape(test_name)}
                                    </a>
                                </div>
                    ''')
                elif status == 'manual' and manual_command:
                    html_parts.append(f'''
                                <div style="font-size: 12px; margin-top: 4px;">
                                    <span style="background: {status_bg}; color: {status_color}; padding: 2px 6px; border-radius: 3px; font-weight: 600; font-size: 10px; margin-right: 6px;">{status_text}</span>
                                    <code style="background: #f8f9fa; padding: 2px 6px; border-radius: 2px; font-size: 11px; color: #495057;">{escape(manual_command)}</code>
                                </div>
                    ''')
                elif not can_validate and note:
                    # Show status badge for inline checks (no test, no manual command, but has note)
                    html_parts.append(f'''
                                <div style="font-size: 12px; margin-top: 4px;">
                                    <span style="background: {status_bg}; color: {status_color}; padding: 2px 6px; border-radius: 3px; font-weight: 600; font-size: 10px; margin-right: 6px;">INLINE CHECK</span>
                                </div>
                    ''')

                # Add note if present
                if note:
                    html_parts.append(f'''
                                <div style="font-size: 11px; color: #6c757d; font-style: italic; margin-top: 4px;">
                                    ℹ️ {escape(note)}
                                </div>
                    ''')

                html_parts.append('''
                            </div>
                        </div>
                    </li>
                ''')

            html_parts.append('''
                    </ul>
                </div>
            ''')

        html_parts.append('''
            </div>
        </div>
        ''')

        return '\n'.join(html_parts)

    def _generate_api_requests_html(self, test: Dict[str, Any]) -> str:
        """
        Generate HTML for API request errors section.

        Shows API requests that failed during data collection, with error codes,
        timestamps, and remediation guidance.

        Args:
            test: Test result dictionary from JSON report

        Returns:
            HTML string for API requests section
        """
        from html import escape

        # Check if test has API request error data
        user_properties = test.get('user_properties', [])
        api_request_errors = []

        # Extract API request errors from user_properties
        if user_properties and isinstance(user_properties, list):
            for prop in user_properties:
                if isinstance(prop, dict) and 'api_request_errors' in prop:
                    api_request_errors = prop['api_request_errors']
                    break

        if not api_request_errors:
            return ''

        html_parts = []
        html_parts.append('''
        <div class="detail-section api-requests-section">
            <details style="margin: 10px 0;">
                <summary style="cursor: pointer; font-weight: bold; color: #e74c3c; padding: 8px; background: #fadbd8; border-radius: 4px; user-select: none;">
                    🚫 API Request Errors ({count})
                </summary>
                <div style="margin-top: 10px; padding: 10px; background: #fff5f5; border: 1px solid #e74c3c; border-radius: 4px;">
        '''.replace('{count}', str(len(api_request_errors))))

        # Group errors by service
        errors_by_service = {}
        for error in api_request_errors:
            service = error.get('service', 'unknown')
            if service not in errors_by_service:
                errors_by_service[service] = []
            errors_by_service[service].append(error)

        for service, errors in sorted(errors_by_service.items()):
            html_parts.append(f'''
                <div style="margin-bottom: 15px; border-left: 4px solid #e74c3c; padding-left: 10px;">
                    <h5 style="color: #c0392b; margin: 5px 0; font-size: 14px;">Service: {escape(service)}</h5>
            ''')

            for error in errors:
                operation = error.get('operation', 'unknown')
                error_code = error.get('error_code', 'Unknown')
                error_message = error.get('error_message', 'No message')
                timestamp = error.get('timestamp', 'Unknown')
                response_code = error.get('response_code')
                duration_ms = error.get('duration_ms')

                # Determine error category for styling
                error_category = 'permission'
                if error_code in ['AccessDenied', 'UnauthorizedOperation', 'Forbidden', 'AccessDeniedException']:
                    error_category = 'permission'
                    badge_color = '#e74c3c'
                    badge_bg = '#fadbd8'
                elif error_code in ['Throttling', 'RequestLimitExceeded', 'TooManyRequestsException']:
                    error_category = 'throttling'
                    badge_color = '#f39c12'
                    badge_bg = '#fef5e7'
                elif error_code in ['InvalidParameterValue', 'ValidationException', 'InvalidInput']:
                    error_category = 'validation'
                    badge_color = '#3498db'
                    badge_bg = '#d6eaf8'
                else:
                    error_category = 'service'
                    badge_color = '#95a5a6'
                    badge_bg = '#ecf0f1'

                html_parts.append(f'''
                    <div style="background: white; padding: 10px; margin: 8px 0; border-radius: 4px; border: 1px solid #ecf0f1;">
                        <div style="display: flex; justify-content: space-between; align-items: start; margin-bottom: 8px;">
                            <div>
                                <span style="background: {badge_bg}; color: {badge_color}; padding: 3px 8px; border-radius: 3px; font-size: 11px; font-weight: 600; margin-right: 8px;">{escape(error_code)}</span>
                                <code style="background: #f8f9fa; padding: 2px 6px; border-radius: 3px; font-size: 13px;">{escape(operation)}</code>
                            </div>
                            <div style="text-align: right; font-size: 12px; color: #7f8c8d;">
                                <div><strong>Time:</strong> {escape(str(timestamp))}</div>
                                {f'<div><strong>Duration:</strong> {duration_ms}ms</div>' if duration_ms else ''}
                                {f'<div><strong>Response Code:</strong> {response_code}</div>' if response_code else ''}
                            </div>
                        </div>
                        <div style="color: #2c3e50; font-size: 13px; margin-top: 8px; padding: 8px; background: #f8f9fa; border-radius: 3px;">
                            {escape(error_message[:300])}{'...' if len(error_message) > 300 else ''}
                        </div>
                ''')

                # Add remediation guidance based on error type
                if error_category == 'permission':
                    html_parts.append('''
                        <div style="margin-top: 8px; padding: 8px; background: #fff3cd; border-left: 3px solid #ffc107; font-size: 12px;">
                            <strong>💡 Remediation:</strong> IAM permissions missing. Add required permission to the IAM policy attached to your credentials.
                        </div>
                    ''')
                elif error_category == 'throttling':
                    html_parts.append('''
                        <div style="margin-top: 8px; padding: 8px; background: #fff3cd; border-left: 3px solid #ffc107; font-size: 12px;">
                            <strong>💡 Remediation:</strong> AWS API rate limit exceeded. Wait a few minutes and retry, or request rate limit increase.
                        </div>
                    ''')
                elif error_category == 'validation':
                    html_parts.append('''
                        <div style="margin-top: 8px; padding: 8px; background: #d6eaf8; border-left: 3px solid #3498db; font-size: 12px;">
                            <strong>💡 Remediation:</strong> Invalid request parameters. Verify resource IDs and parameter values are correct.
                        </div>
                    ''')

                html_parts.append('</div>')  # Close error div

            html_parts.append('</div>')  # Close service group div

        html_parts.append('''
                </div>
            </details>
        </div>
        ''')

        return '\n'.join(html_parts)

    def _generate_installation_phase_section_html(self, test: Dict[str, Any]) -> str:
        """
        Generate Installation Phase Analysis section.

        Extracts bootstrap_analysis_* from user_properties and renders:
        - Phase progress visualization (0-100% progress bar)
        - Timeline of completed steps
        - Current stage indicator
        - Failures with embedded remediation
        - Links to related tests

        Args:
            test: Test result dictionary from JSON report

        Returns:
            HTML string for installation phase analysis section
        """
        from html import escape

        user_properties = test.get('user_properties', [])
        bootstrap_analyses = {}

        # Extract all bootstrap analyses
        for prop in user_properties:
            if isinstance(prop, dict):
                for key, value in prop.items():
                    if key.startswith('bootstrap_analysis_'):
                        instance_id = key.replace('bootstrap_analysis_', '')
                        bootstrap_analyses[instance_id] = value

        if not bootstrap_analyses:
            return ''

        html_parts = []
        html_parts.append('''
    <div class="detail-section installation-phase-section">
        <details open style="margin: 10px 0;">
            <summary style="cursor: pointer; font-weight: bold; color: #3498db; padding: 8px; background: #e8f4f8; border: 1px solid #3498db; border-radius: 4px; user-select: none;">
                🔍 Installation Phase Analysis
            </summary>
            <div style="margin-top: 10px; padding: 15px; background: #fff; border: 1px solid #dee2e6; border-radius: 4px;">
        ''')

        for instance_id, analysis in bootstrap_analyses.items():
            instance_name = analysis.get('instance_name', instance_id)
            stage = analysis.get('stage', 'unknown')
            progress = analysis.get('progress_percentage', 0)
            current_step = analysis.get('current_step', 'Unknown')
            completed_steps = analysis.get('completed_steps', [])
            failures = analysis.get('failures', [])
            timeline = analysis.get('timeline', [])

            # Determine progress color
            if progress < 50:
                progress_color = '#ffc107'  # Yellow
            elif progress < 90:
                progress_color = '#17a2b8'  # Blue
            else:
                progress_color = '#28a745'  # Green

            # Render instance analysis
            html_parts.append(f'''
                <div class="phase-instance" style="margin-bottom: 20px; border: 1px solid #dee2e6; border-radius: 4px; overflow: hidden;">
                    <div class="phase-instance-header" style="background: #f8f9fa; padding: 12px; border-bottom: 1px solid #dee2e6;">
                        <strong>Instance:</strong> {escape(instance_name)} <span style="color: #6c757d; font-size: 12px;">({escape(instance_id)})</span>
                    </div>
                    <div class="phase-instance-body" style="padding: 15px;">
            ''')

            # Progress bar
            html_parts.append(f'''
                <div class="phase-progress-container" style="margin-bottom: 15px;">
                    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 5px;">
                        <span style="font-weight: 600; color: #2c3e50;">Progress:</span>
                        <span style="font-weight: 600; color: {progress_color};">{progress}%</span>
                    </div>
                    <div class="phase-progress-bar" style="width: 100%; height: 30px; background: #e9ecef; border-radius: 15px; overflow: hidden; position: relative;">
                        <div class="phase-progress-fill" style="width: {progress}%; height: 100%; background: linear-gradient(90deg, {progress_color}, {progress_color}aa); transition: width 0.3s ease;"></div>
                        <div style="position: absolute; top: 50%; left: 50%; transform: translate(-50%, -50%); font-size: 12px; font-weight: 600; color: #2c3e50;">
                            {escape(stage.replace('_', ' ').title())}
                        </div>
                    </div>
                </div>
            ''')

            # Current step
            html_parts.append(f'''
                <div style="margin-bottom: 15px; padding: 10px; background: #e8f4f8; border-left: 4px solid #3498db; border-radius: 4px;">
                    <strong>Current Step:</strong> {escape(current_step)}
                </div>
            ''')

            # Completed steps timeline
            if completed_steps:
                html_parts.append('''
                    <div class="phase-timeline" style="margin: 15px 0; padding: 15px; background: #f8f9fa; border-left: 3px solid #28a745; border-radius: 4px;">
                        <strong style="color: #28a745;">Completed Steps:</strong>
                        <ul style="list-style: none; padding-left: 0; margin: 10px 0 0 0;">
                ''')
                for step in completed_steps:
                    html_parts.append(f'''
                        <li class="phase-timeline-item" style="padding: 8px 0; display: flex; align-items: center; gap: 10px;">
                            <span class="phase-timeline-icon" style="width: 20px; height: 20px; border-radius: 50%; background: #28a745; display: flex; align-items: center; justify-content: center; color: white; font-size: 12px; flex-shrink: 0;">✓</span>
                            <span style="color: #2c3e50;">{escape(step)}</span>
                        </li>
                    ''')
                html_parts.append('</ul></div>')

            # Failures section
            if failures:
                html_parts.append(f'''
                    <div class="phase-failures" style="margin: 15px 0; padding: 15px; background: #fff5f5; border: 1px solid #f8d7da; border-radius: 4px;">
                        <strong style="color: #e74c3c;">⚠️ Failures Detected ({len(failures)}):</strong>
                ''')

                for failure in failures:
                    failure_type = failure.get('type', 'unknown')
                    message = failure.get('message', 'No message')
                    line = failure.get('line', 'N/A')
                    pattern_id = failure.get('pattern_id', '')
                    remediation_steps = failure.get('remediation', [])

                    html_parts.append(f'''
                        <div class="phase-failure-item" style="margin: 12px 0; padding: 12px; background: white; border-left: 4px solid #e74c3c; border-radius: 3px;">
                            <div style="font-weight: 600; color: #e74c3c; margin-bottom: 6px;">
                                {escape(failure_type.replace('_', ' ').title())} <span style="font-size: 11px; color: #6c757d;">(Line {line})</span>
                            </div>
                            <div style="font-size: 13px; color: #2c3e50; margin-bottom: 8px; font-family: monospace; background: #f8f9fa; padding: 8px; border-radius: 3px; overflow-x: auto; word-wrap: break-word;">
                                {escape(message)}
                            </div>
                    ''')

                    if remediation_steps:
                        html_parts.append('''
                            <div style="margin-top: 8px;">
                                <strong style="color: #2c3e50; font-size: 12px;">Remediation:</strong>
                                <ol style="margin: 5px 0 0 20px; padding: 0; font-size: 12px; color: #495057;">
                        ''')
                        for step in remediation_steps:
                            html_parts.append(f'<li style="margin: 4px 0;">{escape(step)}</li>')
                        html_parts.append('</ol></div>')

                    html_parts.append('</div>')  # Close failure-item

                html_parts.append('</div>')  # Close phase-failures

            # Timeline summary
            if timeline and len(timeline) > 0:
                html_parts.append(f'''
                    <div style="margin-top: 15px; padding: 10px; background: #f8f9fa; border-radius: 4px;">
                        <strong style="color: #6c757d; font-size: 12px;">Timeline:</strong>
                        <span style="color: #6c757d; font-size: 12px;">
                            {len(timeline)} events recorded
                        </span>
                    </div>
                ''')

            html_parts.append('</div></div>')  # Close phase-instance-body and phase-instance

        html_parts.append('</div></details></div>')  # Close installation-phase-section

        return '\n'.join(html_parts)

    def _parse_test_description(self, docstring: str) -> str:
        """Parse test docstring into structured HTML with enhanced sections"""
        if not docstring:
            return '<p class="no-description">No description available</p>'

        # Split docstring into parts
        lines = docstring.split('\n')
        brief = lines[0].strip() if lines else 'No description'

        # Initialize section texts
        why_text = ''
        failure_text = ''
        success_text = ''
        remediation_text = ''
        documentation_text = ''
        severity_text = ''

        # Section markers and their stop markers
        sections = {
            'Why:': ('why_text', ['Failure indicates:', 'Success indicates:', 'Remediation:', 'Documentation:', 'Severity:']),
            'Failure indicates:': ('failure_text', ['Success indicates:', 'Remediation:', 'Documentation:', 'Severity:']),
            'Success indicates:': ('success_text', ['Remediation:', 'Documentation:', 'Severity:']),
            'Remediation:': ('remediation_text', ['Documentation:', 'Severity:']),
            'Documentation:': ('documentation_text', ['Severity:']),
            'Severity:': ('severity_text', [])
        }

        for i, line in enumerate(lines):
            line_stripped = line.strip()

            for marker, (var_name, stop_markers) in sections.items():
                if line_stripped.startswith(marker):
                    # Extract initial text after marker
                    text = line_stripped[len(marker):].strip()

                    # Collect continuation lines until next section or end
                    j = i + 1
                    while j < len(lines):
                        next_line = lines[j].strip()
                        # Stop if we hit another section marker
                        if any(next_line.startswith(stop) for stop in stop_markers):
                            break
                        # Stop if empty line for non-remediation sections
                        if not next_line and marker != 'Remediation:':
                            break
                        # Add the line (preserving formatting for Remediation)
                        if marker == 'Remediation:':
                            # Preserve indentation and line breaks for code blocks
                            text += '\n' + lines[j].rstrip()
                        else:
                            text += ' ' + next_line
                        j += 1

                    # Assign to appropriate variable
                    if var_name == 'why_text':
                        why_text = text
                    elif var_name == 'failure_text':
                        failure_text = text
                    elif var_name == 'success_text':
                        success_text = text
                    elif var_name == 'remediation_text':
                        remediation_text = text
                    elif var_name == 'documentation_text':
                        documentation_text = text
                    elif var_name == 'severity_text':
                        severity_text = text

        # Build HTML output
        html = f'<p class="test-brief"><strong>{brief}</strong></p>'

        # Add severity badge if present
        if severity_text:
            severity_class = severity_text.lower().split()[0] if severity_text else 'medium'
            html += f'<span class="severity-badge severity-{severity_class}">{severity_text}</span>'

        if why_text:
            html += f'<div class="test-section test-why"><strong>Why:</strong> {why_text}</div>'

        if failure_text:
            html += f'<div class="test-section test-failure"><strong>Failure indicates:</strong> {failure_text}</div>'

        if success_text:
            html += f'<div class="test-section test-success"><strong>Success indicates:</strong> {success_text}</div>'

        if remediation_text:
            # Format remediation with code blocks
            remediation_html = remediation_text.replace('<', '&lt;').replace('>', '&gt;')
            html += f'''
            <div class="test-section test-remediation">
                <strong>Remediation:</strong>
                <pre class="remediation-code"><code>{remediation_html}</code></pre>
            </div>
            '''

        if documentation_text:
            # Make URLs clickable
            if documentation_text.startswith('http'):
                html += f'<div class="test-section test-docs"><strong>Documentation:</strong> <a href="{documentation_text}" target="_blank">{documentation_text}</a></div>'
            else:
                html += f'<div class="test-section test-docs"><strong>Documentation:</strong> {documentation_text}</div>'

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

        .category-header.status-error {
            border-left: 4px solid #ff6b35;
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

        .stat-error {
            background: #ffe5d9;
            color: #d63e00;
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
            table-layout: fixed;
        }

        /* Set fixed column widths to prevent table expansion */
        .test-table th:nth-child(1),
        .test-table td:nth-child(1) {
            width: 30%;
        }

        .test-table th:nth-child(2),
        .test-table td:nth-child(2) {
            width: 15%;
        }

        .test-table th:nth-child(3),
        .test-table td:nth-child(3) {
            width: 15%;
        }

        .test-table th:nth-child(4),
        .test-table td:nth-child(4) {
            width: 40%;
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

        .status-error .status-badge {
            background: #ffe5d9;
            color: #d63e00;
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

        .status-error .test-details {
            color: #d63e00;
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
            max-width: 100%;
            overflow-x: auto;
            box-sizing: border-box;
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
            overflow-x: auto;
            max-width: 100%;
            word-wrap: normal;
            white-space: pre;
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

        .detail-value.status-error {
            color: #ff6b35;
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

        .status-reason.status-error {
            background: #fff8f5;
            border-color: #ffe5d9;
            color: #d63e00;
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

        .test-section {
            font-size: 14px;
            line-height: 1.6;
            margin-bottom: 10px;
            color: #555;
        }

        .test-success {
            color: #28a745;
        }

        .test-remediation {
            background-color: #f8f9fa;
            border-left: 4px solid #007bff;
            padding: 12px;
            margin: 12px 0;
        }

        .test-docs a {
            color: #007bff;
            text-decoration: none;
        }

        .test-docs a:hover {
            text-decoration: underline;
        }

        .remediation-code {
            background-color: #fff;
            border: 1px solid #dee2e6;
            border-radius: 4px;
            padding: 10px;
            margin-top: 8px;
            font-family: 'Courier New', monospace;
            font-size: 13px;
            line-height: 1.5;
            overflow-x: auto;
            white-space: pre;
        }

        .severity-badge {
            display: inline-block;
            padding: 4px 12px;
            border-radius: 12px;
            font-size: 12px;
            font-weight: bold;
            margin-left: 10px;
            margin-bottom: 8px;
            text-transform: uppercase;
        }

        .severity-critical {
            background-color: #dc3545;
            color: white;
        }

        .severity-high {
            background-color: #fd7e14;
            color: white;
        }

        .severity-medium {
            background-color: #ffc107;
            color: #000;
        }

        .severity-low {
            background-color: #28a745;
            color: white;
        }

        .severity-info {
            background-color: #17a2b8;
            color: white;
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
            max-width: 100%;
            overflow-y: auto;
            overflow-x: auto;
            word-wrap: normal;
            white-space: pre;
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

        /* CloudTrail Events Section */
        .cloudtrail-section {
            margin: 16px 0;
            border: 1px solid #dee2e6;
            border-radius: 4px;
            background-color: #f8f9fa;
        }

        .cloudtrail-header {
            padding: 12px;
            display: flex;
            align-items: center;
            gap: 8px;
        }

        .cloudtrail-toggle {
            width: 100%;
            padding: 12px;
            border: none;
            background: none;
            text-align: left;
            cursor: pointer;
            display: flex;
            align-items: center;
            gap: 8px;
            font-size: 14px;
            font-weight: 600;
            color: #495057;
        }

        .cloudtrail-toggle:hover {
            background-color: #e9ecef;
        }

        .cloudtrail-icon {
            font-size: 18px;
        }

        .toggle-indicator {
            margin-left: auto;
            transition: transform 0.2s;
        }

        .cloudtrail-content {
            padding: 12px;
            border-top: 1px solid #dee2e6;
        }

        .cloudtrail-event {
            padding: 12px;
            margin-bottom: 12px;
            background-color: #fff;
            border: 1px solid #dee2e6;
            border-radius: 4px;
        }

        .cloudtrail-event:last-child {
            margin-bottom: 0;
        }

        .event-header {
            display: flex;
            align-items: center;
            gap: 8px;
            margin-bottom: 8px;
            flex-wrap: wrap;
        }

        .event-time {
            color: #6c757d;
            font-size: 13px;
            margin-left: auto;
        }

        .event-summary {
            color: #495057;
            font-size: 13px;
            line-height: 1.5;
            margin: 8px 0;
        }

        .event-link-container {
            margin-top: 8px;
            padding-top: 8px;
            border-top: 1px solid #e9ecef;
        }

        .event-link {
            color: #007bff;
            text-decoration: none;
            font-size: 13px;
            font-weight: 500;
        }

        .event-link:hover {
            text-decoration: underline;
        }

        /* CloudTrail Event Category Badges */
        .badge {
            display: inline-block;
            padding: 4px 8px;
            border-radius: 3px;
            font-size: 11px;
            font-weight: 600;
            text-transform: uppercase;
        }

        .badge-creation-failed {
            background-color: #dc3545;
            color: white;
        }

        .badge-deletion {
            background-color: #fd7e14;
            color: white;
        }

        .badge-creation {
            background-color: #28a745;
            color: white;
        }

        .badge-modification {
            background-color: #ffc107;
            color: #000;
        }

        .badge-authorization {
            background-color: #17a2b8;
            color: white;
        }

        .badge-revocation {
            background-color: #e83e8c;
            color: white;
        }

        .badge-other {
            background-color: #6c757d;
            color: white;
        }

        .badge-installer {
            background-color: #17a2b8;
            color: white;
            font-weight: 600;
        }

        .status-success {
            background-color: #28a745;
            color: white;
        }

        .status-error {
            background-color: #ff6b35;
            color: white;
        }

        .cloudtrail-available-message {
            color: #6c757d;
            font-size: 13px;
            font-style: italic;
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
                button.querySelector('.toggle-text').textContent = 'Hide Details';
            } else {
                detailsRow.classList.add('hidden');
                button.classList.remove('expanded');
                button.querySelector('.toggle-arrow').textContent = '►';
                button.querySelector('.toggle-text').textContent = 'View Details';
            }
        }

        // Function to expand test details when navigating via hash link
        function expandTestFromHash() {
            const hash = window.location.hash;
            if (hash && hash.startsWith('#test-')) {
                const testId = hash.substring(1); // Remove the '#'
                const detailsRow = document.getElementById(testId);

                if (detailsRow && detailsRow.classList.contains('test-details-row')) {
                    // Remove hidden class to show the details
                    detailsRow.classList.remove('hidden');

                    // Find the corresponding button and update it
                    const testRow = detailsRow.previousElementSibling;
                    if (testRow) {
                        const button = testRow.querySelector('.details-toggle');
                        if (button) {
                            button.classList.add('expanded');
                            const arrow = button.querySelector('.toggle-arrow');
                            const text = button.querySelector('.toggle-text');
                            if (arrow) arrow.textContent = '▼';
                            if (text) text.textContent = 'Hide Details';
                        }
                    }

                    // Scroll to the element with smooth behavior
                    setTimeout(() => {
                        detailsRow.scrollIntoView({ behavior: 'smooth', block: 'center' });
                    }, 100);
                }
            }
        }

        // Initialize on page load
        document.addEventListener('DOMContentLoaded', function() {
            // All categories start expanded, no action needed
            // Handle hash navigation on page load
            expandTestFromHash();
        });

        // Handle hash changes (when clicking links)
        window.addEventListener('hashchange', expandTestFromHash);
    </script>"""
