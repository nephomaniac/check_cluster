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


def pytest_runtest_makereport(item, call):
    """Hook to capture test docstrings and output for HTML/JSON report"""
    # Get the pytest report
    outcome = pytest.TestReport.from_item_and_call(item, call)

    if call.when == "call":
        # Get the test function's docstring
        if item.function.__doc__:
            # Store docstring as user property for JSON report
            item.user_properties.append(("test_doc", item.function.__doc__))

        # Capture stdout/stderr for HTML report
        if hasattr(outcome, 'capstdout'):
            item.user_properties.append(("captured_output", outcome.capstdout))

    return outcome


def pytest_html_results_table_header(cells):
    """Customize HTML report table header"""
    cells.insert(2, '<th>Status Reason</th>')
    cells.insert(3, '<th>Test Output</th>')
    cells.insert(1, '<th class="sortable time" data-column-type="time">Duration</th>')


def pytest_html_results_table_row(report, cells):
    """Customize HTML report table rows to include JSON output and status reason"""
    from html import escape
    import json as json_module
    import re

    # Add duration
    cells.insert(1, f'<td class="col-duration">{report.duration:.2f}s</td>')

    # Extract status reason
    status_reason_html = '<td class="col-status-reason">'

    if report.passed:
        # For passed tests, extract the success message
        if hasattr(report, 'capstdout') and report.capstdout:
            lines = report.capstdout.split('\n')
            success_lines = [line for line in lines if line.startswith('✓')]
            if success_lines:
                reason = escape(success_lines[0])
                status_reason_html += f'<span style="color: #27ae60; font-weight: 600;">{reason}</span>'
            else:
                status_reason_html += '<span style="color: #27ae60;">Passed</span>'
        else:
            status_reason_html += '<span style="color: #27ae60;">Passed</span>'

    elif report.failed:
        # For failed tests, extract the failure message
        if hasattr(report, 'capstdout') and report.capstdout:
            lines = report.capstdout.split('\n')
            failure_lines = [line for line in lines if line.startswith('✗')]
            if failure_lines:
                reason = escape(failure_lines[0])
                status_reason_html += f'<span style="color: #e74c3c; font-weight: 600;">{reason}</span>'
            else:
                status_reason_html += '<span style="color: #e74c3c;">Failed</span>'
        elif hasattr(report, 'longrepr'):
            # Extract assertion error message
            error_msg = str(report.longrepr).split('\n')[0] if report.longrepr else 'Failed'
            status_reason_html += f'<span style="color: #e74c3c; font-weight: 600;">{escape(error_msg[:100])}</span>'
        else:
            status_reason_html += '<span style="color: #e74c3c;">Failed</span>'

    elif report.skipped:
        # For skipped tests, extract the skip reason
        if hasattr(report, 'wasxfail'):
            reason = f"Expected failure: {report.wasxfail}"
            status_reason_html += f'<span style="color: #f39c12; font-style: italic;">{escape(reason)}</span>'
        elif hasattr(report, 'longrepr') and report.longrepr:
            # Extract skip reason from longrepr (format: ('path', line, 'Skipped: reason'))
            skip_msg = str(report.longrepr)
            if 'Skipped:' in skip_msg:
                # Extract just the skip message, removing file path and line number
                reason = skip_msg.split('Skipped:')[1].strip()
                # Remove trailing quote and paren if present
                if reason.endswith("')"):
                    reason = reason[:-2]
                elif reason.endswith("'"):
                    reason = reason[:-1]
                status_reason_html += f'<span style="color: #f39c12; font-style: italic;">Skipped: {escape(reason)}</span>'
            else:
                status_reason_html += f'<span style="color: #f39c12; font-style: italic;">Skipped</span>'
        else:
            status_reason_html += '<span style="color: #f39c12; font-style: italic;">Skipped</span>'

    status_reason_html += '</td>'
    cells.insert(2, status_reason_html)

    # Extract and format test output (JSON objects)
    output_html = '<td class="col-output">'

    if hasattr(report, 'capstdout') and report.capstdout:
        output = report.capstdout

        # Look for JSON blocks in the output
        json_blocks = []
        lines = output.split('\n')
        current_json = []
        in_json = False

        for line in lines:
            # Detect start of JSON
            if line.strip().startswith('[') or line.strip().startswith('{'):
                in_json = True
                current_json = [line]
            elif in_json:
                current_json.append(line)
                # Try to parse accumulated JSON
                try:
                    json_str = '\n'.join(current_json)
                    json_module.loads(json_str)
                    # Valid JSON - save it
                    json_blocks.append(json_str)
                    in_json = False
                    current_json = []
                except json_module.JSONDecodeError:
                    # Keep accumulating
                    pass

        # Format output with syntax highlighting
        formatted_output = []
        for block in json_blocks:
            # Add syntax-highlighted JSON
            formatted_output.append(f'<pre class="json-output" style="background: #f5f5f5; padding: 10px; border-radius: 4px; overflow-x: auto;"><code>{escape(block)}</code></pre>')

        if formatted_output:
            output_html += ''.join(formatted_output)
        else:
            # Show text output if no JSON found
            text_lines = [line for line in lines if line and not line.startswith('✓') and not line.startswith('✗')]
            if text_lines:
                output_html += f'<pre style="font-size: 0.9em;">{escape(chr(10).join(text_lines))}</pre>'
            else:
                output_html += '<em style="color: #888;">No JSON output</em>'
    else:
        output_html += '<em style="color: #888;">No output</em>'

    output_html += '</td>'
    cells.insert(3, output_html)


def pytest_html_report_title(report):
    """Customize HTML report title"""
    report.title = "ROSA Cluster Health Check Results"


def pytest_html_results_summary(prefix, summary, postfix):
    """Add custom summary information to HTML report"""
    prefix.extend([
        '<p style="background: #e3f2fd; padding: 15px; border-radius: 5px; margin: 10px 0;">',
        '<strong>Test Report Information:</strong><br>',
        'This report shows the results of ROSA cluster health checks. ',
        'Tests marked with ✓ show the JSON objects that met expectations. ',
        'Tests marked with ✗ show what was expected but not found.',
        '</p>'
    ])


def pytest_html_results_table_html(report, data):
    """Add custom CSS for JSON output in HTML report"""
    if not hasattr(report, 'extra_css'):
        report.extra_css = []

    report.extra_css.append("""
        <style>
            .json-output {
                background: #2d2d2d !important;
                color: #f8f8f2 !important;
                font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', 'Consolas', monospace;
                font-size: 12px;
                line-height: 1.5;
                border: 1px solid #444;
                max-height: 400px;
                overflow-y: auto;
            }

            .json-output code {
                color: #f8f8f2;
            }

            .col-status-reason {
                max-width: 400px;
                font-size: 13px;
                padding: 8px 12px;
            }

            .col-status-reason span {
                display: inline-block;
                padding: 4px 0;
            }

            .col-output {
                max-width: 600px;
                font-size: 13px;
            }

            .col-output div {
                margin-bottom: 8px;
            }

            .col-output pre {
                margin: 5px 0;
                white-space: pre-wrap;
                word-wrap: break-word;
            }

            .col-duration {
                text-align: right;
                font-family: monospace;
            }

            /* Success/Failure indicators */
            td.col-result.passed {
                background-color: #dff0d8 !important;
            }

            td.col-result.failed {
                background-color: #f2dede !important;
            }

            td.col-result.skipped {
                background-color: #fcf8e3 !important;
            }

            /* Table styling */
            table {
                border-collapse: collapse;
                width: 100%;
            }

            th {
                background-color: #337ab7 !important;
                color: white !important;
                padding: 10px !important;
                text-align: left;
            }

            td {
                padding: 8px !important;
                border-bottom: 1px solid #ddd;
                vertical-align: top;
            }

            tr:hover {
                background-color: #f5f5f5;
            }

            /* Collapsible sections */
            .collapsible {
                cursor: pointer;
                padding: 10px;
                background-color: #f0f0f0;
                border: none;
                text-align: left;
                width: 100%;
                font-weight: bold;
            }

            .collapsible:hover {
                background-color: #e0e0e0;
            }
        </style>
    """)
