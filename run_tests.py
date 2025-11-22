#!/usr/bin/env python3
"""
ROSA Cluster Health Check Runner

Main entry point for running cluster health checks and generating reports.
"""

import sys
import argparse
from pathlib import Path
import subprocess
from reporters.html_generator import HTMLReportGenerator


def run_pytest(cluster_dir: Path, json_output: Path, html_output: Path, verbose: bool = False) -> int:
    """
    Run pytest with appropriate options.

    Args:
        cluster_dir: Path to cluster data directory
        json_output: Path for JSON report output
        html_output: Path for HTML report output
        verbose: Enable verbose output

    Returns:
        Exit code from pytest
    """
    cmd = [
        'pytest',
        'tests/',
        f'--cluster-dir={cluster_dir}',
        f'--json-report',
        f'--json-report-file={json_output}',
        '--json-report-indent=2',
    ]

    if verbose:
        cmd.append('-v')
    else:
        cmd.append('-q')

    # Add color output
    cmd.append('--color=yes')

    print(f"Running tests for cluster data in: {cluster_dir}")
    print(f"Command: {' '.join(str(c) for c in cmd)}\n")

    result = subprocess.run(cmd)
    return result.returncode


def generate_html_report(json_report: Path, cluster_dir: Path, html_output: Path) -> None:
    """
    Generate HTML report from pytest JSON output.

    Args:
        json_report: Path to pytest JSON report
        cluster_dir: Path to cluster data directory
        html_output: Path for HTML report output
    """
    print(f"\nGenerating HTML report...")

    generator = HTMLReportGenerator(json_report, cluster_dir)
    generator.generate_html(html_output)

    print(f"HTML report generated: {html_output}")


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description='Run ROSA cluster health checks and generate reports',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Run tests for a cluster and generate reports
  %(prog)s --cluster-dir broken

  # Run tests with verbose output
  %(prog)s --cluster-dir new_good --verbose

  # Specify custom output paths
  %(prog)s --cluster-dir broken --html-output custom_report.html
        """
    )

    parser.add_argument(
        '--cluster-dir',
        type=Path,
        required=True,
        help='Path to directory containing cluster data files'
    )

    parser.add_argument(
        '--json-output',
        type=Path,
        default=Path('test_results.json'),
        help='Path for JSON test results (default: test_results.json)'
    )

    parser.add_argument(
        '--html-output',
        type=Path,
        default=Path('test_report.html'),
        help='Path for HTML report (default: test_report.html)'
    )

    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable verbose output'
    )

    parser.add_argument(
        '--tests-only',
        action='store_true',
        help='Run tests only, do not generate HTML report'
    )

    parser.add_argument(
        '--report-only',
        action='store_true',
        help='Generate HTML report only (requires existing JSON results)'
    )

    args = parser.parse_args()

    # Validate cluster directory
    if not args.cluster_dir.exists():
        print(f"Error: Cluster directory does not exist: {args.cluster_dir}", file=sys.stderr)
        return 1

    if not args.cluster_dir.is_dir():
        print(f"Error: Not a directory: {args.cluster_dir}", file=sys.stderr)
        return 1

    # Run tests
    exit_code = 0
    if not args.report_only:
        exit_code = run_pytest(
            args.cluster_dir,
            args.json_output,
            args.html_output,
            args.verbose
        )

    # Generate HTML report
    if not args.tests_only:
        if not args.json_output.exists():
            print(f"Error: JSON report not found: {args.json_output}", file=sys.stderr)
            print("Run tests first or check --json-output path", file=sys.stderr)
            return 1

        try:
            generate_html_report(args.json_output, args.cluster_dir, args.html_output)
        except Exception as e:
            print(f"Error generating HTML report: {e}", file=sys.stderr)
            return 1

    return exit_code


if __name__ == '__main__':
    sys.exit(main())
