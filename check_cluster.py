#!/usr/bin/env python3
"""
check_cluster.py - Unified ROSA Cluster Health Check Tool

Consolidates cluster data collection, validation, and reporting into a single workflow.

SYNOPSIS:
  check_cluster.py <cluster-id> [options]
  check_cluster.py -h|--help

DESCRIPTION:
  Automated end-to-end ROSA cluster health checking tool that:
  1. Collects cluster data from OCM and AWS APIs
  2. Runs comprehensive validation tests
  3. Generates detailed HTML and JSON reports

  By default, runs all operations (collect → test → report).
  Individual operations can be run separately using --collect, --test, or --report flags.

For detailed usage information, see CHECK_README.md
"""

import sys
import argparse
import subprocess
import json
import traceback
from pathlib import Path
from datetime import datetime


class Colors:
    """ANSI color codes for terminal output"""
    RED = '\033[1;31m'
    BLUE = '\033[1;34m'
    GREEN = '\033[1;32m'
    YELLOW = '\033[1;33m'
    RESET = '\033[0m'
    BOLD = '\033[1m'

    @staticmethod
    def error(msg: str):
        """Print red error message"""
        print(f"{Colors.RED}{msg}{Colors.RESET}", file=sys.stderr)

    @staticmethod
    def info(msg: str):
        """Print blue info message"""
        print(f"{Colors.BLUE}{msg}{Colors.RESET}")

    @staticmethod
    def success(msg: str):
        """Print green success message"""
        print(f"{Colors.GREEN}{msg}{Colors.RESET}")

    @staticmethod
    def warning(msg: str):
        """Print yellow warning message"""
        print(f"{Colors.YELLOW}{msg}{Colors.RESET}")

    @staticmethod
    def header(msg: str):
        """Print header with lines"""
        print()
        print('=' * 80)
        print(f"{Colors.BOLD}{Colors.BLUE}{msg}{Colors.RESET}")
        print('=' * 80)
        print()


def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description='Unified ROSA Cluster Health Check Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Full workflow: collect, test, and report
  %(prog)s <cluster-id>

  # Collect data only
  %(prog)s <cluster-id> --collect

  # Collect specific resources only (IAM)
  %(prog)s <cluster-id> --collect --resources=iam

  # Collect multiple resource types
  %(prog)s <cluster-id> --collect --resources=vpc,ec2,quotas

  # Test existing data
  %(prog)s <cluster-id> --test --output-dir existing_data/

  # Regenerate report
  %(prog)s <cluster-id> --report --json-output results.json

For detailed help, see CHECK_README.md
        """
    )

    # Positional argument
    parser.add_argument('cluster_id',
                        help='ROSA cluster ID to check')

    # Operation selection
    ops = parser.add_argument_group('Operations')
    ops.add_argument('--collect', action='store_true',
                     help='Collect cluster data from OCM and AWS')
    ops.add_argument('--test', action='store_true',
                     help='Run validation tests on collected data')
    ops.add_argument('--report', action='store_true',
                     help='Generate HTML report from test results')
    ops.add_argument('--all', action='store_true',
                     help='Run all operations: collect → test → report (default)')

    # Collection options
    collection = parser.add_argument_group('Collection Options')
    collection.add_argument('--resources',
                           help='Comma-separated list of resources to collect: '
                                'iam, vpc, ec2, quotas, cloudtrail, route53, security-groups, load-balancers, all (default: all)')
    collection.add_argument('-r', '--region',
                           help='AWS region (default: from cluster.json)')
    collection.add_argument('-s', '--start',
                           help='CloudTrail start date (YYYY-MM-DDTHH:MM:SSZ)')
    collection.add_argument('-e', '--elapsed',
                           help='CloudTrail window (e.g., "3h", "2d", "4days")')
    collection.add_argument('-p', '--period', type=int,
                           help='CloudWatch metrics period in seconds (default: 300)')
    collection.add_argument('--force-update', action='store_true',
                           help='Force recalculation of time range')
    collection.add_argument('--debug', action='store_true',
                           help='Enable debug output')

    # Test options
    test_opts = parser.add_argument_group('Test Options')
    test_opts.add_argument('--tests-only', action='store_true',
                          help='Run tests without HTML report')
    test_opts.add_argument('-v', '--verbose', action='store_true',
                          help='Enable verbose test output')

    # Output options
    output = parser.add_argument_group('Output Options')
    output.add_argument('-d', '--output-dir',
                       help='Output directory (default: <cluster-id>/)')
    output.add_argument('--json-output',
                       help='JSON test results path (default: <dir>/results/test_results.json)')
    output.add_argument('--html-output',
                       help='HTML report path (default: <dir>/results/report_<timestamp>.html)')

    args = parser.parse_args()

    # If no operation specified, default to --all
    if not (args.collect or args.test or args.report or args.all):
        args.all = True

    # --all means all three operations
    if args.all:
        args.collect = True
        args.test = True
        args.report = True

    # Set default output directory
    if not args.output_dir:
        args.output_dir = args.cluster_id

    return args


def detect_platform(cluster_id: str, output_dir: str) -> str:
    """
    Detect cluster platform (AWS or GCP) by checking cluster metadata.

    Args:
        cluster_id: Cluster ID
        output_dir: Output directory

    Returns:
        'aws' or 'gcp'
    """
    # Try to read existing cluster.json
    cluster_file = Path(output_dir) / cluster_id / 'sources' / 'ocm' / f'{cluster_id}_cluster.json'

    if cluster_file.exists():
        try:
            cluster_json = json.loads(cluster_file.read_text())

            # Check for AWS-specific fields
            if 'aws' in cluster_json or 'aws_infrastructure_access_role_grants' in cluster_json:
                return 'aws'

            # Check for GCP-specific fields
            if 'gcp' in cluster_json or 'gcp_network' in cluster_json:
                return 'gcp'

        except:
            pass

    # Fall back to querying OCM
    try:
        import subprocess
        result = subprocess.run(
            ['ocm', 'get', 'cluster', cluster_id],
            capture_output=True,
            text=True,
            timeout=10
        )

        if result.returncode == 0:
            cluster_json = json.loads(result.stdout)

            if 'aws' in cluster_json or 'aws_infrastructure_access_role_grants' in cluster_json:
                return 'aws'

            if 'gcp' in cluster_json or 'gcp_network' in cluster_json:
                return 'gcp'

    except:
        pass

    # Default to AWS for backward compatibility
    return 'aws'


def run_collection(args):
    """
    Run data collection phase using appropriate collector for platform

    Returns: True if successful, False otherwise
    """
    Colors.header(f"PHASE 1: Collecting Cluster Data for {args.cluster_id}")

    try:
        # Detect platform
        platform = detect_platform(args.cluster_id, args.output_dir)
        Colors.info(f"Detected platform: {platform.upper()}")

        # Parse resources argument
        resources_to_collect = None
        if args.resources:
            resources_to_collect = [r.strip() for r in args.resources.split(',')]
            Colors.info(f"Collecting specific resources: {', '.join(resources_to_collect)}")

        # Create platform-specific collector
        if platform == 'gcp':
            from lib.gcp_data_collection import GCPDataCollector

            collector = GCPDataCollector(
                cluster_id=args.cluster_id,
                work_dir=args.output_dir,
                force_update=args.force_update,
                debug=args.debug,
                resources=resources_to_collect
            )
        else:
            # AWS (default)
            from lib.data_collection import ClusterDataCollector

            collector = ClusterDataCollector(
                cluster_id=args.cluster_id,
                work_dir=args.output_dir,
                region=args.region,
                start_date=args.start,
                elapsed_time=args.elapsed,
                period=args.period if args.period else 300,
                force_update=args.force_update,
                debug=args.debug,
                resources=resources_to_collect
            )

        # Run collection
        collector.run()

        Colors.success("✓ Data collection completed successfully")
        return True

    except ImportError as e:
        Colors.error(f"✗ Error: Failed to import data collection module")
        Colors.error(f"   {e}")
        return False
    except Exception as e:
        Colors.error(f"✗ Data collection failed: {e}")
        if args.debug:
            traceback.print_exc()
        return False


def run_tests(args):
    """
    Run test phase using pytest

    Returns: True if successful, False otherwise
    """
    Colors.header(f"PHASE 2: Running Validation Tests for {args.cluster_id}")

    # Determine paths
    cluster_dir = Path(args.output_dir)
    results_dir = cluster_dir / 'results'
    results_dir.mkdir(parents=True, exist_ok=True)

    json_output = args.json_output if args.json_output else str(results_dir / 'test_results.json')

    if args.html_output:
        html_output = args.html_output
    else:
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        html_output = str(results_dir / f'report_{timestamp}.html')

    # Build pytest command
    cmd = [
        'uv', 'run', 'pytest',
        'tests/',
        f'--cluster-dir={cluster_dir}',
        '--json-report',
        f'--json-report-file={json_output}',
        '--json-report-indent=2',
        f'--html={html_output}',
        '--self-contained-html',
        '--color=yes'
    ]

    if args.verbose:
        cmd.append('-v')
    else:
        cmd.append('-q')

    Colors.info(f"Running: {' '.join(cmd)}")
    print()

    try:
        result = subprocess.run(cmd)

        if result.returncode == 0:
            Colors.success("✓ Tests completed successfully")
        else:
            Colors.warning(f"⚠ Tests completed with exit code {result.returncode}")

        # Show summary
        if Path(json_output).exists():
            try:
                with open(json_output) as f:
                    test_data = json.load(f)
                    summary = test_data.get('summary', {})
                    total = summary.get('total', 0)
                    passed = summary.get('passed', 0)
                    failed = summary.get('failed', 0)
                    skipped = summary.get('skipped', 0)

                    print()
                    Colors.info(f"Test Summary:")
                    print(f"  Total:   {total}")
                    print(f"  Passed:  {Colors.GREEN}{passed}{Colors.RESET}")
                    if failed > 0:
                        print(f"  Failed:  {Colors.RED}{failed}{Colors.RESET}")
                    else:
                        print(f"  Failed:  {failed}")
                    print(f"  Skipped: {skipped}")
                    print()
                    Colors.info(f"Results saved to: {json_output}")

                    # Generate HTML report if not tests-only
                    if not args.tests_only and args.report:
                        if generate_html_report(json_output, cluster_dir, html_output):
                            Colors.info(f"HTML report:     {html_output}")
            except Exception as e:
                Colors.warning(f"Could not read test summary: {e}")

        return result.returncode == 0

    except FileNotFoundError:
        Colors.error("✗ Error: 'uv' command not found")
        Colors.error("   Install uv with: curl -LsSf https://astral.sh/uv/install.sh | sh")
        return False
    except Exception as e:
        Colors.error(f"✗ Tests failed: {e}")
        return False


def generate_html_report(json_output: str, cluster_dir: Path, html_output: str) -> bool:
    """
    Generate HTML report using HTMLReportGenerator

    Returns: True if successful, False otherwise
    """
    try:
        from reporters.html_generator import HTMLReportGenerator

        print(f"\nGenerating custom HTML report...")
        generator = HTMLReportGenerator(Path(json_output), cluster_dir)
        generator.generate_html(Path(html_output))

        return True
    except ImportError as e:
        Colors.warning(f"Could not import HTMLReportGenerator: {e}")
        Colors.warning("Using pytest-html report instead")
        return False
    except json.JSONDecodeError as e:
        Colors.error(f"✗ Error parsing JSON report: {e}")
        return False
    except Exception as e:
        Colors.error(f"✗ Error generating HTML report: {e}")
        if '--debug' in sys.argv:
            traceback.print_exc()
        return False


def run_report_only(args):
    """
    Generate HTML report only from existing test results

    Returns: True if successful, False otherwise
    """
    Colors.header(f"Generating HTML Report for {args.cluster_id}")

    # Determine paths
    cluster_dir = Path(args.output_dir)
    results_dir = cluster_dir / 'results'

    if args.json_output:
        json_output = args.json_output
    else:
        json_output = str(results_dir / 'test_results.json')

    if not Path(json_output).exists():
        Colors.error(f"✗ Error: Test results not found at {json_output}")
        Colors.error("   Run with --test first to generate test results")
        return False

    if args.html_output:
        html_output = args.html_output
    else:
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        html_output = str(results_dir / f'report_{timestamp}.html')

    # Generate report
    if generate_html_report(json_output, cluster_dir, html_output):
        Colors.success("✓ HTML report generated successfully")
        Colors.info(f"Report saved to: {html_output}")
        return True
    else:
        return False


def main():
    """Main entry point"""
    args = parse_arguments()

    Colors.header(f"ROSA Cluster Health Check: {args.cluster_id}")

    # Track success of each phase
    success = True

    # Execute requested operations
    if args.collect:
        if not run_collection(args):
            success = False
            if args.test or args.report:
                Colors.error("Skipping remaining operations due to collection failure")
                sys.exit(1)

    if args.test and not args.report:
        # Tests only, no report
        if not run_tests(args):
            success = False

    elif args.test and args.report:
        # Tests with report generation (report is generated within run_tests)
        if not run_tests(args):
            success = False

    elif args.report and not args.test:
        # Report only from existing results
        if not run_report_only(args):
            success = False

    # Final summary
    print()
    print('=' * 80)
    if success:
        Colors.success("✓ All operations completed successfully")

        # Show output location
        output_dir = Path(args.output_dir)
        print()
        Colors.info(f"Output directory: {output_dir.absolute()}")

        if args.collect:
            sources_dir = output_dir / 'sources'
            if sources_dir.exists():
                Colors.info(f"  Cluster data: {sources_dir}")

        if args.test or args.report:
            results_dir = output_dir / 'results'
            if results_dir.exists():
                Colors.info(f"  Test results: {results_dir}")
                # Find HTML reports
                html_files = list(results_dir.glob('report_*.html'))
                if html_files:
                    latest_report = max(html_files, key=lambda p: p.stat().st_mtime)
                    Colors.info(f"  Latest report: {latest_report.name}")
    else:
        Colors.error("✗ Some operations failed - see errors above")
        sys.exit(1)

    print('=' * 80)
    print()


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print()
        Colors.warning("Operation cancelled by user")
        sys.exit(130)
    except Exception as e:
        Colors.error(f"Unexpected error: {e}")
        traceback.print_exc()
        sys.exit(1)
