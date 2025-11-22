#!/usr/bin/env python3

"""
get_install_artifacts.py - ROSA Cluster Data Collection Tool

SUMMARY:
  Automated data collection script for Red Hat OpenShift Service on AWS (ROSA)
  cluster troubleshooting and post-mortem analysis. Gathers comprehensive AWS
  infrastructure and OpenShift cluster installation artifacts.

USAGE:
  ./get_install_artifacts.py -c <cluster-id>
  ./get_install_artifacts.py --cluster <cluster-id> -d <directory>

PREREQUISITES:
  - ocm CLI (logged in)
  - aws CLI (v2) and boto3
  - Valid AWS credentials (eval $(ocm backplane cloud credentials <cluster-id> -o env))
  - Python packages: boto3, argparse, json
"""

import argparse
import json
import os
import re
import subprocess
import sys
import time
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any


class Colors:
    """ANSI color codes for terminal output"""
    RED = '\033[1;31m'
    BLUE = '\033[1;34m'
    GREEN = '\033[1;32m'
    RESET = '\033[0m'

    @staticmethod
    def perr(msg: str):
        """Print red text to stderr"""
        print(f"{Colors.RED}{msg}{Colors.RESET}", file=sys.stderr)

    @staticmethod
    def blue(msg: str):
        """Print blue text"""
        print(f"{Colors.BLUE}{msg}{Colors.RESET}")

    @staticmethod
    def green(msg: str):
        """Print green text"""
        print(f"{Colors.GREEN}{msg}{Colors.RESET}")

    @staticmethod
    def hdr(msg: str):
        """Print header with lines"""
        try:
            width = min(80, os.get_terminal_size().columns)
        except (OSError, AttributeError):
            width = 80
        print()
        print('-' * width)
        Colors.blue(msg)
        print('-' * width)


def printline(char: str = '-', width: Optional[int] = None):
    """Print a line of characters"""
    if width is None:
        try:
            width = min(80, os.get_terminal_size().columns)
        except (OSError, AttributeError):
            width = 80
    print(char * width)


def parse_elapsed_time(elapsed_str: str) -> Tuple[int, str]:
    """
    Parse elapsed time format (e.g., "3h", "2d", "4days", "3minutes")
    Returns: (number, unit_in_hours) for timedelta calculation
    """
    match = re.match(r'^(\d+)([a-zA-Z]+)$', elapsed_str)
    if not match:
        Colors.perr(f"Error: Invalid elapsed time format '{elapsed_str}'. Expected format: <number><unit> (e.g., '3h', '2days')")
        sys.exit(1)

    num = int(match.group(1))
    unit = match.group(2).lower()

    if unit in ['h', 'hour', 'hours']:
        return num, 'hours'
    elif unit in ['m', 'minute', 'minutes']:
        return num, 'minutes'
    elif unit in ['d', 'day', 'days']:
        return num, 'days'
    else:
        Colors.perr(f"Error: Invalid time unit '{unit}'. Use h/hours, m/minutes, or d/days")
        sys.exit(1)


def format_aws_cli_command(service: str, operation: str, params: Dict[str, Any]) -> str:
    """Format boto3 call as AWS CLI equivalent command with proper quoting"""
    cmd_parts = [f"aws {service} {operation}"]

    for key, value in params.items():
        # Convert boto3 parameter names to CLI format (CamelCase to kebab-case)
        cli_key = re.sub(r'([A-Z])', r'-\1', key).lower().lstrip('-')

        if isinstance(value, list):
            if all(isinstance(item, dict) for item in value):
                # Complex list like Filters or Dimensions
                # Example: --filters "Name=tag:Name,Values=*infra-id*"
                filter_parts = []
                for item in value:
                    # Format each dict as key=value pairs
                    parts = []
                    for k, v in item.items():
                        if isinstance(v, list):
                            # For list values like Values=[...], join them
                            v_str = ','.join(str(x) for x in v)
                            parts.append(f"{k}={v_str}")
                        else:
                            parts.append(f"{k}={v}")
                    filter_parts.append(','.join(parts))
                # Join multiple filter dicts with space and quote the whole thing
                filters_str = ' '.join(filter_parts)
                cmd_parts.append(f'--{cli_key} "{filters_str}"')
            else:
                # Simple list of strings/values - quote if contains spaces or special chars
                list_str = ' '.join(str(v) for v in value)
                if ' ' in list_str or any(c in list_str for c in ['*', '?', '[', ']', '(', ')']):
                    cmd_parts.append(f'--{cli_key} "{list_str}"')
                else:
                    cmd_parts.append(f"--{cli_key} {list_str}")
        elif isinstance(value, dict):
            # JSON format - use single quotes to avoid escaping internal double quotes
            json_str = json.dumps(value)
            cmd_parts.append(f"--{cli_key} '{json_str}'")
        elif isinstance(value, bool):
            if value:
                cmd_parts.append(f"--{cli_key}")
        elif isinstance(value, str):
            # Quote strings if they contain spaces, wildcards, or special characters
            if ' ' in value or any(c in value for c in ['*', '?', '[', ']', '(', ')', '$', '&', '|', ';']):
                cmd_parts.append(f'--{cli_key} "{value}"')
            else:
                cmd_parts.append(f"--{cli_key} {value}")
        else:
            # Numbers and other types don't need quoting
            cmd_parts.append(f"--{cli_key} {value}")

    cmd_parts.append("--output json")
    return ' '.join(cmd_parts)


class AWSCollector:
    """AWS data collection with retry logic and CLI command printing"""

    def __init__(self, region: str = None, max_retries: int = 3, retry_delay: int = 1, debug: bool = False):
        # Import boto3 here so help can be displayed without it
        try:
            import boto3
            from botocore.exceptions import ClientError, BotoCoreError, NoCredentialsError
            self.boto3 = boto3
            self.ClientError = ClientError
            self.BotoCoreError = BotoCoreError
            self.NoCredentialsError = NoCredentialsError
        except ImportError:
            Colors.perr("Error: boto3 is not installed. Please install it with: pip install boto3")
            sys.exit(1)

        self.region = region or os.environ.get('AWS_REGION', 'us-east-1')
        self.max_retries = max_retries
        self.retry_delay = retry_delay
        self.debug = debug

        # Track if we've already shown detailed UnauthorizedOperation error
        self._shown_detailed_auth_error = False

        # Initialize boto3 session from environment variables explicitly
        # This ensures boto3 uses the same credentials as AWS CLI
        session_params = {}
        if os.environ.get('AWS_ACCESS_KEY_ID'):
            session_params['aws_access_key_id'] = os.environ.get('AWS_ACCESS_KEY_ID')
        if os.environ.get('AWS_SECRET_ACCESS_KEY'):
            session_params['aws_secret_access_key'] = os.environ.get('AWS_SECRET_ACCESS_KEY')
        if os.environ.get('AWS_SESSION_TOKEN'):
            session_params['aws_session_token'] = os.environ.get('AWS_SESSION_TOKEN')
        if self.region:
            session_params['region_name'] = self.region

        # Create session with explicit credentials
        if session_params:
            session = boto3.Session(**session_params)
        else:
            session = boto3.Session(region_name=self.region)

        # Configure proxy settings from environment or AWS config
        # boto3 automatically uses HTTP_PROXY, HTTPS_PROXY, NO_PROXY env vars
        client_config = None

        # Check for proxy in environment variables (same as AWS CLI uses)
        https_proxy = os.environ.get('HTTPS_PROXY') or os.environ.get('https_proxy')
        http_proxy = os.environ.get('HTTP_PROXY') or os.environ.get('http_proxy')
        no_proxy = os.environ.get('NO_PROXY') or os.environ.get('no_proxy')
        ca_bundle = os.environ.get('AWS_CA_BUNDLE')

        # Also check AWS CLI config file for proxy and ca_bundle settings
        aws_config_file = os.path.expanduser('~/.aws/config')
        if os.path.exists(aws_config_file):
            try:
                import configparser
                config = configparser.ConfigParser()
                config.read(aws_config_file)

                # Determine which profile to use
                profile = os.environ.get('AWS_PROFILE')

                # Try specified profile first, then fall back to default
                sections_to_try = []
                if profile:
                    # If profile specified, try "profile {name}" format
                    sections_to_try.append(f'profile {profile}')
                    sections_to_try.append(profile)  # Some configs use just the name

                # Always fall back to default section
                sections_to_try.append('default')

                for section in sections_to_try:
                    if config.has_section(section):
                        # Read ca_bundle if not already set
                        if not ca_bundle and config.has_option(section, 'ca_bundle'):
                            ca_bundle = config.get(section, 'ca_bundle').strip('"').strip("'")
                            if self.debug:
                                print(f"Read ca_bundle from [{section}]: {ca_bundle}")

                        # Read proxy settings from config if not in environment
                        if not https_proxy and config.has_option(section, 'https_proxy'):
                            https_proxy = config.get(section, 'https_proxy').strip('"').strip("'")
                            if self.debug:
                                print(f"Read https_proxy from [{section}]: {https_proxy}")

                        if not http_proxy and config.has_option(section, 'http_proxy'):
                            http_proxy = config.get(section, 'http_proxy').strip('"').strip("'")
                            if self.debug:
                                print(f"Read http_proxy from [{section}]: {http_proxy}")

                        if not no_proxy and config.has_option(section, 'no_proxy'):
                            no_proxy = config.get(section, 'no_proxy').strip('"').strip("'")
                            if self.debug:
                                print(f"Read no_proxy from [{section}]: {no_proxy}")

                        # If we found values, stop looking
                        if https_proxy or http_proxy or ca_bundle:
                            break
            except Exception as e:
                if self.debug:
                    print(f"Warning: Failed to read AWS config file: {str(e)}")

        if https_proxy or http_proxy:
            # boto3 Config object for proxy and SSL settings
            from botocore.config import Config

            config_params = {}

            proxy_config = {}
            if https_proxy:
                proxy_config['https'] = https_proxy
            if http_proxy:
                proxy_config['http'] = http_proxy

            config_params['proxies'] = proxy_config
            config_params['proxies_config'] = {'proxy_use_forwarding_for_https': True}

            client_config = Config(**config_params)

            if self.debug:
                print("Proxy configuration detected:")
                if https_proxy:
                    print(f"  HTTPS proxy: {https_proxy}")
                if http_proxy:
                    print(f"  HTTP proxy: {http_proxy}")
                if no_proxy:
                    print(f"  NO_PROXY: {no_proxy}")

        if ca_bundle and self.debug:
            print(f"  CA bundle: {ca_bundle}")

        # Initialize boto3 clients from session with proxy config
        # Add verify parameter for CA bundle if specified
        client_kwargs = {}
        if client_config is not None:
            client_kwargs['config'] = client_config
        if ca_bundle:
            client_kwargs['verify'] = ca_bundle

        self.ec2 = session.client('ec2', region_name=self.region, **client_kwargs)
        self.elbv2 = session.client('elbv2', region_name=self.region, **client_kwargs)
        self.elb = session.client('elb', region_name=self.region, **client_kwargs)
        self.route53 = session.client('route53', **client_kwargs)
        self.cloudtrail = session.client('cloudtrail', region_name=self.region, **client_kwargs)
        self.cloudwatch = session.client('cloudwatch', region_name=self.region, **client_kwargs)
        self.sts = session.client('sts', region_name=self.region, **client_kwargs)

    def validate_credentials(self, cluster_data: Dict = None, cluster_id: str = None,
                           show_header: bool = True) -> bool:
        """
        Validate AWS credentials are present, not expired, and match the cluster account.

        Args:
            cluster_data: Optional cluster data from OCM to validate account match
            cluster_id: Optional cluster ID for better error messages
            show_header: Whether to show the validation header

        Returns True if valid, False otherwise.
        """
        if show_header:
            Colors.hdr("Validating AWS Credentials")

        # Check if AWS credentials are configured
        if not os.environ.get('AWS_ACCESS_KEY_ID') and not os.environ.get('AWS_PROFILE'):
            Colors.perr("No AWS credentials found in environment")
            Colors.perr("Please run:")
            self._print_credential_refresh_instructions()
            return False

        try:
            # Call STS get-caller-identity to validate credentials
            if self.debug:
                print("aws sts get-caller-identity --output json")
            response = self.sts.get_caller_identity()

            # Display credential information
            account = response.get('Account', 'Unknown')
            arn = response.get('Arn', 'Unknown')
            user_id = response.get('UserId', 'Unknown')

            # Only show validation success if this is the initial check
            if not cluster_data:
                Colors.green(f"✓ AWS credentials are valid")
                if self.debug:
                    print(f"  Account: {account}")
                    print(f"  ARN: {arn}")
                    print(f"  User ID: {user_id}")
                else:
                    print(f"  Account: {account}")
                    print(f"  ARN: {arn}")
                print()

            # If cluster data is provided, validate account matches
            if cluster_data and account != 'Unknown':
                if not self._validate_account_match(account, arn, cluster_data, cluster_id):
                    return False

            return True

        except self.ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', 'Unknown')
            error_msg = e.response.get('Error', {}).get('Message', str(e))

            if error_code == 'ExpiredToken':
                Colors.perr("✗ AWS credentials have expired")
                Colors.perr(f"  Error: {error_msg}")
                Colors.perr("")
                Colors.perr("Please refresh your credentials:")
                self._print_credential_refresh_instructions()
            elif error_code == 'InvalidClientTokenId':
                Colors.perr("✗ AWS credentials are invalid")
                Colors.perr(f"  Error: {error_msg}")
                Colors.perr("")
                Colors.perr("Please set valid credentials:")
                self._print_credential_refresh_instructions()
            else:
                Colors.perr(f"✗ Failed to validate AWS credentials: {error_code}")
                Colors.perr(f"  Error: {error_msg}")

            return False

        except self.NoCredentialsError:
            Colors.perr("✗ No AWS credentials configured")
            Colors.perr("")
            Colors.perr("Please set your AWS credentials:")
            self._print_credential_refresh_instructions()
            return False

        except Exception as e:
            Colors.perr(f"✗ Unexpected error validating credentials: {str(e)}")
            return False

    def _get_caller_identity_details(self) -> str:
        """Get caller identity details for troubleshooting permission errors"""
        try:
            response = self.sts.get_caller_identity()
            account = response.get('Account', 'Unknown')
            arn = response.get('Arn', 'Unknown')
            user_id = response.get('UserId', 'Unknown')

            details = [
                "Current AWS Identity:",
                f"  Account: {account}",
                f"  ARN: {arn}",
                f"  User ID: {user_id}"
            ]
            return '\n'.join(details)
        except Exception:
            return "  Unable to retrieve caller identity"

    @staticmethod
    def _print_credential_refresh_instructions():
        """Print standard instructions for refreshing AWS credentials"""
        Colors.perr("  Set missing or expired AWS env vars:")
        Colors.perr("  AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_SESSION_TOKEN, AWS_DEFAULT_REGION, AWS_REGION")
        Colors.perr("  ocm backplane, and osdctl methods...")
        Colors.perr("  eval $(ocm backplane cloud credentials <cluster-id> -o env)")
        Colors.perr("  ...or to use local rosa creds...")
        Colors.perr("  ACCT_ID=\"$(osdctl account mgmt list -u ${OCM_USER_ID} -p ${ROSA_AWS_PROFILE} -o json | jq -r '.accounts[0]' 2>/dev/null )\"")
        Colors.perr("  eval $(osdctl account cli -i ${ACCT_ID} -p ${ROSA_AWS_PROFILE} -r ${REGION} -o env)")

    def _validate_account_match(self, sts_account: str, sts_arn: str,
                                cluster_data: Dict, cluster_id: str = None) -> bool:
        """
        Validate that the STS caller account matches roles defined in cluster data.

        Args:
            sts_account: AWS account ID from STS get-caller-identity
            sts_arn: ARN from STS get-caller-identity
            cluster_data: Cluster data from OCM
            cluster_id: Optional cluster ID for better error messages

        Returns:
            True if account matches or user chooses to continue, False otherwise
        """
        # Extract role ARNs from cluster data
        aws_data = cluster_data.get('aws', {})
        role_arns = []

        # Collect all role ARNs from cluster data
        if aws_data.get('sts', {}).get('support_role_arn'):
            role_arns.append(aws_data['sts']['support_role_arn'])
        if aws_data.get('sts', {}).get('role_arn'):
            role_arns.append(aws_data['sts']['role_arn'])
        if aws_data.get('sts', {}).get('instance_iam_roles', {}).get('master_role_arn'):
            role_arns.append(aws_data['sts']['instance_iam_roles']['master_role_arn'])
        if aws_data.get('sts', {}).get('instance_iam_roles', {}).get('worker_role_arn'):
            role_arns.append(aws_data['sts']['instance_iam_roles']['worker_role_arn'])
        if aws_data.get('sts', {}).get('operator_role_prefix'):
            # Operator roles contain the account in their ARN
            role_arns.append(f"arn:aws:iam::{sts_account}:role/{aws_data['sts']['operator_role_prefix']}")

        # Check if STS account matches any role ARN account
        account_found = False
        matching_role = None

        for role_arn in role_arns:
            # Extract account from role ARN (format: arn:aws:iam::ACCOUNT:role/ROLE_NAME)
            if f"::{sts_account}:" in role_arn:
                account_found = True
                matching_role = role_arn
                break

        if account_found:
            Colors.green(f"✓ AWS account matches cluster account: {sts_account}")
            if self.debug and matching_role:
                print(f"  Matched role: {matching_role}")
            return True

        # Account mismatch - warn user
        print()
        Colors.perr("⚠ WARNING: AWS Account Mismatch Detected")
        Colors.perr("")
        Colors.perr(f"  Current STS identity account: {sts_account}")
        Colors.perr(f"  Current STS ARN: {sts_arn}")
        Colors.perr("")

        if role_arns:
            Colors.perr("  Expected cluster role ARNs:")
            for role_arn in role_arns:
                # Extract account from role ARN
                if '::' in role_arn and ':role/' in role_arn:
                    role_account = role_arn.split('::')[1].split(':')[0]
                    Colors.perr(f"    - {role_arn} (account: {role_account})")
                else:
                    Colors.perr(f"    - {role_arn}")
        else:
            Colors.perr("  No role ARNs found in cluster data")

        Colors.perr("")
        Colors.perr(f"  The current AWS credentials may not be for cluster: {cluster_id or 'Unknown'}")
        Colors.perr("")

        # Prompt user to continue or abort
        try:
            response = input("  Do you want to continue anyway? [y/N]: ").strip().lower()
            if response in ['y', 'yes']:
                print()
                Colors.blue("  Continuing with mismatched credentials...")
                print()
                return True
            else:
                print()
                Colors.perr("  Aborting. Please set credentials for the correct cluster:")
                self._print_credential_refresh_instructions()
                return False
        except (KeyboardInterrupt, EOFError):
            print()
            Colors.perr("\n  Aborted by user")
            return False

    def _debug_credentials(self) -> str:
        """Debug credential configuration for troubleshooting"""
        debug_info = ["Credential Debug Information:"]

        # Check environment variables
        if os.environ.get('AWS_ACCESS_KEY_ID'):
            key_id = os.environ.get('AWS_ACCESS_KEY_ID')
            debug_info.append(f"  AWS_ACCESS_KEY_ID: {key_id[:8]}...{key_id[-4:] if len(key_id) > 12 else ''}")
        else:
            debug_info.append("  AWS_ACCESS_KEY_ID: Not set")

        if os.environ.get('AWS_SECRET_ACCESS_KEY'):
            debug_info.append("  AWS_SECRET_ACCESS_KEY: Set (hidden)")
        else:
            debug_info.append("  AWS_SECRET_ACCESS_KEY: Not set")

        if os.environ.get('AWS_SESSION_TOKEN'):
            token = os.environ.get('AWS_SESSION_TOKEN')
            debug_info.append(f"  AWS_SESSION_TOKEN: {token[:8]}...{token[-4:] if len(token) > 12 else ''}")
        else:
            debug_info.append("  AWS_SESSION_TOKEN: Not set")

        debug_info.append(f"  AWS_REGION: {os.environ.get('AWS_REGION', 'Not set (using default)')}")
        debug_info.append(f"  AWS_DEFAULT_REGION: {os.environ.get('AWS_DEFAULT_REGION', 'Not set')}")

        if os.environ.get('AWS_PROFILE'):
            debug_info.append(f"  AWS_PROFILE: {os.environ.get('AWS_PROFILE')}")

        # Check proxy settings
        https_proxy = os.environ.get('HTTPS_PROXY') or os.environ.get('https_proxy')
        http_proxy = os.environ.get('HTTP_PROXY') or os.environ.get('http_proxy')
        no_proxy = os.environ.get('NO_PROXY') or os.environ.get('no_proxy')
        ca_bundle = os.environ.get('AWS_CA_BUNDLE')

        debug_info.append("")
        debug_info.append("Proxy Configuration:")
        if https_proxy:
            debug_info.append(f"  HTTPS_PROXY: {https_proxy}")
        else:
            debug_info.append("  HTTPS_PROXY: Not set")

        if http_proxy:
            debug_info.append(f"  HTTP_PROXY: {http_proxy}")
        else:
            debug_info.append("  HTTP_PROXY: Not set")

        if no_proxy:
            debug_info.append(f"  NO_PROXY: {no_proxy}")

        if ca_bundle:
            debug_info.append(f"  AWS_CA_BUNDLE: {ca_bundle}")

        return '\n'.join(debug_info)

    def _handle_aws_error(self, e: Exception, operation: str):
        """Handle AWS errors and display caller identity for UnauthorizedOperation"""
        error_code = None
        if hasattr(e, 'response') and isinstance(e.response, dict):
            error_code = e.response.get('Error', {}).get('Code', None)

        if error_code == 'UnauthorizedOperation':
            if not self._shown_detailed_auth_error:
                # Show detailed error first time only
                Colors.perr(f"✗ UnauthorizedOperation: {operation}")
                Colors.perr(f"  Error: {str(e)}")
                Colors.perr("")
                Colors.perr(self._get_caller_identity_details())
                Colors.perr("")
                Colors.perr(self._debug_credentials())
                Colors.perr("")
                Colors.perr("This IAM principal lacks the required permissions.")
                Colors.perr("")
                Colors.perr("TROUBLESHOOTING:")
                Colors.perr("  1. Verify AWS CLI works with same credentials:")
                Colors.perr("     aws sts get-caller-identity")
                Colors.perr("  2. Check proxy configuration (if behind corporate proxy):")
                Colors.perr("     cat ~/.aws/config  # Look for proxy and ca_bundle settings")
                Colors.perr("     echo $HTTPS_PROXY $HTTP_PROXY $AWS_CA_BUNDLE")
                Colors.perr("  3. If CLI works but boto3 fails, try:")
                Colors.perr("     unset AWS_PROFILE  # boto3 may prefer profile over env vars")
                Colors.perr("  4. Refresh credentials:")
                self._print_credential_refresh_instructions()

                self._shown_detailed_auth_error = True
            else:
                # Brief error for subsequent occurrences
                Colors.perr(f"✗ UnauthorizedOperation: {operation} (see earlier error for details)")
        elif error_code and 'unauthorized' in error_code.lower():
            if not self._shown_detailed_auth_error:
                Colors.perr(f"✗ Authorization error during {operation}")
                Colors.perr(f"  Error: {str(e)}")
                Colors.perr("")
                Colors.perr(self._get_caller_identity_details())
                Colors.perr("")
                Colors.perr(self._debug_credentials())

                self._shown_detailed_auth_error = True
            else:
                Colors.perr(f"✗ Authorization error during {operation} (see earlier error for details)")

        raise

    def _retry_request(self, func, service: str, operation: str, params: Dict, description: str):
        """Execute AWS request with retry logic"""
        for attempt in range(1, self.max_retries + 1):
            try:
                result = func(**params)
                return result
            except (self.ClientError, self.BotoCoreError) as e:
                error_code = None
                if hasattr(e, 'response') and isinstance(e.response, dict):
                    error_code = e.response.get('Error', {}).get('Code', None)

                # Handle UnauthorizedOperation errors - don't retry, show identity
                if error_code == 'UnauthorizedOperation' or (error_code and 'unauthorized' in error_code.lower()):
                    self._handle_aws_error(e, description)

                # Handle other errors with retry logic
                if attempt < self.max_retries:
                    Colors.perr(f"Attempt {attempt}/{self.max_retries} failed to {description}: {str(e)}, retrying in {self.retry_delay}s...")
                    time.sleep(self.retry_delay)
                else:
                    Colors.perr(f"Failed to {description} after {self.max_retries} attempts: {str(e)}")
                    raise

    def get_metric_statistics(self, instance_id: str, metric_name: str, namespace: str,
                            start_time: datetime, end_time: datetime, period: int,
                            statistic: str, description: str) -> Dict:
        """Fetch CloudWatch metrics with retry logic"""
        params = {
            'Namespace': namespace,
            'MetricName': metric_name,
            'Dimensions': [{'Name': 'InstanceId', 'Value': instance_id}],
            'StartTime': start_time,
            'EndTime': end_time,
            'Period': period,
            'Statistics': [statistic]
        }

        # Print AWS CLI equivalent
        print(format_aws_cli_command('cloudwatch', 'get-metric-statistics', params))

        return self._retry_request(
            self.cloudwatch.get_metric_statistics,
            'cloudwatch',
            'get-metric-statistics',
            params,
            f"fetch {description} for {instance_id}"
        )

    def describe_vpcs(self, filters: List[Dict] = None, vpc_ids: List[str] = None) -> Dict:
        """Describe VPCs"""
        params = {}
        if filters:
            params['Filters'] = filters
        if vpc_ids:
            params['VpcIds'] = vpc_ids

        print(format_aws_cli_command('ec2', 'describe-vpcs', params))
        try:
            return self.ec2.describe_vpcs(**params)
        except (self.ClientError, self.BotoCoreError) as e:
            self._handle_aws_error(e, 'describe VPCs')

    def describe_vpc_attribute(self, vpc_id: str, attribute: str) -> Dict:
        """Describe VPC attribute"""
        params = {'VpcId': vpc_id, 'Attribute': attribute}
        print(format_aws_cli_command('ec2', 'describe-vpc-attribute', params))
        try:
            return self.ec2.describe_vpc_attribute(**params)
        except (self.ClientError, self.BotoCoreError) as e:
            self._handle_aws_error(e, 'describe VPC attribute')

    def describe_dhcp_options(self, dhcp_options_ids: List[str]) -> Dict:
        """Describe DHCP options"""
        params = {'DhcpOptionsIds': dhcp_options_ids}
        print(format_aws_cli_command('ec2', 'describe-dhcp-options', params))
        try:
            return self.ec2.describe_dhcp_options(**params)
        except (self.ClientError, self.BotoCoreError) as e:
            self._handle_aws_error(e, 'describe DHCP options')

    def describe_instances(self, filters: List[Dict] = None) -> Dict:
        """Describe EC2 instances"""
        params = {}
        if filters:
            params['Filters'] = filters

        print(format_aws_cli_command('ec2', 'describe-instances', params))
        try:
            return self.ec2.describe_instances(**params)
        except (self.ClientError, self.BotoCoreError) as e:
            self._handle_aws_error(e, 'describe EC2 instances')

    def get_console_output(self, instance_id: str) -> Dict:
        """Get EC2 console output"""
        params = {'InstanceId': instance_id}
        print(f"aws ec2 get-console-output --instance-id {instance_id} --output text --query 'Output'")
        try:
            return self.ec2.get_console_output(**params)
        except (self.ClientError, self.BotoCoreError) as e:
            self._handle_aws_error(e, f'get console output for {instance_id}')

    def describe_security_groups(self, filters: List[Dict] = None) -> Dict:
        """Describe security groups"""
        params = {}
        if filters:
            params['Filters'] = filters

        print(format_aws_cli_command('ec2', 'describe-security-groups', params))
        try:
            return self.ec2.describe_security_groups(**params)
        except (self.ClientError, self.BotoCoreError) as e:
            self._handle_aws_error(e, 'describe security groups')

    def describe_load_balancers(self, load_balancer_arns: List[str] = None) -> Dict:
        """Describe load balancers"""
        params = {}
        if load_balancer_arns:
            params['LoadBalancerArns'] = load_balancer_arns

        print(format_aws_cli_command('elbv2', 'describe-load-balancers', params))
        try:
            return self.elbv2.describe_load_balancers(**params)
        except (self.ClientError, self.BotoCoreError) as e:
            self._handle_aws_error(e, 'describe load balancers')

    def describe_tags(self, resource_arns: List[str]) -> Dict:
        """Describe ELB tags"""
        params = {'ResourceArns': resource_arns}
        print(format_aws_cli_command('elbv2', 'describe-tags', params))
        try:
            return self.elbv2.describe_tags(**params)
        except (self.ClientError, self.BotoCoreError) as e:
            self._handle_aws_error(e, 'describe load balancer tags')

    def list_hosted_zones(self) -> Dict:
        """List Route53 hosted zones"""
        print("aws route53 list-hosted-zones --output json")
        try:
            return self.route53.list_hosted_zones()
        except (self.ClientError, self.BotoCoreError) as e:
            self._handle_aws_error(e, 'list hosted zones')

    def list_resource_record_sets(self, hosted_zone_id: str) -> Dict:
        """List Route53 resource record sets"""
        params = {'HostedZoneId': hosted_zone_id}
        print(format_aws_cli_command('route53', 'list-resource-record-sets', params))
        try:
            return self.route53.list_resource_record_sets(**params)
        except (self.ClientError, self.BotoCoreError) as e:
            self._handle_aws_error(e, f'list resource record sets for {hosted_zone_id}')

    def lookup_events(self, start_time: datetime, end_time: datetime) -> List[Dict]:
        """Lookup CloudTrail events"""
        params = {
            'LookupAttributes': [{'AttributeKey': 'ReadOnly', 'AttributeValue': 'false'}],
            'StartTime': start_time,
            'EndTime': end_time
        }

        print(format_aws_cli_command('cloudtrail', 'lookup-events', params))

        try:
            events = []
            paginator = self.cloudtrail.get_paginator('lookup_events')
            for page in paginator.paginate(**params):
                events.extend(page.get('Events', []))
            return events
        except (self.ClientError, self.BotoCoreError) as e:
            self._handle_aws_error(e, 'lookup CloudTrail events')

    def describe_vpc_endpoint_service_configurations(self, filters: List[Dict]) -> Dict:
        """Describe VPC endpoint service configurations"""
        params = {'Filters': filters}
        print(format_aws_cli_command('ec2', 'describe-vpc-endpoint-service-configurations', params))
        try:
            return self.ec2.describe_vpc_endpoint_service_configurations(**params)
        except (self.ClientError, self.BotoCoreError) as e:
            self._handle_aws_error(e, 'describe VPC endpoint service configurations')

    def describe_vpc_endpoint_connections(self, filters: List[Dict]) -> Dict:
        """Describe VPC endpoint connections"""
        params = {'Filters': filters}
        print(format_aws_cli_command('ec2', 'describe-vpc-endpoint-connections', params))
        try:
            return self.ec2.describe_vpc_endpoint_connections(**params)
        except (self.ClientError, self.BotoCoreError) as e:
            self._handle_aws_error(e, 'describe VPC endpoint connections')

    def describe_subnets(self, filters: List[Dict] = None, subnet_ids: List[str] = None) -> Dict:
        """Describe subnets"""
        params = {}
        if filters:
            params['Filters'] = filters
        if subnet_ids:
            params['SubnetIds'] = subnet_ids

        print(format_aws_cli_command('ec2', 'describe-subnets', params))
        try:
            return self.ec2.describe_subnets(**params)
        except (self.ClientError, self.BotoCoreError) as e:
            self._handle_aws_error(e, 'describe subnets')

    def describe_route_tables(self, filters: List[Dict] = None) -> Dict:
        """Describe route tables"""
        params = {}
        if filters:
            params['Filters'] = filters

        print(format_aws_cli_command('ec2', 'describe-route-tables', params))
        try:
            return self.ec2.describe_route_tables(**params)
        except (self.ClientError, self.BotoCoreError) as e:
            self._handle_aws_error(e, 'describe route tables')

    def describe_internet_gateways(self, filters: List[Dict] = None) -> Dict:
        """Describe internet gateways"""
        params = {}
        if filters:
            params['Filters'] = filters

        print(format_aws_cli_command('ec2', 'describe-internet-gateways', params))
        try:
            return self.ec2.describe_internet_gateways(**params)
        except (self.ClientError, self.BotoCoreError) as e:
            self._handle_aws_error(e, 'describe internet gateways')

    def describe_nat_gateways(self, filters: List[Dict] = None) -> Dict:
        """Describe NAT gateways"""
        params = {}
        if filters:
            params['Filters'] = filters

        print(format_aws_cli_command('ec2', 'describe-nat-gateways', params))
        try:
            return self.ec2.describe_nat_gateways(**params)
        except (self.ClientError, self.BotoCoreError) as e:
            self._handle_aws_error(e, 'describe NAT gateways')

    def describe_target_groups(self, load_balancer_arn: str = None) -> Dict:
        """Describe target groups"""
        params = {}
        if load_balancer_arn:
            params['LoadBalancerArn'] = load_balancer_arn

        print(format_aws_cli_command('elbv2', 'describe-target-groups', params))
        try:
            return self.elbv2.describe_target_groups(**params)
        except (self.ClientError, self.BotoCoreError) as e:
            self._handle_aws_error(e, 'describe target groups')

    def describe_target_health(self, target_group_arn: str) -> Dict:
        """Describe target health"""
        params = {'TargetGroupArn': target_group_arn}
        print(format_aws_cli_command('elbv2', 'describe-target-health', params))
        try:
            return self.elbv2.describe_target_health(**params)
        except (self.ClientError, self.BotoCoreError) as e:
            self._handle_aws_error(e, 'describe target health')

    def describe_classic_load_balancers(self, load_balancer_names: List[str] = None) -> Dict:
        """Describe classic load balancers"""
        params = {}
        if load_balancer_names:
            params['LoadBalancerNames'] = load_balancer_names

        print(format_aws_cli_command('elb', 'describe-load-balancers', params))
        try:
            return self.elb.describe_load_balancers(**params)
        except (self.ClientError, self.BotoCoreError) as e:
            self._handle_aws_error(e, 'describe classic load balancers')

    def describe_network_interfaces(self, filters: List[Dict] = None) -> Dict:
        """Describe network interfaces"""
        params = {}
        if filters:
            params['Filters'] = filters

        print(format_aws_cli_command('ec2', 'describe-network-interfaces', params))
        try:
            return self.ec2.describe_network_interfaces(**params)
        except (self.ClientError, self.BotoCoreError) as e:
            self._handle_aws_error(e, 'describe network interfaces')

    def describe_volumes(self, filters: List[Dict] = None) -> Dict:
        """Describe EBS volumes"""
        params = {}
        if filters:
            params['Filters'] = filters

        print(format_aws_cli_command('ec2', 'describe-volumes', params))
        try:
            return self.ec2.describe_volumes(**params)
        except (self.ClientError, self.BotoCoreError) as e:
            self._handle_aws_error(e, 'describe EBS volumes')

    def describe_network_acls(self, filters: List[Dict] = None) -> Dict:
        """Describe network ACLs"""
        params = {}
        if filters:
            params['Filters'] = filters

        print(format_aws_cli_command('ec2', 'describe-network-acls', params))
        try:
            return self.ec2.describe_network_acls(**params)
        except (self.ClientError, self.BotoCoreError) as e:
            self._handle_aws_error(e, 'describe network ACLs')

    def describe_addresses(self, filters: List[Dict] = None) -> Dict:
        """Describe elastic IPs"""
        params = {}
        if filters:
            params['Filters'] = filters

        print(format_aws_cli_command('ec2', 'describe-addresses', params))
        try:
            return self.ec2.describe_addresses(**params)
        except (self.ClientError, self.BotoCoreError) as e:
            self._handle_aws_error(e, 'describe elastic IPs')

    def describe_vpc_peering_connections(self, filters: List[Dict] = None) -> Dict:
        """Describe VPC peering connections"""
        params = {}
        if filters:
            params['Filters'] = filters

        print(format_aws_cli_command('ec2', 'describe-vpc-peering-connections', params))
        try:
            return self.ec2.describe_vpc_peering_connections(**params)
        except (self.ClientError, self.BotoCoreError) as e:
            self._handle_aws_error(e, 'describe VPC peering connections')

    def describe_flow_logs(self, filters: List[Dict] = None) -> Dict:
        """Describe VPC flow logs"""
        params = {}
        if filters:
            params['Filters'] = filters

        print(format_aws_cli_command('ec2', 'describe-flow-logs', params))
        try:
            return self.ec2.describe_flow_logs(**params)
        except (self.ClientError, self.BotoCoreError) as e:
            self._handle_aws_error(e, 'describe VPC flow logs')


class ClusterDataCollector:
    """Main collector class for ROSA cluster artifacts"""

    def __init__(self, cluster_id: str, work_dir: str = ".", start_date: str = None,
                 elapsed_time: str = None, period: int = 300, force_update: bool = False,
                 debug: bool = False):
        self.cluster_id = cluster_id
        self.work_dir = Path(work_dir)
        self.work_dir.mkdir(exist_ok=True)

        self.start_date = start_date
        self.elapsed_time = elapsed_time
        self.period = period
        self.force_update = force_update
        self.debug = debug

        self.file_prefix = self.work_dir / cluster_id
        self.last_run_file = self.work_dir / "last_run.json"

        # Initialize AWS collector
        self.aws = AWSCollector(debug=debug)

        # Runtime variables
        self.capture_start = None
        self.capture_end = None
        self.cluster_data = None
        self.infra_id = None
        self.domain_prefix = None
        self.private_link = False
        self.cluster_state = None

    def run(self):
        """Main execution flow"""
        # Initial credential validation (basic check)
        if not self.aws.validate_credentials():
            Colors.perr("\nAWS credential validation failed. Cannot proceed with data collection.")
            Colors.perr(f"\nRefresh AWS env vars: AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_SESSION_TOKEN.")
            sys.exit(1)

        # Get OCM cluster info
        self._get_ocm_cluster_info()

        # Validate credentials against cluster account
        if not self.aws.validate_credentials(cluster_data=self.cluster_data, cluster_id=self.cluster_id,
                                            show_header=False):
            Colors.perr("\nAWS credential account validation failed.")
            sys.exit(1)

        # Determine time ranges
        self._determine_time_ranges()

        # Get AWS resources
        self._get_vpc_info()
        self._get_network_infrastructure()
        self._get_vpc_endpoint_service_info()
        self._get_ec2_instance_info()
        self._get_cloud_trail_logs()
        self._get_route53_info()
        self._get_security_groups_info()
        self._get_load_balancers_info()

        # Save runtime configuration
        self._write_runtime_config()

    def _get_ocm_cluster_info(self):
        """Fetch cluster information from OCM"""
        Colors.hdr("Get OCM Cluster INFO")

        cluster_json = f"{self.file_prefix}_cluster.json"

        if Path(cluster_json).exists():
            Colors.blue(f"Using existing {cluster_json} file for ocm cluster info")
            with open(cluster_json) as f:
                self.cluster_data = json.load(f)
        else:
            Colors.blue("Fetching ocm cluster info...")
            print(f"ocm get /api/clusters_mgmt/v1/clusters/{self.cluster_id} > {cluster_json}")

            result = subprocess.run(
                ['ocm', 'get', f'/api/clusters_mgmt/v1/clusters/{self.cluster_id}'],
                capture_output=True,
                text=True
            )

            if result.returncode != 0:
                Colors.perr("Failed to get cluster from ocm?")
                Colors.perr(f"ocm get /api/clusters_mgmt/v1/clusters/{self.cluster_id}")
                sys.exit(1)

            self.cluster_data = json.loads(result.stdout)
            with open(cluster_json, 'w') as f:
                json.dump(self.cluster_data, f, indent=2)

        # Extract cluster metadata
        self.infra_id = self.cluster_data.get('infra_id')
        self.domain_prefix = self.cluster_data.get('domain_prefix')
        self.cluster_state = self.cluster_data.get('state')
        self.private_link = self.cluster_data.get('aws', {}).get('private_link', False)

        print(f"Using DOMAIN_PREFIX:{self.domain_prefix}, INFRA_ID:{self.infra_id}")

        # Get cluster context
        cluster_ctx_file = f"{self.file_prefix}_cluster_context.json"
        if Path(cluster_ctx_file).exists():
            Colors.green(f"Using existing cluster context file: {cluster_ctx_file}")
        else:
            Colors.blue("Fetching cluster context...")
            print(f"osdctl cluster context -C {self.cluster_id} -o json")

            result = subprocess.run(
                ['osdctl', 'cluster', 'context', '-C', self.cluster_id, '-o', 'json'],
                capture_output=True,
                text=True
            )

            if result.returncode != 0:
                Colors.perr(f"WARNING - failed to fetch cluster context for cluster:'{self.cluster_id}'")
            else:
                with open(cluster_ctx_file, 'w') as f:
                    f.write(result.stdout)

        # Get cluster resources
        cluster_resources = f"{self.file_prefix}_resources.json"
        if Path(cluster_resources).exists():
            Colors.green(f"Using existing ocm resources file: {cluster_resources}")
        else:
            Colors.blue("Fetching ocm cluster resources for install logs...")
            print(f"ocm get /api/clusters_mgmt/v1/clusters/{self.cluster_id}/resources")

            result = subprocess.run(
                ['ocm', 'get', f'/api/clusters_mgmt/v1/clusters/{self.cluster_id}/resources'],
                capture_output=True,
                text=True
            )

            if result.returncode != 0:
                Colors.perr("Failed to get cluster resources?")
                sys.exit(1)

            resources_data = json.loads(result.stdout)

            if resources_data.get('resources') is None:
                print(f"Cluster state:{self.cluster_state}")
                if self.cluster_state == 'ready':
                    Colors.blue("Cluster OCM resources (install logs) are not expected for clusters in ready state")
                else:
                    Colors.perr("Cluster resources not found for this cluster")
                    Colors.perr(f"Cluster is in {self.cluster_state} state, new clusters in non-ready state may need to wait for this to be populated")
            else:
                with open(cluster_resources, 'w') as f:
                    json.dump(resources_data, f, indent=2)

    def _determine_time_ranges(self):
        """Determine capture start and end times"""
        use_last_run = False

        # Check if we should use last_run.json
        if not self.force_update and self.last_run_file.exists() and not self.start_date and not self.elapsed_time:
            Colors.blue(f"Found previous run configuration: {self.last_run_file}")
            Colors.blue("No time arguments provided (-s/-e) and --force-update not set, using previous run's time range")

            with open(self.last_run_file) as f:
                last_run = json.load(f)

            self.capture_start = last_run.get('capture_start')
            self.capture_end = last_run.get('capture_end')

            if self.capture_start and self.capture_end and self.capture_start != 'null' and self.capture_end != 'null':
                Colors.blue(f"Using CAPTURE_START: {self.capture_start}")
                Colors.blue(f"Using CAPTURE_END: {self.capture_end}")
                use_last_run = True
            else:
                Colors.perr(f"Warning: Invalid data in {self.last_run_file}, will calculate new time range")
        elif self.force_update:
            Colors.blue("--force-update flag set, recalculating time range (ignoring last_run.json)")

        if not use_last_run:
            # Determine elapsed time
            if self.elapsed_time:
                num, unit = parse_elapsed_time(self.elapsed_time)
                if unit == 'hours':
                    capture_window = timedelta(hours=num)
                elif unit == 'minutes':
                    capture_window = timedelta(minutes=num)
                else:  # days
                    capture_window = timedelta(days=num)
                Colors.blue(f"Using provided elapsed time: {self.elapsed_time}")
            else:
                capture_window = timedelta(hours=2)
                Colors.blue("Using default capture window: 2 hours")

            # Determine start date
            if self.start_date:
                self.capture_start = self.start_date
                start_dt = datetime.strptime(self.capture_start, '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc)
                end_dt = start_dt + capture_window
                self.capture_end = end_dt.strftime('%Y-%m-%dT%H:%M:%SZ')
                Colors.blue(f"Using provided start date: {self.capture_start}")
            else:
                if self.cluster_state == 'ready':
                    # For ready clusters, use current time as end
                    end_dt = datetime.now(timezone.utc)
                    start_dt = end_dt - capture_window
                    self.capture_start = start_dt.strftime('%Y-%m-%dT%H:%M:%SZ')
                    self.capture_end = end_dt.strftime('%Y-%m-%dT%H:%M:%SZ')
                    Colors.blue("Cluster is in ready state - using current time window")
                    Colors.blue(f"Start: {self.capture_start} ({capture_window} ago)")
                    Colors.blue(f"End: {self.capture_end} (now)")
                else:
                    # For non-ready clusters, use cluster creation time
                    print("\nFetching cluster create time to use for cloudtrail logs, and metrics...")
                    create_time = self.cluster_data.get('creation_timestamp')
                    self.capture_start = create_time
                    start_dt = datetime.strptime(create_time, '%Y-%m-%dT%H:%M:%S.%fZ').replace(tzinfo=timezone.utc)
                    end_dt = start_dt + capture_window
                    self.capture_end = end_dt.strftime('%Y-%m-%dT%H:%M:%SZ')
                    Colors.blue(f"Cluster is in {self.cluster_state} state - using cluster creation time as start date: {self.capture_start}")

            Colors.blue(f"Using capture start time: {self.capture_start}, end time: {self.capture_end}")

    def _fetch_cloudwatch_metric(self, instance_id: str, metric_name: str, aws_metric_name: str,
                                namespace: str, statistic: str, description: str) -> Optional[str]:
        """Fetch CloudWatch metric with intelligent file caching"""
        file_prefix = f"{self.file_prefix}_{instance_id}_{metric_name}_"

        # Look for existing files
        existing_files = list(self.work_dir.glob(f"{self.cluster_id}_{instance_id}_{metric_name}_*.json"))
        existing_file = existing_files[0] if existing_files else None

        fetch_start = self.capture_start
        fetch_end = self.capture_end
        final_output_file = f"{file_prefix}{self.capture_start}_{self.capture_end}.json"

        if existing_file:
            # Extract timestamps from filename
            filename = existing_file.name
            match = re.search(r'_(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)_(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)\.json$', filename)

            if match:
                file_start = match.group(1)
                file_end = match.group(2)

                # Check if requested range is within existing range
                if self.capture_start >= file_start and self.capture_end <= file_end:
                    print(f"Using existing {description} metrics file (covers requested time range): {existing_file}")
                    return str(existing_file)

                # Determine merged time range
                new_start = min(self.capture_start, file_start)
                new_end = max(self.capture_end, file_end)
                final_output_file = f"{file_prefix}{new_start}_{new_end}.json"

                if self.capture_start < file_start or self.capture_end > file_end:
                    print(f"Fetching additional {description} metrics to expand time range...")
                    print(f"  Existing: {file_start} to {file_end}")
                    print(f"  Requested: {self.capture_start} to {self.capture_end}")
                    print(f"  New range: {new_start} to {new_end}")
                    fetch_start = new_start
                    fetch_end = new_end

        # Fetch metrics from AWS
        start_dt = datetime.strptime(fetch_start, '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc)
        end_dt = datetime.strptime(fetch_end, '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc)

        try:
            metrics_output = self.aws.get_metric_statistics(
                instance_id=instance_id,
                metric_name=aws_metric_name,
                namespace=namespace,
                start_time=start_dt,
                end_time=end_dt,
                period=self.period,
                statistic=statistic,
                description=description
            )
        except Exception as e:
            Colors.perr(f"Failed to fetch {description} for {instance_id}: {str(e)}")
            return None

        # Merge with existing data if needed
        if existing_file and existing_file != Path(final_output_file):
            print("Merging new data with existing data...")
            with open(existing_file) as f:
                old_data = json.load(f)

            # Merge and deduplicate datapoints
            old_datapoints = old_data.get('Datapoints', [])
            new_datapoints = metrics_output.get('Datapoints', [])

            all_datapoints = old_datapoints + new_datapoints
            # Deduplicate by Timestamp
            seen = set()
            unique_datapoints = []
            for dp in all_datapoints:
                ts = dp['Timestamp'].isoformat() if isinstance(dp['Timestamp'], datetime) else dp['Timestamp']
                if ts not in seen:
                    seen.add(ts)
                    unique_datapoints.append(dp)

            # Sort by timestamp
            unique_datapoints.sort(key=lambda x: x['Timestamp'] if isinstance(x['Timestamp'], str) else x['Timestamp'].isoformat())

            metrics_output['Datapoints'] = unique_datapoints

            # Remove old file if different
            if existing_file != Path(final_output_file):
                existing_file.unlink()
                print(f"Removed old file: {existing_file}")

        # Write final output
        with open(final_output_file, 'w') as f:
            # Convert datetime objects to strings for JSON serialization
            datapoints = metrics_output.get('Datapoints', [])
            for dp in datapoints:
                if isinstance(dp.get('Timestamp'), datetime):
                    dp['Timestamp'] = dp['Timestamp'].isoformat()
            json.dump(metrics_output, f, indent=2, default=str)

        print(f"Saved metrics to: {final_output_file}")
        return final_output_file

    def _get_vpc_info(self):
        """Fetch VPC information from AWS"""
        Colors.hdr("Getting VPC info using infra id tags")

        print("Attempting to fetch AWS VPCs by tag values...")
        vpc_ids_file = f"{self.file_prefix}_VPC_IDS.json"

        if Path(vpc_ids_file).exists():
            Colors.green(f"Using existing vpc ids file: {vpc_ids_file}")
            with open(vpc_ids_file) as f:
                vpc_ids = json.load(f)
        else:
            print("Fetching VPC ids from AWS...")
            try:
                response = self.aws.describe_vpcs(
                    filters=[{'Name': 'tag:Name', 'Values': [f'*{self.infra_id}*']}]
                )
                vpc_ids = [vpc['VpcId'] for vpc in response.get('Vpcs', [])]

                with open(vpc_ids_file, 'w') as f:
                    json.dump(vpc_ids, f)
            except Exception as e:
                Colors.perr(f"Error fetching vpc ids from AWS: {str(e)}")
                vpc_ids = []

        if not vpc_ids:
            Colors.perr("Warning no VPC IDS found?")
        else:
            Colors.blue(f"Found the following VPCs filtering for tags matching infra_id:'{self.infra_id}':")
            Colors.blue(' '.join(vpc_ids))
            self._populate_vpc_info_files(vpc_ids)

    def _populate_vpc_info_files(self, vpc_ids: List[str]):
        """Populate VPC information files"""
        Colors.green(f"Found the following VPC ids in cluster resources install logs:\n{' '.join(vpc_ids)}")

        for vpc_id in vpc_ids:
            vpc_file = f"{self.file_prefix}_{vpc_id}_VPC.json"
            vpc_file_dns_host = f"{self.file_prefix}_{vpc_id}_VPC_attrDnsHost.json"
            vpc_file_dns_supp = f"{self.file_prefix}_{vpc_id}_VPC_attrDnsSupp.json"

            # Get VPC info
            if Path(vpc_file).exists():
                Colors.green(f"Using existing VPC file {vpc_file}")
            else:
                Colors.blue(f"Fetching AWS info for {vpc_id}...")
                try:
                    response = self.aws.describe_vpcs(vpc_ids=[vpc_id])
                    with open(vpc_file, 'w') as f:
                        json.dump(response, f, indent=2, default=str)
                except Exception as e:
                    Colors.perr(f"Error fetch VPC:{vpc_id} from AWS, skipping VPC attribute requests...")
                    continue

            # Get VPC DNS hostname attribute
            if Path(vpc_file_dns_host).exists():
                Colors.green(f"Using existing VPC dns hostname attributes file {vpc_file_dns_host}")
            else:
                Colors.blue("Fetching VPC attr enableDnsHostNames from AWS")
                try:
                    response = self.aws.describe_vpc_attribute(vpc_id, 'enableDnsHostnames')
                    with open(vpc_file_dns_host, 'w') as f:
                        json.dump(response, f, indent=2, default=str)
                except Exception as e:
                    Colors.perr(f"Failed to fetch vpc attribute enableDnsHostnames from AWS: {str(e)}")

            # Get VPC DNS support attribute
            if Path(vpc_file_dns_supp).exists():
                Colors.green(f"Using existing VPC dns support attributes file {vpc_file_dns_supp}")
            else:
                Colors.blue("Fetching VPC attr enableDnsSupport from AWS")
                try:
                    response = self.aws.describe_vpc_attribute(vpc_id, 'enableDnsSupport')
                    with open(vpc_file_dns_supp, 'w') as f:
                        json.dump(response, f, indent=2, default=str)
                except Exception as e:
                    Colors.perr(f"Failed to fetch vpc attribute enableDnsSupport from AWS: {str(e)}")

            # Get DHCP options
            if Path(vpc_file).exists():
                with open(vpc_file) as f:
                    vpc_data = json.load(f)
                    dhcp_id = vpc_data.get('Vpcs', [{}])[0].get('DhcpOptionsId')

                    if dhcp_id:
                        dhcp_opt_file = f"{self.file_prefix}_{dhcp_id}_DHCP_OPT.json"

                        if Path(dhcp_opt_file).exists():
                            Colors.green(f"Found existing local dhcp options file: {dhcp_opt_file}")
                        else:
                            Colors.blue(f"Attempting to fetch aws dhcp options info for: {dhcp_id}...")
                            try:
                                response = self.aws.describe_dhcp_options([dhcp_id])
                                with open(dhcp_opt_file, 'w') as f:
                                    json.dump(response, f, indent=2, default=str)
                            except Exception as e:
                                Colors.perr(f"Failed to fetch dhcp option {dhcp_id} from AWS: {str(e)}")

    def _get_vpc_endpoint_service_info(self):
        """Fetch VPC endpoint service information for PrivateLink clusters"""
        Colors.hdr("Getting VPC endpoint service info")

        if not self.private_link:
            return

        Colors.hdr("Private Link detected getting VPC endpoint service info")

        vpc_epsrv_file = f"{self.file_prefix}_vpc_endpoint_service.json"
        vpc_ep_conn_file = f"{self.file_prefix}_vpc_endpoint_service_conns.json"

        if Path(vpc_epsrv_file).exists():
            Colors.green(f"Using existing vpc endpoint service file: {vpc_epsrv_file}")
        else:
            Colors.blue("Fetching vpc endpoint service info from AWS...")
            try:
                response = self.aws.describe_vpc_endpoint_service_configurations(
                    filters=[{'Name': 'tag:Name', 'Values': [f'{self.infra_id}-vpc-endpoint-service']}]
                )
                with open(vpc_epsrv_file, 'w') as f:
                    json.dump(response, f, indent=2, default=str)
            except Exception as e:
                Colors.perr(f"Failed to fetch vpc service configuration from AWS: {str(e)}")

        if Path(vpc_epsrv_file).exists():
            if Path(vpc_ep_conn_file).exists():
                Colors.green(f"Using existing vpc endpoint service connections file: {vpc_ep_conn_file}")
            else:
                Colors.blue("Fetching vpc endpoint service config id...")
                with open(vpc_epsrv_file) as f:
                    vpc_ep_data = json.load(f)
                    service_id = vpc_ep_data.get('ServiceConfigurations', [{}])[0].get('ServiceId')

                    if service_id:
                        Colors.blue(f"Fetching vpc endpoint connections for serviceId: '{service_id}'")
                        try:
                            response = self.aws.describe_vpc_endpoint_connections(
                                filters=[{'Name': 'service-id', 'Values': [service_id]}]
                            )
                            with open(vpc_ep_conn_file, 'w') as f:
                                json.dump(response, f, indent=2, default=str)
                        except Exception as e:
                            Colors.perr(f"Failed to fetch vpc endpoint connections for: {service_id}: {str(e)}")

    def _get_network_infrastructure(self):
        """Fetch network infrastructure: subnets, route tables, gateways"""
        Colors.hdr("Getting network infrastructure")

        # Subnets
        subnets_file = f"{self.file_prefix}_subnets.json"
        if Path(subnets_file).exists():
            Colors.green(f"Using existing subnets file: {subnets_file}")
        else:
            Colors.blue("Fetching subnets from AWS...")
            try:
                response = self.aws.describe_subnets(
                    filters=[{'Name': 'tag:Name', 'Values': [f'*{self.infra_id}*']}]
                )
                with open(subnets_file, 'w') as f:
                    json.dump(response, f, indent=2, default=str)
            except Exception as e:
                Colors.perr(f"Failed to fetch subnets: {str(e)}")

        # Route Tables
        route_tables_file = f"{self.file_prefix}_route_tables.json"
        if Path(route_tables_file).exists():
            Colors.green(f"Using existing route tables file: {route_tables_file}")
        else:
            Colors.blue("Fetching route tables from AWS...")
            try:
                response = self.aws.describe_route_tables(
                    filters=[{'Name': 'tag:Name', 'Values': [f'*{self.infra_id}*']}]
                )
                with open(route_tables_file, 'w') as f:
                    json.dump(response, f, indent=2, default=str)
            except Exception as e:
                Colors.perr(f"Failed to fetch route tables: {str(e)}")

        # Internet Gateways
        igw_file = f"{self.file_prefix}_internet_gateways.json"
        if Path(igw_file).exists():
            Colors.green(f"Using existing internet gateways file: {igw_file}")
        else:
            Colors.blue("Fetching internet gateways from AWS...")
            try:
                response = self.aws.describe_internet_gateways(
                    filters=[{'Name': 'tag:Name', 'Values': [f'*{self.infra_id}*']}]
                )
                with open(igw_file, 'w') as f:
                    json.dump(response, f, indent=2, default=str)
            except Exception as e:
                Colors.perr(f"Failed to fetch internet gateways: {str(e)}")

        # NAT Gateways
        nat_file = f"{self.file_prefix}_nat_gateways.json"
        if Path(nat_file).exists():
            Colors.green(f"Using existing NAT gateways file: {nat_file}")
        else:
            Colors.blue("Fetching NAT gateways from AWS...")
            try:
                response = self.aws.describe_nat_gateways(
                    filters=[{'Name': 'tag:Name', 'Values': [f'*{self.infra_id}*']}]
                )
                with open(nat_file, 'w') as f:
                    json.dump(response, f, indent=2, default=str)
            except Exception as e:
                Colors.perr(f"Failed to fetch NAT gateways: {str(e)}")

        # Network Interfaces
        eni_file = f"{self.file_prefix}_network_interfaces.json"
        if Path(eni_file).exists():
            Colors.green(f"Using existing network interfaces file: {eni_file}")
        else:
            Colors.blue("Fetching network interfaces from AWS...")
            try:
                response = self.aws.describe_network_interfaces(
                    filters=[{'Name': 'tag:Name', 'Values': [f'*{self.infra_id}*']}]
                )
                with open(eni_file, 'w') as f:
                    json.dump(response, f, indent=2, default=str)
            except Exception as e:
                Colors.perr(f"Failed to fetch network interfaces: {str(e)}")

        # Network ACLs
        nacl_file = f"{self.file_prefix}_network_acls.json"
        if Path(nacl_file).exists():
            Colors.green(f"Using existing network ACLs file: {nacl_file}")
        else:
            Colors.blue("Fetching network ACLs from AWS...")
            try:
                response = self.aws.describe_network_acls(
                    filters=[{'Name': 'tag:Name', 'Values': [f'*{self.infra_id}*']}]
                )
                with open(nacl_file, 'w') as f:
                    json.dump(response, f, indent=2, default=str)
            except Exception as e:
                Colors.perr(f"Failed to fetch network ACLs: {str(e)}")

        # Elastic IPs
        eip_file = f"{self.file_prefix}_elastic_ips.json"
        if Path(eip_file).exists():
            Colors.green(f"Using existing elastic IPs file: {eip_file}")
        else:
            Colors.blue("Fetching elastic IPs from AWS...")
            try:
                response = self.aws.describe_addresses(
                    filters=[{'Name': 'tag:Name', 'Values': [f'*{self.infra_id}*']}]
                )
                with open(eip_file, 'w') as f:
                    json.dump(response, f, indent=2, default=str)
            except Exception as e:
                Colors.perr(f"Failed to fetch elastic IPs: {str(e)}")

        # VPC Peering Connections
        peering_file = f"{self.file_prefix}_vpc_peering.json"
        if Path(peering_file).exists():
            Colors.green(f"Using existing VPC peering file: {peering_file}")
        else:
            Colors.blue("Fetching VPC peering connections from AWS...")
            try:
                response = self.aws.describe_vpc_peering_connections(
                    filters=[{'Name': 'tag:Name', 'Values': [f'*{self.infra_id}*']}]
                )
                with open(peering_file, 'w') as f:
                    json.dump(response, f, indent=2, default=str)
            except Exception as e:
                Colors.perr(f"Failed to fetch VPC peering connections: {str(e)}")

        # VPC Flow Logs
        flowlogs_file = f"{self.file_prefix}_vpc_flow_logs.json"
        if Path(flowlogs_file).exists():
            Colors.green(f"Using existing VPC flow logs file: {flowlogs_file}")
        else:
            Colors.blue("Fetching VPC flow logs from AWS...")
            try:
                response = self.aws.describe_flow_logs(
                    filters=[{'Name': 'tag:Name', 'Values': [f'*{self.infra_id}*']}]
                )
                with open(flowlogs_file, 'w') as f:
                    json.dump(response, f, indent=2, default=str)
            except Exception as e:
                Colors.perr(f"Failed to fetch VPC flow logs: {str(e)}")

        # EBS Volumes
        volumes_file = f"{self.file_prefix}_ebs_volumes.json"
        if Path(volumes_file).exists():
            Colors.green(f"Using existing EBS volumes file: {volumes_file}")
        else:
            Colors.blue("Fetching EBS volumes from AWS...")
            try:
                response = self.aws.describe_volumes(
                    filters=[{'Name': 'tag:Name', 'Values': [f'*{self.infra_id}*']}]
                )
                with open(volumes_file, 'w') as f:
                    json.dump(response, f, indent=2, default=str)
            except Exception as e:
                Colors.perr(f"Failed to fetch EBS volumes: {str(e)}")

    def _get_ec2_instance_info(self):
        """Fetch EC2 instance information, metrics, and console logs"""
        Colors.hdr("Getting EC2 instance information")

        cluster_ec2_instances = f"{self.file_prefix}_ec2_instances.json"

        if Path(cluster_ec2_instances).exists():
            Colors.green(f"using existing ec2 instances file: {cluster_ec2_instances}")
        else:
            Colors.blue("Fetching ec2 instances from AWS...")
            try:
                response = self.aws.describe_instances()

                # Flatten the response to extract instances
                instances = []
                for reservation in response.get('Reservations', []):
                    for instance in reservation.get('Instances', []):
                        instances.append({
                            'InstanceId': instance.get('InstanceId'),
                            'State': instance.get('State', {}).get('Name'),
                            'LaunchTime': instance.get('LaunchTime').isoformat() if instance.get('LaunchTime') else None,
                            'Tags': instance.get('Tags', [])
                        })

                with open(cluster_ec2_instances, 'w') as f:
                    json.dump(instances, f, indent=2)
            except Exception as e:
                Colors.perr(f"Failed to fetch EC2 Instances: {str(e)}")
                return

            printline()

        if Path(cluster_ec2_instances).exists():
            with open(cluster_ec2_instances) as f:
                instances = json.load(f)

            # Filter instances by infra_id tag
            cluster_instances = [
                inst for inst in instances
                if any(tag.get('Value', '').find(self.infra_id) != -1 for tag in inst.get('Tags', []))
            ]

            # Print instance table
            print("\nINSTANCE_ID\t\tAWS_STATE\tNAME")
            for inst in cluster_instances:
                inst_id = inst.get('InstanceId')
                state = inst.get('State')
                name = next((tag['Value'] for tag in inst.get('Tags', []) if tag.get('Key') == 'Name'), 'N/A')
                print(f"{inst_id}\t{state}\t{name}")

            Colors.hdr("Getting EC2 instance metrics, and console logs")

            # Fetch console logs and metrics for each instance
            for inst in cluster_instances:
                inst_id = inst.get('InstanceId')
                self._fetch_instance_console_logs(inst_id)
                self._fetch_instance_cpu_percent_metrics(inst_id)
                self._fetch_instance_mem_percent_metrics(inst_id)
                self._fetch_instance_ebs_iops_exceeded(inst_id)
                self._fetch_instance_ebs_throughput_exceeded(inst_id)
                self._fetch_instance_eni_bw_in_allowance_exceeded(inst_id)
                self._fetch_instance_eni_bw_out_allowance_exceeded(inst_id)
                self._fetch_instance_eni_pps_allowance_exceeded(inst_id)
        else:
            Colors.perr(f"No ec2 instances file found: '{cluster_ec2_instances}'")

    def _fetch_instance_console_logs(self, instance_id: str):
        """Fetch EC2 instance console logs"""
        console_file = f"{self.file_prefix}_{instance_id}_console.log"

        print(f"VM: {instance_id}")
        if Path(console_file).exists():
            Colors.green(f"Using existing vm {instance_id} console file: {console_file}")
            return

        Colors.blue(f"Getting console output for instance {instance_id}")
        try:
            response = self.aws.get_console_output(instance_id)
            console_output = response.get('Output', '')

            if console_output:
                with open(console_file, 'w') as f:
                    f.write(console_output)
            else:
                Colors.perr(f"No console output available for instance: {instance_id}")
        except Exception as e:
            Colors.perr(f"Failed to fetch ec2 console output for instance: {instance_id}: {str(e)}")

    def _fetch_instance_cpu_percent_metrics(self, instance_id: str):
        """Fetch CloudWatch CPU percent metrics"""
        self._fetch_cloudwatch_metric(
            instance_id, 'CPUUtilization', 'CPUUtilization',
            'AWS/EC2', 'Average', 'CPU percent'
        )

    def _fetch_instance_mem_percent_metrics(self, instance_id: str):
        """Fetch CloudWatch memory percent metrics"""
        self._fetch_cloudwatch_metric(
            instance_id, 'mem_used_percent', 'mem_used_percent',
            'CWAgent', 'Average', 'memory percent'
        )

    def _fetch_instance_ebs_iops_exceeded(self, instance_id: str):
        """Fetch CloudWatch EBS IOPS exceeded metrics"""
        self._fetch_cloudwatch_metric(
            instance_id, 'InstanceEBSIOPSExceededCheck', 'InstanceEBSIOPSExceededCheck',
            'AWS/EC2', 'Average', 'EBS IOPS exceeded'
        )

    def _fetch_instance_ebs_throughput_exceeded(self, instance_id: str):
        """Fetch CloudWatch EBS throughput exceeded metrics"""
        self._fetch_cloudwatch_metric(
            instance_id, 'InstanceEBSThroughputExceededCheck', 'InstanceEBSThroughputExceededCheck',
            'AWS/EC2', 'Average', 'EBS throughput exceeded'
        )

    def _fetch_instance_eni_bw_in_allowance_exceeded(self, instance_id: str):
        """Fetch CloudWatch ENI bandwidth in allowance exceeded metrics"""
        self._fetch_cloudwatch_metric(
            instance_id, 'bw_in_allowance_exceeded', 'bw_in_allowance_exceeded',
            'AWS/EC2', 'Sum', 'ENI bandwidth in allowance exceeded'
        )

    def _fetch_instance_eni_bw_out_allowance_exceeded(self, instance_id: str):
        """Fetch CloudWatch ENI bandwidth out allowance exceeded metrics"""
        self._fetch_cloudwatch_metric(
            instance_id, 'bw_out_allowance_exceeded', 'bw_out_allowance_exceeded',
            'AWS/EC2', 'Sum', 'ENI bandwidth out allowance exceeded'
        )

    def _fetch_instance_eni_pps_allowance_exceeded(self, instance_id: str):
        """Fetch CloudWatch ENI PPS allowance exceeded metrics"""
        self._fetch_cloudwatch_metric(
            instance_id, 'pps_allowance_exceeded', 'pps_allowance_exceeded',
            'AWS/EC2', 'Sum', 'ENI PPS allowance exceeded'
        )

    def _get_cloud_trail_logs(self):
        """Fetch CloudTrail logs for the cluster"""
        Colors.hdr("Getting Cloud trail logs")

        cluster_ct_logs = f"{self.file_prefix}_{self.capture_start}.{self.capture_end}.cloudtrail.json"

        if Path(cluster_ct_logs).exists():
            Colors.green(f"using existing cloudtrail logs: {cluster_ct_logs}")
        else:
            Colors.blue(f"Gathering cloudtrail logs from '{self.capture_start}' to '{self.capture_end}'...")

            try:
                start_dt = datetime.strptime(self.capture_start, '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc)
                end_dt = datetime.strptime(self.capture_end, '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc)

                events = self.aws.lookup_events(start_dt, end_dt)

                if events:
                    with open(cluster_ct_logs, 'w') as f:
                        json.dump(events, f, indent=2, default=str)
                else:
                    Colors.perr("No CloudTrail events found")
            except Exception as e:
                Colors.perr(f"Failed fetch cloudtrail info from AWS: {str(e)}")

        printline()

    def _get_route53_info(self):
        """Fetch Route53 hosted zone and DNS record information"""
        Colors.hdr("Getting route53 info...")

        base_domain = self.cluster_data.get('dns', {}).get('base_domain')
        base_domain = f"{self.domain_prefix}.{base_domain}"
        hosted_zones_file = f"{self.file_prefix}_hosted_zones.json"

        print(f"BASE_DOMAIN=\"{base_domain}\"")

        if Path(hosted_zones_file).exists():
            Colors.green(f"using existing file: {hosted_zones_file}")
        else:
            Colors.blue(f"fetching hosted zone for cluster domain {base_domain}...")
            try:
                response = self.aws.list_hosted_zones()

                # Filter zones that contain the base domain
                matching_zones = [
                    zone for zone in response.get('HostedZones', [])
                    if base_domain in zone.get('Name', '')
                ]

                with open(hosted_zones_file, 'w') as f:
                    json.dump(matching_zones, f, indent=2)
            except Exception as e:
                Colors.perr(f"Failed to fetch hosted zones for domain {base_domain}: {str(e)}")

        if Path(hosted_zones_file).exists():
            print(f"\nGetting hosted ZONE_ID from {hosted_zones_file}...")
            with open(hosted_zones_file) as f:
                zones = json.load(f)

            for zone in zones:
                zone_id = zone.get('Id', '').split('/')[-1]

                if zone_id:
                    record_sets = f"{self.file_prefix}_route53_{zone_id}.records.json"

                    if Path(record_sets).exists():
                        Colors.green(f"using existing file {record_sets}")
                    else:
                        Colors.blue(f"Fetching API records sets for hosted zone {zone_id} ...")
                        try:
                            response = self.aws.list_resource_record_sets(zone_id)
                            with open(record_sets, 'w') as f:
                                json.dump(response, f, indent=2, default=str)
                        except Exception as e:
                            Colors.perr(f"Failed to get API record sets: {str(e)}")
        else:
            Colors.perr(f"No zone found for cluster domain:'{base_domain}' ?")

    def _get_security_groups_info(self):
        """Fetch AWS security group information"""
        Colors.hdr("Getting Security Group info")

        sg_file = f"{self.file_prefix}_security_groups.json"

        if Path(sg_file).exists():
            Colors.green(f"Using existing security group file: {sg_file}")
        else:
            Colors.blue(f"Getting security groups with tags matching infra_id:{self.infra_id} ...")
            try:
                response = self.aws.describe_security_groups(
                    filters=[{'Name': 'tag-value', 'Values': [f'*{self.infra_id}*']}]
                )
                with open(sg_file, 'w') as f:
                    json.dump(response, f, indent=2, default=str)
            except Exception as e:
                Colors.perr(f"Error fetching security group info from AWS: {str(e)}")

        printline()

    def _get_load_balancers_info(self):
        """Fetch AWS load balancer information and tag associations"""
        Colors.hdr("Getting Load Balancers")

        lb_all_file = f"{self.file_prefix}_load_balancers_all.json"

        if Path(lb_all_file).exists():
            Colors.green(f"Using existing all load balancers json file {lb_all_file} ...")
        else:
            Colors.blue("Fetching all load balancers from AWS...")
            try:
                response = self.aws.describe_load_balancers()
                with open(lb_all_file, 'w') as f:
                    json.dump(response, f, indent=2, default=str)
            except Exception as e:
                Colors.perr(f"Failed to fetch load balancers from AWS: {str(e)}")

        if Path(lb_all_file).exists():
            print("""
AWS LBs dont provide tags in the describe LB response, so
a separate API call 'describe-tags' is need to create a tag <-> resource association.
Iterating over LBs found in {lb_all_file} to get tag associations...
""")

            with open(lb_all_file) as f:
                lb_data = json.load(f)

            for lb in lb_data.get('LoadBalancers', []):
                arn = lb.get('LoadBalancerArn')
                lb_name = arn.split('/')[-1]
                lb_file = f"{self.file_prefix}_{lb_name}_lb_tags.json"

                if Path(lb_file).exists():
                    Colors.green(f"using existing load balancer file: {lb_file}")
                else:
                    Colors.blue(f"Get AWS load balancer info for: {arn}")
                    try:
                        response = self.aws.describe_tags([arn])
                        with open(lb_file, 'w') as f:
                            json.dump(response, f, indent=2, default=str)
                    except Exception as e:
                        Colors.perr(f"Failed to describe-tags for elb {arn}: {str(e)}")

                # Check if tags match infra_id
                if Path(lb_file).exists():
                    with open(lb_file) as f:
                        tags_data = json.load(f)

                    matching_tags = []
                    for tag_desc in tags_data.get('TagDescriptions', []):
                        for tag in tag_desc.get('Tags', []):
                            if self.infra_id in tag.get('Value', '') or self.infra_id in tag.get('Key', ''):
                                matching_tags.append(f"{tag['Key']}={tag['Value']}")

                    if matching_tags:
                        printline()
                        Colors.green(f"  Found LB info: {lb_name}, with tag(s) matching infra:{self.infra_id}")

                        # Get service name and role
                        for tag_desc in tags_data.get('TagDescriptions', []):
                            for tag in tag_desc.get('Tags', []):
                                if tag.get('Key') == 'kubernetes.io/service-name':
                                    Colors.green(f"  LB Kub Service Name: 'Kub service-name: {tag['Value']}'")
                                if 'role' in tag.get('Key', ''):
                                    Colors.green(f"  LB Kub Role: 'Kub role: {tag['Value']}'")
                        printline()

        # Get Target Groups for ELBv2
        Colors.blue("Fetching target groups for load balancers...")
        target_groups_file = f"{self.file_prefix}_target_groups.json"
        if Path(target_groups_file).exists():
            Colors.green(f"Using existing target groups file: {target_groups_file}")
        else:
            try:
                response = self.aws.describe_target_groups()
                with open(target_groups_file, 'w') as f:
                    json.dump(response, f, indent=2, default=str)
            except Exception as e:
                Colors.perr(f"Failed to fetch target groups: {str(e)}")

        # Get Target Health for each target group
        if Path(target_groups_file).exists():
            with open(target_groups_file) as f:
                tg_data = json.load(f)

            for tg in tg_data.get('TargetGroups', []):
                tg_arn = tg.get('TargetGroupArn')
                tg_name = tg.get('TargetGroupName', 'unknown')

                # Check if target group belongs to cluster
                if self.infra_id not in tg_name:
                    continue

                tg_health_file = f"{self.file_prefix}_{tg_name}_target_health.json"
                if Path(tg_health_file).exists():
                    Colors.green(f"Using existing target health file: {tg_health_file}")
                else:
                    Colors.blue(f"Fetching target health for: {tg_name}")
                    try:
                        response = self.aws.describe_target_health(tg_arn)
                        with open(tg_health_file, 'w') as f:
                            json.dump(response, f, indent=2, default=str)
                    except Exception as e:
                        Colors.perr(f"Failed to fetch target health for {tg_name}: {str(e)}")

        # Get Classic Load Balancers (ELB)
        Colors.blue("Fetching classic load balancers...")
        classic_lb_file = f"{self.file_prefix}_classic_load_balancers.json"
        if Path(classic_lb_file).exists():
            Colors.green(f"Using existing classic load balancers file: {classic_lb_file}")
        else:
            try:
                response = self.aws.describe_classic_load_balancers()
                with open(classic_lb_file, 'w') as f:
                    json.dump(response, f, indent=2, default=str)
            except Exception as e:
                Colors.perr(f"Failed to fetch classic load balancers: {str(e)}")

    def _write_runtime_config(self):
        """Write runtime configuration to last_run.json"""
        config = {
            'cluster_id': self.cluster_id,
            'capture_start': self.capture_start,
            'capture_end': self.capture_end,
            'start_date': self.start_date,
            'elapsed_time': self.elapsed_time,
            'period': self.period,
            'timestamp': datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
        }

        with open(self.last_run_file, 'w') as f:
            json.dump(config, f, indent=2)

        print(f"Runtime configuration saved to: {self.last_run_file}")


def show_help():
    """Show help message"""
    help_text = """
ROSA Cluster Data Collection Tool

SYNOPSIS:
  get_install_artifacts.py -c|--cluster <cluster-id> [-d|--dir <directory>]
  get_install_artifacts.py -h|--help

DESCRIPTION:
  Automated data collection script for ROSA cluster troubleshooting and analysis.
  Gathers comprehensive AWS infrastructure and OpenShift cluster installation
  artifacts from OCM and AWS APIs.

  The script automatically reuses the time range from the previous run if:
    • A last_run.json file exists in the working directory
    • No -s/--start or -e/--elapsed arguments are provided
  This makes it easy to refresh data for the same time window.

OPTIONS:
  -c, --cluster <cluster-id>    ROSA cluster ID to collect data for
  -d, --dir <directory>         Directory for reading/writing files (default: current directory)
  -s, --start <date>            CloudTrail start date in format: YYYY-MM-DDTHH:MM:SSZ
  -e, --elapsed <time>          CloudTrail capture window (e.g., "3h", "2d", "4days")
  -p, --period <seconds>        CloudWatch metrics period in seconds (default: 300)
  -f, --force-update            Force recalculation of time range, ignore last_run.json
  --debug                       Enable debug output (shows proxy config, AWS commands, etc.)
  -h, --help                    Display this help message and exit

EXAMPLES:
  # First run - collect data with default 2-hour window
  eval $(ocm backplane cloud credentials <clusterid> -o env)
  ./get_install_artifacts.py -c <clusterid>

  # Use custom time window
  ./get_install_artifacts.py -c <clusterid> -s 2025-01-15T10:30:00Z -e 3h

  # Enable debug output to troubleshoot proxy/credential issues
  ./get_install_artifacts.py -c <clusterid> --debug
"""
    print(help_text)


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description='ROSA Cluster Data Collection Tool',
        add_help=False
    )

    parser.add_argument('-c', '--cluster', required=False, help='ROSA cluster ID')
    parser.add_argument('-d', '--dir', default='.', help='Working directory (default: current directory)')
    parser.add_argument('-s', '--start', help='Start date (YYYY-MM-DDTHH:MM:SSZ)')
    parser.add_argument('-e', '--elapsed', help='Elapsed time (e.g., "3h", "2days")')
    parser.add_argument('-p', '--period', type=int, default=300, help='CloudWatch metrics period in seconds')
    parser.add_argument('-f', '--force-update', action='store_true', help='Force recalculation of time range')
    parser.add_argument('--debug', action='store_true', help='Enable debug output')
    parser.add_argument('-h', '--help', action='store_true', help='Show help message')

    args = parser.parse_args()

    if args.help:
        show_help()
        sys.exit(0)

    if not args.cluster:
        Colors.perr("Error: Cluster ID is required")
        print()
        show_help()
        sys.exit(1)

    # Create collector and run
    collector = ClusterDataCollector(
        cluster_id=args.cluster,
        work_dir=args.dir,
        start_date=args.start,
        elapsed_time=args.elapsed,
        period=args.period,
        force_update=args.force_update,
        debug=args.debug
    )

    collector.run()


if __name__ == '__main__':
    main()
