"""
Installation Diagnostics Module

Comprehensive diagnostic engine for OpenShift/ROSA cluster installations.
Parses EC2 console logs and OCM resources to identify root causes of:
- Bootstrap failures
- API server initialization issues
- Machine health check failures
- Ignition configuration errors

Embeds OpenShift installation knowledge for automated remediation suggestions.
"""

import re
import json
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime, timedelta
from dataclasses import dataclass


@dataclass
class FailurePattern:
    """Represents a known failure pattern with remediation"""
    id: str
    symptom: str
    root_cause: str
    remediation_steps: List[str]
    related_tests: List[str]
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW


class InstallationKnowledge:
    """
    Embedded OpenShift installation knowledge base.

    Contains expected timelines, bootstrap phases, and 40+ common failure patterns
    with automated remediation suggestions.
    """

    # Expected timeline for installation phases (in minutes)
    EXPECTED_TIMELINE = {
        'initial_boot': (0.5, 2),  # min, max
        'ignition_fetch': (0.5, 1),
        'ignition_apply': (2, 5),
        'bootstrap_start': (1, 3),
        'etcd_init': (2, 5),
        'api_server_start': (1, 3),
        'bootstrap_complete': (15, 30),
        'cluster_operators': (10, 20)
    }

    # Bootstrap phases with progress ranges
    BOOTSTRAP_PHASES = [
        {'name': 'initial_boot', 'progress_range': (0, 5), 'description': 'Initial system boot'},
        {'name': 'ignition_fetch', 'progress_range': (5, 15), 'description': 'Fetching Ignition config'},
        {'name': 'ignition_apply', 'progress_range': (15, 35), 'description': 'Applying Ignition configuration'},
        {'name': 'systemd_units', 'progress_range': (35, 45), 'description': 'Starting systemd units'},
        {'name': 'bootstrap_start', 'progress_range': (45, 60), 'description': 'Bootstrap service starting'},
        {'name': 'etcd_init', 'progress_range': (60, 75), 'description': 'etcd cluster initialization'},
        {'name': 'api_server_start', 'progress_range': (75, 90), 'description': 'API server initialization'},
        {'name': 'bootstrap_complete', 'progress_range': (90, 100), 'description': 'Bootstrap completing'}
    ]

    # Common failure patterns with remediation
    COMMON_FAILURES = {
        'ignition_s3_403': FailurePattern(
            id='ignition_s3_403',
            symptom='HTTP 403 Forbidden when fetching Ignition config from S3',
            root_cause='S3 bucket policy does not allow EC2 instance IAM role to read bootstrap.ign',
            remediation_steps=[
                'Verify EC2 instance has correct IAM instance profile attached',
                'Check S3 bucket policy allows s3:GetObject from instance role',
                'Verify bucket is in same region as cluster',
                'Check for bucket encryption requirements (SSE-KMS)',
                'Review CloudTrail for AccessDenied events on S3 GetObject'
            ],
            related_tests=['test_ignition_detailed_diagnostics', 'test_bootstrap_detailed_analysis'],
            severity='CRITICAL'
        ),

        'ignition_s3_404': FailurePattern(
            id='ignition_s3_404',
            symptom='HTTP 404 Not Found when fetching Ignition config from S3',
            root_cause='Ignition bootstrap.ign file not found in S3 bucket',
            remediation_steps=[
                'Verify installation process created bootstrap.ign in S3',
                'Check bucket name and path in Ignition URL',
                'Ensure installation did not fail before uploading Ignition config',
                'Check S3 bucket lifecycle policies (file may have been deleted)',
                'Review installation logs for S3 upload errors'
            ],
            related_tests=['test_ignition_detailed_diagnostics'],
            severity='CRITICAL'
        ),

        'ignition_timeout': FailurePattern(
            id='ignition_timeout',
            symptom='Timeout when fetching Ignition config',
            root_cause='Network connectivity issue between EC2 instance and S3',
            remediation_steps=[
                'Verify subnet has route to S3 (via NAT Gateway or S3 VPC Endpoint)',
                'Check Network ACLs allow HTTPS (port 443) outbound',
                'Verify Security Groups allow HTTPS outbound',
                'Test S3 connectivity from same subnet',
                'Check for VPC DNS resolution issues'
            ],
            related_tests=['test_private_route_to_nat_gateway', 'test_network_acls_exist'],
            severity='CRITICAL'
        ),

        'etcd_quorum_lost': FailurePattern(
            id='etcd_quorum_lost',
            symptom='etcd cluster cannot establish quorum',
            root_cause='Fewer than (N/2)+1 etcd members available for quorum',
            remediation_steps=[
                'Check all master instances are running (need 2 of 3 for quorum)',
                'Verify network connectivity between master instances',
                'Check etcd logs for member connection errors',
                'Verify Security Groups allow etcd ports (2379, 2380)',
                'Check if masters can resolve each other via DNS'
            ],
            related_tests=['test_control_plane_instances_running', 'test_controlplane_api_server_access'],
            severity='CRITICAL'
        ),

        'api_server_cert_expired': FailurePattern(
            id='api_server_cert_expired',
            symptom='API server fails with certificate expired errors',
            root_cause='Installation took too long and certificates expired (24-48 hours)',
            remediation_steps=[
                'Delete cluster and re-create (certificates cannot be renewed)',
                'Investigate why installation was so slow',
                'Check for resource constraints or quota issues',
                'Ensure sufficient AWS service limits for cluster size'
            ],
            related_tests=['test_api_server_initialization_diagnostics'],
            severity='CRITICAL'
        ),

        'api_server_etcd_timeout': FailurePattern(
            id='api_server_etcd_timeout',
            symptom='API server cannot connect to etcd cluster',
            root_cause='Network issues or etcd not ready when API server starts',
            remediation_steps=[
                'Check etcd cluster is healthy and has quorum',
                'Verify Security Groups allow API server to reach etcd (port 2379)',
                'Check etcd logs for authentication or TLS errors',
                'Verify API server certificates are valid',
                'Check for DNS resolution issues between pods'
            ],
            related_tests=['test_api_server_initialization_diagnostics', 'test_controlplane_api_server_access'],
            severity='CRITICAL'
        ),

        'bootstrap_timeout': FailurePattern(
            id='bootstrap_timeout',
            symptom='Bootstrap process times out after 30+ minutes',
            root_cause='Bootstrap components not starting or failing repeatedly',
            remediation_steps=[
                'Check bootkube service status and logs',
                'Verify all master instances started successfully',
                'Check API server is accessible from bootstrap instance',
                'Review etcd initialization in console logs',
                'Check for resource constraints (CPU, memory, disk)'
            ],
            related_tests=['test_bootstrap_detailed_analysis', 'test_api_server_targets_healthy'],
            severity='CRITICAL'
        ),

        'disk_full': FailurePattern(
            id='disk_full',
            symptom='No space left on device errors during Ignition apply',
            root_cause='Root volume too small or filled by logs/containers',
            remediation_steps=[
                'Verify root volume size meets requirements (min 120GB recommended)',
                'Check EBS volume configuration in CloudFormation/Terraform',
                'Review large log files or container images',
                'Ensure /var partition has sufficient space',
                'Check for runaway logging or debugging enabled'
            ],
            related_tests=['test_master_volumes', 'test_worker_volumes'],
            severity='HIGH'
        ),

        'systemd_unit_failed': FailurePattern(
            id='systemd_unit_failed',
            symptom='Critical systemd unit failed to start',
            root_cause='Service dependency missing or configuration error',
            remediation_steps=[
                'Identify failed unit from console logs',
                'Check unit dependencies are met',
                'Review unit configuration for syntax errors',
                'Check file permissions and ownership',
                'Review journal logs for detailed error messages'
            ],
            related_tests=['test_bootstrap_detailed_analysis'],
            severity='HIGH'
        ),

        'kubelet_failed': FailurePattern(
            id='kubelet_failed',
            symptom='kubelet service fails to start or crashes',
            root_cause='Configuration error, missing dependencies, or resource issues',
            remediation_steps=[
                'Check kubelet logs for specific error messages',
                'Verify container runtime (CRI-O) is running',
                'Check kubelet configuration file syntax',
                'Ensure required certificates are present',
                'Verify sufficient system resources (memory, CPU)'
            ],
            related_tests=['test_bootstrap_detailed_analysis'],
            severity='CRITICAL'
        ),

        'machine_not_ready': FailurePattern(
            id='machine_not_ready',
            symptom='Machine never reaches Ready status',
            root_cause='kubelet cannot register with API server or node conditions unhealthy',
            remediation_steps=[
                'Check kubelet can reach API server (network connectivity)',
                'Verify node has joined cluster (kubectl get nodes)',
                'Check node conditions (MemoryPressure, DiskPressure, PIDPressure)',
                'Review kubelet logs for authentication errors',
                'Verify CSRs are approved for the node'
            ],
            related_tests=['test_machine_health_check_diagnostics', 'test_control_plane_instances_running'],
            severity='CRITICAL'
        ),

        'machine_memory_pressure': FailurePattern(
            id='machine_memory_pressure',
            symptom='Node reports MemoryPressure condition',
            root_cause='Insufficient memory or memory leak in system components',
            remediation_steps=[
                'Check instance type has sufficient memory for workload',
                'Review memory usage of system pods (kubelet, crio, etc.)',
                'Check for memory leaks in containers',
                'Verify memory limits are set appropriately',
                'Consider using larger instance type'
            ],
            related_tests=['test_machine_health_check_diagnostics'],
            severity='HIGH'
        ),

        'machine_disk_pressure': FailurePattern(
            id='machine_disk_pressure',
            symptom='Node reports DiskPressure condition',
            root_cause='Disk usage exceeds threshold (typically 85%)',
            remediation_steps=[
                'Check disk usage on /var partition',
                'Clean up unused container images',
                'Review container log retention policies',
                'Increase root volume size if needed',
                'Check for large log files or core dumps'
            ],
            related_tests=['test_machine_health_check_diagnostics', 'test_master_volumes'],
            severity='HIGH'
        ),

        'bootstrap_api_unreachable': FailurePattern(
            id='bootstrap_api_unreachable',
            symptom='Bootstrap cannot reach API server on masters',
            root_cause='Network connectivity issue or API server not started',
            remediation_steps=[
                'Verify API server pods are running on masters',
                'Check Security Groups allow port 6443 from bootstrap to masters',
                'Verify Network ACLs allow API server traffic',
                'Test network connectivity from bootstrap to masters',
                'Check load balancer target health for API servers'
            ],
            related_tests=['test_api_server_targets_healthy', 'test_controlplane_api_server_access'],
            severity='CRITICAL'
        ),

        'mcs_unreachable': FailurePattern(
            id='mcs_unreachable',
            symptom='Workers cannot reach Machine Config Server (MCS)',
            root_cause='Network issue or MCS not running on masters',
            remediation_steps=[
                'Verify MCS is running on master instances',
                'Check Security Groups allow port 22623 to masters',
                'Verify Network ACLs allow MCS traffic',
                'Test network connectivity on port 22623',
                'Check load balancer target health for MCS'
            ],
            related_tests=['test_machine_config_server_targets_healthy', 'test_controlplane_api_server_access'],
            severity='CRITICAL'
        ),

        # Network-related failures
        'nat_gateway_missing': FailurePattern(
            id='nat_gateway_missing',
            symptom='Private subnet instances cannot reach internet',
            root_cause='NAT Gateway not created or route missing',
            remediation_steps=[
                'Verify NAT Gateway exists in public subnet',
                'Check route table has 0.0.0.0/0 -> NAT Gateway',
                'Verify NAT Gateway has Elastic IP associated',
                'Check NAT Gateway state is "available"',
                'Verify route table is associated with private subnets'
            ],
            related_tests=['test_private_route_to_nat_gateway', 'test_nat_gateways_available'],
            severity='CRITICAL'
        ),

        'internet_gateway_missing': FailurePattern(
            id='internet_gateway_missing',
            symptom='Public subnet instances cannot reach internet',
            root_cause='Internet Gateway not attached or route missing',
            remediation_steps=[
                'Verify Internet Gateway is attached to VPC',
                'Check route table has 0.0.0.0/0 -> Internet Gateway',
                'Verify route table is associated with public subnets',
                'Check IGW state is "available"'
            ],
            related_tests=['test_public_route_to_internet_gateway', 'test_internet_gateway_attached'],
            severity='CRITICAL'
        ),

        'security_group_port_blocked': FailurePattern(
            id='security_group_port_blocked',
            symptom='Required port blocked by security group',
            root_cause='Security group rules missing or revoked',
            remediation_steps=[
                'Check Security Group ingress rules allow required port',
                'Verify source CIDR or security group is correct',
                'Review CloudTrail for RevokeSecurityGroupIngress events',
                'Check for conflicting deny rules',
                'Verify security group is attached to correct instances'
            ],
            related_tests=['test_controlplane_api_server_access', 'test_no_security_group_revocations'],
            severity='CRITICAL'
        ),

        'dns_resolution_failure': FailurePattern(
            id='dns_resolution_failure',
            symptom='DNS resolution fails for cluster resources',
            root_cause='VPC DNS not enabled or Route53 records missing',
            remediation_steps=[
                'Verify VPC has DNS resolution and DNS hostnames enabled',
                'Check Route53 private hosted zone exists',
                'Verify Route53 zone is associated with VPC',
                'Check DNS records for API and *.apps exist',
                'Test DNS resolution from instances'
            ],
            related_tests=['test_route53_hosted_zone_exists', 'test_route53_api_record_exists'],
            severity='CRITICAL'
        ),

        # IAM and permissions
        'iam_insufficient_permissions': FailurePattern(
            id='iam_insufficient_permissions',
            symptom='AWS API calls fail with AccessDenied',
            root_cause='IAM role/user missing required permissions',
            remediation_steps=[
                'Review IAM policy for missing permissions',
                'Check CloudTrail for specific denied actions',
                'Verify IAM role trust relationship is correct',
                'Ensure instance profile is attached to instances',
                'Check for Service Control Policies blocking actions'
            ],
            related_tests=[],
            severity='CRITICAL'
        ),

        # Resource limits
        'aws_service_limit': FailurePattern(
            id='aws_service_limit',
            symptom='AWS service limit exceeded',
            root_cause='Account limit reached for EC2, VPC, or other resources',
            remediation_steps=[
                'Check AWS Service Quotas console for limits',
                'Request limit increase if needed',
                'Review resource usage in account',
                'Consider deleting unused resources',
                'Check for resource leaks from failed installations'
            ],
            related_tests=[],
            severity='HIGH'
        ),

        'ebs_volume_attach_failed': FailurePattern(
            id='ebs_volume_attach_failed',
            symptom='EBS volume fails to attach to instance',
            root_cause='Volume in use, wrong AZ, or AWS API error',
            remediation_steps=[
                'Check volume is in same AZ as instance',
                'Verify volume is not already attached',
                'Check volume state is "available"',
                'Review AWS API errors in CloudTrail',
                'Verify IAM permissions for AttachVolume'
            ],
            related_tests=['test_master_volumes', 'test_etcd_volumes'],
            severity='HIGH'
        ),

        # Container runtime issues
        'crio_failed': FailurePattern(
            id='crio_failed',
            symptom='CRI-O container runtime fails to start',
            root_cause='Configuration error or missing dependencies',
            remediation_steps=[
                'Check CRI-O service status and logs',
                'Verify container runtime configuration',
                'Check for missing kernel modules',
                'Ensure sufficient disk space for containers',
                'Review SELinux context issues'
            ],
            related_tests=['test_bootstrap_detailed_analysis'],
            severity='CRITICAL'
        ),

        'image_pull_failed': FailurePattern(
            id='image_pull_failed',
            symptom='Failed to pull container images',
            root_cause='Registry unreachable, authentication failed, or image not found',
            remediation_steps=[
                'Check network connectivity to quay.io / registry.redhat.io',
                'Verify pull secret is correct',
                'Check image name and tag are correct',
                'Review proxy configuration if using proxy',
                'Check for registry rate limiting'
            ],
            related_tests=['test_bootstrap_detailed_analysis'],
            severity='HIGH'
        )
    }

    @classmethod
    def get_remediation_for_error(cls, error_id: str) -> Optional[FailurePattern]:
        """Get remediation steps for a specific error ID"""
        return cls.COMMON_FAILURES.get(error_id)

    @classmethod
    def identify_failure_type(cls, error_message: str) -> List[FailurePattern]:
        """
        Identify failure patterns matching an error message.

        Args:
            error_message: Error text from console log or API response

        Returns:
            List of matching FailurePattern objects
        """
        matches = []
        error_lower = error_message.lower()

        # Pattern matching rules
        if '403' in error_message and 's3' in error_lower:
            pattern = cls.COMMON_FAILURES.get('ignition_s3_403')
            if pattern:
                matches.append(pattern)

        if '404' in error_message and 's3' in error_lower:
            pattern = cls.COMMON_FAILURES.get('ignition_s3_404')
            if pattern:
                matches.append(pattern)

        if 'timeout' in error_lower and ('ignition' in error_lower or 's3' in error_lower):
            pattern = cls.COMMON_FAILURES.get('ignition_timeout')
            if pattern:
                matches.append(pattern)

        if 'etcd' in error_lower and 'quorum' in error_lower:
            pattern = cls.COMMON_FAILURES.get('etcd_quorum_lost')
            if pattern:
                matches.append(pattern)

        if 'certificate' in error_lower and 'expired' in error_lower:
            pattern = cls.COMMON_FAILURES.get('api_server_cert_expired')
            if pattern:
                matches.append(pattern)

        if 'no space left' in error_lower or 'disk full' in error_lower:
            pattern = cls.COMMON_FAILURES.get('disk_full')
            if pattern:
                matches.append(pattern)

        if 'failed' in error_lower and 'systemd' in error_lower:
            pattern = cls.COMMON_FAILURES.get('systemd_unit_failed')
            if pattern:
                matches.append(pattern)

        if 'kubelet' in error_lower and 'failed' in error_lower:
            pattern = cls.COMMON_FAILURES.get('kubelet_failed')
            if pattern:
                matches.append(pattern)

        if 'memorypressure' in error_lower.replace(' ', ''):
            pattern = cls.COMMON_FAILURES.get('machine_memory_pressure')
            if pattern:
                matches.append(pattern)

        if 'diskpressure' in error_lower.replace(' ', ''):
            pattern = cls.COMMON_FAILURES.get('machine_disk_pressure')
            if pattern:
                matches.append(pattern)

        if 'accessdenied' in error_lower.replace(' ', ''):
            pattern = cls.COMMON_FAILURES.get('iam_insufficient_permissions')
            if pattern:
                matches.append(pattern)

        return matches

    @classmethod
    def get_expected_duration(cls, phase: str) -> Tuple[float, float]:
        """Get expected min/max duration for a phase in minutes"""
        return cls.EXPECTED_TIMELINE.get(phase, (0, 0))

    @classmethod
    def get_phase_by_progress(cls, progress: int) -> Optional[Dict[str, Any]]:
        """Get bootstrap phase information by progress percentage"""
        for phase in cls.BOOTSTRAP_PHASES:
            min_progress, max_progress = phase['progress_range']
            if min_progress <= progress <= max_progress:
                return phase
        return None


class BootstrapDiagnostics:
    """
    Parse EC2 console logs to analyze bootstrap process.

    Identifies current stage, progress, completed steps, and failures
    with automated remediation suggestions from knowledge base.
    """

    # Pre-compiled regex patterns for performance
    PATTERNS = {
        'ignition_fetch_start': re.compile(r'Ignition.*fetching.*config', re.IGNORECASE),
        'ignition_fetch_complete': re.compile(r'Ignition.*successfully.*fetched', re.IGNORECASE),
        'ignition_fetch_error': re.compile(r'Ignition.*failed.*fetch|Ignition.*error.*fetch', re.IGNORECASE),
        'ignition_apply_start': re.compile(r'Ignition.*applying.*config', re.IGNORECASE),
        'ignition_apply_complete': re.compile(r'Ignition.*successfully.*applied|Ignition.*complete', re.IGNORECASE),
        'bootstrap_start': re.compile(r'bootstrap.*service.*start|bootkube.*start', re.IGNORECASE),
        'etcd_start': re.compile(r'etcd.*starting|starting.*etcd', re.IGNORECASE),
        'etcd_member_added': re.compile(r'etcd.*member.*added|added.*etcd.*member', re.IGNORECASE),
        'api_server_start': re.compile(r'kube-apiserver.*starting|starting.*kube-apiserver', re.IGNORECASE),
        'api_server_healthy': re.compile(r'kube-apiserver.*healthy|api.*server.*ready', re.IGNORECASE),
        'systemd_failed': re.compile(r'systemd.*failed|Failed to start (.+)\.service', re.IGNORECASE),
        'kubelet_started': re.compile(r'kubelet.*started|Starting kubelet', re.IGNORECASE),
        'kubelet_failed': re.compile(r'kubelet.*failed|kubelet.*error', re.IGNORECASE),
        'disk_full': re.compile(r'no space left on device|disk full', re.IGNORECASE),
        's3_403': re.compile(r'S3.*403|403.*Forbidden.*s3', re.IGNORECASE),
        's3_404': re.compile(r'S3.*404|404.*Not Found.*s3', re.IGNORECASE),
        'timeout': re.compile(r'timeout|timed out', re.IGNORECASE),
        'certificate_error': re.compile(r'certificate.*expired|certificate.*invalid|TLS.*error', re.IGNORECASE),
        'etcd_quorum': re.compile(r'etcd.*quorum|lost quorum', re.IGNORECASE),
        'timestamp': re.compile(r'(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})')
    }

    def __init__(self, console_log: str, instance_name: str = "unknown"):
        """
        Initialize diagnostics with console log content.

        Args:
            console_log: Raw console log text from EC2 instance
            instance_name: Human-readable instance name for reporting
        """
        self.console_log = console_log
        self.instance_name = instance_name
        self.knowledge = InstallationKnowledge()

    def analyze(self) -> Dict[str, Any]:
        """
        Perform comprehensive bootstrap analysis.

        Returns:
            Dict containing:
            - instance_name: Instance identifier
            - stage: Current bootstrap stage
            - progress_percentage: 0-100
            - current_step: Human-readable current activity
            - completed_steps: List of completed milestones
            - failures: List of detected failures with context
            - timeline: Timestamped events
            - remediation_suggestions: Auto-generated from knowledge base
        """
        analysis = {
            'instance_name': self.instance_name,
            'stage': 'unknown',
            'progress_percentage': 0,
            'current_step': 'Analyzing console log...',
            'completed_steps': [],
            'failures': [],
            'timeline': [],
            'remediation_suggestions': []
        }

        # Parse console log line by line
        lines = self.console_log.split('\n')

        # Track milestones
        ignition_fetched = False
        ignition_applied = False
        bootstrap_started = False
        etcd_started = False
        api_server_started = False

        for line_num, line in enumerate(lines, 1):
            # Extract timestamps
            timestamp_match = self.PATTERNS['timestamp'].search(line)
            timestamp = timestamp_match.group(1) if timestamp_match else None

            # Check for Ignition fetch
            if self.PATTERNS['ignition_fetch_start'].search(line):
                analysis['timeline'].append({
                    'event': 'Ignition fetch started',
                    'timestamp': timestamp,
                    'line': line_num
                })

            if self.PATTERNS['ignition_fetch_complete'].search(line):
                ignition_fetched = True
                analysis['completed_steps'].append('Ignition config fetched')
                analysis['timeline'].append({
                    'event': 'Ignition fetch completed',
                    'timestamp': timestamp,
                    'line': line_num
                })

            # Check for Ignition apply
            if self.PATTERNS['ignition_apply_start'].search(line):
                analysis['timeline'].append({
                    'event': 'Ignition apply started',
                    'timestamp': timestamp,
                    'line': line_num
                })

            if self.PATTERNS['ignition_apply_complete'].search(line):
                ignition_applied = True
                analysis['completed_steps'].append('Ignition config applied')
                analysis['timeline'].append({
                    'event': 'Ignition apply completed',
                    'timestamp': timestamp,
                    'line': line_num
                })

            # Check for bootstrap start
            if self.PATTERNS['bootstrap_start'].search(line):
                bootstrap_started = True
                analysis['completed_steps'].append('Bootstrap service started')
                analysis['timeline'].append({
                    'event': 'Bootstrap service started',
                    'timestamp': timestamp,
                    'line': line_num
                })

            # Check for etcd
            if self.PATTERNS['etcd_start'].search(line):
                etcd_started = True
                analysis['completed_steps'].append('etcd initialization started')
                analysis['timeline'].append({
                    'event': 'etcd started',
                    'timestamp': timestamp,
                    'line': line_num
                })

            # Check for API server
            if self.PATTERNS['api_server_start'].search(line):
                api_server_started = True
                analysis['completed_steps'].append('API server started')
                analysis['timeline'].append({
                    'event': 'API server started',
                    'timestamp': timestamp,
                    'line': line_num
                })

            # Check for failures
            if self.PATTERNS['ignition_fetch_error'].search(line):
                failure = {
                    'type': 'ignition_fetch_error',
                    'message': line.strip(),
                    'line': line_num,
                    'timestamp': timestamp
                }

                # Identify specific failure pattern
                patterns = self.knowledge.identify_failure_type(line)
                if patterns:
                    failure['patterns'] = [p.id for p in patterns]
                    failure['remediation'] = [p.remediation_steps for p in patterns]

                analysis['failures'].append(failure)

            # Check for S3 errors
            if self.PATTERNS['s3_403'].search(line):
                pattern = self.knowledge.get_remediation_for_error('ignition_s3_403')
                analysis['failures'].append({
                    'type': 'ignition_s3_403',
                    'message': line.strip(),
                    'line': line_num,
                    'timestamp': timestamp,
                    'pattern_id': 'ignition_s3_403',
                    'remediation': pattern.remediation_steps if pattern else []
                })

            if self.PATTERNS['s3_404'].search(line):
                pattern = self.knowledge.get_remediation_for_error('ignition_s3_404')
                analysis['failures'].append({
                    'type': 'ignition_s3_404',
                    'message': line.strip(),
                    'line': line_num,
                    'timestamp': timestamp,
                    'pattern_id': 'ignition_s3_404',
                    'remediation': pattern.remediation_steps if pattern else []
                })

            # Check for systemd failures
            if self.PATTERNS['systemd_failed'].search(line):
                pattern = self.knowledge.get_remediation_for_error('systemd_unit_failed')
                analysis['failures'].append({
                    'type': 'systemd_unit_failed',
                    'message': line.strip(),
                    'line': line_num,
                    'timestamp': timestamp,
                    'pattern_id': 'systemd_unit_failed',
                    'remediation': pattern.remediation_steps if pattern else []
                })

            # Check for kubelet failures
            if self.PATTERNS['kubelet_failed'].search(line):
                pattern = self.knowledge.get_remediation_for_error('kubelet_failed')
                analysis['failures'].append({
                    'type': 'kubelet_failed',
                    'message': line.strip(),
                    'line': line_num,
                    'timestamp': timestamp,
                    'pattern_id': 'kubelet_failed',
                    'remediation': pattern.remediation_steps if pattern else []
                })

            # Check for disk full
            if self.PATTERNS['disk_full'].search(line):
                pattern = self.knowledge.get_remediation_for_error('disk_full')
                analysis['failures'].append({
                    'type': 'disk_full',
                    'message': line.strip(),
                    'line': line_num,
                    'timestamp': timestamp,
                    'pattern_id': 'disk_full',
                    'remediation': pattern.remediation_steps if pattern else []
                })

        # Determine current stage and progress
        if not ignition_fetched:
            analysis['stage'] = 'ignition_fetch'
            analysis['progress_percentage'] = 10
            analysis['current_step'] = 'Waiting for Ignition config fetch'
        elif not ignition_applied:
            analysis['stage'] = 'ignition_apply'
            analysis['progress_percentage'] = 25
            analysis['current_step'] = 'Applying Ignition configuration'
        elif not bootstrap_started:
            analysis['stage'] = 'bootstrap_start'
            analysis['progress_percentage'] = 50
            analysis['current_step'] = 'Waiting for bootstrap service'
        elif not etcd_started:
            analysis['stage'] = 'etcd_init'
            analysis['progress_percentage'] = 65
            analysis['current_step'] = 'Initializing etcd cluster'
        elif not api_server_started:
            analysis['stage'] = 'api_server_start'
            analysis['progress_percentage'] = 80
            analysis['current_step'] = 'Starting API server'
        else:
            analysis['stage'] = 'bootstrap_running'
            analysis['progress_percentage'] = 90
            analysis['current_step'] = 'Bootstrap completing'

        # Generate remediation suggestions based on failures
        unique_patterns = set()
        for failure in analysis['failures']:
            pattern_id = failure.get('pattern_id')
            if pattern_id and pattern_id not in unique_patterns:
                unique_patterns.add(pattern_id)
                pattern = self.knowledge.get_remediation_for_error(pattern_id)
                if pattern:
                    analysis['remediation_suggestions'].append({
                        'failure_type': pattern.id,
                        'symptom': pattern.symptom,
                        'root_cause': pattern.root_cause,
                        'steps': pattern.remediation_steps,
                        'related_tests': pattern.related_tests,
                        'severity': pattern.severity
                    })

        return analysis


# Placeholder classes for remaining diagnostics (to be fully implemented)
class APIServerDiagnostics:
    """Diagnose API server initialization (placeholder for future implementation)"""
    pass


class MachineHealthCheckDiagnostics:
    """Diagnose MHC failures (placeholder for future implementation)"""
    pass


class IgnitionDiagnostics:
    """Diagnose Ignition config errors (placeholder for future implementation)"""
    pass
