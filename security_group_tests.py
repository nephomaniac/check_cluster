#!/usr/bin/env python3
"""
Security Group Tests

Validates that security groups allow necessary traffic flows for ROSA clusters.
"""

from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any, Tuple
from test_framework import TestCase, TestStatus
import re


@dataclass
class TrafficExpectation:
    """
    Represents an expected traffic flow that must be allowed by security groups.

    This defines WHAT traffic should be allowed, not HOW (which specific rules).
    The validator will search for any rules that satisfy this expectation.
    """
    description: str  # Why this traffic is needed
    protocol: str  # tcp, udp, icmp, -1 (all), etc.
    direction: str  # "ingress" or "egress"
    port_range: Optional[Tuple[int, int]] = None  # (from_port, to_port) or None for all ports
    source_type: str = "any"  # "cidr", "sg", "any", "vpc", "public"
    source_values: List[str] = field(default_factory=list)  # Expected source CIDRs or SG IDs
    required: bool = True  # Is this expectation mandatory or optional?
    applies_to_sg: Optional[List[str]] = None  # Which SG names this applies to (None = all)

    def get_port_display(self) -> str:
        """Get human-readable port range"""
        if not self.port_range:
            return "all"
        from_port, to_port = self.port_range
        if from_port == to_port:
            return str(from_port)
        return f"{from_port}-{to_port}"

    def matches_rule(self, rule: Dict[str, Any], rule_direction: str) -> bool:
        """
        Check if a security group rule satisfies this expectation.

        Args:
            rule: Security group rule dict from AWS
            rule_direction: "ingress" or "egress"

        Returns:
            True if this rule satisfies the expectation
        """
        # Check direction
        if rule_direction != self.direction:
            return False

        # Check protocol
        rule_protocol = rule.get('IpProtocol', '')
        if self.protocol != '-1' and rule_protocol != self.protocol:
            # -1 means all protocols, so a rule with -1 matches any expectation
            if rule_protocol != '-1':
                return False

        # Check port range
        if self.port_range:
            from_port, to_port = self.port_range
            rule_from = rule.get('FromPort')
            rule_to = rule.get('ToPort')

            # Rule must cover the expected port range
            if rule_from is not None and rule_to is not None:
                # Check if rule covers expected ports
                if not (rule_from <= from_port and rule_to >= to_port):
                    return False

        # Check source (for ingress) or destination (for egress)
        if self.source_type == "any":
            # Any source is acceptable
            return True

        # Get sources from rule
        rule_sources = self._extract_sources_from_rule(rule)

        if self.source_type == "public":
            # Expect public access (0.0.0.0/0 or ::/0)
            return "0.0.0.0/0" in rule_sources or "::/0" in rule_sources

        elif self.source_type == "vpc":
            # Expect VPC CIDR ranges (10.x, 172.16-31.x, 192.168.x)
            return any(self._is_private_cidr(src) for src in rule_sources)

        elif self.source_type == "cidr":
            # Expect specific CIDR blocks
            if not self.source_values:
                return True  # No specific CIDRs required
            return any(val in rule_sources for val in self.source_values)

        elif self.source_type == "sg":
            # Expect security group references
            sg_sources = [src for src in rule_sources if src.startswith('sg-')]
            if not self.source_values:
                return len(sg_sources) > 0  # Any SG reference is acceptable
            return any(val in sg_sources for val in self.source_values)

        return False

    def _extract_sources_from_rule(self, rule: Dict[str, Any]) -> List[str]:
        """Extract all source identifiers from a rule"""
        sources = []

        # CIDR blocks (IPv4)
        for ip_range in rule.get('IpRanges', []):
            cidr = ip_range.get('CidrIp', '')
            if cidr:
                sources.append(cidr)

        # CIDR blocks (IPv6)
        for ipv6_range in rule.get('Ipv6Ranges', []):
            cidr = ipv6_range.get('CidrIpv6', '')
            if cidr:
                sources.append(cidr)

        # Security group references
        for sg_pair in rule.get('UserIdGroupPairs', []):
            sg_id = sg_pair.get('GroupId', '')
            if sg_id:
                sources.append(sg_id)

        # Prefix lists
        for prefix_list in rule.get('PrefixListIds', []):
            pl_id = prefix_list.get('PrefixListId', '')
            if pl_id:
                sources.append(pl_id)

        return sources

    @staticmethod
    def _is_private_cidr(cidr: str) -> bool:
        """Check if CIDR is a private IP range"""
        if not cidr:
            return False
        # Simple check for private IP ranges
        return (cidr.startswith('10.') or
                cidr.startswith('172.16.') or cidr.startswith('172.17.') or
                cidr.startswith('172.18.') or cidr.startswith('172.19.') or
                cidr.startswith('172.20.') or cidr.startswith('172.21.') or
                cidr.startswith('172.22.') or cidr.startswith('172.23.') or
                cidr.startswith('172.24.') or cidr.startswith('172.25.') or
                cidr.startswith('172.26.') or cidr.startswith('172.27.') or
                cidr.startswith('172.28.') or cidr.startswith('172.29.') or
                cidr.startswith('172.30.') or cidr.startswith('172.31.') or
                cidr.startswith('192.168.'))


class SecurityGroupTests(TestCase):
    """
    Security group validation test suite.

    Validates that security groups allow necessary traffic flows based on
    cluster configuration (public vs private, HCP vs Classic, etc.)
    """

    def __init__(self, cluster_data: Dict[str, Any], sg_data: Dict[str, Any], infra_id: str):
        super().__init__("security_groups", cluster_data)
        self.sg_data = sg_data
        self.infra_id = infra_id
        self.security_groups = sg_data.get('SecurityGroups', [])

        # Determine cluster configuration
        self.is_private = cluster_data.get('api', {}).get('listening') == 'internal'
        self.is_privatelink = cluster_data.get('aws', {}).get('private_link', False)

        # Build SG lookup by name
        self.sgs_by_name = {}
        for sg in self.security_groups:
            sg_name = sg.get('GroupName', '')
            if infra_id in sg_name:
                self.sgs_by_name[sg_name] = sg

    def run(self) -> 'TestSuiteResult':
        """Execute all security group traffic flow validations"""
        # Generate expectations based on cluster config
        expectations = self._generate_traffic_expectations()

        # Validate each expectation
        for expectation in expectations:
            self._validate_expectation(expectation)

        return self.results

    def _generate_traffic_expectations(self) -> List[TrafficExpectation]:
        """
        Generate traffic expectations based on cluster configuration.

        Returns a list of TrafficExpectation objects that define what
        traffic must be allowed for this specific cluster.
        """
        expectations = []

        # === CONTROL PLANE / API LB EXPECTATIONS ===
        api_lb_sgs = [f"{self.infra_id}-lb", f"{self.infra_id}-apiserver-lb"]

        if self.is_private:
            # Private cluster: API should be accessible from VPC only
            expectations.append(TrafficExpectation(
                description="Kubernetes API Server access from VPC",
                protocol="tcp",
                direction="ingress",
                port_range=(6443, 6443),
                source_type="vpc",
                applies_to_sg=api_lb_sgs
            ))
            expectations.append(TrafficExpectation(
                description="Machine Config Server access from VPC",
                protocol="tcp",
                direction="ingress",
                port_range=(22623, 22623),
                source_type="vpc",
                applies_to_sg=api_lb_sgs
            ))
        else:
            # Public cluster: API should be publicly accessible
            expectations.append(TrafficExpectation(
                description="Kubernetes API Server public access",
                protocol="tcp",
                direction="ingress",
                port_range=(6443, 6443),
                source_type="public",
                applies_to_sg=api_lb_sgs
            ))
            expectations.append(TrafficExpectation(
                description="Machine Config Server public access",
                protocol="tcp",
                direction="ingress",
                port_range=(22623, 22623),
                source_type="public",
                applies_to_sg=api_lb_sgs
            ))

        # === WORKER NODE EXPECTATIONS ===
        node_sg = f"{self.infra_id}-node"

        expectations.extend([
            TrafficExpectation(
                description="SSH access to worker nodes",
                protocol="tcp",
                direction="ingress",
                port_range=(22, 22),
                source_type="sg",  # Typically from control plane or bastion
                applies_to_sg=[node_sg]
            ),
            TrafficExpectation(
                description="Kubelet API access",
                protocol="tcp",
                direction="ingress",
                port_range=(10250, 10250),
                source_type="sg",  # From control plane
                applies_to_sg=[node_sg]
            ),
            TrafficExpectation(
                description="NodePort Services range",
                protocol="tcp",
                direction="ingress",
                port_range=(30000, 32767),
                source_type="sg",  # From other nodes or LB
                applies_to_sg=[node_sg]
            ),
            TrafficExpectation(
                description="VXLAN overlay network",
                protocol="udp",
                direction="ingress",
                port_range=(4789, 4789),
                source_type="sg",  # From other nodes
                applies_to_sg=[node_sg]
            ),
            TrafficExpectation(
                description="Geneve overlay network",
                protocol="udp",
                direction="ingress",
                port_range=(6081, 6081),
                source_type="sg",  # From other nodes
                applies_to_sg=[node_sg]
            ),
            TrafficExpectation(
                description="Internal cluster communication",
                protocol="tcp",
                direction="ingress",
                port_range=(9000, 9999),
                source_type="sg",  # From other nodes
                applies_to_sg=[node_sg]
            ),
        ])

        # === CONTROL PLANE / MASTER NODE EXPECTATIONS ===
        cp_sg = f"{self.infra_id}-controlplane"

        expectations.extend([
            TrafficExpectation(
                description="Kubernetes API Server on control plane",
                protocol="tcp",
                direction="ingress",
                port_range=(6443, 6443),
                source_type="sg",  # From LB and nodes
                applies_to_sg=[cp_sg]
            ),
            TrafficExpectation(
                description="Machine Config Server on control plane",
                protocol="tcp",
                direction="ingress",
                port_range=(22623, 22623),
                source_type="sg",  # From nodes
                applies_to_sg=[cp_sg]
            ),
            TrafficExpectation(
                description="etcd client communication",
                protocol="tcp",
                direction="ingress",
                port_range=(2379, 2379),
                source_type="sg",  # From other control plane nodes
                required=False,  # Optional - may not be exposed
                applies_to_sg=[cp_sg]
            ),
            TrafficExpectation(
                description="etcd peer communication",
                protocol="tcp",
                direction="ingress",
                port_range=(2380, 2380),
                source_type="sg",  # From other control plane nodes
                required=False,  # Optional - may not be exposed
                applies_to_sg=[cp_sg]
            ),
        ])

        # === EGRESS EXPECTATIONS (ALL SGs) ===
        all_sgs = list(self.sgs_by_name.keys())
        expectations.append(TrafficExpectation(
            description="Allow all outbound traffic",
            protocol="-1",
            direction="egress",
            port_range=None,
            source_type="any",
            applies_to_sg=all_sgs
        ))

        return expectations

    def _validate_expectation(self, expectation: TrafficExpectation):
        """
        Validate a single traffic expectation against actual security group rules.

        Searches all relevant security groups for rules that satisfy this expectation.
        """
        matching_rules = []

        # Determine which SGs to check
        sgs_to_check = expectation.applies_to_sg if expectation.applies_to_sg else list(self.sgs_by_name.keys())

        for sg_name in sgs_to_check:
            if sg_name not in self.sgs_by_name:
                continue

            sg = self.sgs_by_name[sg_name]
            sg_id = sg.get('GroupId', 'unknown')

            # Get rules based on direction
            if expectation.direction == "ingress":
                rules = sg.get('IpPermissions', [])
            else:  # egress
                rules = sg.get('IpPermissionsEgress', [])

            # Check each rule
            for rule in rules:
                if expectation.matches_rule(rule, expectation.direction):
                    # Found a matching rule!
                    rule_info = self._format_rule_info(rule, sg_name, sg_id, expectation.direction)
                    matching_rules.append(rule_info)

        # Determine test result
        if matching_rules:
            # Success - found rules that allow this traffic
            details = "; ".join(matching_rules)
            self.results.add_result(self._create_sg_result(
                expectation=expectation,
                status=TestStatus.PASS,
                allowed_by=details
            ))
        else:
            # Failure - no rules allow this traffic
            if expectation.required:
                self.results.add_result(self._create_sg_result(
                    expectation=expectation,
                    status=TestStatus.FAIL,
                    allowed_by="No matching rules found"
                ))
            else:
                # Optional expectation not met - warning
                self.results.add_result(self._create_sg_result(
                    expectation=expectation,
                    status=TestStatus.WARNING,
                    allowed_by="No matching rules (optional)"
                ))

    def _format_rule_info(self, rule: Dict[str, Any], sg_name: str, sg_id: str, direction: str) -> str:
        """Format rule information for display"""
        protocol = rule.get('IpProtocol', 'unknown')
        from_port = rule.get('FromPort', 'any')
        to_port = rule.get('ToPort', 'any')

        if from_port == to_port and from_port != 'any':
            port_str = str(from_port)
        elif from_port != 'any':
            port_str = f"{from_port}-{to_port}"
        else:
            port_str = "all"

        # Get sources
        sources = []
        for ip_range in rule.get('IpRanges', []):
            cidr = ip_range.get('CidrIp', '')
            if cidr:
                sources.append(cidr)
        for sg_pair in rule.get('UserIdGroupPairs', []):
            sg_ref = sg_pair.get('GroupId', '')
            if sg_ref:
                sources.append(sg_ref)

        source_str = ", ".join(sources) if sources else "any"

        return f"{sg_name}({sg_id}): {protocol}/{port_str} from {source_str}"

    def _create_sg_result(self, expectation: TrafficExpectation, status: TestStatus, allowed_by: str):
        """Create a test result with security group-specific metadata"""
        from test_framework import TestResult

        return TestResult(
            description=expectation.description,
            status=status,
            details=None,  # Don't use details for passing tests
            metadata={
                'protocol': expectation.protocol,
                'direction': expectation.direction,
                'port_range': expectation.get_port_display(),
                'source_type': expectation.source_type,
                'allowed_by': allowed_by,
                'required': expectation.required
            }
        )
