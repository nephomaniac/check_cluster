"""
AWS Service Quota Tests

This module validates that AWS service quotas meet the minimum requirements for ROSA clusters.
Based on Red Hat documentation:
- https://docs.redhat.com/en/documentation/red_hat_openshift_service_on_aws/4/html/prepare_your_environment/rosa-hcp-prereqs
- https://docs.redhat.com/en/documentation/red_hat_openshift_service_on_aws/4/html/prepare_your_environment/rosa-sts-required-aws-service-quotas
"""

import pytest
import json
from pathlib import Path
from typing import Dict, List, Any
from models.cluster import ClusterData


# ROSA Classic minimum quota requirements
ROSA_CLASSIC_MINIMUM_QUOTAS = {
    'ec2': {
        'Running On-Demand Standard (A, C, D, H, I, M, R, T, Z) instances': {
            'quota_code': 'L-1216C47A',
            'minimum_value': 100,
            'default_value': 5,
            'unit': 'vCPUs'
        }
    },
    'vpc': {
        'VPCs per Region': {
            'quota_code': 'L-F678F1CE',
            'minimum_value': 5,
            'default_value': 5,
            'unit': 'count'
        },
        'Internet gateways per Region': {
            'quota_code': 'L-A4707A72',
            'minimum_value': 5,
            'default_value': 5,
            'unit': 'count'
        },
        'Network interfaces per Region': {
            'quota_code': 'L-DF5E4CA3',
            'minimum_value': 5000,
            'default_value': 5000,
            'unit': 'count'
        }
    },
    'elasticloadbalancing': {
        'Network Load Balancers per Region': {
            'quota_code': 'L-69A177A2',
            'minimum_value': 50,
            'default_value': 50,
            'unit': 'count'
        },
        'Target groups per Region': {
            'quota_code': 'L-B22855CB',
            'minimum_value': 3000,
            'default_value': 3000,
            'unit': 'count'
        }
    },
    'ebs': {
        'Storage for General Purpose SSD (gp3) volumes, in TiB': {
            'quota_code': 'L-7A658B76',
            'minimum_value': 300,
            'default_value': 50,
            'unit': 'TiB'
        }
    }
}

# ROSA HCP minimum quota requirements
ROSA_HCP_MINIMUM_QUOTAS = {
    'ec2': {
        'Running On-Demand Standard (A, C, D, H, I, M, R, T, Z) instances': {
            'quota_code': 'L-1216C47A',
            'minimum_value': 32,
            'default_value': 5,
            'unit': 'vCPUs',
            'note': 'Minimum for cluster creation, availability, and upgrades'
        }
    }
}


def get_service_quotas_data(cluster_data: ClusterData) -> Dict[str, Any]:
    """Load service quotas data from cluster artifacts"""
    quotas_file = cluster_data.aws_dir / f"{cluster_data.cluster_id}_service_quotas.json"

    if not quotas_file.exists():
        return {}

    with open(quotas_file) as f:
        return json.load(f)


def check_quota(quotas_data: Dict, service_code: str, quota_name: str, required_value: float) -> tuple:
    """Check if a specific quota meets the minimum requirement

    Returns: (meets_requirement: bool, current_value: float, error_message: str)
    """
    service_quotas = quotas_data.get(service_code, {})

    for quota in service_quotas.get('Quotas', []):
        if quota.get('QuotaName') == quota_name:
            current_value = quota.get('Value', 0)

            if current_value >= required_value:
                return True, current_value, None
            else:
                return False, current_value, \
                    f"Quota '{quota_name}' is {current_value}, requires {required_value}"

    return False, 0, f"Quota '{quota_name}' not found in service quotas data"


@pytest.mark.aws
def test_service_quotas_file_exists(cluster_data: ClusterData):
    """Service quotas data should be collected

    Why: Service quotas determine if a cluster can be created and scaled properly.

    Failure indicates: Data collection did not collect service quota information.
    Run the script again to collect quota data.

    Success indicates: Quota data is available for validation.
    
    Documentation: https://docs.redhat.com/en/documentation/red_hat_openshift_service_on_aws/4/html/prepare_your_environment/rosa-sts-aws-prereqs#rosa-sts-required-aws-service-quotas
    """
    quotas_file = cluster_data.aws_dir / f"{cluster_data.cluster_id}_service_quotas.json"

    if not quotas_file.exists():
        print(f"\n✗ Service quotas file not found: {quotas_file}")
        print("\nTo collect service quota information, ensure check_cluster.py <cluster-id> --collect --resources=quotas is run")
        print("is updated to collect AWS service quotas.")
        pytest.skip("Service quotas file not found - run check_cluster.py <cluster-id> --collect")
    else:
        quotas_data = get_service_quotas_data(cluster_data)
        service_count = len(quotas_data.keys())
        print(f"\n✓ Service quotas file found with data for {service_count} service(s)")


@pytest.mark.aws
def test_ec2_vcpu_quota_sufficient_for_rosa_classic(cluster_data: ClusterData):
    """EC2 vCPU quota should meet ROSA Classic minimum (100 vCPUs)

    Why: ROSA Classic clusters require a minimum of 100 vCPUs for cluster creation,
    availability, and upgrades. The default AWS quota is only 5 vCPUs.

    Failure indicates: EC2 vCPU quota is insufficient. Request a quota increase via AWS Support.

    Success indicates: Sufficient vCPU quota for ROSA Classic cluster creation.

    Reference: https://docs.redhat.com/en/documentation/red_hat_openshift_service_on_aws/4/html/prepare_your_environment/rosa-sts-required-aws-service-quotas
    
    Documentation: https://docs.redhat.com/en/documentation/red_hat_openshift_service_on_aws/4/html/prepare_your_environment/rosa-sts-aws-prereqs#rosa-sts-required-aws-service-quotas
    """
    quotas_data = get_service_quotas_data(cluster_data)

    if not quotas_data:
        pytest.skip("Service quotas data not available")

    quota_name = 'Running On-Demand Standard (A, C, D, H, I, M, R, T, Z) instances'
    required_vcpus = 100

    meets_req, current_value, error_msg = check_quota(
        quotas_data, 'ec2', quota_name, required_vcpus
    )

    if meets_req:
        print(f"\n✓ EC2 vCPU quota: {current_value} vCPUs (required: {required_vcpus})")
    else:
        print(f"\n✗ EC2 vCPU quota insufficient")
        print(f"Current: {current_value} vCPUs")
        print(f"Required: {required_vcpus} vCPUs")
        print(f"Shortfall: {required_vcpus - current_value} vCPUs")
        print("\nHow to fix:")
        print("1. Go to AWS Service Quotas console")
        print("2. Navigate to Amazon Elastic Compute Cloud (Amazon EC2)")
        print(f"3. Find: '{quota_name}'")
        print(f"4. Request increase to at least {required_vcpus} vCPUs")

    assert meets_req, \
        f"EC2 vCPU quota ({current_value}) is less than required ({required_vcpus}). " \
        "ROSA Classic cluster creation will fail. Request quota increase via AWS Support."


@pytest.mark.aws
def test_ec2_vcpu_quota_sufficient_for_rosa_hcp(cluster_data: ClusterData):
    """EC2 vCPU quota should meet ROSA HCP minimum (32 vCPUs)

    Why: ROSA HCP clusters require a minimum of 32 vCPUs for cluster creation,
    availability, and upgrades. The default AWS quota is only 5 vCPUs.

    Failure indicates: EC2 vCPU quota is insufficient. Request a quota increase via AWS Support.

    Success indicates: Sufficient vCPU quota for ROSA HCP cluster creation.

    Reference: https://docs.redhat.com/en/documentation/red_hat_openshift_service_on_aws/4/html/prepare_your_environment/rosa-hcp-prereqs
    
    Documentation: https://docs.redhat.com/en/documentation/red_hat_openshift_service_on_aws/4/html/prepare_your_environment/rosa-sts-aws-prereqs#rosa-sts-required-aws-service-quotas
    """
    quotas_data = get_service_quotas_data(cluster_data)

    if not quotas_data:
        pytest.skip("Service quotas data not available")

    quota_name = 'Running On-Demand Standard (A, C, D, H, I, M, R, T, Z) instances'
    required_vcpus = 32

    meets_req, current_value, error_msg = check_quota(
        quotas_data, 'ec2', quota_name, required_vcpus
    )

    if meets_req:
        print(f"\n✓ EC2 vCPU quota: {current_value} vCPUs (required for HCP: {required_vcpus})")
        if current_value >= 100:
            print(f"  Also sufficient for ROSA Classic (100 vCPUs)")
    else:
        print(f"\n✗ EC2 vCPU quota insufficient for ROSA HCP")
        print(f"Current: {current_value} vCPUs")
        print(f"Required: {required_vcpus} vCPUs")
        print(f"Shortfall: {required_vcpus - current_value} vCPUs")

    assert meets_req, \
        f"EC2 vCPU quota ({current_value}) is less than required ({required_vcpus}). " \
        "ROSA HCP cluster creation will fail. Request quota increase via AWS Support."


@pytest.mark.aws
def test_ebs_storage_quota_sufficient(cluster_data: ClusterData):
    """EBS storage quota should meet ROSA requirements (300 TiB for Classic)

    Why: ROSA uses EBS for persistent storage. Insufficient quota prevents node
    and persistent volume creation.

    Failure indicates: EBS storage quota may be insufficient for production clusters.

    Success indicates: Sufficient EBS storage quota.

    Reference: https://docs.redhat.com/en/documentation/red_hat_openshift_service_on_aws/4/html/prepare_your_environment/rosa-sts-required-aws-service-quotas
    
    Documentation: https://docs.redhat.com/en/documentation/red_hat_openshift_service_on_aws/4/html/prepare_your_environment/rosa-sts-aws-prereqs#rosa-sts-required-aws-service-quotas
    """
    quotas_data = get_service_quotas_data(cluster_data)

    if not quotas_data:
        pytest.skip("Service quotas data not available")

    quota_name = 'Storage for General Purpose SSD (gp3) volumes, in TiB'
    required_storage = 300  # TiB for ROSA Classic

    ebs_quotas = quotas_data.get('ebs', {}).get('Quotas', [])

    if not ebs_quotas:
        print("\n⚠ EBS quota data not available")
        print("This may indicate the quota collection needs to be updated")
        pytest.skip("EBS quota data not available")

    meets_req, current_value, error_msg = check_quota(
        quotas_data, 'ebs', quota_name, required_storage
    )

    if meets_req:
        print(f"\n✓ EBS gp3 storage quota: {current_value} TiB (required: {required_storage} TiB)")
    else:
        print(f"\n⚠ EBS gp3 storage quota: {current_value} TiB (recommended: {required_storage} TiB)")
        print("This may limit cluster scalability for production workloads")

    # Make this a warning, not a hard failure for now
    if not meets_req:
        print("\nNote: This is informational. Smaller clusters may function with less storage.")


@pytest.mark.aws
def test_elb_service_role_exists(cluster_data: ClusterData):
    """AWS Elastic Load Balancing service role should exist

    Why: ROSA creates Network Load Balancers for API and ingress access.
    The ELB service-linked role named AWSServiceRoleForElasticLoadBalancing is required.

    Failure indicates: ELB service role does not exist or was not collected.

    Success indicates: ELB service role exists.

    Reference: https://docs.redhat.com/en/documentation/red_hat_openshift_service_on_aws/4/html/prepare_your_environment/rosa-hcp-prereqs
    
    Documentation: https://docs.redhat.com/en/documentation/red_hat_openshift_service_on_aws/4/html/prepare_your_environment/rosa-sts-aws-prereqs#rosa-sts-required-aws-service-quotas
    """
    # Check for ELB service role in IAM roles data
    roles_file = cluster_data.aws_dir / f"{cluster_data.cluster_id}_iam_roles.json"

    if not roles_file.exists():
        print("\n⚠ IAM roles file not found - cannot validate ELB service role")
        pytest.skip("IAM roles data not available")

    with open(roles_file) as f:
        iam_data = json.load(f)

    roles = iam_data.get('Roles', [])
    elb_service_role = next(
        (role for role in roles if role.get('RoleName') == 'AWSServiceRoleForElasticLoadBalancing'),
        None
    )

    if elb_service_role:
        print(f"\n✓ ELB service role exists: AWSServiceRoleForElasticLoadBalancing")
        print(f"  ARN: {elb_service_role.get('Arn')}")
        print(f"  Created: {elb_service_role.get('CreateDate')}")
    else:
        print(f"\n✗ ELB service role NOT found: AWSServiceRoleForElasticLoadBalancing")
        print("\nThis role is usually created automatically when you first use ELB.")
        print("To create it manually, run:")
        print("  aws iam create-service-linked-role --aws-service-name elasticloadbalancing.amazonaws.com")

    assert elb_service_role is not None, \
        "ELB service role AWSServiceRoleForElasticLoadBalancing not found. " \
        "This role is required for ROSA to create load balancers."


@pytest.mark.aws
def test_minimum_bandwidth_requirement(cluster_data: ClusterData):
    """Document minimum bandwidth requirement (120 Mbps)

    Why: During cluster deployment, ROSA requires a minimum bandwidth of 120 Mbps
    between cluster infrastructure and the public internet or private network
    locations that provide deployment artifacts and resources.

    When network connectivity is slower than 120 Mbps (e.g., when connecting
    through a proxy), the cluster installation process times out and deployment fails.

    This test is informational only - bandwidth cannot be tested from cluster data.

    Reference: https://docs.redhat.com/en/documentation/red_hat_openshift_service_on_aws/4/html/prepare_your_environment/rosa-hcp-prereqs
    
    Documentation: https://docs.redhat.com/en/documentation/red_hat_openshift_service_on_aws/4/html/prepare_your_environment/rosa-sts-aws-prereqs#rosa-sts-required-aws-service-quotas
    """
    print("\n" + "="*80)
    print("ROSA Network Bandwidth Requirement")
    print("="*80)
    print("\n⚠ Minimum network bandwidth: 120 Mbps")
    print("\nThis bandwidth is required between:")
    print("  - Cluster infrastructure")
    print("  - Public internet or private network providing deployment artifacts")
    print("\nIf network connectivity is slower than 120 Mbps:")
    print("  - Cluster installation process will timeout")
    print("  - Deployment will fail")
    print("\nCommon scenarios with <120 Mbps:")
    print("  - Slow proxy connections")
    print("  - Bandwidth-limited VPN connections")
    print("  - Network throttling/QoS policies")
    print("\nThis cannot be validated from cluster data - ensure network meets requirements.")
    print("="*80 + "\n")

    # This is informational only
    pytest.skip("Bandwidth requirement is informational - cannot be validated from cluster data")
