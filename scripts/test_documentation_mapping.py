"""
Documentation URL mapping for all ROSA cluster health check tests.

Maps test categories to their relevant Red Hat OpenShift/ROSA documentation,
AWS documentation, and GitHub source code references.
"""

DOCUMENTATION_MAPPING = {
    # IAM and AWS Resources
    "iam": "https://docs.redhat.com/en/documentation/red_hat_openshift_service_on_aws/4/html/prepare_your_environment/rosa-sts-aws-prereqs#rosa-sts-overview-of-the-deployment-workflow",
    "iam_permissions": "https://docs.redhat.com/en/documentation/red_hat_openshift_service_on_aws/4/html/prepare_your_environment/rosa-sts-aws-prereqs#rosa-sts-required-aws-service-quotas",
    "iam_permission_validation": "https://docs.redhat.com/en/documentation/red_hat_openshift_service_on_aws/4/html/prepare_your_environment/rosa-sts-aws-prereqs#rosa-sts-required-aws-iam-permissions",
    "rosa_iam_resources": "https://docs.aws.amazon.com/rosa/latest/userguide/security-iam-awsmanpol.html",
    "rosa_installer_role": "https://docs.aws.amazon.com/rosa/latest/userguide/security-iam-awsmanpol.html",
    "rosa_operator_roles": "https://docs.redhat.com/en/documentation/red_hat_openshift_service_on_aws/4/html/prepare_your_environment/rosa-sts-aws-prereqs#rosa-sts-understanding-aws-account-association",
    "rosa_worker_role": "https://docs.aws.amazon.com/rosa/latest/userguide/security-iam-awsmanpol.html",
    "aws_resources": "https://docs.redhat.com/en/documentation/red_hat_openshift_service_on_aws/4/html/prepare_your_environment/rosa-sts-aws-prereqs",
    "aws_prerequisites": "https://docs.redhat.com/en/documentation/red_hat_openshift_service_on_aws/4/html/prepare_your_environment/rosa-sts-aws-prereqs",
    "aws_service_quotas": "https://docs.redhat.com/en/documentation/red_hat_openshift_service_on_aws/4/html/prepare_your_environment/rosa-sts-aws-prereqs#rosa-sts-required-aws-service-quotas",

    # VPC and Networking
    "vpc": "https://docs.redhat.com/en/documentation/red_hat_openshift_service_on_aws/4/html/prepare_your_environment/rosa-sts-aws-prereqs#rosa-vpc-requirements",
    "byo_vpc": "https://docs.redhat.com/en/documentation/red_hat_openshift_service_on_aws/4/html/prepare_your_environment/rosa-sts-aws-prereqs#rosa-vpc-requirements",
    "vpc_endpoints": "https://docs.redhat.com/en/documentation/red_hat_openshift_service_on_aws/4/html/prepare_your_environment/rosa-sts-aws-prereqs#rosa-privatelink-aws-vpc-requirements",
    "network": "https://docs.redhat.com/en/documentation/red_hat_openshift_service_on_aws/4/html/prepare_your_environment/rosa-sts-aws-prereqs#rosa-vpc-requirements",
    "privatelink": "https://docs.redhat.com/en/documentation/red_hat_openshift_service_on_aws/4/html/architecture/rosa-architecture-models#rosa-architecture-privatelink",

    # Security Groups
    "security_groups": "https://docs.redhat.com/en/documentation/red_hat_openshift_service_on_aws/4/html/prepare_your_environment/rosa-sts-aws-prereqs#rosa-security-groups",
    "security_groups_detailed": "https://docs.redhat.com/en/documentation/red_hat_openshift_service_on_aws/4/html/prepare_your_environment/rosa-sts-aws-prereqs#rosa-security-groups",

    # EC2 and Compute
    "instances": "https://docs.redhat.com/en/documentation/red_hat_openshift_service_on_aws/4/html/prepare_your_environment/rosa-sts-aws-prereqs#rosa-ec2-instances",
    "autoscaling": "https://docs.redhat.com/en/documentation/red_hat_openshift_service_on_aws/4/html/cluster_administration/rosa-nodes-machinepools-about",

    # Load Balancers
    "load_balancers": "https://docs.redhat.com/en/documentation/red_hat_openshift_service_on_aws/4/html/networking/load-balancers",
    "load_balancer_target_health": "https://docs.aws.amazon.com/elasticloadbalancing/latest/network/target-group-health-checks.html",

    # Storage
    "storage": "https://docs.redhat.com/en/documentation/red_hat_openshift_service_on_aws/4/html/storage",

    # Route53
    "route53": "https://docs.redhat.com/en/documentation/red_hat_openshift_service_on_aws/4/html/prepare_your_environment/rosa-sts-aws-prereqs#rosa-dns-requirements",

    # CloudTrail
    "cloudtrail": "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-user-guide.html",

    # Installation
    "installation": "https://docs.redhat.com/en/documentation/red_hat_openshift_service_on_aws/4/html/install_rosa_classic_clusters/rosa-sts-creating-a-cluster-quickly",
    "installation_diagnostics": "https://docs.redhat.com/en/documentation/red_hat_openshift_service_on_aws/4/html/troubleshooting/rosa-troubleshooting-installations",
    "openshift_installation_progress": "https://docs.openshift.com/container-platform/latest/installing/index.html#installation-process",
}

# Specific test function overrides (when a test needs a more specific doc link)
TEST_SPECIFIC_DOCS = {
    # VPC tests
    "test_vpc_dns_hostnames_enabled": "https://docs.aws.amazon.com/vpc/latest/userguide/vpc-dns.html#vpc-dns-hostnames",
    "test_vpc_dns_support_enabled": "https://docs.aws.amazon.com/vpc/latest/userguide/vpc-dns.html#vpc-dns-support",
    "test_vpc_cidr_block_configured": "https://docs.aws.amazon.com/vpc/latest/userguide/configure-your-vpc.html#vpc-cidr-blocks",

    # Security Group tests
    "test_api_server_access": "https://docs.redhat.com/en/documentation/red_hat_openshift_service_on_aws/4/html/prepare_your_environment/rosa-sts-aws-prereqs#rosa-security-groups",
    "test_machine_config_server_access": "https://docs.openshift.com/container-platform/latest/architecture/control-plane.html#architecture-machine-config-operator_control-plane",
    "test_worker_kubelet_access": "https://kubernetes.io/docs/reference/command-line-tools-reference/kubelet/",
    "test_worker_vxlan_overlay": "https://docs.openshift.com/container-platform/latest/networking/ovn_kubernetes_network_provider/about-ovn-kubernetes.html",
    "test_worker_geneve_overlay": "https://docs.openshift.com/container-platform/latest/networking/ovn_kubernetes_network_provider/about-ovn-kubernetes.html",

    # Installation tests
    "test_bootstrap_detailed_analysis": "https://docs.openshift.com/container-platform/latest/installing/index.html#installation-process",

    # PrivateLink tests
    "test_vpc_endpoints_exist": "https://docs.redhat.com/en/documentation/red_hat_openshift_service_on_aws/4/html/prepare_your_environment/rosa-sts-aws-prereqs#rosa-privatelink-aws-vpc-requirements",

    # IAM tests
    "test_installer_role_exists": "https://docs.aws.amazon.com/rosa/latest/userguide/security-iam-awsmanpol.html",
    "test_worker_role_exists": "https://docs.aws.amazon.com/rosa/latest/userguide/security-iam-awsmanpol.html",
}


def get_documentation_url(test_file: str, test_function: str) -> str:
    """
    Get the appropriate documentation URL for a test.

    Args:
        test_file: Test file name (e.g., "test_vpc.py")
        test_function: Test function name (e.g., "test_vpc_dns_hostnames_enabled")

    Returns:
        Documentation URL string
    """
    # Check for test-specific override first
    if test_function in TEST_SPECIFIC_DOCS:
        return TEST_SPECIFIC_DOCS[test_function]

    # Get category from file name
    category = test_file.replace("test_", "").replace(".py", "")

    # Return category documentation
    return DOCUMENTATION_MAPPING.get(category, "https://docs.redhat.com/en/documentation/red_hat_openshift_service_on_aws/4")
