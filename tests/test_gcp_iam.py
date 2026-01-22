"""
GCP IAM Configuration Tests

Validates IAM configuration for OpenShift, including:
- Workload Identity Federation (WIF) - modern approach
- Service Account Key authentication - legacy approach

Documentation:
- WIF: https://docs.redhat.com/en/documentation/openshift_container_platform/4.19/html/installing_on_gcp/index#using-gcp-workload-identity
- GCP IAM: https://docs.redhat.com/en/documentation/openshift_container_platform/4.19/html/installing_on_gcp/index#installation-gcp-permissions_installing-gcp-customizations
"""

import json
import pytest


# Mark all tests as GCP-specific
pytestmark = pytest.mark.gcp


# Required IAM roles for Service Account authentication
REQUIRED_SERVICE_ACCOUNT_ROLES = [
    "roles/compute.admin",
    "roles/iam.securityAdmin",
    "roles/iam.serviceAccountAdmin",
    "roles/iam.serviceAccountUser",
    "roles/iam.serviceAccountKeyAdmin",
    "roles/storage.admin",
    "roles/dns.admin",
]


@pytest.mark.iam
def test_iam_policy_file_exists(gcp_cluster_data):
    """IAM policy file must exist.

    Documentation: https://cloud.google.com/iam/docs/policies
    """
    iam_policy_file = gcp_cluster_data.gcp_dir / f"{gcp_cluster_data.cluster_id}_iam_policy.json"

    if not iam_policy_file.exists():
        pytest.skip(f"IAM policy file not found - run check_cluster.py {gcp_cluster_data.cluster_id} --collect --resources=iam")

    print(f"\n✓ Found IAM policy: {iam_policy_file}")


@pytest.mark.iam
def test_authentication_type_detected(gcp_cluster_data):
    """Cluster authentication type must be detected.

    OpenShift on GCP supports two authentication methods:
    - WIF (Workload Identity Federation) - recommended
    - Service Account Key - legacy

    Documentation: https://docs.redhat.com/en/documentation/openshift_container_platform/4.19/html/installing_on_gcp/index#using-gcp-workload-identity
    """
    auth_type = gcp_cluster_data.auth_type

    print(f"\n✓ Authentication Type:")
    print(f"  Type: {auth_type}")

    if auth_type == 'WIF':
        print(f"  ✓ Using Workload Identity Federation (recommended)")
    else:
        print(f"  ⚠️  Using Service Account Key (legacy method)")
        print(f"  Consider migrating to Workload Identity Federation")

    assert auth_type in ['WIF', 'ServiceAccountKey'], \
        f"Unknown authentication type: {auth_type}"


@pytest.mark.iam
@pytest.mark.wif
def test_wif_config_exists(gcp_cluster_data):
    """WIF configuration file must exist for WIF-enabled clusters.

    Documentation: https://cloud.google.com/iam/docs/workload-identity-federation
    """
    if gcp_cluster_data.auth_type != 'WIF':
        pytest.skip("Cluster does not use Workload Identity Federation")

    wif_config_file = gcp_cluster_data.gcp_dir / f"{gcp_cluster_data.cluster_id}_wif_config.json"

    if not wif_config_file.exists():
        pytest.skip(f"WIF config file not found - run check_cluster.py {gcp_cluster_data.cluster_id} --collect --resources=iam")

    print(f"\n✓ Found WIF config: {wif_config_file}")


@pytest.mark.iam
@pytest.mark.wif
def test_wif_config_valid(gcp_cluster_data):
    """WIF configuration must be valid.

    Documentation: https://cloud.google.com/iam/docs/workload-identity-federation
    """
    if gcp_cluster_data.auth_type != 'WIF':
        pytest.skip("Cluster does not use Workload Identity Federation")

    wif_config_file = gcp_cluster_data.gcp_dir / f"{gcp_cluster_data.cluster_id}_wif_config.json"

    if not wif_config_file.exists():
        pytest.skip("WIF config not found")

    with open(wif_config_file) as f:
        wif_data = json.load(f)

    print(f"\n✓ WIF Configuration:")
    print(f"  Project: {gcp_cluster_data.project_id}")
    print(f"  Workload pool: {wif_data.get('workloadIdentityPool', {}).get('poolId', 'N/A')}")
    print(f"  Provider: {wif_data.get('workloadIdentityProvider', {}).get('providerId', 'N/A')}")

    # Basic validation
    assert wif_data.get('workloadIdentityPool'), \
        "WIF configuration missing workload identity pool"
    assert wif_data.get('workloadIdentityProvider'), \
        "WIF configuration missing workload identity provider"


@pytest.mark.iam
@pytest.mark.wif
def test_wif_verification_passed(gcp_cluster_data):
    """WIF configuration must pass OCM verification.

    This test checks if 'ocm gcp verify wif-config' was run and passed.

    Documentation: https://docs.redhat.com/en/documentation/openshift_container_platform/4.19/html/installing_on_gcp/index#using-gcp-workload-identity
    """
    if gcp_cluster_data.auth_type != 'WIF':
        pytest.skip("Cluster does not use Workload Identity Federation")

    wif_verification_file = gcp_cluster_data.gcp_dir / f"{gcp_cluster_data.cluster_id}_wif_verification.json"

    if not wif_verification_file.exists():
        print(f"\n  ⚠️  WIF verification results not found")
        print(f"  Run: ocm gcp verify wif-config --wif-config=<wif-config-id> --project-id={gcp_cluster_data.project_id}")
        pytest.skip("WIF verification results not found")

    with open(wif_verification_file) as f:
        verification_data = json.load(f)

    # Check verification status
    status = verification_data.get('status', 'unknown')
    passed = (status.lower() in ['passed', 'success', 'verified'])

    print(f"\n✓ WIF Verification:")
    print(f"  Status: {status}")

    if verification_data.get('errors'):
        print(f"  Errors:")
        for error in verification_data.get('errors', []):
            print(f"    - {error}")

    assert passed, \
        f"WIF verification failed with status: {status}"


@pytest.mark.iam
def test_service_account_roles(gcp_cluster_data):
    """Service account must have required IAM roles.

    Only applicable for Service Account Key authentication (not WIF).

    Documentation: https://docs.redhat.com/en/documentation/openshift_container_platform/4.19/html/installing_on_gcp/index#installation-gcp-permissions_installing-gcp-customizations
    """
    if gcp_cluster_data.auth_type == 'WIF':
        pytest.skip("Cluster uses WIF, service account roles validation not required")

    iam_policy_file = gcp_cluster_data.gcp_dir / f"{gcp_cluster_data.cluster_id}_iam_policy.json"

    if not iam_policy_file.exists():
        pytest.skip("IAM policy not found")

    with open(iam_policy_file) as f:
        iam_data = json.load(f)

    # Extract all roles from bindings
    granted_roles = set()
    for binding in iam_data.get('bindings', []):
        granted_roles.add(binding.get('role'))

    print(f"\n✓ Service Account Roles:")
    print(f"  Total roles granted: {len(granted_roles)}")

    missing_roles = []
    for required_role in REQUIRED_SERVICE_ACCOUNT_ROLES:
        if required_role in granted_roles:
            print(f"    ✓ {required_role}")
        else:
            print(f"    ✗ {required_role} - MISSING")
            missing_roles.append(required_role)

    if missing_roles:
        print(f"\n  Missing {len(missing_roles)} required role(s)")
        print(f"\n  To grant missing roles, run:")
        for role in missing_roles:
            print(f"    gcloud projects add-iam-policy-binding {gcp_cluster_data.project_id} \\")
            print(f"      --member=serviceAccount:<service-account-email> \\")
            print(f"      --role={role}")

    assert len(missing_roles) == 0, \
        f"Service account missing {len(missing_roles)} required IAM role(s): {', '.join(missing_roles)}"


@pytest.mark.iam
def test_service_accounts_exist(gcp_cluster_data):
    """Required service accounts must exist.

    Documentation: https://cloud.google.com/iam/docs/service-accounts
    """
    service_accounts_file = gcp_cluster_data.gcp_dir / f"{gcp_cluster_data.cluster_id}_service_accounts.json"

    if not service_accounts_file.exists():
        pytest.skip("Service accounts file not found")

    with open(service_accounts_file) as f:
        sa_data = json.load(f)

    accounts = sa_data.get('accounts', [])

    print(f"\n✓ Service Accounts:")
    print(f"  Total service accounts: {len(accounts)}")

    # Look for cluster-related service accounts
    cluster_sas = []
    if gcp_cluster_data.infra_id:
        cluster_sas = [sa for sa in accounts if gcp_cluster_data.infra_id in sa.get('email', '')]

    print(f"  Cluster-related accounts: {len(cluster_sas)}")

    if cluster_sas:
        for sa in cluster_sas[:5]:  # Show first 5
            print(f"    - {sa.get('email')}")

    assert len(accounts) > 0, "No service accounts found in project"


@pytest.mark.iam
def test_iam_summary(gcp_cluster_data):
    """Summary of IAM configuration.

    Documentation: https://docs.redhat.com/en/documentation/openshift_container_platform/4.19/html/installing_on_gcp/index#installation-gcp-permissions_installing-gcp-customizations
    """
    print(f"\n✓ IAM Configuration Summary:")
    print(f"  Project: {gcp_cluster_data.project_id}")
    print(f"  Authentication type: {gcp_cluster_data.auth_type}")

    if gcp_cluster_data.auth_type == 'WIF':
        wif_config_file = gcp_cluster_data.gcp_dir / f"{gcp_cluster_data.cluster_id}_wif_config.json"
        if wif_config_file.exists():
            with open(wif_config_file) as f:
                wif_data = json.load(f)
            print(f"\n  WIF Configuration:")
            print(f"    Workload pool: {wif_data.get('workloadIdentityPool', {}).get('poolId', 'N/A')}")
            print(f"    Provider: {wif_data.get('workloadIdentityProvider', {}).get('providerId', 'N/A')}")
            print(f"    ✓ Using modern Workload Identity Federation")
        else:
            print(f"  ⚠️  WIF configuration file not found")
    else:
        iam_policy_file = gcp_cluster_data.gcp_dir / f"{gcp_cluster_data.cluster_id}_iam_policy.json"
        if iam_policy_file.exists():
            with open(iam_policy_file) as f:
                iam_data = json.load(f)
            granted_roles = set(binding.get('role') for binding in iam_data.get('bindings', []))
            print(f"\n  Service Account Configuration:")
            print(f"    IAM roles granted: {len(granted_roles)}")
            print(f"    ⚠️  Using legacy Service Account Key authentication")
        else:
            print(f"  ⚠️  IAM policy file not found")

    # This is an informational test, always passes
    assert True
