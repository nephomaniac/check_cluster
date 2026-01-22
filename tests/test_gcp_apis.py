"""
GCP API Enablement Tests

Validates that required GCP APIs are enabled for OpenShift cluster installation.

Documentation:
- GCP APIs: https://cloud.google.com/apis/docs/getting-started
- OpenShift on GCP: https://docs.redhat.com/en/documentation/openshift_container_platform/4.19/html/installing_on_gcp/index
"""

import json
import pytest


# Mark all tests as GCP-specific
pytestmark = pytest.mark.gcp


REQUIRED_APIS = [
    "compute.googleapis.com",
    "cloudapis.googleapis.com",
    "cloudresourcemanager.googleapis.com",
    "dns.googleapis.com",
    "iamcredentials.googleapis.com",
    "iam.googleapis.com",
    "servicemanagement.googleapis.com",
    "serviceusage.googleapis.com",
    "storage-api.googleapis.com",
    "storage-component.googleapis.com",
]


@pytest.mark.apis
def test_enabled_apis_file_exists(gcp_cluster_data):
    """Enabled APIs file must exist.

    Documentation: https://cloud.google.com/service-usage/docs/list-services
    """
    apis_file = gcp_cluster_data.gcp_dir / f"{gcp_cluster_data.cluster_id}_enabled_apis.json"

    if not apis_file.exists():
        pytest.skip(f"Enabled APIs file not found - run check_cluster.py {gcp_cluster_data.cluster_id} --collect --resources=apis")

    print(f"\n✓ Found enabled APIs file: {apis_file}")


@pytest.mark.apis
def test_compute_api_enabled(gcp_cluster_data):
    """Compute Engine API must be enabled.

    Required for creating VMs, disks, and network resources.

    Documentation: https://cloud.google.com/compute/docs/api/libraries
    """
    apis_file = gcp_cluster_data.gcp_dir / f"{gcp_cluster_data.cluster_id}_enabled_apis.json"

    if not apis_file.exists():
        pytest.skip("Enabled APIs file not found")

    with open(apis_file) as f:
        apis_data = json.load(f)

    # APIs can be returned in different formats from gcloud
    enabled_apis = []
    if isinstance(apis_data, list):
        enabled_apis = [api.get('name', '') if isinstance(api, dict) else str(api) for api in apis_data]
    elif isinstance(apis_data, dict) and 'services' in apis_data:
        enabled_apis = [api.get('name', '') if isinstance(api, dict) else str(api) for api in apis_data['services']]

    # Check if compute API is enabled (handle different response formats)
    api_enabled = any('compute.googleapis.com' in api for api in enabled_apis)

    print(f"\n✓ Compute Engine API: {'Enabled' if api_enabled else 'DISABLED'}")

    assert api_enabled, \
        "Compute Engine API (compute.googleapis.com) is not enabled. Enable it with: gcloud services enable compute.googleapis.com"


@pytest.mark.apis
def test_cloudapis_enabled(gcp_cluster_data):
    """Cloud APIs must be enabled.

    Required for Google Cloud APIs infrastructure.

    Documentation: https://cloud.google.com/apis/docs/getting-started
    """
    apis_file = gcp_cluster_data.gcp_dir / f"{gcp_cluster_data.cluster_id}_enabled_apis.json"

    if not apis_file.exists():
        pytest.skip("Enabled APIs file not found")

    with open(apis_file) as f:
        apis_data = json.load(f)

    enabled_apis = []
    if isinstance(apis_data, list):
        enabled_apis = [api.get('name', '') if isinstance(api, dict) else str(api) for api in apis_data]
    elif isinstance(apis_data, dict) and 'services' in apis_data:
        enabled_apis = [api.get('name', '') if isinstance(api, dict) else str(api) for api in apis_data['services']]

    api_enabled = any('cloudapis.googleapis.com' in api for api in enabled_apis)

    print(f"\n✓ Cloud APIs: {'Enabled' if api_enabled else 'DISABLED'}")

    assert api_enabled, \
        "Cloud APIs (cloudapis.googleapis.com) is not enabled. Enable it with: gcloud services enable cloudapis.googleapis.com"


@pytest.mark.apis
def test_cloudresourcemanager_api_enabled(gcp_cluster_data):
    """Cloud Resource Manager API must be enabled.

    Required for managing GCP projects and resources.

    Documentation: https://cloud.google.com/resource-manager/docs/apis
    """
    apis_file = gcp_cluster_data.gcp_dir / f"{gcp_cluster_data.cluster_id}_enabled_apis.json"

    if not apis_file.exists():
        pytest.skip("Enabled APIs file not found")

    with open(apis_file) as f:
        apis_data = json.load(f)

    enabled_apis = []
    if isinstance(apis_data, list):
        enabled_apis = [api.get('name', '') if isinstance(api, dict) else str(api) for api in apis_data]
    elif isinstance(apis_data, dict) and 'services' in apis_data:
        enabled_apis = [api.get('name', '') if isinstance(api, dict) else str(api) for api in apis_data['services']]

    api_enabled = any('cloudresourcemanager.googleapis.com' in api for api in enabled_apis)

    print(f"\n✓ Cloud Resource Manager API: {'Enabled' if api_enabled else 'DISABLED'}")

    assert api_enabled, \
        "Cloud Resource Manager API is not enabled. Enable it with: gcloud services enable cloudresourcemanager.googleapis.com"


@pytest.mark.apis
def test_dns_api_enabled(gcp_cluster_data):
    """Cloud DNS API must be enabled.

    Required for creating and managing DNS zones and records.

    Documentation: https://cloud.google.com/dns/docs
    """
    apis_file = gcp_cluster_data.gcp_dir / f"{gcp_cluster_data.cluster_id}_enabled_apis.json"

    if not apis_file.exists():
        pytest.skip("Enabled APIs file not found")

    with open(apis_file) as f:
        apis_data = json.load(f)

    enabled_apis = []
    if isinstance(apis_data, list):
        enabled_apis = [api.get('name', '') if isinstance(api, dict) else str(api) for api in apis_data]
    elif isinstance(apis_data, dict) and 'services' in apis_data:
        enabled_apis = [api.get('name', '') if isinstance(api, dict) else str(api) for api in apis_data['services']]

    api_enabled = any('dns.googleapis.com' in api for api in enabled_apis)

    print(f"\n✓ Cloud DNS API: {'Enabled' if api_enabled else 'DISABLED'}")

    assert api_enabled, \
        "Cloud DNS API (dns.googleapis.com) is not enabled. Enable it with: gcloud services enable dns.googleapis.com"


@pytest.mark.apis
def test_iam_credentials_api_enabled(gcp_cluster_data):
    """IAM Credentials API must be enabled.

    Required for Workload Identity Federation (WIF) authentication.

    Documentation: https://cloud.google.com/iam/docs/reference/credentials/rest
    """
    apis_file = gcp_cluster_data.gcp_dir / f"{gcp_cluster_data.cluster_id}_enabled_apis.json"

    if not apis_file.exists():
        pytest.skip("Enabled APIs file not found")

    with open(apis_file) as f:
        apis_data = json.load(f)

    enabled_apis = []
    if isinstance(apis_data, list):
        enabled_apis = [api.get('name', '') if isinstance(api, dict) else str(api) for api in apis_data]
    elif isinstance(apis_data, dict) and 'services' in apis_data:
        enabled_apis = [api.get('name', '') if isinstance(api, dict) else str(api) for api in apis_data['services']]

    api_enabled = any('iamcredentials.googleapis.com' in api for api in enabled_apis)

    print(f"\n✓ IAM Credentials API: {'Enabled' if api_enabled else 'DISABLED'}")

    assert api_enabled, \
        "IAM Credentials API is not enabled. Enable it with: gcloud services enable iamcredentials.googleapis.com"


@pytest.mark.apis
def test_iam_api_enabled(gcp_cluster_data):
    """IAM API must be enabled.

    Required for managing service accounts and IAM policies.

    Documentation: https://cloud.google.com/iam/docs/reference/rest
    """
    apis_file = gcp_cluster_data.gcp_dir / f"{gcp_cluster_data.cluster_id}_enabled_apis.json"

    if not apis_file.exists():
        pytest.skip("Enabled APIs file not found")

    with open(apis_file) as f:
        apis_data = json.load(f)

    enabled_apis = []
    if isinstance(apis_data, list):
        enabled_apis = [api.get('name', '') if isinstance(api, dict) else str(api) for api in apis_data]
    elif isinstance(apis_data, dict) and 'services' in apis_data:
        enabled_apis = [api.get('name', '') if isinstance(api, dict) else str(api) for api in apis_data['services']]

    api_enabled = any('iam.googleapis.com' in api for api in enabled_apis)

    print(f"\n✓ IAM API: {'Enabled' if api_enabled else 'DISABLED'}")

    assert api_enabled, \
        "IAM API (iam.googleapis.com) is not enabled. Enable it with: gcloud services enable iam.googleapis.com"


@pytest.mark.apis
def test_servicemanagement_api_enabled(gcp_cluster_data):
    """Service Management API must be enabled.

    Required for managing Google Cloud services.

    Documentation: https://cloud.google.com/service-infrastructure/docs/service-management/reference/rest
    """
    apis_file = gcp_cluster_data.gcp_dir / f"{gcp_cluster_data.cluster_id}_enabled_apis.json"

    if not apis_file.exists():
        pytest.skip("Enabled APIs file not found")

    with open(apis_file) as f:
        apis_data = json.load(f)

    enabled_apis = []
    if isinstance(apis_data, list):
        enabled_apis = [api.get('name', '') if isinstance(api, dict) else str(api) for api in apis_data]
    elif isinstance(apis_data, dict) and 'services' in apis_data:
        enabled_apis = [api.get('name', '') if isinstance(api, dict) else str(api) for api in apis_data['services']]

    api_enabled = any('servicemanagement.googleapis.com' in api for api in enabled_apis)

    print(f"\n✓ Service Management API: {'Enabled' if api_enabled else 'DISABLED'}")

    assert api_enabled, \
        "Service Management API is not enabled. Enable it with: gcloud services enable servicemanagement.googleapis.com"


@pytest.mark.apis
def test_serviceusage_api_enabled(gcp_cluster_data):
    """Service Usage API must be enabled.

    Required for listing and managing enabled services.

    Documentation: https://cloud.google.com/service-usage/docs
    """
    apis_file = gcp_cluster_data.gcp_dir / f"{gcp_cluster_data.cluster_id}_enabled_apis.json"

    if not apis_file.exists():
        pytest.skip("Enabled APIs file not found")

    with open(apis_file) as f:
        apis_data = json.load(f)

    enabled_apis = []
    if isinstance(apis_data, list):
        enabled_apis = [api.get('name', '') if isinstance(api, dict) else str(api) for api in apis_data]
    elif isinstance(apis_data, dict) and 'services' in apis_data:
        enabled_apis = [api.get('name', '') if isinstance(api, dict) else str(api) for api in apis_data['services']]

    api_enabled = any('serviceusage.googleapis.com' in api for api in enabled_apis)

    print(f"\n✓ Service Usage API: {'Enabled' if api_enabled else 'DISABLED'}")

    assert api_enabled, \
        "Service Usage API is not enabled. Enable it with: gcloud services enable serviceusage.googleapis.com"


@pytest.mark.apis
def test_storage_api_enabled(gcp_cluster_data):
    """Cloud Storage API must be enabled.

    Required for creating and managing storage buckets.

    Documentation: https://cloud.google.com/storage/docs/apis
    """
    apis_file = gcp_cluster_data.gcp_dir / f"{gcp_cluster_data.cluster_id}_enabled_apis.json"

    if not apis_file.exists():
        pytest.skip("Enabled APIs file not found")

    with open(apis_file) as f:
        apis_data = json.load(f)

    enabled_apis = []
    if isinstance(apis_data, list):
        enabled_apis = [api.get('name', '') if isinstance(api, dict) else str(api) for api in apis_data]
    elif isinstance(apis_data, dict) and 'services' in apis_data:
        enabled_apis = [api.get('name', '') if isinstance(api, dict) else str(api) for api in apis_data['services']]

    api_enabled = any('storage-api.googleapis.com' in api for api in enabled_apis)

    print(f"\n✓ Storage API: {'Enabled' if api_enabled else 'DISABLED'}")

    assert api_enabled, \
        "Storage API (storage-api.googleapis.com) is not enabled. Enable it with: gcloud services enable storage-api.googleapis.com"


@pytest.mark.apis
def test_all_required_apis_enabled(gcp_cluster_data):
    """All required GCP APIs must be enabled for OpenShift installation.

    Documentation: https://docs.redhat.com/en/documentation/openshift_container_platform/4.19/html/installing_on_gcp/index
    """
    apis_file = gcp_cluster_data.gcp_dir / f"{gcp_cluster_data.cluster_id}_enabled_apis.json"

    if not apis_file.exists():
        pytest.skip("Enabled APIs file not found")

    with open(apis_file) as f:
        apis_data = json.load(f)

    enabled_apis = []
    if isinstance(apis_data, list):
        enabled_apis = [api.get('name', '') if isinstance(api, dict) else str(api) for api in apis_data]
    elif isinstance(apis_data, dict) and 'services' in apis_data:
        enabled_apis = [api.get('name', '') if isinstance(api, dict) else str(api) for api in apis_data['services']]

    # Convert to set for easier comparison
    enabled_apis_set = set(enabled_apis)

    missing_apis = []
    for required_api in REQUIRED_APIS:
        if not any(required_api in api for api in enabled_apis):
            missing_apis.append(required_api)

    print(f"\n✓ API Status:")
    print(f"  Required: {len(REQUIRED_APIS)}")
    print(f"  Enabled: {len(REQUIRED_APIS) - len(missing_apis)}")

    if missing_apis:
        print(f"  Missing: {len(missing_apis)}")
        print(f"\n  Missing APIs:")
        for api in missing_apis:
            print(f"    - {api}")
        print(f"\n  To enable missing APIs:")
        print(f"    gcloud services enable {' '.join(missing_apis)}")

    assert len(missing_apis) == 0, \
        f"{len(missing_apis)} required API(s) not enabled: {', '.join(missing_apis)}"
