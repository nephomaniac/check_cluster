"""
GCP RHCOS Image Tests

Validates Red Hat CoreOS (RHCOS) images for OpenShift installation.

Documentation:
- RHCOS Images: https://docs.redhat.com/en/documentation/openshift_container_platform/4.19/html/installing_on_gcp/index
- GCP Images: https://cloud.google.com/compute/docs/images
"""

import json
import pytest


# Mark all tests as GCP-specific
pytestmark = pytest.mark.gcp


@pytest.mark.storage
def test_images_file_exists(gcp_cluster_data):
    """Images file must exist.

    Documentation: https://cloud.google.com/compute/docs/images
    """
    images_file = gcp_cluster_data.gcp_dir / f"{gcp_cluster_data.cluster_id}_images.json"

    if not images_file.exists():
        pytest.skip(f"Images file not found - run check_cluster.py {gcp_cluster_data.cluster_id} --collect --resources=storage")

    print(f"\n✓ Found images: {images_file}")


@pytest.mark.storage
def test_rhcos_images_available(gcp_cluster_data):
    """RHCOS images must be available or will be imported by installer.

    The OpenShift installer can import RHCOS images if not already present.

    Documentation: https://docs.redhat.com/en/documentation/openshift_container_platform/4.19/html/installing_on_gcp/index
    """
    images_file = gcp_cluster_data.gcp_dir / f"{gcp_cluster_data.cluster_id}_images.json"

    if not images_file.exists():
        pytest.skip("Images file not found")

    with open(images_file) as f:
        images_data = json.load(f)

    # Look for RHCOS images (usually contain 'rhcos' in name)
    rhcos_images = []
    for image in images_data:
        name = image.get('name', '').lower()
        if 'rhcos' in name or 'coreos' in name:
            rhcos_images.append(image)

    print(f"\n✓ RHCOS Images:")
    print(f"  Found: {len(rhcos_images)}")

    if rhcos_images:
        print(f"  Images:")
        for image in rhcos_images[:5]:  # Show first 5
            print(f"    - {image.get('name')}")
            print(f"      Status: {image.get('status', 'UNKNOWN')}")
            print(f"      Family: {image.get('family', 'N/A')}")
            print(f"      Disk size: {image.get('diskSizeGb', 'N/A')}GB")
    else:
        print(f"\n  ℹ️  No RHCOS images found in project")
        print(f"  This is normal - OpenShift installer will import RHCOS images during installation")


@pytest.mark.storage
def test_rhcos_image_status(gcp_cluster_data):
    """RHCOS images should be ready (if present).

    Documentation: https://cloud.google.com/compute/docs/images/image-management-best-practices
    """
    images_file = gcp_cluster_data.gcp_dir / f"{gcp_cluster_data.cluster_id}_images.json"

    if not images_file.exists():
        pytest.skip("Images file not found")

    with open(images_file) as f:
        images_data = json.load(f)

    # Look for RHCOS images
    rhcos_images = []
    for image in images_data:
        name = image.get('name', '').lower()
        if 'rhcos' in name or 'coreos' in name:
            rhcos_images.append(image)

    if not rhcos_images:
        pytest.skip("No RHCOS images found (installer will import during installation)")

    print(f"\n✓ RHCOS Image Status:")

    not_ready = []
    for image in rhcos_images:
        status = image.get('status', 'UNKNOWN')
        print(f"  {image.get('name')}: {status}")

        if status != 'READY':
            not_ready.append(image.get('name'))

    if not_ready:
        print(f"\n  ⚠️  {len(not_ready)} image(s) not ready:")
        for img in not_ready:
            print(f"    - {img}")

    # Only fail if images exist but are not ready
    assert len(not_ready) == 0, \
        f"{len(not_ready)} RHCOS image(s) not ready: {', '.join(not_ready)}"


@pytest.mark.storage
def test_cluster_specific_rhcos_images(gcp_cluster_data):
    """Check for cluster-specific RHCOS images.

    During installation, the installer creates cluster-specific image copies.

    Documentation: https://docs.redhat.com/en/documentation/openshift_container_platform/4.19/html/installing_on_gcp/index
    """
    images_file = gcp_cluster_data.gcp_dir / f"{gcp_cluster_data.cluster_id}_images.json"

    if not images_file.exists():
        pytest.skip("Images file not found")

    with open(images_file) as f:
        images_data = json.load(f)

    # Look for images with cluster infra_id
    cluster_images = []
    if gcp_cluster_data.infra_id:
        for image in images_data:
            name = image.get('name', '')
            if gcp_cluster_data.infra_id in name:
                cluster_images.append(image)

    print(f"\n✓ Cluster-Specific Images:")
    print(f"  Found: {len(cluster_images)}")

    if cluster_images:
        for image in cluster_images:
            print(f"    - {image.get('name')}")
            print(f"      Status: {image.get('status', 'UNKNOWN')}")
    else:
        print(f"  ℹ️  No cluster-specific images found")
        print(f"  This is normal for pre-installation validation")


@pytest.mark.storage
def test_images_summary(gcp_cluster_data):
    """Summary of images configuration.

    Documentation: https://cloud.google.com/compute/docs/images
    """
    images_file = gcp_cluster_data.gcp_dir / f"{gcp_cluster_data.cluster_id}_images.json"

    if not images_file.exists():
        pytest.skip("Images file not found")

    with open(images_file) as f:
        images_data = json.load(f)

    # Count RHCOS images
    rhcos_images = [img for img in images_data if 'rhcos' in img.get('name', '').lower() or 'coreos' in img.get('name', '').lower()]

    # Count cluster-specific images
    cluster_images = []
    if gcp_cluster_data.infra_id:
        cluster_images = [img for img in images_data if gcp_cluster_data.infra_id in img.get('name', '')]

    print(f"\n✓ Images Summary:")
    print(f"  Total images in project: {len(images_data)}")
    print(f"  RHCOS images: {len(rhcos_images)}")
    print(f"  Cluster-specific images: {len(cluster_images)}")

    print(f"\n  RHCOS Image Availability:")
    if rhcos_images:
        print(f"    ✓ RHCOS images present in project")
    else:
        print(f"    ℹ️  No RHCOS images in project")
        print(f"    OpenShift installer will import RHCOS images during installation")

    assert True  # Informational test
