"""Data loader for cluster artifacts"""

import json
from pathlib import Path
from typing import Optional, Dict, Any, List
from models.cluster import ClusterData


def load_json_file(file_path: Path) -> Optional[Dict[str, Any]]:
    """
    Load a JSON file and return its contents.

    Args:
        file_path: Path to JSON file

    Returns:
        Parsed JSON data or None if file doesn't exist
    """
    if not file_path.exists():
        return None

    try:
        with open(file_path, 'r') as f:
            return json.load(f)
    except (json.JSONDecodeError, IOError) as e:
        print(f"Warning: Failed to load {file_path}: {e}")
        return None


def load_cluster_data(data_dir: Path) -> ClusterData:
    """
    Load all cluster data from a directory.

    Args:
        data_dir: Directory containing cluster JSON files

    Returns:
        ClusterData object with all loaded data

    Raises:
        ValueError: If required files are missing
    """
    data_dir = Path(data_dir).resolve()

    if not data_dir.exists() or not data_dir.is_dir():
        raise ValueError(f"Data directory does not exist: {data_dir}")

    # Find cluster ID from *_cluster.json file
    cluster_files = list(data_dir.glob('*_cluster.json'))
    if not cluster_files:
        raise ValueError(f"No cluster file (*_cluster.json) found in {data_dir}")

    cluster_id = cluster_files[0].stem.replace('_cluster', '')

    # Load core cluster data
    cluster_json = load_json_file(data_dir / f"{cluster_id}_cluster.json")
    if not cluster_json:
        raise ValueError(f"Failed to load cluster.json for {cluster_id}")

    # Create ClusterData object
    cluster_data = ClusterData(
        cluster_id=cluster_id,
        data_dir=data_dir,
        cluster_json=cluster_json
    )

    # Load optional files
    cluster_data.security_groups = load_json_file(data_dir / f"{cluster_id}_security_groups.json") or {}
    cluster_data.load_balancers = load_json_file(data_dir / f"{cluster_id}_load_balancers_all.json") or {}
    cluster_data.vpcs = load_json_file(data_dir / f"{cluster_id}_VPC_IDS.json") or {}
    cluster_data.cluster_context = load_json_file(data_dir / f"{cluster_id}_cluster_context.json") or {}
    cluster_data.resources = load_json_file(data_dir / f"{cluster_id}_resources.json") or {}

    # Load VPC info (look for main VPC file, not attribute files)
    vpc_files = [
        f for f in data_dir.glob(f"{cluster_id}_vpc-*_VPC.json")
        if not f.name.endswith(('_attrDnsHost.json', '_attrDnsSupp.json', '_attrEnableDns.json'))
    ]
    if vpc_files:
        cluster_data.vpcs = load_json_file(vpc_files[0]) or {}

        # Merge VPC DNS attributes into VPC data
        if cluster_data.vpcs and 'Vpcs' in cluster_data.vpcs:
            for vpc in cluster_data.vpcs['Vpcs']:
                vpc_id = vpc.get('VpcId')
                if vpc_id:
                    # Load DNS hostname attribute
                    dns_host_file = data_dir / f"{cluster_id}_{vpc_id}_VPC_attrDnsHost.json"
                    dns_host_data = load_json_file(dns_host_file)
                    if dns_host_data and 'EnableDnsHostnames' in dns_host_data:
                        vpc['EnableDnsHostnames'] = dns_host_data['EnableDnsHostnames'].get('Value', False)

                    # Load DNS support attribute
                    dns_supp_file = data_dir / f"{cluster_id}_{vpc_id}_VPC_attrDnsSupp.json"
                    dns_supp_data = load_json_file(dns_supp_file)
                    if dns_supp_data and 'EnableDnsSupport' in dns_supp_data:
                        vpc['EnableDnsSupport'] = dns_supp_data['EnableDnsSupport'].get('Value', False)

    # Load EC2 instances
    instances_file = data_dir / f"{cluster_id}_ec2_instances.json"
    instances_data = load_json_file(instances_file)
    if instances_data:
        if isinstance(instances_data, list):
            cluster_data.ec2_instances = instances_data
        else:
            # Handle both formats
            cluster_data.ec2_instances = instances_data.get('Instances', [])

    # Load CloudTrail events
    cloudtrail_files = list(data_dir.glob(f"{cluster_id}_*.cloudtrail.json"))
    if cloudtrail_files:
        ct_data = load_json_file(cloudtrail_files[0])
        if ct_data:
            if isinstance(ct_data, list):
                cluster_data.cloudtrail_events = ct_data
            else:
                cluster_data.cloudtrail_events = ct_data.get('Events', [])

    # Load Route53 data
    route53_files = list(data_dir.glob(f"{cluster_id}_hosted_zones.json"))
    if route53_files:
        route53_data = load_json_file(route53_files[0])
        if route53_data:
            # Handle both list and dict formats
            if isinstance(route53_data, list):
                cluster_data.route53_zones = {'HostedZones': route53_data}
            else:
                cluster_data.route53_zones = route53_data
        else:
            cluster_data.route53_zones = {}

    return cluster_data
