"""Data loader for cluster artifacts"""

import json
import sys
import os
from pathlib import Path
from typing import Optional, Dict, Any, List
from models.cluster import ClusterData


def load_json_file(file_path: Path, cluster_data: Optional['ClusterData'] = None) -> Optional[Dict[str, Any]]:
    """
    Load a JSON file and return its contents.

    Args:
        file_path: Path to JSON file
        cluster_data: Optional ClusterData object to track file access

    Returns:
        Parsed JSON data or None if file doesn't exist

    Raises:
        json.JSONDecodeError: If the JSON file is malformed (with detailed diagnostics)
    """
    if not file_path.exists():
        # Track missing file
        if cluster_data is not None:
            cluster_data.files_missing.append(str(file_path))
        return None

    try:
        with open(file_path, 'r') as f:
            data = json.load(f)

        # Track successfully loaded file with metadata
        if cluster_data is not None:
            stat = file_path.stat()
            cluster_data.files_loaded[str(file_path)] = {
                'size': stat.st_size,
                'created': stat.st_ctime,
                'modified': stat.st_mtime,
                'name': file_path.name
            }

        return data
    except json.JSONDecodeError as e:
        # Provide detailed error information for corrupted/incomplete JSON files
        print(f"\n{'='*80}", file=sys.stderr)
        print(f"❌ ERROR: Corrupted or incomplete JSON file", file=sys.stderr)
        print(f"{'='*80}", file=sys.stderr)
        print(f"File: {file_path}", file=sys.stderr)
        print(f"Error: {e.msg}", file=sys.stderr)
        print(f"Location: line {e.lineno}, column {e.colno} (character position {e.pos})", file=sys.stderr)

        # Show the problematic line
        try:
            with open(file_path, 'r') as f:
                lines = f.readlines()
                if e.lineno > 0 and e.lineno <= len(lines):
                    print(f"\nProblematic line {e.lineno}:", file=sys.stderr)
                    problem_line = lines[e.lineno - 1].rstrip()
                    print(f"  {problem_line}", file=sys.stderr)
                    # Show pointer to exact column
                    if e.colno > 0:
                        print(f"  {' ' * (e.colno - 1)}^", file=sys.stderr)
        except Exception:
            pass

        print(f"\n{'─'*80}", file=sys.stderr)
        print(f"Possible causes:", file=sys.stderr)
        print(f"  • The data collection script (get_install_artifacts.py) was interrupted", file=sys.stderr)
        print(f"  • Network timeout during AWS API call", file=sys.stderr)
        print(f"  • Disk full or I/O error while writing file", file=sys.stderr)
        print(f"  • File was manually edited and has syntax errors", file=sys.stderr)

        print(f"\n{'─'*80}", file=sys.stderr)
        print(f"How to fix:", file=sys.stderr)
        print(f"  1. Delete the corrupted file:", file=sys.stderr)
        print(f"     rm {file_path}", file=sys.stderr)
        print(f"  2. Re-run data collection for this cluster:", file=sys.stderr)
        print(f"     eval $(ocm backplane cloud credentials <cluster-id> -o env)", file=sys.stderr)
        print(f"     ./get_install_artifacts.py -c <cluster-id> -d {file_path.parent}", file=sys.stderr)
        print(f"{'='*80}\n", file=sys.stderr)

        # Re-raise the exception with original details
        raise
    except IOError as e:
        print(f"\n❌ ERROR: Failed to read file: {file_path}", file=sys.stderr)
        print(f"   {e}", file=sys.stderr)
        raise


def load_cluster_data(data_dir: Path) -> ClusterData:
    """
    Load all cluster data from a directory.

    Supports both new structured layout (sources/ocm, sources/aws) and legacy flat layout.

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

    # Check if we're using new directory structure
    sources_ocm = data_dir / "sources" / "ocm"
    sources_aws = data_dir / "sources" / "aws"
    use_new_structure = sources_ocm.exists() and sources_aws.exists()

    # Determine where to look for cluster.json
    if use_new_structure:
        ocm_dir = sources_ocm
        aws_dir = sources_aws
    else:
        # Legacy flat structure - all files in data_dir
        ocm_dir = data_dir
        aws_dir = data_dir

    # Find cluster ID from *_cluster.json file
    cluster_files = list(ocm_dir.glob('*_cluster.json'))
    if not cluster_files:
        # Fallback to data_dir for legacy structure
        cluster_files = list(data_dir.glob('*_cluster.json'))
    if not cluster_files:
        raise ValueError(f"No cluster file (*_cluster.json) found in {ocm_dir if use_new_structure else data_dir}")

    cluster_id = cluster_files[0].stem.replace('_cluster', '')

    # Load core cluster data (from OCM directory)
    cluster_json = load_json_file(ocm_dir / f"{cluster_id}_cluster.json")
    if not cluster_json:
        raise ValueError(f"Failed to load cluster.json for {cluster_id}")

    # Create ClusterData object
    cluster_data = ClusterData(
        cluster_id=cluster_id,
        data_dir=data_dir,
        cluster_json=cluster_json
    )

    # Track the cluster.json file manually
    cluster_json_path = ocm_dir / f"{cluster_id}_cluster.json"
    if cluster_json_path.exists():
        stat = cluster_json_path.stat()
        cluster_data.files_loaded[str(cluster_json_path)] = {
            'size': stat.st_size,
            'created': stat.st_ctime,
            'modified': stat.st_mtime,
            'name': cluster_json_path.name
        }
        # Register that cluster_json attribute uses this file
        cluster_data.register_attribute_file('cluster_json', str(cluster_json_path))

    # Load optional OCM files
    context_path = ocm_dir / f"{cluster_id}_cluster_context.json"
    cluster_data.cluster_context = load_json_file(context_path, cluster_data) or {}
    if context_path.exists():
        cluster_data.register_attribute_file('cluster_context', str(context_path))

    resources_path = ocm_dir / f"{cluster_id}_resources.json"
    cluster_data.resources = load_json_file(resources_path, cluster_data) or {}
    if resources_path.exists():
        cluster_data.register_attribute_file('resources', str(resources_path))

    # Load AWS files (from AWS directory)
    sg_path = aws_dir / f"{cluster_id}_security_groups.json"
    cluster_data.security_groups = load_json_file(sg_path, cluster_data) or {}
    if sg_path.exists():
        cluster_data.register_attribute_file('security_groups', str(sg_path))

    lb_path = aws_dir / f"{cluster_id}_load_balancers_all.json"
    cluster_data.load_balancers = load_json_file(lb_path, cluster_data) or {}
    if lb_path.exists():
        cluster_data.register_attribute_file('load_balancers', str(lb_path))

    vpc_ids_path = aws_dir / f"{cluster_id}_VPC_IDS.json"
    cluster_data.vpcs = load_json_file(vpc_ids_path, cluster_data) or {}
    if vpc_ids_path.exists():
        cluster_data.register_attribute_file('vpcs', str(vpc_ids_path))

    # Load VPC info (look for main VPC file, not attribute files)
    vpc_files = [
        f for f in aws_dir.glob(f"{cluster_id}_vpc-*_VPC.json")
        if not f.name.endswith(('_attrDnsHost.json', '_attrDnsSupp.json', '_attrEnableDns.json'))
    ]
    if vpc_files:
        cluster_data.vpcs = load_json_file(vpc_files[0], cluster_data) or {}
        cluster_data.register_attribute_file('vpcs', str(vpc_files[0]))

        # Merge VPC DNS attributes into VPC data
        if cluster_data.vpcs and 'Vpcs' in cluster_data.vpcs:
            for vpc in cluster_data.vpcs['Vpcs']:
                vpc_id = vpc.get('VpcId')
                if vpc_id:
                    # Load DNS hostname attribute
                    dns_host_file = aws_dir / f"{cluster_id}_{vpc_id}_VPC_attrDnsHost.json"
                    dns_host_data = load_json_file(dns_host_file, cluster_data)
                    if dns_host_data and 'EnableDnsHostnames' in dns_host_data:
                        vpc['EnableDnsHostnames'] = dns_host_data['EnableDnsHostnames'].get('Value', False)
                        cluster_data.register_attribute_file('vpcs', str(dns_host_file))

                    # Load DNS support attribute
                    dns_supp_file = aws_dir / f"{cluster_id}_{vpc_id}_VPC_attrDnsSupp.json"
                    dns_supp_data = load_json_file(dns_supp_file, cluster_data)
                    if dns_supp_data and 'EnableDnsSupport' in dns_supp_data:
                        vpc['EnableDnsSupport'] = dns_supp_data['EnableDnsSupport'].get('Value', False)
                        cluster_data.register_attribute_file('vpcs', str(dns_supp_file))

    # Load EC2 instances
    instances_file = aws_dir / f"{cluster_id}_ec2_instances.json"
    instances_data = load_json_file(instances_file, cluster_data)
    if instances_data:
        cluster_data.register_attribute_file('ec2_instances', str(instances_file))
        if isinstance(instances_data, list):
            # Flatten nested list structure from AWS CLI query Reservations[*].Instances[*]
            # This results in list[list[dict]] which needs to be flattened to list[dict]
            flattened_instances = []
            for item in instances_data:
                if isinstance(item, list):
                    # Nested list - flatten it
                    flattened_instances.extend(item)
                elif isinstance(item, dict):
                    # Already a dict - keep it
                    flattened_instances.append(item)
            cluster_data.ec2_instances = flattened_instances
        else:
            # Handle dict format with 'Instances' key
            cluster_data.ec2_instances = instances_data.get('Instances', [])

    # Load CloudTrail events
    cloudtrail_files = list(aws_dir.glob(f"{cluster_id}_*.cloudtrail.json"))
    if cloudtrail_files:
        ct_data = load_json_file(cloudtrail_files[0], cluster_data)
        if ct_data:
            cluster_data.register_attribute_file('cloudtrail_events', str(cloudtrail_files[0]))
            if isinstance(ct_data, list):
                cluster_data.cloudtrail_events = ct_data
            else:
                cluster_data.cloudtrail_events = ct_data.get('Events', [])

    # Load Route53 data
    route53_files = list(aws_dir.glob(f"{cluster_id}_hosted_zones.json"))
    if route53_files:
        route53_data = load_json_file(route53_files[0], cluster_data)
        if route53_data:
            cluster_data.register_attribute_file('route53_zones', str(route53_files[0]))
            # Handle both list and dict formats
            if isinstance(route53_data, list):
                cluster_data.route53_zones = {'HostedZones': route53_data}
            else:
                cluster_data.route53_zones = route53_data
        else:
            cluster_data.route53_zones = {}

    return cluster_data
