#!/bin/bash

#
# get_install_artifacts.sh - ROSA Cluster Data Collection Tool
#
# SUMMARY:
#   Automated data collection script for Red Hat OpenShift Service on AWS (ROSA)
#   cluster troubleshooting and post-mortem analysis. Gathers comprehensive AWS
#   infrastructure and OpenShift cluster installation artifacts by:
#
#   1. Fetching cluster metadata from OpenShift Cluster Manager (OCM)
#   2. Extracting resource IDs from installation logs
#   3. Collecting detailed AWS resource information (VPC, EC2, Load Balancers, etc.)
#   4. Gathering CloudTrail audit logs for the cluster creation window
#   5. Retrieving EC2 instance console logs
#
#   All data is saved to local JSON files for offline analysis by tools like
#   check_aws_health.py. The script is idempotent and safe to run multiple times.
#
# USAGE:
#   ./get_install_artifacts.sh -c <cluster-id>
#   ./get_install_artifacts.sh --cluster <cluster-id>
#
# PREREQUISITES:
#   - ocm CLI (logged in)
#   - aws CLI (v2)
#   - Valid AWS credentials (eval $(ocm backplane cloud credentials <cluster-id> -o env))
#   - jq, python3, gdate (brew install coreutils on macOS)
#

# Show usage information
show_help() {
  cat << EOF
ROSA Cluster Data Collection Tool

SYNOPSIS:
  $(basename "$0") -c|--cluster <cluster-id> [-d|--dir <directory>]
  $(basename "$0") -h|--help

DESCRIPTION:
  Automated data collection script for ROSA cluster troubleshooting and analysis.
  Gathers comprehensive AWS infrastructure and OpenShift cluster installation
  artifacts from OCM and AWS APIs.

  Collected data includes:
    • OCM cluster metadata and installation logs
    • VPC details and DNS attributes
    • DHCP Options Sets
    • VPC Endpoint Services (PrivateLink clusters)
    • EC2 instances and console logs
    • Load Balancers and Target Groups
    • Route53 DNS records
    • Security Groups
    • CloudTrail audit logs (2-hour window from cluster creation)

OPTIONS:
  -c, --cluster <cluster-id>    ROSA cluster ID to collect data for
  -d, --dir <directory>         Directory for reading/writing files (default: current directory)
  -h, --help                    Display this help message and exit

PREREQUISITES:
  • ocm CLI (authenticated)
  • aws CLI v2
  • Valid AWS credentials:
      eval \$(ocm backplane cloud credentials <cluster-id> -o env)
  • Required tools: jq, python3, gdate (macOS: brew install coreutils)

EXAMPLES:
  # Refresh AWS credentials and collect data in current directory
  eval \$(ocm backplane cloud credentials <clusterid> -o env)
  $(basename "$0") -c <clusterid>

  # Collect data in a specific directory
  eval \$(ocm backplane cloud credentials <clusterid> -o env)
  $(basename "$0") -c <clusterid> -d /path/to/cluster/data

OUTPUT FILES:
  All files are created in the specified directory (or current directory if -d
  not provided) with naming pattern:
    {cluster_id}_{resource_type}.json
    {cluster_id}_{resource_id}_{resource_type}.json

  Examples:
    <clusterid>_cluster.json
    <clusterid>_vpc-xxx_VPC.json
    <clusterid>_ec2_instances.json
    <clusterid>_cloudtrail.json

NOTES:
  • Script is idempotent - safe to run multiple times
  • Existing files are reused (not re-fetched)
  • Use with check_aws_health.py for automated health validation

EOF
}


printline() {
  local char="${1:--}"
  local width="${2:-$(tput cols)}"
  [ $width > 80 ] && width=80
  printf '%*s\n' "$width" '' | tr ' ' "$char"
}

# print red text
PERR() {
  echo -e "\033[1;31m$1\033[0m"
}

BLUE() {
  echo -e "\033[1;34m$1\033[0m"
}

GREEN() {
  echo -e "\033[1;32m$1\033[0m"
}

HDR() {
  echo ""
  printline
  BLUE "$@"
  printline 
}

# Parse command-line arguments
clusterid=""
WRKDIR="."

while [[ $# -gt 0 ]]; do
  case $1 in
    -c|--cluster)
      clusterid="$2"
      shift 2
      ;;
    -d|--dir)
      WRKDIR="$2"
      shift 2
      ;;
    -h|--help)
      show_help
      exit 0
      ;;
    *)
      echo "Error: Unknown option: $1" >&2
      echo ""
      show_help
      exit 1
      ;;
  esac
done

# Validate cluster ID was provided
if [ -z "${clusterid}" ]; then
  PERR "Error: Cluster ID is required" >&2
  echo ""
  show_help
  exit 1
fi

# Handle WRKDIR - create if needed and change to it
if [ ! -d "${WRKDIR}" ]; then
  echo "Creating directory: ${WRKDIR}"
  mkdir -p "${WRKDIR}"
  if [ $? -ne 0 ]; then
    PERR "Error: Failed to create directory: ${WRKDIR}" >&2
    exit 1
  fi
fi
# Remove any trailing slashes, replace with a single slash. 
WRKDIR="${WRKDIR%/}/"


BLUE "This may require refreshing local AWS creds, example..."
BLUE "eval \$(ocm backplane cloud credentials ${clusterid} -o env)"
echo ""
CLUSTER_JSON="${WRKDIR}${clusterid}_cluster.json"
CLUSTER_CTX_FILE="${WRKDIR}${clusterid}_cluster_context.json"
CLUSTER_RESOURCES="${WRKDIR}${clusterid}_resources.json"
CLUSTER_EC2_INSTANCES="${WRKDIR}${clusterid}_ec2_instances.json"

HDR "Get OCM Cluster INFO"
if [ -f ${CLUSTER_JSON} ]; then
  BLUE "Using existing ${CLUSTER_JSON} file for ocm cluster info"
else
  BLUE "Fetching ocm cluster info..."
  echo "ocm get /api/clusters_mgmt/v1/clusters/${clusterid} > ${CLUSTER_JSON}"
  OUT=$(ocm get /api/clusters_mgmt/v1/clusters/${clusterid}) 
  if [ $? -ne 0 ]; then
    PERR "Failed to get cluster from ocm? "
    PERR "ocm get /api/clusters_mgmt/v1/clusters/${clusterid}"
    exit 1
  else
    echo $OUT > ${CLUSTER_JSON}
  fi
fi

if [ -f ${CLUSTER_CTX_FILE} ]; then 
  GREEN "Using existing cluster context file: ${CLUSTER_CTX_FILE}"
else
  BLUE "Fetching cluster context..."
  echo "osdctl cluster context  -C ${clusterid} -o json"
  CLUSTER_CTX=$(osdctl cluster context  -C ${clusterid} -o json)
  if [ $? -ne 0 ]; then
    PERR "WARNING - failed to fetch cluster context for cluster:'${clusterid}'"
  else 
    echo ${CLUSTER_CTX} > ${CLUSTER_CTX_FILE}
  fi
fi

if [ -f ${CLUSTER_RESOURCES} ]; then
  GREEN "Using existing ocm resources file: ${CLUSTER_RESOURCES}"
else
  BLUE "Fetching ocm cluster resources for install logs..."
  echo "ocm get /api/clusters_mgmt/v1/clusters/${clusterid}/resources"
  RESOUT=$(ocm get /api/clusters_mgmt/v1/clusters/${clusterid}/resources)
  if [ $? -ne 0 ]; then
    PERR "Failed to get cluster resources?"
    echo "ocm get /api/clusters_mgmt/v1/clusters/${clusterid}/resources > ${CLUSTER_RESOURCES}"
    exit 1
  fi
  # Check if cluster resources, install logs are empty. This is expected for a ready cluster. 
  RES=$(echo ${RESOUT} | jq -r 'if .resources == null then "empty" else "notNull" end' 2> /dev/null)
  if [ "empty" == "${RES}" ]; then  
    CSTATE=$(jq -r '.state' ${CLUSTER_JSON})
    echo "Cluster state:${CSTATE}"
    if [ "${CSTATE}" == "ready" ]; then
      BLUE "Cluster OCM resources (install logs) are not expected for clusters in ready state"
    else 
      PERR "Cluster resources not found for this cluster"
      PERR "Cluster is in ${CSTATE} state, new clusters in non-ready state may need to wait for this to be populated"
      PERR "Can run this command again later to retry, will attempt to gather info from AWS without this for now"
    fi
  else  
    echo ${RESOUT} > ${CLUSTER_RESOURCES}
  fi
fi

DOMAIN_PREFIX=$(jq -r '.domain_prefix' ${CLUSTER_JSON})
INFRA_ID=$(jq -r '.infra_id' ${CLUSTER_JSON})
PRIVATE_LINK=$(jq -r 'if .aws.private_link == false then 0 else 1 end' ${CLUSTER_JSON})

echo "Using DOMAIN_PREFIX:${DOMAIN_PREFIX}, INFRA_ID:${INFRA_ID}"

# Function to iterate through a provided list of VPC IDs and record AWS info for each
populate_vpc_info_files() {
  local VPC_IDS="$*"
  GREEN "Found the following VPC ids in cluster resources install logs:\n${VPC_IDS}"
  for VPC in ${VPC_IDS}; do
    local VPC_FILE="${WRKDIR}${clusterid}_${VPC}_VPC.json"
    local VPC_FILE_DNS_HOST="${WRKDIR}${clusterid}_${VPC}_VPC_attrDnsHost.json"
    local VPC_FILE_DNS_SUPP="${WRKDIR}${clusterid}_${VPC}_VPC_attrDnsSupp.json"

    if [ -f ${VPC_FILE} ]; then
      GREEN "Using existing VPC file ${VPC_FILE}"
    else
      BLUE "Fetching AWS info for ${VPC}..."
      echo "aws ec2 describe-vpcs --vpc-ids ${VPC} > ${VPC_FILE}"
      VPCINFO=$(aws ec2 describe-vpcs --vpc-ids ${VPC})
      if [[ $? -ne 0 || -z $VPCINFO ]]; then
        PERR "Error fetch VPC:${VPC} from AWS, skipping VPC attribute requests..."
        continue
      fi
      echo "${VPCINFO}" > ${VPC_FILE}
    fi

    if [ -f ${VPC_FILE_DNS_HOST} ]; then
      GREEN "Using existing VPC dns hostname attributes file ${VPC_FILE_DNS_HOST}"
    else
      BLUE "Fetching VPC attr enableDnsHostNames from AWS"
      echo "aws ec2 describe-vpc-attribute --vpc-id ${VPC} --attribute enableDnsHostnames > ${VPC_FILE_DNS_HOST}"
      OUT=$(aws ec2 describe-vpc-attribute --vpc-id ${VPC} --attribute enableDnsHostnames)
      if [[ $? -eq 0  && -n $OUT ]]; then
        echo $OUT > ${VPC_FILE_DNS_HOST}
      else
        PERR "Failed to fetch vpc atribute enableDnsHostnames from AWS"
      fi
    fi

    if [ -f ${VPC_FILE_DNS_SUPP} ]; then
      GREEN "Using existing VPC dns support attributes file ${VPC_FILE_DNS_SUPP}"
    else
      BLUE "Fetching VPC attr enableDnsSupport from AWS"
      echo "aws ec2 describe-vpc-attribute --vpc-id ${VPC} --attribute enableDnsSupport > ${VPC_FILE_DNS_SUPP}"
      OUT=$(aws ec2 describe-vpc-attribute --vpc-id ${VPC} --attribute enableDnsSupport)
      if [[ $? -eq 0  && -n $OUT ]]; then
        echo $OUT > ${VPC_FILE_DNS_SUPP}
      else
        PERR "Failed to fetch vpc atribute enableDnsSupport from AWS"
      fi
    fi

    dhcp_id=$(jq -r '.Vpcs[].DhcpOptionsId' ${VPC_FILE})
    local DHCP_OPT_FILE="${WRKDIR}${clusterid}_${dhcp_id}_DHCP_OPT.json"
    if [ -f ${DHCP_OPT_FILE} ]; then
      GREEN "Found existing local dhcp options file: ${DHCP_OPT_FILE}"
    else
      BLUE "Attempting to fetch aws dhcp options info for: ${dhcp_id}..."
      echo "aws ec2 describe-dhcp-options --dhcp-options-ids $dhcp_id > ${DHCP_OPT_FILE}"
      OUT=$(aws ec2 describe-dhcp-options --dhcp-options-ids $dhcp_id)
      if [[ $? -eq 0  && -n $OUT ]]; then
        echo $OUT > ${DHCP_OPT_FILE}
      else
        PERR "Failed to fetch dhcp option ${$dhcp_id} from AWS"
      fi
    fi
  done
}

# Parse out the instance IDs and make a 'guess' at their roles from the install logs...
# This will show all the instances used for the bootstrap + install phases, not necessarily ones still in use by the cluster
if [ -f ${CLUSTER_RESOURCES} ]; then
  HDR "Get AWS resource info from OCM cluster resources, install logs"
  export _CLUSTER_RESOURCES_FILE=${CLUSTER_RESOURCES}
  python3 << 'PYEOF'
import json, re, os

if '_CLUSTER_RESOURCES_FILE' in os.environ:
    cluster_resources = os.environ['_CLUSTER_RESOURCES_FILE']
else:
    raise SystemExit("Environment variable not set: '_CLUSTER_RESOURCES_FILE'")


with open(cluster_resources) as f:
    data = json.load(f)

# Extract AMI IDs to exclude (they look like instance IDs but aren't)
ami_ids = set()
install_config_str = data['resources']['install_config']
if '"amiID"' in install_config_str:
    ami_matches = re.findall(r'"amiID":"(i-[0-9a-f]{17})"', install_config_str)
    ami_ids.update(ami_matches)

# Get all JSON content as text
all_text = json.dumps(data)

# Extract instance IDs with their roles from context
instance_roles = {}
for line in all_text.split('\\n'):
    match = re.search(r'i-[0-9a-f]{17}', line)
    if match:
        iid = match.group()

        # Skip AMI IDs
        if iid in ami_ids:
            continue

        # Determine role from context
        line_lower = line.lower()
        role = 'unknown'

        if 'bootstrap' in line_lower:
            role = 'bootstrap'
        elif 'master' in line_lower or 'control' in line_lower:
            role = 'master'
        elif 'worker' in line_lower:
            role = 'worker'
        elif 'infra' in line_lower:
            role = 'infra'

        # Keep most specific role found
        if iid not in instance_roles or instance_roles[iid] == 'unknown':
            instance_roles[iid] = role

# Output results
print('Instance ID          (GUESSED) Role')
print('-' * 40)
for iid in sorted(instance_roles.keys()):
    print(f'{iid}  {instance_roles[iid]}')

print(f'\nTotal: {len(instance_roles)} instances found in cluster resources/install logs')
PYEOF

  ##########
  printline
  # Grab the list of instance IDS for easy parsing needs later...
  INSTANCE_IDS=$(python3 << 'PYEOF2'
import json, re, os

if '_CLUSTER_RESOURCES_FILE' in os.environ:
    cluster_resources = os.environ['_CLUSTER_RESOURCES_FILE']
else:
    raise SystemExit("Environment variable not set: '_CLUSTER_RESOURCES_FILE'")


with open(cluster_resources) as f:
    data = json.load(f)

# Extract AMI IDs to exclude
ami_ids = set()
install_config_str = data['resources']['install_config']
if '"amiID"' in install_config_str:
    ami_matches = re.findall(r'"amiID":"(i-[0-9a-f]{17})"', install_config_str)
    ami_ids.update(ami_matches)

# Get all instance IDs
all_text = json.dumps(data)
instance_ids = set()
for match in re.finditer(r'i-[0-9a-f]{17}', all_text):
    iid = match.group()
    if iid not in ami_ids:
        instance_ids.add(iid)

# Output space-separated list
print(' '.join(sorted(instance_ids)))
PYEOF2
2> /dev/null)

  echo "Found the following instance IDS in the cluster install logs: \"${INSTANCE_IDS}\" \n\n"

  ##########
  printline
  LB_ARNS=$(python3 << 'PYEOF3'
import json
import re, os

if '_CLUSTER_RESOURCES_FILE' in os.environ:
    cluster_resources = os.environ['_CLUSTER_RESOURCES_FILE']
else:
    raise SystemExit("Environment variable not set: '_CLUSTER_RESOURCES_FILE'")

with open(cluster_resources) as f:
    data = json.load(f)

all_text = json.dumps(data)

# Extract load balancer names and IDs
pattern = r'(listener|loadbalancer)/(net|app)/([^/]+)/([a-f0-9]+)'
matches = re.findall(pattern, all_text)

lb_info = {}
for match in matches:
    lb_type = match[1]  # net or app
    lb_name = match[2]
    lb_id = match[3]
    lb_info[lb_id] = (lb_name, lb_type)

# Collect ARNs for AWS CLI command
lb_arns = []
for lb_id in sorted(lb_info.keys()):
    lb_name, lb_type = lb_info[lb_id]
    arn = f"arn:aws:elasticloadbalancing:us-east-1:340148571693:loadbalancer/{lb_type}/{lb_name}/{lb_id}"
    print(arn)
PYEOF3
)
  HDR "Getting LB info from IDs found in install logs"
  echo "Found the following load balancer ARNS in cluster install logs:\n${LB_ARNS}"
  printline

  for ARN in ${LB_ARNS}; do
    LB="${ARN##*/}"
    LB_FILE="${WRKDIR}${clusterid}_LB_${LB}.json"
    echo "Checking ARN: ${ARN}"
    if [ -f ${LB_FILE} ]; then
      GREEN "Using existing load balancer file: ${LB_FILE}"
    else
      BLUE "Fetching AWS info for load balancer: ${ARN}"
      echo "aws elbv2 describe-load-balancers --load-balancer-arns ${ARN}"
      LBJ=$(aws elbv2 describe-load-balancers --load-balancer-arns ${ARN} 2> /dev/null)
      if [[ $? -eq 0 && -n "$LBJ" ]]; then
        echo "Writing load balancer info to file: ${LB_FILE}"
        echo ${LBJ} > ${LB_FILE}
      else
        PERR "Failed to fetch load balancer: ${ARN}"
      fi
    fi
    printline
  done

  HDR "Getting VPC info from IDs found in install logs"
  BLUE "Looking for VPCs in cluster resources install logs..."
  echo "grep -o 'vpc-[a-f0-9]\{17\}' ${CLUSTER_RESOURCES} | sort -u"
  VPC_IDS=$(grep -o 'vpc-[a-f0-9]\{17\}' ${CLUSTER_RESOURCES} | sort -u)
  GREEN "Found the following VPC ids in cluster resources install logs:\n${VPC_IDS}"
  populate_vpc_info_files "${VPC_IDS}"

  printline

  if [ ${PRIVATE_LINK} ]; then
    VPC_SRV_IDS=$(grep -oE 'vpce-svc-[a-f0-9]{17}' ${CLUSTER_RESOURCES} | sort -u)
    VPC_EP_IDS=$(grep -oE 'vpce-[a-f0-9]{17}' ${CLUSTER_RESOURCES} | sort -u)
    GREEN "Found VPC service endpoint service ids in install logs:'${VPC_SRV_IDS}'"
    GREEN "Found VPC service endpoint ids in install logs:'${VPC_IDS}'"
  fi

fi #end of code block 'if [ -f ${CLUSTER_RESOURCES}]...'
####################################################################


# Attempt to gather VPC endpoint info from AWS based on our tags.
if [ ${PRIVATE_LINK} ]; then
  HDR "Private Link detected getting VPC endpoint service info"
  VPC_EPSRV_FILE=${WRKDIR}${cluster_id}_vpc_endpoint_service.json
  VPC_EP_CONN_FILE=${WRKDIR}${cluster_id}_vpc_endpoint_service_conns.json

  if [ -f ${VPC_EPSRV_FILE} ]; then
    GREEN "Using existing vpc endpoint service file: ${VPC_EPSRV_FILE}"
  else
    BLUE "Fetching vpc endpoint service info from AWS..."
    echo "aws ec2 describe-vpc-endpoint-service-configurations --filters \"Name=tag:Name,Values=${INFRA_ID}-vpc-endpoint-service\""
    VPCSRVOUT=$(aws ec2 describe-vpc-endpoint-service-configurations --filters "Name=tag:Name,Values=${INFRA_ID}-vpc-endpoint-service")
    if [[ $? -ne 0 || -z "$VPCSRVOUT" ]]; then
      PERR "Failed to fetch vpc service configuration from AWS"
    else
      echo "${VPCSRVOUT}" > ${VPC_EPSRV_FILE}
    fi
  fi

  if [ -f ${VPC_EPSRV_FILE} ]; then
    if [ -f ${VPC_EP_CONN_FILE} ]; then
      GREEN "Using existing vpc endpoint service connections file: ${VPC_EP_CONN_FILE}"
    else
      BLUE "Fetching vpc endpoint service config id..."
      echo "jq -r '.ServiceConfigurations[0].ServiceId' ${VPC_EPSRV_FILE}"
      SERVICE_ID=$(jq -r '.ServiceConfigurations[0].ServiceId' ${VPC_EPSRV_FILE})
      BLUE "Fetching vpc endpoint connections for serviceId: '${SERVICE_ID}'"
      echo "aws ec2 describe-vpc-endpoint-connections --filters \"Name=service-id,Values=${SERVICE_ID}\""
      CONNOUT=$(aws ec2 describe-vpc-endpoint-connections --filters "Name=service-id,Values=${SERVICE_ID}")
      if [[ $? -ne 0 || -z "${CONNOUT}" ]]; then
        PERR "Failed to fetch vpc endpoint connections for: ${SERVICE_ID}"
      else
        echo ${CONNOUT} > ${VPC_EP_CONN_FILE}
      fi
    fi
  fi
fi


HDR "Getting VPC info using infra id tags"
# Fetch VPCs using method separate from install logs, will skip if VPC
# info was already gathered for the VPCs found
echo "Attempting to fetch AWS VPCs by tag values..."
VPC_IDS=$(aws ec2 describe-vpcs --filters "Name=tag:Name,Values=*${INFRA_ID}*" --query 'Vpcs[].VpcId' --output text)
BLUE "Found the following VPCs filtering for tags matching infra_id:'${INFRA_ID}':"
BLUE ${VPC_IDS}
populate_vpc_info_files "${VPC_IDS}"

printline
# Grab the EC2 Instances from aws...
if [ -f ${CLUSTER_EC2_INSTANCES} ]; then
  GREEN "using existing ec2 instances file: ${CLUSTER_EC2_INSTANCES}"
else
  # Dont filter these yet, previous checks included those for bad tags...
  BLUE "Fetching ec2 instances from AWS..."
  echo "aws ec2 describe-instances --query \"Reservations[*].Instances[*].{InstanceId:InstanceId,State:State.Name,LaunchTime:LaunchTime,Tags:Tags}\" --output json"
  OUT=$(aws ec2 describe-instances --query "Reservations[*].Instances[*].{InstanceId:InstanceId,State:State.Name,LaunchTime:LaunchTime,Tags:Tags}" --output json)
  if [[ $? -eq 0 && -n "${OUT}" ]]; then
    echo ${OUT} > ${CLUSTER_EC2_INSTANCES}
  else 
    PERR "Failed to fetch EC2 Instances"
  fi
  printline
fi

HDR "Getting EC2 instances from AWS"
if [ -f ${CLUSTER_EC2_INSTANCES} ]; then 
  # Parse the ec2 output into a table for viewing filter out the instances by our cluster tags.
  # AI can chew on the raw json later...
  echo """
  jq --arg tag_str \"${INFRA_ID}\" -r '[\"INSTANCE_ID\", \"STATE\", \"NAME\"],
    ([.[][] | select(.Tags[]? | .Value | contains(\$tag_str))] |
    unique_by(.InstanceId) |
    .[] |
    [.InstanceId, .State, (.Tags[] | select(.Key==\"Name\") | .Value // \"N/A\")]) |
    @tsv' ${CLUSTER_EC2_INSTANCES} | column -t
  """

  jq --arg tag_str "${INFRA_ID}" -r '["INSTANCE_ID", "AWS_STATE", "NAME"],
    ([.[][] | select(.Tags[]? | .Value | contains($tag_str))] |
    unique_by(.InstanceId) |
    .[] |
    [.InstanceId, .State, (.Tags[] | select(.Key=="Name") | .Value // "N/A")]) |
    @tsv' ${CLUSTER_EC2_INSTANCES} | column -t
  printline
fi

HDR "Getting EC2 instance console logs"
# iterate over all the instance IDs found existing in AWS and grab their console logs...
BLUE "Getting console output for instances found in AWS..."
jq --arg tag_str "f1l4r4k5d2p3a1l" -r '.[] | unique_by(.InstanceId)[]| select(.Tags[]? | .Value | contains($tag_str)) |.InstanceId' ${CLUSTER_EC2_INSTANCES} | while read vm; do
  CONSOLE_FILE=${WRKDIR}${clusterid}_${vm}_console.log
  echo "VM: ${vm}"
  if [ -f ${CONSOLE_FILE} ]; then
    GREEN "Using existing vm ${vm} console file: ${CONSOLE_FILE}"
  else
    BLUE "Getting console output for instance ${vm}"
    echo "aws ec2 get-console-output --instance-id ${vm} --output text --query 'Output' > ${CONSOLE_FILE}"
    OUT=$(aws ec2 get-console-output --instance-id ${vm} --output text --query 'Output')
    if [[ $? -eq 0 && -n "${OUT}" ]]; then
      echo $OUT > ${CONSOLE_FILE}
    else 
      PERR "FAiled to fetch ec2 console output for instance: ${vm}"
    fi
  fi
done

HDR "Getting Cloud trail logs"

# Fetch the cloud trail logs to local file for parsing later...
echo "\nFetching cluster create time to use for cloudtrail logs..."
echo "CREATE_TIME=\$(jq -r '.creation_timestamp' ${CLUSTER_JSON})"
CREATE_TIME=$(jq -r '.creation_timestamp' ${CLUSTER_JSON})
CLUSTER_CT_LOGS="${WRKDIR}${clusterid}_cloudtrail.json"
CAPTURE_WINDOW="2 hours"
CAPTURE_START=${CREATE_TIME}
CAPTURE_END=$(gdate -u -d "${CREATE_TIME} + ${CAPTURE_WINDOW}" '+%Y-%m-%dT%H:%M:%SZ')
CLUSTER_CT_LOGS="${WRKDIR}${clusterid}_${CAPTURE_START}.${CAPTURE_END}.cloudtrail.json"

if [ -f ${CLUSTER_CT_LOGS} ]; then
  GREEN "using existing cloudtrail logs: ${CLUSTER_CT_LOGS} "
else
  # This is currently using the cluster creation time as the start for the window and 2 hours for the size of the window.
  # For PD alerts or issues not involving cluster installs, this should be adjusted using the timestamp of the alert
  BLUE "Gathering cloudtrail logs for '${CAPTURE_WINDOW}' from '${CAPTURE_START}' to '${CAPTURE_END}' ..."
  echo "aws cloudtrail lookup-events --lookup-attributes AttributeKey=ReadOnly,AttributeValue=false --start-time ${CAPTURE_START} --end-time ${CAPTURE_END}  --output json | jq -c '.[]' > ${CLUSTER_CT_LOGS}"

  CTOUT=$(aws cloudtrail lookup-events --lookup-attributes AttributeKey=ReadOnly,AttributeValue=false --start-time ${CAPTURE_START} --end-time ${CAPTURE_END} --output json | jq -c '.[]') 
  if [[ $? -eq 0 && -n "$CTOUT" ]]; then 
    echo ${CTOUT} > ${CLUSTER_CT_LOGS}
  else
    PERR "Failed fetch cloudtrail info from AWS"
  fi
fi
printline

# Fetch the route53 info...
HDR "Getting route53 info..."
BASE_DOMAIN=$(jq -r '.dns.base_domain' ${CLUSTER_JSON})
BASE_DOMAIN="${DOMAIN_PREFIX}.${BASE_DOMAIN}"
HOSTED_ZONES=${WRKDIR}${clusterid}_hosted_zones.json

echo "BASE_DOMAIN=\"${DOMAIN_PREFIX}.${BASE_DOMAIN}\""


if [ -f ${HOSTED_ZONES} ]; then
  GREEN "using existing file: ${HOSTED_ZONES}"
else
  BLUE "fetching hosted zone for cluster domain ${BASE_DOMAIN}..."
  echo "aws route53 list-hosted-zones --query \"HostedZones[?contains(Name, '${BASE_DOMAIN}')]\" --output json"
  OUT=$(aws route53 list-hosted-zones --query "HostedZones[?contains(Name, '${BASE_DOMAIN}')]" --output json)
  if [[ $? -eq 0 && -n "${OUT}" ]]; then
      echo $OUT > ${HOSTED_ZONES}
  else 
      PERR "Failed to fetch hosted zones for domain ${BASE_DOMAIN}"
  fi
   
fi
ZONE_ID=""
if [ -f ${HOSTED_ZONES} ]; then
  echo "\nGetting hosted ZONE_ID from ${HOSTED_ZONES}..."
  for ZONE_ID in $(jq -r '.[].Id | split("/")[2]'   ${HOSTED_ZONES}); do
    if [ -n "$ZONE_ID" ]; then
      RECORD_SETS=${WRKDIR}${clusterid}_route53_${ZONE_ID}.records.json
      if [ -f ${RECORD_SETS} ]; then
        GREEN "using existing file ${RECORD_SETS}"
      else
        BLUE "Fetching API records sets for hosted zone ${ZONE_ID} ..."
        echo "aws route53 list-resource-record-sets --hosted-zone-id \"$ZONE_ID\" --output json"
        RSOUT=$(aws route53 list-resource-record-sets --hosted-zone-id "$ZONE_ID" --output json)
        if [[ $? -eq 0 && -n "$RSOUT" ]]; then 
          echo ${RSOUT} > ${RECORD_SETS}
        else
          PERR "Failed to get API record sets"
        fi
      fi
    fi
  done
else
  PERR "No zone found for cluster domain:'${BASE_DOMAIN}' ?"
fi


HDR "Getting Security Group info"
# Printing the security group IDs found in the install logs, for comparison to what we find in AWS using expected tags filters...
if [ -f ${CLUSTER_RESOURCES} ]; then
  RESOURCES_SGS=$(jq -r '.. | strings' ${CLUSTER_RESOURCES} | grep -oE 'sg-[0-9a-f]+' | sort -u)
  BLUE "Found the following AWS security group IDs in the ${CLUSTER_RESOURCES}..."
fi

# Fetch the security groups from AWS...
SG_FILE=${WRKDIR}${clusterid}_security_groups.json

if [ -f ${SG_FILE} ]; then
  GREEN "Using existing security group file: ${SG_FILE}"
else
  BLUE "Getting security groups with tags matching infra_id:${INFRA_ID} ..."
  echo "aws ec2 describe-security-groups --filters \"Name=tag-value,Values=*${INFRA_ID}*\" --output json > ${SG_FILE}"
  SGOUT=$(aws ec2 describe-security-groups --filters "Name=tag-value,Values=*${INFRA_ID}*" --output json)
  if [[ $? -eq 0 && -n "$SGOUT" ]]; then 
    echo ${SGOUT} > ${SG_FILE}
  else
    PERR "Erring fetching securtiy group info from AWS"
  fi
fi
printline

HDR "Getting Load Balancers"
LB_ALL_FILE=${WRKDIR}${clusterid}_LB_ALL.json
if [ -f ${LB_ALL_FILE} ]; then
  GREEN "Using existing all load balancers json file ${LB_ALL_FILE} ..."
else
  BLUE "Fetching all load balancers from AWS..."
  echo "aws elbv2 describe-load-balancers --output json"
  OUT=$(aws elbv2 describe-load-balancers --output json) 
  if [[ $? -eq 0 && -n "$OUT" ]]; then 
    echo ${OUT} > ${LB_ALL_FILE}
  else
    PERR "Failed to fetch load balancers from AWS"
  fi
fi

jq -r '.LoadBalancers[].LoadBalancerArn' ${LB_ALL_FILE} | while read -r arn; do
  lb="${arn##*/}"
  LB_FILE="${WRKDIR}${clusterid}_LB_${lb}.json"
  if [ -f ${LB_FILE} ]; then
    GREEN "using existing load balancer file: ${LB_FILE}"
  else
    BLUE "Get AWS load balancer info for: $arn"
    OUT=$(aws elbv2 describe-tags --resource-arns "$arn" --output json)
    if [[ $? -ne 0 || -z "$OUT" ]]; then 
      PERR "Failed to describe-tags for elb ${arn}" 
    else
      echo ${OUT} > ${LB_FILE}
    fi
  fi
  if [ -f ${LB_FILE} ]; then
    # Check if any tag contains the infra ID
    echo "Looking for LB tags containing infra: '${INFRA_ID}'..."
    echo "jq -r --arg infra \"${INFRA_ID}\" '.TagDescriptions[].Tags[] | select((.Value | contains(\$infra)) or (.Key | contains(\$infra))) | .Key + "=" + .Value' ${LB_FILE}"
    MATCH=$(jq -r --arg infra "${INFRA_ID}" '.TagDescriptions[].Tags[] | select((.Value | contains($infra)) or (.Key | contains($infra))) | .Key + "=" + .Value' ${LB_FILE})
    if [ -n "$MATCH" ]; then
      GREEN "Found LOAD balancer with matching infra_id(${INFRA_ID}): '$arn'"
    else
      PERR "LB ${arn} did not have tags matching infra:${INFRA_ID}"
    fi
  fi
done
