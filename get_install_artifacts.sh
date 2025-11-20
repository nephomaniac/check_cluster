
clusterid=$1
if [ -z "${clusterid}" ]; then 
  echo "missing cluster id?"
  exit 1
fi
echo "This may require refreshing local AWS creds, example..."
echo "eval \$(ocm backplane cloud credentials ${clusterid} -o env)\n\n"
CLUSTER_JSON="${clusterid}_cluster.json"
CLUSTER_RESOURCES="${clusterid}_resources.json"
CLUSTER_EC2_INSTANCES="${clusterid}_ec2_instances.json"

printline() {
      local char="${1:--}"
      local width="${2:-$(tput cols)}"
      printf '%*s\n' "$width" '' | tr ' ' "$char"
}



if [ -f ${CLUSTER_JSON} ]; then 
  echo "Using existing ${CLUSTER_JSON} file for ocm cluster info"
else 
  echo "Fetching ocm cluster info..."
  echo "ocm get /api/clusters_mgmt/v1/clusters/${clusterid} > ${CLUSTER_JSON}"
  ocm get /api/clusters_mgmt/v1/clusters/${clusterid} > ${CLUSTER_JSON}
  if [ $? -ne 0 ]; then 
    echo "Failed to get cluster from ocm? "
    echo "ocm get /api/clusters_mgmt/v1/clusters/${clusterid} > ${CLUSTER_JSON}"
    exit 1
  fi
fi

if [ -f ${CLUSTER_RESOURCES} ]; then
  echo "Using existing ${CLUSTER_RESOURCES} file"
else
  echo "Fetching ocm cluster resources for install logs..."
  echo "ocm get /api/clusters_mgmt/v1/clusters/${clusterid}/resources > ${CLUSTER_RESOURCES}"
  ocm get /api/clusters_mgmt/v1/clusters/${clusterid}/resources > ${CLUSTER_RESOURCES}
  if [ $? -ne 0 ]; then 
    echo "Failed to get cluster resources?"
    echo "ocm get /api/clusters_mgmt/v1/clusters/${clusterid}/resources > ${CLUSTER_RESOURCES}"
    exit 1
  fi
fi

DOMAIN_PREFIX=$(jq -r '.domain_prefix' ${CLUSTER_JSON})
INFRA_ID=$(jq -r '.infra_id' ${CLUSTER_JSON}) 
PRIVATE_LINK=$(jq -r 'if .aws.private_link == false then 0 else 1 end' ${CLUSTER_JSON})

echo "Using DOMAIN_PREFIX:${DOMAIN_PREFIX}, INFRA_ID:${INFRA_ID}"


# Function to iterate through a provided list of VPC IDs and record AWS info for each
populate_vpc_info_files() {
  local VPC_IDS="$*"
    echo "Found the following VPC ids in cluster resources install logs:\n${VPC_IDS}"
    for VPC in ${VPC_IDS}; do
      local VPC_FILE="${clusterid}_${VPC}_VPC.json"
      local VPC_FILE_DNS_HOST="${clusterid}_${VPC}_VPC_attrDnsHost.json"
      local VPC_FILE_DNS_SUPP="${clusterid}_${VPC}_VPC_attrDnsSupp.json"

      if [ -f ${VPC_FILE} ]; then
        echo "Using existing VPC file ${VPC_FILE}"
      else 
        echo "Fetching AWS info for ${VPC}..."
        echo "aws ec2 describe-vpcs --vpc-ids ${VPC} > ${VPC_FILE}"
        VPCINFO=$(aws ec2 describe-vpcs --vpc-ids ${VPC})
        if [ $? -ne 0 ]; then
          echo "Error fetch VPC:${VPC} from AWS, skipping VPC attribute requests..."
          continue
        fi
        echo "${VPCINFO}" > ${VPC_FILE}
      fi
    
      if [ -f ${VPC_FILE_DNS_HOST} ]; then
        echo "Using existing VPC dns hostname attributes file ${VPC_FILE_DNS_HOST}"
      else 
        echo "aws ec2 describe-vpc-attribute --vpc-id ${VPC} --attribute enableDnsHostnames > ${VPC_FILE_DNS_HOST}"
        aws ec2 describe-vpc-attribute --vpc-id ${VPC} --attribute enableDnsHostnames > ${VPC_FILE_DNS_HOST}
      fi
    
    
      if [ -f ${VPC_FILE_DNS_SUPP} ]; then
        echo "Using existing VPC dns support attributes file ${VPC_FILE_DNS_SUPP}"
      else 
        echo "aws ec2 describe-vpc-attribute --vpc-id ${VPC} --attribute enableDnsSupport > ${VPC_FILE_DNS_SUPP}"
        aws ec2 describe-vpc-attribute --vpc-id ${VPC} --attribute enableDnsSupport > ${VPC_FILE_DNS_SUPP}
      fi

      dhcp_id=$(jq -r '.Vpcs[].DhcpOptionsId' ${VPC_FILE})
      local DHCP_OPT_FILE="${clusterid}_${dhcp_id}_DHCP_OPT.json"
      if [ -f ${DHCP_OPT_FILE} ]; then
        echo "Found existing local dhcp options file: ${DHCP_OPT_FILE}"
      else
        echo "Attempting to fetch aws dhcp option info for: ${dhcp_id}..."
        echo "aws ec2 describe-dhcp-options --dhcp-options-ids $dhcp_id > ${DHCP_OPT_FILE}"
        aws ec2 describe-dhcp-options --dhcp-options-ids $dhcp_id > ${DHCP_OPT_FILE}
      fi
    done
}


# Parse out the instance IDs and make a 'guess' at their roles from the install logs...
# This will show all the instances used for the bootstrap + install phases, not necessarily ones still in use by the cluster
if [ -f ${CLUSTER_RESOURCES} ]; then 
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
2>/dev/null )

echo  "Found the following instance IDS in the cluster install logs: \"${INSTANCE_IDS}\" \n\n"
printline


LB_ARNS=$( python3 << 'PYEOF3'
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
echo "Found the following load balancer ARNS in cluster install logs:\n${LB_ARNS}" 
printline

for ARN in ${LB_ARNS}; do
  LB="${ARN##*/}"
  LB_FILE="${clusterid}_LB_${LB}.json"
  echo "Checking ARN: ${ARN}"
  if [ -f ${LB_FILE} ]; then 
    echo "Using existing load balancer file: ${LB_FILE}"
  else 
    echo "Fetching AWS info for load balancer: ${ARN}"
    echo "aws elbv2 describe-load-balancers --load-balancer-arns ${ARN}"
    LBJ=$(aws elbv2 describe-load-balancers --load-balancer-arns ${ARN} 2>/dev/null)
    if [ -n "$LBJ" ]; then 
      echo "Writing load balancer info to file: ${LB_FILE}"
    else 
      echo "Failed to fetch load balancer: ${ARN}"
    fi
  fi
  printline

done

echo "Looking for VPCs in cluster resources install logs..."
echo "grep -o 'vpc-[a-f0-9]\{17\}' ${CLUSTER_RESOURCES} | sort -u"
VPC_IDS=$(grep -o 'vpc-[a-f0-9]\{17\}' ${CLUSTER_RESOURCES} | sort -u)
echo "Found the following VPC ids in cluster resources install logs:\n${VPC_IDS}"
populate_vpc_info_files "${VPC_IDS}"


printline

if [ ${PRIVATE_LINK} ]; then 
  VPC_SRV_IDS=$(grep -oE 'vpce-svc-[a-f0-9]{17}'  ${CLUSTER_RESOURCES} | sort -u)
  VPC_EP_IDS=$(grep -oE 'vpce-[a-f0-9]{17}' ${CLUSTER_RESOURCES} | sort -u)
  echo "Found VPC service endpoint service ids in install logs:'${VPC_SRV_IDS}'"
  echo "Found VPC service endpoint ids in install logs:'${VPC_IDS}'"
fi

fi #end of code block 'if [ -f ${CLUSTER_RESOURCES}]...'   
####################################################################


# Attempt to gather VPC endpoint info from AWS based on our tags. 
if [ ${PRIVATE_LINK} ]; then 
  VPC_EPSRV_FILE=${cluster_id}_vpc_endpoint_service.json
  VPC_EP_CONN_FILE=${cluster_id}_vpc_endpoint_service_conns.json
  
  
  if [ -f ${VPC_EPSRV_FILE} ]; then
    echo "Using existing vpc endpoint service file: ${VPC_EPSRV_FILE}"
  else
    echo "Fetching vpc endpoint service info from AWS..."
    echo "aws ec2 describe-vpc-endpoint-service-configurations --filters \"Name=tag:Name,Values=${INFRA_ID}-vpc-endpoint-service\""
    VPCSRVOUT=$(aws ec2 describe-vpc-endpoint-service-configurations --filters "Name=tag:Name,Values=${INFRA_ID}-vpc-endpoint-service")
    if [ $? -ne 0 ]; then
      echo "Failed to fetch vpc service configuration from AWS"
    else 
      echo "${VPCSRVOUT}" > ${VPC_EPSRV_FILE}
    fi
  fi
  
  if [ -f ${VPC_EPSRV_FILE} ]; then
    if [ -f ${VPC_EP_CONN_FILE} ]; then
      echo "Using existing vpc endpoint service connections file: ${VPC_EP_CONN_FILE}"
    else
      echo "Fetching vpc endpoint service config id..."
      echo "jq -r '.ServiceConfigurations[0].ServiceId' ${VPC_EPSRV_FILE}"
      SERVICE_ID=$(jq -r '.ServiceConfigurations[0].ServiceId' ${VPC_EPSRV_FILE})
      echo "Fetching vpc endpoint connections for serviceId: '${SERVICE_ID}'"
      echo "aws ec2 describe-vpc-endpoint-connections --filters \"Name=service-id,Values=${SERVICE_ID}\""
      CONNOUT=$(aws ec2 describe-vpc-endpoint-connections --filters "Name=service-id,Values=${SERVICE_ID}")
      if [ $? -ne 0 ]; then
        echo "Failed to fetch vpc endpoint connections for: ${SERVICE_ID}"
      else
        echo ${CONNOUT} > ${VPC_EP_CONN_FILE}
      fi
    fi
  fi
fi

printline
# Fetch VPCs using method separate from install logs, will skip if VPC 
# info was already gathered for the VPCs found
echo "Attempting to fetch AWS VPCs by tag values..."
VPC_IDS=$(aws ec2 describe-vpcs --filters "Name=tag:Name,Values=*${INFRA_ID}*" --query 'Vpcs[].VpcId' --output text)
echo "Found the following VPCs filtering for tags matching infra_id:'${INFRA_ID}':"
echo ${VPC_IDS}
populate_vpc_info_files "${VPC_IDS}"


printline
# Grab the EC2 Instances from aws...
if [ -f ${CLUSTER_EC2_INSTANCES} ]; then 
  echo "using existing ec2 instances file: ${CLUSTER_EC2_INSTANCES}"
else
  echo "Fetching ec2 instances from AWS..."
  echo "aws ec2 describe-instances --query "Reservations[*].Instances[*].{InstanceId:InstanceId,State:State.Name,LaunchTime:LaunchTime,Tags:Tags}" --output json > ${CLUSTER_EC2_INSTANCES}"
  aws ec2 describe-instances --query "Reservations[*].Instances[*].{InstanceId:InstanceId,State:State.Name,LaunchTime:LaunchTime,Tags:Tags}" --output json > ${CLUSTER_EC2_INSTANCES}
  printline
fi

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

# iterate over all the instance IDs found existing in AWS and grab their console logs...
echo "Getting console output for instances found in AWS..."
jq --arg tag_str "f1l4r4k5d2p3a1l" -r '.[] | unique_by(.InstanceId)[]| select(.Tags[]? | .Value | contains($tag_str)) |.InstanceId' ${CLUSTER_EC2_INSTANCES} | while read vm; do
  CONSOLE_FILE=${clusterid}_${vm}_console.log
  echo "VM: ${vm}" 
  if [ -f ${CONSOLE_FILE} ]; then 
    echo "Using existing vm ${vm} console file: ${CONSOLE_FILE}"
  else
    echo "Getting console output for instance ${vm}"
    echo "aws ec2 get-console-output --instance-id ${vm} --output text --query 'Output' > ${CONSOLE_FILE}"
    aws ec2 get-console-output --instance-id ${vm} --output text --query 'Output' > ${CONSOLE_FILE}
  fi
done


printline

# Fetch the cloud trail logs to local file for parsing later...
echo "\nFetching cluster create time to use for cloudtrail logs..."
echo "CREATE_TIME=\$(jq -r '.creation_timestamp' ${CLUSTER_JSON})"
CREATE_TIME=$(jq -r '.creation_timestamp' ${CLUSTER_JSON})
CLUSTER_CT_LOGS="${clusterid}_cloudtrail.json"
CAPTURE_WINDOW="2 hours"
CAPTURE_START=${CREATE_TIME}
CAPTURE_END=$(gdate -u -d "${CREATE_TIME} + ${CAPTURE_WINDOW}" '+%Y-%m-%dT%H:%M:%SZ')

if [ -f ${CLUSTER_CT_LOGS} ]; then 
  echo "using existing cloudtrail logs: ${CLUSTER_CT_LOGS} "
else
  # This is currently using the cluster creation time as the start for the window and 2 hours for the size of the window. 
  # For PD alerts or issues not involving cluster installs, this should be adjusted using the timestamp of the alert
  echo "Gathering cloudtrail logs for '${CAPTURE_WINDOW}' from '${CAPTURE_START}' to '${CAPTURE_END}' ..."
  echo "aws cloudtrail lookup-events --lookup-attributes AttributeKey=ReadOnly,AttributeValue=false --start-time ${CAPTURE_START} --end-time ${CAPTURE_END}  --output json | jq -c '.[]' > ${CLUSTER_CT_LOGS}"
  
  aws cloudtrail lookup-events --lookup-attributes AttributeKey=ReadOnly,AttributeValue=false --start-time ${CAPTURE_START} --end-time ${CAPTURE_END}  --output json | jq -c '.[]' > ${CLUSTER_CT_LOGS}
fi
printline


# Fetch the route53 info...
echo "\nGetting route53 info..."
BASE_DOMAIN=$(jq -r '.dns.base_domain' ${CLUSTER_JSON})
CLUSTER_DOMAIN="${DOMAIN_PREFIX}.${BASE_DOMAIN}"
API_RECORD_SETS=${clusterid}_route53_api_record_sets.json
APPS_RECORD_SETS=${clusterid}_route53_apps_record_sets.json
HOSTED_ZONES=${clusterid}_hosted_zones.json

echo "CLUSTER_DOMAIN=\"${DOMAIN_PREFIX}.${BASE_DOMAIN}\""

echo "ZONE_ID=\$(aws route53 list-hosted-zones --query \"HostedZones[?Name=='${CLUSTER_DOMAIN}.'].Id\" --output text | cut -d'/' -f3)"

if [ -f ${HOSTED_ZONES} ]; then 
  echo "using existing file: ${HOSTED_ZONES}"
else
  echo "fetching hosted zone for cluster domain ${CLUSTER_DOMAIN}..."
  echo "aws route53 list-hosted-zones --query \"HostedZones[?Name=='${CLUSTER_DOMAIN}.'].Id\" --output json > ${HOSTED_ZONES}"
  aws route53 list-hosted-zones --query "HostedZones[?Name=='${CLUSTER_DOMAIN}.'].Id" --output json > ${HOSTED_ZONES}
fi


echo "\nGetting hosted ZONE_ID from ${HOSTED_ZONES}..."
echo "ZONE_ID=\$( jq -r '.[0] | split("/")[2]' ${HOSTED_ZONES})"
ZONE_ID=$( jq -r '.[0] | split("/")[2]' ${HOSTED_ZONES}) 

if [ -n "$ZONE_ID" ]; then
  if [ -f ${API_RECORD_SETS} ]; then
    echo "using existing file ${API_RECORD_SETS}"
  else 
    echo "Fetching API records sets for hosted zone ${ZONE_ID} ..."
    echo "aws route53 list-resource-record-sets --hosted-zone-id \"$ZONE_ID\" --query \"ResourceRecordSets[?Name=='api.${CLUSTER_DOMAIN}.']\" --output json > ${API_RECORD_SETS}"
    aws route53 list-resource-record-sets --hosted-zone-id "$ZONE_ID" --query "ResourceRecordSets[?Name=='api.${CLUSTER_DOMAIN}.']" --output json > ${API_RECORD_SETS}
  fi

  if [ -f ${APPS_RECORD_SETS} ]; then
    echo "using existing file ${APPS_RECORD_SETS}"
  else 
    echo "Fetching APPS records sets for hosted zone ${ZONE_ID} ..."
    echo "aws route53 list-resource-record-sets --hosted-zone-id \"$ZONE_ID\" --query \"ResourceRecordSets[?Name=='*.apps.${CLUSTER_DOMAIN}.']\" --output json > ${APPS_RECORD_SETS}"
    aws route53 list-resource-record-sets --hosted-zone-id "$ZONE_ID" --query "ResourceRecordSets[?Name=='*.apps.${CLUSTER_DOMAIN}.']" --output json > ${APPS_RECORD_SETS}
  fi

else
  echo "No zone found for cluster domain:'${CLUSTER_DOMAIN}' ?"
fi
printline


# Printing the security group IDs found in the install logs, for comparison to what we find in AWS using expected tags filters...
if [ -f ${CLUSTER_RESOURCES} ]; then
  RESOURCES_SGS=$(jq -r '.. | strings' ${CLUSTER_RESOURCES} | grep -oE 'sg-[0-9a-f]+' | sort -u)
  echo "Found the following AWS security group IDs in the ${CLUSTER_RESOURCES}..."
fi 


# Fetch the security groups from AWS...
SG_FILE=${clusterid}_security_groups.json

if [ -f ${SG_FILE} ]; then 
  echo "Using existing security group file: ${SG_FILE}"
else
  echo "Getting security groups with tags matching infra_id:${INFRA_ID} ..."
  echo "aws ec2 describe-security-groups --filters \"Name=tag-value,Values=*${INFRA_ID}*\" --output json > ${SG_FILE}"
  aws ec2 describe-security-groups --filters "Name=tag-value,Values=*${INFRA_ID}*" --output json > ${SG_FILE}
fi
printline



# Get all load balancers
LB_ALL_FILE=${clusterid}_LB_ALL.json
if [ -f ${LB_ALL_FILE} ]; then
  echo "Using existing all load balancers json file ${LB_ALL_FILE} ..."
else
  echo "Fetching all load balancers from AWS..."
  echo "aws elbv2 describe-load-balancers --output json  > ${LB_ALL_FILE}"
  aws elbv2 describe-load-balancers --output json  > ${LB_ALL_FILE}
fi

jq -r '.LoadBalancers[].LoadBalancerArn' ${LB_ALL_FILE} |  while read -r arn; do
    lb="${arn##*/}"
    LB_FILE="${clusterid}_LB_${lb}.json"
    if [ -f ${LB_FILE} ]; then 
      echo "using existing load balancer file: ${LB_FILE}"
    else
      echo "Get AWS load balancer info for: $arn"
      lbjson=$(aws elbv2 describe-tags --resource-arns "$arn" --output json)
      # Check if any tag contains the infra ID
      MATCH=$(echo "${lbjson}" | jq -r --arg infra "$INFRA_ID" '.TagDescriptions[].Tags[] | select(.Value | contains($infra)) | .Key + "=" + .Value' 2>/dev/null)
      if [ -n "$MATCH" ]; then
        echo "Found LOAD balancer with matching infra_id(${INFRA_ID}): '$arn'"
        echo "Writing LB json to file '${LB_FILE}'"
        echo "${lbjson}" > ${LB_FILE} 
      fi
    fi
done












