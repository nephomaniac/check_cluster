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

  The script automatically reuses the time range from the previous run if:
    • A last_run.json file exists in the working directory
    • No -s/--start or -e/--elapsed arguments are provided
  This makes it easy to refresh data for the same time window.

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
  -s, --start <date>            CloudTrail start date in format: YYYY-MM-DDTHH:MM:SSZ
                                Overrides automatic last_run.json behavior
                                (default: cluster creation time, or last_run.json if present)
  -e, --elapsed <time>          CloudTrail capture window (e.g., "3h", "2d", "4days", "3minutes")
                                Overrides automatic last_run.json behavior
                                (default: 2 hours, or last_run.json if present)
  -p, --period <seconds>        CloudWatch metrics period in seconds (default: 300)
  -f, --force-update            Force recalculation of time range, ignore last_run.json
                                Updates last_run.json with new values
  -h, --help                    Display this help message and exit

PREREQUISITES:
  • ocm CLI (authenticated)
  • aws CLI v2
  • Valid AWS credentials:
      eval \$(ocm backplane cloud credentials <cluster-id> -o env)
  • Required tools: jq, python3, gdate (macOS: brew install coreutils)

EXAMPLES:
  # First run - collect data with default 2-hour window from cluster creation
  eval \$(ocm backplane cloud credentials <clusterid> -o env)
  $(basename "$0") -c <clusterid>

  # Subsequent run - automatically reuses the same time range from first run
  eval \$(ocm backplane cloud credentials <clusterid> -o env)
  $(basename "$0") -c <clusterid>

  # Collect data in a specific directory
  eval \$(ocm backplane cloud credentials <clusterid> -o env)
  $(basename "$0") -c <clusterid> -d /path/to/cluster/data

  # Use custom CloudTrail time window (overrides automatic last_run.json)
  eval \$(ocm backplane cloud credentials <clusterid> -o env)
  $(basename "$0") -c <clusterid> -s 2025-01-15T10:30:00Z -e 3h

  # Collect CloudTrail logs for a 2-day window
  eval \$(ocm backplane cloud credentials <clusterid> -o env)
  $(basename "$0") -c <clusterid> -s 2025-01-15T00:00:00Z -e 2days

  # Force update - recalculate time range even if last_run.json exists
  eval \$(ocm backplane cloud credentials <clusterid> -o env)
  $(basename "$0") -c <clusterid> --force-update

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
  • Automatically saves run configuration to last_run.json
  • Subsequent runs without -s/-e will reuse the previous time range
  • Use -s or -e arguments to override and set a new time range
  • Use --force-update to recalculate time range and update last_run.json
  • Use with check_cluster_artifacts.py for automated health validation

EOF
}


printline() {
  local char="${1:--}"
  local width="${2:-$(tput cols)}"
  [ $width -gt 80 ] && width=80
  printf '%*s\n' "$width" '' | tr ' ' "$char"
}

# print red text to stderr
PERR() {
  echo -e "\033[1;31m$1\033[0m" >&2
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

# Parse elapsed time format (e.g., "3h", "2d", "4days", "3minutes")
# and convert to gdate-compatible format
parse_elapsed_time() {
  local input="$1"

  # Extract number and unit
  if [[ "$input" =~ ^([0-9]+)([a-zA-Z]+)$ ]]; then
    local num="${BASH_REMATCH[1]}"
    local unit="${BASH_REMATCH[2]}"

    # Normalize unit to full word format for gdate
    case "${unit,,}" in
      h|hour|hours)
        echo "${num} hours"
        ;;
      m|minute|minutes)
        echo "${num} minutes"
        ;;
      d|day|days)
        echo "${num} days"
        ;;
      *)
        PERR "Error: Invalid time unit '${unit}'. Use h/hours, m/minutes, or d/days"
        return 1
        ;;
    esac
  else
    PERR "Error: Invalid elapsed time format '${input}'. Expected format: <number><unit> (e.g., '3h', '2days')"
    return 1
  fi
}

# Write runtime configuration to a JSON file
# Uses global variables: WRKDIR, clusterid, CAPTURE_START, CAPTURE_END, START_DATE, ELAPSED_TIME, PERIOD
write_runtime_config_to_file() {
  local config_file="${WRKDIR}last_run.json"

  cat > "$config_file" << EOF
{
  "cluster_id": "${clusterid}",
  "capture_start": "${CAPTURE_START}",
  "capture_end": "${CAPTURE_END}",
  "start_date": "${START_DATE}",
  "elapsed_time": "${ELAPSED_TIME}",
  "period": "${PERIOD:-300}",
  "timestamp": "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
}
EOF

  if [ $? -eq 0 ]; then
    echo "Runtime configuration saved to: ${config_file}"
  else
    PERR "Failed to write runtime configuration to ${config_file}"
  fi
}

# Helper function to fetch CloudWatch metrics with intelligent file caching
# Arguments:
#   $1 - instance_id
#   $2 - metric_name (used in filename)
#   $3 - aws_metric_name (CloudWatch metric name)
#   $4 - namespace (e.g., AWS/EC2, CWAgent)
#   $5 - statistic (e.g., Average, Sum)
#   $6 - description (for error messages)
# Uses global variables: CAPTURE_START, CAPTURE_END, PERIOD, clusterid, WRKDIR
fetch_cloudwatch_metric() {
  local instance_id="$1"
  local metric_name="$2"
  local aws_metric_name="$3"
  local namespace="$4"
  local statistic="$5"
  local description="$6"
  local metric_period="${PERIOD:-300}"

  # Look for existing files matching the prefix
  local file_prefix="${_F_PREFIX}_${instance_id}_${metric_name}_"
  local existing_file=$(ls ${file_prefix}*.json 2>/dev/null | head -n 1)

  local fetch_start="${CAPTURE_START}"
  local fetch_end="${CAPTURE_END}"
  local final_output_file="${file_prefix}${CAPTURE_START}_${CAPTURE_END}.json"

  if [ -n "$existing_file" ]; then
    # Extract timestamps from existing filename
    local filename=$(basename "$existing_file")
    # Pattern: clusterid_instanceid_metricname_START_END.json
    if [[ "$filename" =~ _([0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z)_([0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z)\.json$ ]]; then
      local file_start="${BASH_REMATCH[1]}"
      local file_end="${BASH_REMATCH[2]}"

      # Check if requested range is completely within existing file's range
      if [[ "$CAPTURE_START" > "$file_start" || "$CAPTURE_START" == "$file_start" ]] && [[ "$CAPTURE_END" < "$file_end" || "$CAPTURE_END" == "$file_end" ]]; then
        echo "Using existing ${description} metrics file (covers requested time range): ${existing_file}"
        return 0
      fi

      # Determine the merged time range
      local new_start="$CAPTURE_START"
      local new_end="$CAPTURE_END"
      [[ "$file_start" < "$new_start" ]] && new_start="$file_start"
      [[ "$file_end" > "$new_end" ]] && new_end="$file_end"

      final_output_file="${file_prefix}${new_start}_${new_end}.json"

      # If we need to expand the range, fetch new data
      if [[ "$CAPTURE_START" < "$file_start" || "$CAPTURE_END" > "$file_end" ]]; then
        echo "Fetching additional ${description} metrics to expand time range..."
        echo "  Existing: ${file_start} to ${file_end}"
        echo "  Requested: ${CAPTURE_START} to ${CAPTURE_END}"
        echo "  New range: ${new_start} to ${new_end}"

        # Fetch the full new range
        fetch_start="$new_start"
        fetch_end="$new_end"
      fi
    fi
  fi

  # Fetch metrics from AWS with retry logic
  echo "aws cloudwatch get-metric-statistics --namespace ${namespace} --metric-name ${aws_metric_name} --dimensions Name=InstanceId,Value=${instance_id} --start-time ${fetch_start} --end-time ${fetch_end} --period ${metric_period} --statistics ${statistic} --output json"

  local metrics_output
  local attempt=1
  local max_attempts=3
  local retry_delay=1

  while [ $attempt -le $max_attempts ]; do
    metrics_output=$(aws cloudwatch get-metric-statistics \
      --namespace ${namespace} \
      --metric-name ${aws_metric_name} \
      --dimensions Name=InstanceId,Value=${instance_id} \
      --start-time ${fetch_start} \
      --end-time ${fetch_end} \
      --period ${metric_period} \
      --statistics ${statistic} \
      --output json 2>&1)

    if [ $? -eq 0 ]; then
      break
    else
      if [ $attempt -lt $max_attempts ]; then
        PERR "Attempt ${attempt}/${max_attempts} failed to fetch ${description} for ${instance_id}, retrying in ${retry_delay}s..."
        sleep ${retry_delay}
        attempt=$((attempt + 1))
      else
        PERR "Failed to fetch ${description} for ${instance_id} after ${max_attempts} attempts"
        return 1
      fi
    fi
  done

  # If we have an existing file and fetched new data, merge the datapoints
  if [ -n "$existing_file" ] && [ "$existing_file" != "$final_output_file" ]; then
    echo "Merging new data with existing data..."
    local merged_data
    merged_data=$(jq -s '.[0] as $old | .[1] as $new | $old + {Datapoints: (($old.Datapoints // []) + ($new.Datapoints // []) | unique_by(.Timestamp) | sort_by(.Timestamp))}' "$existing_file" <(echo "$metrics_output"))

    echo "$merged_data" > "$final_output_file"

    # Remove old file if it's different from new file
    if [ "$existing_file" != "$final_output_file" ]; then
      rm -f "$existing_file"
      echo "Removed old file: ${existing_file}"
      echo "Created new file: ${final_output_file}"
    fi
  else
    # No existing file or same filename, just write the data
    echo "${metrics_output}" > "${final_output_file}"
  fi

  return 0
}



# Fetch CloudWatch CPU percent metrics for an EC2 instance
# Arguments:
#   $1 - EC2 instance ID
# Uses global variables: CAPTURE_START, CAPTURE_END, PERIOD, clusterid, WRKDIR
# Returns CPU utilization as a percentage (0-100)
fetch_instance_cpu_percent_metrics() {
  fetch_cloudwatch_metric "$1" "CPUUtilization" "CPUUtilization" "AWS/EC2" "Average" "CPU percent"
}

# Fetch CloudWatch memory percent metrics for an EC2 instance
# Arguments:
#   $1 - EC2 instance ID
# Uses global variables: CAPTURE_START, CAPTURE_END, PERIOD, clusterid, WRKDIR
# Note: Requires CloudWatch agent to be installed on the instance
fetch_instance_mem_percent_metrics() {
  fetch_cloudwatch_metric "$1" "mem_used_percent" "mem_used_percent" "CWAgent" "Average" "memory percent"
}

# Fetch CloudWatch EBS IOPS exceeded check metrics for an EC2 instance
# Arguments:
#   $1 - EC2 instance ID
# Uses global variables: CAPTURE_START, CAPTURE_END, PERIOD, clusterid, WRKDIR
# Returns 1 if instance has exceeded EBS IOPS limit, 0 otherwise
fetch_instance_ebs_iops_exceeded() {
  fetch_cloudwatch_metric "$1" "InstanceEBSIOPSExceededCheck" "InstanceEBSIOPSExceededCheck" "AWS/EC2" "Average" "EBS IOPS exceeded"
}

# Fetch CloudWatch EBS throughput exceeded check metrics for an EC2 instance
# Arguments:
#   $1 - EC2 instance ID
# Uses global variables: CAPTURE_START, CAPTURE_END, PERIOD, clusterid, WRKDIR
# Returns 1 if instance has exceeded EBS throughput limit, 0 otherwise
fetch_instance_ebs_througput_exceeded() {
  fetch_cloudwatch_metric "$1" "InstanceEBSThroughputExceededCheck" "InstanceEBSThroughputExceededCheck" "AWS/EC2" "Average" "EBS throughput exceeded"
}

# Fetch CloudWatch ENI bandwidth in allowance exceeded metrics for an EC2 instance
# Arguments:
#   $1 - EC2 instance ID
# Uses global variables: CAPTURE_START, CAPTURE_END, PERIOD, clusterid, WRKDIR
# Returns sum of times bandwidth in allowance was exceeded
fetch_instance_eni_bw_in_allowance_exceeded() {
  fetch_cloudwatch_metric "$1" "bw_in_allowance_exceeded" "bw_in_allowance_exceeded" "AWS/EC2" "Sum" "ENI bandwidth in allowance exceeded"
}

# Fetch CloudWatch ENI bandwidth out allowance exceeded metrics for an EC2 instance
# Arguments:
#   $1 - EC2 instance ID
# Uses global variables: CAPTURE_START, CAPTURE_END, PERIOD, clusterid, WRKDIR
# Returns sum of times bandwidth out allowance was exceeded
fetch_instance_eni_bw_out_allowance_exceeded() {
  fetch_cloudwatch_metric "$1" "bw_out_allowance_exceeded" "bw_out_allowance_exceeded" "AWS/EC2" "Sum" "ENI bandwidth out allowance exceeded"
}

# Fetch CloudWatch ENI packets per second allowance exceeded metrics for an EC2 instance
# Arguments:
#   $1 - EC2 instance ID
# Uses global variables: CAPTURE_START, CAPTURE_END, PERIOD, clusterid, WRKDIR
# Returns sum of times PPS allowance was exceeded
fetch_instance_eni_pps_allowance_exceeded() {
  fetch_cloudwatch_metric "$1" "pps_allowance_exceeded" "pps_allowance_exceeded" "AWS/EC2" "Sum" "ENI PPS allowance exceeded"
}

# Fetch EC2 instance console logs
# Arguments:
#   $1 - EC2 instance ID
# Uses global variables: clusterid, WRKDIR
fetch_instance_console_logs() {
  local instance_id="$1"
  local console_file="${_F_PREFIX}_${instance_id}_console.log"

  echo "VM: ${instance_id}"
  if [ -f "${console_file}" ]; then
    GREEN "Using existing vm ${instance_id} console file: ${console_file}"
    return 0
  fi

  BLUE "Getting console output for instance ${instance_id}"
  echo "aws ec2 get-console-output --instance-id ${instance_id} --output text --query 'Output' > ${console_file}"

  local console_output
  console_output=$(aws ec2 get-console-output --instance-id ${instance_id} --output text --query 'Output')

  if [[ $? -eq 0 && -n "${console_output}" ]]; then
    echo "${console_output}" > "${console_file}"
  else
    PERR "Failed to fetch ec2 console output for instance: ${instance_id}"
    return 1
  fi
}

# Fetch CloudTrail logs for the cluster
# Uses global variables: ELAPSED_TIME, START_DATE, WRKDIR, clusterid, CLUSTER_JSON
# Sets global variables: CAPTURE_START, CAPTURE_END, CAPTURE_WINDOW, CLUSTER_CT_LOGS
get_cloud_trail_logs() {
  CLUSTER_CT_LOGS="${_F_PREFIX}_${CAPTURE_START}.${CAPTURE_END}.cloudtrail.json"

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
}

# Fetch Route53 hosted zone and DNS record information
# Uses global variables: CLUSTER_JSON, DOMAIN_PREFIX, WRKDIR, clusterid
get_route53_info() {
  local base_domain=$(jq -r '.dns.base_domain' ${CLUSTER_JSON})
  base_domain="${DOMAIN_PREFIX}.${base_domain}"
  local hosted_zones="${_F_PREFIX}_hosted_zones.json"

  echo "BASE_DOMAIN=\"${DOMAIN_PREFIX}.${base_domain}\""

  if [ -f ${hosted_zones} ]; then
    GREEN "using existing file: ${hosted_zones}"
  else
    BLUE "fetching hosted zone for cluster domain ${base_domain}..."
    echo "aws route53 list-hosted-zones --query \"HostedZones[?contains(Name, '${base_domain}')]\" --output json"
    local zone_output
    zone_output=$(aws route53 list-hosted-zones --query "HostedZones[?contains(Name, '${base_domain}')]" --output json)
    if [[ $? -eq 0 && -n "${zone_output}" ]]; then
      echo ${zone_output} > ${hosted_zones}
    else
      PERR "Failed to fetch hosted zones for domain ${base_domain}"
    fi
  fi

  local zone_id=""
  if [ -f ${hosted_zones} ]; then
    echo "\nGetting hosted ZONE_ID from ${hosted_zones}..."
    for zone_id in $(jq -r '.[].Id | split("/")[2]' ${hosted_zones}); do
      if [ -n "$zone_id" ]; then
        local record_sets="${_F_PREFIX}_route53_${zone_id}.records.json"
        if [ -f ${record_sets} ]; then
          GREEN "using existing file ${record_sets}"
        else
          BLUE "Fetching API records sets for hosted zone ${zone_id} ..."
          echo "aws route53 list-resource-record-sets --hosted-zone-id \"$zone_id\" --output json"
          local records_output
          records_output=$(aws route53 list-resource-record-sets --hosted-zone-id "$zone_id" --output json)
          if [[ $? -eq 0 && -n "$records_output" ]]; then
            echo ${records_output} > ${record_sets}
          else
            PERR "Failed to get API record sets"
          fi
        fi
      fi
    done
  else
    PERR "No zone found for cluster domain:'${base_domain}' ?"
  fi
}

# Fetch AWS load balancer information and tag associations
# Uses global variables: WRKDIR, clusterid, INFRA_ID
get_load_balancers_info() {
  local lb_all_file="${_F_PREFIX}_load_balancers_all.json"

  if [ -f ${lb_all_file} ]; then
    GREEN "Using existing all load balancers json file ${lb_all_file} ..."
  else
    BLUE "Fetching all load balancers from AWS..."
    echo "aws elbv2 describe-load-balancers --output json"
    local lb_output
    lb_output=$(aws elbv2 describe-load-balancers --output json)
    if [[ $? -eq 0 && -n "$lb_output" ]]; then
      echo ${lb_output} > ${lb_all_file}
    else
      PERR "Failed to fetch load balancers from AWS"
    fi
  fi

  echo """
AWS LBs dont provide tags in the describe LB response, so
a separate API call 'describe-tags' is need to create a tag <-> resource association.
Iterating over LBs found in ${lb_all_file} to get tag associations...
jq -r '.LoadBalancers[].LoadBalancerArn' ${lb_all_file}
"""

  jq -r '.LoadBalancers[].LoadBalancerArn' ${lb_all_file} | while read -r arn; do
    local lb="${arn##*/}"
    local lb_file="${_F_PREFIX}_${lb}_lb_tags.json"

    if [ -f ${lb_file} ]; then
      GREEN "using existing load balancer file: ${lb_file}"
    else
      BLUE "Get AWS load balancer info for: $arn"
      local tags_output
      tags_output=$(aws elbv2 describe-tags --resource-arns "$arn" --output json)
      if [[ $? -ne 0 || -z "$tags_output" ]]; then
        PERR "Failed to describe-tags for elb ${arn}"
      else
        echo ${tags_output} > ${lb_file}
      fi
    fi

    if [ -f ${lb_file} ]; then
      # Check if any tag contains the infra ID
      echo "Looking for LB tags containing infra: '${INFRA_ID}'..."
      echo "jq -r --arg infra \"${INFRA_ID}\" '.TagDescriptions[].Tags[] | select((.Value | contains(\$infra)) or (.Key | contains(\$infra))) | .Key + \"=\" + .Value' ${lb_file}"
      local match
      match=$(jq -r --arg infra "${INFRA_ID}" '.TagDescriptions[].Tags[] | select((.Value | contains($infra)) or (.Key | contains($infra))) | .Key + "=" + .Value' ${lb_file})
      if [ -n "$match" ]; then
        local lb_svc
        local lb_role
        lb_svc=$(jq -r '.TagDescriptions[].Tags[] | select(.Key == "kubernetes.io/service-name") | "Kub service-name: " + .Value' ${lb_file})
        lb_role=$(jq -r '.TagDescriptions[].Tags[] | select(.Key | contains("role")) | "Kub role: " + .Value' ${lb_file})
        printline
        GREEN "  Found LB info: ${lb}, with tag(s) matching infra:${INFRA_ID}"
        GREEN "  LB Kub Service Name: '${lb_svc}'"
        GREEN "  LB Kub Role: '${lb_role}'"
        printline
      else
        PERR "LB ${arn} did not have tags matching infra:${INFRA_ID}"
      fi
    fi
  done
}

# Fetch AWS security group information
# Uses global variables: CLUSTER_RESOURCES, WRKDIR, clusterid, INFRA_ID
get_security_groups_info() {
  # Printing the security group IDs found in the install logs, for comparison to what we find in AWS using expected tags filters...
  if [ -f ${CLUSTER_RESOURCES} ]; then
    local resources_sgs
    resources_sgs=$(jq -r '.. | strings' ${CLUSTER_RESOURCES} | grep -oE 'sg-[0-9a-f]+' | sort -u)
    BLUE "Found the following AWS security group IDs in the ${CLUSTER_RESOURCES}..."
  fi

  # Fetch the security groups from AWS...
  local sg_file="${_F_PREFIX}_security_groups.json"

  if [ -f ${sg_file} ]; then
    GREEN "Using existing security group file: ${sg_file}"
  else
    BLUE "Getting security groups with tags matching infra_id:${INFRA_ID} ..."
    echo "aws ec2 describe-security-groups --filters \"Name=tag-value,Values=*${INFRA_ID}*\" --output json > ${sg_file}"
    local sg_output
    sg_output=$(aws ec2 describe-security-groups --filters "Name=tag-value,Values=*${INFRA_ID}*" --output json)
    if [[ $? -eq 0 && -n "$sg_output" ]]; then
      echo ${sg_output} > ${sg_file}
    else
      PERR "Erring fetching securtiy group info from AWS"
    fi
  fi
  printline
}

# Fetch EC2 instance information, metrics, and console logs
# Uses global variables: CLUSTER_EC2_INSTANCES, INFRA_ID
get_ec2_instance_info() {
  # Grab the EC2 Instances from aws...
  if [ -f ${CLUSTER_EC2_INSTANCES} ]; then
    GREEN "using existing ec2 instances file: ${CLUSTER_EC2_INSTANCES}"
  else
    # Dont filter these yet, previous checks included those for bad tags...
    BLUE "Fetching ec2 instances from AWS..."
    echo "aws ec2 describe-instances --query \"Reservations[*].Instances[*].{InstanceId:InstanceId,State:State.Name,LaunchTime:LaunchTime,Tags:Tags}\" --output json"
    local instances_output
    instances_output=$(aws ec2 describe-instances --query "Reservations[*].Instances[*].{InstanceId:InstanceId,State:State.Name,LaunchTime:LaunchTime,Tags:Tags}" --output json)
    if [[ $? -eq 0 && -n "${instances_output}" ]]; then
      echo ${instances_output} > ${CLUSTER_EC2_INSTANCES}
    else
      PERR "Failed to fetch EC2 Instances"
    fi
    printline
  fi

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

    HDR "Getting EC2 instance metrics, and console logs"
    # iterate over all the instance IDs found existing in AWS and grab their console logs...
    jq --arg tag_str "${INFRA_ID}" -r '.[] | unique_by(.InstanceId)[]| select(.Tags[]? | .Value | contains($tag_str)) |.InstanceId' ${CLUSTER_EC2_INSTANCES} | while read vm; do
      fetch_instance_console_logs "${vm}"
      fetch_instance_cpu_percent_metrics "${vm}"
      fetch_instance_mem_percent_metrics "${vm}"
      fetch_instance_ebs_iops_exceeded "${vm}"
      fetch_instance_ebs_througput_exceeded "${vm}"
      fetch_instance_eni_bw_in_allowance_exceeded "${vm}"
      fetch_instance_eni_bw_out_allowance_exceeded "${vm}"
      fetch_instance_eni_pps_allowance_exceeded "${vm}"
    done
  else
    PERR "No ec2 instances file found: '${CLUSTER_EC2_INSTANCES}'"
  fi
}

# Fetch VPC endpoint service information for PrivateLink clusters
# Uses global variables: PRIVATE_LINK, WRKDIR, cluster_id, INFRA_ID
get_vpc_endpoint_service_info() {
  # Attempt to gather VPC endpoint info from AWS based on our tags.
  if [ ${PRIVATE_LINK} ]; then
    HDR "Private Link detected getting VPC endpoint service info"
    local vpc_epsrv_file="${WRKDIR}${cluster_id}_vpc_endpoint_service.json"
    local vpc_ep_conn_file="${WRKDIR}${cluster_id}_vpc_endpoint_service_conns.json"

    if [ -f ${vpc_epsrv_file} ]; then
      GREEN "Using existing vpc endpoint service file: ${vpc_epsrv_file}"
    else
      BLUE "Fetching vpc endpoint service info from AWS..."
      echo "aws ec2 describe-vpc-endpoint-service-configurations --filters \"Name=tag:Name,Values=${INFRA_ID}-vpc-endpoint-service\""
      local vpcsrvout
      vpcsrvout=$(aws ec2 describe-vpc-endpoint-service-configurations --filters "Name=tag:Name,Values=${INFRA_ID}-vpc-endpoint-service")
      if [[ $? -ne 0 || -z "$vpcsrvout" ]]; then
        PERR "Failed to fetch vpc service configuration from AWS"
      else
        echo "${vpcsrvout}" > ${vpc_epsrv_file}
      fi
    fi

    if [ -f ${vpc_epsrv_file} ]; then
      if [ -f ${vpc_ep_conn_file} ]; then
        GREEN "Using existing vpc endpoint service connections file: ${vpc_ep_conn_file}"
      else
        BLUE "Fetching vpc endpoint service config id..."
        echo "jq -r '.ServiceConfigurations[0].ServiceId' ${vpc_epsrv_file}"
        local service_id
        service_id=$(jq -r '.ServiceConfigurations[0].ServiceId' ${vpc_epsrv_file})
        BLUE "Fetching vpc endpoint connections for serviceId: '${service_id}'"
        echo "aws ec2 describe-vpc-endpoint-connections --filters \"Name=service-id,Values=${service_id}\""
        local connout
        connout=$(aws ec2 describe-vpc-endpoint-connections --filters "Name=service-id,Values=${service_id}")
        if [[ $? -ne 0 || -z "${connout}" ]]; then
          PERR "Failed to fetch vpc endpoint connections for: ${service_id}"
        else
          echo ${connout} > ${vpc_ep_conn_file}
        fi
      fi
    fi
  fi
}

# Fetch VPC information from AWS using tags
# Uses global variables: WRKDIR, clusterid, INFRA_ID
get_vpc_info() {
  echo "Attempting to fetch AWS VPCs by tag values..."
  local vpc_ids=""
  local vpc_ids_file="${_F_PREFIX}_VPC_IDS.json"

  if [ -f ${vpc_ids_file} ]; then
    GREEN "Using existing vpc ids file: ${vpc_ids_file}"
    vpc_ids=$(cat ${vpc_ids_file})
  else
    echo "fetching VPC ids from AWS..."
    echo "aws ec2 describe-vpcs --filters \"Name=tag:Name,Values=*${INFRA_ID}*\" --query 'Vpcs[].VpcId' --output text"
    vpc_ids=$(aws ec2 describe-vpcs --filters "Name=tag:Name,Values=*${INFRA_ID}*" --query 'Vpcs[].VpcId' --output text)
    if [ $? -ne 0 || -z "${vpc_ids}" ]; then
      echo "Error fetching vpc ids from AWS"
    else
      echo ${vpc_ids} > ${vpc_ids_file}
    fi
  fi

  if [ -z "${vpc_ids}" ]; then
    PERR "Warning no VPC IDS found?"
  else
    BLUE "Found the following VPCs filtering for tags matching infra_id:'${INFRA_ID}':"
    BLUE ${vpc_ids}
    populate_vpc_info_files "${vpc_ids}"
  fi
}

# Parse command-line arguments
clusterid=""
WRKDIR="."
START_DATE=""
ELAPSED_TIME=""
PERIOD=""
FORCE_UPDATE=0

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
    -s|--start)
      START_DATE="$2"
      shift 2
      ;;
    -e|--elapsed)
      ELAPSED_TIME="$2"
      shift 2
      ;;
    -p|--period)
      PERIOD="$2"
      shift 2
      ;;
    -f|--force-update)
      FORCE_UPDATE=1
      shift
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
_F_PREFIX="${WRKDIR}${clusterid}"

# Check if we should use last_run.json or force recalculation
LAST_RUN_FILE="${WRKDIR}last_run.json"
USE_LAST_RUN=0

# Only load from last_run.json if:
# 1. --force-update is NOT set
# 2. No time arguments (-s/-e) were provided
# 3. last_run.json exists
if [ ${FORCE_UPDATE} -eq 0 ] && [ -f "${LAST_RUN_FILE}" ] && [ -z "${START_DATE}" ] && [ -z "${ELAPSED_TIME}" ]; then
  # Automatic: last_run.json exists and no time arguments provided and not forcing update
  BLUE "Found previous run configuration: ${LAST_RUN_FILE}"
  BLUE "No time arguments provided (-s/-e) and --force-update not set, using previous run's time range"

  CAPTURE_START=$(jq -r '.capture_start' "${LAST_RUN_FILE}")
  CAPTURE_END=$(jq -r '.capture_end' "${LAST_RUN_FILE}")

  if [ -z "${CAPTURE_START}" ] || [ "${CAPTURE_START}" == "null" ] || [ -z "${CAPTURE_END}" ] || [ "${CAPTURE_END}" == "null" ]; then
    PERR "Warning: Invalid data in ${LAST_RUN_FILE}, will calculate new time range"
    USE_LAST_RUN=0
  else
    BLUE "Using CAPTURE_START: ${CAPTURE_START}"
    BLUE "Using CAPTURE_END: ${CAPTURE_END}"
    USE_LAST_RUN=1
  fi
elif [ ${FORCE_UPDATE} -eq 1 ]; then
  BLUE "--force-update flag set, recalculating time range (ignoring last_run.json)"
fi

BLUE "This may require refreshing local AWS creds, example..."
BLUE "eval \$(ocm backplane cloud credentials ${clusterid} -o env)"
echo ""
CLUSTER_JSON="${_F_PREFIX}_cluster.json"
CLUSTER_CTX_FILE="${_F_PREFIX}_cluster_context.json"
CLUSTER_RESOURCES="${_F_PREFIX}_resources.json"
CLUSTER_EC2_INSTANCES="${_F_PREFIX}_ec2_instances.json"

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


# Only calculate time ranges if not loaded from last_run.json
if [ ${USE_LAST_RUN} -ne 1 ]; then
  # Determine elapsed time first (needed for ready cluster logic)
  if [ -n "${ELAPSED_TIME}" ]; then
    CAPTURE_WINDOW=$(parse_elapsed_time "${ELAPSED_TIME}")
    if [ $? -ne 0 ]; then
      PERR "Failed to parse elapsed time"
      exit 1
    fi
    BLUE "Using provided elapsed time: ${ELAPSED_TIME} (${CAPTURE_WINDOW})"
  else
    CAPTURE_WINDOW="2 hours"
    BLUE "Using default capture window: ${CAPTURE_WINDOW}"
  fi

  # Determine start date based on cluster state and provided arguments
  if [ -n "${START_DATE}" ]; then
    # User provided explicit start date
    CAPTURE_START="${START_DATE}"
    CAPTURE_END=$(gdate -u -d "${CAPTURE_START} + ${CAPTURE_WINDOW}" '+%Y-%m-%dT%H:%M:%SZ')
    BLUE "Using provided start date: ${CAPTURE_START}"
  else
    # Check cluster state
    CLUSTER_STATE=$(jq -r '.state' ${CLUSTER_JSON})

    if [ "${CLUSTER_STATE}" == "ready" ]; then
      # For ready clusters, use current time as end and calculate start as (now - elapsed)
      CAPTURE_END=$(gdate -u '+%Y-%m-%dT%H:%M:%SZ')
      CAPTURE_START=$(gdate -u -d "${CAPTURE_END} - ${CAPTURE_WINDOW}" '+%Y-%m-%dT%H:%M:%SZ')
      BLUE "Cluster is in ready state - using current time window"
      BLUE "Start: ${CAPTURE_START} (${CAPTURE_WINDOW} ago)"
      BLUE "End: ${CAPTURE_END} (now)"
    else
      # For non-ready clusters, use cluster creation time
      echo "\nFetching cluster create time to use for cloudtrail logs, and metrics..."
      echo "CREATE_TIME=\$(jq -r '.creation_timestamp' ${CLUSTER_JSON})"
      CREATE_TIME=$(jq -r '.creation_timestamp' ${CLUSTER_JSON})
      CAPTURE_START=${CREATE_TIME}
      CAPTURE_END=$(gdate -u -d "${CAPTURE_START} + ${CAPTURE_WINDOW}" '+%Y-%m-%dT%H:%M:%SZ')
      BLUE "Cluster is in ${CLUSTER_STATE} state - using cluster creation time as start date: ${CAPTURE_START}"
    fi
  fi
  BLUE "Using capture start time: ${CAPTURE_START}, end time: ${CAPTURE_END}"
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
    local VPC_FILE="${_F_PREFIX}_${VPC}_VPC.json"
    local VPC_FILE_DNS_HOST="${_F_PREFIX}_${VPC}_VPC_attrDnsHost.json"
    local VPC_FILE_DNS_SUPP="${_F_PREFIX}_${VPC}_VPC_attrDnsSupp.json"

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
    local DHCP_OPT_FILE="${_F_PREFIX}_${dhcp_id}_DHCP_OPT.json"
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
# This is targeted at cluster provisioning errors and delays. Clusters
# which become 'ready' may not have populated install logs in OCM cluster resources. 
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
    LB_FILE="${_F_PREFIX}_load_balancer_${LB}.json"
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
#        MAIN Collection section
#        This section should rely on AWS artifact tags
#        for collecting resource data, 
#        not OCM's cluster resources/install logs. 
####################################################################


##############################
HDR "Getting VPC info using infra id tags"
get_vpc_info

##############################
HDR "Getting VPC endpoint service info"
get_vpc_endpoint_service_info

##############################
HDR "Getting EC2 instance information"
get_ec2_instance_info

##############################
HDR "Getting Cloud trail logs"
get_cloud_trail_logs

##############################
HDR "Getting route53 info..."
get_route53_info

##############################
HDR "Getting Security Group info"
get_security_groups_info

##############################
HDR "Getting Load Balancers"
get_load_balancers_info

##############################
# Save runtime configuration to last_run.json for future automatic reuse
write_runtime_config_to_file
