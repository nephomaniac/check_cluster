# get_install_artifacts.sh - Summary

## Purpose
Automated data collection script that gathers comprehensive AWS infrastructure and OpenShift cluster installation artifacts for troubleshooting and analysis. Designed for ROSA (Red Hat OpenShift Service on AWS) cluster debugging and post-mortem analysis.

## What It Does

### Overview
The script performs a complete cluster artifact collection by:
1. Fetching cluster metadata from OpenShift Cluster Manager (OCM)
2. Extracting resource IDs from installation logs
3. Collecting detailed AWS resource information
4. Gathering CloudTrail audit logs
5. Retrieving EC2 instance console logs

All data is saved to local JSON files for offline analysis by tools like `check_aws_health.py`.

---

## Detailed Workflow

### 1. Prerequisites Check (Lines 1-9)
```bash
clusterid=$1
if [ -z "${clusterid}" ]; then
  echo "missing cluster id?"
  exit 1
fi
```
- Requires cluster ID as first argument
- Reminds user to refresh AWS credentials: `eval $(ocm backplane cloud credentials ${clusterid} -o env)`

### 2. OCM Cluster Information (Lines 20-44)
**Fetches cluster metadata from OpenShift Cluster Manager**

Files created:
- `{cluster_id}_cluster.json` - Full cluster configuration
- `{cluster_id}_resources.json` - Installation logs and resource metadata

Commands executed:
```bash
ocm get /api/clusters_mgmt/v1/clusters/${clusterid} > ${CLUSTER_JSON}
ocm get /api/clusters_mgmt/v1/clusters/${clusterid}/resources > ${CLUSTER_RESOURCES}
```

Extracts:
- `DOMAIN_PREFIX` - Cluster domain prefix
- `INFRA_ID` - Infrastructure ID (used for tagging)
- `PRIVATE_LINK` - PrivateLink cluster flag

### 3. Instance ID Extraction (Lines 100-200)
**Parses installation logs to identify all EC2 instances used during cluster creation**

Uses embedded Python script to:
- Extract instance IDs using regex: `i-[0-9a-f]{17}`
- Filter out AMI IDs (they look like instance IDs but aren't)
- Guess instance roles from log context (bootstrap, master, worker, infra)
- Display table of instances with guessed roles

Output example:
```
Instance ID          (GUESSED) Role
----------------------------------------
i-0d9ca2d2ead2b03a1  bootstrap
i-01234567890abcdef  master
i-0fedcba0987654321  worker
```

### 4. Load Balancer Discovery (Lines 202-257)
**Extracts load balancer ARNs from installation logs**

Uses Python regex to find load balancer patterns:
```python
pattern = r'(listener|loadbalancer)/(net|app)/([^/]+)/([a-f0-9]+)'
```

For each load balancer:
- Constructs full ARN
- Fetches details via AWS CLI
- Saves to `{cluster_id}_LB_{lb_id}.json`

### 5. VPC Information Collection (Lines 259-322)
**Discovers and documents VPCs used by the cluster**

#### Step 1: Extract VPC IDs from install logs
```bash
VPC_IDS=$(grep -o 'vpc-[a-f0-9]\{17\}' ${CLUSTER_RESOURCES} | sort -u)
```

#### Step 2: For each VPC, collect:

**VPC Details** (`{cluster_id}_{vpc_id}_VPC.json`):
```bash
aws ec2 describe-vpcs --vpc-ids ${VPC}
```

**DNS Hostname Attribute** (`{cluster_id}_{vpc_id}_VPC_attrDnsHost.json`):
```bash
aws ec2 describe-vpc-attribute --vpc-id ${VPC} --attribute enableDnsHostnames
```

**DNS Support Attribute** (`{cluster_id}_{vpc_id}_VPC_attrDnsSupp.json`):
```bash
aws ec2 describe-vpc-attribute --vpc-id ${VPC} --attribute enableDnsSupport
```

**DHCP Options** (`{cluster_id}_{dhcp_id}_DHCP_OPT.json`):
```bash
dhcp_id=$(jq -r '.Vpcs[].DhcpOptionsId' ${VPC_FILE})
aws ec2 describe-dhcp-options --dhcp-options-ids $dhcp_id
```

#### Step 3: Fallback VPC discovery by tags
If install logs don't contain VPC IDs, searches by cluster tags:
```bash
aws ec2 describe-vpcs --filters "Name=tag:Name,Values=*${INFRA_ID}*"
```

### 6. VPC Endpoint Service Collection (PrivateLink only) (Lines 267-312)
**For PrivateLink clusters, collects VPC Endpoint Service information**

Extracts endpoint IDs from logs:
```bash
VPC_SRV_IDS=$(grep -oE 'vpce-svc-[a-f0-9]{17}' ${CLUSTER_RESOURCES})
VPC_EP_IDS=$(grep -oE 'vpce-[a-f0-9]{17}' ${CLUSTER_RESOURCES})
```

Fetches service configuration by tags:
```bash
aws ec2 describe-vpc-endpoint-service-configurations \
  --filters "Name=tag:Name,Values=${INFRA_ID}-vpc-endpoint-service"
```

Fetches endpoint connections:
```bash
SERVICE_ID=$(jq -r '.ServiceConfigurations[0].ServiceId' ${VPC_EPSRV_FILE})
aws ec2 describe-vpc-endpoint-connections \
  --filters "Name=service-id,Values=${SERVICE_ID}"
```

Files created:
- `{cluster_id}_vpc_endpoint_service.json`
- `{cluster_id}_vpc_endpoint_service_conns.json`

### 7. EC2 Instance Details (Lines 324-351)
**Fetches all EC2 instances from AWS**

```bash
aws ec2 describe-instances \
  --query "Reservations[*].Instances[*].{InstanceId:InstanceId,State:State.Name,LaunchTime:LaunchTime,Tags:Tags}" \
  --output json > ${CLUSTER_EC2_INSTANCES}
```

Filters and displays cluster instances in table format:
```bash
jq --arg tag_str "${INFRA_ID}" -r '["INSTANCE_ID", "AWS_STATE", "NAME"],
    ([.[][] | select(.Tags[]? | .Value | contains($tag_str))] |
    unique_by(.InstanceId) |
    .[] |
    [.InstanceId, .State, (.Tags[] | select(.Key=="Name") | .Value // "N/A")]) |
    @tsv' ${CLUSTER_EC2_INSTANCES} | column -t
```

Output:
```
INSTANCE_ID          AWS_STATE  NAME
i-0d9ca2d2ead2b03a1  running    f1l4r4k5d2p3a1l-lx89p-bootstrap
i-01234567890abcdef  running    f1l4r4k5d2p3a1l-lx89p-master-0
```

### 8. Console Log Collection (Lines 353-365)
**Retrieves EC2 console output for each cluster instance**

For debugging bootstrap and instance startup issues:
```bash
aws ec2 get-console-output --instance-id ${vm} --output text --query 'Output' \
  > ${clusterid}_${vm}_console.log
```

Files created: `{cluster_id}_{instance_id}_console.log`

### 9. CloudTrail Audit Logs (Lines 369-388)
**Collects AWS CloudTrail logs for cluster creation window**

Time window calculation:
```bash
CREATE_TIME=$(jq -r '.creation_timestamp' ${CLUSTER_JSON})
CAPTURE_WINDOW="2 hours"
CAPTURE_END=$(gdate -u -d "${CREATE_TIME} + ${CAPTURE_WINDOW}" '+%Y-%m-%dT%H:%M:%SZ')
```

Fetches non-read-only events (write operations only):
```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=ReadOnly,AttributeValue=false \
  --start-time ${CAPTURE_START} \
  --end-time ${CAPTURE_END} \
  --output json | jq -c '.[]' > ${CLUSTER_CT_LOGS}
```

**Why 2 hours?** Captures entire cluster installation lifecycle including:
- Infrastructure provisioning
- Bootstrap process
- Control plane initialization
- Any errors/failures during installation

### 10. Route53 DNS Records (Lines 390-434)
**Fetches Route53 hosted zone and DNS records**

Constructs cluster domain:
```bash
CLUSTER_DOMAIN="${DOMAIN_PREFIX}.${BASE_DOMAIN}"
```

Gets hosted zone ID:
```bash
aws route53 list-hosted-zones \
  --query "HostedZones[?Name=='${CLUSTER_DOMAIN}.'].Id" \
  --output json > ${HOSTED_ZONES}
```

Fetches API record:
```bash
aws route53 list-resource-record-sets \
  --hosted-zone-id "$ZONE_ID" \
  --query "ResourceRecordSets[?Name=='api.${CLUSTER_DOMAIN}.']" \
  --output json > ${API_RECORD_SETS}
```

Fetches apps wildcard record:
```bash
aws route53 list-resource-record-sets \
  --hosted-zone-id "$ZONE_ID" \
  --query "ResourceRecordSets[?Name=='*.apps.${CLUSTER_DOMAIN}.']" \
  --output json > ${APPS_RECORD_SETS}
```

Files created:
- `{cluster_id}_hosted_zones.json`
- `{cluster_id}_route53_api_record_sets.json`
- `{cluster_id}_route53_apps_record_sets.json`

### 11. Security Groups (Lines 436-452)
**Collects security group configurations**

First, shows security groups found in install logs:
```bash
RESOURCES_SGS=$(jq -r '.. | strings' ${CLUSTER_RESOURCES} | grep -oE 'sg-[0-9a-f]+' | sort -u)
```

Then fetches from AWS by cluster tags:
```bash
aws ec2 describe-security-groups \
  --filters "Name=tag-value,Values=*${INFRA_ID}*" \
  --output json > ${SG_FILE}
```

File created: `{cluster_id}_security_groups.json`

### 12. Load Balancer Tag Matching (Lines 454-481)
**Fetches ALL load balancers and filters by cluster tags**

Gets all load balancers:
```bash
aws elbv2 describe-load-balancers --output json > ${LB_ALL_FILE}
```

For each load balancer, checks tags:
```bash
lbjson=$(aws elbv2 describe-tags --resource-arns "$arn" --output json)
MATCH=$(echo "${lbjson}" | jq -r --arg infra "$INFRA_ID" \
  '.TagDescriptions[].Tags[] | select(.Value | contains($infra)) | .Key + "=" + .Value')
```

If tags match cluster infra-id, saves to `{cluster_id}_LB_{lb_id}.json`

---

## Files Created

### OCM Cluster Data
- `{cluster_id}_cluster.json` - Cluster configuration from OCM
- `{cluster_id}_resources.json` - Installation logs and resources

### VPC Resources
- `{cluster_id}_{vpc_id}_VPC.json` - VPC details
- `{cluster_id}_{vpc_id}_VPC_attrDnsHost.json` - DNS hostname attribute
- `{cluster_id}_{vpc_id}_VPC_attrDnsSupp.json` - DNS support attribute
- `{cluster_id}_{dhcp_id}_DHCP_OPT.json` - DHCP options configuration

### VPC Endpoint (PrivateLink only)
- `{cluster_id}_vpc_endpoint_service.json` - VPC endpoint service config
- `{cluster_id}_vpc_endpoint_service_conns.json` - Endpoint connections

### EC2 Resources
- `{cluster_id}_ec2_instances.json` - All EC2 instances
- `{cluster_id}_{instance_id}_console.log` - Console output per instance

### Load Balancers
- `{cluster_id}_LB_ALL.json` - All load balancers in account
- `{cluster_id}_LB_{lb_id}.json` - Individual load balancer details

### Route53
- `{cluster_id}_hosted_zones.json` - Hosted zone information
- `{cluster_id}_route53_api_record_sets.json` - API DNS records
- `{cluster_id}_route53_apps_record_sets.json` - Apps wildcard DNS records

### Security & Audit
- `{cluster_id}_security_groups.json` - Security group configurations
- `{cluster_id}_cloudtrail.json` - CloudTrail audit logs (2-hour window)

---

## Key Features

### 1. Idempotent Operation
- Checks for existing files before fetching
- Reuses cached data to avoid redundant API calls
- Safe to run multiple times

### 2. Multi-Source Resource Discovery
- Parses installation logs for historical resource IDs
- Queries AWS by tags for current resources
- Cross-references both sources for completeness

### 3. Smart Role Detection
Uses context clues from install logs to guess instance roles:
- "bootstrap" in log line → bootstrap role
- "master" or "control" → master role
- "worker" → worker role
- "infra" → infra role

### 4. AMI ID Filtering
Prevents false positives by excluding AMI IDs (which match instance ID pattern):
```python
ami_matches = re.findall(r'"amiID":"(i-[0-9a-f]{17})"', install_config_str)
```

### 5. PrivateLink Detection
Automatically detects PrivateLink clusters and collects additional VPC endpoint data:
```bash
PRIVATE_LINK=$(jq -r 'if .aws.private_link == false then 0 else 1 end' ${CLUSTER_JSON})
```

---

## Dependencies

### Required Tools
- `bash` - Shell interpreter
- `jq` - JSON parsing
- `grep`, `awk`, `sed` - Text processing
- `python3` - Embedded scripts for complex parsing
- `gdate` - GNU date (macOS: `brew install coreutils`)
- `column` - Table formatting

### AWS/OCM Authentication
- `ocm` - OpenShift Cluster Manager CLI
- `aws` - AWS CLI v2
- Valid AWS credentials (via ocm backplane or AWS profile)

### Required Permissions
**OCM API**:
- Read cluster metadata
- Read cluster resources/logs

**AWS API**:
- `ec2:DescribeVpcs`
- `ec2:DescribeVpcAttribute`
- `ec2:DescribeDhcpOptions`
- `ec2:DescribeInstances`
- `ec2:DescribeSecurityGroups`
- `ec2:DescribeVpcEndpointServiceConfigurations`
- `ec2:DescribeVpcEndpointConnections`
- `ec2:GetConsoleOutput`
- `elasticloadbalancing:DescribeLoadBalancers`
- `elasticloadbalancing:DescribeTags`
- `route53:ListHostedZones`
- `route53:ListResourceRecordSets`
- `cloudtrail:LookupEvents`

---

## Usage

### Basic Usage
```bash
./get_install_artifacts.sh <cluster-id>
```

### With Fresh AWS Credentials
```bash
eval $(ocm backplane cloud credentials <cluster-id> -o env)
./get_install_artifacts.sh <cluster-id>
```

### Example
```bash
./get_install_artifacts.sh 2ml4ao38fdomfv0iqrsca3abmttnlclm
```

---

## Integration with check_aws_health.py

This script collects **all the data files** that `check_aws_health.py` analyzes:

| check_aws_health.py Function | Files Required | Provided by get_install_artifacts.sh |
|------------------------------|----------------|--------------------------------------|
| `check_vpc_dns_attributes()` | VPC files, DNS attributes | ✅ Lines 52-98 |
| `check_dhcp_options()` | VPC files, DHCP options | ✅ Lines 88-96 |
| `check_vpc_endpoint_service()` | VPC endpoint service, connections | ✅ Lines 267-312 |
| `check_security_groups()` | Security groups JSON | ✅ Lines 436-452 |
| `check_instances()` | EC2 instances JSON | ✅ Lines 324-351 |
| `check_load_balancers()` | Load balancer JSON files | ✅ Lines 202-257, 454-481 |
| `check_route53()` | Hosted zones, record sets | ✅ Lines 390-434 |
| `check_cloudtrail_logs()` | CloudTrail events JSON | ✅ Lines 369-388 |
| `check_installation_status()` | Cluster JSON, resources JSON | ✅ Lines 20-44 |

---

## Workflow Summary

```
┌─────────────────────────────────────────────────────────────────────┐
│                    get_install_artifacts.sh Workflow                │
└─────────────────────────────────────────────────────────────────────┘

1. Validate Inputs
   └─> Require cluster ID

2. Fetch OCM Metadata
   ├─> cluster.json (configuration)
   └─> resources.json (install logs)

3. Parse Install Logs (Python)
   ├─> Extract instance IDs
   ├─> Extract load balancer ARNs
   ├─> Extract VPC IDs
   └─> Extract security group IDs

4. Collect VPC Data (for each VPC)
   ├─> VPC details
   ├─> DNS hostname attribute
   ├─> DNS support attribute
   └─> DHCP options

5. Collect VPC Endpoints (if PrivateLink)
   ├─> VPC endpoint service config
   └─> VPC endpoint connections

6. Collect EC2 Data
   ├─> All instances (JSON)
   └─> Console logs (per instance)

7. Collect Load Balancer Data
   ├─> All load balancers
   └─> Cluster-tagged LBs

8. Collect Route53 Data
   ├─> Hosted zones
   ├─> API records
   └─> Apps records

9. Collect Security Data
   ├─> Security groups
   └─> CloudTrail logs (2-hour window)

10. Display Summary Tables
    ├─> Instance table with roles
    └─> Cluster resource counts
```

---

## Common Use Cases

### 1. Cluster Installation Failure Investigation
Collects all resources involved in cluster creation to identify what went wrong during bootstrap.

### 2. Post-Mortem Analysis
Provides complete snapshot of cluster state at creation time, including CloudTrail audit trail.

### 3. Network Troubleshooting
Gathers VPC, security group, load balancer, and DNS data to diagnose connectivity issues.

### 4. Compliance Auditing
CloudTrail logs show who did what during cluster creation (via CloudTrail events).

### 5. Offline Analysis
All data saved locally allows analysis without AWS API access (useful for check_aws_health.py).

---

## Design Principles

1. **Idempotent** - Safe to run multiple times
2. **Comprehensive** - Collects all relevant cluster data
3. **Efficient** - Reuses cached files
4. **Self-documenting** - Echoes all commands before execution
5. **Error-tolerant** - Continues on individual failures
6. **Offline-friendly** - Saves everything locally for later analysis