# BYO VPC (Bring Your Own VPC) Support

## Overview

This feature adds comprehensive support for ROSA clusters deployed into customer-provided (BYO) VPCs. The system now handles two scenarios:

1. **BYO VPC Clusters**: Subnet IDs specified in `cluster.json` at `aws.subnet_ids`
2. **Installer-Provisioned VPCs**: Subnets discovered via infrastructure ID tags

## Architecture Changes

### Data Collection (`get_install_artifacts.py`)

#### New Methods

##### `_get_subnets_and_vpcs_from_cluster_json()`
- **Purpose**: Fetch subnets and VPCs for BYO VPC configurations
- **Location**: Lines 1495-1580
- **Behavior**:
  1. Checks `cluster.json` for `aws.subnet_ids`
  2. If found, fetches each subnet individually from AWS
  3. Saves each subnet to `<cluster_id>_<subnet_id>.json`
  4. Extracts VPC IDs from subnet data
  5. Calls `_fetch_vpc_details()` for each discovered VPC

**Output Files**:
- `<cluster_id>_<subnet_id>.json` - Individual subnet details
- Subnet IDs from cluster.json: `['subnet-abc123', 'subnet-def456']`

##### `_fetch_vpc_details(vpc_id: str)`
- **Purpose**: Fetch complete VPC information including DNS attributes
- **Location**: Lines 1582-1634
- **Behavior**:
  1. Fetches main VPC details
  2. Saves to `<cluster_id>_<vpc_id>_VPC.json`
  3. Fetches DNS hostname attribute
  4. Saves to `<cluster_id>_<vpc_id>_VPC_attrDnsHost.json`
  5. Fetches DNS support attribute
  6. Saves to `<cluster_id>_<vpc_id>_VPC_attrDnsSupp.json`

**Output Files**:
- `<cluster_id>_vpc-abc123_VPC.json` - Main VPC details
- `<cluster_id>_vpc-abc123_VPC_attrDnsHost.json` - DNS hostname attribute
- `<cluster_id>_vpc-abc123_VPC_attrDnsSupp.json` - DNS support attribute

#### Execution Flow

The main collection flow (lines 1075-1081) now follows this sequence:

```python
# 1. BYO VPC subnet fetch from cluster.json (new)
self._get_subnets_and_vpcs_from_cluster_json()

# 2. Tag-based VPC discovery (existing)
self._get_vpc_info()

# 3. Tag-based network infrastructure discovery (existing)
self._get_network_infrastructure()
```

This layered approach ensures both BYO and installer-provisioned scenarios are handled.

---

## Test Suite (`tests/test_byo_vpc.py`)

### Test Categories

#### 1. Configuration Detection
**Test**: `test_byo_vpc_subnets_configuration_exists`
- Validates `aws.subnet_ids` exists in cluster.json
- Skips if not a BYO VPC cluster
- **Pass Criteria**: subnet_ids is a non-empty list

#### 2. Subnet Availability
**Test**: `test_byo_vpc_all_subnets_fetched`
- Ensures all subnets from cluster.json were fetched from AWS
- **Why Critical**: Missing subnets indicate deleted infrastructure or permission issues
- **Pass Criteria**: All subnet files exist on disk
- **Failure Guidance**: Run `get_install_artifacts.py` to fetch missing subnets

#### 3. VPC Consistency
**Test**: `test_byo_vpc_subnets_in_same_vpc`
- Validates all subnets are in the same VPC
- **Why Critical**: ROSA requires single VPC for cluster networking
- **Pass Criteria**: All subnets have identical VpcId
- **Failure Message**: Shows which subnet is in which VPC (e.g., `subnet-abc→vpc-123, subnet-def→vpc-456`)

#### 4. Cluster Tagging - Subnets
**Test**: `test_byo_vpc_subnets_have_cluster_tags`
- Validates subnets have `kubernetes.io/cluster/<infra_id>` tag
- **Why Critical**: Required for Kubernetes cloud provider resource discovery
- **Pass Criteria**: All subnets tagged with cluster infra_id
- **Failure Impact**:
  - Load balancer provisioning may fail
  - Resource cleanup may be incomplete
  - AWS resource discovery breaks

#### 5. Role Tagging - Subnets
**Test**: `test_byo_vpc_subnets_have_role_tags`
- Validates subnets have role tags:
  - `kubernetes.io/role/elb` for public subnets
  - `kubernetes.io/role/internal-elb` for private subnets
- **Why Critical**: Kubernetes uses these to determine LB placement
- **Pass Criteria**: Each subnet has at least one role tag
- **Failure Impact**: Load balancers may provision in wrong subnets

#### 6. Cluster Tagging - VPC
**Test**: `test_byo_vpc_has_correct_tags`
- Validates VPC has `kubernetes.io/cluster/<infra_id>` tag
- **Why Critical**: Required for VPC resource discovery
- **Pass Criteria**: VPC tagged with cluster infra_id
- **Failure Impact**: Cluster networking may not function correctly

#### 7. Subnet State
**Test**: `test_byo_vpc_subnets_available`
- Validates all subnets are in 'available' state
- **Why Critical**: Only available subnets can be used by the cluster
- **Pass Criteria**: All subnets have `State: 'available'`
- **Failure Impact**: Cluster may not provision or function correctly

#### 8. CIDR Validation
**Test**: `test_byo_vpc_subnet_cidr_within_vpc_cidr`
- Validates subnet CIDR blocks are within VPC CIDR
- **Why Critical**: AWS networking requirement for proper routing
- **Pass Criteria**: All subnet CIDRs are subnets of VPC CIDR
- **Uses**: Python `ipaddress` module for CIDR arithmetic
- **Example Failure**: `subnet-123 (10.1.0.0/24 not in VPC 10.0.0.0/16)`

---

## File Naming Conventions

### Individual Subnet Files
**Format**: `<cluster_id>_<subnet_id>.json`

**Example**: `2mmfeq6n72nis2kekgvim4k1lmrho0ri_subnet-0f0474abff2efdf88.json`

**Content Structure**:
```json
{
  "Subnets": [
    {
      "SubnetId": "subnet-0f0474abff2efdf88",
      "VpcId": "vpc-09f77cd18941ce59a",
      "CidrBlock": "10.0.64.0/18",
      "AvailabilityZone": "us-west-2a",
      "State": "available",
      "Tags": [
        {
          "Key": "kubernetes.io/cluster/maclarkrosa1120-vrrvr",
          "Value": "owned"
        },
        {
          "Key": "kubernetes.io/role/elb",
          "Value": "1"
        }
      ]
    }
  ],
  "ResponseMetadata": { ... }
}
```

### VPC Files
**Format**: `<cluster_id>_<vpc_id>_VPC.json`

**Example**: `2mmfeq6n72nis2kekgvim4k1lmrho0ri_vpc-09f77cd18941ce59a_VPC.json`

### VPC DNS Attribute Files
**Formats**:
- `<cluster_id>_<vpc_id>_VPC_attrDnsHost.json` - DNS hostnames
- `<cluster_id>_<vpc_id>_VPC_attrDnsSupp.json` - DNS support

---

## cluster.json Structure

### BYO VPC Configuration
For clusters with customer-provided VPCs, subnet IDs are specified in the cluster configuration:

```json
{
  "id": "2mmfeq6n72nis2kekgvim4k1lmrho0ri",
  "infra_id": "maclarkrosa1120-vrrvr",
  "aws": {
    "subnet_ids": [
      "subnet-0f0474abff2efdf88",
      "subnet-0fd643b54bc926445"
    ]
  }
}
```

### Detection Logic
```python
subnet_ids = cluster_data.get('aws', {}).get('subnet_ids', [])
is_byo_vpc = len(subnet_ids) > 0
```

---

## Usage Examples

### Running Data Collection

```bash
# Standard collection (handles both BYO and installer-provisioned)
python get_install_artifacts.py --cluster-name my-rosa-cluster

# The script will:
# 1. Load cluster.json
# 2. Check for aws.subnet_ids
# 3. If found, fetch each subnet individually
# 4. Extract VPC IDs and fetch VPC details
# 5. Fall back to tag-based discovery for remaining resources
```

### Running BYO VPC Tests

```bash
# Run all BYO VPC tests
pytest tests/test_byo_vpc.py --cluster-dir=<data_directory> -v

# Run specific test
pytest tests/test_byo_vpc.py::test_byo_vpc_subnets_have_cluster_tags \
  --cluster-dir=<data_directory> -v

# Run with detailed output
pytest tests/test_byo_vpc.py --cluster-dir=<data_directory> -vv
```

### Expected Behavior

**For BYO VPC Clusters**:
- All 8 tests execute validation
- Tests fail if configuration is incorrect
- Detailed failure messages guide remediation

**For Installer-Provisioned Clusters**:
- All 8 tests skip with message: "Not a BYO VPC cluster"
- No false failures for non-BYO clusters

---

## AWS Permissions Required

### For Subnet Fetching
```json
{
  "Effect": "Allow",
  "Action": [
    "ec2:DescribeSubnets"
  ],
  "Resource": "*"
}
```

### For VPC Fetching
```json
{
  "Effect": "Allow",
  "Action": [
    "ec2:DescribeVpcs",
    "ec2:DescribeVpcAttribute"
  ],
  "Resource": "*"
}
```

---

## Error Handling

### Subnet Not Found
**Scenario**: Subnet ID in cluster.json doesn't exist in AWS

**Error Message**:
```
Subnet subnet-abc123 not found in AWS!
```

**Common Causes**:
- Subnet was deleted after cluster creation
- Wrong AWS account/region
- Insufficient permissions

**Test Failure**:
```
test_byo_vpc_all_subnets_fetched FAILED
AssertionError: Subnet files not found for: subnet-abc123.
Run get_install_artifacts.py to fetch missing subnets.
```

### VPC Mismatch
**Scenario**: Subnets are in different VPCs

**Test Failure**:
```
test_byo_vpc_subnets_in_same_vpc FAILED
AssertionError: Subnets are in 2 different VPCs:
  subnet-abc123→vpc-111111, subnet-def456→vpc-222222
```

### Missing Tags
**Scenario**: Subnet missing required cluster tag

**Test Failure**:
```
test_byo_vpc_subnets_have_cluster_tags FAILED
AssertionError: Subnets missing required tag
  'kubernetes.io/cluster/my-infra-id': subnet-abc123
```

---

## Troubleshooting Guide

### Problem: Tests are skipping
**Solution**: This is expected if not a BYO VPC cluster. Check if `aws.subnet_ids` exists in cluster.json:

```bash
jq '.aws.subnet_ids' <cluster_id>_cluster.json
```

### Problem: Subnet files missing
**Solution**: Re-run data collection:

```bash
python get_install_artifacts.py --cluster-name <cluster-name>
```

### Problem: CIDR validation failing
**Cause**: Subnet CIDR not within VPC CIDR

**Investigation**:
```bash
# Check VPC CIDR
jq '.Vpcs[0].CidrBlock' <cluster_id>_<vpc_id>_VPC.json

# Check subnet CIDRs
jq '.Subnets[0].CidrBlock' <cluster_id>_<subnet_id>.json
```

**Fix**: Subnet CIDRs must be within VPC CIDR range. This is an AWS infrastructure issue requiring subnet reconfiguration.

### Problem: Tag validation failing
**Cause**: Missing or incorrect tags on subnets/VPC

**Investigation**:
```bash
# Check subnet tags
jq '.Subnets[0].Tags' <cluster_id>_<subnet_id>.json

# Check VPC tags
jq '.Vpcs[0].Tags' <cluster_id>_<vpc_id>_VPC.json
```

**Fix**: Add missing tags using AWS CLI:

```bash
# Tag subnet
aws ec2 create-tags \
  --resources subnet-abc123 \
  --tags Key=kubernetes.io/cluster/<infra-id>,Value=owned

# Tag subnet with role
aws ec2 create-tags \
  --resources subnet-abc123 \
  --tags Key=kubernetes.io/role/elb,Value=1
```

---

## Integration with Existing Tests

The BYO VPC tests complement existing network tests:

- **Existing `test_network.py`**: Validates tag-discovered subnets
- **New `test_byo_vpc.py`**: Validates cluster.json-specified subnets

Both test suites can run simultaneously:
- BYO VPC cluster: Both sets execute
- Installer-provisioned: Only `test_network.py` executes, `test_byo_vpc.py` skips

---

## Future Enhancements

### Potential Additions

1. **Multi-AZ Validation**
   - Ensure subnets span multiple availability zones
   - Validate even distribution across AZs

2. **Subnet Size Validation**
   - Check subnet has sufficient available IPs
   - Warn if approaching capacity

3. **Route Table Validation**
   - Verify public subnets have IGW route
   - Verify private subnets have NAT route

4. **Security Group Validation**
   - Check default VPC security group configuration
   - Validate NACL rules

---

## References

### AWS Documentation
- [VPC and Subnet Sizing](https://docs.aws.amazon.com/vpc/latest/userguide/VPC_Subnets.html)
- [VPC Resource Tagging](https://docs.aws.amazon.com/vpc/latest/userguide/vpc-tagging.html)

### Kubernetes Documentation
- [Cloud Provider AWS](https://kubernetes.io/docs/concepts/cluster-administration/cloud-providers/)
- [AWS Load Balancer Controller](https://kubernetes-sigs.github.io/aws-load-balancer-controller/)

### ROSA Documentation
- [ROSA VPC Requirements](https://docs.openshift.com/rosa/rosa_install_access_delete_clusters/rosa_getting_started_iam/rosa-aws-prereqs.html)
- [ROSA Network Configuration](https://docs.openshift.com/rosa/networking/rosa-vpc-interface-endpoints.html)
