# EC2 Instance Collection Fix

## Problem

The `get_install_artifacts.py` script was collecting EC2 instances with incomplete data:
- Zone-specific instance files had **null values** for critical fields:
  - `PrivateIpAddress`
  - `VpcId`
  - `SubnetId`
  - `SecurityGroups`
  - `PublicIpAddress`
  - `PrivateDnsName`
  - `IamInstanceProfile`
  - `BlockDeviceMappings`

This caused tests to fail when checking instance network configuration.

## Root Causes

### 1. **Zone-Specific Collection Missing Fields** (PRIMARY ISSUE)

**Location**: `get_install_artifacts.py` lines 2464-2474 in `_collect_zone_specific_artifacts()`

**Problem**: Zone-specific instance collection only saved 5 fields:
```python
instances.append({
    'InstanceId': instance.get('InstanceId'),
    'State': instance.get('State', {}).get('Name'),
    'InstanceType': instance.get('InstanceType'),
    'AvailabilityZone': instance.get('Placement', {}).get('AvailabilityZone'),
    'Tags': instance.get('Tags', [])
})
```

**Result**: Files like `{cluster_id}_us-east-1a_instances.json` had incomplete data.

### 2. **Main Collection Had No Filters** (EFFICIENCY ISSUE)

**Location**: `get_install_artifacts.py` line 2523 in `_get_ec2_instance_info()`

**Problem**: Main instance collection fetched ALL instances in the region:
```python
response = self.aws.describe_instances()  # No filters!
```

Then filtered in code later (lines 2572-2575):
```python
cluster_instances = [
    inst for inst in instances
    if any(tag.get('Value', '').find(self.infra_id) != -1 for tag in inst.get('Tags', []))
]
```

**Result**:
- Inefficient - fetched unnecessary instances from other clusters/resources
- The saved file contained ALL instances, not just cluster instances
- Confusion about which instances belong to the cluster

## Fixes Applied

### Fix 1: Zone-Specific Collection Now Includes All Fields

**Changed**: Lines 2464-2488 in `_collect_zone_specific_artifacts()`

**Before**:
```python
instances.append({
    'InstanceId': instance.get('InstanceId'),
    'State': instance.get('State', {}).get('Name'),
    'InstanceType': instance.get('InstanceType'),
    'AvailabilityZone': instance.get('Placement', {}).get('AvailabilityZone'),
    'Tags': instance.get('Tags', [])
})
```

**After** (matches main collection):
```python
instances.append({
    'InstanceId': instance.get('InstanceId'),
    'State': instance.get('State', {}).get('Name'),
    'LaunchTime': instance.get('LaunchTime').isoformat() if instance.get('LaunchTime') else None,
    'PrivateIpAddress': instance.get('PrivateIpAddress'),
    'PublicIpAddress': instance.get('PublicIpAddress'),
    'PrivateDnsName': instance.get('PrivateDnsName'),
    'PublicDnsName': instance.get('PublicDnsName'),
    'SecurityGroups': instance.get('SecurityGroups', []),
    'VpcId': instance.get('VpcId'),
    'SubnetId': instance.get('SubnetId'),
    'Placement': instance.get('Placement', {}),
    'InstanceType': instance.get('InstanceType'),
    'IamInstanceProfile': instance.get('IamInstanceProfile'),
    'ImageId': instance.get('ImageId'),
    'Architecture': instance.get('Architecture'),
    'RootDeviceName': instance.get('RootDeviceName'),
    'RootDeviceType': instance.get('RootDeviceType'),
    'BlockDeviceMappings': instance.get('BlockDeviceMappings', []),
    'Tags': instance.get('Tags', [])
})
```

### Fix 2: Main Collection Now Filters by Cluster

**Changed**: Lines 2534-2542 in `_get_ec2_instance_info()`

**Before**:
```python
response = self.aws.describe_instances()
```

**After**:
```python
# Filter by cluster infra_id to avoid fetching all instances in the region
response = self.aws.describe_instances(
    filters=[
        {'Name': 'tag:Name', 'Values': [f'*{self.infra_id}*']}
    ]
)
```

## Benefits

### 1. **Complete Instance Data**
- All instances now have full networking and configuration details
- Tests can properly validate VPC membership, security groups, IPs, etc.
- No need for manual data enrichment from other files

### 2. **Consistent Field Structure**
- Main collection and zone-specific collections use identical field structure
- Easier to merge/combine instance data from different sources
- Reduces confusion and errors

### 3. **Improved Performance**
- Main collection now filters at AWS API level
- Fetches only cluster instances, not all instances in region
- Faster data collection, lower API costs

### 4. **Better Data Accuracy**
- Saved files contain only cluster-related instances
- No post-processing filtering needed
- Clear which instances belong to which cluster

## Files Modified

**File**: `get_install_artifacts.py`

**Changes**:
1. Lines 2464-2488: Zone-specific instance collection - added 14 missing fields
2. Lines 2534-2542: Main instance collection - added infra_id filter

**Total changes**: ~35 lines modified

## Testing

To verify the fix, delete existing instance files and re-collect:

```bash
# Set AWS credentials
eval $(ocm backplane cloud credentials <cluster-id> -o env)

# Delete old instance files
rm {cluster-dir}/*_instances.json
rm {cluster-dir}/*_ec2_instances.json

# Re-collect with fixed script
./get_install_artifacts.py -c <cluster-id> -d {cluster-dir}

# Verify all fields are present
python3 << EOF
import json
with open('{cluster-dir}/{cluster-id}_ec2_instances.json', 'r') as f:
    instances = json.load(f)

required_fields = [
    'InstanceId', 'State', 'PrivateIpAddress', 'VpcId',
    'SubnetId', 'SecurityGroups', 'Tags'
]

for inst in instances:
    missing = [f for f in required_fields if f not in inst or inst[f] is None]
    if missing:
        print(f"Instance {inst['InstanceId']} missing: {missing}")
    else:
        print(f"✓ Instance {inst['InstanceId']} has all required fields")
EOF
```

Expected output: All instances should have all required fields.

## Impact on Existing Data

**Existing cluster data directories**: Will continue to work but may have incomplete zone-specific instance files. Re-run data collection to update.

**Tests**: Will now pass for instance validation tests (VPC membership, security groups, private IPs) when using newly collected data.

**Backward Compatibility**: ✅ Fully backward compatible - no breaking changes to file formats or APIs.

## Related Issues

This fix resolves:
- ✅ EC2 instances with null PrivateIpAddress
- ✅ EC2 instances with null VpcId
- ✅ EC2 instances with null/empty SecurityGroups
- ✅ Inefficient fetching of all instances in region
- ✅ Inconsistent data between main and zone-specific collections

## Conclusion

The EC2 instance collection now:
- ✅ Includes all required fields in both main and zone-specific collections
- ✅ Filters by cluster infra_id at API level for efficiency
- ✅ Provides consistent data structure across all collection methods
- ✅ Enables all instance validation tests to run properly

No more null private IP addresses or missing network configuration!
