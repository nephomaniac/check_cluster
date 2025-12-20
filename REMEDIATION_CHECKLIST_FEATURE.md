# Interactive Remediation Checklist Feature

## Overview
Enhanced load balancer target health tests with interactive HTML remediation checklists that link directly to related test results and show real-time status indicators.

## Implementation Summary

### Components Added

#### 1. Test Helper Functions (test_load_balancer_target_health.py)

**`get_test_result_status(request, test_name: str) -> str`**
- Retrieves the current status of a specific test from the pytest session
- Returns: 'passed', 'failed', 'skipped', 'error', or 'unknown'
- Enables dynamic status checking for remediation checklist items

**`build_remediation_checklist(request, resource_type: str) -> dict`**
- Builds comprehensive remediation checklist data structure
- Maps remediation steps to actual test cases
- Retrieves live test statuses
- Returns structured data for HTML rendering

**Checklist Structure:**
```python
{
    "resource_type": "API Server",  # or "MCS"
    "port": "6443",  # or "22623" for MCS
    "checklist": [
        {
            "category": "1. Instance Not Running",
            "checks": [
                {
                    "description": "Verify instances are in running state",
                    "test": "test_control_plane_instances_running",
                    "test_file": "tests/test_instances.py",
                    "can_validate": True,
                    "status": "passed",  # dynamically retrieved
                    "note": "Optional explanatory note"
                }
            ]
        }
        # ... 4 more categories
    ]
}
```

#### 2. HTML Generator Enhancement (reporters/html_generator.py)

**`_generate_remediation_checklist_html(test: Dict[str, Any]) -> str`**
- Extracts remediation_checklist from test user_properties
- Renders interactive HTML checklist with:
  - **Status Indicators**:
    - ✓ Green (PASSED) - Test passed, issue resolved
    - ✗ Red (FAILED) - Test failed, issue present
    - ⚠ Orange (ERROR) - Test encountered Python exception
    - ○ Yellow (SKIPPED) - Test was skipped
    - ⚙ Grey (MANUAL) - Manual check required
    - ? Grey (UNKNOWN) - Status unavailable
  - **Clickable Links**: Direct links to related test results
  - **Manual Commands**: Shell commands for manual checks
  - **Contextual Notes**: Additional information where needed

**Integration:**
- Added to test details section for failed/skipped tests
- Positioned after failure details, before API requests
- Only shown when remediation checklist data is available

### 3. Remediation Coverage

#### Category 1: Instance Not Running
- **Test Coverage**: test_control_plane_instances_running
- **CloudTrail**: Checks for Stop/Terminate events (in-test correlation)
- **Coverage**: 100% automated validation

#### Category 2: Security Group Blocking Port 6443/22623
- **Test Coverage**:
  - test_controlplane_api_server_access (port validation)
  - test_no_security_group_revocations (CloudTrail)
- **Coverage**: 100% automated validation

#### Category 3: API Server/MCS Not Responding
- **Test Coverage**: Manual (requires SSH access to instances)
- **Manual Commands**: Provided for crictl, systemctl, journalctl
- **Coverage**: 0% automated (infrastructure limitation)

#### Category 4: etcd/Bootstrap Dependencies
- **Test Coverage**: Manual (requires SSH access to instances)
- **Manual Commands**: Provided for service status checks
- **Coverage**: 0% automated (infrastructure limitation)

#### Category 5: Network Connectivity
- **Test Coverage**:
  - test_private_route_to_nat_gateway (NAT routing)
  - test_public_route_to_internet_gateway (IGW routing)
  - test_subnets_exist (subnet configuration)
  - test_network_acls_exist (ACL validation)
- **Coverage**: 100% automated validation

### Overall Coverage
- **Automated Checks**: 8 out of 12 remediation items (67%)
- **Manual Checks**: 4 out of 12 items (33%) - require SSH access
- **Artifact-Based Coverage**: 100% of checks possible with AWS API artifacts

## Usage

### For Test Developers
1. Import helper functions in test file
2. Build checklist: `checklist_data = build_remediation_checklist(request, resource_type="API Server")`
3. Store in user_properties: `request.node.user_properties.append(("remediation_checklist", checklist_data))`
4. HTML generator automatically renders checklist for failed/skipped tests

### For Users Viewing Reports
1. Open HTML report
2. Navigate to failed load balancer target health test
3. Click "View Details" button
4. Scroll to "Interactive Remediation Checklist" section
5. See status indicators for each remediation step
6. Click test links to jump to related test results
7. Use manual commands for items requiring SSH access

## Visual Design

### Status Indicators
- **Circle badges** with icon, color-coded by status
- **Left border** color matches status for visual scanning
- **Status labels** (PASSED/FAILED/ERROR/SKIPPED/MANUAL/UNKNOWN)

### Layout
- **Hierarchical structure**: Categories > Checks
- **Flex layout**: Icon on left, content on right
- **Responsive**: Works on various screen sizes
- **Light background**: Distinguishes from other sections

## Benefits

1. **Faster Troubleshooting**: See at a glance which remediation steps are already validated
2. **Guided Investigation**: Follow checklist from top to bottom
3. **Cross-Referenced Tests**: Jump directly to related test results
4. **Manual Guidance**: Commands provided for checks requiring SSH
5. **Live Status**: Status indicators update with each test run
6. **Educational**: Learn the relationship between failures and remediation steps

## Example Output

When a target health test fails, users see:

```
🔧 Interactive Remediation Checklist for API Server

1. Instance Not Running
  ✓ PASSED → test_control_plane_instances_running
    Verify instances are in running state

  ✓ PASSED → test_no_security_group_revocations
    Check CloudTrail for Stop/Terminate events

2. Security Group Blocking Port 6443
  ✗ FAILED → test_controlplane_api_server_access
    Verify security groups allow TCP 6443

  ✓ PASSED → test_no_security_group_revocations
    Check for RevokeSecurityGroupIngress events

3. API Server Not Responding
  ⚙ MANUAL: ssh core@<instance-ip> sudo crictl ps | grep kube-apiserver
    SSH to instance and check service status

  ⚙ MANUAL: ssh core@<instance-ip> sudo crictl logs <container-id>
    View service logs

4. etcd Not Available
  ⚙ MANUAL: ssh core@<instance-ip> sudo crictl ps | grep etcd
    Check etcd status

5. Network Connectivity
  ✓ PASSED → test_private_route_to_nat_gateway
    Verify route tables configuration

  ✓ PASSED → test_public_route_to_internet_gateway
    Verify public routes to internet gateway

  ✓ PASSED → test_subnets_exist
    Verify subnet configuration

  ✓ PASSED → test_network_acls_exist
    Check Network ACLs
```

## Files Modified

1. **tests/test_load_balancer_target_health.py**
   - Added get_test_result_status() helper
   - Added build_remediation_checklist() helper
   - Updated test_api_server_targets_healthy() to generate and store checklist
   - Updated test_machine_config_server_targets_healthy() to generate and store checklist

2. **reporters/html_generator.py**
   - Added _generate_remediation_checklist_html() method
   - Integrated checklist generation for failed/skipped tests
   - Added checklist HTML to test details output

## Future Enhancements

1. **Add SSH-based tests**: If infrastructure allows SSH access during test run
2. **Expand coverage**: Add checklists to other critical failure points
3. **Interactive filtering**: Allow users to filter checklist by status
4. **Export**: Enable checklist export as markdown or PDF
5. **Historical tracking**: Show checklist status across multiple test runs
