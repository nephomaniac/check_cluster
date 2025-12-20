# OpenShift Installation Progress and Status Tests

## Overview

The OpenShift installation tests validate cluster installation status by analyzing multiple data sources to determine installation phase, progress, and identify where errors occurred during the installation process.

## Based On

### Official Documentation
- **OpenShift Installation Overview**: [Red Hat Documentation](https://docs.redhat.com/en/documentation/openshift_container_platform/4.13/html/installation_overview/ocp-installation-overview)
- **Troubleshooting Installations**: [OKD Documentation](https://docs.okd.io/latest/support/troubleshooting/troubleshooting-installations.html)
- **Bootstrap Process**: [DeepWiki - OpenShift Appliance](https://deepwiki.com/openshift/appliance/5.1-bootstrap-process)
- **Troubleshooting Bootstrap**: [GitHub - openshift/installer](https://github.com/openshift/installer/blob/main/docs/user/troubleshootingbootstrap.md)

### OpenShift Ignition Project
- **Ignition Overview**: [Red Hat Blog](https://www.redhat.com/en/blog/openshift-4.x-installation-quick-overview)
- **Installation Process**: [Medium - OpenShift Installation](https://rdalal3.medium.com/openshift-installation-process-a750d490f21b)

## Installation Phases

### 1. Ignition Configuration Phase
**What happens:**
- Ignition configuration files are created: `bootstrap.ign`, `master.ign`, `worker.ign`
- These files contain the initial node configuration including systemd services, storage files, and scripts

**Validation:**
- Ignition configuration files are accessible
- Proper S3 bucket permissions configured (for cloud installs)
- Network connectivity to ignition source

### 2. Bootstrap Node Initialization
**What happens:**
- Bootstrap machine boots using `bootstrap.ign`
- Temporary etcd cluster starts
- Temporary Kubernetes control plane starts
- Machine Config Server (MCS) starts

**Validation:**
- Bootstrap instance launched
- Console logs show ignition fetch success
- Bootstrap services started

### 3. Control Plane Bootstrap
**What happens:**
- Control plane instances fetch `master.ign` (stage-1)
- Control plane instances get full config from MCS (stage-2)
- Control plane instances start etcd
- Control plane joins bootstrap etcd cluster

**Validation:**
- All 3 control plane instances running
- Console logs show ignition applied
- etcd processes started

### 4. Production Control Plane Activation
**What happens:**
- etcd quorum formed (3 nodes)
- Production Kubernetes API server starts
- Cluster Version Operator (CVO) deploys
- Temporary control plane transfers control to production

**Validation:**
- etcd quorum achieved (3 of 3 nodes)
- Kubernetes API accessible
- CVO running

### 5. Cluster Operators Deployment
**What happens:**
- CVO deploys cluster operators
- etcd Operator scales etcd to all control plane nodes
- Cluster operators initialize cluster services

**Validation:**
- Cluster operators deployed
- Required operators available
- Operator status healthy

### 6. Bootstrap Completion and Cleanup
**What happens:**
- Bootstrap node completes preparation tasks
- Cluster reaches "preparing-for-installation" status
- Bootstrap machine is destroyed
- Production control plane fully operational

**Validation:**
- Cluster state becomes "ready"
- Bootstrap instance terminated
- API server fully operational

### 7. Worker Node Joining
**What happens:**
- Worker nodes fetch `worker.ign` (stage-1)
- Worker nodes get full config from MCS (stage-2)
- Worker nodes join cluster
- Workload scheduling enabled

**Validation:**
- Worker instances running
- Nodes joined cluster
- kubelet services running

## Test Files

### `test_openshift_installation_progress.py`

#### Test Functions

##### 1. `test_installation_phase_detection()`
**Purpose**: Detect and report current installation phase

**What it checks:**
- Cluster state from OCM
- Control plane instance status
- Worker instance status
- Installation progress percentage

**Output:**
- Current phase
- Progress percentage (0-100%)
- Completed stages
- Current stage
- Next expected stage
- Error indicators

**Example Output:**
```
📊 Installation Phase Detection
────────────────────────────────────────────────────────────────────────────────
Current Phase: control_plane_bootstrap
Progress: 40%
Description: Control plane instances running, waiting for etcd quorum

✓ Completed Stages:
  • Ignition Configuration
  • Bootstrap Initialization

⏳ Current Stage: Control plane running - operators deploying
➡️  Next Expected: Bootstrap completion
────────────────────────────────────────────────────────────────────────────────
```

##### 2. `test_cluster_installation_state()`
**Purpose**: Validate cluster installation state

**What it checks:**
- Cluster state is valid (ready, installing, error)
- State categorization
- Operational status

**States:**
- **Ready**: `ready`, `installed`, `active`
- **In Progress**: `installing`, `pending`, `validating`
- **Error**: `error`, `failed`, `degraded`

**Failure scenarios:**
- Cluster in error state → Provides phase info and investigation steps
- Cluster not in ready state when expected

##### 3. `test_control_plane_bootstrap_status()`
**Purpose**: Verify control plane bootstrap completion

**What it checks:**
- Control plane instances exist (expected: 3 for HA)
- All control plane instances running
- Cluster state indicates bootstrap complete

**Failure scenarios:**
- No control plane instances found
  - Provides causes and remediation steps
- Some control plane instances not running
  - Details on which instances are down
- Bootstrap in progress
  - Skips with status details

##### 4. `test_console_log_analysis_master()`
**Purpose**: Analyze EC2 console logs for installation progress

**What it checks:**
- Ignition fetch status
- Ignition application status
- Bootstrap service status
- etcd service status
- kubelet service status
- Error patterns
- Warning patterns

**Console Log Markers Detected:**

**Ignition:**
- `Ignition.*fetch.*success`
- `Ignition.*ran.*successfully`
- `Applied.*ignition.*config`

**Services:**
- `bootkube.*service.*started`
- `etcd.*started`
- `kubelet.*started`

**Errors:**
- `Failed to fetch.*ignition`
- `etcd.*failed`
- `kubelet.*failed`
- `timeout`
- `Connection refused`

**Output:**
```
📊 Control Plane Console Log Analysis
File: cluster123_i-abc123_console.txt
────────────────────────────────────────────────────────────────────────────────
{
  "IgnitionFetched": true,
  "IgnitionApplied": true,
  "BootstrapStarted": true,
  "etcdStarted": true,
  "KubeletStarted": true,
  "CurrentStage": "kubelet_running",
  "ErrorCount": 2,
  "WarningCount": 5
}
────────────────────────────────────────────────────────────────────────────────

❌ Errors Found (2):

  Line 1234: Ignition fetch failure
  Failed to fetch ignition config from https://...
```

##### 5. `test_ignition_configuration_accessible()`
**Purpose**: Verify Ignition configuration was accessible

**What it checks:**
- OCM resources for ignition-related configuration
- Ignition URLs in cluster.json
- S3 bucket access markers

**Note**: Full validation requires console log analysis

##### 6. `test_cluster_operators_deployment_status()`
**Purpose**: Check cluster operators deployment

**What it checks:**
- Cluster state is ready (operators deploy after bootstrap)
- Operator resources exist

**Note**: Detailed operator validation requires OpenShift API access

##### 7. `test_bootstrap_completion_indicators()`
**Purpose**: Validate bootstrap completion

**Indicators checked:**
- ✅ Cluster state is ready
- ✅ All control plane instances running
- ✅ No bootstrap instances exist
- ✅ API URL configured

**Output:**
```
📊 Bootstrap Completion Indicators
────────────────────────────────────────────────────────────────────────────────
{
  "cluster_ready": true,
  "control_plane_running": true,
  "no_bootstrap_instances": true,
  "api_url_configured": true
}
────────────────────────────────────────────────────────────────────────────────

✓ All bootstrap completion indicators met
  Bootstrap completed successfully
```

##### 8. `test_etcd_quorum_formation()`
**Purpose**: Verify etcd quorum formation

**What it checks:**
- Control plane instances exist (3 for HA)
- Quorum possible (need majority: 2 of 3)
- All nodes running (ideal: 3 of 3)

**Quorum requirements:**
- **3-node cluster**: Need 2 running for quorum
- **5-node cluster**: Need 3 running for quorum

**Output:**
```
📊 etcd Quorum Status
────────────────────────────────────────────────────────────────────────────────
{
  "ExpectedControlPlaneNodes": 3,
  "ActualControlPlaneNodes": 3,
  "RunningControlPlaneNodes": 3,
  "QuorumRequirement": "2 of 3",
  "QuorumPossible": true,
  "AllNodesRunning": true
}
────────────────────────────────────────────────────────────────────────────────

✓ All 3 control plane nodes running
  etcd quorum can be formed (2 of 3 required)
```

## Data Sources

### 1. OCM cluster.json
**Location**: `<cluster-id>_cluster.json` or `sources/ocm/<cluster-id>_cluster.json`

**Fields used:**
- `state`: Cluster state (ready, installing, error, etc.)
- `openshift_version`: OpenShift version
- `api.url`: API endpoint URL
- `region.id`: AWS region
- `nodes`: Node configuration

### 2. OCM resources.json
**Location**: `<cluster-id>_resources.json` or `sources/ocm/<cluster-id>_resources.json`

**Fields used:**
- Ignition-related resource URLs
- Bootstrap configuration
- Install configuration

### 3. EC2 Instances
**Location**: `<cluster-id>_instances.json` or `sources/aws/<cluster-id>_instances.json`

**Used for:**
- Control plane instance detection
- Worker instance detection
- Bootstrap instance detection
- Instance state checking

### 4. EC2 Console Logs
**Location**: `<cluster-id>_<instance-id>_console.txt`

**Must be collected manually:**
```bash
# AWS Console method:
# 1. EC2 → Instances → Select instance
# 2. Actions → Monitor and troubleshoot → Get system log
# 3. Save as: <cluster-id>_<instance-id>_console.txt

# AWS CLI method:
aws ec2 get-console-output \
  --instance-id i-abc123 \
  --output text > cluster123_i-abc123_console.txt
```

**Contains:**
- Boot messages
- Ignition fetch attempts
- Ignition application status
- systemd service status
- Error messages
- Service logs

## Usage

### Run all installation tests:
```bash
pytest tests/test_openshift_installation_progress.py -v
```

### Run specific test categories:
```bash
# Ignition tests only
pytest -m ignition -v

# Bootstrap tests only
pytest -m bootstrap -v

# etcd tests only
pytest -m etcd -v

# Operators tests only
pytest -m operators -v
```

### Run installation phase detection:
```bash
pytest tests/test_openshift_installation_progress.py::test_installation_phase_detection -v -s
```

### Analyze console logs:
```bash
pytest tests/test_openshift_installation_progress.py::test_console_log_analysis_master -v -s
```

## Troubleshooting with Tests

### Scenario 1: Installation stuck, no progress

**Run:**
```bash
pytest tests/test_openshift_installation_progress.py::test_installation_phase_detection -v -s
```

**Look for:**
- Current phase and progress percentage
- Which stages completed
- What's expected next

**Example:**
```
Current Phase: bootstrap_init
Progress: 25%
Current Stage: Control plane instances launching
Next Expected: Control plane instances running
```

**Action:** Check why control plane instances aren't starting

### Scenario 2: Control plane instances won't start

**Run:**
```bash
pytest tests/test_openshift_installation_progress.py::test_control_plane_bootstrap_status -v -s
pytest tests/test_openshift_installation_progress.py::test_console_log_analysis_master -v -s
```

**Look for:**
- Instance state (pending, running, stopped)
- Console log errors
- Ignition fetch failures

**Common causes:**
- Ignition URL not accessible
- S3 bucket permissions
- Network security group rules
- Subnet routing issues

### Scenario 3: Bootstrap not completing

**Run:**
```bash
pytest tests/test_openshift_installation_progress.py::test_bootstrap_completion_indicators -v -s
pytest tests/test_openshift_installation_progress.py::test_etcd_quorum_formation -v -s
```

**Look for:**
- Which completion indicators are missing
- etcd quorum status
- Bootstrap instance still running

**Common causes:**
- etcd quorum not formed
- Control plane instances not all running
- Operator deployment failures
- Network connectivity between nodes

### Scenario 4: Cluster in error state

**Run:**
```bash
pytest tests/test_openshift_installation_progress.py::test_cluster_installation_state -v -s
pytest tests/test_openshift_installation_progress.py::test_installation_phase_detection -v -s
```

**Look for:**
- Error indicators
- Phase where failure occurred
- Suggested investigation steps

## Console Log Collection

Console logs must be collected manually for detailed analysis:

### For each master node:
```bash
# Get instance IDs
CLUSTER_ID="your-cluster-id"
MASTER_IDS=$(aws ec2 describe-instances \
  --filters "Name=tag:Name,Values=*${CLUSTER_ID}*master*" \
  --query 'Reservations[].Instances[].InstanceId' \
  --output text)

# Get console logs for each master
for INSTANCE_ID in $MASTER_IDS; do
  aws ec2 get-console-output \
    --instance-id $INSTANCE_ID \
    --output text > "${CLUSTER_ID}_${INSTANCE_ID}_console.txt"
  echo "Saved ${CLUSTER_ID}_${INSTANCE_ID}_console.txt"
done
```

### For bootstrap node (if still running):
```bash
BOOTSTRAP_ID=$(aws ec2 describe-instances \
  --filters "Name=tag:Name,Values=*${CLUSTER_ID}*bootstrap*" \
  --query 'Reservations[].Instances[].InstanceId' \
  --output text)

if [ -n "$BOOTSTRAP_ID" ]; then
  aws ec2 get-console-output \
    --instance-id $BOOTSTRAP_ID \
    --output text > "${CLUSTER_ID}_${BOOTSTRAP_ID}_bootstrap_console.txt"
  echo "Saved ${CLUSTER_ID}_${BOOTSTRAP_ID}_bootstrap_console.txt"
fi
```

## Installation Progress Flow

```
┌─────────────────────────────────────┐
│ Ignition Configuration              │ 0-10%
│ - bootstrap.ign created             │
│ - master.ign created                │
│ - worker.ign created                │
└──────────┬──────────────────────────┘
           │
           ▼
┌─────────────────────────────────────┐
│ Bootstrap Node Initialization       │ 10-25%
│ - Bootstrap instance launches       │
│ - Fetches bootstrap.ign            │
│ - Starts temporary control plane    │
│ - Starts Machine Config Server      │
└──────────┬──────────────────────────┘
           │
           ▼
┌─────────────────────────────────────┐
│ Control Plane Bootstrap             │ 25-50%
│ - Master instances launch           │
│ - Fetch master.ign (stage-1)       │
│ - Get config from MCS (stage-2)    │
│ - etcd processes start              │
└──────────┬──────────────────────────┘
           │
           ▼
┌─────────────────────────────────────┐
│ Production Control Plane            │ 50-70%
│ - etcd quorum formed (3 nodes)     │
│ - Production API server starts      │
│ - Cluster Version Operator deploys │
│ - Temporary control plane transfers│
└──────────┬──────────────────────────┘
           │
           ▼
┌─────────────────────────────────────┐
│ Cluster Operators Deployment        │ 70-85%
│ - CVO deploys all operators        │
│ - etcd Operator scales etcd        │
│ - Operators initialize services     │
└──────────┬──────────────────────────┘
           │
           ▼
┌─────────────────────────────────────┐
│ Bootstrap Completion                │ 85-95%
│ - All operators available           │
│ - Bootstrap node destroyed          │
│ - Cluster state: "ready"            │
└──────────┬──────────────────────────┘
           │
           ▼
┌─────────────────────────────────────┐
│ Worker Nodes Joining                │ 95-100%
│ - Worker instances launch           │
│ - Fetch worker.ign                 │
│ - Join cluster                      │
│ - Ready for workloads               │
└─────────────────────────────────────┘
```

## References

- [OpenShift Installation Overview](https://docs.redhat.com/en/documentation/openshift_container_platform/4.13/html/installation_overview/ocp-installation-overview)
- [Troubleshooting Installations](https://docs.okd.io/latest/support/troubleshooting/troubleshooting-installations.html)
- [Bootstrap Process](https://deepwiki.com/openshift/appliance/5.1-bootstrap-process)
- [Troubleshooting Bootstrap](https://github.com/openshift/installer/blob/main/docs/user/troubleshootingbootstrap.md)
- [OpenShift Ignition Overview](https://www.redhat.com/en/blog/openshift-4.x-installation-quick-overview)
- [Installation Process](https://rdalal3.medium.com/openshift-installation-process-a750d490f21b)
- [etcd Bootstrap Process](https://deepwiki.com/openshift/cluster-etcd-operator/4.1-bootstrap-process)
- [Control Plane Architecture](https://docs.redhat.com/en/documentation/openshift_container_platform/4.10/html/installing/index.html)
