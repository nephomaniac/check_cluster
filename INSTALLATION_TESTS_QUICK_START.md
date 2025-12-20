# OpenShift Installation Tests - Quick Start Guide

## Quick Reference

### Run All Installation Tests
```bash
pytest tests/test_openshift_installation_progress.py -v
```

### Run by Category
```bash
# Ignition configuration tests
pytest -m ignition -v

# Bootstrap process tests
pytest -m bootstrap -v

# etcd quorum tests
pytest -m etcd -v

# Cluster operators tests
pytest -m operators -v

# All installation tests
pytest -m installation -v
```

## Individual Tests

### 1. Check Installation Phase
```bash
pytest tests/test_openshift_installation_progress.py::test_installation_phase_detection -v -s
```
**Shows:** Current phase, progress %, completed stages, what's next

### 2. Check Cluster State
```bash
pytest tests/test_openshift_installation_progress.py::test_cluster_installation_state -v -s
```
**Shows:** Whether cluster is ready, installing, or in error state

### 3. Check Control Plane Bootstrap
```bash
pytest tests/test_openshift_installation_progress.py::test_control_plane_bootstrap_status -v -s
```
**Shows:** Control plane instances status, bootstrap completion

### 4. Analyze Console Logs
```bash
pytest tests/test_openshift_installation_progress.py::test_console_log_analysis_master -v -s
```
**Shows:** Ignition status, services status, errors from console logs

### 5. Check Bootstrap Completion
```bash
pytest tests/test_openshift_installation_progress.py::test_bootstrap_completion_indicators -v -s
```
**Shows:** All bootstrap completion indicators

### 6. Check etcd Quorum
```bash
pytest tests/test_openshift_installation_progress.py::test_etcd_quorum_formation -v -s
```
**Shows:** etcd quorum status, control plane node count

## Collecting Console Logs

Console logs must be collected manually from AWS:

### Quick Script
```bash
#!/bin/bash
CLUSTER_ID="your-cluster-id"

# Get master instance IDs
MASTER_IDS=$(aws ec2 describe-instances \
  --filters "Name=tag:Name,Values=*${CLUSTER_ID}*master*" \
            "Name=instance-state-name,Values=running,stopped" \
  --query 'Reservations[].Instances[].InstanceId' \
  --output text)

# Collect console logs
for INSTANCE_ID in $MASTER_IDS; do
  echo "Collecting console log for $INSTANCE_ID..."
  aws ec2 get-console-output \
    --instance-id $INSTANCE_ID \
    --output text > "${CLUSTER_ID}_${INSTANCE_ID}_console.txt"
done

echo "Console logs collected!"
```

### Manual Collection (AWS Console)
1. Go to EC2 → Instances
2. Select a master instance
3. Actions → Monitor and troubleshoot → Get system log
4. Copy and save as: `<cluster-id>_<instance-id>_console.txt`

## Common Scenarios

### Installation is Stuck
```bash
# Step 1: Check current phase
pytest tests/test_openshift_installation_progress.py::test_installation_phase_detection -v -s

# Step 2: Check control plane status
pytest tests/test_openshift_installation_progress.py::test_control_plane_bootstrap_status -v -s

# Step 3: Collect and analyze console logs
# (collect logs first, then run)
pytest tests/test_openshift_installation_progress.py::test_console_log_analysis_master -v -s
```

### Installation Failed
```bash
# Step 1: Check cluster state
pytest tests/test_openshift_installation_progress.py::test_cluster_installation_state -v -s

# Step 2: Check installation phase for error indicators
pytest tests/test_openshift_installation_progress.py::test_installation_phase_detection -v -s

# Step 3: Analyze console logs for specific errors
pytest tests/test_openshift_installation_progress.py::test_console_log_analysis_master -v -s
```

### Bootstrap Won't Complete
```bash
# Step 1: Check bootstrap indicators
pytest tests/test_openshift_installation_progress.py::test_bootstrap_completion_indicators -v -s

# Step 2: Check etcd quorum
pytest tests/test_openshift_installation_progress.py::test_etcd_quorum_formation -v -s

# Step 3: Check control plane bootstrap
pytest tests/test_openshift_installation_progress.py::test_control_plane_bootstrap_status -v -s
```

## Expected Output Examples

### Installation In Progress
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

### Installation Complete
```
📊 Installation Phase Detection
────────────────────────────────────────────────────────────────────────────────
Current Phase: installation_complete
Progress: 100%
Description: Cluster installation completed successfully

✓ Completed Stages:
  • Ignition Configuration
  • Bootstrap Initialization
  • Control Plane Bootstrap
  • Production Control Plane
  • Cluster Operators
  • Bootstrap Complete
  • Worker Nodes Joined

⏳ Current Stage: Installation Complete
────────────────────────────────────────────────────────────────────────────────
```

### Console Log Analysis
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
  "ErrorCount": 0,
  "WarningCount": 3
}
────────────────────────────────────────────────────────────────────────────────
```

### etcd Quorum Status
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

## Installation Phase Progress

| Phase | Progress | Description |
|-------|----------|-------------|
| Ignition Configuration | 0-10% | Configuration files created |
| Bootstrap Initialization | 10-25% | Bootstrap node starting |
| Control Plane Bootstrap | 25-50% | Master nodes starting |
| Production Control Plane | 50-70% | etcd quorum, API server |
| Cluster Operators | 70-85% | Operators deploying |
| Bootstrap Complete | 85-95% | Bootstrap node destroyed |
| Worker Nodes Joining | 95-100% | Workers joining cluster |
| Installation Complete | 100% | Cluster ready |

## Test Markers

| Marker | Description |
|--------|-------------|
| `installation` | All installation-related tests |
| `ignition` | Ignition configuration tests |
| `bootstrap` | Bootstrap process tests |
| `operators` | Cluster operators tests |
| `etcd` | etcd quorum and cluster tests |

## Troubleshooting Common Issues

### Ignition Fetch Failures
**Console log shows:** `Failed to fetch ignition config`

**Run:**
```bash
pytest tests/test_openshift_installation_progress.py::test_console_log_analysis_master -v -s
```

**Check:**
- S3 bucket permissions
- Network security group rules
- Subnet route tables
- Ignition URL accessibility

### etcd Won't Start
**Console log shows:** `etcd.*failed`

**Run:**
```bash
pytest tests/test_openshift_installation_progress.py::test_etcd_quorum_formation -v -s
```

**Check:**
- All 3 control plane nodes running
- Network connectivity between nodes
- Security groups allow etcd ports (2379, 2380)

### Bootstrap Never Completes
**Cluster stuck in "installing" state**

**Run:**
```bash
pytest tests/test_openshift_installation_progress.py::test_bootstrap_completion_indicators -v -s
```

**Check:**
- Bootstrap instance still exists (should be terminated)
- Control plane nodes all running
- Operators deploying successfully

## Data Files Required

| File | Location | Purpose |
|------|----------|---------|
| `<cluster-id>_cluster.json` | `sources/ocm/` or root | Cluster state, version, config |
| `<cluster-id>_instances.json` | `sources/aws/` or root | EC2 instance status |
| `<cluster-id>_<instance-id>_console.txt` | root | Console log analysis |
| `<cluster-id>_resources.json` | `sources/ocm/` or root | OCM resources (optional) |

## Additional Commands

### List all installation tests:
```bash
pytest tests/test_openshift_installation_progress.py --collect-only
```

### Run with verbose output:
```bash
pytest tests/test_openshift_installation_progress.py -v -s
```

### Generate HTML report with installation results:
```bash
pytest tests/test_openshift_installation_progress.py --html=installation_report.html --self-contained-html
```

## For More Details

See [OPENSHIFT_INSTALLATION_TESTS.md](OPENSHIFT_INSTALLATION_TESTS.md) for:
- Detailed installation phase descriptions
- Complete console log marker patterns
- Troubleshooting workflows
- References to official documentation
