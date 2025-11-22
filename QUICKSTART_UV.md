# Quick Start with uv

This guide shows how to use these tools with `uv`, a fast Python package installer and runner.

---

## 📚 Documentation Navigation

- **[Main README](README.md)** - Complete documentation, tool reference, and requirements
- **[Pytest Health Check Framework](PYTEST_README.md)** - Test framework architecture and extending tests
- **[QUICKSTART_UV.md](QUICKSTART_UV.md)** (this file) - Fast setup with uv

---

## What is uv?

`uv` is a modern, fast Python package installer and resolver (similar to pip but much faster). It can also run Python scripts with automatic dependency management, eliminating the need to manually create virtual environments.

**Benefits:**
- ⚡ 10-100x faster than pip
- 🔒 Automatic dependency resolution
- 🚀 Can run scripts without activating virtual environments
- 📦 Manages Python versions automatically

## Installation

### Install uv

```bash
# macOS/Linux
curl -LsSf https://astral.sh/uv/install.sh | sh

# After installation, restart your shell or run:
source $HOME/.cargo/env
```

## Usage Methods

### Method 1: Using `uv run` (Recommended - No venv needed!)

This is the easiest method. `uv run` automatically manages dependencies without requiring a virtual environment.

```bash
# Refresh AWS credentials first
eval $(ocm backplane cloud credentials <cluster-id> -o env)

# Collect cluster artifacts
uv run get_install_artifacts.py -c <cluster-id>

# Run health check
uv run check_cluster_artifacts.py -d .
```

**How it works:**
- `uv run` reads `pyproject.toml` or `requirements.txt`
- Automatically installs missing dependencies
- Runs the script in an isolated environment
- No need to activate a virtual environment!

### Method 2: Using virtual environment (Traditional)

If you prefer the traditional venv approach:

```bash
# Create virtual environment
uv venv

# Activate it
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install dependencies
uv pip install -r requirements.txt

# Run scripts normally
python3 get_install_artifacts.py -c <cluster-id>
python3 check_cluster_artifacts.py -d .

# Deactivate when done
deactivate
```

### Method 3: Using Makefile (Convenience)

We've included a Makefile for common operations:

```bash
# Show available commands
make help

# Create venv and install dependencies
make venv
make install

# Collect artifacts (requires CLUSTER_ID env var)
CLUSTER_ID=abc123 make run-collect

# Run health check
make run-check

# Development commands
make lint      # Run linter
make format    # Format code
make clean     # Clean up temp files
```

## Complete Workflow Examples

### Example 1: Quick Analysis (using uv run)

```bash
# 1. Authenticate with OCM
ocm login --token <your-token>

# 2. Get AWS credentials
eval $(ocm backplane cloud credentials <cluster-id> -o env)

# 3. Collect data (uv handles dependencies automatically)
uv run get_install_artifacts.py -c <cluster-id>

# 4. Analyze data
uv run check_cluster_artifacts.py -d .

# 5. View results
open results_*/index.html  # macOS
xdg-open results_*/index.html  # Linux
```

### Example 2: Custom Time Window

```bash
# Collect last 6 hours of data for a ready cluster
eval $(ocm backplane cloud credentials <cluster-id> -o env)
uv run get_install_artifacts.py -c <cluster-id> -e 6h

# Analyze with incident timestamp
uv run check_cluster_artifacts.py -d . --incident-date 2025-01-15T14:30:00Z
```

### Example 3: Specific Directory

```bash
# Create directory for cluster data
mkdir -p ~/troubleshooting/my-cluster
cd ~/troubleshooting/my-cluster

# Collect data
eval $(ocm backplane cloud credentials <cluster-id> -o env)
uv run /path/to/get_install_artifacts.py -c <cluster-id>

# Analyze
uv run /path/to/check_cluster_artifacts.py -d .
```

### Example 4: Using Makefile

```bash
# Set credentials
eval $(ocm backplane cloud credentials abc123 -o env)

# Collect and analyze
CLUSTER_ID=abc123 make run-collect
make run-check
```

## Command Reference

### get_install_artifacts.py

```bash
# Show help
uv run get_install_artifacts.py --help

# Basic usage
uv run get_install_artifacts.py -c <cluster-id>

# Custom time window
uv run get_install_artifacts.py -c <cluster-id> -s 2025-01-15T10:00:00Z -e 3h

# Different directory
uv run get_install_artifacts.py -c <cluster-id> -d /path/to/data

# Force new time range calculation
uv run get_install_artifacts.py -c <cluster-id> --force-update

# Custom CloudWatch metrics period
uv run get_install_artifacts.py -c <cluster-id> -p 60  # 1-minute granularity
```

### check_cluster_artifacts.py

```bash
# Show help
uv run check_cluster_artifacts.py --help

# Analyze current directory
uv run check_cluster_artifacts.py -d .

# Analyze specific directory
uv run check_cluster_artifacts.py -d /path/to/cluster/data

# With incident timestamp for temporal filtering
uv run check_cluster_artifacts.py -d . --incident-date 2025-01-15T14:30:00Z
```

## Troubleshooting

### uv: command not found

Install uv:
```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
source $HOME/.cargo/env
```

### boto3 import error when using venv

Install dependencies:
```bash
uv pip install -r requirements.txt
```

### AWS credentials expired

Refresh credentials:
```bash
eval $(ocm backplane cloud credentials <cluster-id> -o env)
```

### Permission denied on scripts

Make scripts executable:
```bash
chmod +x get_install_artifacts.py check_cluster_artifacts.py
```

## Why Use uv?

### Speed Comparison

```bash
# Traditional pip (slow)
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt  # 10-30 seconds

# uv (fast!)
uv venv
source .venv/bin/activate
uv pip install -r requirements.txt  # 1-2 seconds

# uv run (fastest - no venv needed!)
uv run get_install_artifacts.py -c <cluster-id>  # Instant
```

### Automatic Dependency Management

With `uv run`, you never need to:
- Create virtual environments
- Activate virtual environments
- Manually install dependencies
- Worry about dependency conflicts

Just run your script and uv handles the rest!

## Additional Resources

### External Documentation
- **uv documentation**: https://docs.astral.sh/uv/
- **pytest documentation**: https://docs.pytest.org/

### Project Documentation
- **[Main README](README.md)** - Complete tool documentation and reference
  - Data collection with `get_install_artifacts.py`
  - Health validation with `check_cluster_artifacts.py`
  - AWS permissions and requirements
  - Troubleshooting guide

- **[Pytest Framework Guide](PYTEST_README.md)** - Modern health check framework
  - 63 tests across 7 categories
  - How to run specific tests
  - Extending the test framework
  - HTML report interpretation

- **Legacy Tools**: Bash version available as `get_install_artifacts.sh` (deprecated)

## Tips

1. **Use `uv run` for one-off commands** - No venv setup needed
2. **Use venv for development** - Better IDE integration
3. **Keep credentials fresh** - Re-run the `eval $(ocm backplane...)` command if you get AWS errors
4. **Check help first** - Both scripts have comprehensive `--help` output
5. **Use incident-date** - Filter CloudTrail events to focus on relevant timeframe
6. **Review HTML reports** - Interactive charts make it easier to spot resource exhaustion

## Next Steps

1. **Try the quick example above** - Get hands-on experience with the tools
2. **[Read the Main README](README.md)** for comprehensive documentation:
   - [Data collection options](README.md#tool-1-get_install_artifactspy-python-version---recommended)
   - [AWS permissions required](README.md#requirements)
   - [Workflow examples](README.md#workflow)
   - [Troubleshooting guide](README.md#troubleshooting)

3. **[Explore the Pytest Framework](PYTEST_README.md)** for advanced validation:
   - Run specific test categories
   - Understand test results
   - Add custom validations
   - Generate detailed HTML reports

4. **Customize for your use case**:
   - Adjust time windows for different incident types
   - Use `--debug` flag for credential troubleshooting
   - Review generated reports for visual insights
   - Add cluster-specific test cases
