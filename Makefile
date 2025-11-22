.PHONY: help install venv clean test lint format run-collect run-check

help:
	@echo "ROSA Cluster Artifacts Collection - Make Commands"
	@echo ""
	@echo "Setup:"
	@echo "  make install       Install dependencies with uv"
	@echo "  make venv          Create virtual environment with uv"
	@echo ""
	@echo "Development:"
	@echo "  make lint          Run ruff linter"
	@echo "  make format        Format code with black"
	@echo "  make clean         Clean up generated files"
	@echo ""
	@echo "Usage (requires CLUSTER_ID environment variable):"
	@echo "  make run-collect   Collect cluster artifacts"
	@echo "  make run-check     Run health check analysis"
	@echo ""
	@echo "Examples:"
	@echo "  CLUSTER_ID=abc123 make run-collect"
	@echo "  make run-check"

install:
	@echo "Installing dependencies with uv..."
	uv pip install -r requirements.txt

venv:
	@echo "Creating virtual environment with uv..."
	uv venv
	@echo ""
	@echo "Activate with: source .venv/bin/activate"

clean:
	@echo "Cleaning up..."
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete
	find . -type f -name "*.pyo" -delete
	find . -type d -name "*.egg-info" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name ".pytest_cache" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name ".ruff_cache" -exec rm -rf {} + 2>/dev/null || true
	@echo "Clean complete"

lint:
	@echo "Running ruff linter..."
	uv run ruff check get_install_artifacts.py check_cluster_artifacts.py || true

format:
	@echo "Formatting code with black..."
	uv run black get_install_artifacts.py check_cluster_artifacts.py || true

run-collect:
ifndef CLUSTER_ID
	@echo "Error: CLUSTER_ID environment variable is required"
	@echo "Usage: CLUSTER_ID=abc123 make run-collect"
	@exit 1
endif
	@echo "Collecting artifacts for cluster: $(CLUSTER_ID)"
	@echo "Make sure AWS credentials are set:"
	@echo "  eval \$$(ocm backplane cloud credentials $(CLUSTER_ID) -o env)"
	@echo ""
	uv run get_install_artifacts.py -c $(CLUSTER_ID)

run-check:
	@echo "Running health check analysis..."
	uv run check_cluster_artifacts.py -d .
