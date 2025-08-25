# SysManage Agent Makefile
# Provides testing and linting for Python agent

.PHONY: test lint clean setup install-dev help format run stop

# Default target
help:
	@echo "SysManage Agent - Available targets:"
	@echo "  make test          - Run all unit tests"
	@echo "  make lint          - Run Python linting"
	@echo "  make format        - Format Python code"
	@echo "  make setup         - Install development dependencies"
	@echo "  make clean         - Clean test artifacts and cache"
	@echo "  make install-dev   - Install development tools"
	@echo "  make run           - Start the agent"
	@echo "  make stop          - Stop the agent"

# Virtual environment activation
VENV := .venv
PYTHON := $(VENV)/bin/python
PIP := $(VENV)/bin/pip

# Create or repair virtual environment
$(VENV)/bin/activate:
	@echo "Creating/repairing virtual environment..."
	@rm -rf $(VENV)
	@python3 -m venv $(VENV)
	@$(PIP) install --upgrade pip
	@if [ -f requirements.txt ]; then $(PIP) install -r requirements.txt; fi

# Install development dependencies
install-dev: $(VENV)/bin/activate
	@echo "Installing Python development dependencies..."
	@$(PIP) install pytest pytest-cov pytest-asyncio pylint black isort

# Setup target that ensures everything is ready
setup: install-dev
	@echo "Development environment setup complete!"

# Clean trailing whitespace from Python files (silent operation)
clean-whitespace:
	@find . -name "*.py" -type f -exec sed -i '' 's/[[:space:]]*$$//' {} \; 2>/dev/null || true

# Python linting
lint: $(VENV)/bin/activate clean-whitespace
	@echo "=== Python Linting ==="
	@echo "Running Black code formatter check..."
	@$(PYTHON) -m black --check --diff . || (echo "Run 'make format' to fix formatting"; exit 1)
	@echo "Running pylint..."
	@$(PYTHON) -m pylint main.py tests/ --rcfile=.pylintrc || true
	@echo "✅ Python linting completed"

# Format Python code
format: $(VENV)/bin/activate clean-whitespace
	@echo "Formatting Python code..."
	@$(PYTHON) -m black .
	@echo "✅ Code formatting completed"

# Python tests
test: $(VENV)/bin/activate clean-whitespace
	@echo "=== Running Agent Tests ==="
	@$(PYTHON) -m pytest tests/ -v --tb=short --cov=main --cov-report=term-missing --cov-report=html
	@echo "✅ Tests completed"

# Clean artifacts
clean:
	@echo "Cleaning test artifacts and cache..."
	@find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	@find . -type d -name ".pytest_cache" -exec rm -rf {} + 2>/dev/null || true
	@find . -name "*.pyc" -delete 2>/dev/null || true
	@rm -rf htmlcov/ .coverage
	@echo "✅ Clean completed"

# Agent management targets
run:
	@echo "Starting SysManage Agent..."
	@./run.sh

stop:
	@echo "Stopping SysManage Agent..."
	@./stop.sh

# Development helpers
check-syntax: $(VENV)/bin/activate
	@echo "Checking Python syntax..."
	@$(PYTHON) -m py_compile main.py
	@echo "✅ Syntax check passed"

# Run agent in development mode (with verbose output)
run-dev: $(VENV)/bin/activate
	@echo "Starting agent in development mode..."
	@$(PYTHON) main.py

# Quick test (run specific test file)
test-quick: $(VENV)/bin/activate
	@echo "Running quick tests..."
	@$(PYTHON) -m pytest tests/test_agent_basic.py -v

# Coverage report
coverage: $(VENV)/bin/activate clean-whitespace
	@echo "Generating coverage report..."
	@$(PYTHON) -m pytest tests/ --cov=main --cov-report=html --cov-report=term
	@echo "Coverage report generated in htmlcov/index.html"