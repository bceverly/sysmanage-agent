# SysManage Agent Makefile
# Provides testing and linting for Python agent

.PHONY: test lint clean setup install-dev help format-python run stop

# Default target
help:
	@echo "SysManage Agent - Available targets:"
	@echo "  make test          - Run all unit tests"
	@echo "  make lint          - Run Python linting"
	@echo "  make format-python - Format Python code"
	@echo "  make setup         - Install development dependencies"
	@echo "  make clean         - Clean test artifacts and cache"
	@echo "  make install-dev   - Install development tools"
	@echo "  make run           - Start the agent"
	@echo "  make stop          - Stop the agent"

# Virtual environment activation
VENV := .venv

# Detect operating system for cross-platform compatibility
ifeq ($(OS),Windows_NT)
    PYTHON := $(VENV)\Scripts\python.exe
    PIP := $(VENV)\Scripts\pip.exe
    RM := rmdir /s /q
    PYTHON_CMD := python
else
    PYTHON := $(VENV)/bin/python
    PIP := $(VENV)/bin/pip
    RM := rm -rf
    PYTHON_CMD := python3
endif

# Create or repair virtual environment
ifeq ($(OS),Windows_NT)
$(VENV)\Scripts\activate.bat:
	@echo "Creating/repairing virtual environment..."
	@if exist $(VENV) $(RM) $(VENV) 2>nul || echo
	@$(PYTHON_CMD) -m venv $(VENV)
	@$(PIP) install --upgrade pip
	@if exist requirements.txt $(PIP) install -r requirements.txt

setup-venv: $(VENV)\Scripts\activate.bat
else
$(VENV)/bin/activate:
	@echo "Creating/repairing virtual environment..."
	@$(RM) $(VENV) 2>/dev/null || true
	@$(PYTHON_CMD) -m venv $(VENV)
	@$(PIP) install --upgrade pip
	@if [ -f requirements.txt ]; then $(PIP) install -r requirements.txt; fi

setup-venv: $(VENV)/bin/activate
endif

# Install development dependencies
install-dev: setup-venv
	@echo "Installing Python development dependencies..."
	@$(PIP) install pytest pytest-cov pytest-asyncio pylint black isort

# Setup target that ensures everything is ready
setup: install-dev
	@echo "Development environment setup complete!"

# Clean trailing whitespace from Python files (silent operation)
clean-whitespace: setup-venv
	@$(PYTHON) scripts/clean_whitespace.py

# Python linting
ifeq ($(OS),Windows_NT)
lint: format-python
	@echo "=== Python Linting ==="
	@echo "Running pylint..."
	@echo "OS detected: $(OS)"
	@echo "Using Python: $(PYTHON)"
	@.venv\Scripts\python.exe -m pylint main.py tests/ --rcfile=.pylintrc || echo "Pylint completed with warnings/errors"
	@echo "[OK] Python linting completed"
else
lint: format-python
	@echo "=== Python Linting ==="
	@echo "Running pylint..."
	@$(PYTHON) -m pylint main.py tests/ --rcfile=.pylintrc || true
	@echo "[OK] Python linting completed"
endif

# Format Python code
format-python: setup-venv clean-whitespace
	@echo "Formatting Python code..."
	@$(PYTHON) -m black .
	@echo "[OK] Code formatting completed"

# Python tests
test: setup-venv clean-whitespace
	@echo "=== Running Agent Tests ==="
	@$(PYTHON) -m pytest tests/ -v --tb=short --cov=main --cov=config --cov=registration --cov-report=term-missing --cov-report=html
	@echo "[OK] Tests completed"

# Clean artifacts
clean:
	@echo "Cleaning test artifacts and cache..."
ifeq ($(OS),Windows_NT)
	@if exist __pycache__ $(RM) __pycache__ 2>nul || echo
	@if exist .pytest_cache $(RM) .pytest_cache 2>nul || echo
	@if exist htmlcov $(RM) htmlcov 2>nul || echo
	@if exist .coverage del .coverage 2>nul || echo
	@for /r %%i in (*.pyc) do @del "%%i" 2>nul || echo >nul
	@for /r %%i in (__pycache__) do @if exist "%%i" $(RM) "%%i" 2>nul || echo >nul
else
	@find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	@find . -type d -name ".pytest_cache" -exec rm -rf {} + 2>/dev/null || true
	@find . -name "*.pyc" -delete 2>/dev/null || true
	@rm -rf htmlcov/ .coverage
endif
	@echo "[OK] Clean completed"

# Agent management targets
run:
	@echo "Starting SysManage Agent..."
ifeq ($(OS),Windows_NT)
	@cmd /c run.cmd
else
	@./run.sh
endif

stop:
	@echo "Stopping SysManage Agent..."
ifeq ($(OS),Windows_NT)
	@cmd /c stop.cmd
else
	@./stop.sh
endif

# Development helpers
check-syntax: setup-venv
	@echo "Checking Python syntax..."
	@$(PYTHON) -m py_compile main.py
	@echo "[OK] Syntax check passed"

# Run agent in development mode (with verbose output)
run-dev: setup-venv
	@echo "Starting agent in development mode..."
	@$(PYTHON) main.py

# Quick test (run specific test file)
test-quick: setup-venv
	@echo "Running quick tests..."
	@$(PYTHON) -m pytest tests/test_agent_basic.py -v

# Coverage report
coverage: setup-venv clean-whitespace
	@echo "Generating coverage report..."
	@$(PYTHON) -m pytest tests/ --cov=main --cov-report=html --cov-report=term
	@echo "Coverage report generated in htmlcov/index.html"