# SysManage Agent Makefile
# Provides testing and linting for Python agent

.PHONY: test lint clean setup install-dev help format-python start start-privileged start-unprivileged stop security security-full security-python security-secrets security-upgrades

# Default target
help:
	@echo "SysManage Agent - Available targets:"
	@echo "  make start             - Start SysManage Agent (unprivileged for security)"
	@echo "  make start-privileged  - Start SysManage Agent with elevated privileges"
	@echo "  make start-unprivileged - Start SysManage Agent without elevated privileges"
	@echo "  make stop              - Stop SysManage Agent (auto-detects shell/platform)"
	@echo ""
	@echo "Development targets:"
	@echo "  make test          - Run all unit tests"
	@echo "  make lint          - Run Python linting"
	@echo "  make format-python - Format Python code"
	@echo "  make setup         - Install development dependencies"
	@echo "  make clean         - Clean test artifacts and cache"
	@echo "  make install-dev   - Install development tools"
	@echo "  make check-test-models - Check model synchronization and database compatibility"
	@echo "  make security      - Run comprehensive security analysis (all tools)"
	@echo "  make security-full - Run comprehensive security analysis (all tools)"
	@echo "  make security-python - Run Python security scanning (Bandit + Safety)"
	@echo "  make security-secrets - Run secrets detection"
	@echo "  make security-upgrades - Check for security package upgrades"
	@echo ""
	@echo "Privilege Levels:"
	@echo "  unprivileged - Runs as regular user (default for security)"
	@echo "                 ✓ System monitoring, reporting"
	@echo "                 ✗ Package management, system changes"
	@echo ""
	@echo "  privileged   - Runs with elevated permissions"
	@echo "                 ✓ Full functionality including package management"
	@echo "                 ⚠ Requires sudo/doas access"

# Virtual environment activation
VENV = .venv

# Platform detection and variable setup
ifeq ($(OS),Windows_NT)
    # Windows-specific paths and commands
    PYTHON = "$(VENV)/Scripts/python.exe"
    PIP = "$(VENV)/Scripts/pip.exe"
    RM = rmdir /s /q
    PYTHON_CMD = python
    VENV_ACTIVATE = $(VENV)/Scripts/activate
    NULL_REDIRECT = >nul 2>&1
    SHELL_TEST = if exist
    SHELL_AND = &&
    DEL_CMD = del /q
else
    # Unix/BSD/Linux defaults (works on FreeBSD)
    PYTHON = $(VENV)/bin/python
    PIP = $(VENV)/bin/pip
    RM = rm -rf
    PYTHON_CMD = python3
    VENV_ACTIVATE = $(VENV)/bin/activate
    NULL_REDIRECT = 2>/dev/null
    SHELL_TEST = if [ -f
    SHELL_AND = ] ; then
    DEL_CMD = rm -f
endif

# Create or repair virtual environment
$(VENV_ACTIVATE):
	@echo "Creating/repairing virtual environment..."
ifeq ($(OS),Windows_NT)
	@if exist $(VENV) $(RM) $(VENV) $(NULL_REDIRECT) || echo.
	@$(PYTHON_CMD) -m venv $(VENV)
	@$(PIP) install --upgrade pip
	@if exist requirements.txt $(PIP) install -r requirements.txt
else
	@$(RM) $(VENV) $(NULL_REDIRECT) || true
	@$(PYTHON_CMD) -m venv $(VENV)
	@$(PIP) install --upgrade pip
	@if [ -f requirements.txt ]; then $(PIP) install -r requirements.txt; fi
endif

setup-venv: $(VENV_ACTIVATE)

# Install development dependencies
install-dev: setup-venv
	@echo "Installing Python development dependencies..."
	@$(PIP) install pytest pytest-cov pytest-asyncio pylint black isort bandit safety semgrep

# Setup target that ensures everything is ready
setup: install-dev
	@echo "Development environment setup complete!"

# Clean trailing whitespace from Python files (silent operation)
clean-whitespace: setup-venv
	@$(PYTHON) scripts/clean_whitespace.py

# Python linting
lint: format-python
	@echo "=== Python Linting ==="
	@echo "Running pylint..."
ifeq ($(OS),Windows_NT)
	@$(PYTHON) -m pylint main.py src/ tests/ --rcfile=.pylintrc || echo.
else
	@$(PYTHON) -m pylint main.py src/ tests/ --rcfile=.pylintrc || true
endif
	@echo "[OK] Python linting completed"

# Format Python code
format-python: setup-venv clean-whitespace
	@echo "Formatting Python code..."
	@$(PYTHON) -m black .
	@echo "[OK] Code formatting completed"

# Python tests
test: setup-venv clean-whitespace
	@echo "=== Running Agent Tests ==="
ifeq ($(OS),Windows_NT)
	@set PYTHONWARNINGS=ignore::RuntimeWarning && $(PYTHON) -m pytest tests/ -v --tb=short --cov=main --cov=src/sysmanage_agent --cov=src/database --cov=src/i18n --cov=src/security --cov-report=term-missing --cov-report=html
else
	@PYTHONWARNINGS=ignore::RuntimeWarning $(PYTHON) -m pytest tests/ -v --tb=short --cov=main --cov=src/sysmanage_agent --cov=src/database --cov=src/i18n --cov=src/security --cov-report=term-missing --cov-report=html
endif
	@echo "[OK] Tests completed"

# Clean artifacts
clean:
	@echo "Cleaning test artifacts and cache..."
ifeq ($(OS),Windows_NT)
	@for /d /r . %%d in (__pycache__) do @if exist "%%d" rmdir /s /q "%%d" $(NULL_REDIRECT) || echo.
	@for /d /r . %%d in (.pytest_cache) do @if exist "%%d" rmdir /s /q "%%d" $(NULL_REDIRECT) || echo.
	@for /r . %%f in (*.pyc) do @if exist "%%f" del /q "%%f" $(NULL_REDIRECT) || echo.
	@if exist htmlcov rmdir /s /q htmlcov $(NULL_REDIRECT) || echo.
	@if exist .coverage del /q .coverage $(NULL_REDIRECT) || echo.
else
	@find . -type d -name "__pycache__" -exec rm -rf {} + $(NULL_REDIRECT) || true
	@find . -type d -name ".pytest_cache" -exec rm -rf {} + $(NULL_REDIRECT) || true
	@find . -name "*.pyc" -delete $(NULL_REDIRECT) || true
	@rm -rf htmlcov/ .coverage
endif
	@echo "[OK] Clean completed"

# Agent management targets with privilege level selection

# Default start target (unprivileged for security)
start: start-unprivileged

# Unprivileged start
start-unprivileged:
	@echo "Starting SysManage Agent (unprivileged mode)..."
	@./scripts/start.sh

# Privileged start
start-privileged:
	@echo "Starting SysManage Agent (privileged mode)..."
ifeq ($(OS),Windows_NT)
	@powershell.exe -ExecutionPolicy Bypass -File scripts/start-privileged-background.ps1
else
	@./scripts/start-privileged.sh
endif

# Stop agent
stop:
	@echo "Stopping SysManage Agent..."
	@./scripts/stop.sh

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

# Model synchronization check
check-test-models: setup-venv
	@echo "Checking test model synchronization..."
	@$(PYTHON) scripts/check_test_models.py

# Security analysis targets

# Comprehensive security analysis (default)
security: security-full

# Show upgrade recommendations by checking outdated packages
security-upgrades: setup-venv
	@echo "=== Security Upgrade Recommendations ==="
	@echo "Current versions of security-critical packages:"
ifeq ($(OS),Windows_NT)
	@$(PYTHON) -m pip list | findstr /r "cryptography aiohttp black bandit websockets PyYAML SQLAlchemy alembic safety"
	@echo.
	@echo "Checking for outdated packages..."
	@$(PYTHON) -m pip list --outdated --format=columns $(NULL_REDIRECT) | findstr /r "cryptography aiohttp black bandit websockets PyYAML SQLAlchemy alembic safety" || echo "All security packages are up to date"
else
	@$(PYTHON) -m pip list | grep -E "(cryptography|aiohttp|black|bandit|websockets|PyYAML|SQLAlchemy|alembic|safety)"
	@echo ""
	@echo "Checking for outdated packages..."
	@$(PYTHON) -m pip list --outdated --format=columns $(NULL_REDIRECT) | grep -E "(cryptography|aiohttp|black|bandit|websockets|PyYAML|SQLAlchemy|alembic|safety)" || echo "All security packages are up to date"
endif
	@echo ""
	@echo "For detailed vulnerability info, check:"
	@echo "  https://platform.safetycli.com/codebases/sysmanage-agent/findings?branch=main"

# Comprehensive security analysis - all tools  
security-full: security-python security-secrets
	@echo "[OK] Comprehensive security analysis completed!"

# Python security analysis (Bandit + Safety)
security-python: setup-venv
	@echo "=== Python Security Analysis ==="
	@echo "Running Bandit static security analysis..."
ifeq ($(OS),Windows_NT)
	@$(PYTHON) -m bandit -r *.py src/ scripts/ -f screen --skip B101,B404,B603,B607 || echo.
	@echo.
	@echo "Running Safety dependency vulnerability scan..."
	@$(PYTHON) -m safety scan --output screen || echo "Safety scan completed with issues"
	@echo.
	@echo "=== Current dependency versions (for upgrade reference) ==="
	@$(PYTHON) -m pip list | findstr /r "cryptography aiohttp black bandit websockets PyYAML SQLAlchemy alembic" || echo "Package list completed"
else
	@$(PYTHON) -m bandit -r *.py src/ scripts/ -f screen --skip B101,B404,B603,B607 || true
	@echo ""
	@echo "Running Semgrep static analysis..."
	@echo "Tip: Export SEMGREP_APP_TOKEN for access to Pro rules and features"
ifeq ($(OS),Windows_NT)
	@semgrep scan --config="p/default" --config="p/security-audit" --config="p/python" --config="p/django" --config="p/flask" --config="p/owasp-top-ten" || echo "Semgrep scan completed"
	@echo.
else
	@semgrep scan --config="p/default" --config="p/security-audit" --config="p/python" --config="p/django" --config="p/flask" --config="p/owasp-top-ten" || true
	@echo ""
endif
	@echo "Running Safety dependency vulnerability scan..."
	@$(PYTHON) -m safety scan --output screen || echo "Safety scan completed with issues"
	@echo ""
	@echo "=== Current dependency versions (for upgrade reference) ==="
	@$(PYTHON) -m pip list | grep -E "(cryptography|aiohttp|black|bandit|websockets|PyYAML|SQLAlchemy|alembic)" || echo "Package list completed"
endif
	@echo ""
	@echo "Note: Check Safety web UI at https://platform.safetycli.com/codebases/sysmanage-agent/findings?branch=main"
	@echo "      for specific version upgrade recommendations when vulnerabilities are found."
	@echo "[OK] Python security analysis completed"

# Secrets detection (basic pattern matching)
security-secrets:
	@echo "=== Secrets Detection ==="
	@echo "Scanning for potential secrets and credentials..."
	@echo "Checking for common secret patterns..."
ifeq ($(OS),Windows_NT)
	@findstr /r /s /i /v /f:"nul" "(password|secret|key|token)" *.py src\*.py tests\*.py scripts\*.py alembic\*.py $(NULL_REDIRECT) || echo "No obvious secrets found in patterns"
	@echo.
	@echo "Checking for hardcoded API keys..."
	@findstr /r /s /i "api.*key.*=" *.py src\*.py tests\*.py scripts\*.py alembic\*.py $(NULL_REDIRECT) || echo "No obvious API keys found"
	@echo.
	@echo "Checking for AWS credentials..."
	@findstr /r /s /i "AKIA" *.py src\*.py tests\*.py scripts\*.py alembic\*.py $(NULL_REDIRECT) || echo "No AWS credentials found"
else
	@grep -r -i --exclude-dir=.git --exclude-dir=.venv --exclude-dir=__pycache__ --exclude="*.pyc" -E "(password|secret|key|token)\\s*[:=]\\s*['\"][^'\"\\\\s]{8,}" . || echo "No obvious secrets found in patterns"
	@echo ""
	@echo "Checking for hardcoded API keys..."
	@grep -r -i --exclude-dir=.git --exclude-dir=.venv --exclude-dir=__pycache__ --exclude="*.pyc" -E "(api_?key|access_?token|auth_?token)\\s*[:=]\\s*['\"][A-Za-z0-9+/=]{20,}" . || echo "No obvious API keys found"
	@echo ""
	@echo "Checking for AWS credentials..."
	@grep -r -i --exclude-dir=.git --exclude-dir=.venv --exclude-dir=__pycache__ --exclude="*.pyc" -E "(AKIA[0-9A-Z]{16}|aws_secret_access_key)" . || echo "No AWS credentials found"
endif
	@echo "[OK] Basic secrets detection completed"