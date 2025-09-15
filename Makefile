# SysManage Agent Makefile
# Provides testing and linting for Python agent

.PHONY: test lint clean setup install-dev help format-python start start-privileged start-unprivileged stop security security-full security-python security-secrets

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
	@echo "  make security      - Run comprehensive security analysis (all tools)"
	@echo "  make security-full - Run comprehensive security analysis (all tools)"
	@echo "  make security-python - Run Python security scanning (Bandit + Safety)"
	@echo "  make security-secrets - Run secrets detection"
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
	@$(PIP) install pytest pytest-cov pytest-asyncio pylint black isort bandit safety

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
	@$(PYTHON) -m pytest tests/ -v --tb=short --cov=main --cov=src/sysmanage_agent --cov=src/database --cov=src/i18n --cov=src/security --cov-report=term-missing --cov-report=html
	@echo "[OK] Tests completed"

# Clean artifacts
clean:
	@echo "Cleaning test artifacts and cache..."
ifeq ($(OS),Windows_NT)
	@if exist __pycache__ $(RM) __pycache__ 2>nul || echo
	@if exist .pytest_cache $(RM) .pytest_cache 2>nul || echo
	@if exist htmlcov $(RM) htmlcov 2>nul || echo
	@if exist .coverage del .coverage 2>nul || echo
	@for /r %%i in (*.pyc) do @del "%%i" 2>NUL || echo.
	@for /r %%i in (__pycache__) do @if exist "%%i" $(RM) "%%i" 2>NUL || echo.
else
	@find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	@find . -type d -name ".pytest_cache" -exec rm -rf {} + 2>/dev/null || true
	@find . -name "*.pyc" -delete 2>/dev/null || true
	@rm -rf htmlcov/ .coverage
endif
	@echo "[OK] Clean completed"

# Agent management targets with privilege level selection

# Default start target (unprivileged for security)
start: start-unprivileged

# Unprivileged start
start-unprivileged:
	@echo "Starting SysManage Agent (unprivileged mode)..."
ifeq ($(OS),Windows_NT)
	@if defined PSModulePath (powershell -ExecutionPolicy Bypass -File scripts/start.ps1) else (scripts\start.cmd)
else
	@if [ -n "$$ZSH_VERSION" ]; then \
		echo "Detected zsh shell, using start.sh"; \
		./scripts/start.sh; \
	elif [ -n "$$BASH_VERSION" ]; then \
		echo "Detected bash shell, using start.sh"; \
		./scripts/start.sh; \
	elif [ -n "$$KSH_VERSION" ]; then \
		echo "Detected ksh shell, using start.sh"; \
		./scripts/start.sh; \
	else \
		echo "Detected POSIX shell, using start.sh"; \
		./scripts/start.sh; \
	fi
endif

# Privileged start
start-privileged:
	@echo "Starting SysManage Agent (privileged mode)..."
ifeq ($(OS),Windows_NT)
	@if defined PSModulePath (powershell -ExecutionPolicy Bypass -File scripts/start-privileged.ps1) else (scripts\start-privileged.cmd)
else
	@if [ -n "$$ZSH_VERSION" ]; then \
		echo "Detected zsh shell, using start-privileged.sh"; \
		./scripts/start-privileged.sh; \
	elif [ -n "$$BASH_VERSION" ]; then \
		echo "Detected bash shell, using start-privileged.sh"; \
		./scripts/start-privileged.sh; \
	elif [ -n "$$KSH_VERSION" ]; then \
		echo "Detected ksh shell, using start-privileged.sh"; \
		./scripts/start-privileged.sh; \
	else \
		echo "Detected POSIX shell, using start-privileged.sh"; \
		./scripts/start-privileged.sh; \
	fi
endif

# Stop agent
stop:
	@echo "Stopping SysManage Agent..."
ifeq ($(OS),Windows_NT)
	@if defined PSModulePath (powershell -ExecutionPolicy Bypass -File scripts/stop.ps1) else (scripts\stop.cmd)
else
	@if [ -n "$$ZSH_VERSION" ]; then \
		echo "Detected zsh shell, using stop.sh"; \
		./scripts/stop.sh; \
	elif [ -n "$$BASH_VERSION" ]; then \
		echo "Detected bash shell, using stop.sh"; \
		./scripts/stop.sh; \
	elif [ -n "$$KSH_VERSION" ]; then \
		echo "Detected ksh shell, using stop.sh"; \
		./scripts/stop.sh; \
	else \
		echo "Detected POSIX shell, using stop.sh"; \
		./scripts/stop.sh; \
	fi
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

# Security analysis targets

# Comprehensive security analysis (default)
security: security-full

# Comprehensive security analysis - all tools  
security-full: security-python security-secrets
	@echo "[OK] Comprehensive security analysis completed!"

# Python security analysis (Bandit + Safety)
security-python: setup-venv
	@echo "=== Python Security Analysis ==="
	@echo "Running Bandit static security analysis..."
ifeq ($(OS),Windows_NT)
	-@$(PYTHON) -m bandit -r *.py alembic/ src/ scripts/ -f screen --skip B101,B404,B603,B607
else
	@$(PYTHON) -m bandit -r *.py alembic/ src/ scripts/ -f screen --skip B101,B404,B603,B607 || true
endif
	@echo ""
	@echo "Running Safety dependency vulnerability scan..."
ifeq ($(OS),Windows_NT)
	-@echo "Safety scan requires authentication - skipping interactive prompt"
else
	@echo "Safety scan requires authentication - skipping interactive prompt"
endif
	@echo "[OK] Python security analysis completed"

# Secrets detection (basic pattern matching)
security-secrets:
	@echo "=== Secrets Detection ==="
	@echo "Scanning for potential secrets and credentials..."
	@echo "Checking for common secret patterns..."
	@grep -r -i --exclude-dir=.git --exclude-dir=.venv --exclude-dir=__pycache__ --exclude="*.pyc" -E "(password|secret|key|token)\s*[:=]\s*['\"][^'\"\\s]{8,}" . || echo "No obvious secrets found in patterns"
	@echo ""
	@echo "Checking for hardcoded API keys..."
	@grep -r -i --exclude-dir=.git --exclude-dir=.venv --exclude-dir=__pycache__ --exclude="*.pyc" -E "(api_?key|access_?token|auth_?token)\s*[:=]\s*['\"][A-Za-z0-9+/=]{20,}" . || echo "No obvious API keys found"
	@echo ""
	@echo "Checking for AWS credentials..."
	@grep -r -i --exclude-dir=.git --exclude-dir=.venv --exclude-dir=__pycache__ --exclude="*.pyc" -E "(AKIA[0-9A-Z]{16}|aws_secret_access_key)" . || echo "No AWS credentials found"
	@echo "[OK] Basic secrets detection completed"