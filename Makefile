# SysManage Agent Makefile
# Provides testing and linting for Python agent

.PHONY: test lint clean setup install-dev install-dev-rpm help format-python start start-privileged start-unprivileged stop security security-full security-python security-secrets security-upgrades installer installer-deb installer-rpm

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
	@echo "  make install-dev   - Install development tools (includes packaging tools on Ubuntu)"
	@echo "  make check-test-models - Check model synchronization and database compatibility"
	@echo "  make security      - Run comprehensive security analysis (all tools)"
	@echo "  make security-full - Run comprehensive security analysis (all tools)"
	@echo "  make security-python - Run Python security scanning (Bandit + Safety)"
	@echo "  make security-secrets - Run secrets detection"
	@echo "  make security-upgrades - Check for security package upgrades"
	@echo ""
	@echo "Packaging targets:"
	@echo "  make installer     - Build installer package (auto-detects platform: .deb or .rpm)"
	@echo "  make installer-deb - Build Ubuntu/Debian .deb package (explicit)"
	@echo "  make installer-rpm - Build CentOS/RHEL/Fedora .rpm package (explicit)"
	@echo ""
	@echo "Platform-specific notes:"
	@echo "  make install-dev auto-detects your platform and installs appropriate tools:"
	@echo "    Ubuntu/Debian: debhelper, dpkg-buildpackage, lintian, etc."
	@echo "    CentOS/RHEL/Fedora: rpm-build, rpmdevtools, python3-devel, etc."
	@echo "  BSD users: install-dev checks for C tracer dependencies"
	@echo "    OpenBSD: gcc, py3-cffi"
	@echo "    NetBSD: gcc13, py312-cffi"
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
	@$(PYTHON) -m pip install --upgrade pip
	@if [ -f requirements.txt ]; then $(PYTHON) -m pip install -r requirements.txt; fi
endif

setup-venv: $(VENV_ACTIVATE)

# Install development dependencies (auto-detects platform)
install-dev: setup-venv
	@echo "Installing Python development dependencies..."
ifeq ($(OS),Windows_NT)
	@$(PYTHON) scripts/install-dev-deps.py
else
	@if [ -f /etc/redhat-release ]; then \
		echo "[INFO] Red Hat-based system detected - checking for RPM build tools..."; \
		MISSING_PKGS=""; \
		command -v rpmbuild >/dev/null 2>&1 || MISSING_PKGS="$$MISSING_PKGS rpm-build"; \
		command -v rpmdev-setuptree >/dev/null 2>&1 || MISSING_PKGS="$$MISSING_PKGS rpmdevtools"; \
		rpm -q python3-devel >/dev/null 2>&1 || MISSING_PKGS="$$MISSING_PKGS python3-devel"; \
		rpm -q python3-setuptools >/dev/null 2>&1 || MISSING_PKGS="$$MISSING_PKGS python3-setuptools"; \
		if [ -n "$$MISSING_PKGS" ]; then \
			echo "Missing packages:$$MISSING_PKGS"; \
			echo "Installing RPM build tools..."; \
			if command -v dnf >/dev/null 2>&1; then \
				echo "Running: sudo dnf install -y rpm-build rpmdevtools python3-devel python3-setuptools rsync"; \
				sudo dnf install -y rpm-build rpmdevtools python3-devel python3-setuptools rsync || \
				echo "[WARNING] Could not install RPM build tools. Run manually: sudo dnf install -y rpm-build rpmdevtools python3-devel python3-setuptools rsync"; \
			else \
				echo "Running: sudo yum install -y rpm-build rpmdevtools python3-devel python3-setuptools rsync"; \
				sudo yum install -y rpm-build rpmdevtools python3-devel python3-setuptools rsync || \
				echo "[WARNING] Could not install RPM build tools. Run manually: sudo yum install -y rpm-build rpmdevtools python3-devel python3-setuptools rsync"; \
			fi; \
		else \
			echo "✓ All RPM build tools already installed"; \
		fi; \
	elif [ "$$(uname -s)" = "Linux" ] && [ -f /etc/lsb-release ] && grep -q Ubuntu /etc/lsb-release 2>/dev/null; then \
		echo "[INFO] Ubuntu/Debian detected - checking for packaging build tools..."; \
		MISSING_PKGS=""; \
		command -v dpkg-buildpackage >/dev/null 2>&1 || MISSING_PKGS="$$MISSING_PKGS devscripts"; \
		dpkg -l dh-python 2>/dev/null | grep -q "^ii" || MISSING_PKGS="$$MISSING_PKGS dh-python"; \
		dpkg -l python3-all 2>/dev/null | grep -q "^ii" || MISSING_PKGS="$$MISSING_PKGS python3-all"; \
		dpkg -l debhelper 2>/dev/null | grep -q "^ii" || MISSING_PKGS="$$MISSING_PKGS debhelper"; \
		dpkg -l lintian 2>/dev/null | grep -q "^ii" || MISSING_PKGS="$$MISSING_PKGS lintian"; \
		if [ -n "$$MISSING_PKGS" ]; then \
			echo "Missing packages:$$MISSING_PKGS"; \
			echo "Installing Debian packaging build tools..."; \
			echo "Running: sudo apt-get install -y debhelper dh-python python3-all python3-setuptools build-essential devscripts lintian"; \
			sudo apt-get update && sudo apt-get install -y debhelper dh-python python3-all python3-setuptools build-essential devscripts lintian || \
			echo "[WARNING] Could not install packaging tools. Run manually: sudo apt-get install -y debhelper dh-python python3-all python3-setuptools build-essential devscripts lintian"; \
		else \
			echo "✓ All packaging build tools already installed"; \
		fi; \
	fi
	@if [ "$$(uname -s)" = "NetBSD" ]; then \
		echo "[INFO] NetBSD detected - configuring for grpcio build..."; \
		export TMPDIR=/var/tmp && \
		export CFLAGS="-I/usr/pkg/include" && \
		export CXXFLAGS="-std=c++17 -I/usr/pkg/include -fpermissive" && \
		export LDFLAGS="-L/usr/pkg/lib -Wl,-R/usr/pkg/lib" && \
		export GRPC_PYTHON_BUILD_SYSTEM_OPENSSL=1 && \
		export GRPC_PYTHON_BUILD_SYSTEM_ZLIB=1 && \
		export GRPC_PYTHON_BUILD_SYSTEM_CARES=1 && \
		$(PYTHON) scripts/install-dev-deps.py; \
	else \
		$(PYTHON) scripts/install-dev-deps.py; \
	fi
endif
	@echo "Checking for BSD C tracer requirements..."
	@$(PYTHON) scripts/check-openbsd-deps.py
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
ifeq ($(OS),Windows_NT)
	@powershell.exe -ExecutionPolicy Bypass -File scripts\start.ps1
else
	@./scripts/start.sh
endif

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
ifeq ($(OS),Windows_NT)
	@powershell -ExecutionPolicy Bypass -File ./scripts/stop.ps1
else
	@./scripts/stop.sh
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
	@echo "Tip: Export SEMGREP_APP_TOKEN for access to Pro rules and supply chain analysis"
ifeq ($(OS),Windows_NT)
	@if defined SEMGREP_APP_TOKEN (semgrep ci) else (semgrep scan --config="p/default" --config="p/security-audit" --config="p/python" --config="p/django" --config="p/flask" --config="p/owasp-top-ten") || echo "Semgrep scan completed"
	@echo.
else
	@if [ -n "$$SEMGREP_APP_TOKEN" ]; then \
		echo "Using Semgrep CI with supply chain analysis..."; \
		semgrep ci || true; \
	else \
		echo "Using basic Semgrep scan (set SEMGREP_APP_TOKEN for supply chain analysis)..."; \
		semgrep scan --config="p/default" --config="p/security-audit" --config="p/python" --config="p/django" --config="p/flask" --config="p/owasp-top-ten" || true; \
	fi
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

# Build installer package (auto-detects platform)
installer:
	@if [ -f /etc/redhat-release ]; then \
		echo "Red Hat-based system detected - building RPM package"; \
		$(MAKE) installer-rpm; \
	elif [ -f /etc/debian_version ] || [ -f /etc/lsb-release ]; then \
		echo "Debian-based system detected - building DEB package"; \
		$(MAKE) installer-deb; \
	else \
		echo "ERROR: Unsupported platform for package building"; \
		echo "Detected OS: $$(uname -s)"; \
		exit 1; \
	fi

# Build Ubuntu/Debian installer package
installer-deb:
	@echo "=== Building Ubuntu/Debian .deb Package ==="
	@echo ""
	@echo "Checking build dependencies..."
	@command -v dpkg-buildpackage >/dev/null 2>&1 || { \
		echo "ERROR: dpkg-buildpackage not found."; \
		echo "Install with: sudo apt-get install -y debhelper dh-python python3-all build-essential devscripts lintian"; \
		exit 1; \
	}
	@echo "✓ Build tools available"
	@echo ""; \
	echo "Determining version..."; \
	set -e; \
	VERSION=$$(git describe --tags --abbrev=0 2>/dev/null | sed 's/^v//'); \
	if [ -z "$$VERSION" ]; then \
		VERSION="0.1.0"; \
		echo "No git tags found, using default version: $$VERSION"; \
	else \
		echo "Building version: $$VERSION"; \
	fi; \
	echo ""; \
	echo "Creating build directory..."; \
	CURRENT_DIR=$$(pwd); \
	BUILD_TEMP="$$CURRENT_DIR/installer/dist/build-temp"; \
	BUILD_DIR="$$BUILD_TEMP/sysmanage-agent-$$VERSION"; \
	OUTPUT_DIR="$$CURRENT_DIR/installer/dist"; \
	mkdir -p "$$OUTPUT_DIR"; \
	rm -rf "$$BUILD_TEMP"; \
	mkdir -p "$$BUILD_DIR"; \
	echo "✓ Build directory created: $$BUILD_DIR"; \
	echo ""; \
	echo "Copying source files..."; \
	rsync -a --exclude='htmlcov' --exclude='__pycache__' --exclude='*.pyc' --exclude='.pytest_cache' src/ "$$BUILD_DIR/src/"; \
	cp main.py "$$BUILD_DIR/"; \
	cp alembic.ini "$$BUILD_DIR/"; \
	cp requirements-prod.txt "$$BUILD_DIR/"; \
	cp README.md "$$BUILD_DIR/" 2>/dev/null || touch "$$BUILD_DIR/README.md"; \
	echo "✓ Application source copied (excluding test artifacts)"; \
	echo ""; \
	echo "Copying Debian packaging files..."; \
	cp -r installer/ubuntu/debian "$$BUILD_DIR/"; \
	mkdir -p "$$BUILD_DIR/installer/ubuntu"; \
	cp installer/ubuntu/*.service "$$BUILD_DIR/installer/ubuntu/"; \
	cp installer/ubuntu/*.sudoers "$$BUILD_DIR/installer/ubuntu/"; \
	cp installer/ubuntu/*.example "$$BUILD_DIR/installer/ubuntu/"; \
	echo "✓ Packaging files copied"; \
	echo ""; \
	echo "Updating version in changelog..."; \
	DATE=$$(date -R); \
	sed -i "s/0\.1\.0-1/$$VERSION-1/g" "$$BUILD_DIR/debian/changelog"; \
	sed -i "s/Mon, 14 Oct 2025 00:00:00 -0400/$$DATE/g" "$$BUILD_DIR/debian/changelog"; \
	echo "✓ Changelog updated to version $$VERSION"; \
	echo ""; \
	echo "Creating source tarball..."; \
	cd "$$BUILD_TEMP" && tar czf "sysmanage-agent_$$VERSION.orig.tar.gz" "sysmanage-agent-$$VERSION/"; \
	echo "✓ Source tarball created"; \
	echo ""; \
	echo "Building package..."; \
	cd "$$BUILD_DIR" && dpkg-buildpackage -us -uc -b 2>&1 | tee build.log; \
	BUILD_STATUS=$$?; \
	DEB_FILE="$$OUTPUT_DIR/sysmanage-agent_$$VERSION-1_all.deb"; \
	if [ $$BUILD_STATUS -eq 0 ]; then \
		echo ""; \
		echo "✓ Package built successfully!"; \
		echo ""; \
		echo "Moving package and metadata to output directory..."; \
		mv "$$BUILD_TEMP/sysmanage-agent_$$VERSION-1_all.deb" "$$DEB_FILE"; \
		mv "$$BUILD_TEMP/sysmanage-agent_$$VERSION-1_amd64.buildinfo" "$$OUTPUT_DIR/" 2>/dev/null || true; \
		mv "$$BUILD_TEMP/sysmanage-agent_$$VERSION-1_amd64.changes" "$$OUTPUT_DIR/" 2>/dev/null || true; \
		echo "✓ Package and metadata moved to $$OUTPUT_DIR"; \
		echo ""; \
		echo "Running lintian quality checks..."; \
		cd "$$OUTPUT_DIR" && lintian "sysmanage-agent_$$VERSION-1_all.deb" 2>&1 || true; \
		echo ""; \
		echo "Cleaning up temporary build files..."; \
		rm -rf "$$BUILD_TEMP"; \
		echo "✓ Temporary files cleaned"; \
		echo ""; \
		echo "==================================="; \
		echo "Build Complete!"; \
		echo "==================================="; \
		echo ""; \
		echo "Package: $$DEB_FILE"; \
		ls -lh "$$DEB_FILE"; \
		echo ""; \
		echo "Install with:"; \
		echo "  sudo apt install $$DEB_FILE"; \
		echo ""; \
		echo "Check package contents:"; \
		echo "  dpkg-deb --contents $$DEB_FILE"; \
		echo ""; \
		echo "View package info:"; \
		echo "  dpkg-deb --info $$DEB_FILE"; \
		echo ""; \
	else \
		echo ""; \
		echo "✗ Build failed! Check build.log for details:"; \
		echo "  cat $$BUILD_DIR/build.log"; \
		exit 1; \
	fi

# Install RPM build dependencies (for CentOS/RHEL/Fedora)
install-dev-rpm: setup-venv
	@echo "Installing RPM build dependencies..."
	@if [ -f /etc/redhat-release ]; then \
		echo "[INFO] Red Hat-based system detected - checking for RPM build tools..."; \
		MISSING_PKGS=""; \
		command -v rpmbuild >/dev/null 2>&1 || MISSING_PKGS="$$MISSING_PKGS rpm-build"; \
		command -v rpmdev-setuptree >/dev/null 2>&1 || MISSING_PKGS="$$MISSING_PKGS rpmdevtools"; \
		rpm -q python3-devel >/dev/null 2>&1 || MISSING_PKGS="$$MISSING_PKGS python3-devel"; \
		rpm -q python3-setuptools >/dev/null 2>&1 || MISSING_PKGS="$$MISSING_PKGS python3-setuptools"; \
		if [ -n "$$MISSING_PKGS" ]; then \
			echo "Missing packages:$$MISSING_PKGS"; \
			echo "Installing RPM build tools..."; \
			if command -v dnf >/dev/null 2>&1; then \
				echo "Running: sudo dnf install -y rpm-build rpmdevtools python3-devel python3-setuptools"; \
				sudo dnf install -y rpm-build rpmdevtools python3-devel python3-setuptools || \
				echo "[WARNING] Could not install RPM build tools. Run manually: sudo dnf install -y rpm-build rpmdevtools python3-devel python3-setuptools"; \
			else \
				echo "Running: sudo yum install -y rpm-build rpmdevtools python3-devel python3-setuptools"; \
				sudo yum install -y rpm-build rpmdevtools python3-devel python3-setuptools || \
				echo "[WARNING] Could not install RPM build tools. Run manually: sudo yum install -y rpm-build rpmdevtools python3-devel python3-setuptools"; \
			fi; \
		else \
			echo "✓ All RPM build tools already installed"; \
		fi; \
	else \
		echo "[WARNING] Not a Red Hat-based system. RPM build tools may not be available."; \
	fi
	@echo "RPM build environment setup complete!"

# Build CentOS/RHEL/Fedora installer package
installer-rpm:
	@echo "=== Building CentOS/RHEL/Fedora .rpm Package ==="
	@echo ""
	@echo "Checking build dependencies..."
	@command -v rpmbuild >/dev/null 2>&1 || { \
		echo "ERROR: rpmbuild not found."; \
		echo "Install with: sudo dnf install -y rpm-build rpmdevtools python3-devel python3-setuptools"; \
		echo "Or run: make install-dev-rpm"; \
		exit 1; \
	}
	@echo "✓ Build tools available"
	@echo ""; \
	echo "Determining version..."; \
	set -e; \
	VERSION=$$(git describe --tags --abbrev=0 2>/dev/null | sed 's/^v//'); \
	if [ -z "$$VERSION" ]; then \
		VERSION="0.1.0"; \
		echo "No git tags found, using default version: $$VERSION"; \
	else \
		echo "Building version: $$VERSION"; \
	fi; \
	echo ""; \
	echo "Setting up RPM build tree..."; \
	CURRENT_DIR=$$(pwd); \
	BUILD_TEMP="$$CURRENT_DIR/installer/dist/rpmbuild"; \
	OUTPUT_DIR="$$CURRENT_DIR/installer/dist"; \
	mkdir -p "$$OUTPUT_DIR"; \
	rm -rf "$$BUILD_TEMP"; \
	mkdir -p "$$BUILD_TEMP"/{BUILD,RPMS,SOURCES,SPECS,SRPMS}; \
	echo "✓ RPM build tree created"; \
	echo ""; \
	echo "Creating source tarball..."; \
	TAR_NAME="sysmanage-agent-$$VERSION"; \
	TAR_DIR="$$BUILD_TEMP/SOURCES/$$TAR_NAME"; \
	mkdir -p "$$TAR_DIR"; \
	rsync -a --exclude='htmlcov' --exclude='__pycache__' --exclude='*.pyc' --exclude='.pytest_cache' src/ "$$TAR_DIR/src/"; \
	cp main.py "$$TAR_DIR/"; \
	cp alembic.ini "$$TAR_DIR/"; \
	cp requirements-prod.txt "$$TAR_DIR/"; \
	cp README.md "$$TAR_DIR/" 2>/dev/null || touch "$$TAR_DIR/README.md"; \
	cp LICENSE "$$TAR_DIR/" 2>/dev/null || touch "$$TAR_DIR/LICENSE"; \
	mkdir -p "$$TAR_DIR/installer/centos"; \
	cp installer/centos/*.service "$$TAR_DIR/installer/centos/"; \
	cp installer/centos/*.sudoers "$$TAR_DIR/installer/centos/"; \
	cp installer/centos/*.example "$$TAR_DIR/installer/centos/"; \
	cd "$$BUILD_TEMP/SOURCES" && tar czf "sysmanage-agent-$$VERSION.tar.gz" "$$TAR_NAME/"; \
	rm -rf "$$TAR_DIR"; \
	echo "✓ Source tarball created"; \
	echo ""; \
	echo "Updating spec file with version..."; \
	cp "$$CURRENT_DIR/installer/centos/sysmanage-agent.spec" "$$BUILD_TEMP/SPECS/"; \
	DATE=$$(date "+%a %b %d %Y"); \
	sed -i "s/^Version:.*/Version:        $$VERSION/" "$$BUILD_TEMP/SPECS/sysmanage-agent.spec"; \
	sed -i "s/^\\* Mon Oct 14 2024/\\* $$DATE/" "$$BUILD_TEMP/SPECS/sysmanage-agent.spec"; \
	echo "✓ Spec file updated to version $$VERSION"; \
	echo ""; \
	echo "Building RPM package..."; \
	cd "$$BUILD_TEMP" && rpmbuild --define "_topdir $$BUILD_TEMP" -bb SPECS/sysmanage-agent.spec 2>&1 | tee build.log; \
	BUILD_STATUS=$$?; \
	if [ $$BUILD_STATUS -eq 0 ]; then \
		echo ""; \
		echo "✓ Package built successfully!"; \
		echo ""; \
		echo "Moving package to output directory..."; \
		RPM_FILE=$$(find "$$BUILD_TEMP/RPMS" -name "sysmanage-agent-$$VERSION-*.rpm" | head -1); \
		if [ -n "$$RPM_FILE" ]; then \
			cp "$$RPM_FILE" "$$OUTPUT_DIR/"; \
			RPM_BASENAME=$$(basename "$$RPM_FILE"); \
			echo "✓ Package moved to $$OUTPUT_DIR/$$RPM_BASENAME"; \
			echo ""; \
			echo "Cleaning up temporary build files..."; \
			rm -rf "$$BUILD_TEMP"; \
			echo "✓ Temporary files cleaned"; \
			echo ""; \
			echo "==================================="; \
			echo "Build Complete!"; \
			echo "==================================="; \
			echo ""; \
			echo "Package: $$OUTPUT_DIR/$$RPM_BASENAME"; \
			ls -lh "$$OUTPUT_DIR/$$RPM_BASENAME"; \
			echo ""; \
			echo "Install with:"; \
			echo "  sudo dnf install $$OUTPUT_DIR/$$RPM_BASENAME"; \
			echo "  or"; \
			echo "  sudo yum install $$OUTPUT_DIR/$$RPM_BASENAME"; \
			echo "  or"; \
			echo "  sudo rpm -ivh $$OUTPUT_DIR/$$RPM_BASENAME"; \
			echo ""; \
			echo "Check package contents:"; \
			echo "  rpm -qlp $$OUTPUT_DIR/$$RPM_BASENAME"; \
			echo ""; \
			echo "View package info:"; \
			echo "  rpm -qip $$OUTPUT_DIR/$$RPM_BASENAME"; \
			echo ""; \
		else \
			echo "ERROR: Built RPM not found!"; \
			exit 1; \
		fi; \
	else \
		echo ""; \
		echo "✗ Build failed! Check build.log for details:"; \
		echo "  cat $$BUILD_TEMP/build.log"; \
		exit 1; \
	fi