# SysManage Agent Makefile
# Provides testing and linting for Python agent

.PHONY: test lint clean setup install-dev install-dev-rpm help format-python start start-privileged start-unprivileged stop security security-full security-python security-secrets security-upgrades installer installer-deb installer-rpm installer-msi installer-msi-x64 installer-msi-arm64 installer-msi-all installer-openbsd installer-freebsd installer-netbsd snap snap-clean snap-install snap-uninstall

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
	@echo "  make installer     - Build installer package (auto-detects platform)"
	@echo "  make installer-deb - Build Ubuntu/Debian .deb package (explicit)"
	@echo "  make installer-rpm - Build CentOS/RHEL/Fedora .rpm package (explicit)"
	@echo "  make installer-msi - Build Windows .msi package for x64 (default)"
	@echo "  make installer-msi-x64 - Build Windows .msi package for x64"
	@echo "  make installer-msi-arm64 - Build Windows .msi package for ARM64"
	@echo "  make installer-msi-all - Build Windows .msi for both x64 and ARM64"
	@echo "  make installer-openbsd - Prepare OpenBSD port (copy to /usr/ports)"
	@echo "  make installer-freebsd - Build FreeBSD .pkg package"
	@echo "  make installer-netbsd - Build NetBSD .tgz package"
	@echo "  make snap          - Build Ubuntu Snap package (core22 base)"
	@echo "  make snap-clean    - Clean snap build artifacts"
	@echo "  make snap-install  - Install locally built snap package (Ubuntu only)"
	@echo "  make snap-uninstall - Uninstall snap package (Ubuntu only)"
	@echo ""
	@echo "Platform-specific notes:"
	@echo "  make install-dev auto-detects your platform and installs appropriate tools:"
	@echo "    Ubuntu/Debian: debhelper, dpkg-buildpackage, lintian, snapcraft, etc."
	@echo "    CentOS/RHEL/Fedora: rpm-build, rpmdevtools, python3-devel, etc."
	@echo "    Windows: WiX Toolset v4 (for MSI creation)"
	@echo "    OpenBSD: Python packages (websockets, yaml, aiohttp, cryptography, sqlalchemy, alembic)"
	@echo "    FreeBSD: pkgconf (for package creation)"
	@echo "    NetBSD: No additional tools needed (uses pkg_create)"
	@echo "  BSD users: install-dev checks for C tracer dependencies"
	@echo "    OpenBSD: gcc, py3-cffi (plus all Python deps as pre-built packages)"
	@echo "    NetBSD: gcc14, py312-cffi"
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
	@powershell -ExecutionPolicy Bypass -File scripts\install-wix.ps1 || echo.
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
	elif [ -f /etc/os-release ] && grep -qE "^ID=\"?(opensuse-leap|opensuse-tumbleweed|sles)\"?" /etc/os-release; then \
		echo "[INFO] openSUSE/SLES detected - checking for RPM build tools..."; \
		MISSING_PKGS=""; \
		command -v rpmbuild >/dev/null 2>&1 || MISSING_PKGS="$$MISSING_PKGS rpm-build"; \
		command -v rpmdev-setuptree >/dev/null 2>&1 || MISSING_PKGS="$$MISSING_PKGS rpmdevtools"; \
		rpm -q python311-devel >/dev/null 2>&1 || MISSING_PKGS="$$MISSING_PKGS python311-devel"; \
		rpm -q python3-setuptools >/dev/null 2>&1 || MISSING_PKGS="$$MISSING_PKGS python3-setuptools"; \
		if [ -n "$$MISSING_PKGS" ]; then \
			echo "Missing packages:$$MISSING_PKGS"; \
			echo "Installing RPM build tools..."; \
			echo "Running: sudo zypper install -y rpm-build rpmdevtools python311-devel python3-setuptools rsync"; \
			sudo zypper install -y rpm-build rpmdevtools python311-devel python3-setuptools rsync || \
			echo "[WARNING] Could not install RPM build tools. Run manually: sudo zypper install -y rpm-build rpmdevtools python311-devel python3-setuptools rsync"; \
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
		echo "[INFO] Checking for Snap build tools..."; \
		LXD_GROUP_ADDED=0; \
		if ! command -v snap >/dev/null 2>&1; then \
			echo "snapd not found - installing..."; \
			echo "Running: sudo apt-get install -y snapd"; \
			sudo apt-get install -y snapd || { \
				echo "[WARNING] Could not install snapd. Run manually: sudo apt-get install -y snapd"; \
			}; \
			echo "Ensuring snapd service is enabled and started..."; \
			sudo systemctl enable --now snapd.socket || true; \
			sudo systemctl start snapd || true; \
			echo "Waiting for snapd to initialize..."; \
			sleep 5; \
		fi; \
		if ! command -v snapcraft >/dev/null 2>&1; then \
			echo "snapcraft not found - installing via snap..."; \
			echo "Running: sudo snap install snapcraft --classic"; \
			sudo snap install snapcraft --classic || { \
				echo "[WARNING] Could not install snapcraft. Run manually: sudo snap install snapcraft --classic"; \
			}; \
		else \
			echo "✓ snapcraft already installed"; \
		fi; \
		LXD_NEEDS_REINSTALL=0; \
		if ! snap list lxd >/dev/null 2>&1; then \
			echo "LXD not found - installing via snap..."; \
			echo "Running: sudo snap install lxd"; \
			sudo snap install lxd || { \
				echo "[WARNING] Could not install lxd. Run manually: sudo snap install lxd"; \
			}; \
			LXD_NEEDS_REINSTALL=1; \
		else \
			echo "✓ LXD already installed"; \
		fi; \
		CURRENT_USER=$$(whoami); \
		if ! groups $$CURRENT_USER | grep -q '\blxd\b'; then \
			echo "Adding $$CURRENT_USER to lxd group..."; \
			echo "Running: sudo usermod -aG lxd $$CURRENT_USER"; \
			sudo usermod -aG lxd $$CURRENT_USER || { \
				echo "[WARNING] Could not add user to lxd group. Run manually: sudo usermod -aG lxd $$CURRENT_USER"; \
			}; \
			echo "✓ User $$CURRENT_USER added to lxd group"; \
			LXD_GROUP_ADDED=1; \
		else \
			echo "✓ User $$CURRENT_USER already in lxd group"; \
		fi; \
		if [ "$$LXD_NEEDS_REINSTALL" -eq 1 ] || ! sudo lxd init --dump >/dev/null 2>&1; then \
			echo "Initializing LXD with automatic configuration..."; \
			echo "Running: sudo lxd init --auto"; \
			sudo lxd init --auto || { \
				echo "[WARNING] Could not initialize LXD. Run manually: sudo lxd init --auto"; \
			}; \
			echo "✓ LXD initialized"; \
		else \
			echo "✓ LXD already initialized"; \
		fi; \
		if command -v snap >/dev/null 2>&1 && command -v snapcraft >/dev/null 2>&1; then \
			echo "✓ All Snap build tools installed"; \
		fi; \
		if [ "$$LXD_GROUP_ADDED" -eq 1 ]; then \
			echo "$$LXD_GROUP_ADDED" > /tmp/.sysmanage-lxd-group-added-$$$$.tmp; \
		fi; \
	fi
	@if [ "$$(uname -s)" = "Darwin" ]; then \
		echo "[INFO] macOS detected - checking for packaging tools..."; \
		command -v pkgbuild >/dev/null 2>&1 || { \
			echo "[ERROR] pkgbuild not found. Please install Xcode Command Line Tools:"; \
			echo "        xcode-select --install"; \
			exit 1; \
		}; \
		command -v productbuild >/dev/null 2>&1 || { \
			echo "[ERROR] productbuild not found. Please install Xcode Command Line Tools:"; \
			echo "        xcode-select --install"; \
			exit 1; \
		}; \
		echo "✓ All macOS packaging tools available"; \
		$(PYTHON) scripts/install-dev-deps.py; \
	elif [ "$$(uname -s)" = "OpenBSD" ]; then \
		echo "[INFO] OpenBSD detected - installing Python dependencies as packages..."; \
		MISSING_PKGS=""; \
		pkg_info -e py3-websockets || MISSING_PKGS="$$MISSING_PKGS py3-websockets"; \
		pkg_info -e py3-yaml || MISSING_PKGS="$$MISSING_PKGS py3-yaml"; \
		pkg_info -e py3-aiohttp || MISSING_PKGS="$$MISSING_PKGS py3-aiohttp"; \
		pkg_info -e py3-cryptography || MISSING_PKGS="$$MISSING_PKGS py3-cryptography"; \
		pkg_info -e py3-sqlalchemy || MISSING_PKGS="$$MISSING_PKGS py3-sqlalchemy"; \
		pkg_info -e py3-alembic || MISSING_PKGS="$$MISSING_PKGS py3-alembic"; \
		if [ -n "$$MISSING_PKGS" ]; then \
			echo "Missing packages:$$MISSING_PKGS"; \
			echo "Installing Python dependencies..."; \
			echo "Running: doas pkg_add$$MISSING_PKGS"; \
			doas pkg_add$$MISSING_PKGS || \
			echo "[WARNING] Could not install packages. Run manually: doas pkg_add$$MISSING_PKGS"; \
		else \
			echo "✓ All Python dependencies already installed"; \
		fi; \
		$(PYTHON) scripts/install-dev-deps.py; \
	elif [ "$$(uname -s)" = "NetBSD" ]; then \
		echo "[INFO] NetBSD detected - configuring for grpcio build..."; \
		echo "[INFO] Checking for package creation tools..."; \
		command -v pkg_create >/dev/null 2>&1 || { \
			echo "[ERROR] pkg_create not found. Please install pkgtools from pkgsrc."; \
			exit 1; \
		}; \
		echo "✓ NetBSD package creation tools ready"; \
		export TMPDIR=/var/tmp && \
		export CFLAGS="-I/usr/pkg/include" && \
		export CXXFLAGS="-std=c++17 -I/usr/pkg/include -fpermissive" && \
		export LDFLAGS="-L/usr/pkg/lib -Wl,-R/usr/pkg/lib" && \
		export GRPC_PYTHON_BUILD_SYSTEM_OPENSSL=1 && \
		export GRPC_PYTHON_BUILD_SYSTEM_ZLIB=1 && \
		export GRPC_PYTHON_BUILD_SYSTEM_CARES=1 && \
		$(PYTHON) scripts/install-dev-deps.py; \
	elif [ "$$(uname -s)" = "FreeBSD" ]; then \
		echo "[INFO] FreeBSD detected - installing package creation tools..."; \
		if ! command -v pkg >/dev/null 2>&1; then \
			echo "[ERROR] pkg not found. Please install pkg first."; \
			exit 1; \
		fi; \
		echo "[INFO] Checking for required package creation tools..."; \
		if ! pkg info -q pkgconf; then \
			echo "    Installing pkgconf for package creation..."; \
			sudo pkg install -y pkgconf; \
		fi; \
		echo "✓ FreeBSD package creation tools ready"; \
		$(PYTHON) scripts/install-dev-deps.py; \
	else \
		$(PYTHON) scripts/install-dev-deps.py; \
	fi
endif
	@echo "Checking for BSD C tracer requirements..."
	@$(PYTHON) scripts/check-openbsd-deps.py
	@echo "Development environment setup complete!"
	@if [ -f /tmp/.sysmanage-lxd-group-added-*.tmp ]; then \
		echo ""; \
		echo "============================================================"; \
		echo "[IMPORTANT] LXD group membership change detected!"; \
		echo "============================================================"; \
		echo "You were added to the 'lxd' group during this installation."; \
		echo ""; \
		echo "For the group membership to take effect, you MUST log out"; \
		echo "and log back in before running 'make snap'."; \
		echo ""; \
		echo "The group change will NOT work in the current session,"; \
		echo "even if you run 'newgrp lxd'."; \
		echo ""; \
		echo "Please log out and log back in now, then run 'make snap'."; \
		echo "============================================================"; \
		echo ""; \
		rm -f /tmp/.sysmanage-lxd-group-added-*.tmp; \
	fi

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
	@echo "Generating requirements-prod.txt from requirements.txt..."
	@python3 scripts/update-requirements-prod.py
ifeq ($(OS),Windows_NT)
	@echo "Windows detected - building MSI installer"
	@$(MAKE) installer-msi
else
	@if [ "$$(uname -s)" = "Darwin" ]; then \
		echo "macOS detected - building PKG installer"; \
		$(MAKE) installer-pkg; \
	elif [ "$$(uname -s)" = "OpenBSD" ]; then \
		echo "OpenBSD detected - preparing port"; \
		$(MAKE) installer-openbsd; \
	elif [ "$$(uname -s)" = "FreeBSD" ]; then \
		echo "FreeBSD detected - building PKG package"; \
		$(MAKE) installer-freebsd; \
	elif [ "$$(uname -s)" = "NetBSD" ]; then \
		echo "NetBSD detected - building TGZ package"; \
		$(MAKE) installer-netbsd; \
	elif [ -f /etc/os-release ]; then \
		. /etc/os-release; \
		if [ "$$ID" = "opensuse-leap" ] || [ "$$ID" = "opensuse-tumbleweed" ] || [ "$$ID" = "sles" ]; then \
			echo "openSUSE/SLES system detected - building RPM package"; \
			$(MAKE) installer-rpm-suse; \
		elif [ -f /etc/redhat-release ]; then \
			echo "Red Hat-based system detected - building RPM package"; \
			$(MAKE) installer-rpm; \
		elif [ -f /etc/debian_version ] || [ -f /etc/lsb-release ]; then \
			echo "Debian-based system detected - building DEB package"; \
			$(MAKE) installer-deb; \
		else \
			echo "ERROR: Unsupported platform for package building"; \
			echo "Detected OS: $$ID"; \
			exit 1; \
		fi; \
	elif [ -f /etc/redhat-release ]; then \
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
endif

# Build macOS .pkg installer package
installer-pkg:
	@echo "Generating requirements-prod.txt from requirements.txt..."
	@python3 scripts/update-requirements-prod.py
	@echo "=== Building macOS .pkg Package ==="
	@echo ""
	@echo "Checking build dependencies..."
	@command -v pkgbuild >/dev/null 2>&1 || { \
		echo "ERROR: pkgbuild not found."; \
		echo "Install with: xcode-select --install"; \
		exit 1; \
	}
	@command -v productbuild >/dev/null 2>&1 || { \
		echo "ERROR: productbuild not found."; \
		echo "Install with: xcode-select --install"; \
		exit 1; \
	}
	@echo "✓ Build tools available"
	@echo ""; \
	echo "Determining version..."; \
	set -e; \
	if [ -n "$$VERSION" ]; then \
		echo "Using VERSION from environment: $$VERSION"; \
	else \
		VERSION=$$(git describe --tags --abbrev=0 2>/dev/null | sed 's/^v//'); \
		if [ -z "$$VERSION" ]; then \
			VERSION="0.1.0"; \
			echo "No git tags found, using default version: $$VERSION"; \
		else \
			echo "Building version: $$VERSION"; \
		fi; \
	fi; \
	echo ""; \
	echo "Creating build directory..."; \
	CURRENT_DIR=$$(pwd); \
	BUILD_TEMP="$$CURRENT_DIR/installer/dist/build-temp"; \
	BUILD_DIR="$$BUILD_TEMP/sysmanage-agent-$$VERSION"; \
	OUTPUT_DIR="$$CURRENT_DIR/installer/dist"; \
	PAYLOAD_DIR="$$BUILD_TEMP/payload"; \
	SCRIPTS_DIR="$$BUILD_TEMP/scripts"; \
	mkdir -p "$$OUTPUT_DIR"; \
	rm -rf "$$BUILD_TEMP"; \
	mkdir -p "$$BUILD_DIR"; \
	mkdir -p "$$PAYLOAD_DIR"; \
	mkdir -p "$$SCRIPTS_DIR"; \
	echo "✓ Build directories created"; \
	echo ""; \
	echo "Copying source files..."; \
	rsync -a --exclude='htmlcov' --exclude='__pycache__' --exclude='*.pyc' --exclude='.pytest_cache' src/ "$$BUILD_DIR/src/"; \
	cp main.py "$$BUILD_DIR/"; \
	cp alembic.ini "$$BUILD_DIR/"; \
	cp requirements-prod.txt "$$BUILD_DIR/"; \
	cp README.md "$$BUILD_DIR/" 2>/dev/null || touch "$$BUILD_DIR/README.md"; \
	echo "✓ Application source copied (excluding test artifacts)"; \
	echo ""; \
	echo "Creating package payload structure..."; \
	mkdir -p "$$PAYLOAD_DIR/opt/sysmanage-agent"; \
	mkdir -p "$$PAYLOAD_DIR/Library/LaunchDaemons"; \
	cp -r "$$BUILD_DIR"/* "$$PAYLOAD_DIR/opt/sysmanage-agent/"; \
	echo "✓ Payload structure created"; \
	echo ""; \
	echo "Creating LaunchDaemon plist..."; \
	{ printf '%s\n' \
		'<?xml version="1.0" encoding="UTF-8"?>' \
		'<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">' \
		'<plist version="1.0">' \
		'<dict>' \
		'	<key>Label</key>' \
		'	<string>com.sysmanage.agent</string>' \
		'	<key>ProgramArguments</key>' \
		'	<array>' \
		'		<string>/opt/sysmanage-agent/venv/bin/python3</string>' \
		'		<string>/opt/sysmanage-agent/main.py</string>' \
		'	</array>' \
		'	<key>WorkingDirectory</key>' \
		'	<string>/opt/sysmanage-agent</string>' \
		'	<key>RunAtLoad</key>' \
		'	<true/>' \
		'	<key>KeepAlive</key>' \
		'	<true/>' \
		'	<key>StandardOutPath</key>' \
		'	<string>/var/log/sysmanage-agent.log</string>' \
		'	<key>StandardErrorPath</key>' \
		'	<string>/var/log/sysmanage-agent-error.log</string>' \
		'	<key>EnvironmentVariables</key>' \
		'	<dict>' \
		'		<key>PATH</key>' \
		'		<string>/opt/sysmanage-agent/venv/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin</string>' \
		'	</dict>' \
		'</dict>' \
		'</plist>'; \
	} > "$$PAYLOAD_DIR/Library/LaunchDaemons/com.sysmanage.agent.plist"; \
	echo "✓ LaunchDaemon plist created"; \
	echo ""; \
	echo "Creating postinstall script..."; \
	{ printf '%s\n' \
		'#!/bin/bash' \
		'set -e' \
		'' \
		'# Log file for debugging' \
		'LOGFILE="/tmp/sysmanage-agent-install.log"' \
		'exec > >(tee -a "$$LOGFILE") 2>&1' \
		'' \
		'echo "=== SysManage Agent Installation ===" ' \
		'echo "Date: $$(date)"' \
		'echo "Architecture: $$(uname -m)"' \
		'echo "Python: $$(which python3)"' \
		'echo "Python version: $$(python3 --version)"' \
		'' \
		'echo "Setting up sysmanage-agent..."' \
		'' \
		'cd /opt/sysmanage-agent' \
		'' \
		'# Remove old venv to ensure clean installation with correct architecture' \
		'if [ -d "venv" ]; then' \
		'	echo "Removing old virtual environment..."' \
		'	rm -rf venv' \
		'fi' \
		'' \
		'echo "Creating virtual environment..."' \
		'# On Apple Silicon, force ARM64 architecture for venv and pip' \
		'# Use sysctl to detect actual hardware, not uname which may report x86_64 under Rosetta' \
		'ACTUAL_ARCH=$$(sysctl -n machdep.cpu.brand_string | grep -q "Apple" && echo "arm64" || uname -m)' \
		'echo "Detected architecture: $$ACTUAL_ARCH"' \
		'if [ "$$ACTUAL_ARCH" = "arm64" ]; then' \
		'	echo "Apple Silicon detected - forcing ARM64 architecture"' \
		'	echo "Creating ARM64 virtual environment with system Python..."' \
		'	export ARCHFLAGS="-arch arm64"' \
		'	export _PYTHON_HOST_PLATFORM="macosx-11.0-arm64"' \
		'	arch -arm64 python3 -m venv venv' \
		'	echo "Installing Python dependencies for ARM64..."' \
		'	arch -arm64 ./venv/bin/pip install --upgrade pip setuptools wheel' \
		'	echo "Installing application dependencies..."' \
		'	arch -arm64 ./venv/bin/pip install -r requirements-prod.txt' \
		'	echo "Dependency installation complete"' \
		'else' \
		'	echo "Intel architecture detected"' \
		'	python3 -m venv venv' \
		'	echo "Installing Python dependencies..."' \
		'	./venv/bin/pip install --upgrade pip setuptools wheel' \
		'	./venv/bin/pip install -r requirements-prod.txt' \
		'fi' \
		'' \
		'if [ ! -f "/etc/sysmanage-agent.yaml" ]; then' \
		'	echo "Creating example configuration..."' \
		'	cat > /etc/sysmanage-agent.yaml.example <<'\''CONFIG_EOF'\''' \
		'# SysManage Agent Configuration' \
		'# Customize for your environment' \
		'' \
		'# Server connection settings' \
		'server:' \
		'  # WebSocket URL of the SysManage server' \
		'  url: "wss://sysmanage.example.com:8443"' \
		'' \
		'  # Authentication token (obtain from SysManage server)' \
		'  token: "YOUR_AGENT_TOKEN_HERE"' \
		'' \
		'  # Reconnect settings' \
		'  reconnect_interval: 30  # seconds' \
		'  max_reconnect_attempts: 0  # 0 = unlimited' \
		'' \
		'# Database settings' \
		'database:' \
		'  # Path to SQLite database file' \
		'  path: "/var/lib/sysmanage-agent/agent.db"' \
		'' \
		'# Logging settings' \
		'logging:' \
		'  # Log level: DEBUG, INFO, WARNING, ERROR, CRITICAL' \
		'  level: "INFO"' \
		'' \
		'  # Log file path' \
		'  file: "/var/log/sysmanage-agent/agent.log"' \
		'' \
		'  # Maximum log file size (in bytes)' \
		'  max_size: 10485760  # 10MB' \
		'' \
		'  # Number of backup log files to keep' \
		'  backup_count: 5' \
		'' \
		'# Collection intervals (in seconds)' \
		'collection:' \
		'  system_info_interval: 300  # 5 minutes' \
		'  package_info_interval: 3600  # 1 hour' \
		'  update_check_interval: 3600  # 1 hour' \
		'  hardware_info_interval: 3600  # 1 hour' \
		'' \
		'# Security settings' \
		'security:' \
		'  verify_ssl: true' \
		'' \
		'# Feature flags' \
		'features:' \
		'  auto_update: false' \
		'  firewall_management: true' \
		'  certificate_management: true' \
		'  script_execution: true' \
		'CONFIG_EOF' \
		'	echo "⚠️  Please configure /etc/sysmanage-agent.yaml before starting the service"' \
		'fi' \
		'' \
		'# Create database directory' \
		'mkdir -p /var/lib/sysmanage-agent' \
		'chmod 755 /var/lib/sysmanage-agent' \
		'' \
		'# Create log directory' \
		'mkdir -p /var/log/sysmanage-agent' \
		'chmod 755 /var/log/sysmanage-agent' \
		'' \
		'echo "Loading LaunchDaemon..."' \
		'launchctl load /Library/LaunchDaemons/com.sysmanage.agent.plist 2>/dev/null || true' \
		'' \
		'echo "✓ sysmanage-agent installation complete"' \
		'echo ""' \
		'echo "To start the service:"' \
		'echo "  sudo launchctl start com.sysmanage.agent"' \
		'echo ""' \
		'echo "To stop the service:"' \
		'echo "  sudo launchctl stop com.sysmanage.agent"' \
		'' \
		'exit 0'; \
	} > "$$SCRIPTS_DIR/postinstall"; \
	chmod +x "$$SCRIPTS_DIR/postinstall"; \
	echo "✓ Postinstall script created"; \
	echo ""; \
	echo "Creating preinstall script..."; \
	{ printf '%s\n' \
		'#!/bin/bash' \
		'' \
		'if launchctl list | grep -q com.sysmanage.agent; then' \
		'	echo "Stopping sysmanage-agent service..."' \
		'	launchctl unload /Library/LaunchDaemons/com.sysmanage.agent.plist 2>/dev/null || true' \
		'fi' \
		'' \
		'exit 0'; \
	} > "$$SCRIPTS_DIR/preinstall"; \
	chmod +x "$$SCRIPTS_DIR/preinstall"; \
	echo "✓ Preinstall script created"; \
	echo ""; \
	echo "Building component package..."; \
	pkgbuild --root "$$PAYLOAD_DIR" \
		--scripts "$$SCRIPTS_DIR" \
		--identifier com.sysmanage.agent \
		--version "$$VERSION" \
		--install-location / \
		"$$BUILD_TEMP/sysmanage-agent-component.pkg"; \
	echo "✓ Component package created"; \
	echo ""; \
	echo "Creating distribution XML..."; \
	{ printf '%s\n' \
		'<?xml version="1.0" encoding="utf-8"?>' \
		'<installer-gui-script minSpecVersion="1">' \
		'	<title>SysManage Agent</title>' \
		'	<organization>com.sysmanage</organization>' \
		'	<domains enable_localSystem="true"/>' \
		'	<options customize="never" require-scripts="true" rootVolumeOnly="true" />' \
		'	<choices-outline>' \
		'		<line choice="default">' \
		'			<line choice="com.sysmanage.agent"/>' \
		'		</line>' \
		'	</choices-outline>' \
		'	<choice id="default"/>' \
		'	<choice id="com.sysmanage.agent" visible="false">' \
		'		<pkg-ref id="com.sysmanage.agent"/>' \
		'	</choice>' \
		'	<pkg-ref id="com.sysmanage.agent" onConclusion="none">sysmanage-agent-component.pkg</pkg-ref>' \
		'</installer-gui-script>'; \
	} > "$$BUILD_TEMP/distribution.xml"; \
	echo "✓ Distribution XML created"; \
	echo ""; \
	echo "Building final installer package..."; \
	productbuild --distribution "$$BUILD_TEMP/distribution.xml" \
		--package-path "$$BUILD_TEMP" \
		"$$OUTPUT_DIR/sysmanage-agent-$$VERSION-macos.pkg"; \
	echo "✓ Final package created"; \
	echo ""; \
	echo "Package built successfully!"; \
	echo "Location: $$OUTPUT_DIR/sysmanage-agent-$$VERSION-macos.pkg"; \
	echo ""; \
	echo "To install:"; \
	echo "  sudo installer -pkg $$OUTPUT_DIR/sysmanage-agent-$$VERSION-macos.pkg -target /"; \
	echo ""; \
	ls -lh "$$OUTPUT_DIR/sysmanage-agent-$$VERSION-macos.pkg"

# Build openSUSE/SLES installer package
installer-rpm-suse:
	@echo "Generating requirements-prod.txt from requirements.txt..."
	@python3 scripts/update-requirements-prod.py
	@echo "=== Building openSUSE/SLES .rpm Package ==="
	@echo ""
	@echo "Checking build dependencies..."
	@command -v rpmbuild >/dev/null 2>&1 || { \
		echo "ERROR: rpmbuild not found."; \
		echo "Install with: sudo zypper install -y rpm-build rpmdevtools python3-devel python3-setuptools"; \
		echo "Or run: make install-dev-rpm-suse"; \
		exit 1; \
	}
	@echo "✓ Build tools available"
	@echo ""; \
	echo "Determining version..."; \
	set -e; \
	if [ -n "$$VERSION" ]; then \
		echo "Using VERSION from environment: $$VERSION"; \
	else \
		VERSION=$$(git describe --tags --abbrev=0 2>/dev/null | sed 's/^v//'); \
		if [ -z "$$VERSION" ]; then \
			VERSION="0.1.0"; \
			echo "No git tags found, using default version: $$VERSION"; \
		else \
			echo "Building version: $$VERSION"; \
		fi; \
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
	mkdir -p "$$TAR_DIR/installer/opensuse"; \
	cp installer/opensuse/*.service "$$TAR_DIR/installer/opensuse/"; \
	cp installer/opensuse/*.sudoers "$$TAR_DIR/installer/opensuse/"; \
	cp installer/opensuse/*.example "$$TAR_DIR/installer/opensuse/"; \
	cd "$$BUILD_TEMP/SOURCES" && tar czf "sysmanage-agent-$$VERSION.tar.gz" "$$TAR_NAME/"; \
	rm -rf "$$TAR_DIR"; \
	echo "✓ Source tarball created"; \
	echo ""; \
	echo "Updating spec file with version..."; \
	cp "$$CURRENT_DIR/installer/opensuse/sysmanage-agent.spec" "$$BUILD_TEMP/SPECS/"; \
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
			echo "Signing RPM package with GPG..."; \
			if gpg --list-keys E033E691377F0AE3 >/dev/null 2>&1; then \
				if [ -n "$$GPG_PASSPHRASE" ]; then \
					echo "Using GPG passphrase from environment variable"; \
					echo "$$GPG_PASSPHRASE" > /tmp/.rpm-gpg-pass-$$$$; \
					chmod 600 /tmp/.rpm-gpg-pass-$$$$; \
					rpmsign --addsign --define "_gpg_name E033E691377F0AE3" --define "__gpg_sign_cmd %{__gpg} gpg --batch --no-verbose --no-armor --passphrase-file /tmp/.rpm-gpg-pass-$$$$ --no-secmem-warning -u E033E691377F0AE3 -sbo %{__signature_filename} %{__plaintext_filename}" "$$OUTPUT_DIR/$$RPM_BASENAME" 2>&1 && \
					{ rm -f /tmp/.rpm-gpg-pass-$$$$; echo "✓ Package signed successfully"; } || \
					{ rm -f /tmp/.rpm-gpg-pass-$$$$; echo "ERROR: Failed to sign package"; exit 1; }; \
				elif [ -f "$$CURRENT_DIR/.gpg-passphrase" ]; then \
					echo "Using GPG passphrase from .gpg-passphrase file"; \
					rpmsign --addsign --define "_gpg_name E033E691377F0AE3" --define "__gpg_sign_cmd %{__gpg} gpg --batch --no-verbose --no-armor --pinentry-mode loopback --passphrase-file $$CURRENT_DIR/.gpg-passphrase --no-secmem-warning -u E033E691377F0AE3 -sbo %{__signature_filename} %{__plaintext_filename}" "$$OUTPUT_DIR/$$RPM_BASENAME" 2>&1 && \
					echo "✓ Package signed successfully" || \
					{ echo "ERROR: Failed to sign package"; exit 1; }; \
				else \
					echo ""; \
					echo "ERROR: GPG passphrase not found!"; \
					echo ""; \
					echo "Package signing is required. Please provide your GPG passphrase using one of:"; \
					echo ""; \
					echo "  Option 1: Create .gpg-passphrase file (recommended for local builds):"; \
					echo "    echo 'your-passphrase' > .gpg-passphrase"; \
					echo "    chmod 600 .gpg-passphrase"; \
					echo ""; \
					echo "  Option 2: Set GPG_PASSPHRASE environment variable (for CI/CD):"; \
					echo "    export GPG_PASSPHRASE='your-passphrase'"; \
					echo ""; \
					exit 1; \
				fi; \
			else \
				echo "ERROR: GPG key E033E691377F0AE3 not found!"; \
				echo "Run: gpg --list-keys to verify your key is available"; \
				exit 1; \
			fi; \
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
			echo "  sudo zypper install $$OUTPUT_DIR/$$RPM_BASENAME"; \
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

# Build Ubuntu/Debian installer package
installer-deb:
	@echo "Generating requirements-prod.txt from requirements.txt..."
	@python3 scripts/update-requirements-prod.py
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
	if [ -n "$$VERSION" ]; then \
		echo "Using VERSION from environment: $$VERSION"; \
	else \
		VERSION=$$(git describe --tags --abbrev=0 2>/dev/null | sed 's/^v//'); \
		if [ -z "$$VERSION" ]; then \
			VERSION="0.1.0"; \
			echo "No git tags found, using default version: $$VERSION"; \
		else \
			echo "Building version: $$VERSION"; \
		fi; \
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
	sed -i "s/^sysmanage-agent (0\.1\.0)/sysmanage-agent ($$VERSION-1)/" "$$BUILD_DIR/debian/changelog"; \
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
		echo "Signing DEB package with GPG..."; \
		if gpg --list-keys E033E691377F0AE3 >/dev/null 2>&1; then \
			if [ -n "$$GPG_PASSPHRASE" ] || [ -f "$$CURRENT_DIR/.gpg-passphrase" ]; then \
				if command -v debsigs >/dev/null 2>&1; then \
					if [ -n "$$GPG_PASSPHRASE" ]; then \
						echo "Using GPG passphrase from environment variable"; \
						echo "$$GPG_PASSPHRASE" | debsigs --sign=origin -k E033E691377F0AE3 "$$DEB_FILE" && \
						echo "✓ Package signed successfully with debsigs" || \
						{ echo "ERROR: Failed to sign package with debsigs"; exit 1; }; \
					else \
						echo "Using GPG passphrase from .gpg-passphrase file"; \
						cat "$$CURRENT_DIR/.gpg-passphrase" | debsigs --sign=origin -k E033E691377F0AE3 "$$DEB_FILE" && \
						echo "✓ Package signed successfully with debsigs" || \
						{ echo "ERROR: Failed to sign package with debsigs"; exit 1; }; \
					fi; \
				else \
					echo "[INFO] debsigs not installed - creating detached signature"; \
					if [ -n "$$GPG_PASSPHRASE" ]; then \
						echo "$$GPG_PASSPHRASE" | gpg --batch --yes --pinentry-mode loopback --passphrase-fd 0 --default-key E033E691377F0AE3 --armor --detach-sign "$$DEB_FILE" && \
						echo "✓ Package signature created: $$DEB_FILE.asc" || \
						{ echo "ERROR: Failed to create signature"; exit 1; }; \
					else \
						cat "$$CURRENT_DIR/.gpg-passphrase" | gpg --batch --yes --pinentry-mode loopback --passphrase-fd 0 --default-key E033E691377F0AE3 --armor --detach-sign "$$DEB_FILE" && \
						echo "✓ Package signature created: $$DEB_FILE.asc" || \
						{ echo "ERROR: Failed to create signature"; exit 1; }; \
					fi; \
				fi; \
			else \
				echo ""; \
				echo "ERROR: GPG passphrase not found!"; \
				echo ""; \
				echo "Package signing is required. Please provide your GPG passphrase using one of:"; \
				echo ""; \
				echo "  Option 1: Create .gpg-passphrase file (recommended for local builds):"; \
				echo "    echo 'your-passphrase' > .gpg-passphrase"; \
				echo "    chmod 600 .gpg-passphrase"; \
				echo ""; \
				echo "  Option 2: Set GPG_PASSPHRASE environment variable (for CI/CD):"; \
				echo "    export GPG_PASSPHRASE='your-passphrase'"; \
				echo ""; \
				exit 1; \
			fi; \
		else \
			echo "ERROR: GPG key E033E691377F0AE3 not found!"; \
			echo "Run: gpg --list-keys to verify your key is available"; \
			exit 1; \
		fi; \
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

install-dev-rpm-suse: setup-venv
	@echo "Installing openSUSE/SLES RPM build dependencies..."
	@if [ -f /etc/os-release ]; then \
		. /etc/os-release; \
		if [ "$$ID" = "opensuse-leap" ] || [ "$$ID" = "opensuse-tumbleweed" ] || [ "$$ID" = "sles" ]; then \
			echo "[INFO] openSUSE/SLES system detected - checking for RPM build tools..."; \
			MISSING_PKGS=""; \
			command -v rpmbuild >/dev/null 2>&1 || MISSING_PKGS="$$MISSING_PKGS rpm-build"; \
			command -v rpmdev-setuptree >/dev/null 2>&1 || MISSING_PKGS="$$MISSING_PKGS rpmdevtools"; \
			rpm -q python311-devel >/dev/null 2>&1 || MISSING_PKGS="$$MISSING_PKGS python311-devel"; \
			rpm -q python3-setuptools >/dev/null 2>&1 || MISSING_PKGS="$$MISSING_PKGS python3-setuptools"; \
			if [ -n "$$MISSING_PKGS" ]; then \
				echo "Missing packages:$$MISSING_PKGS"; \
				echo "Installing RPM build tools..."; \
				echo "Running: sudo zypper install -y rpm-build rpmdevtools python311-devel python3-setuptools"; \
				sudo zypper install -y rpm-build rpmdevtools python311-devel python3-setuptools || \
				echo "[WARNING] Could not install RPM build tools. Run manually: sudo zypper install -y rpm-build rpmdevtools python311-devel python3-setuptools"; \
			else \
				echo "✓ All RPM build tools already installed"; \
			fi; \
		else \
			echo "[WARNING] Not an openSUSE/SLES system. Use install-dev-rpm for Red Hat systems or install-dev-deb for Debian systems."; \
		fi; \
	else \
		echo "[WARNING] Cannot detect OS. RPM build tools may not be available."; \
	fi
	@echo "openSUSE/SLES RPM build environment setup complete!"

# Build CentOS/RHEL/Fedora installer package
installer-rpm:
	@echo "Generating requirements-prod.txt from requirements.txt..."
	@python3 scripts/update-requirements-prod.py
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
	if [ -n "$$VERSION" ]; then \
		echo "Using VERSION from environment: $$VERSION"; \
	else \
		VERSION=$$(git describe --tags --abbrev=0 2>/dev/null | sed 's/^v//'); \
		if [ -z "$$VERSION" ]; then \
			VERSION="0.1.0"; \
			echo "No git tags found, using default version: $$VERSION"; \
		else \
			echo "Building version: $$VERSION"; \
		fi; \
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
			echo "Signing RPM package with GPG..."; \
			if gpg --list-keys E033E691377F0AE3 >/dev/null 2>&1; then \
				if [ -n "$$GPG_PASSPHRASE" ]; then \
					echo "Using GPG passphrase from environment variable"; \
					echo "$$GPG_PASSPHRASE" > /tmp/.rpm-gpg-pass-$$$$; \
					chmod 600 /tmp/.rpm-gpg-pass-$$$$; \
					rpmsign --addsign --define "_gpg_name E033E691377F0AE3" --define "__gpg_sign_cmd %{__gpg} gpg --batch --no-verbose --no-armor --passphrase-file /tmp/.rpm-gpg-pass-$$$$ --no-secmem-warning -u E033E691377F0AE3 -sbo %{__signature_filename} %{__plaintext_filename}" "$$OUTPUT_DIR/$$RPM_BASENAME" 2>&1 && \
					{ rm -f /tmp/.rpm-gpg-pass-$$$$; echo "✓ Package signed successfully"; } || \
					{ rm -f /tmp/.rpm-gpg-pass-$$$$; echo "ERROR: Failed to sign package"; exit 1; }; \
				elif [ -f "$$CURRENT_DIR/.gpg-passphrase" ]; then \
					echo "Using GPG passphrase from .gpg-passphrase file"; \
					rpmsign --addsign --define "_gpg_name E033E691377F0AE3" --define "__gpg_sign_cmd %{__gpg} gpg --batch --no-verbose --no-armor --pinentry-mode loopback --passphrase-file $$CURRENT_DIR/.gpg-passphrase --no-secmem-warning -u E033E691377F0AE3 -sbo %{__signature_filename} %{__plaintext_filename}" "$$OUTPUT_DIR/$$RPM_BASENAME" 2>&1 && \
					echo "✓ Package signed successfully" || \
					{ echo "ERROR: Failed to sign package"; exit 1; }; \
				else \
					echo ""; \
					echo "ERROR: GPG passphrase not found!"; \
					echo ""; \
					echo "Package signing is required. Please provide your GPG passphrase using one of:"; \
					echo ""; \
					echo "  Option 1: Create .gpg-passphrase file (recommended for local builds):"; \
					echo "    echo 'your-passphrase' > .gpg-passphrase"; \
					echo "    chmod 600 .gpg-passphrase"; \
					echo ""; \
					echo "  Option 2: Set GPG_PASSPHRASE environment variable (for CI/CD):"; \
					echo "    export GPG_PASSPHRASE='your-passphrase'"; \
					echo ""; \
					exit 1; \
				fi; \
			else \
				echo "ERROR: GPG key E033E691377F0AE3 not found!"; \
				echo "Run: gpg --list-keys to verify your key is available"; \
				exit 1; \
			fi; \
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

# Prepare OpenBSD port (copy to /usr/ports/sysutils/sysmanage-agent)
installer-openbsd:
	@echo "=== Preparing OpenBSD Port ==="
	@echo ""
	@echo "OpenBSD uses a ports system rather than pre-built packages."
	@echo "This target will copy the port infrastructure to the ports tree."
	@echo ""
	@CURRENT_DIR=$$(pwd); \
	PORTS_DIR="/usr/ports/sysutils/sysmanage-agent"; \
	SOURCE_DIR="$$CURRENT_DIR/installer/openbsd"; \
	echo "Determining version from git..."; \
	VERSION=$$(git describe --tags --abbrev=0 2>/dev/null | sed 's/^v//'); \
	if [ -z "$$VERSION" ]; then \
		VERSION="0.1.0"; \
		echo "WARNING: No git tags found, using default version: $$VERSION"; \
	else \
		echo "Building version: $$VERSION"; \
	fi; \
	echo ""; \
	echo "Checking source directory..."; \
	if [ ! -d "$$SOURCE_DIR" ]; then \
		echo "ERROR: Source directory not found: $$SOURCE_DIR"; \
		exit 1; \
	fi; \
	echo "✓ Source directory found"; \
	echo ""; \
	echo "Creating ports directory (requires doas)..."; \
	doas mkdir -p "$$PORTS_DIR" || { \
		echo "ERROR: Failed to create $$PORTS_DIR"; \
		echo "Make sure you have doas privileges"; \
		exit 1; \
	}; \
	echo "✓ Ports directory created/verified: $$PORTS_DIR"; \
	echo ""; \
	echo "Copying port files..."; \
	doas cp -R "$$SOURCE_DIR"/* "$$PORTS_DIR/" || { \
		echo "ERROR: Failed to copy port files"; \
		exit 1; \
	}; \
	echo "✓ Port files copied"; \
	echo ""; \
	echo "Updating version in Makefile to v$$VERSION..."; \
	doas sed -i "s/^GH_TAGNAME =.*/GH_TAGNAME =\t\tv$$VERSION/" "$$PORTS_DIR/Makefile" || { \
		echo "ERROR: Failed to update version in Makefile"; \
		exit 1; \
	}; \
	echo "✓ Version updated to v$$VERSION"; \
	echo ""; \
	echo "==================================="; \
	echo "Port Preparation Complete!"; \
	echo "==================================="; \
	echo ""; \
	echo "Port location: $$PORTS_DIR"; \
	echo ""; \
	echo "Next steps:"; \
	echo ""; \
	echo "1. Generate checksums:"; \
	echo "   cd $$PORTS_DIR"; \
	echo "   doas make makesum"; \
	echo ""; \
	echo "2. Build the port:"; \
	echo "   doas make"; \
	echo ""; \
	echo "3. Install the port:"; \
	echo "   doas make install"; \
	echo ""; \
	echo "4. Enable and start the service:"; \
	echo "   doas rcctl enable sysmanage_agent"; \
	echo "   doas rcctl start sysmanage_agent"; \
	echo ""; \
	echo "5. Configure:"; \
	echo "   doas vi /etc/sysmanage-agent/sysmanage-agent.yaml"; \
	echo "   doas rcctl restart sysmanage_agent"; \
	echo ""; \
	echo "For detailed instructions, see:"; \
	echo "  $$CURRENT_DIR/installer/openbsd/README.md"

# Build FreeBSD .pkg package
installer-freebsd:
	@echo "=== Building FreeBSD Package ==="
	@echo ""
	@echo "Creating FreeBSD .pkg package for sysmanage-agent..."
	@echo ""
	@CURRENT_DIR=$$(pwd); \
	OUTPUT_DIR="$$CURRENT_DIR/installer/dist"; \
	BUILD_DIR="$$CURRENT_DIR/build/freebsd"; \
	PACKAGE_ROOT="$$BUILD_DIR/package-root"; \
	MANIFEST_FILE="$$CURRENT_DIR/installer/freebsd/+MANIFEST"; \
	echo "Determining version from git..."; \
	VERSION=$$(git describe --tags --abbrev=0 2>/dev/null | sed 's/^v//'); \
	if [ -z "$$VERSION" ]; then \
		VERSION="1.0.0"; \
		echo "WARNING: No git tags found, using default version: $$VERSION"; \
	else \
		echo "Building version: $$VERSION"; \
	fi; \
	echo ""; \
	echo "Cleaning build directory..."; \
	rm -rf "$$BUILD_DIR"; \
	mkdir -p "$$PACKAGE_ROOT"; \
	echo "✓ Build directory prepared: $$BUILD_DIR"; \
	echo ""; \
	echo "Creating package directory structure..."; \
	mkdir -p "$$PACKAGE_ROOT/usr/local/lib/sysmanage-agent"; \
	mkdir -p "$$PACKAGE_ROOT/usr/local/etc/sysmanage-agent"; \
	mkdir -p "$$PACKAGE_ROOT/usr/local/etc/rc.d"; \
	mkdir -p "$$PACKAGE_ROOT/var/log/sysmanage-agent"; \
	mkdir -p "$$PACKAGE_ROOT/var/run/sysmanage"; \
	echo "✓ Package directories created"; \
	echo ""; \
	echo "Copying agent files..."; \
	cp -R src "$$PACKAGE_ROOT/usr/local/lib/sysmanage-agent/"; \
	cp main.py "$$PACKAGE_ROOT/usr/local/lib/sysmanage-agent/"; \
	cp requirements.txt "$$PACKAGE_ROOT/usr/local/lib/sysmanage-agent/"; \
	cp alembic.ini "$$PACKAGE_ROOT/usr/local/lib/sysmanage-agent/"; \
	echo "✓ Agent files copied"; \
	echo ""; \
	echo "Copying configuration files..."; \
	cp installer/freebsd/config.yaml.example "$$PACKAGE_ROOT/usr/local/etc/sysmanage-agent/"; \
	cp installer/freebsd/sysmanage-agent.rc "$$PACKAGE_ROOT/usr/local/etc/rc.d/sysmanage_agent"; \
	cp installer/freebsd/sysmanage-agent-wrapper.sh "$$PACKAGE_ROOT/usr/local/lib/sysmanage-agent/"; \
	chmod +x "$$PACKAGE_ROOT/usr/local/etc/rc.d/sysmanage_agent"; \
	chmod +x "$$PACKAGE_ROOT/usr/local/lib/sysmanage-agent/sysmanage-agent-wrapper.sh"; \
	echo "✓ Configuration files copied"; \
	echo ""; \
	echo "Creating package manifest..."; \
	sed "s/version: \".*\"/version: \"$$VERSION\"/" "$$MANIFEST_FILE" > "$$BUILD_DIR/+MANIFEST"; \
	echo "✓ Manifest created with version $$VERSION"; \
	echo ""; \
	echo "Building package..."; \
	cd "$$BUILD_DIR" && pkg create -M +MANIFEST -r package-root -o .; \
	if [ $$? -eq 0 ]; then \
		PACKAGE_FILE=$$(ls sysmanage-agent-*.pkg 2>/dev/null | head -1); \
		if [ -n "$$PACKAGE_FILE" ]; then \
			mkdir -p "$$OUTPUT_DIR"; \
			mv "$$PACKAGE_FILE" "$$OUTPUT_DIR/"; \
			echo ""; \
			echo "✓ FreeBSD package created successfully: $$OUTPUT_DIR/$$PACKAGE_FILE"; \
			echo ""; \
			echo "Installation commands:"; \
			echo "  sudo pkg add $$OUTPUT_DIR/$$PACKAGE_FILE"; \
			echo "  sudo sysrc sysmanage_agent_enable=YES"; \
			echo "  sudo service sysmanage-agent start"; \
		else \
			echo "ERROR: Package file not found after creation"; \
			exit 1; \
		fi; \
	else \
		echo "ERROR: Package creation failed"; \
		exit 1; \
	fi

# Build Windows .msi installer packages (both x64 and ARM64)
installer-msi: installer-msi-all

# Build Windows .msi installer for x64
installer-msi-x64:
	@echo "Generating requirements-prod.txt from requirements.txt..."
	@python scripts/update-requirements-prod.py
	@powershell -ExecutionPolicy Bypass -File installer\windows\build-msi.ps1 -Architecture x64

# Build Windows .msi installer for ARM64
installer-msi-arm64:
	@echo "Generating requirements-prod.txt from requirements.txt..."
	@python scripts/update-requirements-prod.py
	@powershell -ExecutionPolicy Bypass -File installer\windows\build-msi.ps1 -Architecture arm64

# Build Windows .msi installers for both x64 and ARM64
installer-msi-all: installer-msi-x64 installer-msi-arm64
	@echo ""
	@echo "=================================="
	@echo "All Windows installers built!"
	@echo "=================================="

# Build NetBSD .tgz package
installer-netbsd:
	@echo "=== Building NetBSD Package ==="
	@echo ""
	@echo "Creating NetBSD .tgz package for sysmanage-agent..."
	@echo ""
	@CURRENT_DIR=$$(pwd); \
	OUTPUT_DIR="$$CURRENT_DIR/installer/dist"; \
	BUILD_DIR="$$CURRENT_DIR/build/netbsd"; \
	PACKAGE_ROOT="$$BUILD_DIR/package-root"; \
	echo "Determining version from git..."; \
	VERSION=$$(git describe --tags --abbrev=0 2>/dev/null | sed 's/^v//'); \
	if [ -z "$$VERSION" ]; then \
		VERSION="1.0.0"; \
		echo "WARNING: No git tags found, using default version: $$VERSION"; \
	else \
		echo "Building version: $$VERSION"; \
	fi; \
	echo ""; \
	echo "Cleaning build directory..."; \
	rm -rf "$$BUILD_DIR"; \
	mkdir -p "$$PACKAGE_ROOT"; \
	echo "✓ Build directory prepared: $$BUILD_DIR"; \
	echo ""; \
	echo "Creating package directory structure..."; \
	mkdir -p "$$PACKAGE_ROOT/usr/pkg/lib/sysmanage-agent"; \
	mkdir -p "$$PACKAGE_ROOT/usr/pkg/etc/sysmanage-agent"; \
	mkdir -p "$$PACKAGE_ROOT/usr/pkg/share/examples/rc.d"; \
	mkdir -p "$$PACKAGE_ROOT/var/log/sysmanage-agent"; \
	mkdir -p "$$PACKAGE_ROOT/var/run/sysmanage"; \
	echo "✓ Package directories created"; \
	echo ""; \
	echo "Copying agent files..."; \
	cp -R src "$$PACKAGE_ROOT/usr/pkg/lib/sysmanage-agent/"; \
	cp main.py "$$PACKAGE_ROOT/usr/pkg/lib/sysmanage-agent/"; \
	cp requirements.txt "$$PACKAGE_ROOT/usr/pkg/lib/sysmanage-agent/"; \
	cp alembic.ini "$$PACKAGE_ROOT/usr/pkg/lib/sysmanage-agent/"; \
	echo "✓ Agent files copied"; \
	echo ""; \
	echo "Copying configuration files..."; \
	cp installer/netbsd/config.yaml.example "$$PACKAGE_ROOT/usr/pkg/etc/sysmanage-agent/"; \
	cp installer/netbsd/sysmanage_agent.rc "$$PACKAGE_ROOT/usr/pkg/share/examples/rc.d/sysmanage_agent"; \
	cp installer/netbsd/sysmanage-agent-wrapper.sh "$$PACKAGE_ROOT/usr/pkg/lib/sysmanage-agent/"; \
	chmod +x "$$PACKAGE_ROOT/usr/pkg/share/examples/rc.d/sysmanage_agent"; \
	chmod +x "$$PACKAGE_ROOT/usr/pkg/lib/sysmanage-agent/sysmanage-agent-wrapper.sh"; \
	echo "✓ Configuration files copied"; \
	echo ""; \
	echo "Copying package metadata files..."; \
	cp installer/netbsd/+INSTALL "$$BUILD_DIR/"; \
	cp installer/netbsd/+DESC "$$BUILD_DIR/"; \
	cp installer/netbsd/+COMMENT "$$BUILD_DIR/"; \
	cp installer/netbsd/+BUILD_INFO "$$BUILD_DIR/"; \
	chmod +x "$$BUILD_DIR/+INSTALL"; \
	echo "✓ Metadata files copied"; \
	echo ""; \
	echo "Creating packing list with dependencies..."; \
	{ \
		echo "@name sysmanage-agent-$$VERSION"; \
		echo "@comment SysManage Agent - System management agent for NetBSD"; \
		echo "@pkgdep python312>=3.12"; \
		echo "@pkgdep py312-websockets>=15.0"; \
		echo "@pkgdep py312-yaml>=6.0"; \
		echo "@pkgdep py312-aiohttp>=3.12"; \
		echo "@pkgdep py312-cryptography>=45.0"; \
		echo "@pkgdep py312-sqlalchemy>=2.0"; \
		echo "@pkgdep py312-alembic>=1.16"; \
		cd "$$PACKAGE_ROOT" && find . -type f -o -type l | sed 's,^\./,,'; \
		cd "$$PACKAGE_ROOT" && find . -type d | sed 's,^\./,,' | grep -v '^\.' | sed 's,^,@dirrm ,'; \
	} | sort -u > "$$BUILD_DIR/+CONTENTS"; \
	echo "✓ Packing list created with dependencies"; \
	echo ""; \
	echo "Building package with pkg_create..."; \
	pkg_create \
		-B "$$BUILD_DIR/+BUILD_INFO" \
		-c "$$BUILD_DIR/+COMMENT" \
		-d "$$BUILD_DIR/+DESC" \
		-I "$$BUILD_DIR/+INSTALL" \
		-f "$$BUILD_DIR/+CONTENTS" \
		-p "$$PACKAGE_ROOT" \
		"$$BUILD_DIR/sysmanage-agent-$$VERSION.tgz"; \
	if [ $$? -eq 0 ]; then \
		PACKAGE_FILE="sysmanage-agent-$$VERSION.tgz"; \
		if [ -f "$$BUILD_DIR/$$PACKAGE_FILE" ]; then \
			mkdir -p "$$OUTPUT_DIR"; \
			mv "$$BUILD_DIR/$$PACKAGE_FILE" "$$OUTPUT_DIR/"; \
			echo ""; \
			echo "✓ NetBSD package created successfully: $$OUTPUT_DIR/$$PACKAGE_FILE"; \
			echo ""; \
			echo "Installation commands:"; \
			echo "  sudo pkg_add $$OUTPUT_DIR/$$PACKAGE_FILE"; \
			echo "  sudo cp /usr/pkg/share/examples/rc.d/sysmanage_agent /etc/rc.d/"; \
			echo "  sudo sh -c 'echo sysmanage_agent=YES >> /etc/rc.conf'"; \
			echo "  sudo /etc/rc.d/sysmanage_agent start"; \
			echo ""; \
			echo "Package details:"; \
			ls -lh "$$OUTPUT_DIR/$$PACKAGE_FILE"; \
		else \
			echo "ERROR: Package file not found after creation"; \
			exit 1; \
		fi; \
	else \
		echo "ERROR: Package creation failed"; \
		exit 1; \
	fi

# Build Ubuntu Snap package
snap:
	@if [ "$$(uname -s)" != "Linux" ] || ! [ -f /etc/lsb-release ] || ! grep -q Ubuntu /etc/lsb-release 2>/dev/null; then \
		echo "ERROR: Snap packaging is only supported on Ubuntu systems."; \
		echo "Current system: $$(uname -s)"; \
		exit 1; \
	fi
	@echo "=== Building Ubuntu Snap Package ==="
	@echo ""
	@echo "Checking build dependencies..."
	@command -v snapcraft >/dev/null 2>&1 || { \
		echo "ERROR: snapcraft not found."; \
		echo "Install with: sudo apt-get install -y snapd snapcraft"; \
		echo "Or run: make install-dev"; \
		exit 1; \
	}
	@echo "✓ Snapcraft available"
	@echo ""
	@echo "Generating requirements-prod.txt from requirements.txt..."
	@python3 scripts/update-requirements-prod.py
	@echo "✓ requirements-prod.txt generated"
	@echo ""
	@echo "Building snap package..."
	@cd installer/ubuntu-snap && snapcraft pack --destructive-mode --verbose
	@echo ""
	@echo "==================================="; \
	echo "Build Complete!"; \
	echo "==================================="; \
	echo ""; \
	SNAP_FILE=$$(ls installer/ubuntu-snap/*.snap 2>/dev/null | head -1); \
	if [ -n "$$SNAP_FILE" ]; then \
		echo "Package: $$SNAP_FILE"; \
		ls -lh "$$SNAP_FILE"; \
		echo ""; \
		echo "Install with:"; \
		echo "  make snap-install"; \
		echo "  OR"; \
		echo "  sudo snap install $$SNAP_FILE --dangerous --classic"; \
		echo ""; \
		echo "After installation:"; \
		echo "  1. Edit /var/snap/sysmanage-agent/common/sysmanage-agent.yaml"; \
		echo "  2. Start: sudo snap start sysmanage-agent"; \
		echo "  3. Check status: sudo snap services sysmanage-agent"; \
		echo "  4. View logs: sudo snap logs sysmanage-agent"; \
		echo ""; \
	else \
		echo "ERROR: Built snap not found!"; \
		exit 1; \
	fi

# Clean snap build artifacts
snap-clean:
	@if [ "$$(uname -s)" != "Linux" ] || ! [ -f /etc/lsb-release ] || ! grep -q Ubuntu /etc/lsb-release 2>/dev/null; then \
		echo "ERROR: Snap packaging is only supported on Ubuntu systems."; \
		echo "Current system: $$(uname -s)"; \
		exit 1; \
	fi
	@echo "=== Cleaning Snap Build Artifacts ==="
	@echo ""
	@echo "Removing snap build artifacts..."
	@cd installer/ubuntu-snap && snapcraft clean || true
	@rm -rf installer/ubuntu-snap/*.snap
	@rm -rf installer/ubuntu-snap/prime
	@rm -rf installer/ubuntu-snap/stage
	@rm -rf installer/ubuntu-snap/parts
	@echo "✓ Snap build artifacts cleaned"
	@echo ""

# Install locally built snap package
snap-install:
	@if [ "$$(uname -s)" != "Linux" ] || ! [ -f /etc/lsb-release ] || ! grep -q Ubuntu /etc/lsb-release 2>/dev/null; then \
		echo "ERROR: Snap packaging is only supported on Ubuntu systems."; \
		echo "Current system: $$(uname -s)"; \
		exit 1; \
	fi
	@echo "=== Installing Snap Package ==="
	@echo ""
	@SNAP_FILE=$$(ls installer/ubuntu-snap/*.snap 2>/dev/null | head -1); \
	if [ -z "$$SNAP_FILE" ]; then \
		echo "ERROR: No snap package found in installer/ubuntu-snap/"; \
		echo "Build one first with: make snap"; \
		exit 1; \
	fi; \
	echo "Found snap package: $$SNAP_FILE"; \
	echo ""; \
	if snap list sysmanage-agent >/dev/null 2>&1; then \
		echo "Existing sysmanage-agent snap detected - upgrading in place..."; \
		echo "(Configuration will be preserved)"; \
		echo ""; \
	else \
		echo "Installing new snap..."; \
		echo ""; \
	fi; \
	sudo snap install "$$SNAP_FILE" --dangerous --classic || { \
		echo "ERROR: Failed to install snap"; \
		exit 1; \
	}; \
	echo ""; \
	echo "==================================="; \
	echo "Installation Complete!"; \
	echo "==================================="; \
	echo ""; \
	echo "Configuration:"; \
	echo "  Config file: /var/snap/sysmanage-agent/common/sysmanage-agent.yaml"; \
	echo ""; \
	echo "Service management:"; \
	echo "  Start:   sudo snap start sysmanage-agent"; \
	echo "  Stop:    sudo snap stop sysmanage-agent"; \
	echo "  Restart: sudo snap restart sysmanage-agent"; \
	echo "  Status:  sudo snap services sysmanage-agent"; \
	echo "  Logs:    sudo snap logs sysmanage-agent -f"; \
	echo ""

# Uninstall snap package
snap-uninstall:
	@if [ "$$(uname -s)" != "Linux" ] || ! [ -f /etc/lsb-release ] || ! grep -q Ubuntu /etc/lsb-release 2>/dev/null; then \
		echo "ERROR: Snap packaging is only supported on Ubuntu systems."; \
		echo "Current system: $$(uname -s)"; \
		exit 1; \
	fi
	@echo "=== Uninstalling Snap Package ==="
	@echo ""
	@if ! snap list sysmanage-agent >/dev/null 2>&1; then \
		echo "sysmanage-agent snap is not installed"; \
		exit 0; \
	fi
	@echo "Stopping sysmanage-agent service..."
	@sudo snap stop sysmanage-agent 2>/dev/null || true
	@echo "✓ Service stopped"
	@echo ""
	@echo "Backing up configuration..."
	@if [ -f /var/snap/sysmanage-agent/common/sysmanage-agent.yaml ]; then \
		sudo cp /var/snap/sysmanage-agent/common/sysmanage-agent.yaml /tmp/sysmanage-agent.yaml.preserved || true; \
		echo "✓ Configuration backed up"; \
	fi
	@echo ""
	@echo "Removing sysmanage-agent snap..."
	@sudo snap remove sysmanage-agent || { \
		echo "ERROR: Failed to remove snap"; \
		exit 1; \
	}
	@echo "✓ Snap removed"
	@echo ""
	@if [ -f /tmp/sysmanage-agent.yaml.preserved ]; then \
		echo "Restoring configuration..."; \
		sudo mkdir -p /var/snap/sysmanage-agent/common; \
		sudo cp /tmp/sysmanage-agent.yaml.preserved /var/snap/sysmanage-agent/common/sysmanage-agent.yaml || true; \
		sudo rm -f /tmp/sysmanage-agent.yaml.preserved; \
		echo "✓ Configuration restored to /var/snap/sysmanage-agent/common/sysmanage-agent.yaml"; \
		echo ""; \
	fi
	@echo "==================================="; \
	echo "Uninstallation Complete!"; \
	echo "==================================="; \
	echo ""; \
	echo "Configuration preserved at:"; \
	echo "  /var/snap/sysmanage-agent/common/sysmanage-agent.yaml"; \
	echo ""; \
	echo "To completely remove all data including config:"; \
	echo "  sudo rm -rf /var/snap/sysmanage-agent"; \
	echo ""
