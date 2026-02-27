# SysManage Agent Makefile
# Provides testing and linting for Python agent

.PHONY: test lint clean setup install-dev install-dev-rpm help format-python start start-privileged start-unprivileged stop security security-full security-python security-secrets security-upgrades sonarqube-scan install-sonar-scanner installer installer-deb installer-alpine installer-rpm installer-msi installer-msi-x64 installer-msi-arm64 installer-msi-all installer-openbsd installer-freebsd installer-netbsd snap snap-clean snap-install snap-uninstall snap-strict snap-strict-clean snap-strict-install snap-strict-uninstall sbom deploy-check-deps checksums release-notes deploy-launchpad deploy-obs deploy-copr deploy-snap deploy-docs-repo release-local

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
	@echo "  make sonarqube-scan - Run SonarQube/SonarCloud analysis"
	@echo "  make install-sonar-scanner - Install SonarQube scanner locally"
	@echo ""
	@echo "Packaging targets:"
	@echo "  make installer     - Build installer package (auto-detects platform)"
	@echo "  make installer-deb - Build Ubuntu/Debian .deb package (explicit)"
	@echo "  make installer-alpine - Build Alpine .apk packages via Docker (explicit)"
	@echo "  make installer-rpm - Build CentOS/RHEL/Fedora .rpm package (explicit)"
	@echo "  make installer-msi - Build Windows .msi package for x64 (default)"
	@echo "  make installer-msi-x64 - Build Windows .msi package for x64"
	@echo "  make installer-msi-arm64 - Build Windows .msi package for ARM64"
	@echo "  make installer-msi-all - Build Windows .msi for both x64 and ARM64"
	@echo "  make installer-openbsd - Prepare OpenBSD port (copy to /usr/ports)"
	@echo "  make installer-freebsd - Build FreeBSD .pkg package"
	@echo "  make installer-netbsd - Build NetBSD .tgz package"
	@echo "  make snap          - Build Ubuntu Snap package (classic confinement)"
	@echo "  make snap-clean    - Clean snap build artifacts"
	@echo "  make snap-install  - Install locally built snap package (Ubuntu only)"
	@echo "  make snap-uninstall - Uninstall snap package (Ubuntu only)"
	@echo "  make snap-strict   - Build Ubuntu Snap package (strict confinement)"
	@echo "  make snap-strict-clean - Clean strict snap build artifacts"
	@echo "  make snap-strict-install - Install locally built strict snap (Ubuntu only)"
	@echo "  make snap-strict-uninstall - Uninstall strict snap (Ubuntu only)"
	@echo "  make sbom          - Generate Software Bill of Materials (CycloneDX format)"
	@echo ""
	@echo "Deploy targets (local build & publish):"
	@echo "  make deploy-check-deps - Verify deployment tools are installed"
	@echo "  make checksums         - Generate SHA256 checksums for packages in installer/dist/"
	@echo "  make release-notes     - Generate release notes markdown"
	@echo "  make deploy-launchpad  - Build & upload source packages to Launchpad PPA"
	@echo "  make deploy-obs        - Upload to openSUSE Build Service"
	@echo "  make deploy-copr       - Build SRPM & upload to Fedora Copr"
	@echo "  make deploy-snap       - Build and publish snap to Snap Store (edge channel)"
	@echo "  make deploy-docs-repo  - Stage packages into local sysmanage-docs repo"
	@echo "  make release-local     - Full release pipeline with interactive confirmation"
	@echo ""
	@echo "Platform-specific notes:"
	@echo "  make install-dev auto-detects your platform and installs appropriate tools:"
	@echo "    Ubuntu/Debian: debhelper, dpkg-buildpackage, lintian, snapcraft, etc."
	@echo "    CentOS/RHEL/Fedora: rpm-build, rpmdevtools, python3-devel, etc."
	@echo "    Windows: WiX Toolset v4 (for MSI creation)"
	@echo "    OpenBSD: Python packages (websockets, yaml, aiohttp, cryptography, sqlalchemy, alembic)"
	@echo "    FreeBSD: pkgconf, rust (for package creation and cryptography compilation)"
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
		echo "[INFO] Checking for Flatpak build tools..."; \
		MISSING_FLATPAK=""; \
		if ! command -v flatpak >/dev/null 2>&1; then \
			MISSING_FLATPAK="$$MISSING_FLATPAK flatpak"; \
		fi; \
		if ! command -v flatpak-builder >/dev/null 2>&1; then \
			MISSING_FLATPAK="$$MISSING_FLATPAK flatpak-builder"; \
		fi; \
		if [ -n "$$MISSING_FLATPAK" ]; then \
			echo "Missing Flatpak tools:$$MISSING_FLATPAK"; \
			echo "Installing Flatpak build tools..."; \
			if command -v dnf >/dev/null 2>&1; then \
				echo "Running: sudo dnf install -y flatpak flatpak-builder"; \
				sudo dnf install -y flatpak flatpak-builder || { \
					echo "[WARNING] Could not install Flatpak tools. Run manually: sudo dnf install -y flatpak flatpak-builder"; \
				}; \
			else \
				echo "Running: sudo yum install -y flatpak flatpak-builder"; \
				sudo yum install -y flatpak flatpak-builder || { \
					echo "[WARNING] Could not install Flatpak tools. Run manually: sudo yum install -y flatpak flatpak-builder"; \
				}; \
			fi; \
		else \
			echo "✓ Flatpak build tools already installed"; \
		fi; \
		if command -v flatpak >/dev/null 2>&1; then \
			if ! flatpak remote-list --user | grep -q flathub; then \
				echo "Adding Flathub repository (user)..."; \
				flatpak remote-add --user --if-not-exists flathub https://flathub.org/repo/flathub.flatpakrepo || { \
					echo "[WARNING] Could not add Flathub repository"; \
				}; \
			else \
				echo "✓ Flathub repository already configured (user)"; \
			fi; \
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
		echo "[INFO] Checking for Flatpak build tools..."; \
		MISSING_FLATPAK=""; \
		if ! command -v flatpak >/dev/null 2>&1; then \
			MISSING_FLATPAK="$$MISSING_FLATPAK flatpak"; \
		fi; \
		if ! command -v flatpak-builder >/dev/null 2>&1; then \
			MISSING_FLATPAK="$$MISSING_FLATPAK flatpak-builder"; \
		fi; \
		if [ -n "$$MISSING_FLATPAK" ]; then \
			echo "Missing Flatpak tools:$$MISSING_FLATPAK"; \
			echo "Installing Flatpak build tools..."; \
			echo "Running: sudo zypper install -y flatpak flatpak-builder"; \
			sudo zypper install -y flatpak flatpak-builder || { \
				echo "[WARNING] Could not install Flatpak tools. Run manually: sudo zypper install -y flatpak flatpak-builder"; \
			}; \
		else \
			echo "✓ Flatpak build tools already installed"; \
		fi; \
		if command -v flatpak >/dev/null 2>&1; then \
			if ! flatpak remote-list --user | grep -q flathub; then \
				echo "Adding Flathub repository (user)..."; \
				flatpak remote-add --user --if-not-exists flathub https://flathub.org/repo/flathub.flatpakrepo || { \
					echo "[WARNING] Could not add Flathub repository"; \
				}; \
			else \
				echo "✓ Flathub repository already configured (user)"; \
			fi; \
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
		echo "[INFO] Checking for Python build dependencies (for strict snap)..."; \
		MISSING_PYTHON_DEPS=""; \
		dpkg -l libssl-dev 2>/dev/null | grep -q "^ii" || MISSING_PYTHON_DEPS="$$MISSING_PYTHON_DEPS libssl-dev"; \
		dpkg -l zlib1g-dev 2>/dev/null | grep -q "^ii" || MISSING_PYTHON_DEPS="$$MISSING_PYTHON_DEPS zlib1g-dev"; \
		dpkg -l libncurses5-dev 2>/dev/null | grep -q "^ii" || MISSING_PYTHON_DEPS="$$MISSING_PYTHON_DEPS libncurses5-dev"; \
		dpkg -l libreadline-dev 2>/dev/null | grep -q "^ii" || MISSING_PYTHON_DEPS="$$MISSING_PYTHON_DEPS libreadline-dev"; \
		dpkg -l libsqlite3-dev 2>/dev/null | grep -q "^ii" || MISSING_PYTHON_DEPS="$$MISSING_PYTHON_DEPS libsqlite3-dev"; \
		dpkg -l libffi-dev 2>/dev/null | grep -q "^ii" || MISSING_PYTHON_DEPS="$$MISSING_PYTHON_DEPS libffi-dev"; \
		if [ -n "$$MISSING_PYTHON_DEPS" ]; then \
			echo "Missing Python build dependencies:$$MISSING_PYTHON_DEPS"; \
			echo "Installing Python build dependencies for strict snap..."; \
			echo "Running: sudo apt-get install -y libssl-dev zlib1g-dev libncurses5-dev libncursesw5-dev libreadline-dev libsqlite3-dev libgdbm-dev libdb-dev libbz2-dev libexpat1-dev liblzma-dev libffi-dev uuid-dev wget"; \
			sudo apt-get install -y libssl-dev zlib1g-dev libncurses5-dev libncursesw5-dev libreadline-dev libsqlite3-dev libgdbm-dev libdb-dev libbz2-dev libexpat1-dev liblzma-dev libffi-dev uuid-dev wget || \
			echo "[WARNING] Could not install Python build dependencies. Run manually: sudo apt-get install -y libssl-dev zlib1g-dev libncurses5-dev libncursesw5-dev libreadline-dev libsqlite3-dev libgdbm-dev libdb-dev libbz2-dev libexpat1-dev liblzma-dev libffi-dev uuid-dev wget"; \
		else \
			echo "✓ All Python build dependencies already installed"; \
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
		echo "[INFO] Checking for Flatpak build tools..."; \
		MISSING_FLATPAK=""; \
		if ! command -v flatpak >/dev/null 2>&1; then \
			MISSING_FLATPAK="$$MISSING_FLATPAK flatpak"; \
		fi; \
		if ! command -v flatpak-builder >/dev/null 2>&1; then \
			MISSING_FLATPAK="$$MISSING_FLATPAK flatpak-builder"; \
		fi; \
		if [ -n "$$MISSING_FLATPAK" ]; then \
			echo "Missing Flatpak tools:$$MISSING_FLATPAK"; \
			echo "Installing Flatpak build tools..."; \
			echo "Running: sudo apt-get install -y flatpak flatpak-builder"; \
			sudo apt-get install -y flatpak flatpak-builder || { \
				echo "[WARNING] Could not install Flatpak tools. Run manually: sudo apt-get install -y flatpak flatpak-builder"; \
			}; \
		else \
			echo "✓ Flatpak build tools already installed"; \
		fi; \
		if command -v flatpak >/dev/null 2>&1; then \
			if ! flatpak remote-list --user | grep -q flathub; then \
				echo "Adding Flathub repository (user)..."; \
				flatpak remote-add --user --if-not-exists flathub https://flathub.org/repo/flathub.flatpakrepo || { \
					echo "[WARNING] Could not add Flathub repository"; \
				}; \
			else \
				echo "✓ Flathub repository already configured (user)"; \
			fi; \
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
		if ! pkg info -q rust; then \
			echo "    Installing rust for cryptography compilation..."; \
			sudo pkg install -y rust; \
		fi; \
		if ! pkg info -q py311-cython; then \
			echo "    Installing py311-cython for coverage C tracer..."; \
			sudo pkg install -y py311-cython; \
		fi; \
		echo "✓ FreeBSD package creation tools ready"; \
		$(PYTHON) scripts/install-dev-deps.py; \
	else \
		$(PYTHON) scripts/install-dev-deps.py; \
	fi
endif
	@echo "Checking for BSD C tracer requirements..."
	@$(PYTHON) scripts/check-openbsd-deps.py
	@echo ""
	@echo "=== Optional: SonarQube/SonarCloud Setup ==="
	@echo "For code quality scanning with 'make sonarqube-scan', choose one option:"
	@echo ""
	@echo "  1. SonarCloud (recommended for CI/CD):"
	@echo "     - Sign up at https://sonarcloud.io and import this project"
	@echo "     - Generate a token and add to your environment:"
	@echo "       export SONAR_TOKEN=your_token_here"
	@echo ""
	@echo "  2. Local SonarQube (Docker auto-start):"
	@echo "     - Just run 'make sonarqube-scan' with Docker installed"
	@echo "     - A temporary SonarQube container will start automatically"
	@echo ""
	@echo "  3. Install scanner locally: make install-sonar-scanner"
	@echo ""
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
	@$(PYTHON) -m pylint main.py src/ tests/ --rcfile=.pylintrc
else
	@$(PYTHON) -m pylint main.py src/ tests/ --rcfile=.pylintrc
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
	@set PYTHONWARNINGS=ignore::RuntimeWarning && $(PYTHON) -m pytest tests/ -v --tb=short -n auto --dist=loadfile --cov=main --cov=src/sysmanage_agent --cov=src/database --cov=src/i18n --cov=src/security --cov-report=term-missing --cov-report=html --cov-report=xml
else
	@PYTHONWARNINGS=ignore::RuntimeWarning $(PYTHON) -m pytest tests/ -v --tb=short -n auto --dist=loadfile --cov=main --cov=src/sysmanage_agent --cov=src/database --cov=src/i18n --cov=src/security --cov-report=term-missing --cov-report=html --cov-report=xml
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

# SonarQube/SonarCloud scan
sonarqube-scan: setup-venv
	@echo "=== SonarQube/SonarCloud Scan ==="
ifeq ($(OS),Windows_NT)
	@where sonar-scanner >nul 2>&1 || (echo "ERROR: sonar-scanner not found. Install from: https://docs.sonarqube.org/latest/analyzing-source-code/scanners/sonarscanner/" && exit 1)
	@if not exist sonar-project.properties (echo "ERROR: sonar-project.properties not found" && exit 1)
	@echo "Running SonarQube scanner..."
	@if defined SONAR_TOKEN ( \
		echo "Using SonarCloud with SONAR_TOKEN..." && \
		sonar-scanner -Dsonar.host.url=https://sonarcloud.io -Dsonar.token=%SONAR_TOKEN% \
	) else if defined SONAR_HOST_URL ( \
		echo "Using custom SonarQube server at %SONAR_HOST_URL%..." && \
		sonar-scanner -Dsonar.host.url=%SONAR_HOST_URL% \
	) else ( \
		echo "ERROR: Set SONAR_TOKEN for SonarCloud or SONAR_HOST_URL for local server" && \
		exit 1 \
	)
else
	@if ! command -v sonar-scanner >/dev/null 2>&1; then \
		echo "ERROR: sonar-scanner not found. Install with: make install-sonar-scanner"; \
		echo "Or download from: https://docs.sonarqube.org/latest/analyzing-source-code/scanners/sonarscanner/"; \
		exit 1; \
	fi
	@if [ ! -f sonar-project.properties ]; then \
		echo "ERROR: sonar-project.properties not found"; \
		exit 1; \
	fi
	@echo "Running SonarQube scanner..."
	@if [ -n "$$SONAR_TOKEN" ]; then \
		echo "Using SonarCloud with SONAR_TOKEN..."; \
		sonar-scanner -Dsonar.host.url=https://sonarcloud.io -Dsonar.token=$$SONAR_TOKEN; \
	elif [ -n "$$SONAR_HOST_URL" ]; then \
		echo "Using custom SonarQube server at $$SONAR_HOST_URL..."; \
		sonar-scanner -Dsonar.host.url=$$SONAR_HOST_URL; \
	elif curl -s --connect-timeout 2 http://localhost:9000/api/system/status >/dev/null 2>&1; then \
		echo "Found local SonarQube server at localhost:9000..."; \
		sonar-scanner -Dsonar.host.url=http://localhost:9000; \
	elif command -v docker >/dev/null 2>&1; then \
		echo "No SonarQube server found. Starting temporary Docker container..."; \
		docker run -d --name sonarqube-temp -p 9000:9000 sonarqube:lts-community || true; \
		echo "Waiting for SonarQube to start (this may take 1-2 minutes)..."; \
		for i in $$(seq 1 60); do \
			if curl -s --connect-timeout 2 http://localhost:9000/api/system/status 2>/dev/null | grep -q '"status":"UP"'; then \
				echo "SonarQube is ready!"; \
				break; \
			fi; \
			if [ $$i -eq 60 ]; then \
				echo "ERROR: SonarQube failed to start. Check: docker logs sonarqube-temp"; \
				exit 1; \
			fi; \
			sleep 2; \
		done; \
		sonar-scanner -Dsonar.host.url=http://localhost:9000; \
		echo "Note: SonarQube container 'sonarqube-temp' is still running."; \
		echo "Stop with: docker stop sonarqube-temp && docker rm sonarqube-temp"; \
	else \
		echo ""; \
		echo "ERROR: No SonarQube server available."; \
		echo ""; \
		echo "Options:"; \
		echo "  1. Use SonarCloud (recommended):"; \
		echo "     - Sign up at https://sonarcloud.io"; \
		echo "     - Import this project"; \
		echo "     - Generate a token and run: export SONAR_TOKEN=your_token"; \
		echo ""; \
		echo "  2. Start local SonarQube with Docker:"; \
		echo "     docker run -d --name sonarqube -p 9000:9000 sonarqube:lts-community"; \
		echo ""; \
		echo "  3. Install Docker to enable automatic local scanning"; \
		echo ""; \
		exit 1; \
	fi
endif
	@echo "[OK] SonarQube scan completed"

# Install SonarQube scanner (helper target)
install-sonar-scanner:
	@echo "=== Installing SonarQube Scanner ==="
ifeq ($(OS),Windows_NT)
	@echo "Please download SonarScanner for Windows from:"
	@echo "https://docs.sonarqube.org/latest/analyzing-source-code/scanners/sonarscanner/"
	@echo "And add it to your PATH"
else
	@case "$$(uname -s)" in \
		Linux) \
			if command -v apt-get >/dev/null 2>&1; then \
				echo "Installing via apt..."; \
				sudo apt-get update && sudo apt-get install -y unzip; \
			fi; \
			echo "Downloading SonarScanner..."; \
			curl -sSL -o /tmp/sonar-scanner.zip https://binaries.sonarsource.com/Distribution/sonar-scanner-cli/sonar-scanner-cli-5.0.1.3006-linux.zip; \
			unzip -o /tmp/sonar-scanner.zip -d /tmp/; \
			sudo mv /tmp/sonar-scanner-5.0.1.3006-linux /opt/sonar-scanner; \
			sudo ln -sf /opt/sonar-scanner/bin/sonar-scanner /usr/local/bin/sonar-scanner; \
			rm /tmp/sonar-scanner.zip; \
			;; \
		Darwin) \
			if command -v brew >/dev/null 2>&1; then \
				brew install sonar-scanner; \
			else \
				echo "Install Homebrew first, then run: brew install sonar-scanner"; \
				exit 1; \
			fi; \
			;; \
		*) \
			echo "Please install sonar-scanner manually from:"; \
			echo "https://docs.sonarqube.org/latest/analyzing-source-code/scanners/sonarscanner/"; \
			exit 1; \
			;; \
	esac
endif
	@echo "[OK] SonarScanner installed"

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
	echo "Generating OpenBSD PLIST..."; \
	python3 installer/openbsd/generate-plist.py || { \
		echo "ERROR: Failed to generate PLIST"; \
		exit 1; \
	}; \
	echo "✓ PLIST generated"; \
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
	echo "Generating distinfo checksums..."; \
	cd "$$PORTS_DIR" && doas make makesum || { \
		echo "ERROR: Failed to generate distinfo checksums"; \
		exit 1; \
	}; \
	echo "✓ Checksums generated"; \
	echo ""; \
	echo "Copying updated distinfo back to source..."; \
	doas cp "$$PORTS_DIR/distinfo" "$$SOURCE_DIR/distinfo" || { \
		echo "ERROR: Failed to copy distinfo back to source"; \
		exit 1; \
	}; \
	echo "✓ Updated distinfo copied to $$SOURCE_DIR/distinfo"; \
	echo ""; \
	echo "==================================="; \
	echo "Port Preparation Complete!"; \
	echo "==================================="; \
	echo ""; \
	echo "Port location: $$PORTS_DIR"; \
	echo ""; \
	echo "Next steps:"; \
	echo ""; \
	echo "1. Build the port:"; \
	echo "   cd $$PORTS_DIR"; \
	echo "   doas make"; \
	echo ""; \
	echo "2. Install the port:"; \
	echo "   doas make install"; \
	echo ""; \
	echo "3. Enable and start the service:"; \
	echo "   doas rcctl enable sysmanage_agent"; \
	echo "   doas rcctl start sysmanage_agent"; \
	echo ""; \
	echo "4. Configure:"; \
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
	echo "Copying SBOM..."; \
	mkdir -p "$$PACKAGE_ROOT/usr/local/share/doc/sysmanage-agent/sbom"; \
	if [ -f sbom/sysmanage-agent-sbom.json ]; then \
		cp sbom/sysmanage-agent-sbom.json "$$PACKAGE_ROOT/usr/local/share/doc/sysmanage-agent/sbom/"; \
		echo "✓ SBOM copied"; \
	else \
		echo "⚠ SBOM not found (sbom/sysmanage-agent-sbom.json)"; \
	fi; \
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

# Build Alpine .apk packages using Docker (replicates CI/CD Alpine build)
# Supports ALPINE_VERSIONS env var (default: "3.19 3.20 3.21")
installer-alpine:
	@echo "=== Building Alpine .apk Packages via Docker ==="
	@echo ""
	@command -v docker >/dev/null 2>&1 || { \
		echo "ERROR: Docker not found."; \
		echo "Docker is required to build Alpine packages."; \
		echo "Install from: https://docs.docker.com/engine/install/"; \
		exit 1; \
	}
	@echo "✓ Docker available"
	@echo ""
	@set -e; \
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
	ALPINE_VERSIONS="$${ALPINE_VERSIONS:-3.19 3.20 3.21}"; \
	echo "Alpine versions: $$ALPINE_VERSIONS"; \
	echo ""; \
	mkdir -p installer/dist; \
	for ALPINE_VER in $$ALPINE_VERSIONS; do \
		echo "--- Building for Alpine $$ALPINE_VER ---"; \
		echo ""; \
		docker pull alpine:$$ALPINE_VER; \
		docker run --rm \
			-v "$$(pwd):/workspace" \
			-e VERSION="$$VERSION" \
			alpine:$$ALPINE_VER \
			/workspace/installer/alpine/docker-build.sh; \
		ALPINE_NODOT=$$(echo "$$ALPINE_VER" | tr -d '.'); \
		for pkg in sysmanage-agent-*.apk; do \
			if [ -f "$$pkg" ]; then \
				NEWNAME="sysmanage-agent-$${VERSION}-alpine$${ALPINE_NODOT}.apk"; \
				mv "$$pkg" "installer/dist/$$NEWNAME"; \
				echo "  Created: installer/dist/$$NEWNAME"; \
			fi; \
		done; \
		echo ""; \
	done; \
	echo "✓ Alpine packages built successfully!"; \
	echo ""; \
	ls -lh installer/dist/*alpine*.apk 2>/dev/null || echo "WARNING: No .apk files found in installer/dist/"

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
	echo "Copying SBOM..."; \
	mkdir -p "$$PACKAGE_ROOT/usr/pkg/share/doc/sysmanage-agent/sbom"; \
	if [ -f sbom/sysmanage-agent-sbom.json ]; then \
		cp sbom/sysmanage-agent-sbom.json "$$PACKAGE_ROOT/usr/pkg/share/doc/sysmanage-agent/sbom/"; \
		echo "✓ SBOM copied"; \
	else \
		echo "⚠ SBOM not found (sbom/sysmanage-agent-sbom.json)"; \
	fi; \
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

# Build strict confinement snap package
snap-strict:
	@if [ "$$(uname -s)" != "Linux" ] || ! [ -f /etc/lsb-release ] || ! grep -q Ubuntu /etc/lsb-release 2>/dev/null; then \
		echo "ERROR: Snap packaging is only supported on Ubuntu systems."; \
		echo "Current system: $$(uname -s)"; \
		exit 1; \
	fi
	@echo "=== Building Ubuntu Snap Package (Strict Confinement) ==="
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
	@echo "Building strict confinement snap package in LXD container (compiling Python 3.10 from source)..."
	@echo "This will take several minutes due to Python compilation and LXD container setup..."
	@echo ""
	@cd installer/ubuntu-snap-strict && snapcraft pack --verbose
	@echo ""
	@echo "==================================="; \
	echo "Build Complete!"; \
	echo "==================================="; \
	echo ""; \
	SNAP_FILE=$$(ls installer/ubuntu-snap-strict/*.snap 2>/dev/null | head -1); \
	if [ -n "$$SNAP_FILE" ]; then \
		echo "Package: $$SNAP_FILE"; \
		ls -lh "$$SNAP_FILE"; \
		echo ""; \
		echo "Install with:"; \
		echo "  make snap-strict-install"; \
		echo "  OR"; \
		echo "  sudo snap install $$SNAP_FILE --dangerous"; \
		echo ""; \
		echo "After installation:"; \
		echo "  1. Edit /var/snap/sysmanage-agent-strict/common/sysmanage-agent.yaml"; \
		echo "  2. Start: sudo snap start sysmanage-agent-strict"; \
		echo "  3. Check status: sudo snap services sysmanage-agent-strict"; \
		echo "  4. View logs: sudo snap logs sysmanage-agent-strict -f"; \
		echo ""; \
		echo "Note: Strict confinement provides read-only monitoring capabilities."; \
		echo "      For full management features, use 'make snap' (classic confinement)."; \
		echo ""; \
	else \
		echo "ERROR: Built snap not found!"; \
		exit 1; \
	fi

# Clean strict snap build artifacts
snap-strict-clean:
	@if [ "$$(uname -s)" != "Linux" ] || ! [ -f /etc/lsb-release ] || ! grep -q Ubuntu /etc/lsb-release 2>/dev/null; then \
		echo "ERROR: Snap packaging is only supported on Ubuntu systems."; \
		echo "Current system: $$(uname -s)"; \
		exit 1; \
	fi
	@echo "=== Cleaning Strict Snap Build Artifacts ==="
	@echo ""
	@echo "Removing snap build artifacts..."
	@cd installer/ubuntu-snap-strict && snapcraft clean || true
	@rm -rf installer/ubuntu-snap-strict/*.snap
	@rm -rf installer/ubuntu-snap-strict/prime
	@rm -rf installer/ubuntu-snap-strict/stage
	@rm -rf installer/ubuntu-snap-strict/parts
	@echo "✓ Strict snap build artifacts cleaned"
	@echo ""

# Install locally built strict snap package
snap-strict-install:
	@if [ "$$(uname -s)" != "Linux" ] || ! [ -f /etc/lsb-release ] || ! grep -q Ubuntu /etc/lsb-release 2>/dev/null; then \
		echo "ERROR: Snap packaging is only supported on Ubuntu systems."; \
		echo "Current system: $$(uname -s)"; \
		exit 1; \
	fi
	@echo "=== Installing Strict Snap Package ==="
	@echo ""
	@SNAP_FILE=$$(ls installer/ubuntu-snap-strict/*.snap 2>/dev/null | head -1); \
	if [ -z "$$SNAP_FILE" ]; then \
		echo "ERROR: No snap package found in installer/ubuntu-snap-strict/"; \
		echo "Build one first with: make snap-strict"; \
		exit 1; \
	fi; \
	echo "Found snap package: $$SNAP_FILE"; \
	echo ""; \
	if snap list sysmanage-agent-strict >/dev/null 2>&1; then \
		echo "Existing sysmanage-agent-strict snap detected - upgrading in place..."; \
		echo "(Configuration will be preserved)"; \
		echo ""; \
	else \
		echo "Installing new snap..."; \
		echo ""; \
	fi; \
	sudo snap install "$$SNAP_FILE" --dangerous || { \
		echo "ERROR: Failed to install snap"; \
		exit 1; \
	}; \
	echo ""; \
	echo "==================================="; \
	echo "Installation Complete!"; \
	echo "==================================="; \
	echo ""; \
	echo "Configuration (using snap commands):"; \
	echo "  Required:"; \
	echo "    sudo snap set sysmanage-agent-strict server-url=\"wss://your-server:8443\""; \
	echo ""; \
	echo "  Optional:"; \
	echo "    sudo snap set sysmanage-agent-strict server-token=\"YOUR_TOKEN\""; \
	echo "    sudo snap set sysmanage-agent-strict log-level=\"INFO|WARNING|ERROR|CRITICAL\""; \
	echo "    sudo snap set sysmanage-agent-strict verify-ssl=true"; \
	echo "    sudo snap set sysmanage-agent-strict reconnect-interval=30"; \
	echo ""; \
	echo "  View settings:"; \
	echo "    sudo snap get sysmanage-agent-strict"; \
	echo ""; \
	echo "  Config file (auto-generated):"; \
	echo "    /var/snap/sysmanage-agent-strict/common/sysmanage-agent.yaml"; \
	echo ""; \
	echo "Service management:"; \
	echo "  Start:   sudo snap start sysmanage-agent-strict"; \
	echo "  Stop:    sudo snap stop sysmanage-agent-strict"; \
	echo "  Restart: sudo snap restart sysmanage-agent-strict"; \
	echo "  Status:  sudo snap services sysmanage-agent-strict"; \
	echo "  Logs:    sudo snap logs sysmanage-agent-strict -f"; \
	echo ""; \
	echo "Note: Configuration changes auto-restart the service."; \
	echo ""

# Uninstall strict snap package
snap-strict-uninstall:
	@if [ "$$(uname -s)" != "Linux" ] || ! [ -f /etc/lsb-release ] || ! grep -q Ubuntu /etc/lsb-release 2>/dev/null; then \
		echo "ERROR: Snap packaging is only supported on Ubuntu systems."; \
		echo "Current system: $$(uname -s)"; \
		exit 1; \
	fi
	@echo "=== Uninstalling Strict Snap Package ==="
	@echo ""
	@if ! snap list sysmanage-agent-strict >/dev/null 2>&1; then \
		echo "sysmanage-agent-strict snap is not installed"; \
		exit 0; \
	fi
	@echo "Stopping sysmanage-agent-strict service..."
	@sudo snap stop sysmanage-agent-strict 2>/dev/null || true
	@echo "✓ Service stopped"
	@echo ""
	@echo "Backing up configuration..."
	@if [ -f /var/snap/sysmanage-agent-strict/common/sysmanage-agent.yaml ]; then \
		sudo cp /var/snap/sysmanage-agent-strict/common/sysmanage-agent.yaml /tmp/sysmanage-agent-strict.yaml.preserved || true; \
		echo "✓ Configuration backed up"; \
	fi
	@echo ""
	@echo "Removing sysmanage-agent-strict snap..."
	@sudo snap remove sysmanage-agent-strict || { \
		echo "ERROR: Failed to remove snap"; \
		exit 1; \
	}
	@echo "✓ Snap removed"
	@echo ""
	@if [ -f /tmp/sysmanage-agent-strict.yaml.preserved ]; then \
		echo "Restoring configuration..."; \
		sudo mkdir -p /var/snap/sysmanage-agent-strict/common; \
		sudo cp /tmp/sysmanage-agent-strict.yaml.preserved /var/snap/sysmanage-agent-strict/common/sysmanage-agent.yaml || true; \
		sudo rm -f /tmp/sysmanage-agent-strict.yaml.preserved; \
		echo "✓ Configuration restored to /var/snap/sysmanage-agent-strict/common/sysmanage-agent.yaml"; \
		echo ""; \
	fi
	@echo "==================================="; \
	echo "Uninstallation Complete!"; \
	echo "==================================="; \
	echo ""; \
	echo "Configuration preserved at:"; \
	echo "  /var/snap/sysmanage-agent-strict/common/sysmanage-agent.yaml"; \
	echo ""; \
	echo "To completely remove all data including config:"; \
	echo "  sudo rm -rf /var/snap/sysmanage-agent-strict"; \
	echo ""

# Publish strict snap to store (edge channel)
snap-strict-publish:
	@if [ "$$(uname -s)" != "Linux" ] || ! [ -f /etc/lsb-release ] || ! grep -q Ubuntu /etc/lsb-release 2>/dev/null; then \
		echo "ERROR: Snap packaging is only supported on Ubuntu systems."; \
		echo "Current system: $$(uname -s)"; \
		exit 1; \
	fi
	@echo "=== Publishing Strict Snap to Store (Edge Channel) ==="
	@echo ""
	@SNAP_FILE=$$(ls -t installer/ubuntu-snap-strict/sysmanage-agent-strict_*.snap 2>/dev/null | head -1); \
	if [ -z "$$SNAP_FILE" ]; then \
		echo "ERROR: No snap file found in installer/ubuntu-snap-strict/"; \
		echo "Run 'make snap-strict' first to build the snap."; \
		exit 1; \
	fi; \
	echo "Found snap: $$SNAP_FILE"; \
	echo ""; \
	echo "This will:"; \
	echo "  1. Login to Snapcraft (if not already logged in)"; \
	echo "  2. Register 'sysmanage-agent-strict' name (if not registered)"; \
	echo "  3. Upload and release to edge channel"; \
	echo ""; \
	read -p "Continue? [y/N] " -n 1 -r; \
	echo ""; \
	if [[ ! $$REPLY =~ ^[Yy]$$ ]]; then \
		echo "Aborted."; \
		exit 1; \
	fi; \
	echo ""; \
	echo "Step 1: Logging in to Snapcraft..."; \
	if ! snapcraft whoami >/dev/null 2>&1; then \
		snapcraft login || { \
			echo "ERROR: Failed to login to Snapcraft"; \
			exit 1; \
		}; \
	else \
		echo "✓ Already logged in as $$(snapcraft whoami | grep email | awk '{print $$2}')"; \
	fi; \
	echo ""; \
	echo "Step 2: Registering snap name..."; \
	if snapcraft register sysmanage-agent-strict 2>&1 | grep -q "already registered"; then \
		echo "✓ Name already registered"; \
	elif snapcraft register sysmanage-agent-strict; then \
		echo "✓ Name registered successfully"; \
	else \
		echo "ERROR: Failed to register snap name"; \
		exit 1; \
	fi; \
	echo ""; \
	echo "Step 3: Uploading to edge channel..."; \
	snapcraft upload --release=edge "$$SNAP_FILE" || { \
		echo "ERROR: Failed to upload snap"; \
		exit 1; \
	}; \
	echo ""; \
	echo "==================================="; \
	echo "Publication Complete!"; \
	echo "==================================="; \
	echo ""; \
	echo "Your snap has been published to the edge channel."; \
	echo ""; \
	echo "View your snap:"; \
	echo "  https://snapcraft.io/sysmanage-agent-strict"; \
	echo ""; \
	echo "Check status:"; \
	echo "  snapcraft status sysmanage-agent-strict"; \
	echo ""; \
	echo "Install from edge:"; \
	echo "  sudo snap install sysmanage-agent-strict --edge"; \
	echo ""; \
	echo "Promote to other channels when ready:"; \
	echo "  snapcraft release sysmanage-agent-strict <revision> beta"; \
	echo "  snapcraft release sysmanage-agent-strict <revision> candidate"; \
	echo "  snapcraft release sysmanage-agent-strict <revision> stable"; \
	echo ""

# Build Flatpak package
flatpak:
	@echo "=== Building Flatpak Package ==="
	@echo ""
	@# Check for supported Linux distributions
	@if [ "$$(uname -s)" != "Linux" ]; then \
		echo "ERROR: Flatpak packaging is only supported on Linux systems."; \
		echo "Current system: $$(uname -s)"; \
		exit 1; \
	fi
	@echo "Checking build dependencies..."
	@command -v flatpak >/dev/null 2>&1 || { \
		echo "ERROR: flatpak not found."; \
		echo "Install with your package manager:"; \
		echo "  Ubuntu/Debian: sudo apt-get install -y flatpak flatpak-builder"; \
		echo "  Fedora/RHEL:   sudo dnf install -y flatpak flatpak-builder"; \
		echo "  openSUSE:      sudo zypper install -y flatpak flatpak-builder"; \
		echo "Or run: make install-dev"; \
		exit 1; \
	}
	@command -v flatpak-builder >/dev/null 2>&1 || { \
		echo "ERROR: flatpak-builder not found."; \
		echo "Install with your package manager:"; \
		echo "  Ubuntu/Debian: sudo apt-get install -y flatpak-builder"; \
		echo "  Fedora/RHEL:   sudo dnf install -y flatpak-builder"; \
		echo "  openSUSE:      sudo zypper install -y flatpak-builder"; \
		echo "Or run: make install-dev"; \
		exit 1; \
	}
	@echo "✓ Flatpak tools available"
	@echo ""
	@# Check for Flathub runtime (user installation)
	@if ! flatpak remote-list --user | grep -q flathub; then \
		echo "Flathub repository not configured. Adding for user..."; \
		flatpak remote-add --user --if-not-exists flathub https://flathub.org/repo/flathub.flatpakrepo || { \
			echo "ERROR: Failed to add Flathub repository"; \
			exit 1; \
		}; \
	fi
	@echo "✓ Flathub repository configured (user)"
	@echo ""
	@# Install Freedesktop runtime and SDK if not present (user installation)
	@if ! flatpak list --user --runtime | grep -q "org.freedesktop.Platform.*24.08"; then \
		echo "Installing Freedesktop Platform 24.08 (user)..."; \
		flatpak install -y --user flathub org.freedesktop.Platform/x86_64/24.08 || { \
			echo "ERROR: Failed to install Freedesktop Platform"; \
			exit 1; \
		}; \
	else \
		echo "✓ Freedesktop Platform 24.08 already installed"; \
	fi
	@if ! flatpak list --user --runtime | grep -q "org.freedesktop.Sdk.*24.08"; then \
		echo "Installing Freedesktop SDK 24.08 (user)..."; \
		flatpak install -y --user flathub org.freedesktop.Sdk/x86_64/24.08 || { \
			echo "ERROR: Failed to install Freedesktop SDK"; \
			exit 1; \
		}; \
	else \
		echo "✓ Freedesktop SDK 24.08 already installed"; \
	fi
	@echo "✓ Required runtimes installed"
	@echo ""
	@# Get version
	@if [ -f VERSION ]; then \
		VERSION=$$(cat VERSION); \
	else \
		VERSION=$$(git describe --tags --always 2>/dev/null || echo "dev"); \
	fi; \
	echo "Building Flatpak for version: $$VERSION"; \
	echo ""
	@# Copy service scripts to flatpak directory
	@echo "Copying service scripts..."
	@cp installer/flatpak/sysmanage-service-install.sh installer/flatpak/sysmanage-service-install.sh.tmp 2>/dev/null || true
	@cp installer/flatpak/sysmanage-service-uninstall.sh installer/flatpak/sysmanage-service-uninstall.sh.tmp 2>/dev/null || true
	@echo "✓ Service scripts ready"
	@echo ""
	@# Create source tarball
	@echo "Creating source tarball..."
	@tar czf installer/flatpak/sysmanage-agent-src.tar.gz \
		--exclude='.venv' \
		--exclude='.git' \
		--exclude='__pycache__' \
		--exclude='*.pyc' \
		--exclude='.pytest_cache' \
		--exclude='agent.db' \
		src main.py alembic.ini requirements.txt
	@echo "✓ Source tarball created"
	@echo ""
	@# Create runtime-only requirements (exclude dev/test dependencies)
	@echo "Creating runtime requirements..."
	@grep -v "^semgrep\|^bandit\|^black\|^pylint\|^pytest\|^coverage\|^safety\|^playwright\|^selenium\|^webdriver-manager" requirements.txt > installer/flatpak/requirements-runtime.txt
	@echo "✓ Runtime requirements created"
	@echo ""
	@# Download Python dependencies as wheels
	@echo "Downloading Python dependencies..."
	@mkdir -p installer/flatpak/pypi-dependencies
	@pip3 download -r installer/flatpak/requirements-runtime.txt -d installer/flatpak/pypi-dependencies \
		--platform manylinux2014_x86_64 \
		--platform manylinux_2_17_x86_64 \
		--python-version 3.12 \
		--only-binary=:all: 2>&1 | grep -v "Ignoring" || true
	@# Also get pure Python packages and any that don't have platform-specific builds
	@pip3 download -r installer/flatpak/requirements-runtime.txt -d installer/flatpak/pypi-dependencies \
		--python-version 3.12 \
		--no-deps 2>&1 | grep -v "Requirement already satisfied" || true
	@echo "✓ Python dependencies downloaded ($(ls -1 installer/flatpak/pypi-dependencies 2>/dev/null | wc -l) files)"
	@echo ""
	@# Create tarball of dependencies (with the directory structure preserved)
	@echo "Creating dependencies tarball..."
	@cd installer/flatpak/pypi-dependencies && tar czf ../pypi-dependencies.tar.gz .
	@echo "✓ Dependencies tarball created"
	@echo ""
	@# Update version in metainfo
	@if [ -f VERSION ]; then \
		VERSION=$$(cat VERSION); \
		sed -i "s/VERSION_PLACEHOLDER/$$VERSION/" installer/flatpak/org.sysmanage.Agent.metainfo.xml; \
	fi
	@echo "Building Flatpak package..."
	@echo "This may take several minutes (downloading runtime, building Python dependencies)..."
	@echo ""
	@cd installer/flatpak && flatpak-builder --force-clean --repo=repo builddir org.sysmanage.Agent.yaml
	@echo ""
	@echo "Creating Flatpak bundle..."
	@if [ -f VERSION ]; then \
		VERSION=$$(cat VERSION); \
	else \
		VERSION=$$(git describe --tags --always 2>/dev/null || echo "dev"); \
	fi; \
	cd installer/flatpak && flatpak build-bundle repo sysmanage-agent-$$VERSION.flatpak org.sysmanage.Agent
	@echo ""
	@echo "==================================="; \
	echo "Build Complete!"; \
	echo "==================================="; \
	echo ""; \
	if [ -f VERSION ]; then \
		VERSION=$$(cat VERSION); \
	else \
		VERSION=$$(git describe --tags --always 2>/dev/null || echo "dev"); \
	fi; \
	FLATPAK_FILE="installer/flatpak/sysmanage-agent-$$VERSION.flatpak"; \
	if [ -f "$$FLATPAK_FILE" ]; then \
		echo "Package: $$FLATPAK_FILE"; \
		ls -lh "$$FLATPAK_FILE"; \
		echo ""; \
		echo "Install with:"; \
		echo "  make flatpak-install"; \
		echo "  OR"; \
		echo "  flatpak install --user $$FLATPAK_FILE"; \
		echo ""; \
		echo "After installation:"; \
		echo "  1. Configure at ~/.var/app/org.sysmanage.Agent/config/sysmanage/sysmanage-agent.yaml"; \
		echo "  2. Run: flatpak run org.sysmanage.Agent"; \
		echo "  3. View logs: journalctl --user -f GLIB_DOMAIN=flatpak"; \
		echo ""; \
		echo "Note: This Flatpak provides read-only monitoring capabilities."; \
		echo "      For full management features, use native packages (DEB/RPM)."; \
		echo ""; \
	else \
		echo "ERROR: Built flatpak not found!"; \
		exit 1; \
	fi

# Clean flatpak build artifacts
flatpak-clean:
	@echo "=== Cleaning Flatpak Build Artifacts ==="
	@echo ""
	@echo "Removing flatpak build artifacts..."
	@rm -rf installer/flatpak/builddir
	@rm -rf installer/flatpak/repo
	@rm -rf installer/flatpak/.flatpak-builder
	@rm -rf installer/flatpak/pypi-dependencies
	@rm -f installer/flatpak/*.flatpak
	@rm -f installer/flatpak/sysmanage-agent-src.tar.gz
	@rm -f installer/flatpak/pypi-dependencies.tar.gz
	@rm -f installer/flatpak/requirements-runtime.txt
	@echo "✓ Flatpak build artifacts cleaned"
	@echo ""

# Install locally built flatpak package
flatpak-install:
	@echo "=== Installing Flatpak Package ==="
	@echo ""
	@if [ -f VERSION ]; then \
		VERSION=$$(cat VERSION); \
	else \
		VERSION=$$(git describe --tags --always 2>/dev/null || echo "dev"); \
	fi; \
	FLATPAK_FILE="installer/flatpak/sysmanage-agent-$$VERSION.flatpak"; \
	if [ ! -f "$$FLATPAK_FILE" ]; then \
		echo "ERROR: No flatpak package found at $$FLATPAK_FILE"; \
		echo "Build one first with: make flatpak"; \
		exit 1; \
	fi; \
	echo "Found flatpak package: $$FLATPAK_FILE"; \
	echo ""; \
	if flatpak list --app | grep -q "org.sysmanage.Agent"; then \
		echo "Existing org.sysmanage.Agent flatpak detected - updating..."; \
		flatpak update -y --user org.sysmanage.Agent || { \
			echo "Update failed, trying reinstall..."; \
			flatpak uninstall -y --user org.sysmanage.Agent || true; \
			flatpak install -y --user "$$FLATPAK_FILE" || { \
				echo "ERROR: Failed to install flatpak"; \
				exit 1; \
			}; \
		}; \
	else \
		echo "Installing new flatpak..."; \
		echo ""; \
		flatpak install -y --user "$$FLATPAK_FILE" || { \
			echo "ERROR: Failed to install flatpak"; \
			exit 1; \
		}; \
	fi; \
	echo ""; \
	bash installer/flatpak/post-install.sh

# Uninstall flatpak package
flatpak-uninstall:
	@echo "=== Uninstalling Flatpak Package ==="
	@echo ""
	@if ! flatpak list --app | grep -q "org.sysmanage.Agent"; then \
		echo "org.sysmanage.Agent is not installed"; \
		exit 0; \
	fi
	@echo "Uninstalling org.sysmanage.Agent..."
	@flatpak uninstall -y --user org.sysmanage.Agent || { \
		echo "ERROR: Failed to uninstall flatpak"; \
		exit 1; \
	}
	@echo "✓ Flatpak removed"
	@echo ""
	@echo "==================================="; \
	echo "Uninstallation Complete!"; \
	echo "==================================="; \
	echo ""; \
	echo "To remove configuration data:"; \
	echo "  rm -rf ~/.var/app/org.sysmanage.Agent"; \
	echo ""

# SBOM (Software Bill of Materials) generation target
sbom:
	@echo "=================================================="
	@echo "Generating Software Bill of Materials (CycloneDX)"
	@echo "=================================================="
	@echo ""
	@echo "Creating SBOM output directory..."
	@mkdir -p sbom
	@echo "✓ Directory created: ./sbom/"
	@echo ""
	@echo "Checking for CycloneDX tools..."
	@set -e; \
	if ! python3 -c "import cyclonedx_py" 2>/dev/null; then \
		echo "Installing cyclonedx-bom for Python..."; \
		python3 -m pip install cyclonedx-bom --quiet; \
		echo "✓ cyclonedx-bom installed"; \
	else \
		echo "✓ cyclonedx-bom already installed"; \
	fi
	@echo ""
	@echo "Generating Python SBOM from requirements.txt..."
	@set -e; \
	python3 -m cyclonedx_py requirements \
		requirements.txt \
		--of JSON \
		-o sbom/sysmanage-agent-sbom.json
	@echo "✓ Python SBOM generated: sbom/sysmanage-agent-sbom.json"
	@echo ""
	@echo "=================================================="
	@echo "SBOM Generation Complete!"
	@echo "=================================================="
	@echo ""
	@echo "Generated files:"
	@ls -lh sbom/*.json
	@echo ""
	@echo "You can view the SBOM with:"
	@echo "  cat sbom/sysmanage-agent-sbom.json | jq ."
	@echo ""
	@echo "Or upload it to vulnerability scanning tools that support CycloneDX format."

# =============================================================================
# Deploy targets - Local build & publish infrastructure
# =============================================================================

# Version resolution: VERSION env var > git tag > fallback 0.1.0
# Usage: VERSION=1.2.3 make <target>

# Check deployment tool dependencies
deploy-check-deps:
	@echo "=================================================="
	@echo "Checking Deployment Tool Dependencies"
	@echo "=================================================="
	@echo ""
	@MISSING=0; \
	WARN=0; \
	OS_TYPE=$$(uname -s); \
	echo "Detected OS: $$OS_TYPE"; \
	echo ""; \
	\
	echo "=== All Platforms ==="; \
	echo ""; \
	echo "--- Version Detection ---"; \
	if command -v git >/dev/null 2>&1; then \
		echo "  [OK] git"; \
		TAG=$$(git describe --tags --abbrev=0 2>/dev/null || true); \
		if [ -n "$$TAG" ]; then \
			echo "  [OK] Git tag found: $$TAG"; \
		else \
			echo "  [WARN] No git tags found (set VERSION env var to override)"; \
			WARN=1; \
		fi; \
	else \
		echo "  [MISSING] git"; \
		MISSING=1; \
	fi; \
	echo ""; \
	\
	echo "--- Checksums ---"; \
	if command -v sha256sum >/dev/null 2>&1; then \
		echo "  [OK] sha256sum"; \
	elif command -v shasum >/dev/null 2>&1; then \
		echo "  [OK] shasum (will use shasum -a 256)"; \
	elif command -v sha256 >/dev/null 2>&1; then \
		echo "  [OK] sha256 (OpenBSD)"; \
	else \
		echo "  [MISSING] sha256sum / shasum / sha256"; \
		MISSING=1; \
	fi; \
	echo ""; \
	\
	echo "--- SBOM Generation ---"; \
	if python3 -c "import cyclonedx_py" 2>/dev/null; then \
		echo "  [OK] cyclonedx-bom (Python)"; \
	else \
		echo "  [MISSING] cyclonedx-bom"; \
		echo "  Install: pip3 install cyclonedx-bom"; \
		MISSING=1; \
	fi; \
	echo ""; \
	\
	echo "--- Docs Repository ---"; \
	DOCS_REPO="$${DOCS_REPO:-$(HOME)/dev/sysmanage-docs}"; \
	if [ -d "$$DOCS_REPO" ]; then \
		echo "  [OK] sysmanage-docs found at $$DOCS_REPO"; \
	else \
		echo "  [MISSING] sysmanage-docs not found at $$DOCS_REPO"; \
		echo "  Clone it or set DOCS_REPO env var to the correct path"; \
		MISSING=1; \
	fi; \
	echo ""; \
	\
	if [ "$$OS_TYPE" = "Linux" ]; then \
		echo "=== Linux Deploy Targets ==="; \
		echo ""; \
		\
		echo "--- Launchpad PPA (Ubuntu source packages) ---"; \
		for cmd in dch debuild debsign dput gpg; do \
			if command -v $$cmd >/dev/null 2>&1; then \
				echo "  [OK] $$cmd"; \
			else \
				echo "  [MISSING] $$cmd"; \
				MISSING=1; \
			fi; \
		done; \
		if ! command -v dch >/dev/null 2>&1 || ! command -v debuild >/dev/null 2>&1; then \
			echo "  Install: sudo apt-get install -y devscripts debhelper dh-python python3-all python3-setuptools dput-ng gnupg"; \
		fi; \
		if command -v gpg >/dev/null 2>&1; then \
			GPG_KEY=$$(gpg --list-secret-keys --keyid-format LONG 2>/dev/null | grep sec | head -1); \
			if [ -n "$$GPG_KEY" ]; then \
				echo "  [OK] GPG signing key found"; \
			else \
				echo "  [WARN] No GPG signing key found (needed for Launchpad uploads)"; \
				echo "  Import a key or set LAUNCHPAD_GPG_KEY env var"; \
				WARN=1; \
			fi; \
		fi; \
		echo ""; \
		\
		echo "--- OBS (openSUSE Build Service) ---"; \
		if command -v osc >/dev/null 2>&1; then \
			echo "  [OK] osc"; \
		else \
			echo "  [MISSING] osc"; \
			echo "  Install: sudo apt-get install -y osc"; \
			MISSING=1; \
		fi; \
		if [ -f "$$HOME/.config/osc/oscrc" ]; then \
			echo "  [OK] OBS credentials (~/.config/osc/oscrc)"; \
		elif [ -n "$$OBS_USERNAME" ] && [ -n "$$OBS_PASSWORD" ]; then \
			echo "  [OK] OBS credentials (OBS_USERNAME + OBS_PASSWORD env vars)"; \
		else \
			echo "  [WARN] No OBS credentials found"; \
			echo "  Configure ~/.config/osc/oscrc or set OBS_USERNAME + OBS_PASSWORD env vars"; \
			WARN=1; \
		fi; \
		echo ""; \
		\
		echo "--- COPR (Fedora Community Build Service) ---"; \
		for cmd in copr-cli rpmbuild; do \
			if command -v $$cmd >/dev/null 2>&1; then \
				echo "  [OK] $$cmd"; \
			else \
				echo "  [MISSING] $$cmd"; \
				MISSING=1; \
			fi; \
		done; \
		if ! command -v copr-cli >/dev/null 2>&1; then \
			echo "  Install: pip3 install copr-cli"; \
		fi; \
		if ! command -v rpmbuild >/dev/null 2>&1; then \
			echo "  Install: sudo apt-get install -y rpm || sudo dnf install -y rpm-build"; \
		fi; \
		if [ -f "$$HOME/.config/copr" ]; then \
			echo "  [OK] COPR credentials (~/.config/copr)"; \
		elif [ -n "$$COPR_LOGIN" ] && [ -n "$$COPR_API_TOKEN" ] && [ -n "$$COPR_USERNAME" ]; then \
			echo "  [OK] COPR credentials (COPR_LOGIN + COPR_API_TOKEN + COPR_USERNAME env vars)"; \
		else \
			echo "  [WARN] No COPR credentials found"; \
			echo "  Configure ~/.config/copr or set COPR_LOGIN + COPR_API_TOKEN + COPR_USERNAME env vars"; \
			WARN=1; \
		fi; \
		echo ""; \
		\
		echo "--- Snap Store ---"; \
		if command -v snapcraft >/dev/null 2>&1; then \
			echo "  [OK] snapcraft"; \
			if snapcraft whoami >/dev/null 2>&1; then \
				echo "  [OK] Snap Store login active"; \
			else \
				echo "  [WARN] Not logged in to Snap Store"; \
				echo "  Run: snapcraft login"; \
				WARN=1; \
			fi; \
		else \
			echo "  [MISSING] snapcraft"; \
			echo "  Install: sudo snap install snapcraft --classic"; \
			MISSING=1; \
		fi; \
		echo ""; \
		\
		echo "--- Docs Repo Metadata Tools ---"; \
		for cmd in dpkg-scanpackages createrepo_c; do \
			if command -v $$cmd >/dev/null 2>&1; then \
				echo "  [OK] $$cmd"; \
			else \
				echo "  [MISSING] $$cmd"; \
				MISSING=1; \
			fi; \
		done; \
		if ! command -v dpkg-scanpackages >/dev/null 2>&1; then \
			echo "  Install: sudo apt-get install -y dpkg-dev"; \
		fi; \
		if ! command -v createrepo_c >/dev/null 2>&1; then \
			echo "  Install: sudo apt-get install -y createrepo-c || sudo dnf install -y createrepo_c"; \
		fi; \
		echo ""; \
		\
		echo "--- Docker (Alpine package builds) ---"; \
		if command -v docker >/dev/null 2>&1; then \
			echo "  [OK] docker"; \
			if docker info >/dev/null 2>&1; then \
				echo "  [OK] Docker daemon accessible"; \
			else \
				echo "  [WARN] Docker installed but daemon not accessible"; \
				echo "  Ensure Docker is running and your user is in the docker group"; \
				WARN=1; \
			fi; \
		else \
			echo "  [MISSING] docker (optional - needed for installer-alpine)"; \
			echo "  Install from: https://docs.docker.com/engine/install/"; \
		fi; \
		echo ""; \
		\
		echo "--- Flatpak ---"; \
		if command -v flatpak-builder >/dev/null 2>&1; then \
			echo "  [OK] flatpak-builder"; \
		else \
			echo "  [MISSING] flatpak-builder (optional - needed for flatpak target)"; \
			echo "  Install: sudo apt-get install -y flatpak flatpak-builder"; \
		fi; \
		if command -v flatpak >/dev/null 2>&1; then \
			echo "  [OK] flatpak"; \
		else \
			echo "  [MISSING] flatpak (optional - needed for flatpak target)"; \
		fi; \
		echo ""; \
	\
	elif [ "$$OS_TYPE" = "Darwin" ]; then \
		echo "=== macOS Packaging Tools ==="; \
		echo ""; \
		for cmd in pkgbuild productbuild; do \
			if command -v $$cmd >/dev/null 2>&1; then \
				echo "  [OK] $$cmd"; \
			else \
				echo "  [MISSING] $$cmd"; \
				echo "  Install: xcode-select --install"; \
				MISSING=1; \
			fi; \
		done; \
		echo ""; \
		echo "(Launchpad, OBS, COPR, Snap targets are Linux-only -- skipped)"; \
		echo ""; \
	\
	elif echo "$$OS_TYPE" | grep -qE "^(MINGW|MSYS)"; then \
		echo "=== Windows Packaging Tools ==="; \
		echo ""; \
		if command -v powershell >/dev/null 2>&1 || command -v powershell.exe >/dev/null 2>&1; then \
			echo "  [OK] PowerShell"; \
		else \
			echo "  [MISSING] PowerShell"; \
			MISSING=1; \
		fi; \
		if command -v wix >/dev/null 2>&1 || command -v dotnet >/dev/null 2>&1; then \
			echo "  [OK] WiX Toolset / .NET SDK"; \
		else \
			echo "  [WARN] WiX Toolset v4 not detected"; \
			echo "  Install: dotnet tool install --global wix"; \
			WARN=1; \
		fi; \
		echo ""; \
		echo "(Launchpad, OBS, COPR, Snap targets are Linux-only -- skipped)"; \
		echo ""; \
	\
	elif [ "$$OS_TYPE" = "FreeBSD" ]; then \
		echo "=== FreeBSD Packaging Tools ==="; \
		echo ""; \
		if command -v pkg >/dev/null 2>&1; then \
			echo "  [OK] pkg"; \
		else \
			echo "  [MISSING] pkg"; \
			MISSING=1; \
		fi; \
		echo ""; \
		echo "(Launchpad, OBS, COPR, Snap targets are Linux-only -- skipped)"; \
		echo ""; \
	\
	elif [ "$$OS_TYPE" = "NetBSD" ]; then \
		echo "=== NetBSD Packaging Tools ==="; \
		echo ""; \
		if command -v pkg_create >/dev/null 2>&1; then \
			echo "  [OK] pkg_create"; \
		else \
			echo "  [MISSING] pkg_create"; \
			MISSING=1; \
		fi; \
		echo ""; \
		echo "(Launchpad, OBS, COPR, Snap targets are Linux-only -- skipped)"; \
		echo ""; \
	\
	elif [ "$$OS_TYPE" = "OpenBSD" ]; then \
		echo "=== OpenBSD Packaging Tools ==="; \
		echo ""; \
		if command -v tar >/dev/null 2>&1; then \
			echo "  [OK] tar (for port tarball creation)"; \
		else \
			echo "  [MISSING] tar"; \
			MISSING=1; \
		fi; \
		echo ""; \
		echo "(Launchpad, OBS, COPR, Snap targets are Linux-only -- skipped)"; \
		echo ""; \
	\
	else \
		echo "=== Unknown Platform: $$OS_TYPE ==="; \
		echo ""; \
		echo "  No platform-specific checks available."; \
		echo ""; \
	fi; \
	\
	echo "=========================================="; \
	echo "Summary"; \
	echo "=========================================="; \
	echo ""; \
	if [ $$MISSING -eq 0 ] && [ $$WARN -eq 0 ]; then \
		echo "All deployment tools and credentials are configured."; \
	elif [ $$MISSING -eq 0 ]; then \
		echo "All required tools are installed."; \
		echo "Some credentials/config may need attention (see [WARN] items above)."; \
	else \
		echo "Some required tools are missing (see [MISSING] items above)."; \
		if [ $$WARN -ne 0 ]; then \
			echo "Some credentials/config may also need attention (see [WARN] items)."; \
		fi; \
	fi

# Generate SHA256 checksums for all packages in installer/dist/
checksums:
	@echo "=================================================="
	@echo "Generating SHA256 Checksums"
	@echo "=================================================="
	@echo ""
	@if [ ! -d installer/dist ] || [ -z "$$(ls -A installer/dist/ 2>/dev/null)" ]; then \
		echo "ERROR: No packages found in installer/dist/"; \
		echo "Run a package build target first (e.g., make installer-deb)"; \
		exit 1; \
	fi
	@set -e; \
	cd installer/dist; \
	if command -v sha256sum >/dev/null 2>&1; then \
		SHA256CMD="sha256sum"; \
	elif command -v shasum >/dev/null 2>&1; then \
		SHA256CMD="shasum -a 256"; \
	elif command -v sha256 >/dev/null 2>&1; then \
		SHA256CMD="sha256 -r"; \
	else \
		echo "ERROR: No SHA256 tool found (sha256sum, shasum, or sha256)"; \
		exit 1; \
	fi; \
	COUNT=0; \
	for f in *; do \
		[ -f "$$f" ] || continue; \
		case "$$f" in \
			*.sha256) continue ;; \
			*) \
				$$SHA256CMD "$$f" > "$$f.sha256"; \
				echo "  $$f.sha256"; \
				COUNT=$$((COUNT + 1)); \
				;; \
		esac; \
	done; \
	echo ""; \
	echo "Generated $$COUNT checksum files in installer/dist/"

# Generate release notes markdown
release-notes:
	@echo "=================================================="
	@echo "Generating Release Notes"
	@echo "=================================================="
	@echo ""
	@set -e; \
	if [ -n "$$VERSION" ]; then \
		echo "Using VERSION from environment: $$VERSION"; \
	else \
		VERSION=$$(git describe --tags --abbrev=0 2>/dev/null | sed 's/^v//'); \
		if [ -z "$$VERSION" ]; then \
			VERSION="0.1.0"; \
			echo "No git tags found, using default version: $$VERSION"; \
		else \
			echo "Using version from git tag: $$VERSION"; \
		fi; \
	fi; \
	mkdir -p installer/dist; \
	NOTES="installer/dist/release-notes-$$VERSION.md"; \
	echo "# SysManage Agent v$$VERSION Release Notes" > "$$NOTES"; \
	echo "" >> "$$NOTES"; \
	echo "Release date: $$(date -u +%Y-%m-%d)" >> "$$NOTES"; \
	echo "" >> "$$NOTES"; \
	echo "## Installation" >> "$$NOTES"; \
	echo "" >> "$$NOTES"; \
	echo "### Ubuntu/Debian (APT)" >> "$$NOTES"; \
	echo '```bash' >> "$$NOTES"; \
	echo "# Add the PPA" >> "$$NOTES"; \
	echo "sudo add-apt-repository ppa:bceverly/sysmanage-agent" >> "$$NOTES"; \
	echo "sudo apt update" >> "$$NOTES"; \
	echo "sudo apt install sysmanage-agent" >> "$$NOTES"; \
	echo '```' >> "$$NOTES"; \
	echo "" >> "$$NOTES"; \
	echo "### Fedora/RHEL/CentOS (COPR)" >> "$$NOTES"; \
	echo '```bash' >> "$$NOTES"; \
	echo "sudo dnf copr enable bceverly/sysmanage-agent" >> "$$NOTES"; \
	echo "sudo dnf install sysmanage-agent" >> "$$NOTES"; \
	echo '```' >> "$$NOTES"; \
	echo "" >> "$$NOTES"; \
	echo "### openSUSE (OBS)" >> "$$NOTES"; \
	echo '```bash' >> "$$NOTES"; \
	echo "# Add the OBS repository for your distribution" >> "$$NOTES"; \
	echo "sudo zypper install sysmanage-agent" >> "$$NOTES"; \
	echo '```' >> "$$NOTES"; \
	echo "" >> "$$NOTES"; \
	echo "### Snap (Edge Channel)" >> "$$NOTES"; \
	echo '```bash' >> "$$NOTES"; \
	echo "sudo snap install sysmanage-agent-strict --edge" >> "$$NOTES"; \
	echo '```' >> "$$NOTES"; \
	echo "" >> "$$NOTES"; \
	echo "### macOS" >> "$$NOTES"; \
	echo '```bash' >> "$$NOTES"; \
	echo "# Download the .pkg installer from the releases page" >> "$$NOTES"; \
	echo "sudo installer -pkg sysmanage-agent-$$VERSION-macos.pkg -target /" >> "$$NOTES"; \
	echo '```' >> "$$NOTES"; \
	echo "" >> "$$NOTES"; \
	echo "### FreeBSD" >> "$$NOTES"; \
	echo '```bash' >> "$$NOTES"; \
	echo "pkg install sysmanage-agent" >> "$$NOTES"; \
	echo '```' >> "$$NOTES"; \
	echo "" >> "$$NOTES"; \
	echo "## Verify Downloads" >> "$$NOTES"; \
	echo "" >> "$$NOTES"; \
	echo "SHA256 checksums are provided for all packages. Verify with:" >> "$$NOTES"; \
	echo '```bash' >> "$$NOTES"; \
	echo "sha256sum -c <package-file>.sha256" >> "$$NOTES"; \
	echo '```' >> "$$NOTES"; \
	echo "" >> "$$NOTES"; \
	echo "## Software Bill of Materials" >> "$$NOTES"; \
	echo "" >> "$$NOTES"; \
	echo "SBOM file in CycloneDX JSON format is available:" >> "$$NOTES"; \
	echo "- \`sysmanage-agent-sbom.json\` - Python dependencies" >> "$$NOTES"; \
	echo "" >> "$$NOTES"; \
	echo "## Packages" >> "$$NOTES"; \
	echo "" >> "$$NOTES"; \
	echo "| Platform | Package |" >> "$$NOTES"; \
	echo "|----------|---------|" >> "$$NOTES"; \
	if [ -d installer/dist ]; then \
		for f in installer/dist/*; do \
			case "$$f" in \
				*.sha256|*.md) continue ;; \
				*) echo "| $$(basename $$f | sed 's/.*\.//' | tr '[:lower:]' '[:upper:]') | \`$$(basename $$f)\` |" >> "$$NOTES" ;; \
			esac; \
		done; \
	fi; \
	echo "" >> "$$NOTES"; \
	echo "Generated: $$NOTES"

# Deploy to Launchpad PPA
# Usage: LAUNCHPAD_RELEASES="noble jammy" make deploy-launchpad
# Default releases: resolute questing plucky oracular noble jammy
deploy-launchpad:
	@echo "=================================================="
	@echo "Deploy to Launchpad PPA"
	@echo "=================================================="
	@echo ""
	@set -e; \
	if [ -n "$$VERSION" ]; then \
		echo "Using VERSION from environment: $$VERSION"; \
	else \
		VERSION=$$(git describe --tags --abbrev=0 2>/dev/null | sed 's/^v//'); \
		if [ -z "$$VERSION" ]; then \
			VERSION="0.1.0"; \
			echo "No git tags found, using default version: $$VERSION"; \
		else \
			echo "Using version from git tag: $$VERSION"; \
		fi; \
	fi; \
	\
	RELEASES="$${LAUNCHPAD_RELEASES:-resolute questing plucky oracular noble jammy}"; \
	echo "Target releases: $$RELEASES"; \
	echo "Version: $$VERSION"; \
	echo ""; \
	\
	for cmd in dch debuild debsign dput gpg; do \
		command -v $$cmd >/dev/null 2>&1 || { \
			echo "ERROR: $$cmd not found."; \
			echo "Install with: sudo apt-get install -y devscripts debhelper dh-python python3-all python3-setuptools dput-ng gnupg"; \
			exit 1; \
		}; \
	done; \
	echo "Build tools available"; \
	\
	GPG_KEY_ID="$${LAUNCHPAD_GPG_KEY:-}"; \
	if [ -z "$$GPG_KEY_ID" ]; then \
		GPG_KEY_ID=$$(gpg --list-secret-keys --keyid-format LONG 2>/dev/null | grep sec | awk '{print $$2}' | cut -d'/' -f2 | head -1); \
	fi; \
	if [ -z "$$GPG_KEY_ID" ]; then \
		echo "ERROR: No GPG key found."; \
		echo "Either import a GPG key to ~/.gnupg/ or set LAUNCHPAD_GPG_KEY env var"; \
		exit 1; \
	fi; \
	echo "Using GPG key: $$GPG_KEY_ID"; \
	echo ""; \
	\
	echo "Pre-warming GPG agent (you may be prompted for your passphrase)..."; \
	export GPG_TTY=$$(tty); \
	echo "test" | gpg --local-user "$$GPG_KEY_ID" --sign --armor -o /dev/null || \
	{ echo "ERROR: GPG signing failed. Please unlock your key first with:"; \
	  echo "  export GPG_TTY=\$$(tty) && gpg --sign --armor /dev/null"; \
	  exit 1; }; \
	echo "GPG agent ready"; \
	echo ""; \
	\
	if dput --version 2>&1 | grep -q "dput-ng"; then \
		mkdir -p ~/.dput.d/profiles; \
		printf '{\n  "fqdn": "ppa.launchpad.net",\n  "incoming": "~bceverly/ubuntu/sysmanage-agent",\n  "method": "ftp",\n  "allow_unsigned_uploads": false\n}\n' > ~/.dput.d/profiles/launchpad.json; \
	else \
		if ! grep -q '^\[launchpad\]' ~/.dput.cf 2>/dev/null; then \
			printf '\n[launchpad]\nfqdn = ppa.launchpad.net\nmethod = ftp\nincoming = ~bceverly/ubuntu/sysmanage-agent/\nlogin = anonymous\nallow_unsigned_uploads = 0\n' >> ~/.dput.cf; \
		fi; \
	fi; \
	echo "Configured dput for Launchpad PPA"; \
	echo ""; \
	\
	echo "Generating requirements-prod.txt..."; \
	python3 scripts/update-requirements-prod.py; \
	\
	echo "Generating SBOM..."; \
	$(MAKE) sbom; \
	echo ""; \
	\
	export DEBFULLNAME="Bryan Everly"; \
	export DEBEMAIL="bryan@theeverlys.com"; \
	\
	for RELEASE in $$RELEASES; do \
		echo "=========================================="; \
		echo "Building source package for Ubuntu $$RELEASE"; \
		echo "Version: $$VERSION"; \
		echo "=========================================="; \
		\
		case "$$RELEASE" in \
			jammy) PYTHON_VERSION="3.10" ;; \
			noble|oracular) PYTHON_VERSION="3.12" ;; \
			plucky|questing) PYTHON_VERSION="3.13" ;; \
			resolute) PYTHON_VERSION="3.14" ;; \
			*) PYTHON_VERSION="3.12" ;; \
		esac; \
		echo "Target Python version: $$PYTHON_VERSION"; \
		\
		echo "Creating vendor directory for Python $$PYTHON_VERSION..."; \
		rm -rf vendor; \
		mkdir -p vendor; \
		pip3 download -r requirements-prod.txt -d vendor \
			--python-version "$$PYTHON_VERSION" \
			--platform manylinux2014_x86_64 \
			--platform manylinux_2_17_x86_64 \
			--only-binary=:all:; \
		pip3 download -r requirements-prod.txt -d vendor \
			--python-version "$$PYTHON_VERSION" \
			--no-binary :all: 2>/dev/null || true; \
		echo "Downloaded $$(ls -1 vendor/*.whl 2>/dev/null | wc -l) wheels"; \
		\
		WORK_DIR="/tmp/sysmanage-agent-$$RELEASE"; \
		rm -rf "$$WORK_DIR"; \
		mkdir -p "$$WORK_DIR"; \
		\
		cp -r . "$$WORK_DIR/"; \
		cd "$$WORK_DIR"; \
		\
		if [ -d "installer/ubuntu/debian" ]; then \
			cp -r installer/ubuntu/debian .; \
		else \
			echo "Error: debian directory not found at installer/ubuntu/debian"; \
			exit 1; \
		fi; \
		\
		dch -v "$${VERSION}+ppa1~$${RELEASE}1" -D "$$RELEASE" "New upstream release $${VERSION}"; \
		\
		debuild -S -sa -us -uc; \
		\
		cd ..; \
		\
		if [ -n "$$LAUNCHPAD_GPG_PASSPHRASE" ]; then \
			echo "$$LAUNCHPAD_GPG_PASSPHRASE" > "/tmp/gpg-passphrase-$$RELEASE"; \
			debsign --re-sign -p"gpg --batch --yes --passphrase-file /tmp/gpg-passphrase-$$RELEASE" \
				-k"$$GPG_KEY_ID" "sysmanage-agent_$${VERSION}+ppa1~$${RELEASE}1_source.changes"; \
			rm -f "/tmp/gpg-passphrase-$$RELEASE"; \
		else \
			debsign --re-sign -k"$$GPG_KEY_ID" "sysmanage-agent_$${VERSION}+ppa1~$${RELEASE}1_source.changes"; \
		fi; \
		\
		dput launchpad "sysmanage-agent_$${VERSION}+ppa1~$${RELEASE}1_source.changes"; \
		\
		echo "Uploaded to Launchpad PPA for $$RELEASE"; \
		echo ""; \
		\
		cd "$(CURDIR)"; \
	done; \
	\
	rm -rf vendor; \
	\
	echo "=========================================="; \
	echo "All Launchpad uploads complete!"; \
	echo "=========================================="; \
	echo ""; \
	echo "View build status at:"; \
	echo "  https://launchpad.net/~bceverly/+archive/ubuntu/sysmanage-agent"

# Deploy to openSUSE Build Service
deploy-obs:
	@echo "=================================================="
	@echo "Deploy to openSUSE Build Service (OBS)"
	@echo "=================================================="
	@echo ""
	@set -e; \
	if [ -n "$$VERSION" ]; then \
		echo "Using VERSION from environment: $$VERSION"; \
	else \
		VERSION=$$(git describe --tags --abbrev=0 2>/dev/null | sed 's/^v//'); \
		if [ -z "$$VERSION" ]; then \
			VERSION="0.1.0"; \
			echo "No git tags found, using default version: $$VERSION"; \
		else \
			echo "Using version from git tag: $$VERSION"; \
		fi; \
	fi; \
	echo "Version: $$VERSION"; \
	echo ""; \
	\
	command -v osc >/dev/null 2>&1 || { \
		echo "ERROR: osc not found."; \
		echo "Install with: sudo apt-get install -y osc"; \
		exit 1; \
	}; \
	echo "osc available"; \
	\
	OBS_USER="$${OBS_USERNAME:-}"; \
	if [ -z "$$OBS_USER" ] && [ -f ~/.config/osc/oscrc ]; then \
		OBS_USER=$$(grep "^user" ~/.config/osc/oscrc 2>/dev/null | head -1 | sed 's/^user[[:space:]]*=[[:space:]]*//');\
	fi; \
	if [ -z "$$OBS_USER" ]; then \
		echo "ERROR: OBS credentials not configured."; \
		echo "Either configure ~/.config/osc/oscrc or set OBS_USERNAME and OBS_PASSWORD env vars"; \
		exit 1; \
	fi; \
	\
	if [ -n "$$OBS_USERNAME" ] && [ -n "$$OBS_PASSWORD" ]; then \
		mkdir -p ~/.config/osc; \
		printf '[general]\napiurl = https://api.opensuse.org\n\n[https://api.opensuse.org]\nuser = %s\npass = %s\n' "$$OBS_USERNAME" "$$OBS_PASSWORD" > ~/.config/osc/oscrc; \
		chmod 600 ~/.config/osc/oscrc; \
		echo "OBS credentials configured from env vars"; \
	fi; \
	echo "OBS user: $$OBS_USER"; \
	echo ""; \
	\
	echo "Generating requirements-prod.txt..."; \
	python3 scripts/update-requirements-prod.py; \
	\
	WORKSPACE="$(CURDIR)"; \
	\
	OBS_DIR="/tmp/obs-sysmanage-agent"; \
	rm -rf "$$OBS_DIR"; \
	mkdir -p "$$OBS_DIR"; \
	cd "$$OBS_DIR"; \
	\
	echo "Checking out OBS package home:$$OBS_USER/sysmanage-agent"; \
	osc checkout "home:$$OBS_USER/sysmanage-agent"; \
	cd "home:$$OBS_USER/sysmanage-agent"; \
	\
	echo "Copying spec file and rpmlintrc..."; \
	cp "$$WORKSPACE/installer/opensuse/sysmanage-agent.spec" .; \
	cp "$$WORKSPACE/installer/opensuse/sysmanage-agent-rpmlintrc" . 2>/dev/null || true; \
	\
	sed -i "s/^Version:.*/Version:        $$VERSION/" sysmanage-agent.spec; \
	\
	echo "Creating source tarball..."; \
	TAR_NAME="sysmanage-agent-$$VERSION"; \
	rm -rf "/tmp/$$TAR_NAME"; \
	mkdir -p "/tmp/$$TAR_NAME"; \
	cp -r "$$WORKSPACE/src" "/tmp/$$TAR_NAME/"; \
	cp "$$WORKSPACE/main.py" "/tmp/$$TAR_NAME/"; \
	cp "$$WORKSPACE/alembic.ini" "/tmp/$$TAR_NAME/"; \
	cp "$$WORKSPACE/requirements.txt" "/tmp/$$TAR_NAME/"; \
	cp "$$WORKSPACE/requirements-prod.txt" "/tmp/$$TAR_NAME/"; \
	cp "$$WORKSPACE/README.md" "/tmp/$$TAR_NAME/" || touch "/tmp/$$TAR_NAME/README.md"; \
	cp "$$WORKSPACE/LICENSE" "/tmp/$$TAR_NAME/" || touch "/tmp/$$TAR_NAME/LICENSE"; \
	mkdir -p "/tmp/$$TAR_NAME/installer/opensuse"; \
	cp "$$WORKSPACE/installer/opensuse/"*.service "/tmp/$$TAR_NAME/installer/opensuse/" || true; \
	cp "$$WORKSPACE/installer/opensuse/"*.sudoers "/tmp/$$TAR_NAME/installer/opensuse/" || true; \
	cp "$$WORKSPACE/installer/opensuse/"*.example "/tmp/$$TAR_NAME/installer/opensuse/" || true; \
	cd /tmp; \
	tar czf "sysmanage-agent-$$VERSION.tar.gz" "$$TAR_NAME/"; \
	echo "Created source tarball: sysmanage-agent-$$VERSION.tar.gz"; \
	\
	echo "Creating vendor tarball (Python 3.11 wheels)..."; \
	rm -rf /tmp/vendor; \
	mkdir -p /tmp/vendor; \
	pip3 download -r "$$WORKSPACE/requirements-prod.txt" -d /tmp/vendor \
		--python-version 311 \
		--platform manylinux2014_x86_64 \
		--platform manylinux_2_17_x86_64 \
		--only-binary=:all:; \
	pip3 download -r "$$WORKSPACE/requirements-prod.txt" -d /tmp/vendor \
		--python-version 311 \
		--no-binary :all: 2>/dev/null || true; \
	cd /tmp; \
	tar czf "sysmanage-agent-vendor-$$VERSION.tar.gz" vendor/; \
	echo "Created vendor tarball: sysmanage-agent-vendor-$$VERSION.tar.gz"; \
	\
	cp "sysmanage-agent-$$VERSION.tar.gz" "$$OBS_DIR/home:$$OBS_USER/sysmanage-agent/"; \
	cp "sysmanage-agent-vendor-$$VERSION.tar.gz" "$$OBS_DIR/home:$$OBS_USER/sysmanage-agent/"; \
	\
	cd "$$OBS_DIR/home:$$OBS_USER/sysmanage-agent"; \
	osc remove *.tar.gz 2>/dev/null || true; \
	osc add "sysmanage-agent-$$VERSION.tar.gz"; \
	osc add "sysmanage-agent-vendor-$$VERSION.tar.gz"; \
	osc add sysmanage-agent.spec 2>/dev/null || true; \
	if [ -f sysmanage-agent-rpmlintrc ]; then \
		osc add sysmanage-agent-rpmlintrc 2>/dev/null || true; \
	fi; \
	\
	echo "Committing to OBS..."; \
	osc commit -m "Release version $$VERSION"; \
	\
	echo ""; \
	echo "=========================================="; \
	echo "Uploaded version $$VERSION to OBS"; \
	echo "=========================================="; \
	echo ""; \
	echo "View build status at:"; \
	echo "  https://build.opensuse.org/package/show/home:$$OBS_USER/sysmanage-agent"

# Deploy to Fedora Copr
deploy-copr:
	@echo "=================================================="
	@echo "Deploy to Fedora Copr"
	@echo "=================================================="
	@echo ""
	@set -e; \
	if [ -n "$$VERSION" ]; then \
		echo "Using VERSION from environment: $$VERSION"; \
	else \
		VERSION=$$(git describe --tags --abbrev=0 2>/dev/null | sed 's/^v//'); \
		if [ -z "$$VERSION" ]; then \
			VERSION="0.1.0"; \
			echo "No git tags found, using default version: $$VERSION"; \
		else \
			echo "Using version from git tag: $$VERSION"; \
		fi; \
	fi; \
	echo "Version: $$VERSION"; \
	echo ""; \
	\
	for cmd in copr-cli rpmbuild; do \
		command -v $$cmd >/dev/null 2>&1 || { \
			echo "ERROR: $$cmd not found."; \
			if [ "$$cmd" = "copr-cli" ]; then \
				echo "Install with: pip3 install copr-cli"; \
			else \
				echo "Install with: sudo apt-get install -y rpm || sudo dnf install -y rpm-build"; \
			fi; \
			exit 1; \
		}; \
	done; \
	echo "Build tools available"; \
	\
	COPR_USER="$${COPR_USERNAME:-}"; \
	if [ -z "$$COPR_USER" ] && [ -f ~/.config/copr ]; then \
		COPR_USER=$$(grep "^username" ~/.config/copr 2>/dev/null | head -1 | awk '{print $$3}'); \
	fi; \
	if [ -z "$$COPR_USER" ]; then \
		echo "ERROR: Copr credentials not configured."; \
		echo "Either configure ~/.config/copr or set COPR_LOGIN, COPR_API_TOKEN, and COPR_USERNAME env vars"; \
		exit 1; \
	fi; \
	\
	if [ -n "$$COPR_LOGIN" ] && [ -n "$$COPR_API_TOKEN" ] && [ -n "$$COPR_USERNAME" ]; then \
		mkdir -p ~/.config; \
		printf '[copr-cli]\nlogin = %s\nusername = %s\ntoken = %s\ncopr_url = https://copr.fedorainfracloud.org\n' "$$COPR_LOGIN" "$$COPR_USERNAME" "$$COPR_API_TOKEN" > ~/.config/copr; \
		chmod 600 ~/.config/copr; \
		echo "Copr credentials configured from env vars"; \
	fi; \
	echo "Copr user: $$COPR_USER"; \
	echo ""; \
	\
	echo "Generating requirements-prod.txt..."; \
	python3 scripts/update-requirements-prod.py; \
	\
	WORKSPACE="$(CURDIR)"; \
	\
	echo "Creating source tarball..."; \
	TAR_NAME="sysmanage-agent-$$VERSION"; \
	rm -rf "/tmp/$$TAR_NAME"; \
	mkdir -p "/tmp/$$TAR_NAME"; \
	cp -r "$$WORKSPACE/src" "/tmp/$$TAR_NAME/"; \
	cp "$$WORKSPACE/main.py" "/tmp/$$TAR_NAME/"; \
	cp "$$WORKSPACE/alembic.ini" "/tmp/$$TAR_NAME/"; \
	cp "$$WORKSPACE/requirements.txt" "/tmp/$$TAR_NAME/"; \
	cp "$$WORKSPACE/requirements-prod.txt" "/tmp/$$TAR_NAME/"; \
	cp "$$WORKSPACE/README.md" "/tmp/$$TAR_NAME/" || touch "/tmp/$$TAR_NAME/README.md"; \
	cp "$$WORKSPACE/LICENSE" "/tmp/$$TAR_NAME/" || touch "/tmp/$$TAR_NAME/LICENSE"; \
	mkdir -p "/tmp/$$TAR_NAME/installer/opensuse"; \
	cp "$$WORKSPACE/installer/opensuse/"*.service "/tmp/$$TAR_NAME/installer/opensuse/" 2>/dev/null || true; \
	cp "$$WORKSPACE/installer/opensuse/"*.sudoers "/tmp/$$TAR_NAME/installer/opensuse/" 2>/dev/null || true; \
	cp "$$WORKSPACE/installer/opensuse/"*.example "/tmp/$$TAR_NAME/installer/opensuse/" 2>/dev/null || true; \
	cd /tmp; \
	tar czf "sysmanage-agent-$$VERSION.tar.gz" "$$TAR_NAME/"; \
	echo "Created source tarball: sysmanage-agent-$$VERSION.tar.gz"; \
	\
	echo "Creating vendor tarball (Python 3.9 + 3.12 + 3.13 + 3.14 wheels)..."; \
	rm -rf /tmp/vendor; \
	mkdir -p /tmp/vendor; \
	echo "Downloading wheels for Python 3.9 (EPEL 9, CentOS Stream 9, Amazon Linux 2023)..."; \
	pip3 download -r "$$WORKSPACE/requirements-prod.txt" -d /tmp/vendor \
		--python-version 3.9.21 \
		--platform manylinux2014_x86_64 \
		--platform manylinux_2_17_x86_64 \
		--only-binary=:all:; \
	pip3 download "async-timeout<6.0,>=4.0" -d /tmp/vendor \
		--python-version 3.9.21 \
		--platform manylinux2014_x86_64 \
		--platform manylinux_2_17_x86_64 \
		--only-binary=:all: 2>/dev/null || true; \
	pip3 download tomli -d /tmp/vendor \
		--python-version 3.9.21 \
		--platform manylinux2014_x86_64 \
		--platform manylinux_2_17_x86_64 \
		--only-binary=:all: 2>/dev/null || true; \
	echo "Downloading wheels for Python 3.12 (EPEL 10, CentOS Stream 10)..."; \
	pip3 download -r "$$WORKSPACE/requirements-prod.txt" -d /tmp/vendor \
		--python-version 3.12.11 \
		--platform manylinux2014_x86_64 \
		--platform manylinux_2_17_x86_64 \
		--only-binary=:all:; \
	echo "Downloading wheels for Python 3.13 (Fedora 41, 42)..."; \
	pip3 download -r "$$WORKSPACE/requirements-prod.txt" -d /tmp/vendor \
		--python-version 3.13.1 \
		--platform manylinux2014_x86_64 \
		--platform manylinux_2_17_x86_64 \
		--only-binary=:all:; \
	echo "Downloading wheels for Python 3.14 (Fedora 43)..."; \
	pip3 download -r "$$WORKSPACE/requirements-prod.txt" -d /tmp/vendor \
		--python-version 3.14.0 \
		--platform manylinux2014_x86_64 \
		--platform manylinux_2_17_x86_64 \
		--only-binary=:all:; \
	echo "Total wheels: $$(ls -1 /tmp/vendor/*.whl 2>/dev/null | wc -l)"; \
	\
	for pkg in websockets PyYAML aiohttp cryptography SQLAlchemy alembic; do \
		pkg_lower=$$(echo "$$pkg" | tr '[:upper:]' '[:lower:]' | tr '-' '_'); \
		if ls /tmp/vendor/$${pkg_lower}* 1>/dev/null 2>&1 || ls /tmp/vendor/$${pkg}* 1>/dev/null 2>&1; then \
			echo "  $$pkg found"; \
		else \
			echo "  WARNING: $$pkg not found in vendor directory"; \
		fi; \
	done; \
	\
	cd /tmp; \
	tar czf "sysmanage-agent-vendor-$$VERSION.tar.gz" vendor/; \
	echo "Created vendor tarball: sysmanage-agent-vendor-$$VERSION.tar.gz"; \
	\
	echo ""; \
	echo "Copying to rpmbuild directory..."; \
	mkdir -p ~/rpmbuild/SOURCES; \
	cp "/tmp/sysmanage-agent-$$VERSION.tar.gz" ~/rpmbuild/SOURCES/; \
	cp "/tmp/sysmanage-agent-vendor-$$VERSION.tar.gz" ~/rpmbuild/SOURCES/; \
	\
	echo "Creating SRPM..."; \
	cp "$$WORKSPACE/installer/opensuse/sysmanage-agent.spec" ~/rpmbuild/SOURCES/; \
	cd ~/rpmbuild/SOURCES; \
	sed -i "s/^Version:.*/Version:        $$VERSION/" sysmanage-agent.spec; \
	rpmbuild -bs sysmanage-agent.spec --define "_topdir $$HOME/rpmbuild"; \
	\
	SRPM=$$(find ~/rpmbuild/SRPMS -name "sysmanage-agent-*.src.rpm" | head -1); \
	echo "Created SRPM: $$SRPM"; \
	\
	echo ""; \
	echo "Uploading SRPM to Copr..."; \
	copr-cli build "$$COPR_USER/sysmanage-agent" "$$SRPM"; \
	\
	echo ""; \
	echo "=========================================="; \
	echo "Uploaded version $$VERSION to Copr"; \
	echo "=========================================="; \
	echo ""; \
	echo "View build status at:"; \
	echo "  https://copr.fedorainfracloud.org/coprs/$$COPR_USER/sysmanage-agent/builds/"

# Deploy snap to Snap Store (wraps snap-strict-publish, edge channel)
deploy-snap:
	@echo "=================================================="
	@echo "Deploy Snap to Snap Store (Edge Channel)"
	@echo "=================================================="
	@echo ""
	@set -e; \
	if [ -n "$$VERSION" ]; then \
		echo "Using VERSION from environment: $$VERSION"; \
	else \
		VERSION=$$(git describe --tags --abbrev=0 2>/dev/null | sed 's/^v//'); \
		if [ -z "$$VERSION" ]; then \
			VERSION="0.1.0"; \
			echo "No git tags found, using default version: $$VERSION"; \
		else \
			echo "Using version from git tag: $$VERSION"; \
		fi; \
	fi; \
	echo "Version: $$VERSION"; \
	echo ""; \
	\
	command -v snapcraft >/dev/null 2>&1 || { \
		echo "ERROR: snapcraft not found."; \
		echo "Install with: sudo snap install snapcraft --classic"; \
		exit 1; \
	}; \
	\
	echo "Creating VERSION file..."; \
	echo "$$VERSION" > VERSION; \
	\
	echo "Creating source tarball for snap..."; \
	tar czf installer/ubuntu-snap-strict/sysmanage-agent-src.tar.gz \
		--exclude='.venv' \
		--exclude='.git' \
		--exclude='__pycache__' \
		--exclude='*.pyc' \
		--exclude='.pytest_cache' \
		--exclude='agent.db' \
		src main.py alembic.ini VERSION; \
	\
	echo "Building strict confinement snap..."; \
	cd installer/ubuntu-snap-strict && snapcraft pack --verbose; \
	cd "$(CURDIR)"; \
	\
	SNAP_FILE=$$(ls -t installer/ubuntu-snap-strict/sysmanage-agent-strict_*.snap 2>/dev/null | head -1); \
	if [ -z "$$SNAP_FILE" ]; then \
		echo "ERROR: No snap file produced in installer/ubuntu-snap-strict/"; \
		exit 1; \
	fi; \
	echo "Built snap: $$SNAP_FILE"; \
	\
	echo ""; \
	echo "Uploading to Snap Store (edge channel)..."; \
	for i in 1 2 3 4 5; do \
		echo "Attempt $$i of 5..."; \
		if snapcraft upload --release=edge "$$SNAP_FILE"; then \
			echo "Upload successful!"; \
			break; \
		fi; \
		if [ $$i -eq 5 ]; then \
			echo "All upload attempts failed"; \
			exit 1; \
		fi; \
		echo "Upload failed, waiting 30 seconds before retry..."; \
		sleep 30; \
	done; \
	\
	echo ""; \
	echo "=========================================="; \
	echo "Published to Snap Store (edge channel)"; \
	echo "=========================================="; \
	echo ""; \
	echo "Install with: sudo snap install sysmanage-agent-strict --edge"; \
	echo "View at: https://snapcraft.io/sysmanage-agent-strict"

# Stage packages into local sysmanage-docs repo (incremental/additive)
# Usage: DOCS_REPO=/path/to/sysmanage-docs make deploy-docs-repo
deploy-docs-repo:
	@echo "=================================================="
	@echo "Stage Packages to sysmanage-docs Repository"
	@echo "=================================================="
	@echo ""
	@set -e; \
	if [ -n "$$VERSION" ]; then \
		echo "Using VERSION from environment: $$VERSION"; \
	else \
		VERSION=$$(git describe --tags --abbrev=0 2>/dev/null | sed 's/^v//'); \
		if [ -z "$$VERSION" ]; then \
			VERSION="0.1.0"; \
			echo "No git tags found, using default version: $$VERSION"; \
		else \
			echo "Using version from git tag: $$VERSION"; \
		fi; \
	fi; \
	echo "Version: $$VERSION"; \
	echo ""; \
	\
	DOCS_REPO="$${DOCS_REPO:-$(HOME)/dev/sysmanage-docs}"; \
	if [ ! -d "$$DOCS_REPO" ]; then \
		echo "ERROR: sysmanage-docs repo not found at $$DOCS_REPO"; \
		echo "Set DOCS_REPO env var to the correct path"; \
		exit 1; \
	fi; \
	echo "Docs repo: $$DOCS_REPO"; \
	echo ""; \
	\
	STAGED=""; \
	MISSING=""; \
	\
	echo "--- Staging DEB packages ---"; \
	DEB_FILES=$$(ls installer/dist/*.deb 2>/dev/null || true); \
	if [ -n "$$DEB_FILES" ]; then \
		DEB_DIR="$$DOCS_REPO/repo/agent/deb/pool/main/$${VERSION}-1"; \
		mkdir -p "$$DEB_DIR"; \
		for f in $$DEB_FILES; do \
			cp "$$f" "$$DEB_DIR/"; \
			echo "  Staged: $$(basename $$f) -> $$DEB_DIR/"; \
		done; \
		STAGED="$$STAGED deb"; \
		if [ -x "$$DOCS_REPO/repo/agent/deb/update-repo.sh" ]; then \
			echo "  Running update-repo.sh..."; \
			cd "$$DOCS_REPO/repo/agent/deb" && ./update-repo.sh 2>/dev/null || true; \
			cd "$(CURDIR)"; \
			echo "  DEB metadata updated"; \
		elif command -v dpkg-scanpackages >/dev/null 2>&1; then \
			echo "  Regenerating DEB metadata..."; \
			cd "$$DOCS_REPO/repo/agent/deb"; \
			dpkg-scanpackages pool/main /dev/null > dists/stable/main/binary-amd64/Packages 2>/dev/null || true; \
			gzip -k -f dists/stable/main/binary-amd64/Packages 2>/dev/null || true; \
			if command -v apt-ftparchive >/dev/null 2>&1; then \
				cd dists/stable && apt-ftparchive release . > Release 2>/dev/null || true; \
				cd "$(CURDIR)"; \
			fi; \
			cd "$(CURDIR)"; \
			echo "  DEB metadata updated"; \
		fi; \
	else \
		echo "  No .deb packages found in installer/dist/"; \
		MISSING="$$MISSING deb"; \
	fi; \
	echo ""; \
	\
	echo "--- Staging RPM packages ---"; \
	RPM_FILES=$$(ls installer/dist/*.rpm 2>/dev/null || true); \
	if [ -n "$$RPM_FILES" ]; then \
		for f in $$RPM_FILES; do \
			BASENAME=$$(basename "$$f"); \
			if echo "$$BASENAME" | grep -q "\.el9\."; then \
				TARGET="el9"; \
			elif echo "$$BASENAME" | grep -q "\.el8\."; then \
				TARGET="el8"; \
			elif echo "$$BASENAME" | grep -q "opensuse-leap"; then \
				TARGET="opensuse-leap"; \
			elif echo "$$BASENAME" | grep -q "opensuse-tumbleweed"; then \
				TARGET="opensuse-tumbleweed"; \
			elif echo "$$BASENAME" | grep -q "sles"; then \
				TARGET="sles"; \
			else \
				TARGET="el9"; \
			fi; \
			if [ -x "$$DOCS_REPO/repo/agent/rpm/update-repo.sh" ]; then \
				echo "  Staging $$BASENAME via update-repo.sh (target: $$TARGET)..."; \
				"$$DOCS_REPO/repo/agent/rpm/update-repo.sh" "$$f" "$$TARGET" 2>/dev/null || true; \
			else \
				echo "  Staging $$BASENAME -> $$TARGET/"; \
				case "$$TARGET" in \
					el8) RPM_DIR="$$DOCS_REPO/repo/agent/rpm/el8/x86_64" ;; \
					el9) RPM_DIR="$$DOCS_REPO/repo/agent/rpm/el9/x86_64" ;; \
					opensuse-leap) RPM_DIR="$$DOCS_REPO/repo/agent/rpm/opensuse-leap/15/x86_64" ;; \
					opensuse-tumbleweed) RPM_DIR="$$DOCS_REPO/repo/agent/rpm/opensuse-tumbleweed/x86_64" ;; \
					sles) RPM_DIR="$$DOCS_REPO/repo/agent/rpm/sles/15/x86_64" ;; \
				esac; \
				mkdir -p "$$RPM_DIR"; \
				cp "$$f" "$$RPM_DIR/"; \
				if command -v createrepo_c >/dev/null 2>&1; then \
					cd "$$RPM_DIR" && createrepo_c . 2>/dev/null || true; \
					cd "$(CURDIR)"; \
				fi; \
			fi; \
		done; \
		STAGED="$$STAGED rpm"; \
	else \
		echo "  No .rpm packages found in installer/dist/"; \
		MISSING="$$MISSING rpm"; \
	fi; \
	echo ""; \
	\
	echo "--- Staging macOS packages ---"; \
	PKG_FILES=$$(ls installer/dist/*macos*.pkg installer/dist/*darwin*.pkg 2>/dev/null || true); \
	if [ -n "$$PKG_FILES" ]; then \
		for f in $$PKG_FILES; do \
			if [ -x "$$DOCS_REPO/repo/agent/mac/update-repo.sh" ]; then \
				echo "  Staging $$(basename $$f) via update-repo.sh..."; \
				"$$DOCS_REPO/repo/agent/mac/update-repo.sh" "$$f" 2>/dev/null || true; \
			else \
				MAC_DIR="$$DOCS_REPO/repo/agent/mac/packages/$$VERSION"; \
				mkdir -p "$$MAC_DIR"; \
				cp "$$f" "$$MAC_DIR/"; \
				if [ -f "$$f.sha256" ]; then cp "$$f.sha256" "$$MAC_DIR/"; fi; \
				echo "  Staged: $$(basename $$f) -> $$MAC_DIR/"; \
			fi; \
		done; \
		STAGED="$$STAGED macos"; \
	else \
		echo "  No macOS packages found in installer/dist/"; \
		MISSING="$$MISSING macos"; \
	fi; \
	echo ""; \
	\
	echo "--- Staging Windows packages ---"; \
	MSI_FILES=$$(ls installer/dist/*.msi 2>/dev/null || true); \
	if [ -n "$$MSI_FILES" ]; then \
		WIN_DIR="$$DOCS_REPO/repo/agent/windows/packages/$$VERSION"; \
		mkdir -p "$$WIN_DIR"; \
		for f in $$MSI_FILES; do \
			cp "$$f" "$$WIN_DIR/"; \
			if [ -f "$$f.sha256" ]; then cp "$$f.sha256" "$$WIN_DIR/"; fi; \
			echo "  Staged: $$(basename $$f) -> $$WIN_DIR/"; \
		done; \
		STAGED="$$STAGED windows"; \
	else \
		echo "  No .msi packages found in installer/dist/"; \
		MISSING="$$MISSING windows"; \
	fi; \
	echo ""; \
	\
	echo "--- Staging FreeBSD packages ---"; \
	FBSD_FILES=$$(ls installer/dist/*freebsd*.pkg installer/dist/*freebsd*.txz 2>/dev/null || true); \
	if [ -n "$$FBSD_FILES" ]; then \
		FBSD_DIR="$$DOCS_REPO/repo/agent/freebsd/$$VERSION"; \
		mkdir -p "$$FBSD_DIR"; \
		for f in $$FBSD_FILES; do \
			cp "$$f" "$$FBSD_DIR/"; \
			echo "  Staged: $$(basename $$f) -> $$FBSD_DIR/"; \
		done; \
		STAGED="$$STAGED freebsd"; \
	else \
		echo "  No FreeBSD packages found in installer/dist/"; \
		MISSING="$$MISSING freebsd"; \
	fi; \
	echo ""; \
	\
	echo "--- Staging OpenBSD packages ---"; \
	OBSD_FILES=$$(ls installer/dist/*openbsd* 2>/dev/null || true); \
	if [ -n "$$OBSD_FILES" ]; then \
		OBSD_DIR="$$DOCS_REPO/repo/agent/openbsd/$$VERSION"; \
		mkdir -p "$$OBSD_DIR"; \
		for f in $$OBSD_FILES; do \
			[ -f "$$f" ] || continue; \
			cp "$$f" "$$OBSD_DIR/"; \
			if [ -f "$$f.sha256" ]; then cp "$$f.sha256" "$$OBSD_DIR/"; fi; \
			echo "  Staged: $$(basename $$f) -> $$OBSD_DIR/"; \
		done; \
		STAGED="$$STAGED openbsd"; \
	else \
		echo "  No OpenBSD packages found"; \
		MISSING="$$MISSING openbsd"; \
	fi; \
	echo ""; \
	\
	echo "--- Staging NetBSD packages ---"; \
	NBSD_FILES=$$(ls installer/dist/*netbsd* 2>/dev/null || true); \
	if [ -n "$$NBSD_FILES" ]; then \
		NBSD_DIR="$$DOCS_REPO/repo/agent/netbsd/$$VERSION"; \
		mkdir -p "$$NBSD_DIR"; \
		for f in $$NBSD_FILES; do \
			[ -f "$$f" ] || continue; \
			cp "$$f" "$$NBSD_DIR/"; \
			if [ -f "$$f.sha256" ]; then cp "$$f.sha256" "$$NBSD_DIR/"; fi; \
			echo "  Staged: $$(basename $$f) -> $$NBSD_DIR/"; \
		done; \
		STAGED="$$STAGED netbsd"; \
	else \
		echo "  No NetBSD packages found"; \
		MISSING="$$MISSING netbsd"; \
	fi; \
	echo ""; \
	\
	echo "--- Staging Alpine packages ---"; \
	APK_FILES=$$(ls installer/dist/*alpine*.apk 2>/dev/null || true); \
	if [ -n "$$APK_FILES" ]; then \
		APK_DIR="$$DOCS_REPO/repo/agent/alpine/$$VERSION"; \
		mkdir -p "$$APK_DIR"; \
		for f in $$APK_FILES; do \
			cp "$$f" "$$APK_DIR/"; \
			if [ -f "$$f.sha256" ]; then cp "$$f.sha256" "$$APK_DIR/"; fi; \
			echo "  Staged: $$(basename $$f) -> $$APK_DIR/"; \
		done; \
		STAGED="$$STAGED alpine"; \
	else \
		echo "  No Alpine .apk packages found in installer/dist/"; \
		MISSING="$$MISSING alpine"; \
	fi; \
	echo ""; \
	\
	echo "--- Staging checksums and SBOMs ---"; \
	if [ -d sbom ]; then \
		SBOM_DIR="$$DOCS_REPO/repo/agent/sbom/$$VERSION"; \
		mkdir -p "$$SBOM_DIR"; \
		cp sbom/*.json "$$SBOM_DIR/" 2>/dev/null || true; \
		echo "  Staged SBOM files -> $$SBOM_DIR/"; \
	fi; \
	echo ""; \
	\
	echo "=========================================="; \
	echo "Staging Summary (v$$VERSION)"; \
	echo "=========================================="; \
	echo ""; \
	if [ -n "$$STAGED" ]; then \
		echo "Staged platforms:$$STAGED"; \
	else \
		echo "No packages were staged."; \
	fi; \
	if [ -n "$$MISSING" ]; then \
		echo "Missing platforms:$$MISSING"; \
		echo ""; \
		echo "Run deploy-docs-repo on other machines to stage those platforms."; \
		echo "Each run is additive - existing packages are preserved."; \
	fi; \
	echo ""; \
	echo "When all platforms are staged and GitHub access is restored:"; \
	echo "  cd $$DOCS_REPO"; \
	echo "  git add repo/"; \
	echo "  git commit -m 'Release sysmanage-agent v$$VERSION'"; \
	echo "  git push"

# Full release pipeline with interactive confirmation
release-local:
	@echo "=================================================="
	@echo "SysManage Agent - Local Release Pipeline"
	@echo "=================================================="
	@echo ""
	@set -e; \
	if [ -n "$$VERSION" ]; then \
		echo "Using VERSION from environment: $$VERSION"; \
	else \
		VERSION=$$(git describe --tags --abbrev=0 2>/dev/null | sed 's/^v//'); \
		if [ -z "$$VERSION" ]; then \
			VERSION="0.1.0"; \
			echo "No git tags found, using default version: $$VERSION"; \
		else \
			echo "Using version from git tag: $$VERSION"; \
		fi; \
	fi; \
	echo "Version: $$VERSION"; \
	echo ""; \
	\
	OS_TYPE=$$(uname -s); \
	echo "Detected OS: $$OS_TYPE"; \
	echo ""; \
	echo "This will run the release pipeline for the current platform."; \
	echo "Each step requires confirmation before proceeding."; \
	echo ""; \
	\
	echo "--- Step 1: Build packages for current platform ---"; \
	case "$$OS_TYPE" in \
		Linux) \
			if [ -f /etc/os-release ] && grep -qE "^ID=\"?(opensuse|sles)" /etc/os-release 2>/dev/null; then \
				BUILD_TARGET="installer-rpm"; \
			elif [ -f /etc/redhat-release ]; then \
				BUILD_TARGET="installer-rpm"; \
			else \
				BUILD_TARGET="installer-deb"; \
			fi; \
			;; \
		Darwin) \
			BUILD_TARGET="installer"; \
			;; \
		FreeBSD) \
			BUILD_TARGET="installer-freebsd"; \
			;; \
		NetBSD) \
			BUILD_TARGET="installer-netbsd"; \
			;; \
		OpenBSD) \
			BUILD_TARGET="installer-openbsd"; \
			;; \
		MINGW*|MSYS*) \
			BUILD_TARGET="installer-msi-all"; \
			;; \
		*) \
			echo "WARNING: Unknown OS $$OS_TYPE, defaulting to installer-deb"; \
			BUILD_TARGET="installer-deb"; \
			;; \
	esac; \
	printf "Build packages with 'make $$BUILD_TARGET'? [y/N] "; \
	read REPLY; \
	case "$$REPLY" in \
		[Yy]*) \
			export VERSION; \
			$(MAKE) $$BUILD_TARGET; \
			;; \
		*) echo "Skipped."; ;; \
	esac; \
	echo ""; \
	\
	echo "--- Step 2: Generate SBOM ---"; \
	printf "Generate SBOM with 'make sbom'? [y/N] "; \
	read REPLY; \
	case "$$REPLY" in \
		[Yy]*) $(MAKE) sbom; ;; \
		*) echo "Skipped."; ;; \
	esac; \
	echo ""; \
	\
	echo "--- Step 3: Generate checksums ---"; \
	printf "Generate checksums with 'make checksums'? [y/N] "; \
	read REPLY; \
	case "$$REPLY" in \
		[Yy]*) $(MAKE) checksums; ;; \
		*) echo "Skipped."; ;; \
	esac; \
	echo ""; \
	\
	echo "--- Step 4: Generate release notes ---"; \
	printf "Generate release notes with 'make release-notes'? [y/N] "; \
	read REPLY; \
	case "$$REPLY" in \
		[Yy]*) export VERSION; $(MAKE) release-notes; ;; \
		*) echo "Skipped."; ;; \
	esac; \
	echo ""; \
	\
	echo "--- Step 5: Stage to docs repo ---"; \
	printf "Stage packages to sysmanage-docs with 'make deploy-docs-repo'? [y/N] "; \
	read REPLY; \
	case "$$REPLY" in \
		[Yy]*) export VERSION; $(MAKE) deploy-docs-repo; ;; \
		*) echo "Skipped."; ;; \
	esac; \
	echo ""; \
	\
	if [ "$$OS_TYPE" = "Linux" ]; then \
		echo "--- Step 6: Deploy to Launchpad ---"; \
		printf "Upload to Launchpad PPA with 'make deploy-launchpad'? [y/N] "; \
		read REPLY; \
		case "$$REPLY" in \
			[Yy]*) export VERSION; $(MAKE) deploy-launchpad; ;; \
			*) echo "Skipped."; ;; \
		esac; \
		echo ""; \
		\
		echo "--- Step 7: Deploy to OBS ---"; \
		printf "Upload to OBS with 'make deploy-obs'? [y/N] "; \
		read REPLY; \
		case "$$REPLY" in \
			[Yy]*) export VERSION; $(MAKE) deploy-obs; ;; \
			*) echo "Skipped."; ;; \
		esac; \
		echo ""; \
		\
		echo "--- Step 8: Deploy to COPR ---"; \
		printf "Upload to COPR with 'make deploy-copr'? [y/N] "; \
		read REPLY; \
		case "$$REPLY" in \
			[Yy]*) export VERSION; $(MAKE) deploy-copr; ;; \
			*) echo "Skipped."; ;; \
		esac; \
		echo ""; \
		\
		echo "--- Step 9: Deploy to Snap Store ---"; \
		printf "Publish snap with 'make deploy-snap'? [y/N] "; \
		read REPLY; \
		case "$$REPLY" in \
			[Yy]*) export VERSION; $(MAKE) deploy-snap; ;; \
			*) echo "Skipped."; ;; \
		esac; \
		echo ""; \
		\
		echo "--- Step 10: Build Alpine packages (requires Docker) ---"; \
		if command -v docker >/dev/null 2>&1; then \
			printf "Build Alpine .apk packages with 'make installer-alpine'? [y/N] "; \
			read REPLY; \
			case "$$REPLY" in \
				[Yy]*) export VERSION; $(MAKE) installer-alpine; ;; \
				*) echo "Skipped."; ;; \
			esac; \
		else \
			echo "  Docker not found, skipping Alpine packages."; \
		fi; \
		echo ""; \
		\
		echo "--- Step 11: Build Flatpak package ---"; \
		if command -v flatpak-builder >/dev/null 2>&1; then \
			printf "Build Flatpak with 'make flatpak'? [y/N] "; \
			read REPLY; \
			case "$$REPLY" in \
				[Yy]*) export VERSION; $(MAKE) flatpak; ;; \
				*) echo "Skipped."; ;; \
			esac; \
		else \
			echo "  flatpak-builder not found, skipping Flatpak package."; \
		fi; \
		echo ""; \
	else \
		echo "(Steps 6-11 skipped: Linux-only deploy targets)"; \
		echo ""; \
	fi; \
	\
	echo "=========================================="; \
	echo "Release pipeline complete for v$$VERSION"; \
	echo "=========================================="; \
	echo ""; \
	echo "Summary:"; \
	echo "  Platform: $$OS_TYPE"; \
	echo "  Version:  $$VERSION"; \
	echo ""; \
	echo "Next steps:"; \
	echo "  - Run 'make release-local' on other machines for additional platforms"; \
	echo "  - When all platforms are done, commit and push sysmanage-docs"
