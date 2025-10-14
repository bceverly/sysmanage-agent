# SysManage Agent Installer Documentation

This document provides comprehensive instructions for building, testing, and distributing the SysManage Agent installers for Ubuntu/Debian (.deb) and CentOS/RHEL/Fedora (.rpm) systems.

---

## Table of Contents

- [Overview](#overview)
- [Quick Start](#quick-start)
  - [Ubuntu/Debian (.deb)](#ubuntudebian-deb)
  - [CentOS/RHEL/Fedora (.rpm)](#centosrhelfedora-rpm)
- [Building the Installer](#building-the-installer)
  - [Ubuntu/Debian Package](#ubuntudebian-package)
  - [CentOS/RHEL/Fedora Package](#centosrhelfedora-package)
- [Testing the Installer](#testing-the-installer)
- [Distribution Methods](#distribution-methods)
- [APT Repository Management](#apt-repository-management)
- [GitHub Actions Automation](#github-actions-automation)
- [Troubleshooting](#troubleshooting)

---

## Overview

The SysManage Agent installer packages provide:

- **Automated installation** with proper system user creation
- **Systemd service** that starts automatically on boot
- **Sudoers configuration** for system management capabilities
- **Database path fallback** (system → local)
- **Privilege detection** via sudoers parsing
- **Multi-Python version support** (3.10, 3.11, 3.12, 3.13)

### Package Types

- **Ubuntu/Debian (.deb)**: For Debian-based distributions
- **CentOS/RHEL/Fedora (.rpm)**: For Red Hat-based distributions

### Installation Locations

| Component | Path |
|-----------|------|
| Application | `/opt/sysmanage-agent/` |
| Configuration | `/etc/sysmanage-agent/` |
| Main Config | `/etc/sysmanage-agent.yaml` |
| Database | `/var/lib/sysmanage-agent/agent.db` |
| Logs | `/var/log/sysmanage-agent/` |
| Systemd Service | `/lib/systemd/system/sysmanage-agent.service` |
| Sudoers | `/etc/sudoers.d/sysmanage-agent` |

### System User

- **Username**: `sysmanage-agent`
- **Type**: System user (non-login)
- **Home**: `/nonexistent`
- **Privileges**: Sudo access via `/etc/sudoers.d/sysmanage-agent`

---

## Quick Start

### Ubuntu/Debian (.deb)

#### Build Installer Locally

```bash
# Using Makefile
make installer

# The .deb file will be in installer/dist/:
ls -lh installer/dist/sysmanage-agent_*.deb
```

#### Install Locally

```bash
# Install the package
sudo apt install installer/dist/sysmanage-agent_*.deb

# Or using dpkg
sudo dpkg -i installer/dist/sysmanage-agent_*.deb
sudo apt-get install -f  # Fix any dependency issues

# Check service status
sudo systemctl status sysmanage-agent
```

### CentOS/RHEL/Fedora (.rpm)

#### Build Installer Locally

```bash
# Using Makefile
make installer-rpm

# The .rpm file will be in installer/dist/:
ls -lh installer/dist/sysmanage-agent-*.rpm
```

#### Install Locally

```bash
# Install the package (choose one method)
sudo dnf install installer/dist/sysmanage-agent-*.rpm
# or
sudo yum install installer/dist/sysmanage-agent-*.rpm
# or
sudo rpm -ivh installer/dist/sysmanage-agent-*.rpm

# Check service status
sudo systemctl status sysmanage-agent
```

### Configure and Start

```bash
# Edit configuration
sudo nano /etc/sysmanage-agent.yaml

# Restart service
sudo systemctl restart sysmanage-agent

# View logs
sudo journalctl -u sysmanage-agent -f
```

---

## Building the Installer

### Ubuntu/Debian Package

#### Prerequisites

Install required build tools:

```bash
sudo apt-get update
sudo apt-get install -y \
  debhelper \
  dh-python \
  python3-all \
  python3-setuptools \
  build-essential \
  devscripts \
  lintian

# Or use the Makefile helper
make install-dev
```

### Manual Build Process

#### 1. Prepare Build Environment

```bash
cd ~/dev/sysmanage-agent

# Create build directory
VERSION="1.0.0"
BUILD_DIR="../sysmanage-agent-$VERSION"
mkdir -p "$BUILD_DIR"
```

#### 2. Copy Source Files

```bash
# Copy application source
cp -r src "$BUILD_DIR/"
cp main.py "$BUILD_DIR/"
cp requirements.txt "$BUILD_DIR/"

# Copy README if it exists
cp README.md "$BUILD_DIR/" || touch "$BUILD_DIR/README.md"

# Copy Debian packaging files
cp -r installer/ubuntu/debian "$BUILD_DIR/"

# Copy installer support files
mkdir -p "$BUILD_DIR/installer/ubuntu"
cp installer/ubuntu/*.service "$BUILD_DIR/installer/ubuntu/"
cp installer/ubuntu/*.sudoers "$BUILD_DIR/installer/ubuntu/"
cp installer/ubuntu/*.example "$BUILD_DIR/installer/ubuntu/"
```

#### 3. Update Version in Changelog

```bash
cd "$BUILD_DIR"

# Update changelog with your version
DATE=$(date -R)
sed -i "s/0\.1\.0-1/$VERSION-1/g" debian/changelog
sed -i "s/Mon, 14 Oct 2025 00:00:00 -0400/$DATE/g" debian/changelog
```

#### 4. Build Package

```bash
# Build without signing (for testing)
dpkg-buildpackage -us -uc -b

# The .deb will be created in the parent directory
ls -lh ../sysmanage-agent_*.deb
```

#### 5. Verify Package

```bash
# Check package contents
dpkg-deb --contents ../sysmanage-agent_*.deb

# Check package info
dpkg-deb --info ../sysmanage-agent_*.deb

# Run lintian (package quality checker)
lintian ../sysmanage-agent_*.deb
```

#### Using the Makefile

The Makefile provides a `make installer` target that automates the entire process:

```bash
# Build installer
make installer

# The .deb file will be in installer/dist/sysmanage-agent_*.deb
```

The Makefile target automatically:
- Creates the build directory
- Copies all necessary files
- Updates the version number (uses git describe)
- Builds the package
- Runs lintian for quality checks
- Reports the output file location

---

### CentOS/RHEL/Fedora Package

#### Prerequisites

Install required build tools:

```bash
# For Fedora/CentOS Stream 9+/RHEL 9+
sudo dnf install -y \
  rpm-build \
  rpmdevtools \
  python3-devel \
  python3-setuptools \
  rsync

# For older CentOS/RHEL 7-8
sudo yum install -y \
  rpm-build \
  rpmdevtools \
  python3-devel \
  python3-setuptools \
  rsync

# Or use the Makefile helper
make install-dev-rpm
```

#### Manual Build Process

##### 1. Set Up RPM Build Tree

```bash
cd ~/dev/sysmanage-agent

# Create RPM build directories
mkdir -p ~/rpmbuild/{BUILD,RPMS,SOURCES,SPECS,SRPMS}
```

##### 2. Create Source Tarball

```bash
VERSION="1.0.0"
TAR_NAME="sysmanage-agent-$VERSION"
TAR_DIR="/tmp/$TAR_NAME"

# Create temporary directory
mkdir -p "$TAR_DIR"

# Copy source files
cp -r src "$TAR_DIR/"
cp main.py "$TAR_DIR/"
cp alembic.ini "$TAR_DIR/"
cp requirements-prod.txt "$TAR_DIR/"
cp README.md "$TAR_DIR/" || touch "$TAR_DIR/README.md"
cp LICENSE "$TAR_DIR/" || touch "$TAR_DIR/LICENSE"

# Copy installer files
mkdir -p "$TAR_DIR/installer/centos"
cp installer/centos/*.service "$TAR_DIR/installer/centos/"
cp installer/centos/*.sudoers "$TAR_DIR/installer/centos/"
cp installer/centos/*.example "$TAR_DIR/installer/centos/"

# Create tarball
cd /tmp
tar czf ~/rpmbuild/SOURCES/sysmanage-agent-$VERSION.tar.gz "$TAR_NAME/"
```

##### 3. Update Spec File

```bash
# Copy spec file
cp installer/centos/sysmanage-agent.spec ~/rpmbuild/SPECS/

# Update version
sed -i "s/^Version:.*/Version:        $VERSION/" ~/rpmbuild/SPECS/sysmanage-agent.spec

# Update changelog date
DATE=$(date "+%a %b %d %Y")
sed -i "s/^\\* Mon Oct 14 2024/\\* $DATE/" ~/rpmbuild/SPECS/sysmanage-agent.spec
```

##### 4. Build Package

```bash
# Build RPM (binary only)
rpmbuild -bb ~/rpmbuild/SPECS/sysmanage-agent.spec

# The .rpm will be in ~/rpmbuild/RPMS/noarch/
ls -lh ~/rpmbuild/RPMS/noarch/sysmanage-agent-*.rpm
```

##### 5. Verify Package

```bash
# Check package contents
rpm -qlp ~/rpmbuild/RPMS/noarch/sysmanage-agent-*.rpm

# Check package info
rpm -qip ~/rpmbuild/RPMS/noarch/sysmanage-agent-*.rpm

# Check package dependencies
rpm -qpR ~/rpmbuild/RPMS/noarch/sysmanage-agent-*.rpm
```

#### Using the Makefile

The Makefile provides a `make installer-rpm` target that automates the entire process:

```bash
# Build RPM installer
make installer-rpm

# The .rpm file will be in installer/dist/sysmanage-agent-*.rpm
```

The Makefile target automatically:
- Creates the RPM build tree
- Creates source tarball
- Copies all necessary files
- Updates the version number (uses git describe)
- Builds the RPM package
- Reports the output file location

---

## Testing the Installer

### Local Testing

#### 1. Install Package

```bash
# Install the .deb
sudo dpkg -i ../sysmanage-agent_*.deb

# If dependencies are missing:
sudo apt-get install -f
```

#### 2. Verify Installation

```bash
# Check user was created
id sysmanage-agent

# Check directories
ls -la /opt/sysmanage-agent/
ls -la /etc/sysmanage-agent/
ls -la /var/lib/sysmanage-agent/
ls -la /var/log/sysmanage-agent/

# Check service
systemctl status sysmanage-agent

# Check sudoers file
sudo cat /etc/sudoers.d/sysmanage-agent

# Verify sudoers syntax
sudo visudo -c -f /etc/sudoers.d/sysmanage-agent
```

#### 3. Test Service

```bash
# Stop service
sudo systemctl stop sysmanage-agent

# Start service
sudo systemctl start sysmanage-agent

# Check logs
sudo journalctl -u sysmanage-agent -n 50

# Follow logs in real-time
sudo journalctl -u sysmanage-agent -f
```

#### 4. Test Privilege Detection

```bash
# Become sysmanage-agent user
sudo -u sysmanage-agent bash

# In Python
python3 -c "
from src.sysmanage_agent.core.agent_utils import is_running_privileged
print('Privileged:', is_running_privileged())
"
# Should return: Privileged: True

# Test sudo access
sudo -n systemctl status sysmanage-agent
# Should work without password prompt
```

#### 5. Test Configuration

```bash
# Edit config
sudo nano /etc/sysmanage-agent.yaml

# Update server URL and token
# Then restart
sudo systemctl restart sysmanage-agent

# Verify it uses the new config
sudo journalctl -u sysmanage-agent -n 20
```

### Testing on Clean System

Use a VM or container for clean testing:

```bash
# Using Docker
docker run -it --rm ubuntu:24.04 bash

# Inside container:
apt-get update
apt-get install -y ./sysmanage-agent_*.deb
systemctl status sysmanage-agent
```

### Removal Testing

```bash
# Remove package (keep config)
sudo apt-get remove sysmanage-agent

# Check what remains
ls /etc/sysmanage-agent.yaml  # Should exist
ls /var/lib/sysmanage-agent/   # Should exist

# Reinstall
sudo dpkg -i ../sysmanage-agent_*.deb

# Purge (remove everything)
sudo apt-get purge sysmanage-agent

# Verify complete removal
ls /etc/sysmanage-agent/       # Should not exist
ls /var/lib/sysmanage-agent/   # Should not exist
id sysmanage-agent             # Should not exist
```

---

## Distribution Methods

There are two primary methods for distributing the installer:

### Method A: Launchpad PPA (Manual)

**Requires**: Launchpad account, GPG key, manual package upload

**Advantages**:
- Official Ubuntu PPA infrastructure
- Automatic updates for users
- Built-in package signing

**Process**:
1. Create Launchpad account
2. Generate GPG key and upload to Launchpad
3. Build source package with `debuild -S`
4. Upload with `dput ppa:bceverly/sysmanage`
5. Wait for Launchpad to build for all architectures

**User Installation**:
```bash
sudo add-apt-repository ppa:bceverly/sysmanage
sudo apt-get update
sudo apt-get install sysmanage-agent
```

### Method B: GitHub Pages APT Repository (Automated)

**Requires**: GitHub Pages enabled on sysmanage-docs repository

**Advantages**:
- Fully automated via GitHub Actions
- No external account needed
- Complete control

**Setup** (One-time):

1. **Enable GitHub Pages** for `sysmanage-docs`:
   - Go to repository Settings → Pages
   - Source: `main` branch
   - Root: `/`

2. **Commit APT structure**:
   ```bash
   cd ~/dev/sysmanage-docs
   git add apt/
   git commit -m "Add APT repository structure for sysmanage-agent"
   git push
   ```

3. **Wait for GitHub Pages** to deploy (2-5 minutes)

4. **Verify repository is accessible**:
   ```bash
   curl -I https://bceverly.github.io/sysmanage-docs/apt/dists/stable/Release
   # Should return 200 OK
   ```

**User Installation**:
```bash
# Add repository (using trusted=yes since we don't sign with GPG yet)
echo "deb [trusted=yes] https://bceverly.github.io/sysmanage-docs/apt stable main" | \
  sudo tee /etc/apt/sources.list.d/sysmanage.list

# Update and install
sudo apt-get update
sudo apt-get install sysmanage-agent
```

---

## APT Repository Management

The APT repository is located in `~/dev/sysmanage-docs/apt/`.

### Repository Structure

```
apt/
├── README.md              # Full documentation
├── update-repo.sh         # Helper script
├── pool/
│   └── main/              # .deb files stored here
│       └── sysmanage-agent_X.Y.Z-1_all.deb
└── dists/
    └── stable/
        ├── Release        # Repository metadata
        └── main/
            └── binary-amd64/
                ├── Packages     # Package index
                └── Packages.gz  # Compressed index
```

### Adding a Package to the Repository

#### Using the Helper Script (Recommended)

```bash
cd ~/dev/sysmanage-docs/apt

# Add package and update indexes
./update-repo.sh ~/dev/sysmanage-agent_1.0.0-1_all.deb

# The script will:
# 1. Copy .deb to pool/main/
# 2. Generate Packages index
# 3. Compress index to Packages.gz
# 4. Update Release file
# 5. Show you what to commit
```

#### Manual Process

```bash
cd ~/dev/sysmanage-docs

# 1. Copy .deb to pool
cp ~/dev/sysmanage-agent_1.0.0-1_all.deb apt/pool/main/

# 2. Generate package index
cd apt
dpkg-scanpackages pool/main /dev/null > dists/stable/main/binary-amd64/Packages

# 3. Compress index
gzip -k -f dists/stable/main/binary-amd64/Packages

# 4. Update Release file
cd dists/stable
apt-ftparchive release . > Release
cd ../..
```

### Publishing Updates

```bash
cd ~/dev/sysmanage-docs

# Commit changes
git add apt/
git commit -m "Add sysmanage-agent version 1.0.0"
git push

# Wait 2-5 minutes for GitHub Pages to update

# Verify
curl https://bceverly.github.io/sysmanage-docs/apt/dists/stable/main/binary-amd64/Packages
```

### Testing the Repository

```bash
# On a test system
echo "deb [trusted=yes] https://bceverly.github.io/sysmanage-docs/apt stable main" | \
  sudo tee /etc/apt/sources.list.d/sysmanage-test.list

sudo apt-get update

# Check available versions
apt-cache policy sysmanage-agent

# Install
sudo apt-get install sysmanage-agent

# Verify
systemctl status sysmanage-agent
```

---

## GitHub Actions Automation

The build process is automated via GitHub Actions in `.github/workflows/build-ubuntu-deb.yml`.

### Triggering a Release Build

#### Method 1: Version Tag (Recommended)

```bash
cd ~/dev/sysmanage-agent

# Create and push a version tag
git tag v1.0.0
git push origin v1.0.0

# GitHub Actions will automatically:
# 1. Wait for CI tests to pass (Python 3.10-3.13)
# 2. Build the .deb package
# 3. Run lintian quality checks
# 4. Create a GitHub Release
# 5. Upload .deb and SHA256 checksum
```

#### Method 2: Manual Workflow Dispatch

1. Go to GitHub repository → Actions → "Build Ubuntu/Debian Package"
2. Click "Run workflow"
3. Enter version number (e.g., `1.0.0`)
4. Click "Run workflow"

The workflow will build and create a release.

### Workflow Stages

1. **Wait for CI Tests**: Ensures all Python versions pass tests
2. **Build Package**: Creates .deb on Ubuntu 24.04
3. **Quality Check**: Runs lintian
4. **Generate Checksums**: Creates SHA256 hash
5. **Create Release**: Publishes to GitHub Releases
6. **Upload Assets**: Attaches .deb and checksum

### Downloading Release Artifacts

```bash
# List releases
gh release list

# Download latest .deb
gh release download v1.0.0 --pattern "*.deb"

# Or use direct URL
wget https://github.com/bceverly/sysmanage-agent/releases/download/v1.0.0/sysmanage-agent_1.0.0-1_all.deb
```

### Integrating with APT Repository

After GitHub Actions creates the release:

1. **Download the .deb**:
   ```bash
   cd ~/dev/sysmanage-docs
   wget https://github.com/bceverly/sysmanage-agent/releases/download/v1.0.0/sysmanage-agent_1.0.0-1_all.deb
   ```

2. **Update repository**:
   ```bash
   ./apt/update-repo.sh sysmanage-agent_1.0.0-1_all.deb
   ```

3. **Commit and push**:
   ```bash
   git add apt/
   git commit -m "Add sysmanage-agent version 1.0.0 to APT repository"
   git push
   ```

4. **Verify** (after 2-5 minutes):
   ```bash
   curl https://bceverly.github.io/sysmanage-docs/apt/dists/stable/main/binary-amd64/Packages | grep Version
   ```

---

## Troubleshooting

### Build Issues

#### Ubuntu/Debian Build Issues

**Error**: `dpkg-checkbuilddeps: error: Unmet build dependencies`

**Solution**:
```bash
sudo apt-get install -y debhelper dh-python python3-all python3-setuptools build-essential
# Or use the helper
make install-dev
```

**Error**: `debian/rules: Permission denied`

**Solution**:
```bash
chmod +x installer/ubuntu/debian/rules
```

**Error**: Various lintian warnings/errors

**Solution**: Most warnings can be ignored for initial releases. Critical errors:
- **sudoers-file-wrong-permissions**: Fixed by debian/rules (chmod 0440)
- **invalid-debian-changelog**: Update version and date format

#### CentOS/RHEL/Fedora Build Issues

**Error**: `rpmbuild: command not found`

**Solution**:
```bash
sudo dnf install -y rpm-build rpmdevtools python3-devel python3-setuptools
# Or use the helper
make install-dev-rpm
```

**Error**: `error: File /root/rpmbuild/SOURCES/sysmanage-agent-X.Y.Z.tar.gz: No such file or directory`

**Solution**: Ensure the source tarball is created before building:
```bash
# The Makefile handles this automatically, but if building manually:
cd /tmp
tar czf ~/rpmbuild/SOURCES/sysmanage-agent-VERSION.tar.gz sysmanage-agent-VERSION/
```

**Error**: `error: Failed build dependencies: python3-devel is needed`

**Solution**:
```bash
sudo dnf install -y python3-devel python3-setuptools
```

**Error**: Sudoers file validation fails during build

**Solution**: The spec file validates the sudoers file syntax. Check the sudoers file:
```bash
visudo -c -f installer/centos/sysmanage-agent.sudoers
```

### Installation Issues

#### Service Fails to Start (Both .deb and .rpm)

**Error**: `systemctl status sysmanage-agent` shows failed

**Solution**:
```bash
# Check logs
sudo journalctl -u sysmanage-agent -n 50

# Common issues:
# 1. Missing config file
sudo cp /etc/sysmanage-agent/sysmanage-agent.yaml.example /etc/sysmanage-agent.yaml

# 2. Database permissions
sudo chown -R sysmanage-agent:sysmanage-agent /var/lib/sysmanage-agent

# 3. Python dependencies (Debian/Ubuntu)
sudo apt-get install -f

# 3. Python dependencies (CentOS/RHEL/Fedora)
sudo dnf install -y python3 python3-pip
```

#### RPM Installation Issues

**Error**: `error: Failed dependencies: python3 >= 3.10 is needed`

**Solution**: Install Python 3.10+ first:
```bash
# On CentOS/RHEL 7-8, you may need to install from EPEL or SCL
sudo dnf install -y python3.10  # or python3.11

# On Fedora/CentOS Stream 9+/RHEL 9+, Python 3.9+ is usually available
sudo dnf install -y python3
```

**Error**: `error: unpacking of archive failed on file /etc/sudoers.d/sysmanage-agent`

**Solution**: This can happen if sudoers directory doesn't exist:
```bash
sudo mkdir -p /etc/sudoers.d
sudo chmod 750 /etc/sudoers.d
```

#### User Not Created

**Error**: `id sysmanage-agent` fails

**Solution**:
```bash
# Manually run postinst script
sudo /var/lib/dpkg/info/sysmanage-agent.postinst configure
```

#### Sudoers File Not Working

**Error**: `sudo -u sysmanage-agent sudo -n systemctl status` asks for password

**Solution**:
```bash
# Verify file exists and has correct permissions
ls -la /etc/sudoers.d/sysmanage-agent
# Should be: -r--r----- 1 root root ... sysmanage-agent

# Check syntax
sudo visudo -c -f /etc/sudoers.d/sysmanage-agent

# Reinstall if needed
sudo apt-get install --reinstall sysmanage-agent
```

### Repository Issues

#### Repository Not Found (404)

**Error**: `E: Failed to fetch https://bceverly.github.io/sysmanage-docs/apt/...`

**Solution**:
1. Verify GitHub Pages is enabled
2. Check that `apt/` directory is in `main` branch
3. Wait 5 minutes after pushing
4. Verify URL in browser: https://bceverly.github.io/sysmanage-docs/apt/dists/stable/Release

#### Package Not Found

**Error**: `E: Unable to locate package sysmanage-agent`

**Solution**:
```bash
# 1. Verify Packages file exists
curl https://bceverly.github.io/sysmanage-docs/apt/dists/stable/main/binary-amd64/Packages

# 2. Update package list
sudo apt-get update

# 3. Check for typos in sources.list
cat /etc/apt/sources.list.d/sysmanage.list
```

#### GPG Signature Errors

**Error**: `NO_PUBKEY` or signature verification failed

**Solution**: Use `[trusted=yes]` in sources.list:
```bash
deb [trusted=yes] https://bceverly.github.io/sysmanage-docs/apt stable main
```

For production, set up GPG signing (see `~/dev/sysmanage-docs/apt/README.md`).

---

## Platform Compatibility

### Tested Platforms

- ✅ Ubuntu 22.04 LTS (Jammy) - Python 3.10
- ✅ Ubuntu 24.04 LTS (Noble) - Python 3.12
- ✅ Debian 11 (Bullseye) - Python 3.9*
- ✅ Debian 12 (Bookworm) - Python 3.11

*Note: Debian 11 has Python 3.9 which is below our minimum requirement (3.10). Package will not install on Debian 11.

### Python Version Requirements

The package requires **Python 3.10+**. This is enforced in:
- `installer/ubuntu/debian/control` - Dependency: `python3 (>= 3.10)`
- `.github/workflows/ci.yml` - Tests on 3.10, 3.11, 3.12, 3.13

**Note**: Python 3.14 is currently excluded from CI testing due to incompatibility with `ruamel.yaml.clib` (a transitive dependency of `semgrep`). This will be re-evaluated once the upstream dependency is updated to support Python 3.14.

### RPM Platform Compatibility

**Tested Platforms**:
- ✅ Rocky Linux 9 - Python 3.9+
- ✅ AlmaLinux 9 - Python 3.9+
- ✅ CentOS Stream 9+ - Python 3.9+
- ✅ RHEL 9+ - Python 3.9+
- ✅ Fedora 38+ - Python 3.11+

**Note**: Older versions (CentOS 7, RHEL 7-8) may require Python 3.10+ to be installed separately.

### Future Platform Support

Planned platform support:
- **Windows**: .msi installer (WiX Toolset)
- **macOS**: .pkg installer (pkgbuild)
- **Arch Linux**: PKGBUILD for AUR

---

## Version Management

### Version Number Format

We use semantic versioning: `MAJOR.MINOR.PATCH`

- **MAJOR**: Breaking changes
- **MINOR**: New features (backward compatible)
- **PATCH**: Bug fixes

### Updating Version

1. **Update changelog**:
   ```bash
   cd ~/dev/sysmanage-agent/installer/ubuntu/debian
   nano changelog
   # Add new entry at the top with new version
   ```

2. **Tag the release**:
   ```bash
   git tag v1.1.0
   git push origin v1.1.0
   ```

3. **GitHub Actions** will automatically build with the new version

### Version Sources

The version number is read from:
1. Git tag (if building via GitHub Actions)
2. `debian/changelog` (first entry)
3. Manual input (workflow_dispatch)

---

## Security Considerations

### Sudoers Privileges

The installer grants extensive sudo privileges to the `sysmanage-agent` user. Review the sudoers file before deploying:

```bash
cat installer/ubuntu/sysmanage-agent.sudoers
```

Consider restricting permissions based on your needs.

### Package Signing

For production deployments, GPG-sign packages:

1. **Generate GPG key**:
   ```bash
   gpg --full-generate-key
   ```

2. **Sign package**:
   ```bash
   dpkg-sig -k YOUR_KEY_ID --sign builder sysmanage-agent_*.deb
   ```

3. **Sign APT repository**:
   ```bash
   cd ~/dev/sysmanage-docs/apt/dists/stable
   gpg --default-key YOUR_KEY_ID -abs -o Release.gpg Release
   ```

See `~/dev/sysmanage-docs/apt/README.md` for detailed GPG setup.

### SSL Verification

By default, the agent verifies SSL certificates. To disable (not recommended):

```yaml
# /etc/sysmanage-agent.yaml
security:
  verify_ssl: false
```

---

## Additional Resources

- **Debian Packaging Guide**: https://www.debian.org/doc/manuals/maint-guide/
- **Ubuntu Packaging**: https://packaging.ubuntu.com/html/
- **APT Repository Format**: https://wiki.debian.org/DebianRepository/Format
- **GitHub Actions**: https://docs.github.com/en/actions

---

## Support

For issues or questions:
- **GitHub Issues**: https://github.com/bceverly/sysmanage-agent/issues
- **Documentation**: https://github.com/bceverly/sysmanage-docs

---

*Last Updated: October 14, 2025 (Python 3.14 excluded from testing)*
