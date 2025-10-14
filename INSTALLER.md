# SysManage Agent Installer Documentation

This document provides comprehensive instructions for building, testing, and distributing the SysManage Agent Ubuntu/Debian installer.

---

## Table of Contents

- [Overview](#overview)
- [Quick Start](#quick-start)
- [Building the Installer](#building-the-installer)
- [Testing the Installer](#testing-the-installer)
- [Distribution Methods](#distribution-methods)
- [APT Repository Management](#apt-repository-management)
- [GitHub Actions Automation](#github-actions-automation)
- [Troubleshooting](#troubleshooting)

---

## Overview

The SysManage Agent installer package provides:

- **Automated installation** with proper system user creation
- **Systemd service** that starts automatically on boot
- **Sudoers configuration** for system management capabilities
- **Database path fallback** (system → local)
- **Privilege detection** via sudoers parsing
- **Multi-Python version support** (3.10, 3.11, 3.12, 3.13, 3.14)

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

### Build Installer Locally

```bash
# Using Makefile
make installer

# The .deb file will be in the parent directory:
ls -lh ../sysmanage-agent_*.deb
```

### Install Locally

```bash
# Install the package
sudo dpkg -i ../sysmanage-agent_*.deb

# Fix any dependency issues (if needed)
sudo apt-get install -f

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

### Prerequisites

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

### Using the Makefile

The Makefile provides a `make installer` target that automates the entire process:

```bash
# Build installer
make installer

# The .deb file will be in ../sysmanage-agent_*.deb
```

The Makefile target automatically:
- Creates the build directory
- Copies all necessary files
- Updates the version number (uses git describe)
- Builds the package
- Runs lintian for quality checks
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
# 1. Wait for CI tests to pass (Python 3.10-3.14)
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

#### Missing Dependencies

**Error**: `dpkg-checkbuilddeps: error: Unmet build dependencies`

**Solution**:
```bash
sudo apt-get install -y debhelper dh-python python3-all python3-setuptools build-essential
```

#### Permission Denied on debian/rules

**Error**: `debian/rules: Permission denied`

**Solution**:
```bash
chmod +x installer/ubuntu/debian/rules
```

#### Lintian Errors

**Error**: Various lintian warnings/errors

**Solution**: Most warnings can be ignored for initial releases. Critical errors:
- **sudoers-file-wrong-permissions**: Fixed by debian/rules (chmod 0440)
- **invalid-debian-changelog**: Update version and date format

### Installation Issues

#### Service Fails to Start

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

# 3. Python dependencies
sudo apt-get install -f
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
- `.github/workflows/ci.yml` - Tests on 3.10, 3.11, 3.12, 3.13, 3.14

### Future Platform Support

Planned platform support:
- **Windows**: .msi installer (WiX Toolset)
- **macOS**: .pkg installer (pkgbuild)
- **RPM-based**: .rpm for CentOS/RHEL/Fedora
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

*Last Updated: October 14, 2025*
