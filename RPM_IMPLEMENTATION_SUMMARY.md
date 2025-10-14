# RPM Packaging Implementation Summary

This document summarizes the RPM packaging implementation for the SysManage Agent on CentOS, RHEL, Fedora, Rocky Linux, and AlmaLinux systems.

## Overview

RPM packaging support has been added to complement the existing Debian/Ubuntu (.deb) packaging. This enables deployment on Red Hat-based Linux distributions.

## Files Created

### 1. RPM Packaging Files (`installer/centos/`)

- **`sysmanage-agent.spec`**: RPM spec file defining package metadata, dependencies, build process, and installation scripts
- **`sysmanage-agent.service`**: Systemd service unit file (identical to Ubuntu version)
- **`sysmanage-agent.sudoers`**: Sudoers configuration with DNF/YUM, firewalld, and SELinux management privileges
- **`sysmanage-agent.yaml.example`**: Example configuration file (copied from Ubuntu version)

### 2. Makefile Targets

Added two new targets to `Makefile`:

- **`make install-dev-rpm`**: Installs RPM build tools (rpm-build, rpmdevtools, python3-devel, etc.)
- **`make installer-rpm`**: Builds the .rpm package locally

### 3. GitHub Actions Workflow

- **`.github/workflows/build-centos-rpm.yml`**: Automated RPM building on tag push
  - Uses Rocky Linux 9 container
  - Waits for CI tests to pass
  - Builds RPM package
  - Creates GitHub Release with .rpm and SHA256 checksum
  - Runs automatically on version tags (e.g., `v1.0.0`)

### 4. Documentation

- **Updated `INSTALLER.md`**: Added comprehensive RPM documentation including:
  - Quick start for RPM
  - Manual build process
  - Prerequisites
  - Platform compatibility
  - Troubleshooting for RPM-specific issues

## Key Differences: DEB vs RPM

### Package Manager Commands

| Task | DEB (Ubuntu/Debian) | RPM (CentOS/RHEL/Fedora) |
|------|---------------------|--------------------------|
| Install | `apt install` / `dpkg -i` | `dnf install` / `yum install` / `rpm -ivh` |
| Remove | `apt remove` | `dnf remove` / `yum remove` / `rpm -e` |
| List files | `dpkg -L` | `rpm -ql` |
| Package info | `dpkg -s` | `rpm -qi` |

### Packaging Tools

- **DEB**: debhelper, dpkg-buildpackage, lintian
- **RPM**: rpm-build, rpmbuild, rpmdevtools

### Sudoers Configuration

**DEB (`installer/ubuntu/sysmanage-agent.sudoers`)**:
- APT/DPKG package management
- UFW firewall management
- Ubuntu Pro management
- systemctl service management

**RPM (`installer/centos/sysmanage-agent.sudoers`)**:
- DNF/YUM/RPM package management
- firewalld firewall management
- SELinux management (setenforce, semanage, setsebool, getsebool)
- systemctl service management

### User Creation

**DEB (`postinst`)**:
```bash
adduser --system --group --home /nonexistent --no-create-home \
    --disabled-password --disabled-login \
    --gecos "SysManage Agent" sysmanage-agent
```

**RPM (`%pre` section in spec)**:
```bash
useradd --system --user-group --home-dir /nonexistent --no-create-home \
    --shell /sbin/nologin --comment "SysManage Agent" sysmanage-agent
```

### Installation Scripts

**DEB**: Uses separate script files
- `postinst`: Post-installation tasks
- `prerm`: Pre-removal tasks
- `postrm`: Post-removal tasks

**RPM**: Uses spec file sections
- `%pre`: Pre-installation (user creation)
- `%post`: Post-installation (permissions, service enable/start)
- `%preun`: Pre-uninstall (service stop)
- `%postun`: Post-uninstall (cleanup on purge)

### Systemd Integration

**DEB**: Manual systemd commands
```bash
systemctl enable sysmanage-agent.service
systemctl start sysmanage-agent.service
```

**RPM**: Uses systemd RPM macros
```bash
%systemd_post sysmanage-agent.service
%systemd_preun sysmanage-agent.service
%systemd_postun_with_restart sysmanage-agent.service
```

## Build Process Comparison

### DEB Build Process

1. Create build directory
2. Copy source files
3. Copy debian/ directory
4. Create source tarball (.orig.tar.gz)
5. Run `dpkg-buildpackage -us -uc -b`
6. Output: `sysmanage-agent_VERSION-1_all.deb`

### RPM Build Process

1. Create RPM build tree (BUILD, RPMS, SOURCES, SPECS, SRPMS)
2. Copy source files to temporary directory
3. Create source tarball in SOURCES/
4. Copy spec file to SPECS/
5. Run `rpmbuild -bb SPECS/sysmanage-agent.spec`
6. Output: `sysmanage-agent-VERSION-1.noarch.rpm` (in RPMS/noarch/)

## Testing Locally

### Building DEB Package
```bash
cd ~/dev/sysmanage-agent
make installer
# Output: installer/dist/sysmanage-agent_*.deb
```

### Building RPM Package
```bash
cd ~/dev/sysmanage-agent
make installer-rpm
# Output: installer/dist/sysmanage-agent-*.rpm
```

### Installing Locally

**Ubuntu/Debian**:
```bash
sudo apt install installer/dist/sysmanage-agent_*.deb
sudo systemctl status sysmanage-agent
```

**CentOS/RHEL/Fedora**:
```bash
sudo dnf install installer/dist/sysmanage-agent-*.rpm
sudo systemctl status sysmanage-agent
```

## Supported Platforms

### DEB Package
- ✅ Ubuntu 22.04 LTS (Jammy) - Python 3.10
- ✅ Ubuntu 24.04 LTS (Noble) - Python 3.12
- ✅ Debian 12 (Bookworm) - Python 3.11

### RPM Package
- ✅ Rocky Linux 9 - Python 3.9+
- ✅ AlmaLinux 9 - Python 3.9+
- ✅ CentOS Stream 9+ - Python 3.9+
- ✅ RHEL 9+ - Python 3.9+
- ✅ Fedora 38+ - Python 3.11+

## GitHub Actions Automation

### DEB Workflow
- **File**: `.github/workflows/build-ubuntu-deb.yml`
- **Container**: ubuntu-24.04
- **Trigger**: Version tags (v*.*.*)
- **Output**: .deb package + Release
- **Additional**: Updates APT repository in sysmanage-docs

### RPM Workflow
- **File**: `.github/workflows/build-centos-rpm.yml`
- **Container**: rockylinux:9
- **Trigger**: Version tags (v*.*.*)
- **Output**: .rpm package + Release

Both workflows:
1. Wait for CI tests to pass
2. Build package
3. Create GitHub Release
4. Upload package and SHA256 checksum

## Directory Structure

```
sysmanage-agent/
├── installer/
│   ├── ubuntu/              # DEB packaging
│   │   ├── debian/
│   │   │   ├── changelog
│   │   │   ├── control
│   │   │   ├── copyright
│   │   │   ├── install
│   │   │   ├── postinst
│   │   │   ├── postrm
│   │   │   ├── prerm
│   │   │   └── rules
│   │   ├── sysmanage-agent.service
│   │   ├── sysmanage-agent.sudoers
│   │   └── sysmanage-agent.yaml.example
│   └── centos/              # RPM packaging (NEW)
│       ├── sysmanage-agent.spec
│       ├── sysmanage-agent.service
│       ├── sysmanage-agent.sudoers
│       └── sysmanage-agent.yaml.example
├── .github/
│   └── workflows/
│       ├── build-ubuntu-deb.yml
│       └── build-centos-rpm.yml  # NEW
└── Makefile                 # Updated with RPM targets
```

## Installation Paths (Same for Both)

| Component | Path |
|-----------|------|
| Application | `/opt/sysmanage-agent/` |
| Configuration | `/etc/sysmanage-agent/` |
| Main Config | `/etc/sysmanage-agent.yaml` |
| Database | `/var/lib/sysmanage-agent/agent.db` |
| Logs | `/var/log/sysmanage-agent/` |
| Systemd Service | `/usr/lib/systemd/system/sysmanage-agent.service` |
| Sudoers | `/etc/sudoers.d/sysmanage-agent` |

## Python Virtual Environment

Both packages create a virtualenv at `/opt/sysmanage-agent/.venv` and install production dependencies from `requirements-prod.txt`.

## Next Steps

### For Testing
1. Test RPM build on Rocky Linux 9 / AlmaLinux 9 / Fedora 39+
2. Verify installation, service startup, and privilege detection
3. Test uninstall and purge scenarios

### For Production Deployment
1. Tag a release: `git tag v1.0.0 && git push origin v1.0.0`
2. GitHub Actions will automatically build both .deb and .rpm packages
3. Packages will be available in GitHub Releases
4. Users can download and install based on their distribution

### Future Enhancements
- YUM/DNF repository hosting (similar to APT repository)
- GPG signing for RPM packages
- Support for older CentOS/RHEL 7-8 (may require Python 3.10+ backport)
- ARM64 package builds

## Troubleshooting

See `INSTALLER.md` for comprehensive troubleshooting guide covering:
- Build issues (missing dependencies, rpmbuild errors)
- Installation issues (service failures, permission problems)
- Platform-specific issues (Python version, SELinux conflicts)

## References

- RPM Packaging Guide: https://rpm-packaging-guide.github.io/
- Fedora Packaging Guidelines: https://docs.fedoraproject.org/en-US/packaging-guidelines/
- systemd RPM macros: https://docs.fedoraproject.org/en-US/packaging-guidelines/Scriptlets/#_systemd
