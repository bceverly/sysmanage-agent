# SysManage Agent - OpenBSD Port

This directory contains the OpenBSD port infrastructure for sysmanage-agent. OpenBSD uses a **ports system** rather than pre-built binary packages like .deb or .rpm files.

## Quick Overview

**What is a port?**
- A "recipe" (Makefile + metadata) that tells OpenBSD how to build and install software
- Users build from source using the ports system
- Ports are submitted to the official OpenBSD ports tree for community use

**Key Differences from Other Platforms:**
- No pre-built packages to distribute
- Users compile from source via ports framework
- Uses BSD make (not GNU make)
- Services use rc.d scripts (not systemd)
- Installation paths follow OpenBSD conventions

## Directory Structure

```
installer/openbsd/
├── Makefile              # BSD make port Makefile
├── distinfo              # SHA256 checksums (auto-generated)
├── pkg/
│   ├── DESCR            # Package description
│   └── PLIST            # Installed files list
├── files/
│   └── sysmanage_agent.rc  # rc.d service script
├── patches/             # Source patches (if needed)
└── README.md            # This file
```

## Installation Paths (OpenBSD Conventions)

| Component | Path | Notes |
|-----------|------|-------|
| Application | `/usr/local/libexec/sysmanage-agent/` | Main application files |
| Configuration | `/etc/sysmanage-agent.yaml` | Config file |
| Database | `/var/db/sysmanage-agent/` | NOT `/var/lib/` |
| Logs | `/var/log/sysmanage-agent/` | Log directory |
| Service Script | `/etc/rc.d/sysmanage_agent` | Note underscore |
| Documentation | `/usr/local/share/doc/sysmanage-agent/` | README, LICENSE |
| Examples | `/usr/local/share/examples/sysmanage-agent/` | Example configs |

## Testing the Port Locally

### 1. Initial Setup

```bash
# Create mystuff directory for testing (as root)
doas mkdir -p /usr/ports/mystuff/sysutils/sysmanage-agent

# Copy port files to mystuff
doas cp -R /home/bceverly/dev/sysmanage-agent/installer/openbsd/* \
    /usr/ports/mystuff/sysutils/sysmanage-agent/

# Navigate to port directory
cd /usr/ports/mystuff/sysutils/sysmanage-agent
```

### 2. Generate Checksums

```bash
# Generate distinfo checksums (downloads source from GitHub)
doas make makesum

# Verify distinfo was updated
cat distinfo
# Should show SHA256 and SIZE values
```

### 3. Build the Port

```bash
# Fetch dependencies and build
doas make

# This will:
# - Download source tarball from GitHub
# - Verify checksums
# - Extract source
# - Build the application
# - Create package staging area
```

### 4. Generate Package List

```bash
# Auto-generate the PLIST file
doas make update-plist

# Review the generated PLIST
cat pkg/PLIST
```

### 5. Install the Port

```bash
# Install to /usr/local/
doas make install

# Verify installation
ls -la /usr/local/libexec/sysmanage-agent/
ls -la /usr/local/share/examples/sysmanage-agent/
ls -la /etc/rc.d/sysmanage_agent
```

### 6. Test the Service

```bash
# Copy example configuration
doas cp /usr/local/share/examples/sysmanage-agent/sysmanage-agent.yaml \
    /etc/sysmanage-agent.yaml

# Edit configuration
doas vi /etc/sysmanage-agent.yaml

# Enable and start service
doas rcctl enable sysmanage_agent
doas rcctl start sysmanage_agent

# Check service status
doas rcctl check sysmanage_agent
doas rcctl status sysmanage_agent

# View logs
doas tail -f /var/log/sysmanage-agent/sysmanage-agent.log
```

### 7. Clean Up

```bash
# Remove installation (for testing reinstalls)
doas make uninstall

# Clean build artifacts
doas make clean

# Deep clean (removes downloaded files too)
doas make distclean
```

## Service Management

OpenBSD uses `rcctl` for service management (not systemctl):

```bash
# Enable service (start on boot)
doas rcctl enable sysmanage_agent

# Start service
doas rcctl start sysmanage_agent

# Stop service
doas rcctl stop sysmanage_agent

# Restart service
doas rcctl restart sysmanage_agent

# Check if running
doas rcctl check sysmanage_agent

# Disable service (don't start on boot)
doas rcctl disable sysmanage_agent

# View service status
doas rcctl status sysmanage_agent
```

## Updating the Version

When releasing a new version:

1. **Update Makefile version**:
   ```bash
   cd ~/dev/sysmanage-agent/installer/openbsd
   # Edit Makefile and change V = 0.9.4 to new version
   vi Makefile
   ```

2. **Update distinfo**:
   ```bash
   # Copy to ports tree
   doas cp -R * /usr/ports/mystuff/sysutils/sysmanage-agent/

   # Regenerate checksums
   cd /usr/ports/mystuff/sysutils/sysmanage-agent
   doas make makesum
   ```

3. **Copy back updated distinfo**:
   ```bash
   doas cp distinfo ~/dev/sysmanage-agent/installer/openbsd/
   ```

## Submitting to Official OpenBSD Ports

Once the port is tested and working:

### 1. Prepare for Submission

```bash
# Ensure all files are properly formatted
cd /usr/ports/mystuff/sysutils/sysmanage-agent

# Check port with portcheck
doas pkg_add portcheck
portcheck

# Run port-lib checks
port-lib-depends-check
```

### 2. Create a Tarball

```bash
# Create tarball of the port
cd /usr/ports/mystuff/sysutils
tar czf ~/sysmanage-agent-port.tar.gz sysmanage-agent/
```

### 3. Submit to ports@ Mailing List

Send an email to **ports@openbsd.org** with:

**Subject:** `NEW: sysutils/sysmanage-agent`

**Body:**
```
Hi,

I would like to submit a new port for sysmanage-agent, a lightweight
system monitoring agent for remote management.

[Brief description of the software and why it's useful]

Attached is the port tarball. The port has been tested on OpenBSD 7.7
[or your version] and builds/runs successfully.

Thanks,
[Your Name]
```

**Attachment:** The tarball

### 4. Follow Up

- Monitor the mailing list for feedback
- Address any requested changes
- Work with port maintainers to refine the port
- Once approved, it will be committed to the official tree

## Port Maintenance

If you become the maintainer, update the `MAINTAINER` line in Makefile:

```makefile
MAINTAINER =        Your Name <your.email@example.com>
```

As maintainer, you'll be responsible for:
- Updating the port when new versions are released
- Fixing build issues on new OpenBSD releases
- Responding to bug reports

## Troubleshooting

### Build Fails: "Cannot find module X"

Check that all `RUN_DEPENDS` are correct:
```bash
# Search for available Python modules
pkg_info -Q py3-websockets
pkg_info -Q py3-yaml
```

### Service Won't Start

Check logs and rc.d script:
```bash
# View rc.d script
cat /etc/rc.d/sysmanage_agent

# Test manually
doas /usr/local/bin/python3 /usr/local/libexec/sysmanage-agent/main.py

# Check permissions
ls -la /var/db/sysmanage-agent/
ls -la /var/log/sysmanage-agent/
```

### distinfo Checksum Mismatch

Regenerate checksums:
```bash
cd /usr/ports/mystuff/sysutils/sysmanage-agent
doas make distclean
doas make makesum
```

### PLIST Issues

Regenerate package list:
```bash
doas make install
doas make update-plist
```

## Differences from systemd/deb/rpm Installers

| Aspect | Ubuntu/Debian/CentOS/macOS | OpenBSD |
|--------|----------------------------|---------|
| **Package Format** | .deb, .rpm, .pkg (binary) | Port (source-based) |
| **Build System** | dpkg-buildpackage, rpmbuild, pkgbuild | BSD make + ports framework |
| **Distribution** | Pre-built packages | Source + Makefile |
| **Service Management** | systemd, LaunchDaemon | rc.d scripts |
| **Installation Path** | `/opt/` or `/usr/local/` | `/usr/local/` (standard) |
| **Database Path** | `/var/lib/` | `/var/db/` |
| **User Creation** | postinst scripts | PLIST @newuser/@newgroup |
| **Configuration** | Package scripts | @sample in PLIST |

## Reference Documentation

- **OpenBSD Porter's Handbook**: https://www.openbsd.org/faq/ports/
- **OpenBSD Ports Directory**: /usr/ports/infrastructure/
- **rc.d Manual**: `man rc.d` and `man rc.subr`
- **ports Mailing List**: https://www.openbsd.org/mail.html
- **Example Ports**: Browse `/usr/ports/` for examples

## Files Explanation

### Makefile
BSD make file following OpenBSD ports conventions. Defines how to download, build, and install the software.

### distinfo
Contains SHA256 checksums and file sizes for source tarballs. Auto-generated with `make makesum`.

### pkg/DESCR
Human-readable description of the package shown to users.

### pkg/PLIST
List of all files installed by the port. Can be auto-generated with `make update-plist`.

### files/sysmanage_agent.rc
OpenBSD rc.d service script. Manages starting/stopping the daemon.

## Support

For OpenBSD port issues:
- **GitHub Issues**: https://github.com/bceverly/sysmanage-agent/issues
- **OpenBSD Ports List**: ports@openbsd.org (for official port)

---

**Last Updated:** October 16, 2025
**OpenBSD Version:** 7.7
**Port Version:** 0.9.4
