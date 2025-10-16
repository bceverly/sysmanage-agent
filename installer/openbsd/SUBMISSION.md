# Submitting SysManage Agent to Official OpenBSD Ports

This document outlines the complete process for submitting the sysmanage-agent port to the official OpenBSD ports tree.

## Overview

The current port is configured for **testing only** and runs as root. For official submission, the port must:
- Register the `_sysmanage` user and group in the OpenBSD user database
- Enable proper user/group ownership in PLIST
- Re-enable daemon_user in the rc.d script
- Pass all portcheck validations
- Follow OpenBSD ports conventions

## Prerequisites

Before starting the submission process:

1. **Test thoroughly on OpenBSD -current**
   - The port must work on the latest development version
   - Test on both amd64 and other architectures if possible

2. **Ensure clean git state**
   - All changes should be committed
   - Latest version should be tagged (e.g., `v0.9.5`)

3. **Have an OpenBSD account for mailing list**
   - Subscribe to `ports@openbsd.org`
   - Read recent submissions to understand expectations

## Step 1: Register User and Group

The `_sysmanage` user and group must be registered in the official OpenBSD user database.

### 1.1 Check Available UIDs/GIDs

```bash
# View the user.list to find available IDs
less /usr/ports/infrastructure/db/user.list

# Look for gaps in the 800-900 range (system users)
# Current placeholder uses 827, verify it's available
```

### 1.2 Request UID/GID Assignment

**Option A: Self-assign (if submitting the port)**

When submitting, propose a UID/GID in your submission email:
```
I would like to register:
_sysmanage:_sysmanage:827:827
```

**Option B: Wait for port maintainer assignment**

The OpenBSD ports team will assign an appropriate UID/GID when committing.

### 1.3 Document in Submission

Note in your submission email:
```
This port requires a system user and group:
- User: _sysmanage
- Group: _sysmanage
- Proposed UID/GID: 827 (or assigned by ports team)
- Purpose: Run the sysmanage-agent daemon with minimal privileges
```

## Step 2: Prepare Port for Submission

### 2.1 Update PLIST - Enable User/Group Directives

Edit `installer/openbsd/pkg/PLIST`:

**Change FROM:**
```
@comment For official port submission, register these in /usr/ports/infrastructure/db/user.list
@comment @newgroup _sysmanage:827
@comment @newuser _sysmanage:827:_sysmanage::SysManage Agent:/nonexistent:/sbin/nologin
```

**Change TO:**
```
@comment User and group for daemon (registered in /usr/ports/infrastructure/db/user.list)
@newgroup _sysmanage:827
@newuser _sysmanage:827:_sysmanage::SysManage Agent:/nonexistent:/sbin/nologin
```

**Also enable ownership directives:**

**Change FROM:**
```
@comment Data directories (ownership disabled for testing without registered user)
@comment @mode 0750
@comment @owner _sysmanage
@comment @group _sysmanage
@sample /var/db/sysmanage-agent/
@sample /var/log/sysmanage-agent/
@comment @mode
@comment @owner
@comment @group
```

**Change TO:**
```
@comment Data directories with proper ownership
@mode 0750
@owner _sysmanage
@group _sysmanage
@sample /var/db/sysmanage-agent/
@sample /var/log/sysmanage-agent/
@mode
@owner
@group
```

### 2.2 Update rc.d Script - Enable daemon_user

Edit `installer/openbsd/files/sysmanage_agent.rc`:

**Change FROM:**
```bash
daemon="/usr/local/bin/python3 /usr/local/libexec/sysmanage-agent/main.py"
#daemon_user="_sysmanage"
daemon_flags=""
```

**Change TO:**
```bash
daemon="/usr/local/bin/python3 /usr/local/libexec/sysmanage-agent/main.py"
daemon_user="_sysmanage"
daemon_flags=""
```

**Also restore ownership in rc_pre():**

**Change FROM:**
```bash
rc_pre() {
	# Ensure required directories exist with correct permissions
	# Running as root for testing (user _sysmanage not registered)
	install -d -m 0750 ${SYSMANAGE_DB_DIR}
	install -d -m 0750 ${SYSMANAGE_LOG_DIR}
```

**Change TO:**
```bash
rc_pre() {
	# Ensure required directories exist with correct permissions
	install -d -o ${daemon_user} -g ${daemon_user} -m 0750 ${SYSMANAGE_DB_DIR}
	install -d -o ${daemon_user} -g ${daemon_user} -m 0750 ${SYSMANAGE_LOG_DIR}
```

### 2.3 Update Makefile - Set Maintainer Info

Edit `installer/openbsd/Makefile`:

**Change FROM:**
```makefile
MAINTAINER =		Your Name <your.email@example.com>
```

**Change TO:**
```makefile
MAINTAINER =		Your Name <your@email.com>
```

Use your real name and email address.

### 2.4 Update Makefile - Remove Testing Comment

**Change FROM:**
```makefile
GH_TAGNAME =		v0.0.0  # Auto-updated by make installer
REVISION =		0
```

**Change TO:**
```makefile
GH_TAGNAME =		v0.9.5
REVISION =		0
```

Use the actual version number (will be updated by `make installer` anyway).

## Step 3: Test with User Registration

Before submitting, test with the user/group created manually:

```bash
# Create test user and group (as root)
doas groupadd -g 827 _sysmanage
doas useradd -u 827 -g _sysmanage -c "SysManage Agent" \
    -d /nonexistent -s /sbin/nologin _sysmanage

# Copy updated port files
cd ~/dev/sysmanage-agent
make installer

# Test installation
cd /usr/ports/sysutils/sysmanage-agent
doas make clean
doas make makesum
doas make package
doas make install

# Test service runs as _sysmanage
doas rcctl start sysmanage_agent
ps aux | grep sysmanage
# Should show process running as _sysmanage user

# Check logs are writable by _sysmanage
ls -la /var/db/sysmanage-agent/
ls -la /var/log/sysmanage-agent/
```

## Step 4: Run Port Quality Checks

### 4.1 Install Port Checking Tools

```bash
doas pkg_add portcheck port-lib-depends-check
```

### 4.2 Run portcheck

```bash
cd /usr/ports/sysutils/sysmanage-agent
portcheck

# Fix any warnings or errors
# Common issues:
# - Incorrect whitespace in Makefile (use tabs not spaces)
# - Missing $OpenBSD$ tags
# - Incorrect variable ordering
```

### 4.3 Check Library Dependencies

```bash
port-lib-depends-check

# This verifies RUN_DEPENDS are correct
# Fix any missing or incorrect dependencies
```

### 4.4 Test Port Removal

```bash
# Ensure port uninstalls cleanly
doas make uninstall

# Verify no files left behind
ls /usr/local/libexec/sysmanage-agent/  # Should not exist
ls /etc/rc.d/sysmanage_agent            # Should not exist
```

## Step 5: Create Submission Package

### 5.1 Create Clean Port Directory

```bash
cd /usr/ports/sysutils
tar czf ~/sysmanage-agent-port.tar.gz sysmanage-agent/

# Verify tarball contents
tar tzf ~/sysmanage-agent-port.tar.gz
```

### 5.2 Test from Tarball

```bash
# Extract to a test location
cd /tmp
tar xzf ~/sysmanage-agent-port.tar.gz
cd sysmanage-agent

# Verify it builds
make makesum
make
make fake
make package
```

## Step 6: Submit to ports@openbsd.org

### 6.1 Prepare Submission Email

**Subject:** `NEW: sysutils/sysmanage-agent`

**Body:**

```
Hi,

I would like to submit a new port for sysmanage-agent, a lightweight
cross-platform system monitoring agent that connects to a central
SysManage server via secure WebSocket connections.

The agent provides:
- Real-time system monitoring (CPU, memory, disk, network)
- Remote command execution with security controls
- Package management capabilities
- Automatic health monitoring and reporting
- Multi-language support (14 languages)
- Minimal resource footprint

The agent is written in Python 3 and uses only pure-Python dependencies
available in OpenBSD ports (websockets, yaml, aiohttp, cryptography,
sqlalchemy, alembic).

The port has been tested on OpenBSD 7.7/amd64 and builds/runs successfully.

This port requires registration of:
- User: _sysmanage:827:_sysmanage
- Group: _sysmanage:827
- Purpose: Run daemon with minimal privileges

The agent's main repository is at:
https://github.com/bceverly/sysmanage-agent

Upstream website:
https://sysmanage.org

License: AGPLv3

Attached is the port tarball.

Thanks,
[Your Name]
```

### 6.2 Send Email

```bash
# Using mail(1)
mail -s "NEW: sysutils/sysmanage-agent" -a ~/sysmanage-agent-port.tar.gz \
    ports@openbsd.org < submission-email.txt
```

## Step 7: Respond to Feedback

### 7.1 Monitor Mailing List

- Check `ports@openbsd.org` archives: https://marc.info/?l=openbsd-ports
- Respond promptly to reviewer feedback
- Be prepared to make changes

### 7.2 Common Feedback Topics

Expect reviewers to ask about:

1. **UID/GID Assignment**
   - May suggest different UID/GID
   - May require coordination with other pending submissions

2. **Dependencies**
   - Verify all dependencies are correct
   - Check for redundant dependencies

3. **Makefile Style**
   - Variable ordering
   - Whitespace (tabs vs spaces)
   - Comments

4. **PLIST Completeness**
   - All files must be listed
   - Verify with `make update-plist`

5. **Security Concerns**
   - Why does it need network access?
   - What privilege level does it need?
   - How is authentication handled?

6. **Testing**
   - Works on multiple architectures?
   - Tested on -current?

### 7.3 Making Changes

When reviewers request changes:

```bash
# Make changes in your local port directory
cd ~/dev/sysmanage-agent/installer/openbsd
vi Makefile  # or PLIST, or files/sysmanage_agent.rc

# Test changes
make installer
cd /usr/ports/sysutils/sysmanage-agent
doas make clean
doas make package
doas make install

# Create new tarball
cd /usr/ports/sysutils
tar czf ~/sysmanage-agent-port-v2.tar.gz sysmanage-agent/

# Reply to the mailing list with updated tarball
mail -s "Re: NEW: sysutils/sysmanage-agent (updated)" \
    -a ~/sysmanage-agent-port-v2.tar.gz \
    ports@openbsd.org < response-email.txt
```

## Step 8: Post-Acceptance

Once the port is committed to the official tree:

### 8.1 Update Your Development Workflow

```bash
# Remove your mystuff version
doas rm -rf /usr/ports/mystuff/sysutils/sysmanage-agent

# Update ports tree to get official version
cd /usr/ports
cvs update -dP

# Your port is now at:
# /usr/ports/sysutils/sysmanage-agent
```

### 8.2 Maintain the Port

As maintainer, you're responsible for:

1. **Version Updates**
   - When you release a new version, update the port
   - Email ports@ with UPDATE: sysutils/sysmanage-agent

2. **Bug Fixes**
   - Respond to bug reports from users
   - Fix build issues on new OpenBSD releases

3. **Security Updates**
   - Promptly address any security issues
   - Coordinate with security@openbsd.org if needed

4. **Dependency Updates**
   - Watch for dependency changes
   - Update port if dependencies change

### 8.3 Updating Process

For future updates:

```bash
# Update version in your local copy
cd ~/dev/sysmanage-agent
git tag v0.9.6
make installer

# Test the update
cd /usr/ports/sysutils/sysmanage-agent
doas make makesum
doas make clean
doas make package
doas make install

# Create diff against CVS
cvs diff -uN > ~/sysmanage-agent-update.diff

# Submit update
mail -s "UPDATE: sysutils/sysmanage-agent to 0.9.6" \
    -a ~/sysmanage-agent-update.diff \
    ports@openbsd.org < update-email.txt
```

## Troubleshooting Submission Issues

### User/Group Already Taken

If UID/GID 827 is already assigned:

```bash
# Check what's available
grep "^[0-9]" /usr/ports/infrastructure/db/user.list | awk -F: '{print $3}' | sort -n | tail -20

# Use next available ID (e.g., 828)
# Update PLIST accordingly
```

### Port Name Conflict

If `sysmanage-agent` conflicts with another port:

- May need to rename (e.g., `py-sysmanage-agent`)
- Discuss with ports@ for guidance

### License Issues

If reviewers question AGPLv3:

- OpenBSD accepts AGPLv3
- Ensure LICENSE file is included
- Verify no license conflicts with dependencies

### Architecture Support

If port fails on non-amd64 architectures:

- Specify `ONLY_FOR_ARCHS = amd64` in Makefile
- Or fix architecture-specific issues
- Note architecture limitations in submission

## Resources

- **Porter's Handbook**: https://www.openbsd.org/faq/ports/
- **Style Guide**: See existing ports in `/usr/ports/`
- **Mailing List Archives**: https://marc.info/?l=openbsd-ports
- **User Database**: `/usr/ports/infrastructure/db/user.list`
- **CVS Guide**: https://www.openbsd.org/anoncvs.html

## Example Successful Submissions

Study these recent Python daemon submissions:

```bash
# View similar ports
ls -la /usr/ports/sysutils/ansible/
ls -la /usr/ports/net/py-websockets/
ls -la /usr/ports/databases/py-sqlalchemy/
```

## Timeline Expectations

- **Initial Review**: 1-7 days
- **Follow-up Discussion**: Varies based on complexity
- **Commit**: After reviewer approval and testing
- **Total Time**: 1-4 weeks typical

Be patient and responsive. The OpenBSD ports team is volunteer-based.

---

**Last Updated:** October 16, 2025
**For Questions:** Contact ports@openbsd.org
