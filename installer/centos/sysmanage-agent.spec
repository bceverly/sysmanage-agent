Name:           sysmanage-agent
Version:        0.1.0
Release:        1%{?dist}
Summary:        System management agent for SysManage

License:        Dual (Open Source / Commercial)
URL:            https://github.com/bceverly/sysmanage-agent
Source0:        %{name}-%{version}.tar.gz
Source1:        %{name}-vendor-%{version}.tar.gz

# Not noarch because virtualenv contains compiled extensions
# Disable debug package generation (no debug symbols in Python bytecode)
%global debug_package %{nil}
%global _enable_debug_package 0
%global __os_install_post /usr/lib/rpm/brp-compress %{nil}

# Disable automatic Python dependency generation
# We manually specify python3 version in Requires (3.11 on EL8, 3.9+ elsewhere)
%global __requires_exclude ^python\\(abi\\)
%global __provides_exclude_from ^%{_libdir}/sysmanage-agent/venv/.*$

# EL8 ships Python 3.6 as default; use the python3.11 AppStream packages instead
%if 0%{?el8}
%global python3_bin python3.11
%global python3_pkg python3.11
%global python3_devel python3.11-devel
%global python3_pip python3.11-pip
%global python3_setuptools python3.11-setuptools
%else
%global python3_bin python3
%global python3_pkg python3 >= 3.9
%global python3_devel python3-devel >= 3.9
%global python3_pip python3-pip
%global python3_setuptools python3-setuptools
%endif

BuildRequires:  %{python3_devel}
BuildRequires:  %{python3_pip}
BuildRequires:  %{python3_setuptools}
BuildRequires:  systemd-rpm-macros

Requires:       %{python3_pkg}
Requires:       %{python3_pip}
Requires:       systemd
Requires:       sudo
Requires(pre):  shadow-utils
Requires(post): systemd
Requires(preun): systemd
Requires(postun): systemd

%description
The SysManage agent provides comprehensive system management capabilities
including:
 * Package inventory and updates
 * System monitoring and metrics
 * Security policy enforcement
 * Certificate management
 * Firewall configuration
 * Remote command execution
 * Integration with SysManage server

This agent runs as a system service and communicates securely with the
SysManage server to provide centralized management of Linux systems.

%prep
%setup -q
# Extract vendor tarball for offline installation (if present in COPR builds)
# Local Makefile builds don't provide vendor tarball - will use network install in %post
if [ -f %{SOURCE1} ]; then
    tar xzf %{SOURCE1}
fi

%build
# No build step needed - Python application

%install
# Create directory structure
install -d %{buildroot}/opt/sysmanage-agent
install -d %{buildroot}/etc/sysmanage-agent
install -d %{buildroot}/var/lib/sysmanage-agent
install -d %{buildroot}/var/log/sysmanage-agent

# Copy application files
cp -r src %{buildroot}/opt/sysmanage-agent/
install -m 644 main.py %{buildroot}/opt/sysmanage-agent/
install -m 644 alembic.ini %{buildroot}/opt/sysmanage-agent/
install -m 644 requirements-prod.txt %{buildroot}/opt/sysmanage-agent/

# Copy vendor directory for offline installation (if present)
if [ -d vendor ]; then
    cp -r vendor %{buildroot}/opt/sysmanage-agent/
fi

# Create virtualenv and install Python dependencies
# If vendor directory exists (COPR builds), use offline installation
# If not (local Makefile builds), skip pip install here - will happen in %post with network
%{python3_bin} -m venv %{buildroot}/opt/sysmanage-agent/.venv
if [ -d %{_builddir}/%{name}-%{version}/vendor ]; then
    %{buildroot}/opt/sysmanage-agent/.venv/bin/pip install --upgrade pip --no-index --find-links=%{_builddir}/%{name}-%{version}/vendor
    %{buildroot}/opt/sysmanage-agent/.venv/bin/pip install -r requirements-prod.txt --no-index --find-links=%{_builddir}/%{name}-%{version}/vendor
fi

# Fix virtualenv paths to use final installation directory instead of buildroot
sed -i 's|%{buildroot}||g' %{buildroot}/opt/sysmanage-agent/.venv/pyvenv.cfg
# Also fix any hardcoded paths in activation scripts
find %{buildroot}/opt/sysmanage-agent/.venv/bin -type f -exec sed -i 's|%{buildroot}||g' {} \;

# Install example config
install -m 644 installer/centos/sysmanage-agent.yaml.example %{buildroot}/etc/sysmanage-agent/

# Install systemd service
install -d %{buildroot}/usr/lib/systemd/system
install -m 644 installer/centos/sysmanage-agent.service %{buildroot}/usr/lib/systemd/system/

# Install sudoers file
# Note: Do NOT create /etc/sudoers.d directory - it's owned by the sudo package
# The directory will exist because sudo is a Requires dependency
install -m 440 -D installer/centos/sysmanage-agent.sudoers %{buildroot}/etc/sudoers.d/sysmanage-agent

# Install SBOM (Software Bill of Materials)
install -d %{buildroot}/usr/share/doc/sysmanage-agent/sbom
if [ -f sbom/sysmanage-agent-sbom.json ]; then
    install -m 644 sbom/sysmanage-agent-sbom.json %{buildroot}/usr/share/doc/sysmanage-agent/sbom/
fi

%pre
# Create sysmanage-agent user if it doesn't exist
if ! getent passwd sysmanage-agent >/dev/null; then
    useradd --system --user-group --home-dir /nonexistent --no-create-home \
        --shell /sbin/nologin --comment "SysManage Agent" sysmanage-agent
fi
exit 0

%post
# Set ownership of application directories
chown -R sysmanage-agent:sysmanage-agent /opt/sysmanage-agent
chown -R sysmanage-agent:sysmanage-agent /var/lib/sysmanage-agent
chown -R sysmanage-agent:sysmanage-agent /var/log/sysmanage-agent
chown -R sysmanage-agent:sysmanage-agent /etc/sysmanage-agent

# Set proper permissions
chmod 755 /opt/sysmanage-agent
chmod 755 /var/lib/sysmanage-agent
chmod 755 /var/log/sysmanage-agent
chmod 750 /etc/sysmanage-agent

# Fix virtualenv to work with system Python
# Recreate the venv using the system's Python to fix all symlinks and paths
cd /opt/sysmanage-agent
rm -rf .venv
%{python3_bin} -m venv .venv

# Check if we have a vendor directory from the RPM (for COPR builds)
if [ -d vendor ]; then
  .venv/bin/pip install --quiet --upgrade pip --no-index --find-links=vendor
  .venv/bin/pip install --quiet -r requirements-prod.txt --no-index --find-links=vendor
else
  # Fallback to network install (for direct RPM installs outside COPR)
  .venv/bin/pip install --quiet --upgrade pip
  .venv/bin/pip install --quiet -r requirements-prod.txt
fi
cd -

# Create config file if it doesn't exist
if [ ! -f /etc/sysmanage-agent.yaml ]; then
    cp /etc/sysmanage-agent/sysmanage-agent.yaml.example /etc/sysmanage-agent.yaml
    chown sysmanage-agent:sysmanage-agent /etc/sysmanage-agent.yaml
    chmod 640 /etc/sysmanage-agent.yaml
    echo "Please edit /etc/sysmanage-agent.yaml to configure the agent"
fi

# Enable and start the service
%systemd_post sysmanage-agent.service

# Explicitly start the service on fresh install
if [ $1 -eq 1 ]; then
    # Fresh install (not an upgrade)
    systemctl start sysmanage-agent.service >/dev/null 2>&1 || true
fi

echo ""
echo "=========================================="
echo "SysManage Agent installation complete!"
echo "=========================================="
echo ""
echo "Next steps:"
echo "  1. Edit /etc/sysmanage-agent.yaml to configure server connection"
echo "  2. Restart the service: sudo systemctl restart sysmanage-agent"
echo "  3. Check status: sudo systemctl status sysmanage-agent"
echo ""
echo "Log files are located in: /var/log/sysmanage-agent/"
echo ""

%preun
%systemd_preun sysmanage-agent.service

%postun
%systemd_postun_with_restart sysmanage-agent.service

# Clean up on purge (erase)
if [ $1 -eq 0 ]; then
    # Remove log files
    rm -rf /var/log/sysmanage-agent || true

    # Remove configuration directory
    rm -rf /etc/sysmanage-agent || true

    # Remove database and runtime data
    rm -rf /var/lib/sysmanage-agent || true

    # Remove user and group
    if getent passwd sysmanage-agent >/dev/null; then
        userdel sysmanage-agent >/dev/null 2>&1 || true
    fi
fi

%files
%license LICENSE
%doc README.md
/opt/sysmanage-agent/
/etc/sysmanage-agent/
%dir /var/lib/sysmanage-agent
%dir /var/log/sysmanage-agent
/usr/lib/systemd/system/sysmanage-agent.service
%config(noreplace) /etc/sudoers.d/sysmanage-agent
%doc /usr/share/doc/sysmanage-agent/sbom/

%changelog
* Mon Oct 14 2024 Bryan Everly <bryan@theeverlys.com> - 0.1.0-1
- Initial RPM release
- Support for CentOS, RHEL, Fedora, Rocky Linux, AlmaLinux
