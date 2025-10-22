Name:           sysmanage-agent
Version:        0.1.0
Release:        0
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
# We manually specify python311 in Requires
%global __requires_exclude ^python\\(abi\\)
%global __provides_exclude_from ^%{_libdir}/sysmanage-agent/venv/.*$

BuildRequires:  python311-devel
BuildRequires:  python311-pip
BuildRequires:  python3-setuptools
BuildRequires:  systemd-rpm-macros

Requires:       python311
Requires:       python311-pip
Requires:       systemd
Requires:       sudo
Requires(pre):  shadow
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
# Extract vendor dependencies to current directory
tar xzf %{_sourcedir}/%{name}-vendor-%{version}.tar.gz

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

# Copy vendor directory for offline installation
cp -r vendor %{buildroot}/opt/sysmanage-agent/

# Create virtualenv and install Python dependencies from vendor directory
# Use python311 explicitly (not python3 which may be 3.6 on older systems)
python3.11 -m venv %{buildroot}/opt/sysmanage-agent/.venv
%{buildroot}/opt/sysmanage-agent/.venv/bin/pip install --upgrade pip --no-index --find-links=%{_builddir}/%{name}-%{version}/vendor
%{buildroot}/opt/sysmanage-agent/.venv/bin/pip install -r requirements-prod.txt --no-index --find-links=%{_builddir}/%{name}-%{version}/vendor

# Fix virtualenv paths to use final installation directory instead of buildroot
sed -i 's|%{buildroot}||g' %{buildroot}/opt/sysmanage-agent/.venv/pyvenv.cfg
# Also fix any hardcoded paths in activation scripts
find %{buildroot}/opt/sysmanage-agent/.venv/bin -type f -exec sed -i 's|%{buildroot}||g' {} \;

# Install example config
install -m 644 installer/opensuse/sysmanage-agent.yaml.example %{buildroot}/etc/sysmanage-agent/

# Install systemd service
install -d %{buildroot}/usr/lib/systemd/system
install -m 644 installer/opensuse/sysmanage-agent.service %{buildroot}/usr/lib/systemd/system/

# Install sudoers file
install -d %{buildroot}/etc/sudoers.d
install -m 440 installer/opensuse/sysmanage-agent.sudoers %{buildroot}/etc/sudoers.d/sysmanage-agent

%pre
# Create sysmanage-agent user if it doesn't exist (openSUSE uses groupadd/useradd)
%service_add_pre sysmanage-agent.service
if ! getent group sysmanage-agent >/dev/null; then
    groupadd --system sysmanage-agent
fi
if ! getent passwd sysmanage-agent >/dev/null; then
    useradd --system --gid sysmanage-agent --home-dir /nonexistent --no-create-home \
        --shell /sbin/nologin --comment "SysManage Agent" sysmanage-agent
fi

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
python3.11 -m venv .venv

# Check if we have a vendor directory from the RPM (for OBS builds)
if [ -d vendor ]; then
  .venv/bin/pip install --quiet --upgrade pip --no-index --find-links=vendor
  .venv/bin/pip install --quiet -r requirements-prod.txt --no-index --find-links=vendor
else
  # Fallback to network install (for direct RPM installs outside OBS)
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

# Enable and start the service using openSUSE macros
%service_add_post sysmanage-agent.service

# For third-party packages, explicitly enable the service
if [ -x /usr/bin/systemctl ]; then
    systemctl daemon-reload
    systemctl enable sysmanage-agent.service

    # Start on fresh install only
    if [ $1 -eq 1 ]; then
        systemctl start sysmanage-agent.service
    fi
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
%service_del_preun sysmanage-agent.service

%postun
%service_del_postun sysmanage-agent.service

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
    if getent group sysmanage-agent >/dev/null; then
        groupdel sysmanage-agent >/dev/null 2>&1 || true
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
%dir /etc/sudoers.d
%config(noreplace) /etc/sudoers.d/sysmanage-agent

%changelog
* Mon Oct 14 2024 Bryan Everly <bryan@theeverlys.com> - 0.1.0-0
- Initial RPM release for openSUSE
- Support for openSUSE Leap, Tumbleweed, and SLES
