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

# Handle different Python package names across distributions
# openSUSE uses python311-* packages
# Fedora, RHEL, CentOS, Amazon Linux use python3-* packages
%if 0%{?suse_version}
BuildRequires:  python311-devel
BuildRequires:  python311-pip
%else
BuildRequires:  python3-devel
BuildRequires:  python3-pip
%endif

BuildRequires:  python3-setuptools
BuildRequires:  systemd-rpm-macros

%if 0%{?suse_version}
BuildRequires:  fdupes
%endif

%if 0%{?suse_version}
Requires:       python311
Requires:       python311-pip
%else
Requires:       python3
Requires:       python3-pip
%endif

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
# Use python3.11 for openSUSE, python3 for Fedora/RHEL/Amazon Linux
%if 0%{?suse_version}
python3.11 -m venv %{buildroot}/opt/sysmanage-agent/.venv
%else
python3 -m venv %{buildroot}/opt/sysmanage-agent/.venv
%endif
%{buildroot}/opt/sysmanage-agent/.venv/bin/pip install --upgrade pip --no-index --find-links=%{_builddir}/%{name}-%{version}/vendor
%{buildroot}/opt/sysmanage-agent/.venv/bin/pip install -r requirements-prod.txt --no-index --find-links=%{_builddir}/%{name}-%{version}/vendor

# Fix virtualenv paths to use final installation directory instead of buildroot
sed -i 's|%{buildroot}||g' %{buildroot}/opt/sysmanage-agent/.venv/pyvenv.cfg
# Also fix any hardcoded paths in activation scripts
find %{buildroot}/opt/sysmanage-agent/.venv/bin -type f -exec sed -i 's|%{buildroot}||g' {} \;

# Remove development files (headers, source files) to reduce package size and avoid rpmlint errors
find %{buildroot}/opt/sysmanage-agent/.venv -type f \( -name "*.h" -o -name "*.c" -o -name "*.cpp" -o -name "*.hpp" \) -delete

# Deduplicate files to save space
# Use %fdupes macro on OBS (openSUSE), use fdupes command elsewhere
%if 0%{?suse_version}
%fdupes %{buildroot}/opt/sysmanage-agent/.venv
%else
# For non-openSUSE builds, use fdupes if available, otherwise skip
if command -v fdupes >/dev/null 2>&1; then
    fdupes -r -1 -N %{buildroot}/opt/sysmanage-agent/.venv | while read line; do
        first=true
        for file in $line; do
            if $first; then
                first=false
            else
                rm -f "$file"
                ln "$line" "$file"
            fi
        done
    done
fi
%endif

# Install example config
install -m 644 installer/opensuse/sysmanage-agent.yaml.example %{buildroot}/etc/sysmanage-agent/

# Install systemd service
install -d %{buildroot}/usr/lib/systemd/system
install -m 644 installer/opensuse/sysmanage-agent.service %{buildroot}/usr/lib/systemd/system/

# Install sudoers file
# Note: Do NOT create /etc/sudoers.d directory - it's owned by the sudo package
# The directory will exist because sudo is a Requires dependency
install -m 440 -D installer/opensuse/sysmanage-agent.sudoers %{buildroot}/etc/sudoers.d/sysmanage-agent

# Install SBOM (Software Bill of Materials)
install -d %{buildroot}/usr/share/doc/sysmanage-agent/sbom
if [ -f sbom/sysmanage-agent-sbom.json ]; then
    install -m 644 sbom/sysmanage-agent-sbom.json %{buildroot}/usr/share/doc/sysmanage-agent/sbom/
fi

%pre
# Create sysmanage-agent user if it doesn't exist
%if 0%{?suse_version}
%service_add_pre sysmanage-agent.service
%else
%systemd_pre sysmanage-agent.service
%endif
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
%if 0%{?suse_version}
python3.11 -m venv .venv
%else
python3 -m venv .venv
%endif

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

# Enable and start the service
%if 0%{?suse_version}
%service_add_post sysmanage-agent.service
%else
%systemd_post sysmanage-agent.service
# Explicitly enable the service on RHEL/Fedora/CentOS
systemctl enable sysmanage-agent.service >/dev/null 2>&1 || :
%endif

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
%if 0%{?suse_version}
%service_del_preun sysmanage-agent.service
%else
%systemd_preun sysmanage-agent.service
%endif

%postun
%if 0%{?suse_version}
%service_del_postun sysmanage-agent.service
%else
%systemd_postun_with_restart sysmanage-agent.service
%endif

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
# Note: Do NOT declare %dir /etc/sudoers.d - it's owned by the sudo package
%config(noreplace) /etc/sudoers.d/sysmanage-agent
%dir /usr/share/doc/sysmanage-agent
%doc /usr/share/doc/sysmanage-agent/sbom/

%changelog
* Mon Oct 14 2024 Bryan Everly <bryan@theeverlys.com> - 0.1.0-0
- Initial RPM release for openSUSE
- Support for openSUSE Leap, Tumbleweed, and SLES
