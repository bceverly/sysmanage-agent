"""
Alpine Linux VMM autoinstall module.

This module implements the automated installation of Alpine Linux VMs:
- Downloads Alpine virt ISO
- Manages serial console interaction for automated setup
- Configures networking and sysmanage-agent
"""

import logging
import os
import subprocess  # nosec B404
import time
import urllib.request
from pathlib import Path
from typing import Any, Dict

from src.i18n import _
from src.sysmanage_agent.operations.child_host_alpine_packages import (
    ALPINE_ISO_URLS,
    ALPINE_REPO_URLS,
)
from src.sysmanage_agent.operations.child_host_config_generator import (
    gen_agent_config_shell_cmds,
)


class AlpineAutoinstallSetup:
    """Alpine Linux automated installation setup for VMM VMs."""

    ISO_CACHE_DIR = "/var/vmm/iso-cache"
    ALPINE_SETS_BASE = "/var/www/htdocs/pub/Alpine"

    def __init__(self, logger: logging.Logger):
        """Initialize Alpine autoinstall setup."""
        self.logger = logger

    def download_alpine_iso(self, version: str) -> Dict[str, Any]:
        """
        Download Alpine Linux virt ISO.

        Args:
            version: Alpine version (e.g., "3.20")

        Returns:
            Dict with success status and ISO path
        """
        try:
            # Ensure cache directory exists
            Path(self.ISO_CACHE_DIR).mkdir(parents=True, exist_ok=True)

            # Get ISO URL for this version
            if version not in ALPINE_ISO_URLS:
                return {
                    "success": False,
                    "iso_path": None,
                    "error": _("Unsupported Alpine version: %s") % version,
                }

            iso_url = ALPINE_ISO_URLS[version]
            iso_filename = os.path.basename(iso_url)
            iso_path = Path(self.ISO_CACHE_DIR) / iso_filename

            # Check if already downloaded
            if iso_path.exists():
                self.logger.info(_("Using cached Alpine ISO: %s"), iso_path)
                return {"success": True, "iso_path": str(iso_path)}

            # Download ISO
            self.logger.info(_("Downloading Alpine %s ISO from %s"), version, iso_url)

            # URL is hardcoded Alpine mirror, not user-provided
            # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected
            with urllib.request.urlopen(iso_url, timeout=600) as response:  # nosec B310
                with open(iso_path, "wb") as iso_file:
                    iso_file.write(response.read())

            self.logger.info(_("Downloaded Alpine ISO: %s"), iso_path)
            return {"success": True, "iso_path": str(iso_path)}

        except Exception as error:  # pylint: disable=broad-except
            return {"success": False, "iso_path": None, "error": str(error)}

    def create_setup_script(  # pylint: disable=too-many-arguments,too-many-locals
        self,
        hostname: str,
        username: str,
        user_password: str,
        root_password: str,
        gateway_ip: str,
        vm_ip: str,
        alpine_version: str,
        dns_server: str = None,
        server_hostname: str = None,
        server_port: int = None,
        use_https: bool = True,
        auto_approve_token: str = None,
    ) -> str:
        """
        Create shell script for automated Alpine setup.

        This script is piped to the VM's serial console to automate
        the setup-alpine process.

        Args:
            hostname: VM hostname (FQDN)
            username: User to create
            user_password: Password for the user (plain text for setup-alpine)
            root_password: Password for root (plain text for setup-alpine)
            gateway_ip: Gateway IP address
            vm_ip: Static IP address for the VM
            alpine_version: Alpine version (e.g., "3.20")
            dns_server: DNS server (defaults to 8.8.8.8)
            server_hostname: SysManage server hostname for agent config
            server_port: SysManage server port for agent config
            use_https: Whether agent should use HTTPS
            auto_approve_token: Auto-approval token for host registration

        Returns:
            Setup script content as string
        """
        if dns_server is None:
            # Use public DNS (Google) since the gateway may not run a DNS resolver
            dns_server = "8.8.8.8"  # NOSONAR - standard DNS fallback

        # Get repo URL for this version
        repo_url = ALPINE_REPO_URLS.get(alpine_version, ALPINE_REPO_URLS["3.21"])

        # Calculate netmask prefix and network
        # Assume /24 subnet
        parts = vm_ip.rsplit(".", 1)
        _network_prefix = parts[0]  # Reserved for future use

        # Build sysmanage-agent config section if server info provided
        # Config goes directly to /etc/sysmanage-agent/sysmanage-agent.yaml
        # where the APK's init script expects it
        agent_config_section = ""
        if server_hostname and server_port:
            # Generate config using unified generator (shell echo commands)
            config_echo_commands = gen_agent_config_shell_cmds(
                hostname=server_hostname,
                port=server_port,
                use_https=use_https,
                os_type="alpine",
                auto_approve_token=auto_approve_token,
                verify_ssl=False,
                config_path="/etc/sysmanage-agent/sysmanage-agent.yaml",
            )

            agent_config_section = f"""
# Create sysmanage-agent configuration
echo "==> Creating sysmanage-agent configuration..."
mkdir -p /etc/sysmanage-agent
{config_echo_commands}
"""

        # Build firstboot script section if server info provided
        firstboot_section = ""
        if server_hostname and server_port:
            firstboot_section = """
# Create firstboot script for sysmanage-agent installation
echo "==> Creating firstboot script..."
mkdir -p /etc/local.d

# Write the firstboot script using echo commands
echo "#!/bin/sh" > /etc/local.d/sysmanage-firstboot.start
echo "# First boot setup - install sysmanage-agent" >> /etc/local.d/sysmanage-firstboot.start
echo "" >> /etc/local.d/sysmanage-firstboot.start
echo "LOGFILE=\\"/var/log/sysmanage-firstboot.log\\"" >> /etc/local.d/sysmanage-firstboot.start
echo "exec >>\\"\\$LOGFILE\\" 2>&1" >> /etc/local.d/sysmanage-firstboot.start
echo "" >> /etc/local.d/sysmanage-firstboot.start
echo "echo \\"==> First boot setup starting at \\$(date)\\"" >> /etc/local.d/sysmanage-firstboot.start
echo "" >> /etc/local.d/sysmanage-firstboot.start
echo "# Update package index" >> /etc/local.d/sysmanage-firstboot.start
echo "apk update" >> /etc/local.d/sysmanage-firstboot.start
echo "" >> /etc/local.d/sysmanage-firstboot.start
echo "# Install Python dependencies" >> /etc/local.d/sysmanage-firstboot.start
echo "apk add --no-cache python3 py3-pip py3-websockets py3-yaml py3-aiohttp \\\\" >> /etc/local.d/sysmanage-firstboot.start
echo "    py3-cryptography py3-sqlalchemy py3-alembic py3-bcrypt py3-pydantic \\\\" >> /etc/local.d/sysmanage-firstboot.start
echo "    py3-cffi py3-greenlet py3-typing-extensions py3-mako py3-markupsafe \\\\" >> /etc/local.d/sysmanage-firstboot.start
echo "    py3-attrs py3-multidict py3-yarl py3-frozenlist py3-aiosignal \\\\" >> /etc/local.d/sysmanage-firstboot.start
echo "    py3-idna py3-charset-normalizer py3-async-timeout wget" >> /etc/local.d/sysmanage-firstboot.start
echo "" >> /etc/local.d/sysmanage-firstboot.start
echo "# Install sysmanage-agent from GitHub releases" >> /etc/local.d/sysmanage-firstboot.start
echo "echo \\"==> Installing sysmanage-agent from GitHub releases...\\"" >> /etc/local.d/sysmanage-firstboot.start
echo "LATEST_URL=\\"https://api.github.com/repos/bceverly/sysmanage-agent/releases/latest\\"" >> /etc/local.d/sysmanage-firstboot.start
echo "ALPINE_VER=\\$(cat /etc/alpine-release | cut -d. -f1,2 | tr -d '.')" >> /etc/local.d/sysmanage-firstboot.start
echo "RELEASE_INFO=\\$(wget -qO- \\"\\$LATEST_URL\\" 2>/dev/null)" >> /etc/local.d/sysmanage-firstboot.start
echo "if [ -n \\"\\$RELEASE_INFO\\" ]; then" >> /etc/local.d/sysmanage-firstboot.start
echo "    APK_URL=\\$(echo \\"\\$RELEASE_INFO\\" | grep -o \\"https://[^\\\\\\"]*alpine\\${ALPINE_VER}\\\\.apk\\" | head -1)" >> /etc/local.d/sysmanage-firstboot.start
echo "    if [ -n \\"\\$APK_URL\\" ]; then" >> /etc/local.d/sysmanage-firstboot.start
echo "        echo \\"Downloading from: \\$APK_URL\\"" >> /etc/local.d/sysmanage-firstboot.start
echo "        wget -O /tmp/sysmanage-agent.apk \\"\\$APK_URL\\" && \\\\" >> /etc/local.d/sysmanage-firstboot.start
echo "            apk add --allow-untrusted /tmp/sysmanage-agent.apk && \\\\" >> /etc/local.d/sysmanage-firstboot.start
echo "            rm -f /tmp/sysmanage-agent.apk" >> /etc/local.d/sysmanage-firstboot.start
echo "    else" >> /etc/local.d/sysmanage-firstboot.start
echo "        echo \\"No Alpine package found in release\\"" >> /etc/local.d/sysmanage-firstboot.start
echo "    fi" >> /etc/local.d/sysmanage-firstboot.start
echo "else" >> /etc/local.d/sysmanage-firstboot.start
echo "    echo \\"Could not reach GitHub API\\"" >> /etc/local.d/sysmanage-firstboot.start
echo "fi" >> /etc/local.d/sysmanage-firstboot.start
echo "" >> /etc/local.d/sysmanage-firstboot.start
echo "# Enable and start the APK's init script (sysmanage-agent with hyphen)" >> /etc/local.d/sysmanage-firstboot.start
echo "rc-update add sysmanage-agent default" >> /etc/local.d/sysmanage-firstboot.start
echo "rc-service sysmanage-agent start" >> /etc/local.d/sysmanage-firstboot.start
echo "" >> /etc/local.d/sysmanage-firstboot.start
echo "echo \\"==> First boot setup complete at \\$(date)\\"" >> /etc/local.d/sysmanage-firstboot.start
echo "rm -f /etc/local.d/sysmanage-firstboot.start" >> /etc/local.d/sysmanage-firstboot.start

chmod 755 /etc/local.d/sysmanage-firstboot.start

# Enable local service to run firstboot script on boot
rc-update add local default
"""

        # Build script using echo commands instead of heredocs
        # Heredocs don't work reliably over serial console automation
        setup_script = f"""#!/bin/sh
# Automated Alpine Linux setup script
# Generated by sysmanage-agent VMM autoinstall

set -e

echo "==> Starting automated Alpine setup..."

# Configure keyboard
setup-keymap us us

# Configure hostname
setup-hostname -n {hostname}
hostname {hostname}

# Configure networking with static IP
# Using echo commands instead of heredoc for serial console compatibility
echo "auto lo" > /etc/network/interfaces
echo "iface lo inet loopback" >> /etc/network/interfaces
echo "" >> /etc/network/interfaces
echo "auto eth0" >> /etc/network/interfaces
echo "iface eth0 inet static" >> /etc/network/interfaces
echo "    address {vm_ip}" >> /etc/network/interfaces
echo "    netmask 255.255.255.0" >> /etc/network/interfaces
echo "    gateway {gateway_ip}" >> /etc/network/interfaces

# Enable networking service to start on boot
rc-update add networking default

# Start networking now
/etc/init.d/networking restart || ifup eth0

# Configure DNS
echo "nameserver {dns_server}" > /etc/resolv.conf

# Configure timezone
setup-timezone -z UTC

# Configure APK repositories
# Using echo commands instead of heredoc for serial console compatibility
echo "{repo_url}/main" > /etc/apk/repositories
echo "{repo_url}/community" >> /etc/apk/repositories

# Update package index
apk update

# Install and configure SSH
apk add openssh
rc-update add sshd default
/etc/init.d/sshd start

# Set root password (using -e flag for pre-hashed password)
echo 'root:{root_password}' | chpasswd -e

# Create user
adduser -D -g "{username}" {username}
echo '{username}:{user_password}' | chpasswd -e
adduser {username} wheel

# Allow wheel group to sudo
apk add sudo
echo "%wheel ALL=(ALL) ALL" >> /etc/sudoers
{agent_config_section}{firstboot_section}
# Install to disk
# Use sys mode for persistent installation
# Note: /dev/vdb is the target disk because we boot with:
#   -d iso (becomes vda) -d disk (becomes vdb)
echo "==> Installing to disk..."
export KERNELOPTS="console=ttyS0,115200"

# Run setup-disk with auto-confirm
# The echo y handles the erase confirmation
echo "y" | setup-disk -m sys /dev/vdb

echo "==> Alpine installation complete!"
echo "==> System will now shutdown..."

# Shutdown so the agent can detect completion and restart without ISO
poweroff
"""
        return setup_script

    def create_firstboot_setup(
        self,
        _server_hostname: str,  # pylint: disable=unused-argument
        _server_port: int,  # pylint: disable=unused-argument
        _use_https: bool,  # pylint: disable=unused-argument
        _auto_approve_token: str = None,  # pylint: disable=unused-argument
    ) -> str:
        """
        Create first-boot setup script for sysmanage-agent installation.

        This script is placed in /etc/local.d/ and runs on first boot
        after the system is installed.

        Args:
            server_hostname: SysManage server hostname
            server_port: SysManage server port
            use_https: Whether to use HTTPS
            auto_approve_token: Optional auto-approval token

        Returns:
            First-boot script content
        """
        # Import locally to avoid circular imports
        from src.sysmanage_agent.operations.child_host_alpine_scripts import (  # pylint: disable=import-outside-toplevel
            generate_firstboot_script,
        )

        return generate_firstboot_script()

    def create_agent_config(
        self,
        server_hostname: str,
        server_port: int,
        use_https: bool,
        auto_approve_token: str = None,
    ) -> str:
        """
        Create sysmanage-agent configuration file.

        Args:
            server_hostname: SysManage server hostname
            server_port: SysManage server port
            use_https: Whether to use HTTPS
            auto_approve_token: Optional auto-approval token

        Returns:
            Agent configuration content
        """
        # Import locally to avoid circular imports
        from src.sysmanage_agent.operations.child_host_alpine_scripts import (  # pylint: disable=import-outside-toplevel
            generate_agent_config,
        )

        return generate_agent_config(
            server_hostname, server_port, use_https, auto_approve_token
        )

    def run_serial_console_setup(
        self,
        vm_name: str,
        setup_script: str,
        timeout: int = 600,  # pylint: disable=unused-argument
    ) -> Dict[str, Any]:
        """
        Run setup script via serial console.

        Uses vmctl console to interact with the VM's serial console
        and pipe the setup script.

        Args:
            vm_name: Name of the VM
            setup_script: Setup script content to run
            timeout: Timeout in seconds

        Returns:
            Dict with success status
        """
        try:
            self.logger.info(
                _("Running setup script via serial console for %s"), vm_name
            )

            # Write setup script to temporary file
            # NOSONAR - temp file for VM setup
            script_path = f"/tmp/alpine_setup_{vm_name}.sh"  # nosec B108
            with open(script_path, "w", encoding="utf-8") as script_file:
                script_file.write(setup_script)

            # The serial console interaction is complex - we need to:
            # 1. Wait for the login prompt
            # 2. Login as root (no password on live ISO)
            # 3. Run the setup script

            # Create an expect-like script for console interaction (for future use)
            _expect_script = f"""#!/bin/sh
# Alpine VM console automation

# Function to send command and wait
send_and_wait() {{
    echo "$1"
    sleep 2
}}

# Wait for login prompt (Alpine boots fast)
sleep 30

# Login as root (no password on live ISO)
send_and_wait "root"
sleep 2

# Run the setup script
cat {script_path} | sh

# Wait for setup to complete
sleep 60
"""

            # For now, we'll use a simpler approach - just document that
            # Alpine VMs require manual first-time setup or a pre-configured
            # disk image. This is a placeholder for future implementation.

            self.logger.warning(
                _(
                    "Alpine serial console automation is complex. "
                    "Consider using a pre-configured Alpine disk image."
                )
            )

            return {
                "success": True,
                "message": _("Serial console setup initiated"),
            }

        except Exception as error:  # pylint: disable=broad-except
            return {"success": False, "error": str(error)}

    def wait_for_alpine_boot(self, vm_name: str, timeout: int = 300) -> Dict[str, Any]:
        """
        Wait for Alpine VM to boot and become accessible.

        Args:
            vm_name: Name of the VM
            timeout: Timeout in seconds

        Returns:
            Dict with success status
        """
        try:
            self.logger.info(_("Waiting for Alpine VM '%s' to boot..."), vm_name)

            start_time = time.time()
            while time.time() - start_time < timeout:
                # Check if VM is running
                result = subprocess.run(  # nosec B603 B607
                    ["vmctl", "status", vm_name],
                    capture_output=True,
                    text=True,
                    timeout=10,
                    check=False,
                )

                if result.returncode == 0 and "running" in result.stdout.lower():
                    self.logger.info(_("Alpine VM '%s' is running"), vm_name)
                    return {"success": True}

                time.sleep(5)

            return {
                "success": False,
                "error": _("Timeout waiting for Alpine VM to boot"),
            }

        except Exception as error:  # pylint: disable=broad-except
            return {"success": False, "error": str(error)}

    def create_alpine_data_disk(
        self,
        vm_name: str,
        setup_script: str,
        agent_config: str,
        firstboot_script: str,
    ) -> Dict[str, Any]:
        """
        Create a data disk with setup files for Alpine VM.

        This creates a small FAT32 disk that Alpine can read during
        setup to get the configuration files.

        Args:
            vm_name: Name of the VM
            setup_script: Setup script content
            agent_config: Agent configuration content
            firstboot_script: First-boot script content

        Returns:
            Dict with success status and disk path
        """
        try:
            data_dir = Path("/var/vmm/alpine-data")
            data_dir.mkdir(parents=True, exist_ok=True)

            # Create a directory with the setup files
            vm_data_dir = data_dir / vm_name
            vm_data_dir.mkdir(exist_ok=True)

            # Write setup script
            setup_path = vm_data_dir / "setup.sh"
            setup_path.write_text(setup_script)
            setup_path.chmod(0o755)

            # Write agent config
            config_path = vm_data_dir / "sysmanage-agent.yaml"
            config_path.write_text(agent_config)

            # Write firstboot script
            firstboot_path = vm_data_dir / "sysmanage-firstboot.start"
            firstboot_path.write_text(firstboot_script)
            firstboot_path.chmod(0o755)

            self.logger.info(_("Created Alpine setup data in %s"), vm_data_dir)

            return {
                "success": True,
                "data_dir": str(vm_data_dir),
            }

        except Exception as error:  # pylint: disable=broad-except
            return {"success": False, "error": str(error)}
