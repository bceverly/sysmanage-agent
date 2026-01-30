"""FreeBSD-specific KVM provisioning using a config disk.

FreeBSD cloud images don't include cloud-init by default, and Linux can't
reliably mount FreeBSD's UFS2 filesystem. Instead, we create a config disk
containing cloud-init compatible user-data and meta-data files.

The FreeBSD BASIC-CLOUDINIT images use nuageinit which can read NoCloud
style configuration from an attached disk or ISO.
"""

import asyncio
import os
import pty
import secrets
import select
import shutil
import subprocess  # nosec B404 # Required for system commands
import tempfile
import time
from typing import Any, Dict, Optional

from src.i18n import _
from src.sysmanage_agent.core.agent_utils import run_command_async
from src.sysmanage_agent.operations.child_host_kvm_dns import get_host_dns_servers
from src.sysmanage_agent.operations.child_host_kvm_types import KvmVmConfig

# SSH options for non-interactive remote execution
_SSH_STRICT_HOST_KEY_CHECKING = "StrictHostKeyChecking=no"
_SSH_USER_KNOWN_HOSTS_FILE = "UserKnownHostsFile=/dev/null"


class FreeBSDProvisioner:
    """FreeBSD VM provisioning using a config disk approach."""

    def __init__(self, logger):
        """
        Initialize FreeBSD provisioner.

        Args:
            logger: Logger instance
        """
        self.logger = logger
        self._config_disk_path = None
        self._ssh_private_key_path: Optional[str] = None
        self._ssh_public_key: Optional[str] = None
        self._bootstrap_username: Optional[str] = None
        self._temp_root_password: Optional[str] = None

    def _generate_ssh_keypair(self, vm_name: str) -> Dict[str, Any]:
        """
        Generate a temporary SSH key pair for bootstrap automation.

        Args:
            vm_name: VM name (used for key comment)

        Returns:
            Dict with success status and key paths
        """
        try:
            # Create key in a temporary location
            key_dir = tempfile.mkdtemp(prefix="freebsd_ssh_")
            key_path = os.path.join(key_dir, "bootstrap_key")

            # Generate ED25519 key (faster and more secure than RSA)
            result = subprocess.run(  # nosec B603 B607
                [
                    "ssh-keygen",
                    "-t",
                    "ed25519",
                    "-f",
                    key_path,
                    "-N",
                    "",  # No passphrase
                    "-C",
                    f"sysmanage-bootstrap-{vm_name}",
                ],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )

            if result.returncode != 0:
                return {
                    "success": False,
                    "error": _("Failed to generate SSH key: %s") % result.stderr,
                }

            # Read the public key
            pub_key_path = f"{key_path}.pub"
            with open(pub_key_path, "r", encoding="utf-8") as pub_key_file:
                public_key = pub_key_file.read().strip()

            self._ssh_private_key_path = key_path
            self._ssh_public_key = public_key

            # Generate a temporary root password for su access
            # nuageinit doesn't set up SSH keys for root, so we use the regular
            # user's SSH key + su with this password
            self._temp_root_password = secrets.token_urlsafe(16)

            self.logger.info(_("Generated temporary SSH key for FreeBSD bootstrap"))
            return {
                "success": True,
                "private_key_path": key_path,
                "public_key": public_key,
            }

        except Exception as err:
            self.logger.error(_("Error generating SSH key: %s"), err)
            return {"success": False, "error": str(err)}

    def is_freebsd(self, config: KvmVmConfig) -> bool:
        """
        Check if the distribution is FreeBSD.

        Args:
            config: VM configuration

        Returns:
            True if FreeBSD, False otherwise
        """
        dist_lower = config.distribution.lower()
        return "freebsd" in dist_lower or "bsd" in dist_lower

    def _generate_user_data(self, config: KvmVmConfig) -> str:
        """
        Generate cloud-init compatible user-data for FreeBSD.

        Note: FreeBSD's nuageinit only supports a subset of cloud-init:
        - hostname, users, ssh_pwauth, network configuration
        - It does NOT support write_files or runcmd
        - Agent installation is handled via bootstrap.sh script on config disk

        Args:
            config: VM configuration

        Returns:
            User-data content in cloud-config format
        """
        # FreeBSD's nuageinit uses 'passwd' field with 'pw -H 0' for hashed
        # passwords. The field name is just 'passwd', not 'hashed_passwd'.

        # Include SSH public key if available for automated bootstrap
        # Note: FreeBSD nuageinit uses 'ssh_authorized_keys' (with underscores)
        ssh_keys_section = ""
        if self._ssh_public_key:
            ssh_keys_section = f"""    ssh_authorized_keys:
      - {self._ssh_public_key}
"""

        # Add chpasswd section to set a temporary root password
        # nuageinit doesn't set up SSH keys for root, so we SSH as regular user
        # and use 'su' with this password to run the bootstrap script
        chpasswd_section = ""
        if self._temp_root_password:
            chpasswd_section = f"""
chpasswd:
  list: |
    root:{self._temp_root_password}
  expire: false
"""

        return f"""#cloud-config
hostname: {config.hostname.split('.')[0]}
fqdn: {config.hostname}

users:
  - name: {config.username}
    groups: wheel
    shell: /bin/sh
    lock_passwd: false
    passwd: "{config.password_hash}"
    sudo: ALL=(ALL) NOPASSWD:ALL
{ssh_keys_section}
ssh_pwauth: true
disable_root: false
{chpasswd_section}"""

    def _generate_bootstrap_script(self, config: KvmVmConfig) -> str:
        """
        Generate bootstrap script for FreeBSD agent installation.

        Since nuageinit doesn't support write_files or runcmd, we create
        a bootstrap script that can be run after VM boot to install the agent.

        Args:
            config: VM configuration

        Returns:
            Shell script content
        """
        # Build the agent config YAML
        auto_approve_section = ""
        if config.auto_approve_token:
            auto_approve_section = f"""auto_approve:
  token: "{config.auto_approve_token}"
"""

        agent_config = f"""server:
  hostname: "{config.server_url}"
  port: {config.server_port}
  use_https: {str(config.use_https).lower()}
hostname: "{config.hostname}"
{auto_approve_section}websocket:
  reconnect_delay: 5
  max_reconnect_delay: 300
privileged_mode: true
script_execution:
  enabled: true
  allowed_shells:
    - "sh"
    - "csh"
database:
  path: "/var/lib/sysmanage-agent/agent.db"
logging:
  level: "INFO|WARNING|ERROR|CRITICAL"
  file: "/var/log/sysmanage-agent/agent.log"
  format: "[%(asctime)s UTC] %(name)s - %(levelname)s - %(message)s"
"""

        # Get DNS servers from the host
        dns_servers = get_host_dns_servers(self.logger)
        dns_config_lines = []
        for dns in dns_servers:
            dns_config_lines.append(f'echo "nameserver {dns}" >> /etc/resolv.conf')
        dns_config = "\n".join(dns_config_lines)

        return f"""#!/bin/sh
# FreeBSD sysmanage-agent bootstrap script
# Run this script as root after VM boot to install the agent
# Usage: sh /mnt/cidata/bootstrap.sh (as root)

set -e

USERNAME="{config.username}"

echo "=== FreeBSD sysmanage-agent Bootstrap ==="

# Step 1: Configure DNS (using host's DNS servers)
echo "Configuring DNS..."
echo "# Configured by sysmanage-agent bootstrap" > /etc/resolv.conf
{dns_config}
echo "DNS configured."

# Step 2: Install sudo and configure user
echo "Installing sudo and configuring user access..."
pkg install -y sudo

# Add user to sudoers with NOPASSWD
echo "$USERNAME ALL=(ALL) NOPASSWD: ALL" > /usr/local/etc/sudoers.d/$USERNAME
chmod 440 /usr/local/etc/sudoers.d/$USERNAME
echo "User $USERNAME added to sudoers with NOPASSWD access."

# Step 3: Install Python and all agent dependencies
echo "Installing Python 3.11 and agent dependencies..."
pkg install -y python311 py311-pip py311-aiosqlite py311-cryptography py311-pyyaml py311-aiohttp py311-sqlalchemy20 py311-alembic py311-websockets

# Step 4: Create required directories BEFORE pkg install
# The package post-install script needs these directories to exist
echo "Creating required directories..."
mkdir -p /usr/local/lib/sysmanage-agent
mkdir -p /usr/local/etc/sysmanage-agent
mkdir -p /var/log/sysmanage-agent
mkdir -p /var/run/sysmanage
mkdir -p /etc/sysmanage-agent
mkdir -p /var/lib/sysmanage-agent
mkdir -p /usr/local/etc/rc.d

# Step 5: Download and install agent from FreeBSD package
echo "Fetching latest version from GitHub..."
LATEST=$(fetch -q -o - https://api.github.com/repos/bceverly/sysmanage-agent/releases/latest | grep -o '"tag_name": *"[^"]*"' | grep -o 'v[0-9.]*')
VERSION=${{LATEST#v}}
echo "Latest version: ${{VERSION}}"

echo "Downloading agent package..."
fetch -o /tmp/sysmanage-agent-${{VERSION}}.pkg "https://github.com/bceverly/sysmanage-agent/releases/download/${{LATEST}}/sysmanage-agent-${{VERSION}}.pkg"

echo "Installing agent package..."
# Note: pkg add has a format issue that doesn't extract files properly
# Register the package in the database first
pkg add /tmp/sysmanage-agent-${{VERSION}}.pkg || true

# Extract files manually using tar (workaround for pkg format issue)
echo "Extracting package files..."
cd / && tar -xf /tmp/sysmanage-agent-${{VERSION}}.pkg --include='usr/*'

# Cleanup downloaded package
rm -f /tmp/sysmanage-agent-${{VERSION}}.pkg

# Step 6: Write agent configuration
echo "Creating agent configuration..."
cat > /etc/sysmanage-agent.yaml << 'AGENT_CONFIG_EOF'
{agent_config}AGENT_CONFIG_EOF

# Create symlink for package's expected config location
ln -sf /etc/sysmanage-agent.yaml /usr/local/etc/sysmanage-agent/config.yaml

# Step 7: Enable and start the agent service
echo "Enabling and starting sysmanage-agent service..."
sysrc sysmanage_agent_enable=YES
sysrc sysmanage_agent_user=root
service sysmanage_agent restart 2>/dev/null || service sysmanage_agent start

echo ""
echo "=== Bootstrap complete ==="
echo "The sysmanage-agent should now be running."
echo "Check status with: service sysmanage_agent status"
echo "User '$USERNAME' has been added to sudoers with NOPASSWD access."
"""

    def _generate_meta_data(self, config: KvmVmConfig) -> str:
        """
        Generate cloud-init compatible meta-data for FreeBSD.

        Args:
            config: VM configuration

        Returns:
            Meta-data content
        """
        return f"""instance-id: {config.vm_name}
local-hostname: {config.hostname.split('.')[0]}
"""

    def create_config_disk(self, config: KvmVmConfig, disk_dir: str) -> Dict[str, Any]:
        """
        Create a config disk ISO with cloud-init files and bootstrap script.

        The ISO contains:
        - user-data: Cloud-init user configuration (handled by nuageinit)
        - meta-data: Instance metadata
        - bootstrap.sh: Agent installation script (run manually after boot)

        Args:
            config: VM configuration
            disk_dir: Directory to create the disk in

        Returns:
            Dict with success status and disk path
        """
        try:
            self.logger.info(_("Creating FreeBSD config disk"))

            # Create temp directory for files
            temp_dir = tempfile.mkdtemp(prefix="freebsd_config_")

            try:
                # Generate user-data, meta-data, and bootstrap script
                user_data = self._generate_user_data(config)
                meta_data = self._generate_meta_data(config)
                bootstrap_script = self._generate_bootstrap_script(config)

                # Write files to temp directory
                user_data_path = os.path.join(temp_dir, "user-data")
                meta_data_path = os.path.join(temp_dir, "meta-data")
                bootstrap_path = os.path.join(temp_dir, "bootstrap.sh")

                # Write cloud-init files to temp directory for ISO creation.
                # These files contain configuration data (including hashed passwords)
                # that must be written to create the cloud-init ISO for VM provisioning.
                # The temp directory is cleaned up after ISO creation.
                # CodeQL: This is intentional - cloud-init requires these files to provision VMs.
                # The password is already hashed and the temp directory is cleaned up after use.
                with open(user_data_path, "w", encoding="utf-8") as udf:  # noqa: S324
                    # codeql[py/clear-text-storage-sensitive-data] - Intentional: cloud-init requires this file, password is pre-hashed, temp dir cleaned after use
                    udf.write(user_data)  # codespell:ignore  # nosec B105
                with open(meta_data_path, "w", encoding="utf-8") as mdf:
                    mdf.write(meta_data)
                with open(bootstrap_path, "w", encoding="utf-8") as bsf:
                    bsf.write(bootstrap_script)
                # Make bootstrap script executable - must be 755 to run as shell script
                # nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions
                os.chmod(bootstrap_path, 0o755)  # nosec B103  # NOSONAR

                # Create ISO image (more compatible than FAT32 for cloud-init)
                self._config_disk_path = os.path.join(
                    disk_dir, f"{config.vm_name}-freebsd-config.iso"
                )

                # Use genisoimage/mkisofs to create ISO
                iso_cmd = None
                if shutil.which("genisoimage"):
                    iso_cmd = "genisoimage"
                elif shutil.which("mkisofs"):
                    iso_cmd = "mkisofs"

                if iso_cmd:
                    result = subprocess.run(  # nosec B603 B607
                        [
                            "sudo",
                            iso_cmd,
                            "-output",
                            self._config_disk_path,
                            "-volid",
                            "cidata",
                            "-joliet",
                            "-rock",
                            user_data_path,
                            meta_data_path,
                            bootstrap_path,
                        ],
                        capture_output=True,
                        text=True,
                        timeout=60,
                        check=False,
                    )
                    if result.returncode != 0:
                        return {
                            "success": False,
                            "error": _("Failed to create config ISO: %s")
                            % result.stderr,
                        }
                else:
                    return {
                        "success": False,
                        "error": _(
                            "No ISO creation tool found. "
                            "Install genisoimage or mkisofs."
                        ),
                    }

                self.logger.info(
                    _("Created FreeBSD config disk: %s"), self._config_disk_path
                )
                return {
                    "success": True,
                    "config_disk_path": self._config_disk_path,
                }

            finally:
                # Clean up temp directory
                shutil.rmtree(temp_dir, ignore_errors=True)

        except Exception as err:
            self.logger.error(_("Error creating config disk: %s"), err)
            return {"success": False, "error": str(err)}

    def provision_image(self, qcow2_path: str, config: KvmVmConfig) -> Dict[str, Any]:
        """
        Provision FreeBSD by creating a config disk.

        Since we can't mount FreeBSD's UFS2 filesystem from Linux, we create
        a separate config disk that FreeBSD's nuageinit will read on boot.

        Args:
            qcow2_path: Path to the qcow2 image (used to determine disk directory)
            config: VM configuration

        Returns:
            Dict with success status and config disk path
        """
        try:
            self.logger.info(_("Provisioning FreeBSD with config disk"))

            # Store username for SSH bootstrap
            self._bootstrap_username = config.username

            # Generate SSH keypair for automated bootstrap
            ssh_result = self._generate_ssh_keypair(config.vm_name)
            if not ssh_result.get("success"):
                self.logger.warning(
                    _(
                        "Could not generate SSH key, bootstrap will require manual run: %s"
                    ),
                    ssh_result.get("error"),
                )
                # Continue without SSH key - manual bootstrap will be needed

            # Get the directory where the main disk is
            disk_dir = os.path.dirname(qcow2_path)

            # Create the config disk (will include SSH key if generated)
            result = self.create_config_disk(config, disk_dir)
            if not result.get("success"):
                return result

            # Store the config disk path in the config for VM creation
            config.freebsd_config_disk = result.get("config_disk_path")

            self.logger.info(_("FreeBSD provisioning complete"))
            return {
                "success": True,
                "config_disk_path": result.get("config_disk_path"),
                "ssh_key_available": self._ssh_private_key_path is not None,
            }

        except Exception as err:
            self.logger.error(_("Error provisioning FreeBSD: %s"), err)
            return {"success": False, "error": str(err)}

    def get_config_disk_path(self) -> str:
        """Get the path to the config disk if created."""
        return self._config_disk_path

    def has_ssh_key(self) -> bool:
        """Check if SSH key is available for automated bootstrap."""
        return self._ssh_private_key_path is not None

    def _install_sshpass(self) -> Dict[str, Any]:
        """
        Install sshpass package on the host system.

        Detects the package manager and installs sshpass, which is needed
        for FreeBSD VM bootstrap (to SSH as root with password auth).

        Returns:
            Dict with success status and error message if failed
        """
        try:
            # Detect package manager and install sshpass
            if shutil.which("apt-get"):
                # Debian/Ubuntu
                self.logger.info(_("Installing sshpass via apt..."))
                result = subprocess.run(  # nosec B603 B607
                    ["sudo", "apt-get", "install", "-y", "sshpass"],
                    capture_output=True,
                    text=True,
                    timeout=120,
                    check=False,
                )
            elif shutil.which("dnf"):
                # Fedora/RHEL 8+
                self.logger.info(_("Installing sshpass via dnf..."))
                result = subprocess.run(  # nosec B603 B607
                    ["sudo", "dnf", "install", "-y", "sshpass"],
                    capture_output=True,
                    text=True,
                    timeout=120,
                    check=False,
                )
            elif shutil.which("yum"):
                # RHEL/CentOS 7
                self.logger.info(_("Installing sshpass via yum..."))
                result = subprocess.run(  # nosec B603 B607
                    ["sudo", "yum", "install", "-y", "sshpass"],
                    capture_output=True,
                    text=True,
                    timeout=120,
                    check=False,
                )
            elif shutil.which("zypper"):
                # openSUSE/SLES
                self.logger.info(_("Installing sshpass via zypper..."))
                result = subprocess.run(  # nosec B603 B607
                    ["sudo", "zypper", "install", "-y", "sshpass"],
                    capture_output=True,
                    text=True,
                    timeout=120,
                    check=False,
                )
            elif shutil.which("apk"):
                # Alpine
                self.logger.info(_("Installing sshpass via apk..."))
                result = subprocess.run(  # nosec B603 B607
                    ["sudo", "apk", "add", "sshpass"],
                    capture_output=True,
                    text=True,
                    timeout=120,
                    check=False,
                )
            else:
                return {
                    "success": False,
                    "error": _(
                        "Could not detect package manager to install sshpass. "
                        "Please install sshpass manually."
                    ),
                }

            if result.returncode != 0:
                self.logger.error(
                    _("Failed to install sshpass: %s"),
                    result.stderr.strip() if result.stderr else result.stdout.strip(),
                )
                return {
                    "success": False,
                    "error": _("Failed to install sshpass: %s")
                    % (
                        result.stderr.strip()
                        if result.stderr
                        else result.stdout.strip()
                    ),
                }

            self.logger.info(_("sshpass installed successfully"))
            return {"success": True}

        except subprocess.TimeoutExpired:
            return {
                "success": False,
                "error": _("Timeout while installing sshpass"),
            }
        except Exception as err:
            self.logger.error(_("Error installing sshpass: %s"), err)
            return {"success": False, "error": str(err)}

    async def run_bootstrap_via_ssh(
        self,
        ip_address: str,
        timeout: int = 600,  # NOSONAR - timeout parameter is for polling loop control
    ) -> Dict[str, Any]:
        """
        Run the FreeBSD bootstrap script via SSH.

        This method SSHs into the VM as the regular user using the temporary
        key pair, then uses 'su' with the temporary root password to mount
        the config disk and run the bootstrap script.

        Args:
            ip_address: VM IP address
            timeout: Maximum time to wait for bootstrap in seconds

        Returns:
            Dict with success status and output
        """
        if not self._ssh_private_key_path:
            return {
                "success": False,
                "error": _("No SSH key available for automated bootstrap"),
            }

        if not self._bootstrap_username:
            return {
                "success": False,
                "error": _("Bootstrap username not set"),
            }

        if not self._temp_root_password:
            return {
                "success": False,
                "error": _("No temporary root password available for bootstrap"),
            }

        try:
            self.logger.info(_("Running FreeBSD bootstrap via SSH on %s"), ip_address)

            # Give nuageinit more time to set up the user and SSH key
            # FreeBSD boot process takes time, and nuageinit runs during firstboot
            self.logger.info(_("Waiting 30 seconds for nuageinit to complete..."))
            await asyncio.sleep(30)

            # Test if SSH key auth works for the regular user
            self.logger.info(
                _("Testing SSH key authentication as %s..."), self._bootstrap_username
            )
            test_result = await run_command_async(
                [
                    "ssh",
                    "-i",
                    self._ssh_private_key_path,
                    "-o",
                    _SSH_STRICT_HOST_KEY_CHECKING,
                    "-o",
                    _SSH_USER_KNOWN_HOSTS_FILE,
                    "-o",
                    "ConnectTimeout=10",
                    "-o",
                    "BatchMode=yes",
                    f"{self._bootstrap_username}@{ip_address}",
                    "echo 'SSH key auth works'",
                ],
                timeout=30,
            )

            if test_result.returncode != 0:
                self.logger.warning(
                    _(
                        "SSH key auth failed (stdout: %s, stderr: %s), trying again after 30s..."
                    ),
                    test_result.stdout.strip(),
                    test_result.stderr.strip(),
                )
                await asyncio.sleep(30)
                # Try again
                test_result = await run_command_async(
                    [
                        "ssh",
                        "-i",
                        self._ssh_private_key_path,
                        "-o",
                        _SSH_STRICT_HOST_KEY_CHECKING,
                        "-o",
                        _SSH_USER_KNOWN_HOSTS_FILE,
                        "-o",
                        "ConnectTimeout=10",
                        "-o",
                        "BatchMode=yes",
                        f"{self._bootstrap_username}@{ip_address}",
                        "echo 'SSH key auth works'",
                    ],
                    timeout=30,
                )
                if test_result.returncode != 0:
                    return {
                        "success": False,
                        "error": _("SSH key authentication failed: %s")
                        % test_result.stderr,
                    }

            self.logger.info(_("SSH key authentication successful"))

            # FreeBSD's su doesn't read passwords from stdin (reads from /dev/tty)
            # FreeBSD's sshd also doesn't allow root password login by default
            # Solution: Use Python pty module to create interactive session with su

            self.logger.info(_("Running bootstrap script as root via su with pty..."))

            # Use pty to run SSH with an interactive terminal for su password entry
            bootstrap_result = self._run_su_bootstrap_via_pty(
                ip_address, self._temp_root_password, timeout
            )

            if not bootstrap_result.get("success"):
                self.logger.error(
                    _("Bootstrap script failed. stdout: %s, stderr: %s"),
                    bootstrap_result.get("stdout", "(empty)"),
                    bootstrap_result.get("stderr", "(empty)"),
                )
                return {
                    "success": False,
                    "error": _("Bootstrap script failed: %s")
                    % bootstrap_result.get("error", "Unknown error"),
                    "stdout": bootstrap_result.get("stdout", ""),
                    "stderr": bootstrap_result.get("stderr", ""),
                }

            self.logger.info(_("FreeBSD bootstrap completed successfully"))
            return {"success": True}

        except asyncio.TimeoutError:
            self.logger.error(_("SSH bootstrap timed out"))
            return {"success": False, "error": _("SSH bootstrap timed out")}
        except Exception as err:
            self.logger.error(_("Error running bootstrap via SSH: %s"), err)
            return {"success": False, "error": str(err)}

    def _read_pty_data(self, master_fd: int) -> Optional[str]:
        """
        Read data from PTY file descriptor.

        Returns:
            Data string if available, empty string for EOF, None on error
        """
        try:
            data = os.read(master_fd, 4096).decode("utf-8", errors="replace")
            return data if data else ""
        except OSError as os_err:
            self.logger.debug(f"PTY read error: {os_err}")
            return None

    def _send_password_if_prompted(
        self, master_fd: int, accumulated: str, password: str, password_sent: bool
    ) -> bool:
        """
        Send password if prompt detected.

        Returns:
            True if password was sent (either now or previously)
        """
        if password_sent:
            return True
        if "assword:" not in accumulated:
            return False

        # Small delay to ensure prompt is ready
        time.sleep(0.3)
        self.logger.debug("Detected password prompt, sending password")
        os.write(master_fd, (password + "\n").encode())
        self.logger.debug("Password sent")
        return True

    def _get_bootstrap_root_commands(self) -> str:
        """Get the shell commands to run as root for bootstrap."""
        return """
set -e
# Mount config disk (could be cd0 or cd1)
if [ ! -d /mnt/cidata ]; then
    mkdir -p /mnt/cidata
fi
mount -t cd9660 /dev/cd0 /mnt/cidata 2>/dev/null || mount -t cd9660 /dev/cd1 /mnt/cidata 2>/dev/null || true
# Run the bootstrap script
if [ -f /mnt/cidata/bootstrap.sh ]; then
    sh /mnt/cidata/bootstrap.sh
    exit $?
else
    echo "ERROR: bootstrap.sh not found on config disk"
    exit 1
fi
"""

    def _build_ssh_command(self, ip_address: str, root_commands: str) -> list:
        """Build the SSH command for PTY bootstrap."""
        return [
            "ssh",
            "-t",
            "-t",  # Double -t forces tty even when stdin is not a terminal
            "-i",
            self._ssh_private_key_path,
            "-o",
            _SSH_STRICT_HOST_KEY_CHECKING,
            "-o",
            _SSH_USER_KNOWN_HOSTS_FILE,
            "-o",
            "ConnectTimeout=30",
            f"{self._bootstrap_username}@{ip_address}",
            f"su -m root -c '{root_commands}'",
        ]

    def _handle_pty_data_available(
        self,
        master_fd: int,
        output: list,
        accumulated: str,
        root_password: str,
        password_sent: bool,
    ) -> tuple:
        """
        Handle data available on PTY.

        Returns:
            Tuple of (should_break, accumulated, password_sent)
        """
        data = self._read_pty_data(master_fd)
        if data is None:
            return (True, accumulated, password_sent)
        if not data:
            self.logger.debug("PTY EOF reached")
            return (True, accumulated, password_sent)

        output.append(data)
        accumulated += data
        self.logger.debug(f"PTY output: {repr(data)}")

        password_sent = self._send_password_if_prompted(
            master_fd, accumulated, root_password, password_sent
        )
        return (False, accumulated, password_sent)

    def _handle_process_exited(self, master_fd: int, output: list) -> None:
        """Handle final read when process has exited."""
        final_data = self._read_pty_data(master_fd)
        if final_data:
            output.append(final_data)
            self.logger.debug(f"Final PTY output: {repr(final_data)}")

    def _run_su_bootstrap_via_pty(
        self, ip_address: str, root_password: str, timeout: int = 600
    ) -> Dict[str, Any]:
        """
        Run bootstrap as root using pty to interact with su password prompt.

        This method creates a pseudo-terminal to handle su's password prompt
        since su reads from /dev/tty, not stdin.
        """
        root_commands = self._get_bootstrap_root_commands()
        ssh_cmd = self._build_ssh_command(ip_address, root_commands)

        output = []
        master_fd = None
        try:
            master_fd, slave_fd = pty.openpty()
            self.logger.debug("Starting SSH with pty for su password entry")

            # pylint: disable=consider-using-with
            process = subprocess.Popen(  # nosec B603
                ssh_cmd,
                stdin=slave_fd,
                stdout=slave_fd,
                stderr=slave_fd,
                close_fds=True,
            )
            # pylint: enable=consider-using-with
            os.close(slave_fd)

            password_sent = False
            start_time = time.time()
            accumulated = ""

            while True:
                if time.time() - start_time > timeout:
                    process.kill()
                    process.wait()
                    return {
                        "success": False,
                        "error": "Timeout waiting for bootstrap",
                        "stdout": "".join(output),
                    }

                readable, _, _ = select.select([master_fd], [], [], 0.5)

                if not readable:
                    if process.poll() is None:
                        continue
                    self._handle_process_exited(master_fd, output)
                    break

                should_break, accumulated, password_sent = (
                    self._handle_pty_data_available(
                        master_fd, output, accumulated, root_password, password_sent
                    )
                )
                if should_break:
                    break

            exit_code = process.wait()
            self.logger.debug(f"Process exit code: {exit_code}")

            os.close(master_fd)
            master_fd = None

            full_output = "".join(output)
            if exit_code == 0:
                return {"success": True, "stdout": full_output, "exit_code": exit_code}

            return {
                "success": False,
                "error": f"Bootstrap exited with code {exit_code}",
                "stdout": full_output,
                "exit_code": exit_code,
            }

        except Exception as err:
            self.logger.error(f"PTY bootstrap error: {err}")
            return {"success": False, "error": str(err), "stdout": "".join(output)}
        finally:
            if master_fd is not None:
                try:
                    os.close(master_fd)
                except OSError:
                    pass

    def cleanup(self):
        """Clean up any created resources."""
        # Clean up config disk
        if self._config_disk_path and os.path.exists(self._config_disk_path):
            try:
                os.remove(self._config_disk_path)
            except OSError:
                pass
        self._config_disk_path = None

        # Clean up SSH key directory
        if self._ssh_private_key_path:
            key_dir = os.path.dirname(self._ssh_private_key_path)
            try:
                shutil.rmtree(key_dir, ignore_errors=True)
            except OSError:
                pass
            self._ssh_private_key_path = None
            self._ssh_public_key = None

        self._bootstrap_username = None
        self._temp_root_password = None
