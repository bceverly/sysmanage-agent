"""FreeBSD-specific KVM provisioning using a config disk.

FreeBSD cloud images don't include cloud-init by default, and Linux can't
reliably mount FreeBSD's UFS2 filesystem. Instead, we create a config disk
containing cloud-init compatible user-data and meta-data files.

The FreeBSD BASIC-CLOUDINIT images use nuageinit which can read NoCloud
style configuration from an attached disk or ISO.
"""

import asyncio
import os
import secrets
import shutil
import subprocess  # nosec B404 # Required for system commands
import tempfile
from typing import Any, Dict, Optional

from src.i18n import _
from src.sysmanage_agent.operations.child_host_kvm_dns import get_host_dns_servers
from src.sysmanage_agent.operations.child_host_kvm_types import KvmVmConfig


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

# Step 0: Configure DNS (using host's DNS servers)
echo "Configuring DNS..."
echo "# Configured by sysmanage-agent bootstrap" > /etc/resolv.conf
{dns_config}
echo "DNS configured."

# Step 1: Install sudo and configure user
echo "Installing sudo and configuring user access..."
pkg install -y sudo

# Add user to sudoers with NOPASSWD
echo "$USERNAME ALL=(ALL) NOPASSWD: ALL" > /usr/local/etc/sudoers.d/$USERNAME
chmod 440 /usr/local/etc/sudoers.d/$USERNAME
echo "User $USERNAME added to sudoers with NOPASSWD access."

# Step 2: Install Python and dependencies
echo "Installing Python and dependencies..."
pkg install -y python311 py311-pip py311-aiosqlite py311-cryptography \\
    py311-pyyaml py311-aiohttp py311-sqlalchemy20 py311-alembic py311-websockets

# Step 3: Create directories and user
echo "Creating agent directories and user..."
mkdir -p /usr/local/lib/sysmanage-agent
mkdir -p /usr/local/etc/sysmanage-agent
mkdir -p /var/lib/sysmanage-agent
mkdir -p /var/log/sysmanage-agent
mkdir -p /var/run/sysmanage

# Create sysmanage user and group if they don't exist
if ! pw groupshow sysmanage >/dev/null 2>&1; then
    pw groupadd sysmanage -g 9999
fi
if ! pw usershow sysmanage >/dev/null 2>&1; then
    pw useradd sysmanage -u 9999 -g sysmanage -h - -s /usr/sbin/nologin \\
       -d /usr/local/lib/sysmanage-agent -c "SysManage Agent User"
fi

# Step 4: Download and install agent from tarball
echo "Fetching latest version from GitHub..."
LATEST=$(fetch -q -o - https://api.github.com/repos/bceverly/sysmanage-agent/releases/latest | grep -o '"tag_name": *"[^"]*"' | grep -o 'v[0-9.]*')
VERSION=${{LATEST#v}}
echo "Latest version: ${{VERSION}}"

echo "Downloading agent tarball..."
fetch -o /tmp/sysmanage-agent-${{VERSION}}.tgz "https://github.com/bceverly/sysmanage-agent/releases/download/${{LATEST}}/sysmanage-agent-${{VERSION}}.tgz"

echo "Extracting agent files..."
# The tarball has NetBSD-style paths (usr/pkg/lib/sysmanage-agent/)
# Extract to temp and copy to FreeBSD location
mkdir -p /tmp/sysmanage-extract
cd /tmp/sysmanage-extract
tar xzf /tmp/sysmanage-agent-${{VERSION}}.tgz

# Copy files to FreeBSD location
if [ -d "usr/pkg/lib/sysmanage-agent" ]; then
    cp -R usr/pkg/lib/sysmanage-agent/* /usr/local/lib/sysmanage-agent/
elif [ -d "usr/local/lib/sysmanage-agent" ]; then
    cp -R usr/local/lib/sysmanage-agent/* /usr/local/lib/sysmanage-agent/
elif [ -f "main.py" ]; then
    cp -R * /usr/local/lib/sysmanage-agent/
else
    echo "ERROR: Unexpected tarball structure"
    ls -la
    exit 1
fi

# Cleanup
cd /
rm -rf /tmp/sysmanage-extract
rm -f /tmp/sysmanage-agent-${{VERSION}}.tgz

# Step 5: Install rc script
echo "Installing rc script..."
cat > /usr/local/etc/rc.d/sysmanage_agent << 'RC_SCRIPT_EOF'
#!/bin/sh
#
# PROVIDE: sysmanage_agent
# REQUIRE: NETWORKING
# KEYWORD: shutdown
#
# Add the following lines to /etc/rc.conf to enable sysmanage_agent:
#
# sysmanage_agent_enable="YES"
#

. /etc/rc.subr

name="sysmanage_agent"
rcvar="sysmanage_agent_enable"
pidfile="/var/run/sysmanage/${{name}}.pid"
logfile="/var/log/sysmanage-agent/agent.log"

command="/usr/local/bin/python3.11"
command_args="/usr/local/lib/sysmanage-agent/main.py >> $logfile 2>&1 & echo \\$! > $pidfile"
command_interpreter="/usr/local/bin/python3.11"

start_cmd="${{name}}_start"
stop_cmd="${{name}}_stop"
status_cmd="${{name}}_status"

sysmanage_agent_start()
{{
    if [ -f $pidfile ]; then
        pid=$(cat $pidfile)
        if kill -0 $pid 2>/dev/null; then
            echo "${{name}} is already running as pid $pid"
            return 1
        fi
    fi
    echo "Starting ${{name}}..."
    mkdir -p /var/run/sysmanage
    mkdir -p /var/log/sysmanage-agent
    cd /usr/local/lib/sysmanage-agent
    /usr/local/bin/python3.11 main.py >> $logfile 2>&1 &
    echo $! > $pidfile
    echo "${{name}} started."
}}

sysmanage_agent_stop()
{{
    if [ -f $pidfile ]; then
        pid=$(cat $pidfile)
        echo "Stopping ${{name}}..."
        kill $pid 2>/dev/null
        rm -f $pidfile
        echo "${{name}} stopped."
    else
        echo "${{name}} is not running."
    fi
}}

sysmanage_agent_status()
{{
    if [ -f $pidfile ]; then
        pid=$(cat $pidfile)
        if kill -0 $pid 2>/dev/null; then
            echo "${{name}} is running as pid $pid"
        else
            echo "${{name}} is not running (stale pid file)"
        fi
    else
        echo "${{name}} is not running."
    fi
}}

load_rc_config $name
run_rc_command "$1"
RC_SCRIPT_EOF

chmod +x /usr/local/etc/rc.d/sysmanage_agent

# Step 6: Set ownership
echo "Setting ownership..."
chown -R sysmanage:sysmanage /usr/local/lib/sysmanage-agent
chown -R sysmanage:sysmanage /var/lib/sysmanage-agent
chown -R sysmanage:sysmanage /var/log/sysmanage-agent
chown -R sysmanage:sysmanage /var/run/sysmanage

# Step 7: Write agent configuration (after install, overwriting any default)
echo "Creating agent configuration..."
cat > /etc/sysmanage-agent.yaml << 'AGENT_CONFIG_EOF'
{agent_config}AGENT_CONFIG_EOF

# Step 8: Enable and start the agent service
echo "Enabling and starting sysmanage-agent service..."
sysrc sysmanage_agent_enable=YES
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

                with open(user_data_path, "w", encoding="utf-8") as udf:
                    udf.write(user_data)
                with open(meta_data_path, "w", encoding="utf-8") as mdf:
                    mdf.write(meta_data)
                with open(bootstrap_path, "w", encoding="utf-8") as bsf:
                    bsf.write(bootstrap_script)
                # Make bootstrap script executable - must be 755 to run as shell script
                os.chmod(bootstrap_path, 0o755)  # nosec B103

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

    async def run_bootstrap_via_ssh(
        self, ip_address: str, timeout: int = 600
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
            test_result = subprocess.run(  # nosec B603 B607
                [
                    "ssh",
                    "-i",
                    self._ssh_private_key_path,
                    "-o",
                    "StrictHostKeyChecking=no",
                    "-o",
                    "UserKnownHostsFile=/dev/null",
                    "-o",
                    "ConnectTimeout=10",
                    "-o",
                    "BatchMode=yes",
                    f"{self._bootstrap_username}@{ip_address}",
                    "echo 'SSH key auth works'",
                ],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
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
                test_result = subprocess.run(  # nosec B603 B607
                    [
                        "ssh",
                        "-i",
                        self._ssh_private_key_path,
                        "-o",
                        "StrictHostKeyChecking=no",
                        "-o",
                        "UserKnownHostsFile=/dev/null",
                        "-o",
                        "ConnectTimeout=10",
                        "-o",
                        "BatchMode=yes",
                        f"{self._bootstrap_username}@{ip_address}",
                        "echo 'SSH key auth works'",
                    ],
                    capture_output=True,
                    text=True,
                    timeout=30,
                    check=False,
                )
                if test_result.returncode != 0:
                    return {
                        "success": False,
                        "error": _("SSH key authentication failed: %s")
                        % test_result.stderr,
                    }

            self.logger.info(_("SSH key authentication successful"))

            # The bootstrap script using su with the temporary root password
            # We use 'echo password | su -' pattern to provide password non-interactively
            # Note: Single quotes around EOF to prevent variable expansion in heredoc
            bootstrap_script = f"""#!/bin/sh
# Provide password to su via stdin
echo '{self._temp_root_password}' | su - root -c '
set -e
# Mount config disk (could be cd0 or cd1)
if [ ! -d /mnt/cidata ]; then
    mkdir -p /mnt/cidata
fi
mount -t cd9660 /dev/cd0 /mnt/cidata 2>/dev/null || mount -t cd9660 /dev/cd1 /mnt/cidata
# Run the bootstrap script
sh /mnt/cidata/bootstrap.sh
'
"""

            # Run via SSH as regular user, using su to become root
            self.logger.info(_("Running bootstrap script via su as root..."))
            result = subprocess.run(  # nosec B603 B607
                [
                    "ssh",
                    "-i",
                    self._ssh_private_key_path,
                    "-o",
                    "StrictHostKeyChecking=no",
                    "-o",
                    "UserKnownHostsFile=/dev/null",
                    "-o",
                    "ConnectTimeout=30",
                    "-o",
                    "BatchMode=yes",
                    f"{self._bootstrap_username}@{ip_address}",
                    bootstrap_script,
                ],
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )

            if result.returncode != 0:
                self.logger.error(_("Bootstrap script failed: %s"), result.stderr)
                return {
                    "success": False,
                    "error": _("Bootstrap script failed: %s") % result.stderr,
                    "stdout": result.stdout,
                    "stderr": result.stderr,
                }

            self.logger.info(_("FreeBSD bootstrap completed successfully"))
            return {
                "success": True,
                "stdout": result.stdout,
                "stderr": result.stderr,
            }

        except subprocess.TimeoutExpired:
            self.logger.error(_("Bootstrap script timed out"))
            return {
                "success": False,
                "error": _("Bootstrap script timed out after %d seconds") % timeout,
            }
        except Exception as err:
            self.logger.error(_("Error running bootstrap: %s"), err)
            return {"success": False, "error": str(err)}

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
