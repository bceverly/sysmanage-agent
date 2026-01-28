"""FreeBSD-specific bhyve provisioning by injecting firstboot scripts.

FreeBSD raw VM images don't include nuageinit/cloud-init, so we inject
a firstboot script directly into the disk image before boot. This script:
- Creates the user with password
- Sets the hostname
- Installs and configures the sysmanage-agent

The firstboot mechanism uses FreeBSD's /etc/rc.d/firstboot support.
"""

import asyncio
import os
import secrets
import shutil
import subprocess  # nosec B404 # needed for sync disk operations
import tempfile
from typing import Any, Dict, Optional

from src.i18n import _
from src.sysmanage_agent.core.agent_utils import run_command_async
from src.sysmanage_agent.operations.child_host_bhyve_types import BhyveVmConfig
from src.sysmanage_agent.operations.child_host_config_generator import (
    generate_agent_config,
)


class FreeBSDBhyveProvisioner:
    """FreeBSD VM provisioning for bhyve by injecting firstboot scripts."""

    def __init__(self, logger):
        """
        Initialize FreeBSD bhyve provisioner.

        Args:
            logger: Logger instance
        """
        self.logger = logger
        self._config_disk_path: Optional[str] = None
        self._ssh_private_key_path: Optional[str] = None
        self._ssh_public_key: Optional[str] = None
        self._bootstrap_username: Optional[str] = None
        self._temp_root_password: Optional[str] = None
        self._md_device: Optional[str] = None

    def _generate_firstboot_script(self, config: BhyveVmConfig) -> str:
        """
        Generate a firstboot rc.d script for FreeBSD.

        This script runs on first boot to install the sysmanage-agent.
        It uses FreeBSD's firstboot mechanism (/etc/rc.d/firstboot).

        Args:
            config: VM configuration

        Returns:
            Shell script content for /etc/rc.d/sysmanage_firstboot
        """
        os_type = "freebsd"
        agent_config = generate_agent_config(
            hostname=config.server_url,
            port=config.server_port,
            use_https=config.use_https,
            os_type=os_type,
            auto_approve_token=config.auto_approve_token,
            verify_ssl=False,
        )

        # Escape any single quotes in the config for embedding in shell script
        agent_config_escaped = agent_config.replace("'", "'\\''")

        return f"""#!/bin/sh

# PROVIDE: sysmanage_firstboot
# REQUIRE: NETWORKING
# BEFORE: LOGIN
# KEYWORD: firstboot

. /etc/rc.subr

name="sysmanage_firstboot"
desc="SysManage Agent First Boot Setup"
rcvar="sysmanage_firstboot_enable"
start_cmd="sysmanage_firstboot_start"
stop_cmd=":"

sysmanage_firstboot_start()
{{
    echo "=== SysManage Agent First Boot Setup ==="

    # Step 1: Install sudo and configure user
    echo "Installing sudo..."
    pkg install -y sudo

    echo "Configuring sudoers for {config.username}..."
    echo "{config.username} ALL=(ALL) NOPASSWD: ALL" > /usr/local/etc/sudoers.d/{config.username}
    chmod 440 /usr/local/etc/sudoers.d/{config.username}

    # Step 2: Install Python and agent dependencies
    echo "Installing Python 3.11 and agent dependencies..."
    pkg install -y python311 py311-pip py311-aiosqlite py311-cryptography py311-pyyaml py311-aiohttp py311-sqlalchemy20 py311-alembic py311-websockets

    # Step 3: Create required directories
    echo "Creating required directories..."
    mkdir -p /usr/local/lib/sysmanage-agent
    mkdir -p /usr/local/etc/sysmanage-agent
    mkdir -p /var/log/sysmanage-agent
    mkdir -p /var/run/sysmanage
    mkdir -p /etc/sysmanage-agent
    mkdir -p /var/lib/sysmanage-agent

    # Step 4: Download and install agent
    echo "Fetching latest agent version from GitHub..."
    LATEST=$(fetch -q -o - https://api.github.com/repos/bceverly/sysmanage-agent/releases/latest | grep -o '"tag_name": *"[^"]*"' | grep -o 'v[0-9.]*')
    VERSION=${{LATEST#v}}
    echo "Latest version: ${{VERSION}}"

    echo "Downloading agent package..."
    fetch -o /tmp/sysmanage-agent-${{VERSION}}.pkg "https://github.com/bceverly/sysmanage-agent/releases/download/${{LATEST}}/sysmanage-agent-${{VERSION}}.pkg"

    echo "Installing agent package..."
    pkg add /tmp/sysmanage-agent-${{VERSION}}.pkg || true
    cd / && tar -xf /tmp/sysmanage-agent-${{VERSION}}.pkg --include='usr/*'
    rm -f /tmp/sysmanage-agent-${{VERSION}}.pkg

    # Step 5: Write agent configuration
    echo "Writing agent configuration..."
    cat > /etc/sysmanage-agent.yaml << 'AGENT_CONFIG_EOF'
{agent_config_escaped}
AGENT_CONFIG_EOF

    ln -sf /etc/sysmanage-agent.yaml /usr/local/etc/sysmanage-agent/config.yaml

    # Step 6: Sync time before starting agent (prevents message timestamp errors)
    echo "Syncing system time..."
    ntpdate -u pool.ntp.org || ntpdate -u time.nist.gov || true

    # Step 7: Enable and start the agent service
    echo "Enabling sysmanage-agent service..."
    sysrc sysmanage_agent_enable=YES
    sysrc sysmanage_agent_user=root

    echo "Starting sysmanage-agent service..."
    service sysmanage_agent start

    echo "=== SysManage Agent First Boot Setup Complete ==="
}}

load_rc_config $name
run_rc_command "$1"
"""

    def inject_firstboot_into_image(
        self, config: BhyveVmConfig, disk_path: str
    ) -> Dict[str, Any]:
        """
        Inject firstboot script, user, and hostname into FreeBSD raw image.

        This mounts the raw disk image, adds:
        - The user with password hash
        - The hostname configuration
        - A firstboot rc.d script to install the agent
        - The /firstboot sentinel file to enable firstboot

        Args:
            config: VM configuration
            disk_path: Path to the raw disk image

        Returns:
            Dict with success status
        """
        mount_point = None
        md_unit = None

        try:
            self.logger.info(_("Injecting firstboot script into FreeBSD image"))

            # Create a temporary mount point
            mount_point = tempfile.mkdtemp(prefix="bhyve_freebsd_mount_")

            # Attach the raw image as a memory disk
            self.logger.info(_("Attaching disk image as memory disk"))
            md_result = subprocess.run(  # nosec B603 B607
                ["mdconfig", "-a", "-t", "vnode", "-f", disk_path],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )

            if md_result.returncode != 0:
                return {
                    "success": False,
                    "error": _("Failed to attach memory disk: %s") % md_result.stderr,
                }

            md_unit = md_result.stdout.strip()  # e.g., "md0"
            self._md_device = md_unit
            self.logger.info(_("Attached as %s"), md_unit)

            # Mount the UFS partition (typically partition 4 on FreeBSD images)
            # Try different partition schemes
            mounted = False
            for partition in ["p4", "p3", "p2", "s1a", "a", ""]:
                dev_path = f"/dev/{md_unit}{partition}"
                if not os.path.exists(dev_path) and partition:
                    continue

                self.logger.info(_("Trying to mount %s"), dev_path)
                mount_result = subprocess.run(  # nosec B603 B607
                    ["mount", "-t", "ufs", dev_path, mount_point],
                    capture_output=True,
                    text=True,
                    timeout=30,
                    check=False,
                )

                if mount_result.returncode == 0:
                    mounted = True
                    self.logger.info(_("Mounted %s successfully"), dev_path)
                    break

            if not mounted:
                return {
                    "success": False,
                    "error": _("Failed to mount FreeBSD partition"),
                }

            # Verify this is a FreeBSD root filesystem
            if not os.path.exists(os.path.join(mount_point, "etc", "rc.conf")):
                subprocess.run(  # nosec B603 B607
                    ["umount", mount_point], check=False, timeout=30
                )
                return {
                    "success": False,
                    "error": _("Mounted filesystem is not a FreeBSD root"),
                }

            # 1. Set hostname
            self.logger.info(_("Setting hostname to %s"), config.hostname)
            rc_conf_path = os.path.join(mount_point, "etc", "rc.conf")
            with open(rc_conf_path, "a", encoding="utf-8") as rc_file:
                rc_file.write(f'\nhostname="{config.hostname}"\n')

            # 2. Create user with password hash
            self.logger.info(_("Creating user %s"), config.username)

            # Add user to master.passwd
            master_passwd_path = os.path.join(mount_point, "etc", "master.passwd")

            # Read existing master.passwd to get next UID
            with open(master_passwd_path, "r", encoding="utf-8") as mpf:
                master_passwd_lines = mpf.readlines()

            # Find max UID and add new user
            max_uid = 1000
            for line in master_passwd_lines:
                parts = line.split(":")
                if len(parts) >= 3:
                    try:
                        uid = int(parts[2])
                        if 1000 <= uid < 65000:
                            max_uid = max(max_uid, uid)
                    except ValueError:
                        pass

            new_uid = max_uid + 1
            # Format: username:password:uid:gid:class:change:expire:gecos:home:shell
            # Note: class field should be empty (not "wheel" - that's for group membership)
            # gid 0 is wheel group
            user_line = (
                f"{config.username}:{config.password_hash}:{new_uid}:0:"
                f":0:0:{config.username} User:/home/{config.username}:/bin/sh\n"
            )

            with open(master_passwd_path, "a", encoding="utf-8") as mpf:
                mpf.write(user_line)

            # Rebuild password database using pwd_mkdb
            # -d specifies output directory for pwd.db/spwd.db (must be /etc)
            # -p creates a Version 7 format passwd file
            etc_dir = os.path.join(mount_point, "etc")
            pwd_result = subprocess.run(  # nosec B603 B607
                ["pwd_mkdb", "-d", etc_dir, "-p", master_passwd_path],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )

            if pwd_result.returncode != 0:
                self.logger.warning(_("pwd_mkdb warning: %s"), pwd_result.stderr)
            else:
                self.logger.info(_("Password database rebuilt successfully"))

            # Create home directory
            home_dir = os.path.join(mount_point, "home", config.username)
            os.makedirs(home_dir, mode=0o755, exist_ok=True)

            # 3. Add user to wheel group in /etc/group
            group_path = os.path.join(mount_point, "etc", "group")
            with open(group_path, "r", encoding="utf-8") as group_file:
                group_lines = group_file.readlines()

            with open(group_path, "w", encoding="utf-8") as group_file:
                for line in group_lines:
                    if line.startswith("wheel:"):
                        line = line.rstrip()
                        if line.endswith(":"):
                            line = f"{line}{config.username}\n"
                        else:
                            line = f"{line},{config.username}\n"
                    group_file.write(line)

            # 4. Create firstboot rc.d script
            self.logger.info(_("Creating firstboot script"))
            rcd_path = os.path.join(mount_point, "etc", "rc.d")
            firstboot_script_path = os.path.join(rcd_path, "sysmanage_firstboot")

            firstboot_script = self._generate_firstboot_script(config)
            with open(firstboot_script_path, "w", encoding="utf-8") as fbf:
                fbf.write(firstboot_script)
            # Make firstboot script executable - must be 755 to run as rc.d script
            # nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions
            os.chmod(
                firstboot_script_path, 0o755
            )  # nosec B103  # NOSONAR - permissions are appropriate for this file type

            # 5. Create /firstboot sentinel file to enable firstboot scripts
            firstboot_sentinel = os.path.join(mount_point, "firstboot")
            with open(firstboot_sentinel, "w", encoding="utf-8") as fsf:
                fsf.write("")

            # 6. Enable firstboot and our script in rc.conf
            with open(rc_conf_path, "a", encoding="utf-8") as rc_file:
                rc_file.write('firstboot_sentinel="/firstboot"\n')
                rc_file.write('sysmanage_firstboot_enable="YES"\n')
                # Also enable sshd for remote access
                rc_file.write('sshd_enable="YES"\n')
                # Enable NTP with sync-on-start to fix time drift issues
                rc_file.write('ntpd_enable="YES"\n')
                rc_file.write('ntpd_sync_on_start="YES"\n')

            self.logger.info(_("Firstboot injection complete"))

            # Unmount
            subprocess.run(  # nosec B603 B607
                ["umount", mount_point],
                capture_output=True,
                timeout=30,
                check=False,
            )

            # Detach memory disk
            subprocess.run(  # nosec B603 B607
                ["mdconfig", "-d", "-u", md_unit],
                capture_output=True,
                timeout=30,
                check=False,
            )
            self._md_device = None

            return {"success": True}

        except Exception as err:
            self.logger.error(_("Error injecting firstboot: %s"), err)

            # Cleanup on error
            if mount_point:
                subprocess.run(  # nosec B603 B607
                    ["umount", mount_point],
                    capture_output=True,
                    timeout=30,
                    check=False,
                )
                shutil.rmtree(mount_point, ignore_errors=True)

            if md_unit:
                subprocess.run(  # nosec B603 B607
                    ["mdconfig", "-d", "-u", md_unit],
                    capture_output=True,
                    timeout=30,
                    check=False,
                )

            return {"success": False, "error": str(err)}

        finally:
            if mount_point and os.path.exists(mount_point):
                shutil.rmtree(mount_point, ignore_errors=True)

    def _generate_ssh_keypair(self, vm_name: str) -> Dict[str, Any]:
        """
        Generate a temporary SSH key pair for bootstrap automation.

        Args:
            vm_name: VM name (used for key comment)

        Returns:
            Dict with success status and key paths
        """
        try:
            key_dir = tempfile.mkdtemp(prefix="bhyve_freebsd_ssh_")
            key_path = os.path.join(key_dir, "bootstrap_key")

            result = subprocess.run(  # nosec B603 B607
                [
                    "ssh-keygen",
                    "-t",
                    "ed25519",
                    "-f",
                    key_path,
                    "-N",
                    "",
                    "-C",
                    f"sysmanage-bhyve-bootstrap-{vm_name}",
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

            pub_key_path = f"{key_path}.pub"
            with open(pub_key_path, "r", encoding="utf-8") as pub_key_file:
                public_key = pub_key_file.read().strip()

            self._ssh_private_key_path = key_path
            self._ssh_public_key = public_key
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

    def _generate_user_data(self, config: BhyveVmConfig) -> str:
        """
        Generate nuageinit-compatible user-data for FreeBSD.

        Note: FreeBSD's nuageinit only supports a subset of cloud-init:
        - hostname, users, ssh_pwauth, network configuration
        - It does NOT support write_files or runcmd
        - Agent installation is handled via bootstrap.sh script

        Args:
            config: VM configuration

        Returns:
            User-data content in cloud-config format
        """
        ssh_keys_section = ""
        if self._ssh_public_key:
            ssh_keys_section = f"""    ssh_authorized_keys:
      - {self._ssh_public_key}
"""

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

    def _generate_bootstrap_script(self, config: BhyveVmConfig) -> str:
        """
        Generate bootstrap script for FreeBSD agent installation.

        Since nuageinit doesn't support write_files or runcmd, we create
        a bootstrap script that can be run after VM boot to install the agent.

        Args:
            config: VM configuration

        Returns:
            Shell script content
        """
        os_type = "freebsd"
        agent_config = generate_agent_config(
            hostname=config.server_url,
            port=config.server_port,
            use_https=config.use_https,
            os_type=os_type,
            auto_approve_token=config.auto_approve_token,
            verify_ssl=False,
        )

        return f"""#!/bin/sh
# FreeBSD sysmanage-agent bootstrap script for bhyve
# Run this script as root after VM boot to install the agent
# Usage: sh /mnt/cidata/bootstrap.sh (as root)

set -e

USERNAME="{config.username}"

echo "=== FreeBSD sysmanage-agent Bootstrap (bhyve) ==="

# Step 1: Install sudo and configure user
echo "Installing sudo and configuring user access..."
pkg install -y sudo

echo "$USERNAME ALL=(ALL) NOPASSWD: ALL" > /usr/local/etc/sudoers.d/$USERNAME
chmod 440 /usr/local/etc/sudoers.d/$USERNAME
echo "User $USERNAME added to sudoers with NOPASSWD access."

# Step 2: Install Python and all agent dependencies
echo "Installing Python 3.11 and agent dependencies..."
pkg install -y python311 py311-pip py311-aiosqlite py311-cryptography py311-pyyaml py311-aiohttp py311-sqlalchemy20 py311-alembic py311-websockets

# Step 3: Create required directories
echo "Creating required directories..."
mkdir -p /usr/local/lib/sysmanage-agent
mkdir -p /usr/local/etc/sysmanage-agent
mkdir -p /var/log/sysmanage-agent
mkdir -p /var/run/sysmanage
mkdir -p /etc/sysmanage-agent
mkdir -p /var/lib/sysmanage-agent
mkdir -p /usr/local/etc/rc.d

# Step 4: Download and install agent from FreeBSD package
echo "Fetching latest version from GitHub..."
LATEST=$(fetch -q -o - https://api.github.com/repos/bceverly/sysmanage-agent/releases/latest | grep -o '"tag_name": *"[^"]*"' | grep -o 'v[0-9.]*')
VERSION=${{LATEST#v}}
echo "Latest version: ${{VERSION}}"

echo "Downloading agent package..."
fetch -o /tmp/sysmanage-agent-${{VERSION}}.pkg "https://github.com/bceverly/sysmanage-agent/releases/download/${{LATEST}}/sysmanage-agent-${{VERSION}}.pkg"

echo "Installing agent package..."
pkg add /tmp/sysmanage-agent-${{VERSION}}.pkg || true

echo "Extracting package files..."
cd / && tar -xf /tmp/sysmanage-agent-${{VERSION}}.pkg --include='usr/*'

rm -f /tmp/sysmanage-agent-${{VERSION}}.pkg

# Step 5: Write agent configuration
echo "Creating agent configuration..."
cat > /etc/sysmanage-agent.yaml << 'AGENT_CONFIG_EOF'
{agent_config}AGENT_CONFIG_EOF

ln -sf /etc/sysmanage-agent.yaml /usr/local/etc/sysmanage-agent/config.yaml

# Step 6: Sync time before starting agent (prevents message timestamp errors)
echo "Syncing system time..."
ntpdate -u pool.ntp.org || ntpdate -u time.nist.gov || true

# Step 7: Enable and start the agent service
echo "Enabling and starting sysmanage-agent service..."
sysrc sysmanage_agent_enable=YES
sysrc sysmanage_agent_user=root
service sysmanage_agent restart 2>/dev/null || service sysmanage_agent start

echo ""
echo "=== Bootstrap complete ==="
echo "The sysmanage-agent should now be running."
echo "Check status with: service sysmanage_agent status"
"""

    def _generate_meta_data(self, config: BhyveVmConfig) -> str:
        """Generate cloud-init compatible meta-data."""
        return f"""instance-id: {config.vm_name}
local-hostname: {config.hostname.split('.')[0]}
"""

    def create_config_disk(
        self, config: BhyveVmConfig, disk_dir: str
    ) -> Dict[str, Any]:
        """
        Create a config disk ISO with cloud-init files and bootstrap script.

        The ISO contains:
        - user-data: Cloud-init user configuration (handled by nuageinit)
        - meta-data: Instance metadata
        - bootstrap.sh: Agent installation script (run via SSH after boot)

        Args:
            config: VM configuration
            disk_dir: Directory to create the disk in

        Returns:
            Dict with success status and disk path
        """
        try:
            self.logger.info(_("Creating FreeBSD config disk for bhyve"))

            temp_dir = tempfile.mkdtemp(prefix="bhyve_freebsd_config_")

            try:
                user_data = self._generate_user_data(config)
                meta_data = self._generate_meta_data(config)
                bootstrap_script = self._generate_bootstrap_script(config)

                user_data_path = os.path.join(temp_dir, "user-data")
                meta_data_path = os.path.join(temp_dir, "meta-data")
                bootstrap_path = os.path.join(temp_dir, "bootstrap.sh")

                # These files contain configuration data (including hashed passwords)
                # that must be written to create the cloud-init ISO for VM provisioning.
                # The temp directory is cleaned up after ISO creation.
                # CodeQL: This is intentional - cloud-init requires these files to provision VMs.
                # The password is already hashed and the temp directory is cleaned up after use.
                with open(user_data_path, "w", encoding="utf-8") as udf:  # noqa: S324
                    # codeql[py/clear-text-storage-sensitive-data] - Intentional: cloud-init requires this file, password is pre-hashed, temp dir cleaned after use
                    udf.write(user_data)  # nosec B105
                with open(meta_data_path, "w", encoding="utf-8") as mdf:
                    mdf.write(meta_data)
                with open(bootstrap_path, "w", encoding="utf-8") as bsf:
                    bsf.write(bootstrap_script)
                # Make bootstrap script executable - must be 755 to run as shell script
                # nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions
                os.chmod(
                    bootstrap_path, 0o755
                )  # nosec B103  # NOSONAR - permissions are appropriate for this file type

                self._config_disk_path = os.path.join(
                    disk_dir, f"{config.vm_name}-freebsd-config.iso"
                )

                # Use makefs on FreeBSD (native tool)
                result = subprocess.run(  # nosec B603 B607
                    [
                        "makefs",
                        "-t",
                        "cd9660",
                        "-o",
                        "rockridge",
                        "-o",
                        "label=cidata",
                        self._config_disk_path,
                        temp_dir,
                    ],
                    capture_output=True,
                    text=True,
                    timeout=60,
                    check=False,
                )

                if result.returncode != 0:
                    return {
                        "success": False,
                        "error": _("Failed to create config ISO: %s") % result.stderr,
                    }

                self.logger.info(
                    _("Created FreeBSD config disk: %s"), self._config_disk_path
                )
                return {
                    "success": True,
                    "config_disk_path": self._config_disk_path,
                }

            finally:
                shutil.rmtree(temp_dir, ignore_errors=True)

        except Exception as err:
            self.logger.error(_("Error creating config disk: %s"), err)
            return {"success": False, "error": str(err)}

    def provision(
        self, config: BhyveVmConfig, disk_path: str, _disk_dir: str
    ) -> Dict[str, Any]:
        """
        Provision FreeBSD by injecting firstboot scripts into the disk image.

        This injects the user, hostname, and firstboot script directly into
        the raw disk image so that everything is configured on first boot
        without needing nuageinit/cloud-init.

        Args:
            config: VM configuration
            disk_path: Path to the raw disk image
            _disk_dir: Directory for config disk (unused, kept for API compatibility)

        Returns:
            Dict with success status
        """
        try:
            self.logger.info(
                _("Provisioning FreeBSD for bhyve via firstboot injection")
            )

            self._bootstrap_username = config.username

            # Inject firstboot script, user, and hostname into the disk image
            inject_result = self.inject_firstboot_into_image(config, disk_path)
            if not inject_result.get("success"):
                return inject_result

            self.logger.info(_("FreeBSD provisioning complete"))
            return {
                "success": True,
                "provisioning_method": "firstboot_injection",
            }

        except Exception as err:
            self.logger.error(_("Error provisioning FreeBSD: %s"), err)
            return {"success": False, "error": str(err)}

    async def run_bootstrap_via_ssh(
        self, ip_address: str, timeout: int = 600
    ) -> Dict[str, Any]:
        """
        Run the FreeBSD bootstrap script via SSH.

        SSHs into the VM as the regular user using the temporary key pair,
        then uses 'su' with the temporary root password to mount the config
        disk and run the bootstrap script.

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
                "error": _("No temporary root password available"),
            }

        try:
            self.logger.info(_("Running FreeBSD bootstrap via SSH on %s"), ip_address)

            # Wait for nuageinit to complete
            self.logger.info(_("Waiting 30 seconds for nuageinit to complete..."))
            await asyncio.sleep(30)

            # Test SSH key auth
            self.logger.info(
                _("Testing SSH key authentication as %s..."), self._bootstrap_username
            )

            for attempt in range(3):
                test_result = await run_command_async(
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
                    timeout=30,
                )

                if test_result.returncode == 0:
                    break

                self.logger.warning(
                    _("SSH auth failed (attempt %d), retrying in 30s..."), attempt + 1
                )
                await asyncio.sleep(30)
            else:
                return {
                    "success": False,
                    "error": _("SSH key authentication failed after retries"),
                }

            self.logger.info(_("SSH key authentication successful"))

            # Run bootstrap via SSH with su
            root_commands = """
set -e
if [ ! -d /mnt/cidata ]; then
    mkdir -p /mnt/cidata
fi
mount -t cd9660 /dev/cd0 /mnt/cidata 2>/dev/null || mount -t cd9660 /dev/cd1 /mnt/cidata 2>/dev/null || true
if [ -f /mnt/cidata/bootstrap.sh ]; then
    sh /mnt/cidata/bootstrap.sh
    exit $?
else
    echo "ERROR: bootstrap.sh not found on config disk"
    exit 1
fi
"""

            # Use expect-style approach with sshpass for su password
            # First check if sshpass is available
            if not shutil.which("sshpass"):
                # Try password-based SSH directly to root if PermitRootLogin is enabled
                self.logger.info(_("Trying SSH as root with password..."))
                bootstrap_result = await run_command_async(
                    [
                        "ssh",
                        "-o",
                        "StrictHostKeyChecking=no",
                        "-o",
                        "UserKnownHostsFile=/dev/null",
                        "-o",
                        "ConnectTimeout=30",
                        f"root@{ip_address}",
                        root_commands,
                    ],
                    timeout=timeout,
                    input_data=self._temp_root_password + "\n",
                )
            else:
                # Use sshpass with su
                self.logger.info(_("Running bootstrap via sshpass + su..."))
                su_command = f"echo '{self._temp_root_password}' | su -m root -c '{root_commands}'"
                bootstrap_result = await run_command_async(
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
                        "-t",
                        "-t",
                        f"{self._bootstrap_username}@{ip_address}",
                        su_command,
                    ],
                    timeout=timeout,
                )

            if bootstrap_result.returncode != 0:
                self.logger.error(
                    _("Bootstrap failed: stdout=%s, stderr=%s"),
                    bootstrap_result.stdout,
                    bootstrap_result.stderr,
                )
                return {
                    "success": False,
                    "error": _("Bootstrap script failed"),
                    "stdout": bootstrap_result.stdout,
                    "stderr": bootstrap_result.stderr,
                }

            self.logger.info(_("FreeBSD bootstrap completed successfully"))
            return {"success": True, "stdout": bootstrap_result.stdout}

        except subprocess.TimeoutExpired:
            self.logger.error(_("SSH bootstrap timed out"))
            return {"success": False, "error": _("SSH bootstrap timed out")}
        except Exception as err:
            self.logger.error(_("Error running bootstrap via SSH: %s"), err)
            return {"success": False, "error": str(err)}

    def get_config_disk_path(self) -> Optional[str]:
        """Get the path to the config disk if created."""
        return self._config_disk_path

    def has_ssh_key(self) -> bool:
        """Check if SSH key is available for automated bootstrap."""
        return self._ssh_private_key_path is not None

    def cleanup(self):
        """Clean up any created resources."""
        if self._config_disk_path and os.path.exists(self._config_disk_path):
            try:
                os.remove(self._config_disk_path)
            except OSError:
                pass
        self._config_disk_path = None

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
