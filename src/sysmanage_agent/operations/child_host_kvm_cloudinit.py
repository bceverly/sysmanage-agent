"""KVM/libvirt cloud-init ISO generation for VM provisioning."""

import os
import shutil
import subprocess  # nosec B404 # Required for ISO creation commands
import tempfile
import time
from typing import Any, Dict

from src.i18n import _
from src.sysmanage_agent.operations.child_host_kvm_dns import get_host_dns_servers
from src.sysmanage_agent.operations.child_host_kvm_types import KvmVmConfig

# Default path for cloud-init ISOs
KVM_CLOUDINIT_DIR = "/var/lib/libvirt/cloud-init"


class KvmCloudInit:
    """Cloud-init ISO generation for KVM VMs."""

    def __init__(self, logger):
        """
        Initialize cloud-init generator.

        Args:
            logger: Logger instance
        """
        self.logger = logger

    def _is_freebsd(self, config: KvmVmConfig) -> bool:
        """
        Check if the distribution is FreeBSD.

        Args:
            config: VM configuration

        Returns:
            True if FreeBSD, False otherwise
        """
        dist_lower = config.distribution.lower()
        return "freebsd" in dist_lower or "bsd" in dist_lower

    def generate_meta_data(self, config: KvmVmConfig) -> str:
        """
        Generate cloud-init meta-data.

        Args:
            config: VM configuration

        Returns:
            meta-data content as string
        """
        instance_id = f"{config.vm_name}-{int(time.time())}"
        return f"""instance-id: {instance_id}
local-hostname: {config.hostname}
"""

    def _indent_content(self, content: str, spaces: int) -> str:
        """
        Indent each line of content by the specified number of spaces.

        Args:
            content: Multi-line string content
            spaces: Number of spaces to indent

        Returns:
            Indented content
        """
        indent = " " * spaces
        lines = content.strip().split("\n")
        return "\n".join(indent + line if line.strip() else "" for line in lines)

    def _generate_freebsd_user_data(self, config: KvmVmConfig) -> str:
        """
        Generate FreeBSD-specific cloud-init user-data.

        FreeBSD cloud images support cloud-init but need BSD-specific configuration:
        - Uses /bin/sh instead of /bin/bash
        - Uses sysrc and service instead of systemctl
        - Uses pkg for package management

        Args:
            config: VM configuration

        Returns:
            user-data content as string (cloud-config YAML)
        """
        # Get host DNS servers for the VM
        dns_servers = get_host_dns_servers(self.logger)

        # Build bootcmd section to configure DNS early
        bootcmd_lines = []
        bootcmd_lines.append(
            f"  - echo 'nameserver {dns_servers[0]}' > /etc/resolv.conf"
        )
        if len(dns_servers) > 1:
            for dns in dns_servers[1:]:
                bootcmd_lines.append(f"  - echo 'nameserver {dns}' >> /etc/resolv.conf")
        bootcmd_section = "\n".join(bootcmd_lines)

        # Build runcmd section with agent installation (FreeBSD-specific)
        runcmd_lines = []

        # FreeBSD-specific: ensure pkg is bootstrapped
        runcmd_lines.append("  - env ASSUME_ALWAYS_YES=yes pkg bootstrap")
        runcmd_lines.append("  - pkg update")

        for cmd in config.agent_install_commands:
            # Escape single quotes in commands
            escaped_cmd = cmd.replace("'", "'\"'\"'")
            runcmd_lines.append(f"  - {escaped_cmd}")

        # Build auto_approve section if token provided
        auto_approve_section = ""
        if config.auto_approve_token:
            auto_approve_section = f"""
# Auto-approval token for automatic host approval
auto_approve:
  token: "{config.auto_approve_token}"
"""

        # Build agent config content for write_files module
        agent_config_content = f"""server:
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

# Database configuration
database:
  path: "/var/lib/sysmanage-agent/agent.db"

# Logging configuration
logging:
  level: "INFO|WARNING|ERROR|CRITICAL"
  file: "/var/log/sysmanage-agent/agent.log"
  format: "[%(asctime)s UTC] %(name)s - %(levelname)s - %(message)s"
"""

        # Create directories for database and logs (FreeBSD-specific)
        runcmd_lines.append("  - mkdir -p /var/lib/sysmanage-agent")
        runcmd_lines.append("  - mkdir -p /var/log/sysmanage-agent")
        # FreeBSD uses sysrc and service instead of systemctl
        runcmd_lines.append("  - sysrc sysmanage_agent_enable=YES")
        runcmd_lines.append(
            "  - service sysmanage_agent restart || service sysmanage_agent start"
        )

        runcmd_section = "\n".join(runcmd_lines)

        # Build DNS nameserver list for resolv_conf
        dns_list = "\n".join([f"    - {dns}" for dns in dns_servers])

        # Indent agent config content for write_files block scalar
        indented_agent_config = self._indent_content(agent_config_content, 6)

        return f"""#cloud-config
hostname: {config.hostname}
fqdn: {config.hostname}
manage_etc_hosts: true

# Configure DNS early (before package installation)
bootcmd:
{bootcmd_section}

manage_resolv_conf: true
resolv_conf:
  nameservers:
{dns_list}
  searchdomains:
    - localdomain

users:
  - name: {config.username}
    sudo: ALL=(ALL) NOPASSWD:ALL
    shell: /bin/sh
    lock_passwd: false
    passwd: {config.password_hash}
    groups:
      - wheel

ssh_pwauth: true
disable_root: false

# FreeBSD package management
package_update: true
package_upgrade: false

packages:
  - curl
  - ca_root_nss

write_files:
  - path: /etc/sysmanage-agent.yaml
    owner: root:wheel
    permissions: '0644'
    content: |
{indented_agent_config}

runcmd:
{runcmd_section}

final_message: "Cloud-init completed after $UPTIME seconds"
"""

    def generate_user_data(self, config: KvmVmConfig) -> str:
        """
        Generate cloud-init user-data.

        Automatically detects FreeBSD and generates appropriate configuration.

        Args:
            config: VM configuration

        Returns:
            user-data content as string (cloud-config YAML)
        """
        # Use FreeBSD-specific configuration if applicable
        if self._is_freebsd(config):
            self.logger.info(_("Generating FreeBSD-specific cloud-init configuration"))
            return self._generate_freebsd_user_data(config)

        # Get host DNS servers for the VM
        dns_servers = get_host_dns_servers(self.logger)

        # Build bootcmd section to configure DNS early (before package installation)
        # bootcmd runs before runcmd and before package installation
        bootcmd_lines = []
        bootcmd_lines.append(
            f"  - echo 'nameserver {dns_servers[0]}' > /etc/resolv.conf"
        )
        if len(dns_servers) > 1:
            for dns in dns_servers[1:]:
                bootcmd_lines.append(f"  - echo 'nameserver {dns}' >> /etc/resolv.conf")
        bootcmd_section = "\n".join(bootcmd_lines)

        # Build runcmd section with agent installation
        runcmd_lines = []

        for cmd in config.agent_install_commands:
            # Escape single quotes in commands
            escaped_cmd = cmd.replace("'", "'\"'\"'")
            runcmd_lines.append(f"  - {escaped_cmd}")

        # Build auto_approve section if token provided
        auto_approve_section = ""
        if config.auto_approve_token:
            auto_approve_section = f"""
# Auto-approval token for automatic host approval
auto_approve:
  token: "{config.auto_approve_token}"
"""

        # Build agent config content for write_files module
        agent_config_content = f"""server:
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
    - "bash"
    - "sh"

# Database configuration
database:
  path: "/var/lib/sysmanage-agent/agent.db"

# Logging configuration
logging:
  level: "INFO|WARNING|ERROR|CRITICAL"
  file: "/var/log/sysmanage-agent/agent.log"
  format: "[%(asctime)s UTC] %(name)s - %(levelname)s - %(message)s"
"""

        # Create directories for database and logs
        runcmd_lines.append("  - mkdir -p /var/lib/sysmanage-agent")
        runcmd_lines.append("  - mkdir -p /var/log/sysmanage-agent")
        runcmd_lines.append(
            "  - chown -R sysmanage-agent:sysmanage-agent /var/lib/sysmanage-agent"
        )
        runcmd_lines.append(
            "  - chown -R sysmanage-agent:sysmanage-agent /var/log/sysmanage-agent"
        )
        runcmd_lines.append("  - systemctl daemon-reload")
        runcmd_lines.append("  - systemctl enable sysmanage-agent")
        runcmd_lines.append("  - systemctl restart sysmanage-agent")

        runcmd_section = "\n".join(runcmd_lines)

        # Build DNS nameserver list for resolv_conf
        dns_list = "\n".join([f"    - {dns}" for dns in dns_servers])

        # Indent agent config content for write_files block scalar
        indented_agent_config = self._indent_content(agent_config_content, 6)

        return f"""#cloud-config
hostname: {config.hostname}
fqdn: {config.hostname}
manage_etc_hosts: true

# Configure DNS early (before package installation)
bootcmd:
{bootcmd_section}

manage_resolv_conf: true
resolv_conf:
  nameservers:
{dns_list}
  searchdomains:
    - localdomain

users:
  - name: {config.username}
    sudo: ALL=(ALL) NOPASSWD:ALL
    shell: /bin/bash
    lock_passwd: false
    passwd: {config.password_hash}

ssh_pwauth: true
disable_root: false

package_update: true
package_upgrade: false

packages:
  - curl
  - gnupg
  - ca-certificates

write_files:
  - path: /etc/sysmanage-agent.yaml
    owner: root:root
    permissions: '0644'
    content: |
{indented_agent_config}

runcmd:
{runcmd_section}

final_message: "Cloud-init completed after $UPTIME seconds"
"""

    def create_cloud_init_iso(self, config: KvmVmConfig) -> Dict[str, Any]:
        """
        Create a cloud-init ISO with user-data and meta-data.

        Args:
            config: VM configuration

        Returns:
            Dict with success status and ISO path
        """
        try:
            # Ensure cloud-init directory exists
            os.makedirs(KVM_CLOUDINIT_DIR, mode=0o755, exist_ok=True)

            iso_path = os.path.join(KVM_CLOUDINIT_DIR, f"{config.vm_name}-cidata.iso")

            # Create temporary directory for cloud-init files
            with tempfile.TemporaryDirectory() as tmp_dir:
                # Write meta-data
                meta_data_path = os.path.join(tmp_dir, "meta-data")
                with open(meta_data_path, "w", encoding="utf-8") as meta_file:
                    meta_file.write(self.generate_meta_data(config))

                # Write user-data
                user_data_path = os.path.join(tmp_dir, "user-data")
                with open(user_data_path, "w", encoding="utf-8") as user_file:
                    user_file.write(self.generate_user_data(config))

                self.logger.info(_("Creating cloud-init ISO: %s"), iso_path)

                # Try genisoimage first (Debian/Ubuntu)
                genisoimage = shutil.which("genisoimage")
                mkisofs = shutil.which("mkisofs")
                xorrisofs = shutil.which("xorrisofs")

                if genisoimage:
                    iso_cmd = [
                        "sudo",
                        genisoimage,
                        "-output",
                        iso_path,
                        "-volid",
                        "cidata",
                        "-joliet",
                        "-rock",
                        meta_data_path,
                        user_data_path,
                    ]
                elif mkisofs:
                    iso_cmd = [
                        "sudo",
                        mkisofs,
                        "-o",
                        iso_path,
                        "-V",
                        "cidata",
                        "-J",
                        "-R",
                        meta_data_path,
                        user_data_path,
                    ]
                elif xorrisofs:
                    iso_cmd = [
                        "sudo",
                        xorrisofs,
                        "-o",
                        iso_path,
                        "-V",
                        "cidata",
                        "-J",
                        "-R",
                        meta_data_path,
                        user_data_path,
                    ]
                else:
                    return {
                        "success": False,
                        "error": _(
                            "No ISO creation tool found (genisoimage, mkisofs, or xorrisofs)"
                        ),
                    }

                result = subprocess.run(  # nosec B603 B607
                    iso_cmd,
                    capture_output=True,
                    text=True,
                    timeout=60,
                    check=False,
                )

                if result.returncode != 0:
                    return {
                        "success": False,
                        "error": result.stderr or _("Failed to create cloud-init ISO"),
                    }

            config.cloud_init_iso_path = iso_path
            return {
                "success": True,
                "path": iso_path,
                "message": _("Cloud-init ISO created"),
            }

        except Exception as error:
            self.logger.error(_("Error creating cloud-init ISO: %s"), error)
            return {"success": False, "error": str(error)}
