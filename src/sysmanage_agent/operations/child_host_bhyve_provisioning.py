"""
bhyve VM provisioning helpers for FreeBSD hosts.

This module contains helper functions for provisioning bhyve VMs:
- Cloud-init ISO creation
- bhyve command generation
- VM startup (bhyveload for FreeBSD, UEFI for Linux)
"""

import os
import subprocess  # nosec B404 # needed for sync disk/network operations
from typing import Any, Dict, List

from src.i18n import _
from src.sysmanage_agent.operations.child_host_bhyve_types import BhyveVmConfig
from src.sysmanage_agent.operations.child_host_config_generator import (
    generate_agent_config,
    generate_cloudinit_userdata,
)

# Default paths for bhyve cloud-init
BHYVE_CLOUDINIT_DIR = "/vm/cloud-init"


class BhyveProvisioningHelper:
    """Helper class for bhyve VM provisioning operations."""

    def __init__(self, logger):
        """
        Initialize the provisioning helper.

        Args:
            logger: Logger instance
        """
        self.logger = logger

    def get_nmdm_id(self, vm_name: str) -> int:
        """
        Get the nmdm device ID for a VM.

        Uses a hash of the VM name to generate a consistent device ID.

        Args:
            vm_name: Name of the VM

        Returns:
            nmdm device ID (0-999)
        """
        return abs(hash(vm_name)) % 1000

    def get_console_device(self, vm_name: str) -> str:
        """
        Get the console device path for a VM.

        Returns the user-accessible side of the nmdm pair (/dev/nmdmNB).
        Connect using: cu -l /dev/nmdmNB -s 115200

        Args:
            vm_name: Name of the VM

        Returns:
            Path to the console device (e.g., /dev/nmdm42B)
        """
        nmdm_id = self.get_nmdm_id(vm_name)
        return f"/dev/nmdm{nmdm_id}B"

    def is_linux_guest(self, config: BhyveVmConfig) -> bool:
        """
        Check if the distribution is a Linux guest.

        Linux guests need UEFI boot with grub2-bhyve or native UEFI.
        FreeBSD guests can use bhyveload directly.

        Args:
            config: VM configuration

        Returns:
            True if Linux guest, False if FreeBSD or other
        """
        distro = config.distribution.lower() if config.distribution else ""
        linux_distros = [
            "ubuntu",
            "debian",
            "fedora",
            "centos",
            "rhel",
            "rocky",
            "alma",
            "alpine",
            "arch",
            "opensuse",
            "suse",
            "linux",
        ]
        return any(d in distro for d in linux_distros)

    def create_cloud_init_iso(self, config: BhyveVmConfig) -> Dict[str, Any]:
        """
        Create a cloud-init ISO for VM configuration.

        Args:
            config: VM configuration

        Returns:
            Dict with success status and ISO path
        """
        try:
            iso_dir = os.path.join(BHYVE_CLOUDINIT_DIR, config.vm_name)
            os.makedirs(iso_dir, mode=0o755, exist_ok=True)

            # Create meta-data
            meta_data = f"""instance-id: {config.vm_name}
local-hostname: {config.hostname}
"""
            meta_data_path = os.path.join(iso_dir, "meta-data")
            with open(meta_data_path, "w", encoding="utf-8") as meta_file:
                meta_file.write(meta_data)

            # Build agent install commands as runcmd entries
            runcmd_lines = []
            # Always start with apt-get update to ensure fresh package lists
            runcmd_lines.append("  - 'apt-get update'")
            for cmd in config.agent_install_commands:
                # Escape single quotes for YAML single-quoted strings (double them)
                escaped_cmd = cmd.replace("'", "''")
                runcmd_lines.append(f"  - '{escaped_cmd}'")

            runcmd_section = "\n".join(runcmd_lines) if runcmd_lines else ""

            # Determine OS type from the image for config generation
            # Default to ubuntu for Linux images
            os_type = "ubuntu"
            if config.cloud_image_url:
                url_lower = config.cloud_image_url.lower()
                if "debian" in url_lower:
                    os_type = "debian"
                elif "alpine" in url_lower:
                    os_type = "alpine"
                elif "freebsd" in url_lower:
                    os_type = "freebsd"

            # Generate the complete agent configuration using unified generator
            agent_config = generate_agent_config(
                hostname=config.server_url,
                port=config.server_port,
                use_https=config.use_https,
                os_type=os_type,
                auto_approve_token=config.auto_approve_token,
                verify_ssl=False,
            )

            # Generate cloud-init user-data using unified generator
            user_data = generate_cloudinit_userdata(
                hostname=config.hostname,
                username=config.username,
                password_hash=config.password_hash,
                os_type=os_type,
                agent_config=agent_config,
                auto_approve_token=config.auto_approve_token,
            )

            if runcmd_section:
                user_data += f"""
runcmd:
{runcmd_section}
"""

            user_data_path = os.path.join(iso_dir, "user-data")
            with open(user_data_path, "w", encoding="utf-8") as user_file:
                user_file.write(user_data)

            # Create ISO using makefs (FreeBSD) or genisoimage
            iso_path = os.path.join(BHYVE_CLOUDINIT_DIR, f"{config.vm_name}.iso")
            config.cloud_init_iso_path = iso_path

            # Try makefs first (native FreeBSD)
            result = subprocess.run(  # nosec B603 B607
                [
                    "makefs",
                    "-t",
                    "cd9660",
                    "-o",
                    "rockridge",
                    "-o",
                    "label=cidata",
                    iso_path,
                    iso_dir,
                ],
                capture_output=True,
                text=True,
                timeout=60,
                check=False,
            )

            if result.returncode != 0:
                # Try genisoimage as fallback
                result = subprocess.run(  # nosec B603 B607
                    [
                        "genisoimage",
                        "-output",
                        iso_path,
                        "-volid",
                        "cidata",
                        "-joliet",
                        "-rock",
                        iso_dir,
                    ],
                    capture_output=True,
                    text=True,
                    timeout=60,
                    check=False,
                )
                if result.returncode != 0:
                    return {
                        "success": False,
                        "error": _("Failed to create cloud-init ISO: %s")
                        % result.stderr,
                    }

            self.logger.info(_("Created cloud-init ISO: %s"), iso_path)
            return {"success": True, "path": iso_path}

        except Exception as error:
            return {"success": False, "error": str(error)}

    def generate_bhyve_command(
        self, config: BhyveVmConfig, tap_interface: str, use_nmdm: bool = True
    ) -> List[str]:
        """
        Generate the bhyve command line for starting a VM.

        Args:
            config: VM configuration
            tap_interface: Name of the tap interface for networking
            use_nmdm: If True, use nmdm (null modem) for console (for daemonized VMs).
                      If False, use stdio (for interactive/foreground VMs).

        Returns:
            List of command arguments for bhyve
        """
        memory_mb = config.get_memory_mb()

        # Determine console device
        # When running daemonized via daemon(8), we can't use stdio
        # Use nmdm (null modem device pair) instead - /dev/nmdm{N}A for bhyve,
        # /dev/nmdm{N}B for console access via cu(1)
        if use_nmdm:
            nmdm_id = self.get_nmdm_id(config.vm_name)
            console_device = f"/dev/nmdm{nmdm_id}A"
        else:
            console_device = "stdio"

        cmd = [
            "bhyve",
            "-A",  # Generate ACPI tables
            "-H",  # Yield CPU on HLT
            "-P",  # Exit on PAUSE
            "-s",
            "0:0,hostbridge",  # Host bridge
            "-s",
            "1:0,lpc",  # LPC bridge for console
            "-s",
            f"2:0,virtio-net,{tap_interface}",  # Network
            "-s",
            f"3:0,virtio-blk,{config.disk_path}",  # Main disk
            "-l",
            f"com1,{console_device}",  # Serial console
            "-c",
            str(config.cpus),
            "-m",
            f"{memory_mb}M",
        ]

        # Add cloud-init ISO if present
        if config.cloud_init_iso_path and os.path.exists(config.cloud_init_iso_path):
            cmd.extend(["-s", f"4:0,ahci-cd,{config.cloud_init_iso_path}"])

        # Add UEFI firmware for Linux guests or if explicitly requested
        if config.use_uefi or self.is_linux_guest(config):
            uefi_firmware = "/usr/local/share/uefi-firmware/BHYVE_UEFI.fd"
            if os.path.exists(uefi_firmware):
                cmd.extend(["-l", f"bootrom,{uefi_firmware}"])

        cmd.append(config.vm_name)
        return cmd

    def start_vm_with_bhyveload(
        self, config: BhyveVmConfig, tap_interface: str
    ) -> Dict[str, Any]:
        """
        Start a FreeBSD VM using bhyveload.

        Args:
            config: VM configuration
            tap_interface: Name of the tap interface

        Returns:
            Dict with success status
        """
        try:
            # Load the FreeBSD kernel
            self.logger.info(_("Loading FreeBSD kernel with bhyveload"))
            result = subprocess.run(  # nosec B603 B607
                [
                    "bhyveload",
                    "-m",
                    f"{config.get_memory_mb()}M",
                    "-d",
                    config.disk_path,
                    config.vm_name,
                ],
                capture_output=True,
                text=True,
                timeout=120,
                check=False,
            )

            if result.returncode != 0:
                return {
                    "success": False,
                    "error": _("bhyveload failed: %s") % result.stderr,
                }

            # Start bhyve in background
            bhyve_cmd = self.generate_bhyve_command(config, tap_interface)

            # Use daemon to run bhyve in background
            daemon_cmd = ["daemon", "-p", f"/var/run/bhyve.{config.vm_name}.pid"]
            daemon_cmd.extend(bhyve_cmd)

            result = subprocess.run(  # nosec B603 B607
                daemon_cmd,
                capture_output=True,
                text=True,
                timeout=180,  # 3 minutes for UEFI firmware initialization
                check=False,
            )

            if result.returncode != 0:
                return {
                    "success": False,
                    "error": _("Failed to start bhyve: %s") % result.stderr,
                }

            return {"success": True}

        except Exception as error:
            return {"success": False, "error": str(error)}

    def start_vm_with_uefi(
        self, config: BhyveVmConfig, tap_interface: str
    ) -> Dict[str, Any]:
        """
        Start a VM using UEFI boot (for Linux guests).

        Args:
            config: VM configuration
            tap_interface: Name of the tap interface

        Returns:
            Dict with success status
        """
        try:
            # Generate bhyve command with UEFI
            bhyve_cmd = self.generate_bhyve_command(config, tap_interface)

            # Use daemon to run bhyve in background
            daemon_cmd = ["daemon", "-p", f"/var/run/bhyve.{config.vm_name}.pid"]
            daemon_cmd.extend(bhyve_cmd)

            self.logger.info(_("Starting VM with UEFI boot: %s"), config.vm_name)
            result = subprocess.run(  # nosec B603 B607
                daemon_cmd,
                capture_output=True,
                text=True,
                timeout=180,  # 3 minutes for UEFI firmware initialization
                check=False,
            )

            if result.returncode != 0:
                return {
                    "success": False,
                    "error": _("Failed to start bhyve: %s") % result.stderr,
                }

            return {"success": True}

        except Exception as error:
            return {"success": False, "error": str(error)}
