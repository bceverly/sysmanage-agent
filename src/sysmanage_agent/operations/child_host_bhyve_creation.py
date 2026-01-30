"""
bhyve VM creation helpers for FreeBSD hosts.

This module contains helper functions for creating bhyve VMs:
- Network setup (bridge and tap interfaces)
- VM existence checking
- IP address discovery and SSH waiting

Image handling is in child_host_bhyve_images.py
Provisioning (cloud-init, startup) is in child_host_bhyve_provisioning.py
"""

import asyncio
import os
import socket
import subprocess  # nosec B404 # needed for sync disk/network operations
import time
from typing import Any, Dict, Optional

from src.i18n import _
from src.sysmanage_agent.core.agent_utils import run_command_async
from src.sysmanage_agent.operations.child_host_bhyve_types import BhyveVmConfig

# Import from new modules for delegation
from src.sysmanage_agent.operations.child_host_bhyve_images import (
    BhyveImageHelper,
    BHYVE_IMAGES_DIR,
)
from src.sysmanage_agent.operations.child_host_bhyve_provisioning import (
    BhyveProvisioningHelper,
    BHYVE_CLOUDINIT_DIR,
)

# Re-export metadata functions for backwards compatibility
# pylint: disable=unused-import
from src.sysmanage_agent.operations.child_host_bhyve_metadata import (  # noqa: F401
    BHYVE_METADATA_DIR,
    delete_bhyve_metadata,
    load_bhyve_metadata,
    save_bhyve_metadata,
)

# pylint: enable=unused-import


# Default paths for bhyve
BHYVE_VM_DIR = "/vm"

# Re-export for backwards compatibility
__all__ = [
    "BhyveCreationHelper",
    "BHYVE_VM_DIR",
    "BHYVE_IMAGES_DIR",
    "BHYVE_CLOUDINIT_DIR",
    "BHYVE_METADATA_DIR",
    "delete_bhyve_metadata",
    "load_bhyve_metadata",
    "save_bhyve_metadata",
]


class BhyveCreationHelper:
    """Helper class for bhyve VM creation operations."""

    def __init__(self, logger):
        """
        Initialize the creation helper.

        Args:
            logger: Logger instance
        """
        self.logger = logger
        # Delegate to specialized helpers
        self._image_helper = BhyveImageHelper(logger)
        self._provisioning_helper = BhyveProvisioningHelper(logger)

    def vm_exists(self, vm_name: str) -> bool:
        """
        Check if a bhyve VM with the given name exists.

        Args:
            vm_name: Name of the VM to check

        Returns:
            True if VM exists, False otherwise
        """
        # Check if /dev/vmm/<vm_name> exists (running VM)
        if os.path.exists(f"/dev/vmm/{vm_name}"):
            return True

        # Check if VM directory exists
        vm_dir = os.path.join(BHYVE_VM_DIR, vm_name)
        if os.path.isdir(vm_dir):
            return True

        return False

    def get_nmdm_id(self, vm_name: str) -> int:
        """
        Get the nmdm device ID for a VM.

        Uses a hash of the VM name to generate a consistent device ID.

        Args:
            vm_name: Name of the VM

        Returns:
            nmdm device ID (0-999)
        """
        return self._provisioning_helper.get_nmdm_id(vm_name)

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
        return self._provisioning_helper.get_console_device(vm_name)

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
        return self._provisioning_helper.is_linux_guest(config)

    def get_bridge_interface(self) -> Optional[str]:
        """
        Get the name of a bridge interface for VM networking.

        Prefers bridge1 (our NAT bridge) if it exists.

        Returns:
            Bridge interface name if found, None otherwise
        """
        try:
            result = subprocess.run(  # nosec B603 B607
                ["ifconfig", "-l"],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            if result.returncode == 0:
                interfaces = result.stdout.strip().split()
                # Prefer bridge1 (our NAT bridge) for VM networking
                # bridge0 may be used for WiFi bridging
                if "bridge1" in interfaces:
                    return "bridge1"
                # Look for any existing bridge as fallback
                for iface in interfaces:
                    if iface.startswith("bridge"):
                        return iface
                # Look for vm-switch (vm-bhyve style)
                for iface in interfaces:
                    if "vm-public" in iface or "vm-" in iface:
                        return iface
            return None
        except Exception:
            return None

    def create_bridge_if_needed(self) -> Dict[str, Any]:
        """
        Create or find the bridge interface for VM networking.

        Uses bridge1 (NAT bridge) if it exists, otherwise creates one.
        The NAT bridge is set up by enable_bhyve() with gateway IP
        and connected to pf for NAT.

        Returns:
            Dict with bridge name and success status
        """
        existing_bridge = self.get_bridge_interface()
        if existing_bridge:
            return {"success": True, "bridge": existing_bridge}

        try:
            # Create bridge1 for NAT networking
            # Note: This is a fallback - enable_bhyve() should have created this
            # bridge0 may be used for WiFi bridging
            bridge_name = "bridge1"
            result = subprocess.run(  # nosec B603 B607
                ["ifconfig", bridge_name, "create"],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )

            if result.returncode != 0:
                # Bridge might already exist
                if "exists" not in result.stderr.lower():
                    return {
                        "success": False,
                        "error": _("Failed to create bridge: %s") % result.stderr,
                    }

            # Configure the bridge with NAT gateway IP
            # This matches the setup in enable_bhyve()
            gateway_ip = "10.0.100.1"  # NOSONAR - private subnet for VM networking
            netmask = "255.255.255.0"  # NOSONAR - private subnet for VM networking
            subprocess.run(  # nosec B603 B607
                [
                    "ifconfig",
                    bridge_name,
                    "inet",
                    gateway_ip,
                    "netmask",
                    netmask,
                    "up",
                ],
                capture_output=True,
                timeout=30,
                check=False,
            )

            return {"success": True, "bridge": bridge_name}

        except Exception as error:
            return {"success": False, "error": str(error)}

    def create_tap_interface(self, _vm_name: str) -> Dict[str, Any]:
        """
        Create a tap interface for VM networking.

        Args:
            _vm_name: Name of the VM (unused, kept for API consistency)

        Returns:
            Dict with tap interface name and success status
        """
        try:
            # Create tap interface
            result = subprocess.run(  # nosec B603 B607
                ["ifconfig", "tap", "create"],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )

            if result.returncode != 0:
                return {
                    "success": False,
                    "error": _("Failed to create tap interface: %s") % result.stderr,
                }

            tap_name = result.stdout.strip()

            # Add tap to bridge
            bridge = self.get_bridge_interface()
            if bridge:
                subprocess.run(  # nosec B603 B607
                    ["ifconfig", bridge, "addm", tap_name],
                    capture_output=True,
                    timeout=30,
                    check=False,
                )

            # Bring up the tap interface
            subprocess.run(  # nosec B603 B607
                ["ifconfig", tap_name, "up"],
                capture_output=True,
                timeout=30,
                check=False,
            )

            return {"success": True, "tap": tap_name}

        except Exception as error:
            return {"success": False, "error": str(error)}

    # Delegate image operations to BhyveImageHelper

    def download_cloud_image(
        self, url: str, dest_path: str, disk_size_gb: int = 20
    ) -> Dict[str, Any]:
        """
        Download a cloud image and convert to raw format if needed.

        bhyve requires raw disk images. Cloud images are often in qcow2 format,
        so this function detects and converts them automatically.

        Args:
            url: URL of the cloud image
            dest_path: Destination path for the image
            disk_size_gb: Target disk size in GB (for resizing after conversion)

        Returns:
            Dict with success status and path
        """
        return self._image_helper.download_cloud_image(url, dest_path, disk_size_gb)

    def create_disk_image(
        self, path: str, size_gb: int, use_zvol: bool = False, zvol_parent: str = ""
    ) -> Dict[str, Any]:
        """
        Create a disk image for the VM.

        Args:
            path: Path to create the disk (file path or zvol name)
            size_gb: Size in GB
            use_zvol: Use ZFS zvol instead of file
            zvol_parent: Parent ZFS dataset for zvol

        Returns:
            Dict with success status and disk path
        """
        return self._image_helper.create_disk_image(
            path, size_gb, use_zvol, zvol_parent
        )

    # Delegate provisioning operations to BhyveProvisioningHelper

    def create_cloud_init_iso(self, config: BhyveVmConfig) -> Dict[str, Any]:
        """
        Create a cloud-init ISO for VM configuration.

        Args:
            config: VM configuration

        Returns:
            Dict with success status and ISO path
        """
        return self._provisioning_helper.create_cloud_init_iso(config)

    def generate_bhyve_command(
        self, config: BhyveVmConfig, tap_interface: str, use_nmdm: bool = True
    ) -> list:
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
        return self._provisioning_helper.generate_bhyve_command(
            config, tap_interface, use_nmdm
        )

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
        return self._provisioning_helper.start_vm_with_bhyveload(config, tap_interface)

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
        return self._provisioning_helper.start_vm_with_uefi(config, tap_interface)

    # IP and SSH waiting methods remain in this class (networking-related)

    def extract_ip_from_arp_line(self, line: str) -> Optional[str]:
        """
        Extract IP address from a single ARP table line.

        Args:
            line: ARP table output line

        Returns:
            IP address if found, None otherwise
        """
        # Format: ? (192.168.1.x) at xx:xx:xx:xx:xx:xx on tap0
        if "(" not in line or ")" not in line:
            return None
        ip_part = line.split("(")[1].split(")")[0]
        if ip_part and ip_part != "incomplete":
            return ip_part
        return None

    def find_ip_in_arp_output(
        self, arp_output: str, tap_interface: str, vm_name: str
    ) -> Optional[str]:
        """
        Search ARP output for an IP on the given tap interface or bridge.

        Args:
            arp_output: Output from arp -an command
            tap_interface: Tap interface name to match
            vm_name: VM name for logging

        Returns:
            IP address if found, None otherwise
        """
        for line in arp_output.split("\n"):
            if tap_interface not in line and "bridge" not in line:
                continue
            ip_addr = self.extract_ip_from_arp_line(line)
            if ip_addr:
                self.logger.info(_("VM %s has IP: %s"), vm_name, ip_addr)
                return ip_addr
        return None

    async def wait_for_vm_ip(
        self,
        vm_name: str,
        tap_interface: str,
        timeout: int = 300,  # NOSONAR - timeout parameter is for polling loop control
    ) -> Optional[str]:
        """
        Wait for the VM to get an IP address.

        Args:
            vm_name: Name of the VM
            tap_interface: Tap interface name
            timeout: Maximum time to wait

        Returns:
            IP address if found, None otherwise
        """
        self.logger.info(_("Waiting for VM %s to get IP address..."), vm_name)
        start_time = time.time()

        while time.time() - start_time < timeout:
            # Try to get IP from ARP table (VM should respond to DHCP)
            try:
                result = await run_command_async(["arp", "-an"], timeout=10)
                if result.returncode == 0:
                    ip_addr = self.find_ip_in_arp_output(
                        result.stdout, tap_interface, vm_name
                    )
                    if ip_addr:
                        return ip_addr
            except Exception:  # nosec B110 # Expected: retry on next iteration
                pass

            await asyncio.sleep(5)

        self.logger.warning(_("Timeout waiting for VM %s to get IP"), vm_name)
        return None

    async def wait_for_ssh(
        self, ip: str, port: int = 22, timeout: int = 180  # NOSONAR
    ) -> bool:
        """
        Wait for SSH to become available.

        Args:
            ip: IP address
            port: SSH port
            timeout: Maximum wait time

        Returns:
            True if SSH is available
        """
        self.logger.info(_("Waiting for SSH on %s:%d..."), ip, port)
        start_time = time.time()

        while time.time() - start_time < timeout:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)
                result = sock.connect_ex((ip, port))
                sock.close()
                if result == 0:
                    self.logger.info(_("SSH is available on %s"), ip)
                    return True
            except Exception:  # nosec B110 # polling loop - VM may not exist yet
                pass
            await asyncio.sleep(5)

        self.logger.warning(_("Timeout waiting for SSH on %s"), ip)
        return False
