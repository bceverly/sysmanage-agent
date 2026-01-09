"""
bhyve VM creation helpers for FreeBSD hosts.

This module contains helper functions for creating bhyve VMs:
- Disk image creation and cloud image downloading
- Cloud-init ISO creation
- Network setup (bridge and tap interfaces)
- VM startup (bhyveload for FreeBSD, UEFI for Linux)
"""

import asyncio
import hashlib
import os
import shutil
import socket
import subprocess  # nosec B404 # Required for system command execution
import time
from typing import Any, Dict, List, Optional

from src.i18n import _
from src.sysmanage_agent.operations.child_host_bhyve_types import BhyveVmConfig


# Default paths for bhyve
BHYVE_VM_DIR = "/vm"
BHYVE_IMAGES_DIR = "/vm/images"
BHYVE_CLOUDINIT_DIR = "/vm/cloud-init"


class BhyveCreationHelper:
    """Helper class for bhyve VM creation operations."""

    def __init__(self, logger):
        """
        Initialize the creation helper.

        Args:
            logger: Logger instance
        """
        self.logger = logger

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
            gateway_ip = "10.0.100.1"
            netmask = "255.255.255.0"
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

    def _is_qcow2_image(self, path: str) -> bool:
        """
        Check if a disk image is in qcow2 format.

        Args:
            path: Path to the image file

        Returns:
            True if qcow2 format, False otherwise
        """
        try:
            # Check file magic bytes - qcow2 starts with "QFI\xfb"
            with open(path, "rb") as img_file:
                magic = img_file.read(4)
                return magic == b"QFI\xfb"
        except Exception:
            return False

    def _convert_qcow2_to_raw(self, qcow2_path: str, raw_path: str) -> Dict[str, Any]:
        """
        Convert a qcow2 image to raw format for bhyve.

        bhyve requires raw disk images - it does not support qcow2 natively.

        Args:
            qcow2_path: Path to the qcow2 image
            raw_path: Destination path for raw image

        Returns:
            Dict with success status
        """
        try:
            self.logger.info(
                _("Converting qcow2 image to raw format for bhyve compatibility")
            )

            # Use qemu-img to convert (from qemu-utils package)
            result = subprocess.run(  # nosec B603 B607
                [
                    "qemu-img",
                    "convert",
                    "-f",
                    "qcow2",
                    "-O",
                    "raw",
                    qcow2_path,
                    raw_path,
                ],
                capture_output=True,
                text=True,
                timeout=1800,  # 30 minutes for large images
                check=False,
            )

            if result.returncode != 0:
                return {
                    "success": False,
                    "error": _("Failed to convert qcow2 to raw: %s") % result.stderr,
                }

            self.logger.info(_("Converted image to raw format: %s"), raw_path)
            return {"success": True, "path": raw_path}

        except FileNotFoundError:
            return {
                "success": False,
                "error": _(
                    "qemu-img not found. Install qemu-utils: pkg install qemu-utils"
                ),
            }
        except subprocess.TimeoutExpired:
            return {"success": False, "error": _("Image conversion timed out")}
        except Exception as error:
            return {"success": False, "error": str(error)}

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
        try:
            self.logger.info(_("Downloading cloud image from: %s"), url)

            # Create download directory
            download_dir = os.path.join(BHYVE_IMAGES_DIR, ".downloads")
            os.makedirs(download_dir, mode=0o755, exist_ok=True)

            # Generate cache key from URL
            url_hash = hashlib.md5(url.encode(), usedforsecurity=False).hexdigest()[:8]
            filename = os.path.basename(url.split("?")[0])
            cached_path = os.path.join(download_dir, f"{url_hash}_{filename}")
            # Raw converted cache path
            raw_cached_path = cached_path + ".raw"

            # Handle compressed files
            is_xz = filename.endswith(".xz")
            if is_xz:
                decompressed_path = cached_path[:-3]  # Remove .xz
            else:
                decompressed_path = cached_path

            # Check if we have a cached raw conversion
            if os.path.exists(raw_cached_path):
                self.logger.info(_("Using cached raw cloud image: %s"), raw_cached_path)
                shutil.copy2(raw_cached_path, dest_path)
                # Resize to requested size
                self._resize_disk_image(dest_path, disk_size_gb)
                return {"success": True, "path": dest_path}

            # Check cache for original (may need conversion)
            need_download = not os.path.exists(decompressed_path)

            if need_download:
                # Download
                result = subprocess.run(  # nosec B603 B607
                    ["fetch", "-o", cached_path, url],
                    capture_output=True,
                    text=True,
                    timeout=1800,  # 30 minutes
                    check=False,
                )

                if result.returncode != 0:
                    # Try curl as fallback
                    result = subprocess.run(  # nosec B603 B607
                        ["curl", "-L", "-o", cached_path, url],
                        capture_output=True,
                        text=True,
                        timeout=1800,
                        check=False,
                    )
                    if result.returncode != 0:
                        return {
                            "success": False,
                            "error": _("Failed to download image: %s") % result.stderr,
                        }

                self.logger.info(_("Cloud image downloaded to: %s"), cached_path)

                # Decompress if needed
                if is_xz:
                    self.logger.info(_("Decompressing xz archive"))
                    result = subprocess.run(  # nosec B603 B607
                        ["xz", "-dk", cached_path],
                        capture_output=True,
                        text=True,
                        timeout=600,
                        check=False,
                    )
                    if result.returncode != 0:
                        return {
                            "success": False,
                            "error": _("Failed to decompress: %s") % result.stderr,
                        }
            else:
                self.logger.info(_("Using cached cloud image: %s"), decompressed_path)

            # Check if image is qcow2 and needs conversion
            if self._is_qcow2_image(decompressed_path):
                self.logger.info(
                    _("Detected qcow2 format, converting to raw for bhyve")
                )
                convert_result = self._convert_qcow2_to_raw(
                    decompressed_path, raw_cached_path
                )
                if not convert_result.get("success"):
                    return convert_result
                # Copy converted raw image to destination
                shutil.copy2(raw_cached_path, dest_path)
            else:
                # Already raw format, just copy
                shutil.copy2(decompressed_path, dest_path)

            # Resize disk to requested size
            self._resize_disk_image(dest_path, disk_size_gb)

            return {"success": True, "path": dest_path}

        except subprocess.TimeoutExpired:
            return {"success": False, "error": _("Download timed out")}
        except Exception as error:
            return {"success": False, "error": str(error)}

    def _resize_disk_image(self, path: str, size_gb: int) -> None:
        """
        Resize a raw disk image to the specified size.

        Args:
            path: Path to the raw disk image
            size_gb: Target size in GB
        """
        try:
            size_bytes = size_gb * 1024 * 1024 * 1024
            current_size = os.path.getsize(path)

            if current_size < size_bytes:
                self.logger.info(_("Resizing disk image to %dGB"), size_gb)
                result = subprocess.run(  # nosec B603 B607
                    ["truncate", "-s", str(size_bytes), path],
                    capture_output=True,
                    text=True,
                    timeout=60,
                    check=False,
                )
                if result.returncode != 0:
                    self.logger.warning(_("Failed to resize disk: %s"), result.stderr)
        except Exception as error:
            self.logger.warning(_("Error resizing disk: %s"), error)

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
        try:
            if use_zvol and zvol_parent:
                # Create ZFS zvol
                zvol_name = f"{zvol_parent}/{os.path.basename(path)}"
                self.logger.info(_("Creating ZFS zvol: %s (%dG)"), zvol_name, size_gb)
                result = subprocess.run(  # nosec B603 B607
                    ["zfs", "create", "-V", f"{size_gb}G", zvol_name],
                    capture_output=True,
                    text=True,
                    timeout=120,
                    check=False,
                )
                if result.returncode != 0:
                    return {
                        "success": False,
                        "error": _("Failed to create zvol: %s") % result.stderr,
                    }
                return {"success": True, "path": f"/dev/zvol/{zvol_name}"}

            # Create file-based disk using truncate
            self.logger.info(_("Creating disk image: %s (%dG)"), path, size_gb)
            size_bytes = size_gb * 1024 * 1024 * 1024
            result = subprocess.run(  # nosec B603 B607
                ["truncate", "-s", str(size_bytes), path],
                capture_output=True,
                text=True,
                timeout=120,
                check=False,
            )
            if result.returncode != 0:
                return {
                    "success": False,
                    "error": _("Failed to create disk: %s") % result.stderr,
                }
            return {"success": True, "path": path}

        except Exception as error:
            return {"success": False, "error": str(error)}

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
            for cmd in config.agent_install_commands:
                # Escape single quotes in command
                escaped_cmd = cmd.replace("'", "'\"'\"'")
                runcmd_lines.append(f"  - '{escaped_cmd}'")

            runcmd_section = "\n".join(runcmd_lines) if runcmd_lines else ""

            # Determine protocol and build server URL
            protocol = "https" if config.use_https else "http"
            server_url = f"{protocol}://{config.server_url}:{config.server_port}"

            # Create user-data
            user_data = f"""#cloud-config
hostname: {config.hostname}
manage_etc_hosts: true

users:
  - name: {config.username}
    sudo: ALL=(ALL) NOPASSWD:ALL
    shell: /bin/sh
    lock_passwd: false
    passwd: {config.password_hash}

chpasswd:
  expire: false

ssh_pwauth: true

write_files:
  - path: /etc/sysmanage-agent/config.yaml
    content: |
      server:
        url: {server_url}
        verify_ssl: false
    permissions: '0644'
"""

            if config.auto_approve_token:
                user_data += f"""
  - path: /etc/sysmanage-agent/auto_approve_token
    content: |
      {config.auto_approve_token}
    permissions: '0600'
"""

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
                timeout=60,
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
                timeout=60,
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
        self, vm_name: str, tap_interface: str, timeout: int = 300
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
                result = subprocess.run(  # nosec B603 B607
                    ["arp", "-an"],
                    capture_output=True,
                    text=True,
                    timeout=10,
                    check=False,
                )
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

    async def wait_for_ssh(self, ip: str, port: int = 22, timeout: int = 180) -> bool:
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
