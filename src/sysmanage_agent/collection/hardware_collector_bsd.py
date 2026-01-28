"""
BSD hardware collector for SysManage Agent.
Handles BSD-specific (OpenBSD, FreeBSD, NetBSD) hardware information gathering.
"""

import glob
import logging
import os
import re
import subprocess  # nosec B404
from typing import Any, Dict, List, Optional

from src.i18n import _
from .hardware_collector_base import HardwareCollectorBase

logger = logging.getLogger(__name__)


class HardwareCollectorBSD(HardwareCollectorBase):
    """Collects hardware information on BSD systems."""

    def _collect_cpu_model_and_vendor(self, cpu_info: Dict[str, Any]) -> None:
        """Collect CPU model name and extract vendor from sysctl hw.model."""
        result = subprocess.run(
            ["sysctl", "-n", "hw.model"],  # nosec B603, B607
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        if result.returncode == 0:
            cpu_info["model"] = result.stdout.strip()
            model_lower = result.stdout.lower()
            if "intel" in model_lower:
                cpu_info["vendor"] = "Intel"
            elif "amd" in model_lower:
                cpu_info["vendor"] = "AMD"
            else:
                cpu_info["vendor"] = "Unknown"

    def _collect_cpu_core_counts(self, cpu_info: Dict[str, Any]) -> None:
        """Collect thread and core counts from sysctl hw.ncpu and hw.ncpuonline."""
        result = subprocess.run(
            ["sysctl", "-n", "hw.ncpu"],  # nosec B603, B607
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        if result.returncode == 0:
            cpu_info["threads"] = int(result.stdout.strip())

        result = subprocess.run(
            ["sysctl", "-n", "hw.ncpuonline"],  # nosec B603, B607
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        if result.returncode == 0:
            cpu_info["cores"] = int(result.stdout.strip())
        else:
            cpu_info["cores"] = cpu_info.get("threads", 0)

    def _collect_cpu_frequency_sysctl(self, cpu_info: Dict[str, Any]) -> None:
        """Collect CPU frequency from sysctl keys (hw.cpuspeed, hw.clockrate, machdep.tsc_freq)."""
        for freq_key in ["hw.cpuspeed", "hw.clockrate", "machdep.tsc_freq"]:
            result = subprocess.run(
                ["sysctl", "-n", freq_key],  # nosec B603, B607
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
            if result.returncode == 0:
                freq_value = result.stdout.strip()
                if freq_key == "machdep.tsc_freq":
                    cpu_info["frequency_mhz"] = int(int(freq_value) // 1000000)
                else:
                    cpu_info["frequency_mhz"] = int(freq_value)
                break

    def _parse_cpu_frequency_from_model(self, cpu_info: Dict[str, Any]) -> None:
        """Parse CPU frequency from the model name string as a fallback."""
        if "frequency_mhz" in cpu_info or "model" not in cpu_info:
            return

        model = cpu_info["model"]
        ghz_match = re.search(
            r"@\s*(\d+\.?\d*)\s*GHz", model, re.IGNORECASE
        )  # NOSONAR - regex operates on trusted internal data
        if ghz_match:
            freq_ghz = float(ghz_match.group(1))
            cpu_info["frequency_mhz"] = int(freq_ghz * 1000)
        else:
            mhz_match = re.search(
                r"(\d+)\s*MHz", model, re.IGNORECASE
            )  # NOSONAR - regex operates on trusted internal data
            if mhz_match:
                cpu_info["frequency_mhz"] = int(mhz_match.group(1))

    def get_cpu_info(self) -> Dict[str, Any]:
        """Get CPU information on OpenBSD/FreeBSD using sysctl."""

        cpu_info = {}
        try:
            self._collect_cpu_model_and_vendor(cpu_info)
            self._collect_cpu_core_counts(cpu_info)
            self._collect_cpu_frequency_sysctl(cpu_info)
            self._parse_cpu_frequency_from_model(cpu_info)

        except Exception as error:
            cpu_info["error"] = _("Failed to get BSD CPU info: %s") % str(error)

        return cpu_info

    def get_memory_info(self) -> Dict[str, Any]:
        """Get memory information on OpenBSD/FreeBSD using sysctl."""

        memory_info = {}
        try:
            # Get physical memory
            result = subprocess.run(
                ["sysctl", "-n", "hw.physmem"],  # nosec B603, B607
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
            if result.returncode == 0:
                # hw.physmem returns bytes
                memory_bytes = int(result.stdout.strip())
                memory_info["total_mb"] = memory_bytes // (1024 * 1024)

        except Exception as error:
            memory_info["error"] = _("Failed to get BSD memory info: %s") % str(error)

        return memory_info

    def _parse_df_storage_devices(self) -> List[Dict[str, Any]]:
        """Parse mounted filesystem information from df -h output."""
        storage_devices = []
        result = subprocess.run(
            ["df", "-h"],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,  # nosec B603, B607
        )
        if result.returncode != 0:
            return storage_devices

        lines = result.stdout.strip().split("\n")[1:]  # Skip header
        for line in lines:
            parts = line.split()
            if len(parts) >= 6:
                device_info = self._process_df_line(parts)
                if device_info is not None:
                    storage_devices.append(device_info)

        return storage_devices

    def _process_df_line(self, parts: List[str]) -> Optional[Dict[str, Any]]:
        """Process a single line of df output into a device info dict."""
        device_name = parts[0]
        mount_point = parts[5] if len(parts) > 5 else ""

        if self._should_skip_bsd_filesystem(device_name, mount_point):
            return None

        is_physical = self._is_physical_volume_bsd(device_name, mount_point)
        capacity_bytes = self._parse_size_to_bytes(parts[1])
        used_bytes = self._parse_size_to_bytes(parts[2])
        available_bytes = self._parse_size_to_bytes(parts[3])

        return {
            "name": device_name,
            "size": parts[1],
            "used": parts[2],
            "available": parts[3],
            "mount_point": mount_point,
            "type": "unknown",
            "is_physical": is_physical,
            "device_type": "physical" if is_physical else "logical",
            "capacity_bytes": capacity_bytes,
            "used_bytes": used_bytes,
            "available_bytes": available_bytes,
            "file_system": "unknown",
        }

    def _collect_mount_filesystem_types(
        self, storage_devices: List[Dict[str, Any]]
    ) -> None:
        """Collect filesystem types from mount command and update storage devices."""
        result = subprocess.run(
            ["mount"],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,  # nosec B603, B607
        )
        if result.returncode != 0:
            return

        mount_lines = result.stdout.strip().split("\n")
        device_types = {}
        for line in mount_lines:
            if " on " in line and " type " in line:
                parts = line.split()
                device = parts[0]
                type_idx = parts.index("type") + 1
                if type_idx < len(parts):
                    device_types[device] = parts[type_idx]

        for device in storage_devices:
            if device["name"] in device_types:
                device["type"] = device_types[device["name"]]
                device["file_system"] = device_types[device["name"]]

    def get_storage_info(self) -> List[Dict[str, Any]]:
        """Get storage information on OpenBSD/FreeBSD using df and mount."""

        storage_devices = []
        try:
            storage_devices = self._parse_df_storage_devices()
            self._collect_mount_filesystem_types(storage_devices)
            self._add_physical_bsd_devices(storage_devices)

        except Exception as error:
            storage_devices.append(
                {"error": _("Failed to get BSD storage info: %s") % str(error)}
            )

        return storage_devices

    def _should_skip_bsd_filesystem(self, device_name: str, mount_point: str) -> bool:
        """Determine if a BSD filesystem should be skipped from storage inventory."""
        # Skip special/virtual filesystems
        skip_devices = ["tmpfs", "kernfs", "procfs", "mfs", "fdesc"]
        # Known system mount points to skip during storage inventory
        # NOSONAR - these are system paths to skip, not paths we write to
        skip_mounts = ["/dev", "/proc", "/sys", "/tmp"]  # nosec B108

        device_lower = device_name.lower()
        mount_lower = mount_point.lower()

        # Skip by device type
        for skip_dev in skip_devices:
            if skip_dev in device_lower:
                return True

        # Skip by mount point
        for skip_mount in skip_mounts:
            if mount_lower == skip_mount:
                return True

        return False

    def _is_physical_volume_bsd(self, device_name: str, _mount_point: str) -> bool:
        """Determine if a BSD storage device is physical or logical."""
        device_lower = device_name.lower()

        # Physical device patterns for BSD systems
        # OpenBSD: wd (IDE/SATA), sd (SCSI/SATA/USB), cd (CD-ROM)
        # FreeBSD: ada (SATA), da (SCSI/USB), cd (CD-ROM)
        physical_patterns = [
            "/dev/wd",  # OpenBSD IDE/SATA drives
            "/dev/sd",  # OpenBSD/FreeBSD SCSI/SATA/USB drives
            "/dev/ada",  # FreeBSD SATA drives
            "/dev/da",  # FreeBSD SCSI/USB drives
            "/dev/cd",  # CD/DVD drives
            "/dev/nvd",  # NVMe drives
        ]

        # Logical volume patterns
        logical_patterns = [
            "tmpfs",
            "mfs",
            "procfs",
            "kernfs",
            "devfs",
        ]

        # Check for logical volumes first
        for pattern in logical_patterns:
            if pattern in device_lower:
                return False

        # Check for physical devices
        for pattern in physical_patterns:
            if device_lower.startswith(pattern):
                return True

        # Network mounts are logical
        if ":/" in device_name:  # NFS-style mounts
            return False

        # Default to physical for /dev/ devices, logical for everything else
        return device_name.startswith("/dev/")

    def _add_physical_bsd_devices(self, storage_devices: List[Dict[str, Any]]) -> None:
        """Add physical storage devices that may not appear in df output."""

        # Track devices we already have to avoid duplicates
        existing_devices = {device["name"] for device in storage_devices}

        # Physical device patterns to search for
        device_patterns = [
            "/dev/ada*",  # FreeBSD SATA drives
            "/dev/da*",  # FreeBSD SCSI/USB drives
            "/dev/nvd*",  # NVMe drives
            "/dev/sd*",  # OpenBSD/some FreeBSD SCSI drives
            "/dev/wd*",  # OpenBSD IDE/SATA drives
        ]

        for pattern in device_patterns:
            for device_path in glob.glob(pattern):
                self._process_physical_device(
                    device_path, storage_devices, existing_devices
                )

    def _process_physical_device(
        self,
        device_path: str,
        storage_devices: List[Dict[str, Any]],
        existing_devices: set,
    ) -> None:
        """Process a single physical device and add it to storage_devices if valid."""
        # Skip partition devices (e.g., ada0p1, ada0s1), focus on whole disks
        base_device = device_path
        if any(c in os.path.basename(device_path) for c in ["p", "s"]):
            # This looks like a partition, get the base device
            match = re.match(r"(/dev/[a-z]+\d+)", device_path)
            if match:
                base_device = match.group(1)
            else:
                return  # Skip if we can't determine base device

        # Skip if we already have this device
        if base_device in existing_devices:
            return

        try:
            # Get device size using diskinfo if available
            size_bytes = 0
            size_human = "Unknown"

            try:
                # Use full path to diskinfo for security
                diskinfo_path = "/usr/sbin/diskinfo"
                if os.path.exists(diskinfo_path):
                    result = subprocess.run(  # nosec B603
                        [diskinfo_path, base_device],
                        capture_output=True,
                        text=True,
                        timeout=10,
                        check=False,
                    )
                    if result.returncode == 0:
                        # diskinfo output format: device_name size_bytes sector_size ...
                        parts = result.stdout.strip().split("\t")
                        if len(parts) >= 2:
                            size_bytes = int(parts[1])
                            # Convert to human readable
                            size_human = self._bytes_to_human_readable(size_bytes)
            except (subprocess.TimeoutExpired, ValueError, FileNotFoundError):
                # diskinfo not available or failed, try stat
                try:
                    stat_result = os.stat(base_device)
                    size_bytes = stat_result.st_size
                    size_human = self._bytes_to_human_readable(size_bytes)
                except (OSError, AttributeError):
                    pass

            # Add the physical device
            device_info = {
                "name": base_device,
                "size": size_human,
                "used": "N/A",  # Not applicable for raw devices
                "available": "N/A",  # Not applicable for raw devices
                "mount_point": "",  # Raw devices are not mounted
                "type": "block",
                "is_physical": True,
                "device_type": "physical",
                "capacity_bytes": size_bytes,
                "used_bytes": 0,  # Not applicable for raw devices
                "available_bytes": size_bytes,  # Whole device is "available"
                "file_system": "raw",  # Raw block device
            }
            storage_devices.append(device_info)
            existing_devices.add(base_device)

        except Exception as error:
            # Skip devices we can't access, log for debugging
            logger.debug("Skipping device %s: %s", base_device, error)

    def _detect_interface_header(
        self, line: str, original_line: str
    ) -> Optional[Dict[str, Any]]:
        """Detect and parse a new interface header line from ifconfig output.

        Returns a new interface dict if the line is a header, or None otherwise.
        Returns an empty dict (falsy check won't work, use 'is None') to signal
        that the interface should be skipped (e.g., loopback).
        """
        if (
            original_line.startswith("\t")
            or original_line.startswith(" ")
            or ":" not in line
            or " flags=" not in line
        ):
            return None

        interface_name = line.split(":")[0]
        if interface_name == "lo0":  # Skip loopback
            return {}

        flags_str = ""
        is_up = False
        if "flags=" in line:
            flags_start = line.find("flags=") + 6
            flags_end = line.find(">", flags_start)
            if flags_end > flags_start:
                flags_str = line[flags_start:flags_end]
                is_up = "UP" in flags_str

        return {
            "name": interface_name,
            "flags": flags_str,
            "interface_type": "ethernet",
            "hardware_type": "ethernet",
            "mac_address": "",
            "ipv4_address": None,
            "ipv6_address": None,
            "subnet_mask": None,
            "is_active": is_up,
            "speed_mbps": None,
        }

    def _parse_interface_ether(
        self, line: str, current_interface: Dict[str, Any]
    ) -> None:
        """Parse MAC address from an ifconfig ether line."""
        parts = line.split()
        if len(parts) >= 2:
            # pylint: disable-next=unsupported-assignment-operation
            current_interface["mac_address"] = parts[1]

    def _parse_interface_inet(
        self, line: str, current_interface: Dict[str, Any]
    ) -> None:
        """Parse IPv4 address and subnet mask from an ifconfig inet line."""
        parts = line.split()
        if len(parts) >= 2:
            # pylint: disable-next=unsupported-assignment-operation
            current_interface["ipv4_address"] = parts[1]
        if "netmask" in parts:
            netmask_idx = parts.index("netmask")
            if netmask_idx + 1 < len(parts):
                netmask_hex = parts[netmask_idx + 1]
                if netmask_hex.startswith("0x"):
                    try:
                        netmask_int = int(netmask_hex, 16)
                        subnet_mask = ".".join(
                            [
                                str((netmask_int >> (8 * (3 - i))) & 0xFF)
                                for i in range(4)
                            ]
                        )
                        # pylint: disable-next=unsupported-assignment-operation
                        current_interface["subnet_mask"] = subnet_mask
                    except ValueError:
                        pass

    def _parse_interface_inet6(
        self, line: str, current_interface: Dict[str, Any]
    ) -> None:
        """Parse IPv6 address from an ifconfig inet6 line, skipping link-local."""
        parts = line.split()
        if len(parts) >= 2:
            ipv6_addr = parts[1]
            if "%" in ipv6_addr:
                ipv6_addr = ipv6_addr.split("%")[0]
            if (
                not ipv6_addr.startswith("fe80:")
                and current_interface.get("ipv6_address") is None
            ):
                # pylint: disable-next=unsupported-assignment-operation
                current_interface["ipv6_address"] = ipv6_addr

    def _parse_interface_media(
        self, line: str, current_interface: Dict[str, Any]
    ) -> None:
        """Parse media type from an ifconfig media line."""
        if "Ethernet" in line:
            # pylint: disable-next=unsupported-assignment-operation
            current_interface["interface_type"] = "ethernet"
            # pylint: disable-next=unsupported-assignment-operation
            current_interface["hardware_type"] = "ethernet"
        elif "IEEE802.11" in line or "wireless" in line.lower():
            # pylint: disable-next=unsupported-assignment-operation
            current_interface["interface_type"] = "wireless"
            # pylint: disable-next=unsupported-assignment-operation
            current_interface["hardware_type"] = "wireless"

    def _parse_interface_detail_line(
        self, line: str, current_interface: Dict[str, Any]
    ) -> None:
        """Parse an indented detail line for the current interface."""
        if "ether " in line:
            self._parse_interface_ether(line, current_interface)
        elif "inet " in line:
            self._parse_interface_inet(line, current_interface)
        elif "inet6 " in line:
            self._parse_interface_inet6(line, current_interface)
        elif "media:" in line:
            self._parse_interface_media(line, current_interface)

    def get_network_info(self) -> List[Dict[str, Any]]:
        """Get network information on OpenBSD/FreeBSD using ifconfig."""

        network_interfaces = []
        try:
            result = subprocess.run(
                ["ifconfig", "-a"],  # nosec B603, B607
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
            if result.returncode == 0:
                current_interface: Optional[Dict[str, Any]] = None
                for line in result.stdout.split("\n"):
                    original_line = line
                    line = line.strip()
                    if not line:
                        continue

                    header = self._detect_interface_header(line, original_line)
                    if header is not None:
                        if current_interface:
                            network_interfaces.append(current_interface)
                        # Empty dict means skip (e.g., loopback)
                        current_interface = header if header else None
                        continue

                    if current_interface and (
                        original_line.startswith("\t") or original_line.startswith(" ")
                    ):
                        self._parse_interface_detail_line(line, current_interface)

                # Add the last interface
                if current_interface:
                    network_interfaces.append(current_interface)

        except Exception as error:
            network_interfaces.append(
                {"error": _("Failed to get BSD network info: %s") % str(error)}
            )

        return network_interfaces
