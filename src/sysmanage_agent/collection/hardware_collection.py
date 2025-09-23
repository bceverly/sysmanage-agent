"""
Hardware collection module for SysManage Agent.
Handles platform-specific hardware information gathering.
"""

import glob
import json
import logging
import os
import platform
import re
import subprocess  # nosec B404
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from src.i18n import _

logger = logging.getLogger(__name__)


class HardwareCollector:
    """Collects hardware information across different platforms."""

    def __init__(self):
        self.logger = logging.getLogger(__name__)

    def get_hardware_info(self) -> Dict[str, Any]:
        """Get comprehensive hardware information formatted for database storage."""

        system = platform.system()

        # Initialize the structured hardware info
        hardware_data = {}

        try:
            if system == "Darwin":  # macOS
                # Get CPU information
                cpu_info = self._get_macos_cpu_info()
                # Get memory information
                memory_info = self._get_macos_memory_info()
                # Get storage information
                storage_info = self._get_macos_storage_info()
                # Get network information
                network_info = self._get_macos_network_info()

            elif system == "Linux":
                # Get CPU information
                cpu_info = self._get_linux_cpu_info()
                # Get memory information
                memory_info = self._get_linux_memory_info()
                # Get storage information
                storage_info = self._get_linux_storage_info()
                # Get network information
                network_info = self._get_linux_network_info()

            elif system == "Windows":
                # Get CPU information
                cpu_info = self._get_windows_cpu_info()
                # Get memory information
                memory_info = self._get_windows_memory_info()
                # Get storage information
                storage_info = self._get_windows_storage_info()
                # Get network information
                network_info = self._get_windows_network_info()

            elif system in ("OpenBSD", "FreeBSD"):
                # Get CPU information
                cpu_info = self._get_bsd_cpu_info()
                # Get memory information
                memory_info = self._get_bsd_memory_info()
                # Get storage information
                storage_info = self._get_bsd_storage_info()
                # Get network information
                network_info = self._get_bsd_network_info()

            else:
                # Unsupported platform
                return {
                    "hardware_details": json.dumps(
                        {"error": _("Unsupported platform: %s") % system}
                    ),
                    "storage_details": json.dumps([]),
                    "network_details": json.dumps([]),
                }

            # Format data for database storage
            hardware_data = {
                # Individual CPU fields for easy querying
                "cpu_vendor": cpu_info.get("vendor", ""),
                "cpu_model": cpu_info.get("model", ""),
                "cpu_cores": (
                    cpu_info.get("cores", 0) if cpu_info.get("cores") else None
                ),
                "cpu_threads": (
                    cpu_info.get("threads", 0) if cpu_info.get("threads") else None
                ),
                "cpu_frequency_mhz": (
                    cpu_info.get("frequency_mhz", 0)
                    if cpu_info.get("frequency_mhz")
                    else None
                ),
                # Individual memory field for easy querying
                "memory_total_mb": (
                    memory_info.get("total_mb", 0)
                    if memory_info.get("total_mb")
                    else None
                ),
                # Normalized storage and network data for new tables
                "storage_devices": storage_info,
                "network_interfaces": network_info,
                # JSON fields for complex data (backward compatibility)
                "storage_details": json.dumps(storage_info),
                "network_details": json.dumps(network_info),
                "hardware_details": json.dumps(
                    {
                        "cpu": cpu_info,
                        "memory": memory_info,
                        "platform": system,
                        "collection_timestamp": self._get_timestamp(),
                    }
                ),
            }

        except Exception as e:
            self.logger.error(_("Failed to collect hardware info: %s"), e)
            hardware_data = {
                "hardware_details": json.dumps(
                    {"error": _("Failed to collect hardware info: %s") % str(e)}
                ),
                "storage_details": json.dumps([]),
                "network_details": json.dumps([]),
            }

        return hardware_data

    def _get_timestamp(self) -> str:
        """Get current timestamp in ISO format."""
        return datetime.now(timezone.utc).isoformat()

    def _parse_size_to_bytes(self, size_str: str) -> int:
        """Parse human-readable size to bytes."""
        if not size_str or size_str == "-":
            return 0

        size_str = size_str.strip().upper()
        try:
            # Handle cases like "42G", "4.7G", "312K", "1.0K", "0B"
            multipliers = {
                "B": 1,
                "K": 1024,
                "M": 1024**2,
                "G": 1024**3,
                "T": 1024**4,
                "P": 1024**5,
            }

            # Extract numeric part and unit
            numeric_part = ""
            unit = ""
            for char in size_str:
                if char.isdigit() or char == ".":
                    numeric_part += char
                else:
                    unit = size_str[len(numeric_part) :].strip()
                    break

            if not numeric_part:
                return 0

            size_float = float(numeric_part)

            # Find the multiplier
            multiplier = 1
            for suffix, mult in multipliers.items():
                if unit.startswith(suffix):
                    multiplier = mult
                    break

            return int(size_float * multiplier)

        except (ValueError, TypeError):
            return 0

    # macOS hardware collection methods
    def _get_macos_cpu_info(self) -> Dict[str, Any]:
        """Get CPU information on macOS using system_profiler."""

        cpu_info = {}
        try:  # pylint: disable=too-many-nested-blocks
            # Get CPU info from system_profiler
            result = subprocess.run(
                ["system_profiler", "-json", "SPHardwareDataType"],  # nosec B603, B607
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
            if result.returncode == 0:
                data = json.loads(result.stdout)
                hardware = data.get("SPHardwareDataType", [{}])[0]

                cpu_info["vendor"] = (
                    "Apple"
                    if "Apple" in hardware.get("chip_type", "")
                    else hardware.get("cpu_type", "").split()[0]
                )
                cpu_info["model"] = hardware.get(
                    "chip_type", hardware.get("cpu_type", "")
                )

                # Parse number_processors which can be a string like "proc 14:10:4" or an integer
                num_processors = hardware.get("number_processors", 0)
                if isinstance(num_processors, str) and "proc" in num_processors:
                    # Parse format like "proc 14:10:4" where 14 is total threads
                    parts = num_processors.split()
                    if len(parts) > 1 and ":" in parts[1]:
                        total_cores = int(parts[1].split(":")[0])
                        cpu_info["cores"] = total_cores
                        cpu_info["threads"] = total_cores
                    else:
                        cpu_info["cores"] = 0
                        cpu_info["threads"] = 0
                elif isinstance(num_processors, (int, str)):
                    try:
                        cores = int(num_processors)
                        cpu_info["cores"] = cores
                        cpu_info["threads"] = cores
                    except (ValueError, TypeError):
                        cpu_info["cores"] = 0
                        cpu_info["threads"] = 0

                # Extract frequency from processor speed field if available
                processor_speed = hardware.get("current_processor_speed", "")
                if processor_speed:
                    # Convert GHz to MHz
                    if "GHz" in processor_speed:
                        freq = float(processor_speed.replace(" GHz", ""))
                        cpu_info["frequency_mhz"] = int(freq * 1000)
                    elif "MHz" in processor_speed:
                        cpu_info["frequency_mhz"] = int(
                            processor_speed.replace(" MHz", "")
                        )
                else:
                    # For Apple Silicon Macs, try to extract frequency from chip name
                    chip_type = hardware.get("chip_type", "")
                    if "Apple" in chip_type:
                        # Try to get base frequency from sysctl (may not be available)
                        freq_result = subprocess.run(
                            ["sysctl", "-n", "hw.cpufrequency"],  # nosec B603, B607
                            capture_output=True,
                            text=True,
                            timeout=10,
                            check=False,
                        )
                        if freq_result.returncode == 0 and freq_result.stdout.strip():
                            try:
                                # hw.cpufrequency is in Hz, convert to MHz
                                freq_hz = int(freq_result.stdout.strip())
                                cpu_info["frequency_mhz"] = freq_hz // 1000000
                            except ValueError:
                                # If we can't get frequency, leave it empty
                                pass
                        else:
                            # Try alternative sysctl parameters
                            for sysctl_key in ["hw.cpufrequency_max", "hw.tbfrequency"]:
                                freq_result = subprocess.run(
                                    ["sysctl", "-n", sysctl_key],  # nosec B603, B607
                                    capture_output=True,
                                    text=True,
                                    timeout=10,
                                    check=False,
                                )
                                if (
                                    freq_result.returncode == 0
                                    and freq_result.stdout.strip()
                                ):
                                    try:
                                        freq_hz = int(freq_result.stdout.strip())
                                        # For tb frequency, it's typically much higher, use a heuristic
                                        if sysctl_key == "hw.tbfrequency":
                                            # Typical Apple Silicon base frequency is around 3.2GHz
                                            cpu_info["frequency_mhz"] = 3200
                                        else:
                                            cpu_info["frequency_mhz"] = (
                                                freq_hz // 1000000
                                            )
                                        break
                                    except ValueError:
                                        continue

        except Exception as e:
            cpu_info["error"] = _("Failed to get macOS CPU info: %s") % str(e)

        return cpu_info

    def _get_macos_memory_info(self) -> Dict[str, Any]:
        """Get memory information on macOS using system_profiler."""

        memory_info = {}
        try:
            result = subprocess.run(
                ["system_profiler", "-json", "SPHardwareDataType"],  # nosec B603, B607
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
            if result.returncode == 0:
                data = json.loads(result.stdout)
                hardware = data.get("SPHardwareDataType", [{}])[0]

                memory_str = hardware.get("physical_memory", "")
                if memory_str:
                    # Parse memory string like "16 GB"
                    if "GB" in memory_str:
                        memory_gb = float(memory_str.replace(" GB", ""))
                        memory_info["total_mb"] = int(memory_gb * 1024)
                    elif "MB" in memory_str:
                        memory_info["total_mb"] = int(memory_str.replace(" MB", ""))

        except Exception as e:
            memory_info["error"] = _("Failed to get macOS memory info: %s") % str(e)

        return memory_info

    def _get_macos_storage_info(self) -> List[Dict[str, Any]]:
        """Get storage information on macOS using system_profiler and df."""

        storage_devices = []
        try:  # pylint: disable=too-many-nested-blocks
            # Get basic storage info from system_profiler
            result = subprocess.run(
                ["system_profiler", "-json", "SPStorageDataType"],  # nosec B603, B607
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )

            # Get disk usage info from df
            df_result = subprocess.run(
                ["df", "-k"],  # Get output in 1K blocks  # nosec B603, B607
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )

            # Parse df output to create a mapping of mount points to usage data
            mount_usage = {}
            if df_result.returncode == 0:
                lines = df_result.stdout.split("\n")[1:]  # Skip header
                i = 0
                while i < len(lines):
                    line = lines[i].strip()
                    if not line:
                        i += 1
                        continue

                    parts = line.split()

                    # Handle wrapped lines (when device name is too long)
                    if len(parts) == 1:
                        # This is just the device name, data is on next line
                        if i + 1 < len(lines):
                            next_line = lines[i + 1].strip()
                            parts = [parts[0]] + next_line.split()
                            i += 1

                    if len(parts) >= 6:
                        # Standard df output: device, total, used, avail, percent, mount
                        mount_point = parts[-1]  # Last column is mount point

                        # Find the numeric columns (total, used, available)
                        # They should be at positions 1, 2, 3 after any wrapped device name
                        numeric_start = 1
                        while (
                            numeric_start < len(parts) - 4
                            and not parts[numeric_start].isdigit()
                        ):
                            numeric_start += 1

                        if numeric_start < len(parts) - 4:
                            total_kb = (
                                int(parts[numeric_start])
                                if parts[numeric_start].isdigit()
                                else 0
                            )
                            used_kb = (
                                int(parts[numeric_start + 1])
                                if parts[numeric_start + 1].isdigit()
                                else 0
                            )
                            available_kb = (
                                int(parts[numeric_start + 2])
                                if parts[numeric_start + 2].isdigit()
                                else 0
                            )

                            mount_usage[mount_point] = {
                                "capacity_bytes": total_kb * 1024,
                                "used_bytes": used_kb * 1024,
                                "available_bytes": available_kb * 1024,
                            }
                    i += 1

            if result.returncode == 0:
                data = json.loads(result.stdout)
                storage_data = data.get("SPStorageDataType", [])

                for device in storage_data:
                    mount_point = device.get("mount_point", "")
                    usage_info = mount_usage.get(mount_point, {})

                    # Special handling for macOS APFS volumes that report incorrect usage
                    # APFS containers share space, and system volumes often report minimal usage
                    # Look for a better volume in the same physical drive that has more accurate data
                    if device.get("file_system") == "APFS" and usage_info:
                        # If this volume shows suspiciously low usage (< 5% on a system drive)
                        # try to find a related volume with more accurate data
                        if (
                            usage_info.get("capacity_bytes", 0) > 100 * 1024**3
                        ):  # > 100GB
                            used_pct = (
                                usage_info.get("used_bytes", 0)
                                / usage_info.get("capacity_bytes", 1)
                            ) * 100
                            if used_pct < 5:  # Suspiciously low usage
                                # Look for other volumes with same capacity (same APFS container)
                                same_capacity = usage_info.get("capacity_bytes")
                                for other_mount, other_usage in mount_usage.items():
                                    if (
                                        other_mount != mount_point
                                        and other_usage.get("capacity_bytes")
                                        == same_capacity
                                    ):
                                        other_used_pct = (
                                            other_usage.get("used_bytes", 0)
                                            / other_usage.get("capacity_bytes", 1)
                                        ) * 100
                                        if other_used_pct > used_pct:
                                            # Found a volume with more realistic usage, use it
                                            usage_info = other_usage
                                            break

                    # Filter out unwanted mount points and system volumes
                    excluded_mount_patterns = [
                        "/dev",
                        "/System/Volumes/VM",
                        "/System/Volumes/Preboot",
                        "/System/Volumes/Update",
                        "/System/Volumes/xarts",
                        "/System/Volumes/iSCPreboot",
                        "/System/Volumes/Hardware",
                        "/System/Volumes/Data",
                        "/System/Volumes/Recovery",
                    ]

                    # Skip if mount point matches excluded patterns
                    if any(
                        mount_point.startswith(pattern)
                        for pattern in excluded_mount_patterns
                    ):
                        continue

                    # Skip APFS snapshots
                    if "snapshot" in device.get("_name", "").lower():
                        continue

                    device_type = device.get("physical_drive", {}).get(
                        "device_name", ""
                    )

                    device_info = {
                        "name": device.get("_name", ""),
                        "device_path": device.get("bsd_name", ""),
                        "mount_point": mount_point,
                        "file_system": device.get("file_system", ""),
                        "device_type": device_type,
                        "capacity_bytes": usage_info.get("capacity_bytes"),
                        "used_bytes": usage_info.get("used_bytes"),
                        "available_bytes": usage_info.get("available_bytes"),
                        "is_physical": self._is_physical_volume_macos(
                            {"device_type": device_type}
                        ),
                    }
                    storage_devices.append(device_info)

        except Exception as e:
            storage_devices.append(
                {"error": _("Failed to get macOS storage info: %s") % str(e)}
            )

        # Don't collect APFS containers - they're of no interest to users
        # Only collect actual mounted volumes with slices (e.g., disk3s1, disk3s5)

        return storage_devices

    def _get_macos_apfs_containers(self) -> List[Dict[str, Any]]:
        """Get physical APFS containers using diskutil list."""

        containers = []
        try:  # pylint: disable=too-many-nested-blocks
            result = subprocess.run(
                ["diskutil", "list"],  # nosec B603, B607
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )

            if result.returncode == 0:
                lines = result.stdout.split("\n")
                current_disk = None
                disk_images = set()  # Track which base disks are disk images

                # First pass: identify disk images
                for line in lines:
                    disk_image_match = re.match(r"/dev/(disk\d+) \(disk image\):", line)
                    if disk_image_match:
                        disk_images.add(disk_image_match.group(1))

                # Second pass: process APFS containers
                for line in lines:
                    # Look for disk entries like "/dev/disk3 (synthesized):"
                    disk_match = re.match(r"/dev/(disk\d+) \(synthesized\):", line)
                    if disk_match:
                        current_disk = disk_match.group(1)
                        continue

                    # Look for APFS Container Scheme lines
                    if current_disk and "APFS Container Scheme" in line:
                        parts = line.split()
                        if len(parts) >= 6:
                            # Pattern: "0: APFS Container Scheme - +994.7 GB disk3"
                            # Look for size pattern like "+994.7"
                            size_bytes = None
                            for i, part in enumerate(parts):
                                if part.startswith("+") and i + 1 < len(parts):
                                    size_val_str = part[1:]  # Remove the +
                                    unit = parts[i + 1]  # Next part should be GB/TB
                                    try:
                                        size_val = float(size_val_str)
                                        if unit == "GB":
                                            size_bytes = int(size_val * 1024**3)
                                        elif unit == "TB":
                                            size_bytes = int(size_val * 1024**4)
                                        elif unit == "MB":
                                            size_bytes = int(size_val * 1024**2)
                                        break
                                    except ValueError:
                                        pass

                            # Determine if this container is built on a disk image
                            # We need to continue reading to find the "Physical Store" line
                            is_physical = True  # Default to physical

                            container_info = {
                                "name": f"APFS Container {current_disk}",
                                "device_path": current_disk,
                                "mount_point": "",  # Containers aren't mounted
                                "file_system": "APFS",
                                "device_type": "APFS Container",
                                "capacity_bytes": size_bytes,
                                "used_bytes": None,  # Not available for containers
                                "available_bytes": None,  # Not available for containers
                                "is_physical": is_physical,
                                "_current_disk": current_disk,  # Temporary field for processing
                            }
                            containers.append(container_info)
                        current_disk = None  # Reset after processing

                    # Look for "Physical Store" lines to determine if container is on disk image
                    if "Physical Store" in line and containers:
                        # Pattern: "                                 Physical Store disk4s1"
                        parts = line.strip().split()
                        if (
                            len(parts) >= 3
                            and parts[0] == "Physical"
                            and parts[1] == "Store"
                        ):
                            store_device = parts[2]  # e.g., "disk4s1"
                            base_disk = re.match(r"(disk\d+)", store_device)
                            if base_disk:
                                base_disk_num = base_disk.group(1)
                                # Find the most recent container and update its is_physical status
                                for container in reversed(containers):
                                    if container.get("_current_disk"):
                                        # If the base disk is a disk image, this container is logical
                                        container["is_physical"] = (
                                            base_disk_num not in disk_images
                                        )
                                        del container[
                                            "_current_disk"
                                        ]  # Remove temporary field
                                        break

        except Exception as e:
            containers.append(
                {"error": _("Failed to get APFS container info: %s") % str(e)}
            )

        # Clean up any remaining temporary fields
        for container in containers:
            if "_current_disk" in container:
                del container["_current_disk"]

        return containers

    def _is_physical_volume_macos(self, device: Dict[str, Any]) -> bool:
        """
        Determine if a macOS volume represents a physical device or logical volume.

        From a user perspective:
        - Physical: Main system storage (even if technically a logical volume)
        - Logical: Disk images, simulators, etc.
        """
        device_type = device.get("device_type", "").lower()

        # Simple rule: Disk Images are logical, everything else is physical
        # This treats the main system storage as physical from the user's perspective
        if "disk image" in device_type:
            return False

        # Everything else (APPLE SSD, etc.) is considered physical
        return True

    def _get_macos_network_info(self) -> List[Dict[str, Any]]:
        """Get network information on macOS using system_profiler and ifconfig."""

        network_interfaces = []
        try:  # pylint: disable=too-many-nested-blocks
            # Get basic network info from system_profiler
            result = subprocess.run(
                ["system_profiler", "-json", "SPNetworkDataType"],  # nosec B603, B607
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )

            # Get detailed interface info from ifconfig
            ifconfig_result = subprocess.run(
                ["ifconfig"],  # nosec B603, B607
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )

            # Parse ifconfig output to get IP addresses and MAC addresses
            interface_details = {}
            if ifconfig_result.returncode == 0:
                current_interface = None
                for line in ifconfig_result.stdout.split("\n"):
                    # New interface starts without leading whitespace
                    if line and not line.startswith((" ", "\t")):
                        interface_match = re.match(r"^(\w+):", line)
                        if interface_match:
                            current_interface = interface_match.group(1)
                            interface_details[current_interface] = {
                                "is_active": "RUNNING" in line,
                                "mac_address": None,
                                "ipv4_address": None,
                                "ipv6_address": None,
                                "subnet_mask": None,
                            }
                    elif current_interface and line.strip():
                        # Extract MAC address
                        if "ether" in line:
                            mac_match = re.search(r"ether ([a-fA-F0-9:]{17})", line)
                            if mac_match:
                                interface_details[current_interface]["mac_address"] = (
                                    mac_match.group(1)
                                )
                        # Extract IPv4 address
                        elif "inet " in line and "inet6" not in line:
                            ipv4_match = re.search(r"inet (\d+\.\d+\.\d+\.\d+)", line)
                            mask_match = re.search(r"netmask (0x[a-fA-F0-9]+)", line)
                            if ipv4_match:
                                interface_details[current_interface]["ipv4_address"] = (
                                    ipv4_match.group(1)
                                )
                            if mask_match:
                                # Convert hex netmask to dotted decimal
                                hex_mask = mask_match.group(1)
                                mask_int = int(hex_mask, 16)
                                mask_bytes = [
                                    (mask_int >> (8 * (3 - i))) & 0xFF for i in range(4)
                                ]
                                interface_details[current_interface]["subnet_mask"] = (
                                    ".".join(map(str, mask_bytes))
                                )
                        # Extract IPv6 address (first non-link-local)
                        elif (
                            "inet6" in line
                            and "fe80:" not in line
                            and "scopeid" not in line
                        ):
                            ipv6_match = re.search(r"inet6 ([a-fA-F0-9:]+)", line)
                            if (
                                ipv6_match
                                and not interface_details[current_interface][
                                    "ipv6_address"
                                ]
                            ):
                                interface_details[current_interface]["ipv6_address"] = (
                                    ipv6_match.group(1)
                                )

            if result.returncode == 0:
                data = json.loads(result.stdout)
                network_data = data.get("SPNetworkDataType", [])

                for interface in network_data:
                    name = interface.get("_name", "")
                    # Try to match with ifconfig data using the interface field first, then name patterns
                    details = {}
                    interface_id = interface.get("interface", "")

                    # First try exact match with interface field (e.g., "en0")
                    if interface_id and interface_id in interface_details:
                        details = interface_details[interface_id]
                    else:
                        # Fallback to pattern matching
                        for if_name, if_details in interface_details.items():
                            if (
                                if_name.lower() in name.lower()
                                or name.lower() in if_name.lower()
                            ):
                                details = if_details
                                break

                    interface_info = {
                        "name": name,
                        "interface_type": interface.get("type", ""),
                        "hardware_type": interface.get("hardware", ""),
                        "mac_address": details.get("mac_address"),
                        "ipv4_address": details.get("ipv4_address"),
                        "ipv6_address": details.get("ipv6_address"),
                        "subnet_mask": details.get("subnet_mask"),
                        "is_active": details.get(
                            "is_active", interface.get("has_ip_assigned", False)
                        ),
                        "speed_mbps": None,  # Not easily available on macOS via command line
                    }
                    network_interfaces.append(interface_info)

        except Exception as e:
            network_interfaces.append(
                {"error": _("Failed to get macOS network info: %s") % str(e)}
            )

        return network_interfaces

    # Linux hardware collection methods
    def _get_linux_cpu_info(self) -> Dict[str, Any]:
        """Get CPU information on Linux using /proc/cpuinfo and lscpu."""
        cpu_info = {}
        try:  # pylint: disable=too-many-nested-blocks
            # First try lscpu for structured info

            result = subprocess.run(
                ["lscpu"],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,  # nosec B603, B607
            )
            if result.returncode == 0:
                for line in result.stdout.split("\n"):
                    if ":" in line:
                        key, value = line.split(":", 1)
                        key = key.strip()
                        value = value.strip()

                        if key == "Vendor ID":
                            cpu_info["vendor"] = value
                        elif key == "Model name":
                            cpu_info["model"] = value
                        elif key == "CPU(s)":
                            cpu_info["threads"] = int(value)
                        elif key == "Core(s) per socket":
                            cores_per_socket = int(value)
                            sockets = cpu_info.get("sockets", 1)
                            cpu_info["cores"] = cores_per_socket * sockets
                        elif key == "Socket(s)":
                            cpu_info["sockets"] = int(value)
                        elif key in ("CPU MHz", "CPU max MHz"):
                            # Use max frequency if current frequency not already set
                            if "frequency_mhz" not in cpu_info or key == "CPU max MHz":
                                try:
                                    cpu_info["frequency_mhz"] = int(float(value))
                                except ValueError:
                                    pass

            # Fallback to /proc/cpuinfo if lscpu not available
            if not cpu_info:
                with open("/proc/cpuinfo", "r", encoding="utf-8") as f:
                    lines = f.readlines()

                processor_count = 0
                for line in lines:
                    if ":" in line:
                        key, value = line.split(":", 1)
                        key = key.strip()
                        value = value.strip()

                        if key == "vendor_id" and "vendor" not in cpu_info:
                            cpu_info["vendor"] = value
                        elif key == "model name" and "model" not in cpu_info:
                            cpu_info["model"] = value
                        elif key == "cpu MHz":
                            try:
                                freq = int(float(value))
                                # Only set if we don't already have a frequency or if this is non-zero
                                if "frequency_mhz" not in cpu_info or freq > 0:
                                    cpu_info["frequency_mhz"] = freq
                            except ValueError:
                                pass
                        elif key == "processor":
                            processor_count = max(processor_count, int(value) + 1)

                if processor_count > 0:
                    cpu_info["threads"] = processor_count

            # If still no frequency, try additional methods
            if "frequency_mhz" not in cpu_info or cpu_info.get("frequency_mhz", 0) == 0:
                # Try to read from cpufreq scaling
                try:
                    with open(
                        "/sys/devices/system/cpu/cpu0/cpufreq/cpuinfo_max_freq",
                        "r",
                        encoding="utf-8",
                    ) as f:
                        # This value is in KHz, convert to MHz
                        freq_khz = int(f.read().strip())
                        cpu_info["frequency_mhz"] = freq_khz // 1000
                except (FileNotFoundError, ValueError, IOError):
                    # Try to extract from model name as last resort
                    if "model" in cpu_info:

                        model = cpu_info["model"]
                        # Look for patterns like "@ 2.60GHz" or "2600MHz" in CPU model
                        ghz_match = re.search(
                            r"@\s*(\d+\.?\d*)\s*GHz", model, re.IGNORECASE
                        )
                        if ghz_match:
                            freq_ghz = float(ghz_match.group(1))
                            cpu_info["frequency_mhz"] = int(freq_ghz * 1000)
                        else:
                            mhz_match = re.search(r"(\d+)\s*MHz", model, re.IGNORECASE)
                            if mhz_match:
                                cpu_info["frequency_mhz"] = int(mhz_match.group(1))

        except Exception as e:
            cpu_info["error"] = _("Failed to get Linux CPU info: %s") % str(e)

        return cpu_info

    def _get_linux_memory_info(self) -> Dict[str, Any]:
        """Get memory information on Linux using /proc/meminfo."""
        memory_info = {}
        try:
            with open("/proc/meminfo", "r", encoding="utf-8") as f:
                for line in f:
                    if line.startswith("MemTotal:"):
                        # MemTotal is in kB
                        mem_kb = int(line.split()[1])
                        memory_info["total_mb"] = mem_kb // 1024
                        break

        except Exception as e:
            memory_info["error"] = _("Failed to get Linux memory info: %s") % str(e)

        return memory_info

    def _get_linux_storage_info(self) -> List[Dict[str, Any]]:
        """Get storage information on Linux using lsblk and df."""

        storage_devices = []
        try:
            # Use lsblk to get block devices
            result = subprocess.run(
                [
                    "lsblk",
                    "-J",
                    "-o",
                    "NAME,SIZE,TYPE,MOUNTPOINT,FSTYPE",
                ],  # nosec B603, B607
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
            if result.returncode == 0:
                data = json.loads(result.stdout)
                for device in data.get("blockdevices", []):
                    device_info = {
                        "name": device.get("name", ""),
                        "size": device.get("size", ""),
                        "type": device.get("type", ""),
                        "mount_point": device.get("mountpoint", ""),
                        "file_system": device.get("fstype", ""),
                        "is_physical": self._is_physical_volume_linux(device),
                    }
                    storage_devices.append(device_info)

                    # Add children (partitions)
                    for child in device.get("children", []):
                        child_info = {
                            "name": child.get("name", ""),
                            "size": child.get("size", ""),
                            "type": child.get("type", ""),
                            "mount_point": child.get("mountpoint", ""),
                            "file_system": child.get("fstype", ""),
                            "parent": device.get("name", ""),
                            "is_physical": self._is_physical_volume_linux(
                                child, is_child=True
                            ),
                        }
                        storage_devices.append(child_info)

        except Exception as e:
            storage_devices.append(
                {"error": _("Failed to get Linux storage info: %s") % str(e)}
            )

        return storage_devices

    def _is_physical_volume_linux(
        self, device: Dict[str, Any], is_child: bool = False
    ) -> bool:
        """
        Determine if a Linux volume represents a physical device or logical volume.

        Physical volumes are typically:
        - Actual disk drives (disk, rom)
        - RAID arrays
        - External drives

        Logical volumes are typically:
        - Partitions (part)
        - LVM logical volumes (lvm)
        - Loop devices (loop)
        - RAM disks
        """
        device_name = device.get("name", "").lower()
        device_type = device.get("type", "").lower()
        mount_point = device.get("mountpoint", "") or device.get("mount_point", "")

        # Check for explicitly logical device types
        logical_types = [
            "part",
            "lvm",
            "loop",
            "crypt",
            "raid1",
            "raid0",
            "raid5",
            "raid10",
        ]

        # Check for logical devices by type, name patterns, or mount patterns
        is_logical = (
            device_type in logical_types
            or device_name.startswith(("loop", "ram", "tmpfs"))
            or any(
                mount_point.startswith(pattern)
                for pattern in [
                    "/dev",
                    "/proc",
                    "/sys",
                    "/run",
                    "/boot/efi",
                    "/snap/",
                    "/var/lib/snapd",
                ]
            )
        )

        if is_logical:
            return False

        # Check for explicitly physical device types
        physical_types = ["disk", "rom"]
        is_physical_type = device_type in physical_types and not is_child

        # Root filesystem is considered physical for user clarity
        is_root_fs = mount_point == "/"

        # USB, SCSI, and SATA devices are typically physical
        is_hardware_device = any(
            keyword in device_name for keyword in ["usb", "sd", "hd", "nvme"]
        )

        # Return True if explicitly physical, root filesystem, or hardware device (but not child)
        return (
            is_physical_type
            or is_root_fs
            or (is_hardware_device and not is_child)
            or not is_child  # Default: top-level devices are physical
        )

    def _get_linux_network_info(self) -> List[Dict[str, Any]]:
        """Get network information on Linux using /sys/class/net."""

        network_interfaces = []
        try:
            net_dir = "/sys/class/net"
            if os.path.exists(net_dir):
                for interface in os.listdir(net_dir):
                    if interface == "lo":  # Skip loopback
                        continue

                    interface_path = os.path.join(net_dir, interface)
                    interface_info = {"name": interface}

                    # Get interface type
                    type_file = os.path.join(interface_path, "type")
                    if os.path.exists(type_file):
                        with open(type_file, "r", encoding="utf-8") as f:
                            interface_info["type"] = f.read().strip()

                    # Get operational state
                    operstate_file = os.path.join(interface_path, "operstate")
                    if os.path.exists(operstate_file):
                        with open(operstate_file, "r", encoding="utf-8") as f:
                            interface_info["state"] = f.read().strip()

                    # Get MAC address
                    address_file = os.path.join(interface_path, "address")
                    if os.path.exists(address_file):
                        with open(address_file, "r", encoding="utf-8") as f:
                            interface_info["mac_address"] = f.read().strip()

                    network_interfaces.append(interface_info)

        except Exception as e:
            network_interfaces.append(
                {"error": _("Failed to get Linux network info: %s") % str(e)}
            )

        return network_interfaces

    # Windows hardware collection methods
    def _get_windows_cpu_info(self) -> Dict[str, Any]:
        """Get CPU information on Windows using wmic."""

        cpu_info = {}
        try:
            # Get CPU info using wmic
            result = subprocess.run(
                [
                    "wmic",
                    "cpu",
                    "get",
                    "Name,Manufacturer,NumberOfCores,NumberOfLogicalProcessors,MaxClockSpeed",
                    "/format:csv",
                ],  # nosec B603, B607
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
            if result.returncode == 0:
                lines = [
                    line for line in result.stdout.strip().split("\n") if line.strip()
                ]
                if len(lines) > 1:
                    # Skip header and get first CPU data line
                    data = lines[1].split(",")
                    if len(data) >= 6:
                        # CSV format: Node,Manufacturer,MaxClockSpeed,Name,NumberOfCores,NumberOfLogicalProcessors
                        cpu_info["vendor"] = data[1].strip()
                        cpu_info["frequency_mhz"] = (
                            int(data[2]) if data[2].strip() else 0
                        )
                        cpu_info["model"] = data[3].strip()
                        cpu_info["cores"] = int(data[4]) if data[4].strip() else 0
                        cpu_info["threads"] = int(data[5]) if data[5].strip() else 0

        except Exception as e:
            cpu_info["error"] = _("Failed to get Windows CPU info: %s") % str(e)

        return cpu_info

    def _get_windows_memory_info(self) -> Dict[str, Any]:
        """Get memory information on Windows using wmic."""

        memory_info = {}
        try:
            result = subprocess.run(
                [
                    "wmic",
                    "computersystem",
                    "get",
                    "TotalPhysicalMemory",
                    "/format:csv",
                ],  # nosec B603, B607
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
            if result.returncode == 0:
                lines = [
                    line for line in result.stdout.strip().split("\n") if line.strip()
                ]
                if len(lines) > 1:
                    data = lines[1].split(",")
                    if len(data) >= 2 and data[1].strip():
                        # Convert bytes to MB
                        memory_bytes = int(data[1].strip())
                        memory_info["total_mb"] = memory_bytes // (1024 * 1024)

        except Exception as e:
            memory_info["error"] = _("Failed to get Windows memory info: %s") % str(e)

        return memory_info

    def _get_windows_storage_info(self) -> List[Dict[str, Any]]:
        """Get storage information on Windows using wmic for both physical and logical drives."""

        storage_devices = []

        # First, get physical disk drives
        try:
            result = subprocess.run(
                [
                    "wmic",
                    "diskdrive",
                    "get",
                    "Size,Model,DeviceID,InterfaceType",
                    "/format:csv",
                ],  # nosec B603, B607
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
            if result.returncode == 0:
                lines = [
                    line for line in result.stdout.strip().split("\n") if line.strip()
                ]
                for line in lines[1:]:  # Skip header
                    data = line.split(",")
                    if len(data) >= 4 and data[1].strip():
                        device_info = {
                            "name": data[1].strip(),  # DeviceID like \\.\PHYSICALDRIVE0
                            "model": data[3].strip() if len(data) > 3 else "Unknown",
                            "size": int(data[4]) if data[4].strip().isdigit() else 0,
                            "interface_type": (
                                data[2].strip() if len(data) > 2 else "Unknown"
                            ),
                            "is_physical": True,
                            "device_type": "physical",
                            "file_system": "N/A",  # Physical drives don't have filesystems
                            "free_space": 0,  # Physical drives don't have free space concept
                        }
                        storage_devices.append(device_info)
        except Exception as e:
            self.logger.error("Failed to get Windows physical disk info: %s", str(e))

        # Then, get logical drives (partitions/volumes)
        try:
            result = subprocess.run(
                [
                    "wmic",
                    "logicaldisk",
                    "get",
                    "Size,FreeSpace,FileSystem,DeviceID,VolumeName",
                    "/format:csv",
                ],  # nosec B603, B607
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
            if result.returncode == 0:
                lines = [
                    line for line in result.stdout.strip().split("\n") if line.strip()
                ]
                for line in lines[1:]:  # Skip header
                    data = line.split(",")
                    if len(data) >= 4 and data[1].strip():
                        device_info = {
                            "name": data[1].strip(),  # Drive letter like C:
                            "file_system": data[2].strip(),
                            "free_space": (
                                int(data[3]) if data[3].strip().isdigit() else 0
                            ),
                            "size": int(data[4]) if data[4].strip().isdigit() else 0,
                            "volume_name": data[5].strip() if len(data) > 5 else "",
                            "is_physical": False,  # Logical drives are never physical
                            "device_type": "logical",
                        }
                        storage_devices.append(device_info)

        except Exception as e:
            storage_devices.append(
                {"error": _("Failed to get Windows logical disk info: %s") % str(e)}
            )

        return storage_devices

    def _is_physical_volume_windows(self, drive_letter: str) -> bool:
        """
        Determine if a Windows volume represents a physical device or logical volume.

        Physical volumes are typically:
        - Primary system drives (C:, D:)
        - External drives
        - Removable media

        Logical volumes are typically:
        - Network drives
        - Virtual drives
        - RAM disks
        - CD/DVD drives (considered logical for practical purposes)
        """
        drive_letter = drive_letter.upper().rstrip(":")

        # Network drives are always logical
        if len(drive_letter) > 1:
            return False

        # Single letter drives - most are physical, but some exceptions
        if drive_letter in ["A", "B"]:  # Floppy drives (historical)
            return False

        if drive_letter in ["X", "Y", "Z"]:  # Often used for network/temp drives
            return False

        # C: is typically the system drive (physical)
        # D: through W: are typically physical drives or partitions
        return True

    def _is_physical_volume_generic(self, device_name: str, mount_point: str) -> bool:
        """
        Generic physical/logical volume detection for unknown platforms.

        This is a fallback method for platforms where we don't have
        specific detection logic.
        """
        device_name = device_name.lower()
        mount_point = mount_point.lower()

        # Virtual/special filesystems are logical
        logical_patterns = [
            "tmpfs",
            "proc",
            "sys",
            "dev",
            "run",
            "cgroup",
            "security",
            "loop",
            "ram",
            "swap",
        ]

        for pattern in logical_patterns:
            if pattern in device_name or pattern in mount_point:
                return False

        # Root and common mount points are considered physical
        if mount_point in ["/", "/home", "/var", "/usr", "/opt"]:
            return True

        # Default to physical for unknown cases
        return True

    def _get_windows_network_info(self) -> List[Dict[str, Any]]:
        """Get network information on Windows using ipconfig /all."""

        network_interfaces = []

        try:
            # Run ipconfig /all to get comprehensive network information
            result = subprocess.run(
                ["ipconfig", "/all"],  # nosec B603, B607
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )

            if result.returncode != 0:
                self.logger.error("ipconfig /all failed with return code: %d", result.returncode)
                return network_interfaces

            # Parse the ipconfig output
            output = result.stdout
            current_adapter = None

            for line in output.split('\n'):
                original_line = line
                line = line.strip()

                # Skip empty lines and general system info
                if not line or line.startswith('Windows IP Configuration') or \
                   line.startswith('Host Name') or line.startswith('Primary Dns Suffix') or \
                   line.startswith('Node Type') or line.startswith('IP Routing Enabled') or \
                   line.startswith('WINS Proxy Enabled') or line.startswith('DNS Suffix Search List'):
                    continue

                # Detect new adapter sections (these are not indented)
                if not original_line.startswith('   ') and ('adapter ' in line and ':' in line):
                    # Save previous adapter if it exists
                    if current_adapter:
                        network_interfaces.append(current_adapter)

                    # Start new adapter
                    adapter_name = line.split(':')[0].strip()
                    current_adapter = {
                        "name": adapter_name,
                        "description": adapter_name,
                        "type": "Unknown",
                        "mac_address": None,
                        "ip_addresses": [],
                        "subnet_masks": [],
                        "gateways": [],
                        "dns_servers": [],
                        "dhcp_enabled": False,
                        "enabled": True,
                        "is_active": False,
                        "media_state": "Unknown",
                        "connection_status": "Unknown"
                    }
                    continue

                # Parse adapter properties (these are indented with spaces)
                if current_adapter and original_line.startswith('   ') and ':' in line:
                    key, value = line.split(':', 1)
                    # Clean up the key - remove dots and extra spaces
                    key = key.strip().replace('.', '').replace(' ', ' ').strip()
                    value = value.strip()

                    if "Media State" in key:
                        current_adapter["media_state"] = value
                        current_adapter["is_active"] = value != "Media disconnected"
                        current_adapter["connection_status"] = "Connected" if value != "Media disconnected" else "Disconnected"

                    elif "Description" in key:
                        current_adapter["description"] = value
                        # Extract adapter type from description and adapter name
                        adapter_name = current_adapter.get("name", "")
                        combined_text = f"{adapter_name} {value}".lower()

                        if "bluetooth" in combined_text:
                            current_adapter["type"] = "Bluetooth"
                        elif "wi-fi" in combined_text or "wireless" in combined_text:
                            current_adapter["type"] = "Wireless"
                        elif "ethernet" in combined_text or "gigabit" in combined_text or "network connection" in combined_text:
                            current_adapter["type"] = "Ethernet"
                        elif "loopback" in combined_text:
                            current_adapter["type"] = "Loopback"
                        elif "tunnel" in combined_text or "vpn" in combined_text:
                            current_adapter["type"] = "Tunnel"
                        else:
                            current_adapter["type"] = "Unknown"

                    elif "Physical Address" in key:
                        current_adapter["mac_address"] = value

                    elif "DHCP Enabled" in key:
                        current_adapter["dhcp_enabled"] = value.lower() == "yes"

                    elif "IPv4 Address" in key or key == "IP Address":
                        # Handle multiple IP addresses
                        if value and value != "(none)" and value:
                            # Remove any suffixes like "(Preferred)" and handle IPv6 zone IDs
                            ip = value.split('(')[0].strip()
                            if '%' in ip:  # Remove IPv6 zone ID
                                ip = ip.split('%')[0]
                            if ip:
                                current_adapter["ip_addresses"].append(ip)
                                if not current_adapter["is_active"]:
                                    current_adapter["is_active"] = True
                                    current_adapter["connection_status"] = "Connected"

                    elif "IPv6 Address" in key or "Link-local IPv6 Address" in key:
                        if value and value != "(none)" and value:
                            # Remove any suffixes like "(Preferred)" and handle IPv6 zone IDs
                            ip = value.split('(')[0].strip()
                            if '%' in ip:  # Remove IPv6 zone ID
                                ip = ip.split('%')[0]
                            if ip:
                                current_adapter["ip_addresses"].append(ip)
                                if not current_adapter["is_active"]:
                                    current_adapter["is_active"] = True
                                    current_adapter["connection_status"] = "Connected"

                    elif "Subnet Mask" in key:
                        if value and value != "(none)" and value:
                            current_adapter["subnet_masks"].append(value)

                    elif "Default Gateway" in key:
                        if value and value != "(none)" and value:
                            current_adapter["gateways"].append(value)

                    elif "DNS Servers" in key:
                        if value and value != "(none)" and value:
                            current_adapter["dns_servers"].append(value)

            # Don't forget the last adapter
            if current_adapter:
                network_interfaces.append(current_adapter)

        except Exception as e:
            self.logger.error("Failed to get Windows network info via ipconfig: %s", str(e))
            network_interfaces.append(
                {"error": _("Failed to get Windows network configuration: %s") % str(e)}
            )

        return network_interfaces

    # BSD hardware collection methods
    def _get_bsd_cpu_info(self) -> Dict[str, Any]:
        """Get CPU information on OpenBSD/FreeBSD using sysctl."""

        cpu_info = {}
        try:
            # Get CPU model name
            result = subprocess.run(
                ["sysctl", "-n", "hw.model"],  # nosec B603, B607
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
            if result.returncode == 0:
                cpu_info["model"] = result.stdout.strip()
                # Extract vendor from model name
                model_lower = result.stdout.lower()
                if "intel" in model_lower:
                    cpu_info["vendor"] = "Intel"
                elif "amd" in model_lower:
                    cpu_info["vendor"] = "AMD"
                else:
                    cpu_info["vendor"] = "Unknown"

            # Get number of CPUs
            result = subprocess.run(
                ["sysctl", "-n", "hw.ncpu"],  # nosec B603, B607
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
            if result.returncode == 0:
                cpu_info["threads"] = int(result.stdout.strip())

            # Try to get physical CPU cores (may not be available on all BSD systems)
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
                # Fallback to logical CPUs if physical cores not available
                cpu_info["cores"] = cpu_info.get("threads", 0)

            # Try to get CPU frequency (may not be available)
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
                        # TSC frequency is in Hz, convert to MHz
                        cpu_info["frequency_mhz"] = int(int(freq_value) // 1000000)
                    else:
                        # hw.cpuspeed and hw.clockrate are typically in MHz
                        cpu_info["frequency_mhz"] = int(freq_value)
                    break

            # If no frequency found from sysctl, try to extract from CPU model
            if "frequency_mhz" not in cpu_info and "model" in cpu_info:

                model = cpu_info["model"]
                # Look for patterns like "@ 1.90GHz" or "1900MHz" in CPU model
                ghz_match = re.search(r"@\s*(\d+\.?\d*)\s*GHz", model, re.IGNORECASE)
                if ghz_match:
                    freq_ghz = float(ghz_match.group(1))
                    cpu_info["frequency_mhz"] = int(freq_ghz * 1000)
                else:
                    mhz_match = re.search(r"(\d+)\s*MHz", model, re.IGNORECASE)
                    if mhz_match:
                        cpu_info["frequency_mhz"] = int(mhz_match.group(1))

        except Exception as e:
            cpu_info["error"] = _("Failed to get BSD CPU info: %s") % str(e)

        return cpu_info

    def _get_bsd_memory_info(self) -> Dict[str, Any]:
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

        except Exception as e:
            memory_info["error"] = _("Failed to get BSD memory info: %s") % str(e)

        return memory_info

    def _get_bsd_storage_info(self) -> List[Dict[str, Any]]:
        """Get storage information on OpenBSD/FreeBSD using df and mount."""

        storage_devices = []
        try:
            # Get mounted filesystems
            result = subprocess.run(
                ["df", "-h"],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,  # nosec B603, B607
            )
            if result.returncode == 0:
                lines = result.stdout.strip().split("\n")[1:]  # Skip header
                for line in lines:
                    parts = line.split()
                    if len(parts) >= 6:
                        device_name = parts[0]
                        mount_point = parts[5] if len(parts) > 5 else ""

                        # Skip special filesystems that shouldn't be considered storage
                        if self._should_skip_bsd_filesystem(device_name, mount_point):
                            continue

                        is_physical = self._is_physical_volume_bsd(
                            device_name, mount_point
                        )

                        # Convert human-readable sizes to bytes
                        capacity_bytes = self._parse_size_to_bytes(parts[1])
                        used_bytes = self._parse_size_to_bytes(parts[2])
                        available_bytes = self._parse_size_to_bytes(parts[3])

                        device_info = {
                            "name": device_name,
                            "size": parts[1],
                            "used": parts[2],
                            "available": parts[3],
                            "mount_point": mount_point,
                            "type": "unknown",  # Will be updated from mount command
                            "is_physical": is_physical,
                            "device_type": "physical" if is_physical else "logical",
                            # Add fields expected by server API
                            "capacity_bytes": capacity_bytes,
                            "used_bytes": used_bytes,
                            "available_bytes": available_bytes,
                            "file_system": "unknown",  # Will be updated from mount command
                        }
                        storage_devices.append(device_info)

            # Try to get filesystem types from mount command
            result = subprocess.run(
                ["mount"],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,  # nosec B603, B607
            )
            if result.returncode == 0:
                mount_lines = result.stdout.strip().split("\n")
                device_types = {}
                for line in mount_lines:
                    if " on " in line and " type " in line:
                        parts = line.split()
                        device = parts[0]
                        type_idx = parts.index("type") + 1
                        if type_idx < len(parts):
                            device_types[device] = parts[type_idx]

                # Update storage devices with filesystem types
                for device in storage_devices:
                    if device["name"] in device_types:
                        device["type"] = device_types[device["name"]]
                        device["file_system"] = device_types[device["name"]]

            # Add physical storage devices (not shown in df but exist as block devices)
            self._add_physical_bsd_devices(storage_devices)

        except Exception as e:
            storage_devices.append(
                {"error": _("Failed to get BSD storage info: %s") % str(e)}
            )

        return storage_devices

    def _should_skip_bsd_filesystem(self, device_name: str, mount_point: str) -> bool:
        """Determine if a BSD filesystem should be skipped from storage inventory."""
        # Skip special/virtual filesystems
        skip_devices = ["tmpfs", "kernfs", "procfs", "mfs", "fdesc"]
        # Known system mount points to skip during storage inventory
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

    def _is_physical_volume_bsd(self, device_name: str, mount_point: str) -> bool:
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

        except Exception as e:
            # Skip devices we can't access, log for debugging
            logger.debug("Skipping device %s: %s", base_device, e)

    def _bytes_to_human_readable(self, size_bytes: int) -> str:
        """Convert bytes to human readable format."""
        if size_bytes == 0:
            return "0B"

        units = ["B", "K", "M", "G", "T", "P"]
        unit_index = 0
        size = float(size_bytes)

        while size >= 1024 and unit_index < len(units) - 1:
            size /= 1024
            unit_index += 1

        if unit_index == 0:
            return f"{int(size)}B"
        return f"{size:.1f}{units[unit_index]}"

    def _get_bsd_network_info(self) -> List[Dict[str, Any]]:
        """Get network information on OpenBSD/FreeBSD using ifconfig."""

        network_interfaces = []
        try:  # pylint: disable=too-many-nested-blocks
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

                    # New interface (starts at beginning of line, has interface_name:)
                    if (
                        not original_line.startswith("\t")
                        and not original_line.startswith(" ")
                        and ":" in line
                        and " flags="
                        in line  # Must have flags to be an interface header
                    ):
                        if current_interface:
                            network_interfaces.append(current_interface)

                        interface_name = line.split(":")[0]
                        if interface_name == "lo0":  # Skip loopback
                            current_interface = None
                            continue

                        # Determine if interface is up from flags
                        flags_str = ""
                        is_up = False
                        if "flags=" in line:
                            flags_start = line.find("flags=") + 6
                            flags_end = line.find(">", flags_start)
                            if flags_end > flags_start:
                                flags_str = line[flags_start:flags_end]
                                is_up = "UP" in flags_str

                        current_interface = {
                            "name": interface_name,
                            "flags": flags_str,
                            "interface_type": "ethernet",  # Default type
                            "hardware_type": "ethernet",  # Alias for compatibility
                            "mac_address": "",
                            "ipv4_address": None,
                            "ipv6_address": None,
                            "subnet_mask": None,
                            "is_active": is_up,
                            "speed_mbps": None,
                        }

                    # Interface details (indented lines)
                    elif current_interface and (
                        original_line.startswith("\t") or original_line.startswith(" ")
                    ):
                        if "ether " in line:
                            # MAC address line: "ether 08:00:27:12:34:56"
                            parts = line.split()
                            if len(parts) >= 2 and current_interface is not None:
                                # pylint: disable-next=unsupported-assignment-operation
                                current_interface["mac_address"] = parts[1]
                        elif "inet " in line and current_interface is not None:
                            # IPv4 address line: "inet 192.168.4.188 netmask 0xffffff00 broadcast 192.168.4.255"
                            parts = line.split()
                            if len(parts) >= 2:
                                # pylint: disable-next=unsupported-assignment-operation
                                current_interface["ipv4_address"] = parts[1]
                            if "netmask" in parts:
                                netmask_idx = parts.index("netmask")
                                if netmask_idx + 1 < len(parts):
                                    netmask_hex = parts[netmask_idx + 1]
                                    # Convert hex netmask to decimal notation
                                    if netmask_hex.startswith("0x"):
                                        try:
                                            netmask_int = int(netmask_hex, 16)
                                            # Convert to dotted decimal notation
                                            subnet_mask = ".".join(
                                                [
                                                    str(
                                                        (netmask_int >> (8 * (3 - i)))
                                                        & 0xFF
                                                    )
                                                    for i in range(4)
                                                ]
                                            )
                                            # pylint: disable-next=unsupported-assignment-operation
                                            current_interface["subnet_mask"] = (
                                                subnet_mask
                                            )
                                        except ValueError:
                                            pass
                        elif "inet6 " in line and current_interface is not None:
                            # IPv6 address line: "inet6 fe80::a00:27ff:fe12:3456%em0 prefixlen 64"
                            parts = line.split()
                            if len(parts) >= 2:
                                ipv6_addr = parts[1]
                                # Remove interface suffix if present (e.g., %em0)
                                if "%" in ipv6_addr:
                                    ipv6_addr = ipv6_addr.split("%")[0]
                                # Skip link-local addresses for primary IPv6
                                if (
                                    not ipv6_addr.startswith("fe80:")
                                    and current_interface is not None
                                    and current_interface.get("ipv6_address") is None
                                ):
                                    # pylint: disable-next=unsupported-assignment-operation
                                    current_interface["ipv6_address"] = ipv6_addr
                        elif "media:" in line and current_interface is not None:
                            # Media type information
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

                # Add the last interface
                if current_interface:
                    network_interfaces.append(current_interface)

        except Exception as e:
            network_interfaces.append(
                {"error": _("Failed to get BSD network info: %s") % str(e)}
            )

        return network_interfaces
