"""
Hardware collection module for SysManage Agent.
Handles platform-specific hardware information gathering.
"""

import platform
import logging
from typing import Any, Dict, List
from datetime import datetime, timezone

from i18n import _


class HardwareCollector:
    """Collects hardware information across different platforms."""

    def __init__(self):
        self.logger = logging.getLogger(__name__)

    def get_hardware_info(self) -> Dict[str, Any]:
        """Get comprehensive hardware information formatted for database storage."""
        import json

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

    # macOS hardware collection methods
    def _get_macos_cpu_info(self) -> Dict[str, Any]:
        """Get CPU information on macOS using system_profiler."""
        import subprocess
        import json

        cpu_info = {}
        try:
            # Get CPU info from system_profiler
            result = subprocess.run(
                ["system_profiler", "-json", "SPHardwareDataType"],
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

                # Extract frequency from processor name if available
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

        except Exception as e:
            cpu_info["error"] = _("Failed to get macOS CPU info: %s") % str(e)

        return cpu_info

    def _get_macos_memory_info(self) -> Dict[str, Any]:
        """Get memory information on macOS using system_profiler."""
        import subprocess
        import json

        memory_info = {}
        try:
            result = subprocess.run(
                ["system_profiler", "-json", "SPHardwareDataType"],
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
        import subprocess
        import json

        storage_devices = []
        try:
            # Get basic storage info from system_profiler
            result = subprocess.run(
                ["system_profiler", "-json", "SPStorageDataType"],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )

            # Get disk usage info from df
            df_result = subprocess.run(
                ["df", "-k"],  # Get output in 1K blocks
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
        import subprocess
        import re

        containers = []
        try:
            result = subprocess.run(
                ["diskutil", "list"],
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
        import subprocess
        import json
        import re

        network_interfaces = []
        try:
            # Get basic network info from system_profiler
            result = subprocess.run(
                ["system_profiler", "-json", "SPNetworkDataType"],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )

            # Get detailed interface info from ifconfig
            ifconfig_result = subprocess.run(
                ["ifconfig"],
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
        try:
            # First try lscpu for structured info
            import subprocess

            result = subprocess.run(
                ["lscpu"], capture_output=True, text=True, timeout=30, check=False
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
                        elif key == "CPU MHz":
                            cpu_info["frequency_mhz"] = int(float(value))

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
                        elif key == "cpu MHz" and "frequency_mhz" not in cpu_info:
                            cpu_info["frequency_mhz"] = int(float(value))
                        elif key == "processor":
                            processor_count = max(processor_count, int(value) + 1)

                if processor_count > 0:
                    cpu_info["threads"] = processor_count

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
        import subprocess
        import json

        storage_devices = []
        try:
            # Use lsblk to get block devices
            result = subprocess.run(
                ["lsblk", "-J", "-o", "NAME,SIZE,TYPE,MOUNTPOINT,FSTYPE"],
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

        # Physical device types
        physical_types = ["disk", "rom"]
        if device_type in physical_types and not is_child:
            return True

        # Logical device types
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
        if device_type in logical_types:
            return False

        # Loop devices and temporary filesystems are logical
        if device_name.startswith(("loop", "ram", "tmpfs")):
            return False

        # Virtual and special filesystems are logical
        logical_mount_patterns = [
            "/dev",
            "/proc",
            "/sys",
            "/run",
            "/boot/efi",
            "/snap/",
            "/var/lib/snapd",
        ]

        for pattern in logical_mount_patterns:
            if mount_point.startswith(pattern):
                return False

        # Root filesystem is considered physical for user clarity
        if mount_point == "/":
            return True

        # USB, SCSI, and SATA devices are typically physical
        if any(keyword in device_name for keyword in ["usb", "sd", "hd", "nvme"]):
            return not is_child  # The device itself is physical, partitions are logical

        # Default: top-level devices are physical, children are logical
        return not is_child

    def _get_linux_network_info(self) -> List[Dict[str, Any]]:
        """Get network information on Linux using /sys/class/net."""
        import os

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
        import subprocess

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
                ],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
            if result.returncode == 0:
                lines = result.stdout.strip().split("\n")
                if len(lines) > 1:
                    # Skip header and get first CPU
                    data = lines[1].split(",")
                    if len(data) >= 5:
                        cpu_info["frequency_mhz"] = (
                            int(data[1]) if data[1].strip() else 0
                        )
                        cpu_info["vendor"] = data[2].strip()
                        cpu_info["model"] = data[3].strip()
                        cpu_info["cores"] = int(data[4]) if data[4].strip() else 0
                        cpu_info["threads"] = int(data[5]) if data[5].strip() else 0

        except Exception as e:
            cpu_info["error"] = _("Failed to get Windows CPU info: %s") % str(e)

        return cpu_info

    def _get_windows_memory_info(self) -> Dict[str, Any]:
        """Get memory information on Windows using wmic."""
        import subprocess

        memory_info = {}
        try:
            result = subprocess.run(
                ["wmic", "computersystem", "get", "TotalPhysicalMemory", "/format:csv"],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
            if result.returncode == 0:
                lines = result.stdout.strip().split("\n")
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
        """Get storage information on Windows using wmic."""
        import subprocess

        storage_devices = []
        try:
            result = subprocess.run(
                [
                    "wmic",
                    "logicaldisk",
                    "get",
                    "Size,FreeSpace,FileSystem,DeviceID",
                    "/format:csv",
                ],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
            if result.returncode == 0:
                lines = result.stdout.strip().split("\n")
                for line in lines[1:]:  # Skip header
                    data = line.split(",")
                    if len(data) >= 4 and data[1].strip():
                        device_info = {
                            "name": data[1].strip(),
                            "file_system": data[2].strip(),
                            "free_space": int(data[3]) if data[3].strip() else 0,
                            "size": int(data[4]) if data[4].strip() else 0,
                            "is_physical": self._is_physical_volume_windows(
                                data[1].strip()
                            ),
                        }
                        storage_devices.append(device_info)

        except Exception as e:
            storage_devices.append(
                {"error": _("Failed to get Windows storage info: %s") % str(e)}
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
        """Get network information on Windows using wmic."""
        import subprocess

        network_interfaces = []
        try:
            result = subprocess.run(
                [
                    "wmic",
                    "path",
                    "win32_networkadapter",
                    "get",
                    "Name,AdapterType,MACAddress,NetEnabled",
                    "/format:csv",
                ],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
            if result.returncode == 0:
                lines = result.stdout.strip().split("\n")
                for line in lines[1:]:  # Skip header
                    data = line.split(",")
                    if len(data) >= 4 and data[2].strip():
                        interface_info = {
                            "type": data[1].strip(),
                            "mac_address": data[2].strip(),
                            "name": data[3].strip(),
                            "enabled": (
                                data[4].strip().lower() == "true"
                                if data[4].strip()
                                else False
                            ),
                        }
                        network_interfaces.append(interface_info)

        except Exception as e:
            network_interfaces.append(
                {"error": _("Failed to get Windows network info: %s") % str(e)}
            )

        return network_interfaces

    # BSD hardware collection methods
    def _get_bsd_cpu_info(self) -> Dict[str, Any]:
        """Get CPU information on OpenBSD/FreeBSD using sysctl."""
        import subprocess

        cpu_info = {}
        try:
            # Get CPU model name
            result = subprocess.run(
                ["sysctl", "-n", "hw.model"],
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
                ["sysctl", "-n", "hw.ncpu"],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
            if result.returncode == 0:
                cpu_info["threads"] = int(result.stdout.strip())

            # Try to get physical CPU cores (may not be available on all BSD systems)
            result = subprocess.run(
                ["sysctl", "-n", "hw.ncpuonline"],
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
                    ["sysctl", "-n", freq_key],
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
                import re

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
        import subprocess

        memory_info = {}
        try:
            # Get physical memory
            result = subprocess.run(
                ["sysctl", "-n", "hw.physmem"],
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
        import subprocess

        storage_devices = []
        try:
            # Get mounted filesystems
            result = subprocess.run(
                ["df", "-h"], capture_output=True, text=True, timeout=30, check=False
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

                        device_info = {
                            "name": device_name,
                            "size": parts[1],
                            "used": parts[2],
                            "available": parts[3],
                            "mount_point": mount_point,
                            "type": "unknown",  # Will be updated from mount command
                            "is_physical": self._is_physical_volume_bsd(
                                device_name, mount_point
                            ),
                        }
                        storage_devices.append(device_info)

            # Try to get filesystem types from mount command
            result = subprocess.run(
                ["mount"], capture_output=True, text=True, timeout=30, check=False
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

        except Exception as e:
            storage_devices.append(
                {"error": _("Failed to get BSD storage info: %s") % str(e)}
            )

        return storage_devices

    def _should_skip_bsd_filesystem(self, device_name: str, mount_point: str) -> bool:
        """Determine if a BSD filesystem should be skipped from storage inventory."""
        # Skip special/virtual filesystems
        skip_devices = ["tmpfs", "kernfs", "procfs", "mfs", "fdesc"]
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

    def _get_bsd_network_info(self) -> List[Dict[str, Any]]:
        """Get network information on OpenBSD/FreeBSD using ifconfig."""
        import subprocess

        network_interfaces = []
        try:
            result = subprocess.run(
                ["ifconfig", "-a"],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
            if result.returncode == 0:
                current_interface: Dict[str, Any] = None
                for line in result.stdout.split("\n"):
                    line = line.strip()
                    if not line:
                        continue

                    # New interface (starts at beginning of line)
                    if (
                        not line.startswith("\t")
                        and not line.startswith(" ")
                        and ":" in line
                    ):
                        if current_interface:
                            network_interfaces.append(current_interface)

                        interface_name = line.split(":")[0]
                        if interface_name == "lo0":  # Skip loopback
                            current_interface = None
                            continue

                        current_interface = {
                            "name": interface_name,
                            "flags": "",
                            "type": "ethernet",  # Default type
                            "mac_address": "",
                            "state": "unknown",
                        }

                        # Extract flags from the line
                        if "flags=" in line:
                            flags_start = line.find("flags=") + 6
                            flags_end = line.find(">", flags_start)
                            if flags_end > flags_start:
                                current_interface["flags"] = line[flags_start:flags_end]

                    # Interface details (indented lines)
                    elif current_interface and (
                        line.startswith("\t") or line.startswith(" ")
                    ):
                        if "ether " in line:
                            # MAC address line
                            parts = line.split()
                            if len(parts) >= 2 and current_interface:
                                current_interface["mac_address"] = parts[1]
                        elif "media:" in line and current_interface:
                            # Media type information
                            if "Ethernet" in line:
                                current_interface["type"] = "ethernet"
                            elif "IEEE802.11" in line or "wireless" in line.lower():
                                current_interface["type"] = "wireless"

                # Add the last interface
                if current_interface:
                    network_interfaces.append(current_interface)

        except Exception as e:
            network_interfaces.append(
                {"error": _("Failed to get BSD network info: %s") % str(e)}
            )

        return network_interfaces
