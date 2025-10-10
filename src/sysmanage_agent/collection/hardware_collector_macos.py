"""
macOS hardware collector for SysManage Agent.
Handles macOS-specific hardware information gathering.
"""

import json
import re
import subprocess  # nosec B404
from typing import Any, Dict, List

from src.i18n import _
from .hardware_collector_base import HardwareCollectorBase


class HardwareCollectorMacOS(HardwareCollectorBase):
    """Collects hardware information on macOS systems."""

    def get_cpu_info(self) -> Dict[str, Any]:
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

        except Exception as error:
            cpu_info["error"] = _("Failed to get macOS CPU info: %s") % str(error)

        return cpu_info

    def get_memory_info(self) -> Dict[str, Any]:
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

        except Exception as error:
            memory_info["error"] = _("Failed to get macOS memory info: %s") % str(error)

        return memory_info

    def get_storage_info(self) -> List[Dict[str, Any]]:
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

        except Exception as error:
            storage_devices.append(
                {"error": _("Failed to get macOS storage info: %s") % str(error)}
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

        except Exception as error:
            containers.append(
                {"error": _("Failed to get APFS container info: %s") % str(error)}
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

    def get_network_info(self) -> List[Dict[str, Any]]:
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

        except Exception as error:
            network_interfaces.append(
                {"error": _("Failed to get macOS network info: %s") % str(error)}
            )

        return network_interfaces

    def _get_macos_cpu_info(self) -> Dict[str, Any]:
        """Backward compatibility method for tests. Delegates to get_cpu_info()."""
        return self.get_cpu_info()
