"""
macOS hardware collector for SysManage Agent.
Handles macOS-specific hardware information gathering.
"""

import json
import re
import subprocess  # nosec B404
from typing import Any, Dict, List, Optional

from src.i18n import _
from .hardware_collector_base import HardwareCollectorBase


class HardwareCollectorMacOS(HardwareCollectorBase):
    """Collects hardware information on macOS systems."""

    def _parse_macos_cpu_vendor_and_model(
        self, cpu_info: Dict[str, Any], hardware: Dict[str, Any]
    ) -> None:
        """Parse vendor and model from macOS system_profiler hardware data."""
        cpu_info["vendor"] = (
            "Apple"
            if "Apple" in hardware.get("chip_type", "")
            else hardware.get("cpu_type", "").split()[0]
        )
        cpu_info["model"] = hardware.get("chip_type", hardware.get("cpu_type", ""))

    def _parse_macos_cpu_core_counts(
        self, cpu_info: Dict[str, Any], hardware: Dict[str, Any]
    ) -> None:
        """Parse core and thread counts from the number_processors field."""
        num_processors = hardware.get("number_processors", 0)
        if isinstance(num_processors, str) and "proc" in num_processors:
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

    def _parse_macos_cpu_frequency_from_speed(
        self, cpu_info: Dict[str, Any], processor_speed: str
    ) -> None:
        """Parse CPU frequency from the current_processor_speed string."""
        if "GHz" in processor_speed:
            freq = float(processor_speed.replace(" GHz", ""))
            cpu_info["frequency_mhz"] = int(freq * 1000)
        elif "MHz" in processor_speed:
            cpu_info["frequency_mhz"] = int(processor_speed.replace(" MHz", ""))

    def _detect_apple_silicon_frequency(self, cpu_info: Dict[str, Any]) -> None:
        """Detect CPU frequency for Apple Silicon via sysctl fallback methods."""
        freq_result = subprocess.run(
            ["sysctl", "-n", "hw.cpufrequency"],  # nosec B603, B607
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        if freq_result.returncode == 0 and freq_result.stdout.strip():
            try:
                freq_hz = int(freq_result.stdout.strip())
                cpu_info["frequency_mhz"] = freq_hz // 1000000
                return
            except ValueError:
                pass

        self._detect_apple_silicon_frequency_alt(cpu_info)

    def _detect_apple_silicon_frequency_alt(self, cpu_info: Dict[str, Any]) -> None:
        """Try alternative sysctl keys for Apple Silicon CPU frequency."""
        for sysctl_key in ["hw.cpufrequency_max", "hw.tbfrequency"]:
            freq_result = subprocess.run(
                ["sysctl", "-n", sysctl_key],  # nosec B603, B607
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            if freq_result.returncode == 0 and freq_result.stdout.strip():
                try:
                    freq_hz = int(freq_result.stdout.strip())
                    if sysctl_key == "hw.tbfrequency":
                        cpu_info["frequency_mhz"] = 3200
                    else:
                        cpu_info["frequency_mhz"] = freq_hz // 1000000
                    break
                except ValueError:
                    continue

    def get_cpu_info(self) -> Dict[str, Any]:
        """Get CPU information on macOS using system_profiler."""

        cpu_info = {}
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

                self._parse_macos_cpu_vendor_and_model(cpu_info, hardware)
                self._parse_macos_cpu_core_counts(cpu_info, hardware)

                processor_speed = hardware.get("current_processor_speed", "")
                if processor_speed:
                    self._parse_macos_cpu_frequency_from_speed(
                        cpu_info, processor_speed
                    )
                elif "Apple" in hardware.get("chip_type", ""):
                    self._detect_apple_silicon_frequency(cpu_info)

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

    def _parse_df_mount_usage(self) -> Dict[str, Dict[str, int]]:
        """Parse df -k output into a mapping of mount points to usage data."""
        mount_usage: Dict[str, Dict[str, int]] = {}
        df_result = subprocess.run(
            ["df", "-k"],  # Get output in 1K blocks  # nosec B603, B607
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        if df_result.returncode != 0:
            return mount_usage

        lines = df_result.stdout.split("\n")[1:]  # Skip header
        i = 0
        while i < len(lines):
            line = lines[i].strip()
            if not line:
                i += 1
                continue

            parts = line.split()

            # Handle wrapped lines (when device name is too long)
            if len(parts) == 1 and i + 1 < len(lines):
                next_line = lines[i + 1].strip()
                parts = [parts[0]] + next_line.split()
                i += 1

            if len(parts) >= 6:
                usage = self._parse_df_line_usage(parts)
                if usage is not None:
                    mount_usage[parts[-1]] = usage
            i += 1

        return mount_usage

    def _parse_df_line_usage(self, parts: List[str]) -> Optional[Dict[str, int]]:
        """Parse numeric usage columns from a single df output line.

        Returns a dict with capacity_bytes, used_bytes, available_bytes or None.
        """
        numeric_start = 1
        while numeric_start < len(parts) - 4 and not parts[numeric_start].isdigit():
            numeric_start += 1

        if numeric_start >= len(parts) - 4:
            return None

        total_kb = int(parts[numeric_start]) if parts[numeric_start].isdigit() else 0
        used_kb = (
            int(parts[numeric_start + 1]) if parts[numeric_start + 1].isdigit() else 0
        )
        available_kb = (
            int(parts[numeric_start + 2]) if parts[numeric_start + 2].isdigit() else 0
        )

        return {
            "capacity_bytes": total_kb * 1024,
            "used_bytes": used_kb * 1024,
            "available_bytes": available_kb * 1024,
        }

    def _collect_apfs_corrected_usage(
        self,
        device: Dict[str, Any],
        usage_info: Dict[str, int],
        mount_point: str,
        mount_usage: Dict[str, Dict[str, int]],
    ) -> Dict[str, int]:
        """Correct APFS usage data when a volume reports suspiciously low usage.

        APFS containers share space and system volumes often report minimal usage.
        This looks for a sibling volume in the same container with more accurate data.
        """
        if device.get("file_system") != "APFS" or not usage_info:
            return usage_info

        capacity = usage_info.get("capacity_bytes", 0)
        if capacity <= 100 * 1024**3:  # Only check volumes > 100GB
            return usage_info

        used_pct = (usage_info.get("used_bytes", 0) / max(capacity, 1)) * 100
        if used_pct >= 5:  # Not suspiciously low
            return usage_info

        # Look for sibling volumes with same capacity but more realistic usage
        for other_mount, other_usage in mount_usage.items():
            if other_mount == mount_point:
                continue
            if other_usage.get("capacity_bytes") != capacity:
                continue
            other_used_pct = (other_usage.get("used_bytes", 0) / max(capacity, 1)) * 100
            if other_used_pct > used_pct:
                return other_usage

        return usage_info

    def _should_skip_macos_storage_device(
        self, device: Dict[str, Any], mount_point: str
    ) -> bool:
        """Determine if a macOS storage device should be excluded from results."""
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

        if any(mount_point.startswith(pattern) for pattern in excluded_mount_patterns):
            return True

        if "snapshot" in device.get("_name", "").lower():
            return True

        return False

    def get_storage_info(self) -> List[Dict[str, Any]]:
        """Get storage information on macOS using system_profiler and df."""

        storage_devices = []
        try:
            result = subprocess.run(
                ["system_profiler", "-json", "SPStorageDataType"],  # nosec B603, B607
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )

            mount_usage = self._parse_df_mount_usage()

            if result.returncode == 0:
                data = json.loads(result.stdout)
                storage_data = data.get("SPStorageDataType", [])

                for device in storage_data:
                    mount_point = device.get("mount_point", "")
                    usage_info = mount_usage.get(mount_point, {})

                    usage_info = self._collect_apfs_corrected_usage(
                        device, usage_info, mount_point, mount_usage
                    )

                    if self._should_skip_macos_storage_device(device, mount_point):
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

    def _detect_disk_images(self, lines: List[str]) -> set:
        """Identify which base disks are disk images from diskutil list output."""
        disk_images = set()
        for line in lines:
            disk_image_match = re.match(r"/dev/(disk\d+) \(disk image\):", line)
            if disk_image_match:
                disk_images.add(disk_image_match.group(1))
        return disk_images

    def _parse_apfs_container_size(self, parts: List[str]) -> Optional[int]:
        """Parse the size in bytes from an APFS Container Scheme line's parts.

        Looks for a pattern like '+994.7 GB' within the split line parts.
        Returns the size in bytes, or None if not parseable.
        """
        for i, part in enumerate(parts):
            if part.startswith("+") and i + 1 < len(parts):
                size_val_str = part[1:]
                unit = parts[i + 1]
                try:
                    size_val = float(size_val_str)
                    if unit == "GB":
                        return int(size_val * 1024**3)
                    if unit == "TB":
                        return int(size_val * 1024**4)
                    if unit == "MB":
                        return int(size_val * 1024**2)
                except ValueError:
                    pass
        return None

    def _process_physical_store_line(
        self, line: str, containers: List[Dict[str, Any]], disk_images: set
    ) -> None:
        """Process a 'Physical Store' line to update the most recent container's is_physical status."""
        parts = line.strip().split()
        if len(parts) < 3 or parts[0] != "Physical" or parts[1] != "Store":
            return

        store_device = parts[2]
        base_disk = re.match(r"(disk\d+)", store_device)
        if not base_disk:
            return

        base_disk_num = base_disk.group(1)
        for container in reversed(containers):
            if container.get("_current_disk"):
                container["is_physical"] = base_disk_num not in disk_images
                del container["_current_disk"]
                break

    def _get_macos_apfs_containers(self) -> List[Dict[str, Any]]:
        """Get physical APFS containers using diskutil list."""

        containers = []
        try:
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
                disk_images = self._detect_disk_images(lines)

                for line in lines:
                    disk_match = re.match(r"/dev/(disk\d+) \(synthesized\):", line)
                    if disk_match:
                        current_disk = disk_match.group(1)
                        continue

                    if current_disk and "APFS Container Scheme" in line:
                        parts = line.split()
                        if len(parts) >= 6:
                            size_bytes = self._parse_apfs_container_size(parts)
                            container_info = {
                                "name": f"APFS Container {current_disk}",
                                "device_path": current_disk,
                                "mount_point": "",
                                "file_system": "APFS",
                                "device_type": "APFS Container",
                                "capacity_bytes": size_bytes,
                                "used_bytes": None,
                                "available_bytes": None,
                                "is_physical": True,
                                "_current_disk": current_disk,
                            }
                            containers.append(container_info)
                        current_disk = None

                    if "Physical Store" in line and containers:
                        self._process_physical_store_line(line, containers, disk_images)

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

    def _parse_ifconfig_interface_details(
        self, ifconfig_output: str
    ) -> Dict[str, Dict[str, Any]]:
        """Parse ifconfig output into a dict mapping interface names to their details."""
        interface_details: Dict[str, Dict[str, Any]] = {}
        current_interface = None
        for line in ifconfig_output.split("\n"):
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
                self._parse_ifconfig_detail_line(
                    line, interface_details[current_interface]
                )
        return interface_details

    def _parse_ifconfig_detail_line(self, line: str, details: Dict[str, Any]) -> None:
        """Parse a single indented ifconfig detail line into interface details."""
        if "ether" in line:
            mac_match = re.search(r"ether ([a-fA-F0-9:]{17})", line)
            if mac_match:
                details["mac_address"] = mac_match.group(1)
        elif "inet " in line and "inet6" not in line:
            self._parse_ifconfig_ipv4_line(line, details)
        elif "inet6" in line and "fe80:" not in line and "scopeid" not in line:
            ipv6_match = re.search(r"inet6 ([a-fA-F0-9:]+)", line)
            if ipv6_match and not details["ipv6_address"]:
                details["ipv6_address"] = ipv6_match.group(1)

    def _parse_ifconfig_ipv4_line(self, line: str, details: Dict[str, Any]) -> None:
        """Parse IPv4 address and subnet mask from an ifconfig inet line."""
        ipv4_match = re.search(r"inet (\d+\.\d+\.\d+\.\d+)", line)
        mask_match = re.search(r"netmask (0x[a-fA-F0-9]+)", line)
        if ipv4_match:
            details["ipv4_address"] = ipv4_match.group(1)
        if mask_match:
            hex_mask = mask_match.group(1)
            mask_int = int(hex_mask, 16)
            mask_bytes = [(mask_int >> (8 * (3 - i))) & 0xFF for i in range(4)]
            details["subnet_mask"] = ".".join(map(str, mask_bytes))

    def _collect_interface_details_for_profiler_entry(
        self,
        interface: Dict[str, Any],
        interface_details: Dict[str, Dict[str, Any]],
    ) -> Dict[str, Any]:
        """Match a system_profiler network entry with ifconfig details."""
        name = interface.get("_name", "")
        details: Dict[str, Any] = {}
        interface_id = interface.get("interface", "")

        if interface_id and interface_id in interface_details:
            details = interface_details[interface_id]
        else:
            for if_name, if_details in interface_details.items():
                if if_name.lower() in name.lower() or name.lower() in if_name.lower():
                    details = if_details
                    break

        return {
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
            "speed_mbps": None,
        }

    def get_network_info(self) -> List[Dict[str, Any]]:
        """Get network information on macOS using system_profiler and ifconfig."""

        network_interfaces = []
        try:
            result = subprocess.run(
                ["system_profiler", "-json", "SPNetworkDataType"],  # nosec B603, B607
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )

            ifconfig_result = subprocess.run(
                ["ifconfig"],  # nosec B603, B607
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )

            interface_details = {}
            if ifconfig_result.returncode == 0:
                interface_details = self._parse_ifconfig_interface_details(
                    ifconfig_result.stdout
                )

            if result.returncode == 0:
                data = json.loads(result.stdout)
                network_data = data.get("SPNetworkDataType", [])

                for interface in network_data:
                    interface_info = self._collect_interface_details_for_profiler_entry(
                        interface, interface_details
                    )
                    network_interfaces.append(interface_info)

        except Exception as error:
            network_interfaces.append(
                {"error": _("Failed to get macOS network info: %s") % str(error)}
            )

        return network_interfaces

    def _get_macos_cpu_info(self) -> Dict[str, Any]:
        """Backward compatibility method for tests. Delegates to get_cpu_info()."""
        return self.get_cpu_info()
