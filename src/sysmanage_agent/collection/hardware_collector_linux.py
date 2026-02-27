"""
Linux hardware collector for SysManage Agent.
Handles Linux-specific hardware information gathering.
"""

import json
import os
import re
import subprocess  # nosec B404
from typing import Any, Dict, List

from src.i18n import _
from .hardware_collector_base import HardwareCollectorBase


class HardwareCollectorLinux(HardwareCollectorBase):
    """Collects hardware information on Linux systems."""

    def _parse_lscpu_output(self, cpu_info: Dict[str, Any]) -> bool:
        """Parse lscpu output to populate cpu_info.

        Returns True if lscpu was available and produced output, False otherwise.
        """
        try:
            result = subprocess.run(
                ["lscpu"],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,  # nosec B603, B607
            )
            lscpu_success = result.returncode == 0
        except FileNotFoundError:
            return False

        if not lscpu_success:
            return False

        for line in result.stdout.split("\n"):
            if ":" in line:
                key, value = line.split(":", 1)
                key = key.strip()
                value = value.strip()
                self._process_lscpu_field(cpu_info, key, value)

        return bool(cpu_info)

    def _process_lscpu_field(
        self, cpu_info: Dict[str, Any], key: str, value: str
    ) -> None:
        """Process a single key-value field from lscpu output."""
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
            if "frequency_mhz" not in cpu_info or key == "CPU max MHz":
                try:
                    cpu_info["frequency_mhz"] = int(float(value))
                except ValueError:
                    pass

    def _process_cpuinfo_vendor(self, cpu_info: Dict[str, Any], value: str) -> None:
        """Process vendor_id field from /proc/cpuinfo."""
        if "vendor" not in cpu_info:
            cpu_info["vendor"] = value

    def _process_cpuinfo_model(self, cpu_info: Dict[str, Any], value: str) -> None:
        """Process model name field from /proc/cpuinfo."""
        if "model" not in cpu_info:
            cpu_info["model"] = value

    def _process_cpuinfo_frequency(self, cpu_info: Dict[str, Any], value: str) -> None:
        """Process cpu MHz field from /proc/cpuinfo."""
        try:
            freq = int(float(value))
            if "frequency_mhz" not in cpu_info or freq > 0:
                cpu_info["frequency_mhz"] = freq
        except ValueError:
            pass

    def _process_cpuinfo_field(
        self, cpu_info: Dict[str, Any], key: str, value: str, processor_count: int
    ) -> int:
        """Process a single field from /proc/cpuinfo.

        Returns the updated processor_count.
        """
        if key == "vendor_id":
            self._process_cpuinfo_vendor(cpu_info, value)
        elif key == "model name":
            self._process_cpuinfo_model(cpu_info, value)
        elif key == "cpu MHz":
            self._process_cpuinfo_frequency(cpu_info, value)
        elif key == "processor":
            processor_count = max(processor_count, int(value) + 1)

        return processor_count

    def _parse_proc_cpuinfo(self, cpu_info: Dict[str, Any]) -> None:
        """Parse /proc/cpuinfo as a fallback when lscpu is unavailable."""
        with open("/proc/cpuinfo", "r", encoding="utf-8") as file_handle:
            lines = file_handle.readlines()

        processor_count = 0
        for line in lines:
            if ":" not in line:
                continue

            key, value = line.split(":", 1)
            processor_count = self._process_cpuinfo_field(
                cpu_info, key.strip(), value.strip(), processor_count
            )

        if processor_count > 0:
            cpu_info["threads"] = processor_count

    def _detect_cpu_frequency_fallback(self, cpu_info: Dict[str, Any]) -> None:
        """Detect CPU frequency from cpufreq sysfs or model name as a last resort."""
        if cpu_info.get("frequency_mhz", 0) != 0:
            return

        try:
            with open(
                "/sys/devices/system/cpu/cpu0/cpufreq/cpuinfo_max_freq",
                "r",
                encoding="utf-8",
            ) as file_handle:
                freq_khz = int(file_handle.read().strip())
                cpu_info["frequency_mhz"] = freq_khz // 1000
        except (FileNotFoundError, ValueError, IOError):
            self._parse_cpu_frequency_from_model(cpu_info)

    def _parse_cpu_frequency_from_model(self, cpu_info: Dict[str, Any]) -> None:
        """Extract CPU frequency from the model name string."""
        if "model" not in cpu_info:
            return

        model = cpu_info["model"]
        ghz_match = re.search(r"@\s*(\d+\.?\d*)\s*GHz", model, re.IGNORECASE)  # NOSONAR
        if ghz_match:
            freq_ghz = float(ghz_match.group(1))
            cpu_info["frequency_mhz"] = int(freq_ghz * 1000)
        else:
            mhz_match = re.search(r"(\d+)\s*MHz", model, re.IGNORECASE)  # NOSONAR
            if mhz_match:
                cpu_info["frequency_mhz"] = int(mhz_match.group(1))

    def get_cpu_info(self) -> Dict[str, Any]:
        """Get CPU information on Linux using /proc/cpuinfo and lscpu."""
        cpu_info = {}
        try:
            if not self._parse_lscpu_output(cpu_info):
                self._parse_proc_cpuinfo(cpu_info)

            self._detect_cpu_frequency_fallback(cpu_info)

        except Exception as error:
            cpu_info["error"] = _("Failed to get Linux CPU info: %s") % str(error)

        return cpu_info

    def get_memory_info(self) -> Dict[str, Any]:
        """Get memory information on Linux using /proc/meminfo."""
        memory_info = {}
        try:
            with open("/proc/meminfo", "r", encoding="utf-8") as file_handle:
                for line in file_handle:
                    if line.startswith("MemTotal:"):
                        # MemTotal is in kB
                        mem_kb = int(line.split()[1])
                        memory_info["total_mb"] = mem_kb // 1024
                        break

        except Exception as error:
            memory_info["error"] = _("Failed to get Linux memory info: %s") % str(error)

        return memory_info

    def get_storage_info(self) -> List[Dict[str, Any]]:
        """Get storage information on Linux using lsblk and df."""

        storage_devices = []
        try:
            # Use lsblk to get block devices (may not exist on Alpine/BusyBox)
            try:
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
                lsblk_success = result.returncode == 0
            except FileNotFoundError:
                # lsblk not available (e.g., Alpine Linux with BusyBox)
                lsblk_success = False
                result = None

            if lsblk_success and result:
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

        except Exception as error:
            storage_devices.append(
                {"error": _("Failed to get Linux storage info: %s") % str(error)}
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

    def _collect_interface_sysfs_attr(self, interface_path: str, attr_name: str) -> str:
        """Read a single sysfs attribute file for a network interface.

        Returns the attribute value as a stripped string, or empty string if unavailable.
        """
        attr_file = os.path.join(interface_path, attr_name)
        if os.path.exists(attr_file):
            with open(attr_file, "r", encoding="utf-8") as file_handle:
                return file_handle.read().strip()
        return ""

    def _collect_single_interface_info(self, interface: str) -> Dict[str, Any]:
        """Collect type, operational state, and MAC address for one network interface."""
        interface_path = os.path.join("/sys/class/net", interface)
        interface_info: Dict[str, Any] = {"name": interface}

        iface_type = self._collect_interface_sysfs_attr(interface_path, "type")
        if iface_type:
            interface_info["type"] = iface_type

        state = self._collect_interface_sysfs_attr(interface_path, "operstate")
        if state:
            interface_info["state"] = state

        mac = self._collect_interface_sysfs_attr(interface_path, "address")
        if mac:
            interface_info["mac_address"] = mac

        return interface_info

    @staticmethod
    def _prefixlen_to_netmask(prefixlen: int) -> str:
        """Convert a prefix length (e.g. 24) to a dotted-decimal netmask."""
        bits = (0xFFFFFFFF << (32 - prefixlen)) & 0xFFFFFFFF
        return ".".join(str((bits >> (8 * i)) & 0xFF) for i in range(3, -1, -1))

    def _parse_ip_json_interface(self, iface: Dict[str, Any]) -> Dict[str, Any]:
        """Parse a single interface entry from 'ip -j addr show' JSON output."""
        name = iface.get("ifname", "")
        operstate = iface.get("operstate", "").upper()
        is_active = operstate in ("UP", "UNKNOWN")

        info: Dict[str, Any] = {
            "name": name,
            "mac_address": iface.get("address"),
            "is_active": is_active,
            "ipv4_address": None,
            "ipv6_address": None,
            "subnet_mask": None,
            "mtu": iface.get("mtu"),
            "speed_mbps": None,
        }

        # Read speed from sysfs (only works for physical interfaces)
        speed_path = f"/sys/class/net/{name}/speed"
        if os.path.exists(speed_path):
            try:
                with open(speed_path, "r", encoding="utf-8") as speed_file:
                    speed_val = int(speed_file.read().strip())
                    if speed_val > 0:
                        info["speed_mbps"] = speed_val
            except (ValueError, OSError):
                pass

        # Extract IP addresses from addr_info
        self._extract_addresses(iface.get("addr_info", []), info)

        return info

    def _extract_addresses(
        self, addr_info: List[Dict[str, Any]], info: Dict[str, Any]
    ) -> None:
        """Extract IPv4/IPv6 addresses from addr_info into the info dict."""
        for addr in addr_info:
            family = addr.get("family")
            local = addr.get("local", "")
            if family == "inet" and not info["ipv4_address"]:
                info["ipv4_address"] = local
                prefixlen = addr.get("prefixlen")
                if prefixlen is not None:
                    info["subnet_mask"] = self._prefixlen_to_netmask(prefixlen)
            elif (
                family == "inet6"
                and not info["ipv6_address"]
                and not local.startswith("fe80:")
            ):
                info["ipv6_address"] = local

        if not info["ipv6_address"]:
            for addr in addr_info:
                if addr.get("family") == "inet6":
                    info["ipv6_address"] = addr.get("local", "")
                    break

    def get_network_info(self) -> List[Dict[str, Any]]:
        """Get network information on Linux using 'ip -j addr show'."""
        try:
            result = subprocess.run(
                ["ip", "-j", "addr", "show"],  # nosec B603, B607
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
            if result.returncode == 0 and result.stdout.strip():
                interfaces = json.loads(result.stdout)
                return [
                    self._parse_ip_json_interface(iface)
                    for iface in interfaces
                    if iface.get("ifname") != "lo"
                ]
        except (json.JSONDecodeError, OSError) as error:
            self.logger.debug(
                _("ip -j addr show failed, falling back to sysfs: %s"), error
            )

        # Fallback to sysfs-only collection
        network_interfaces = []
        try:
            net_dir = "/sys/class/net"
            if os.path.exists(net_dir):
                for interface in os.listdir(net_dir):
                    if interface == "lo":
                        continue
                    interface_info = self._collect_single_interface_info(interface)
                    network_interfaces.append(interface_info)
        except Exception as error:
            network_interfaces.append(
                {"error": _("Failed to get Linux network info: %s") % str(error)}
            )

        return network_interfaces

    def _get_linux_storage_info(self) -> List[Dict[str, Any]]:
        """Backward compatibility method for tests. Delegates to get_storage_info()."""
        return self.get_storage_info()
