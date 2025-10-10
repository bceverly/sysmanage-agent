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

    def get_cpu_info(self) -> Dict[str, Any]:
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
                with open("/proc/cpuinfo", "r", encoding="utf-8") as file_handle:
                    lines = file_handle.readlines()

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
                    ) as file_handle:
                        # This value is in KHz, convert to MHz
                        freq_khz = int(file_handle.read().strip())
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

    def get_network_info(self) -> List[Dict[str, Any]]:
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
                        with open(type_file, "r", encoding="utf-8") as file_handle:
                            interface_info["type"] = file_handle.read().strip()

                    # Get operational state
                    operstate_file = os.path.join(interface_path, "operstate")
                    if os.path.exists(operstate_file):
                        with open(operstate_file, "r", encoding="utf-8") as file_handle:
                            interface_info["state"] = file_handle.read().strip()

                    # Get MAC address
                    address_file = os.path.join(interface_path, "address")
                    if os.path.exists(address_file):
                        with open(address_file, "r", encoding="utf-8") as file_handle:
                            interface_info["mac_address"] = file_handle.read().strip()

                    network_interfaces.append(interface_info)

        except Exception as error:
            network_interfaces.append(
                {"error": _("Failed to get Linux network info: %s") % str(error)}
            )

        return network_interfaces

    def _get_linux_storage_info(self) -> List[Dict[str, Any]]:
        """Backward compatibility method for tests. Delegates to get_storage_info()."""
        return self.get_storage_info()
