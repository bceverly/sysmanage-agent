"""
Windows hardware collector for SysManage Agent.
Handles Windows-specific hardware information gathering.
"""

import subprocess  # nosec B404
from typing import Any, Dict, List

from src.i18n import _
from .hardware_collector_base import HardwareCollectorBase

WMIC_CSV_FORMAT = "/format:csv"
NONE_VALUE = "(none)"


class HardwareCollectorWindows(HardwareCollectorBase):
    """Collects hardware information on Windows systems."""

    def _parse_wmic_csv_lines(self, stdout: str) -> List[str]:
        """Parse WMIC CSV output into non-empty lines."""
        return [line for line in stdout.strip().split("\n") if line.strip()]

    def _parse_cpu_wmic_data(self, data: List[str]) -> Dict[str, Any]:
        """Parse a WMIC CSV data row into CPU info fields.

        Expected CSV format: Node,Manufacturer,MaxClockSpeed,Name,NumberOfCores,NumberOfLogicalProcessors
        """
        cpu_info = {}
        if len(data) >= 6:
            cpu_info["vendor"] = data[1].strip()
            cpu_info["frequency_mhz"] = int(data[2]) if data[2].strip() else 0
            cpu_info["model"] = data[3].strip()
            cpu_info["cores"] = int(data[4]) if data[4].strip() else 0
            cpu_info["threads"] = int(data[5]) if data[5].strip() else 0
        return cpu_info

    def get_cpu_info(self) -> Dict[str, Any]:
        """Get CPU information on Windows using wmic."""

        cpu_info = {}
        try:
            result = subprocess.run(
                [
                    "wmic",
                    "cpu",
                    "get",
                    "Name,Manufacturer,NumberOfCores,NumberOfLogicalProcessors,MaxClockSpeed",
                    WMIC_CSV_FORMAT,
                ],  # nosec B603, B607
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
            if result.returncode == 0:
                lines = self._parse_wmic_csv_lines(result.stdout)
                if len(lines) > 1:
                    data = lines[1].split(",")
                    cpu_info = self._parse_cpu_wmic_data(data)

        except Exception as error:
            cpu_info["error"] = _("Failed to get Windows CPU info: %s") % str(error)

        return cpu_info

    def get_memory_info(self) -> Dict[str, Any]:
        """Get memory information on Windows using wmic."""

        memory_info = {}
        try:
            result = subprocess.run(
                [
                    "wmic",
                    "computersystem",
                    "get",
                    "TotalPhysicalMemory",
                    WMIC_CSV_FORMAT,
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

        except Exception as error:
            memory_info["error"] = _("Failed to get Windows memory info: %s") % str(
                error
            )

        return memory_info

    def _collect_physical_disk_drives(self) -> List[Dict[str, Any]]:
        """Collect physical disk drive information from WMIC diskdrive."""
        devices = []
        result = subprocess.run(
            [
                "wmic",
                "diskdrive",
                "get",
                "Size,Model,DeviceID,InterfaceType",
                WMIC_CSV_FORMAT,
            ],  # nosec B603, B607
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        if result.returncode != 0:
            return devices

        lines = self._parse_wmic_csv_lines(result.stdout)
        for line in lines[1:]:  # Skip header
            device_info = self._parse_physical_disk_line(line)
            if device_info is not None:
                devices.append(device_info)

        return devices

    def _parse_physical_disk_line(self, line: str) -> Dict[str, Any]:
        """Parse a single WMIC diskdrive CSV line into a device info dict."""
        data = line.split(",")
        if len(data) < 4 or not data[1].strip():
            return None
        return {
            "name": data[1].strip(),
            "model": data[3].strip(),
            "size": int(data[4]) if data[4].strip().isdigit() else 0,
            "interface_type": data[2].strip(),
            "is_physical": True,
            "device_type": "physical",
            "file_system": "N/A",
            "free_space": 0,
        }

    def _collect_logical_disk_drives(self) -> List[Dict[str, Any]]:
        """Collect logical disk drive information from WMIC logicaldisk."""
        devices = []
        result = subprocess.run(
            [
                "wmic",
                "logicaldisk",
                "get",
                "Size,FreeSpace,FileSystem,DeviceID,VolumeName",
                WMIC_CSV_FORMAT,
            ],  # nosec B603, B607
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        if result.returncode != 0:
            return devices

        lines = self._parse_wmic_csv_lines(result.stdout)
        for line in lines[1:]:  # Skip header
            device_info = self._parse_logical_disk_line(line)
            if device_info is not None:
                devices.append(device_info)

        return devices

    def _parse_logical_disk_line(self, line: str) -> Dict[str, Any]:
        """Parse a single WMIC logicaldisk CSV line into a device info dict."""
        data = line.split(",")
        if len(data) < 4 or not data[1].strip():
            return None
        return {
            "name": data[1].strip(),
            "file_system": data[2].strip(),
            "free_space": int(data[3]) if data[3].strip().isdigit() else 0,
            "size": int(data[4]) if data[4].strip().isdigit() else 0,
            "volume_name": data[5].strip() if len(data) > 5 else "",
            "is_physical": False,
            "device_type": "logical",
        }

    def get_storage_info(self) -> List[Dict[str, Any]]:
        """Get storage information on Windows using wmic for both physical and logical drives."""

        storage_devices = []

        # First, get physical disk drives
        try:
            storage_devices.extend(self._collect_physical_disk_drives())
        except Exception as error:
            self.logger.error(
                "Failed to get Windows physical disk info: %s", str(error)
            )

        # Then, get logical drives (partitions/volumes)
        try:
            storage_devices.extend(self._collect_logical_disk_drives())
        except Exception as error:
            storage_devices.append(
                {"error": _("Failed to get Windows logical disk info: %s") % str(error)}
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

    def _detect_new_adapter(self, line: str, original_line: str) -> Dict[str, Any]:
        """Detect and create a new adapter dict from an ipconfig adapter header line.

        Returns a new adapter dict if the line is an adapter header, None otherwise.
        """
        if original_line.startswith("   "):
            return None
        if "adapter " not in line or ":" not in line:
            return None

        adapter_name = line.split(":")[0].strip()
        return {
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
            "connection_status": "Unknown",
        }

    def get_network_info(self) -> List[Dict[str, Any]]:
        """Get network information on Windows using ipconfig /all."""

        network_interfaces = []

        try:
            result = subprocess.run(
                ["ipconfig", "/all"],  # nosec B603, B607
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )

            if result.returncode != 0:
                self.logger.error(
                    "ipconfig /all failed with return code: %d", result.returncode
                )
                return network_interfaces

            current_adapter = None

            for line in result.stdout.split("\n"):
                original_line = line
                line = line.strip()

                if self._should_skip_ipconfig_line(line):
                    continue

                new_adapter = self._detect_new_adapter(line, original_line)
                if new_adapter is not None:
                    if current_adapter:
                        network_interfaces.append(current_adapter)
                    current_adapter = new_adapter
                    continue

                if current_adapter and original_line.startswith("   ") and ":" in line:
                    self._parse_adapter_property(current_adapter, line)

            if current_adapter:
                network_interfaces.append(current_adapter)

        except Exception as error:
            self.logger.error(
                "Failed to get Windows network info via ipconfig: %s", str(error)
            )
            network_interfaces.append(
                {
                    "error": _("Failed to get Windows network configuration: %s")
                    % str(error)
                }
            )

        return network_interfaces

    def _should_skip_ipconfig_line(self, line: str) -> bool:
        """Check if a line from ipconfig output should be skipped."""
        if not line:
            return True

        skip_prefixes = [
            "Windows IP Configuration",
            "Host Name",
            "Primary Dns Suffix",
            "Node Type",
            "IP Routing Enabled",
            "WINS Proxy Enabled",
            "DNS Suffix Search List",
        ]

        return any(line.startswith(prefix) for prefix in skip_prefixes)

    def _parse_adapter_property(
        self, current_adapter: Dict[str, Any], line: str
    ) -> None:
        """Parse a single adapter property line from ipconfig output."""
        key, value = line.split(":", 1)
        # Clean up the key - remove dots and extra spaces
        key = key.strip().replace(".", "").replace(" ", " ").strip()
        value = value.strip()

        if "Media State" in key:
            self._handle_media_state(current_adapter, value)
        elif "Description" in key:
            self._handle_description(current_adapter, value)
        elif "Physical Address" in key:
            current_adapter["mac_address"] = value
        elif "DHCP Enabled" in key:
            current_adapter["dhcp_enabled"] = value.lower() == "yes"
        elif "IPv4 Address" in key or key == "IP Address":
            self._handle_ip_address(current_adapter, value)
        elif "IPv6 Address" in key or "Link-local IPv6 Address" in key:
            self._handle_ip_address(current_adapter, value)
        elif "Subnet Mask" in key:
            if value and value != NONE_VALUE:
                current_adapter["subnet_masks"].append(value)
        elif "Default Gateway" in key:
            if value and value != NONE_VALUE:
                current_adapter["gateways"].append(value)
        elif "DNS Servers" in key and value and value != NONE_VALUE:
            current_adapter["dns_servers"].append(value)

    def _handle_media_state(self, current_adapter: Dict[str, Any], value: str) -> None:
        """Handle media state property."""
        current_adapter["media_state"] = value
        current_adapter["is_active"] = value != "Media disconnected"
        current_adapter["connection_status"] = (
            "Connected" if value != "Media disconnected" else "Disconnected"
        )

    def _handle_description(self, current_adapter: Dict[str, Any], value: str) -> None:
        """Handle description property and determine adapter type."""
        current_adapter["description"] = value
        # Extract adapter type from description and adapter name
        adapter_name = current_adapter.get("name", "")
        combined_text = f"{adapter_name} {value}".lower()

        if "bluetooth" in combined_text:
            current_adapter["type"] = "Bluetooth"
        elif "wi-fi" in combined_text or "wireless" in combined_text:
            current_adapter["type"] = "Wireless"
        elif (
            "ethernet" in combined_text
            or "gigabit" in combined_text
            or "network connection" in combined_text
        ):
            current_adapter["type"] = "Ethernet"
        elif "loopback" in combined_text:
            current_adapter["type"] = "Loopback"
        elif "tunnel" in combined_text or "vpn" in combined_text:
            current_adapter["type"] = "Tunnel"
        else:
            current_adapter["type"] = "Unknown"

    def _handle_ip_address(self, current_adapter: Dict[str, Any], value: str) -> None:
        """Handle IP address (IPv4 or IPv6) property."""
        if value and value != NONE_VALUE and value:
            # Remove any suffixes like "(Preferred)" and handle IPv6 zone IDs
            ip_addr = value.split("(")[0].strip()
            if "%" in ip_addr:  # Remove IPv6 zone ID
                ip_addr = ip_addr.split("%")[0]
            if ip_addr:
                current_adapter["ip_addresses"].append(ip_addr)
                if not current_adapter["is_active"]:
                    current_adapter["is_active"] = True
                    current_adapter["connection_status"] = "Connected"

    def _get_windows_cpu_info(self) -> Dict[str, Any]:
        """Backward compatibility method for tests. Delegates to get_cpu_info()."""
        return self.get_cpu_info()
