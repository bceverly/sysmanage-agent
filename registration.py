"""
Client registration module for SysManage Agent.
Handles initial registration and periodic re-registration with the server.
"""

import socket
import platform
import logging
import asyncio
import ssl
from typing import Any, Dict, List, Optional, Tuple

try:
    import aiohttp

    AIOHTTP_AVAILABLE = True
except ImportError:
    AIOHTTP_AVAILABLE = False
    print("⚠️  WARNING: aiohttp not available, registration will be skipped")


class ClientRegistration:
    """Handles client registration with the SysManage server."""

    def __init__(self, config_manager):
        self.config = config_manager
        self.logger = logging.getLogger(__name__)
        self.registered = False
        self.registration_data: Optional[Dict[str, Any]] = None

    def get_hostname(self) -> str:
        """Get the hostname, with optional override from config."""
        override = self.config.get_hostname_override()
        if override:
            return override
        return socket.getfqdn()

    def get_ip_addresses(self) -> Tuple[Optional[str], Optional[str]]:
        """Get both IPv4 and IPv6 addresses of the machine."""
        ipv4 = None
        ipv6 = None

        try:
            # Get IPv4 address by connecting to a remote host
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                ipv4 = s.getsockname()[0]
        except Exception as e:
            self.logger.debug("Could not determine IPv4 address: %s", e)

        try:
            # Get IPv6 address by connecting to a remote host
            with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as s:
                s.connect(("2001:4860:4860::8888", 80))
                ipv6 = s.getsockname()[0]
        except Exception as e:
            self.logger.debug("Could not determine IPv6 address: %s", e)

        return ipv4, ipv6

    def get_basic_registration_info(self) -> Dict[str, Any]:
        """Get minimal system information for initial registration."""
        hostname = self.get_hostname()
        ipv4, ipv6 = self.get_ip_addresses()

        return {
            "hostname": hostname,
            "fqdn": hostname,  # For compatibility with server's Host model
            "ipv4": ipv4,
            "ipv6": ipv6,
            "active": True,  # Mark as active when registering
        }

    def get_os_version_info(self) -> Dict[str, Any]:
        """Get comprehensive OS version information as separate data."""
        # Get CPU architecture (x86_64, arm64, aarch64, riscv64, etc.)
        machine_arch = platform.machine()

        # Get detailed OS information
        os_info = {}
        try:
            # Try to get Linux distribution info if available
            if hasattr(platform, "freedesktop_os_release"):
                os_release = platform.freedesktop_os_release()
                os_info["distribution"] = os_release.get("NAME", "")
                os_info["distribution_version"] = os_release.get("VERSION_ID", "")
                os_info["distribution_codename"] = os_release.get(
                    "VERSION_CODENAME", ""
                )
        except (AttributeError, OSError):
            pass

        # For macOS, get additional version info
        if platform.system() == "Darwin":
            mac_ver = platform.mac_ver()
            os_info["mac_version"] = mac_ver[0] if mac_ver[0] else ""

        # For Windows, get additional version info
        if platform.system() == "Windows":
            win_ver = platform.win32_ver()
            os_info["windows_version"] = win_ver[0] if win_ver[0] else ""
            os_info["windows_service_pack"] = win_ver[1] if win_ver[1] else ""

        return {
            "platform": platform.system(),
            "platform_release": platform.release(),
            "platform_version": platform.version(),
            "architecture": platform.architecture()[0],
            "processor": platform.processor(),
            "machine_architecture": machine_arch,  # CPU architecture
            "python_version": platform.python_version(),
            "os_info": os_info,
        }

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
                        {"error": f"Unsupported platform: {system}"}
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
                # JSON fields for complex data
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
            self.logger.error("Failed to collect hardware info: %s", e)
            hardware_data = {
                "hardware_details": json.dumps(
                    {"error": f"Failed to collect hardware info: {str(e)}"}
                ),
                "storage_details": json.dumps([]),
                "network_details": json.dumps([]),
            }

        return hardware_data

    def _get_timestamp(self) -> str:
        """Get current timestamp in ISO format."""
        from datetime import datetime, timezone

        return datetime.now(timezone.utc).isoformat()

    def get_system_info(self) -> Dict[str, Any]:
        """Get comprehensive system information (legacy method for compatibility)."""
        basic_info = self.get_basic_registration_info()
        os_info = self.get_os_version_info()

        # Merge for backward compatibility
        return {**basic_info, **os_info}

    async def register_with_server(self) -> bool:
        """
        Register the client with the SysManage server.

        Returns:
            True if registration successful, False otherwise
        """
        if not AIOHTTP_AVAILABLE:
            self.logger.warning("aiohttp not available, skipping registration")
            self.registered = True  # Pretend we're registered for now
            return True

        server_url = self.config.get_server_rest_url()
        registration_url = f"{server_url}/host/register"

        # Use minimal registration data
        basic_info = self.get_basic_registration_info()

        self.logger.info("Attempting to register with server at %s", registration_url)
        self.logger.info("=== Minimal Registration Data Being Sent ===")
        for key, value in basic_info.items():
            self.logger.info("  %s: %s", key, value)
        self.logger.info("=== End Registration Data ===")
        self.logger.debug("Registration data: %s", basic_info)

        try:
            # Create SSL context that doesn't verify certificates (for development)
            ssl_context = ssl.create_default_context()
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE

            connector = aiohttp.TCPConnector(ssl=ssl_context)
            async with aiohttp.ClientSession(connector=connector) as session:
                async with session.post(
                    registration_url,
                    json=basic_info,
                    headers={"Content-Type": "application/json"},
                ) as response:

                    if response.status in [200, 201]:
                        response_data = await response.json()
                        self.registration_data = response_data
                        self.registered = True
                        self.logger.info(
                            "Successfully registered with server. Host ID: %s",
                            response_data.get("id"),
                        )
                        return True
                    if response.status == 409:
                        # Host already exists - this is OK
                        self.logger.info("Host already registered with server")
                        self.registered = True
                        return True
                    error_text = await response.text()
                    self.logger.error(
                        "Registration failed with status %s: %s",
                        response.status,
                        error_text,
                    )
                    return False

        except (
            Exception
        ) as e:  # Catch all since aiohttp.ClientError might not be available
            self.logger.error("Error during registration: %s", e)
            return False

    async def register_with_retry(self) -> bool:
        """
        Register with server using configured retry settings.

        Returns:
            True if registration eventually succeeds, False if max retries exceeded
        """
        retry_interval = self.config.get_registration_retry_interval()
        max_retries = self.config.get_max_registration_retries()

        attempt = 0
        while max_retries == -1 or attempt < max_retries:
            attempt += 1

            self.logger.info(
                "Registration attempt %s%s",
                attempt,
                # pylint: disable-next=consider-using-f-string
                (" of %s" % max_retries if max_retries != -1 else ""),
            )

            if await self.register_with_server():
                return True

            if max_retries != -1 and attempt >= max_retries:
                self.logger.error("Failed to register after %s attempts", max_retries)
                return False

            self.logger.warning(
                "Registration failed, retrying in %s seconds...", retry_interval
            )
            await asyncio.sleep(retry_interval)

        return False

    def is_registered(self) -> bool:
        """Check if client is currently registered."""
        return self.registered

    def get_registration_data(self) -> Optional[Dict[str, Any]]:
        """Get the registration response data."""
        return self.registration_data

    def get_host_id(self) -> Optional[int]:
        """Get the host ID from registration data."""
        if self.registration_data:
            return self.registration_data.get("id")
        return None

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
            cpu_info["error"] = f"Failed to get macOS CPU info: {str(e)}"

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
            memory_info["error"] = f"Failed to get macOS memory info: {str(e)}"

        return memory_info

    def _get_macos_storage_info(self) -> List[Dict[str, Any]]:
        """Get storage information on macOS using system_profiler."""
        import subprocess
        import json

        storage_devices = []
        try:
            result = subprocess.run(
                ["system_profiler", "-json", "SPStorageDataType"],
                capture_output=True,
                text=True,
                timeout=30,
            )
            if result.returncode == 0:
                data = json.loads(result.stdout)
                storage_data = data.get("SPStorageDataType", [])

                for device in storage_data:
                    device_info = {
                        "name": device.get("_name", ""),
                        "size": device.get("size", ""),
                        "type": device.get("physical_drive", {}).get("device_name", ""),
                        "mount_point": device.get("mount_point", ""),
                        "file_system": device.get("file_system", ""),
                    }
                    storage_devices.append(device_info)

        except Exception as e:
            storage_devices.append(
                {"error": f"Failed to get macOS storage info: {str(e)}"}
            )

        return storage_devices

    def _get_macos_network_info(self) -> List[Dict[str, Any]]:
        """Get network information on macOS using system_profiler."""
        import subprocess
        import json

        network_interfaces = []
        try:
            result = subprocess.run(
                ["system_profiler", "-json", "SPNetworkDataType"],
                capture_output=True,
                text=True,
                timeout=30,
            )
            if result.returncode == 0:
                data = json.loads(result.stdout)
                network_data = data.get("SPNetworkDataType", [])

                for interface in network_data:
                    interface_info = {
                        "name": interface.get("_name", ""),
                        "type": interface.get("type", ""),
                        "hardware": interface.get("hardware", ""),
                        "has_ip_assigned": interface.get("has_ip_assigned", False),
                    }
                    network_interfaces.append(interface_info)

        except Exception as e:
            network_interfaces.append(
                {"error": f"Failed to get macOS network info: {str(e)}"}
            )

        return network_interfaces

    def _get_linux_cpu_info(self) -> Dict[str, Any]:
        """Get CPU information on Linux using /proc/cpuinfo and lscpu."""
        cpu_info = {}
        try:
            # First try lscpu for structured info
            import subprocess

            result = subprocess.run(
                ["lscpu"], capture_output=True, text=True, timeout=30
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
                with open("/proc/cpuinfo", "r") as f:
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
            cpu_info["error"] = f"Failed to get Linux CPU info: {str(e)}"

        return cpu_info

    def _get_linux_memory_info(self) -> Dict[str, Any]:
        """Get memory information on Linux using /proc/meminfo."""
        memory_info = {}
        try:
            with open("/proc/meminfo", "r") as f:
                for line in f:
                    if line.startswith("MemTotal:"):
                        # MemTotal is in kB
                        mem_kb = int(line.split()[1])
                        memory_info["total_mb"] = mem_kb // 1024
                        break

        except Exception as e:
            memory_info["error"] = f"Failed to get Linux memory info: {str(e)}"

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
                        }
                        storage_devices.append(child_info)

        except Exception as e:
            storage_devices.append(
                {"error": f"Failed to get Linux storage info: {str(e)}"}
            )

        return storage_devices

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
                        with open(type_file, "r") as f:
                            interface_info["type"] = f.read().strip()

                    # Get operational state
                    operstate_file = os.path.join(interface_path, "operstate")
                    if os.path.exists(operstate_file):
                        with open(operstate_file, "r") as f:
                            interface_info["state"] = f.read().strip()

                    # Get MAC address
                    address_file = os.path.join(interface_path, "address")
                    if os.path.exists(address_file):
                        with open(address_file, "r") as f:
                            interface_info["mac_address"] = f.read().strip()

                    network_interfaces.append(interface_info)

        except Exception as e:
            network_interfaces.append(
                {"error": f"Failed to get Linux network info: {str(e)}"}
            )

        return network_interfaces

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
            cpu_info["error"] = f"Failed to get Windows CPU info: {str(e)}"

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
            memory_info["error"] = f"Failed to get Windows memory info: {str(e)}"

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
                        }
                        storage_devices.append(device_info)

        except Exception as e:
            storage_devices.append(
                {"error": f"Failed to get Windows storage info: {str(e)}"}
            )

        return storage_devices

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
                {"error": f"Failed to get Windows network info: {str(e)}"}
            )

        return network_interfaces

    def _get_bsd_cpu_info(self) -> Dict[str, Any]:
        """Get CPU information on OpenBSD/FreeBSD using sysctl."""
        import subprocess

        cpu_info = {}
        try:
            # Get CPU model name
            result = subprocess.run(
                ["sysctl", "-n", "hw.model"], capture_output=True, text=True, timeout=30
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
                ["sysctl", "-n", "hw.ncpu"], capture_output=True, text=True, timeout=30
            )
            if result.returncode == 0:
                cpu_info["threads"] = int(result.stdout.strip())

            # Try to get physical CPU cores (may not be available on all BSD systems)
            result = subprocess.run(
                ["sysctl", "-n", "hw.ncpuonline"],
                capture_output=True,
                text=True,
                timeout=30,
            )
            if result.returncode == 0:
                cpu_info["cores"] = int(result.stdout.strip())
            else:
                # Fallback to logical CPUs if physical cores not available
                cpu_info["cores"] = cpu_info.get("threads", 0)

            # Try to get CPU frequency (may not be available)
            for freq_key in ["hw.cpuspeed", "hw.clockrate"]:
                result = subprocess.run(
                    ["sysctl", "-n", freq_key],
                    capture_output=True,
                    text=True,
                    timeout=30,
                )
                if result.returncode == 0:
                    cpu_info["frequency_mhz"] = int(result.stdout.strip())
                    break

        except Exception as e:
            cpu_info["error"] = f"Failed to get BSD CPU info: {str(e)}"

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
            )
            if result.returncode == 0:
                # hw.physmem returns bytes
                memory_bytes = int(result.stdout.strip())
                memory_info["total_mb"] = memory_bytes // (1024 * 1024)

        except Exception as e:
            memory_info["error"] = f"Failed to get BSD memory info: {str(e)}"

        return memory_info

    def _get_bsd_storage_info(self) -> List[Dict[str, Any]]:
        """Get storage information on OpenBSD/FreeBSD using df and mount."""
        import subprocess

        storage_devices = []
        try:
            # Get mounted filesystems
            result = subprocess.run(
                ["df", "-h"], capture_output=True, text=True, timeout=30
            )
            if result.returncode == 0:
                lines = result.stdout.strip().split("\n")[1:]  # Skip header
                for line in lines:
                    parts = line.split()
                    if len(parts) >= 6 and not parts[0].startswith("/dev/"):
                        continue  # Skip non-device filesystems

                    if len(parts) >= 6:
                        device_info = {
                            "name": parts[0],
                            "size": parts[1],
                            "used": parts[2],
                            "available": parts[3],
                            "mount_point": parts[5] if len(parts) > 5 else "",
                            "type": "unknown",  # df doesn't show filesystem type
                        }
                        storage_devices.append(device_info)

            # Try to get filesystem types from mount command
            result = subprocess.run(
                ["mount"], capture_output=True, text=True, timeout=30
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
                {"error": f"Failed to get BSD storage info: {str(e)}"}
            )

        return storage_devices

    def _get_bsd_network_info(self) -> List[Dict[str, Any]]:
        """Get network information on OpenBSD/FreeBSD using ifconfig."""
        import subprocess

        network_interfaces = []
        try:
            result = subprocess.run(
                ["ifconfig", "-a"], capture_output=True, text=True, timeout=30
            )
            if result.returncode == 0:
                current_interface = None
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
                            if len(parts) >= 2:
                                current_interface["mac_address"] = parts[1]
                        elif "media:" in line:
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
                {"error": f"Failed to get BSD network info: {str(e)}"}
            )

        return network_interfaces
