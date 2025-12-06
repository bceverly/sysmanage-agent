"""
Child host listing methods for various virtualization platforms.
"""

import json
import os
import platform
import re
import shutil
import subprocess  # nosec B404 # Required for system command execution
from typing import Any, Dict, List, Optional

# Windows registry access for WSL GUID retrieval
try:
    import winreg
except ImportError:
    winreg = None  # type: ignore[misc, assignment]


class ChildHostListing:
    """Methods to list child hosts on various platforms."""

    def __init__(self, logger):
        """Initialize with logger."""
        self.logger = logger

    def list_wsl_instances(self) -> List[Dict[str, Any]]:
        """
        List all WSL instances on Windows.

        Returns:
            List of WSL instance information dicts
        """
        instances = []

        try:
            # Get list of WSL distributions using wsl -l -v
            result = subprocess.run(  # nosec B603 B607
                ["wsl", "-l", "-v"],
                capture_output=True,
                timeout=30,
                check=False,
                creationflags=(
                    subprocess.CREATE_NO_WINDOW
                    if hasattr(subprocess, "CREATE_NO_WINDOW")
                    else 0
                ),
            )

            if result.returncode != 0:
                self.logger.warning("WSL list command failed: %s", result.stderr)
                return instances

            # Parse the output - WSL outputs UTF-16 with BOM on Windows
            try:
                output = result.stdout.decode("utf-16-le").strip()
            except UnicodeDecodeError:
                try:
                    output = result.stdout.decode("utf-8").strip()
                except UnicodeDecodeError:
                    output = result.stdout.decode("latin-1").strip()

            # Remove null characters that Windows sometimes adds
            output = output.replace("\x00", "")

            # Check for "no distributions" message
            if "no installed distributions" in output.lower():
                self.logger.info("No WSL distributions installed")
                return instances

            # Parse output lines (skip header)
            lines = output.strip().split("\n")
            if len(lines) < 2:
                return instances

            # Skip header line
            for line in lines[1:]:
                line = line.strip()
                if not line:
                    continue

                # Parse line: "* Ubuntu    Running  2" or "  Debian   Stopped  2"
                # The asterisk indicates the default distribution
                is_default = line.startswith("*")
                if is_default:
                    line = line[1:].strip()

                # Split by whitespace
                parts = line.split()
                if len(parts) >= 2:
                    name = parts[0]
                    status = parts[1].lower() if len(parts) > 1 else "unknown"
                    version = parts[2] if len(parts) > 2 else "2"

                    # Map WSL status to our status values
                    if status == "running":
                        mapped_status = "running"
                    elif status == "stopped":
                        mapped_status = "stopped"
                    else:
                        mapped_status = status

                    # Get hostname from inside the WSL instance if it's running
                    hostname = None
                    if mapped_status == "running":
                        hostname = self._get_wsl_hostname(name)

                    # Get unique GUID for this WSL instance from registry
                    wsl_guid = self._get_wsl_guid(name)

                    instance = {
                        "child_type": "wsl",
                        "child_name": name,
                        "status": mapped_status,
                        "is_default": is_default,
                        "wsl_version": version,
                        "distribution": self._parse_wsl_distribution(name),
                        "hostname": hostname,
                        "wsl_guid": wsl_guid,
                    }
                    instances.append(instance)

            self.logger.info("Found %d WSL instances", len(instances))

        except subprocess.TimeoutExpired:
            self.logger.warning("WSL list command timed out")
        except FileNotFoundError:
            self.logger.debug("WSL command not found")
        except Exception as error:
            self.logger.error("Error listing WSL instances: %s", error)

        return instances

    def _get_wsl_guid(self, distribution_name: str) -> Optional[str]:
        """
        Get the unique GUID for a WSL distribution from the Windows registry.

        WSL assigns a unique GUID to each distribution instance. This GUID changes
        when a distribution is deleted and recreated, even with the same name.
        This allows us to distinguish between different instances with the same name.

        Args:
            distribution_name: WSL distribution name (e.g., "Ubuntu-24.04")

        Returns:
            GUID string (e.g., "0283592d-be56-40d4-b935-3dc18c3aa007") or None
        """
        if winreg is None:
            return None

        try:
            lxss_key_path = r"Software\Microsoft\Windows\CurrentVersion\Lxss"
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, lxss_key_path) as lxss_key:
                # Enumerate all subkeys (each is a GUID)
                index = 0
                while True:
                    try:
                        guid = winreg.EnumKey(lxss_key, index)
                        # Open the subkey to get the DistributionName
                        with winreg.OpenKey(lxss_key, guid) as dist_key:
                            try:
                                dist_name, _ = winreg.QueryValueEx(
                                    dist_key, "DistributionName"
                                )
                                if dist_name == distribution_name:
                                    # Remove curly braces if present
                                    return guid.strip("{}")
                            except FileNotFoundError:
                                pass  # DistributionName not found in this key
                        index += 1
                    except OSError:
                        break  # No more subkeys
        except FileNotFoundError:
            self.logger.debug("WSL registry key not found")
        except Exception as error:
            self.logger.debug(
                "Error reading WSL GUID for %s: %s", distribution_name, error
            )

        return None

    def _get_wsl_hostname(self, distribution: str) -> Optional[str]:
        """
        Get the FQDN hostname from inside a running WSL instance.

        Tries multiple methods in order:
        1. Read hostname from /etc/wsl.conf [network] section (most reliable for our setup)
        2. Read from /etc/hostname file
        3. Run hostname -f command
        4. Fall back to hostname command

        Args:
            distribution: WSL distribution name

        Returns:
            FQDN hostname string or None if unable to retrieve
        """
        creationflags = (
            subprocess.CREATE_NO_WINDOW
            if hasattr(subprocess, "CREATE_NO_WINDOW")
            else 0
        )

        try:
            # Method 1: Try reading from wsl.conf where we set the hostname
            result = subprocess.run(  # nosec B603 B607
                [
                    "wsl",
                    "-d",
                    distribution,
                    "--",
                    "sh",
                    "-c",
                    "grep -E '^hostname=' /etc/wsl.conf 2>/dev/null | cut -d= -f2",
                ],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
                creationflags=creationflags,
            )
            if result.returncode == 0:
                hostname = result.stdout.strip()
                if hostname and hostname != "localhost" and "." in hostname:
                    return hostname

            # Method 2: Try reading from /etc/hostname
            result = subprocess.run(  # nosec B603 B607
                ["wsl", "-d", distribution, "--", "cat", "/etc/hostname"],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
                creationflags=creationflags,
            )
            if result.returncode == 0:
                hostname = result.stdout.strip()
                if hostname and hostname != "localhost" and "." in hostname:
                    return hostname

            # Method 3: Try to get FQDN using hostname -f
            result = subprocess.run(  # nosec B603 B607
                ["wsl", "-d", distribution, "--", "hostname", "-f"],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
                creationflags=creationflags,
            )

            if result.returncode == 0:
                hostname = result.stdout.strip()
                if hostname and hostname != "localhost":
                    return hostname

            # Method 4: Fall back to short hostname if FQDN not available
            result = subprocess.run(  # nosec B603 B607
                ["wsl", "-d", distribution, "--", "hostname"],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
                creationflags=creationflags,
            )

            if result.returncode == 0:
                hostname = result.stdout.strip()
                if hostname:
                    return hostname

            # Fall back to reading /etc/hostname if hostname command not available
            # (e.g., openSUSE Tumbleweed minimal install doesn't have hostname command)
            result = subprocess.run(  # nosec B603 B607
                ["wsl", "-d", distribution, "--", "cat", "/etc/hostname"],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
                creationflags=(
                    subprocess.CREATE_NO_WINDOW
                    if hasattr(subprocess, "CREATE_NO_WINDOW")
                    else 0
                ),
            )

            if result.returncode == 0:
                hostname = result.stdout.strip()
                if hostname:
                    return hostname
        except Exception as error:
            self.logger.debug("Error getting hostname for %s: %s", distribution, error)

        return None

    def _parse_wsl_distribution(self, name: str) -> Dict[str, Optional[str]]:
        """
        Parse distribution info from WSL instance name.

        Args:
            name: WSL distribution name (e.g., "Ubuntu-24.04")

        Returns:
            Dict with distribution_name and distribution_version
        """
        # Common WSL distribution name patterns
        distribution_patterns = {
            "Ubuntu": ("Ubuntu", None),
            "Ubuntu-24.04": ("Ubuntu", "24.04"),
            "Ubuntu-22.04": ("Ubuntu", "22.04"),
            "Ubuntu-20.04": ("Ubuntu", "20.04"),
            "Ubuntu-18.04": ("Ubuntu", "18.04"),
            "Debian": ("Debian", None),
            "kali-linux": ("Kali Linux", None),
            "openSUSE-Tumbleweed": ("openSUSE", "Tumbleweed"),
            "openSUSE-Leap-15": ("openSUSE", "15"),
            "SLES-15": ("SLES", "15"),
            "Fedora": ("Fedora", None),
            "AlmaLinux-9": ("AlmaLinux", "9"),
            "RockyLinux-9": ("Rocky Linux", "9"),
        }

        # Try exact match first
        if name in distribution_patterns:
            dist_name, dist_version = distribution_patterns[name]
            return {
                "distribution_name": dist_name,
                "distribution_version": dist_version,
            }

        # Try partial match
        name_lower = name.lower()
        for pattern, (dist_name, dist_version) in distribution_patterns.items():
            if pattern.lower() in name_lower:
                # Try to extract version from name if not in pattern
                if dist_version is None:
                    # Look for version pattern like -XX.XX or -X
                    version_match = re.search(r"-(\d+\.?\d*)", name)
                    if version_match:
                        dist_version = version_match.group(1)
                return {
                    "distribution_name": dist_name,
                    "distribution_version": dist_version,
                }

        # Unknown distribution
        return {
            "distribution_name": name,
            "distribution_version": None,
        }

    def list_hyperv_vms(self) -> List[Dict[str, Any]]:
        """
        List Hyper-V virtual machines on Windows.

        Returns:
            List of Hyper-V VM information dicts
        """
        vms = []

        try:
            # Use PowerShell to get Hyper-V VMs
            ps_command = "Get-VM | Select-Object Name, State, VMId | ConvertTo-Json"

            result = subprocess.run(  # nosec B603 B607
                ["powershell", "-Command", ps_command],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
                creationflags=(
                    subprocess.CREATE_NO_WINDOW
                    if hasattr(subprocess, "CREATE_NO_WINDOW")
                    else 0
                ),
            )

            if result.returncode == 0 and result.stdout.strip():
                vm_data = json.loads(result.stdout)

                # Handle single VM case (not an array)
                if isinstance(vm_data, dict):
                    vm_data = [vm_data]

                for vm_info in vm_data:
                    # Map Hyper-V state to our status
                    state = str(vm_info.get("State", "")).lower()
                    if state in ["2", "running"]:
                        status = "running"
                    elif state in ["3", "off"]:
                        status = "stopped"
                    else:
                        status = state

                    vms.append(
                        {
                            "child_type": "hyperv",
                            "child_name": vm_info.get("Name"),
                            "status": status,
                            "vm_id": vm_info.get("VMId"),
                        }
                    )

        except json.JSONDecodeError:
            self.logger.debug("No Hyper-V VMs found or invalid JSON output")
        except Exception as error:
            self.logger.debug("Error listing Hyper-V VMs: %s", error)

        return vms

    def list_lxd_containers(self) -> List[Dict[str, Any]]:
        """
        List LXD/LXC containers on Linux.

        Returns:
            List of LXD container information dicts with:
            - child_type: 'lxd'
            - child_name: container name
            - status: running/stopped/etc
            - type: container or virtual-machine
            - architecture: e.g., x86_64
            - created_at: ISO timestamp
            - ipv4_address: primary IPv4 address if running
            - ipv6_address: primary IPv6 address if running
            - hostname: hostname from inside container if running
            - distribution: dict with distribution_name and distribution_version
        """
        containers = []

        try:
            # Use lxc list with JSON format
            result = subprocess.run(  # nosec B603 B607
                ["lxc", "list", "--format", "json"],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )

            if result.returncode == 0 and result.stdout.strip():
                container_data = json.loads(result.stdout)

                for container in container_data:
                    name = container.get("name")

                    # Map LXD status to our status
                    status = container.get("status", "").lower()
                    if status == "running":
                        mapped_status = "running"
                    elif status == "stopped":
                        mapped_status = "stopped"
                    else:
                        mapped_status = status

                    # Extract IP addresses from state.network
                    ipv4_address, ipv6_address = self._extract_container_ips(
                        container, mapped_status
                    )

                    # Get hostname from inside the container if running
                    hostname = None
                    if mapped_status == "running":
                        hostname = self._get_lxd_hostname(name)

                    # Parse distribution info from config
                    config = container.get("config", {})
                    distribution = self._parse_lxd_distribution(config)

                    # Get created date
                    created_at = container.get("created_at")

                    containers.append(
                        {
                            "child_type": "lxd",
                            "child_name": name,
                            "status": mapped_status,
                            "type": container.get(
                                "type"
                            ),  # container or virtual-machine
                            "architecture": container.get("architecture"),
                            "created_at": created_at,
                            "ipv4_address": ipv4_address,
                            "ipv6_address": ipv6_address,
                            "hostname": hostname,
                            "distribution": distribution,
                        }
                    )

                self.logger.info("Found %d LXD containers", len(containers))

        except json.JSONDecodeError:
            self.logger.debug("No LXD containers found or invalid JSON output")
        except FileNotFoundError:
            self.logger.debug("lxc command not found")
        except Exception as error:
            self.logger.debug("Error listing LXD containers: %s", error)

        return containers

    def _extract_container_ips(
        self, container: Dict[str, Any], status: str
    ) -> tuple[Optional[str], Optional[str]]:
        """
        Extract IPv4 and IPv6 addresses from container state.

        Args:
            container: Container data dict from lxc list
            status: Container status string

        Returns:
            Tuple of (ipv4_address, ipv6_address), either can be None
        """
        ipv4_address = None
        ipv6_address = None

        if status != "running":
            return ipv4_address, ipv6_address

        state = container.get("state")
        if not state:
            return ipv4_address, ipv6_address

        network = state.get("network", {})
        for iface_name, iface_data in network.items():
            if iface_name == "lo":
                continue
            for addr in iface_data.get("addresses", []):
                family = addr.get("family")
                if family == "inet" and not ipv4_address:
                    ipv4_address = addr.get("address")
                elif family == "inet6" and not ipv6_address:
                    addr_val = addr.get("address", "")
                    if not addr_val.startswith("fe80:"):
                        ipv6_address = addr_val
            if ipv4_address:
                break

        return ipv4_address, ipv6_address

    def _get_lxd_hostname(self, container_name: str) -> Optional[str]:
        """
        Get the hostname from inside a running LXD container.

        Args:
            container_name: LXD container name

        Returns:
            Hostname string or None if unable to retrieve
        """
        try:
            # Try reading from /etc/hostname first
            result = subprocess.run(  # nosec B603 B607
                ["lxc", "exec", container_name, "--", "cat", "/etc/hostname"],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            if result.returncode == 0:
                hostname = result.stdout.strip()
                if hostname:
                    return hostname

            # Fall back to hostname command
            result = subprocess.run(  # nosec B603 B607
                ["lxc", "exec", container_name, "--", "hostname", "-f"],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            if result.returncode == 0:
                hostname = result.stdout.strip()
                if hostname and hostname != "localhost":
                    return hostname

            # Try just hostname without -f
            result = subprocess.run(  # nosec B603 B607
                ["lxc", "exec", container_name, "--", "hostname"],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            if result.returncode == 0:
                hostname = result.stdout.strip()
                if hostname:
                    return hostname

        except Exception as error:
            self.logger.debug(
                "Error getting hostname for LXD container %s: %s", container_name, error
            )

        return None

    def _parse_lxd_distribution(
        self, config: Dict[str, Any]
    ) -> Dict[str, Optional[str]]:
        """
        Parse distribution info from LXD container config.

        Args:
            config: Container config dict containing image.* keys

        Returns:
            Dict with distribution_name and distribution_version
        """
        # LXD stores image info in config keys like:
        # image.os, image.release, image.description
        image_os = config.get("image.os", "")
        image_release = config.get("image.release", "")
        image_description = config.get("image.description", "")

        # Map OS names to proper capitalization
        os_name_map = {
            "ubuntu": "Ubuntu",
            "debian": "Debian",
            "fedora": "Fedora",
            "rockylinux": "Rocky Linux",
            "rocky": "Rocky Linux",
            "almalinux": "AlmaLinux",
            "alma": "AlmaLinux",
            "centos": "CentOS",
            "opensuse": "openSUSE",
        }

        # Ubuntu codename to version mapping
        ubuntu_codename_map = {
            "noble": "24.04",
            "mantic": "23.10",
            "lunar": "23.04",
            "kinetic": "22.10",
            "jammy": "22.04",
            "impish": "21.10",
            "hirsute": "21.04",
            "groovy": "20.10",
            "focal": "20.04",
            "bionic": "18.04",
            "xenial": "16.04",
        }

        # Debian codename to version mapping
        debian_codename_map = {
            "trixie": "13",
            "bookworm": "12",
            "bullseye": "11",
            "buster": "10",
        }

        # Normalize the OS name
        distribution_name = None
        if image_os:
            os_lower = image_os.lower()
            distribution_name = os_name_map.get(os_lower, image_os.capitalize())

        # Process the release/version - might be a codename or version number
        distribution_version = None
        if image_release:
            release_lower = image_release.lower()
            # Check if it's an Ubuntu or Debian codename, else use as-is
            distribution_version = ubuntu_codename_map.get(
                release_lower, debian_codename_map.get(release_lower, image_release)
            )

        # If we don't have image.os, try to parse from description
        if not distribution_name and image_description:
            # Common patterns: "Ubuntu 24.04 LTS", "Debian 12", "Fedora 40"
            desc_lower = image_description.lower()
            for os_key, os_display in os_name_map.items():
                if os_key in desc_lower:
                    distribution_name = os_display
                    break

            # Try to extract version from description
            if not distribution_version:
                # Match patterns like "24.04", "12", "40"
                version_match = re.search(r"(\d+(?:\.\d+)?)", image_description)
                if version_match:
                    distribution_version = version_match.group(1)

        return {
            "distribution_name": distribution_name,
            "distribution_version": distribution_version,
        }

    def list_kvm_vms(self) -> List[Dict[str, Any]]:
        """
        List KVM/QEMU virtual machines on Linux.

        Returns:
            List of KVM VM information dicts
        """
        vms = []

        try:
            # Use virsh to list VMs
            result = subprocess.run(  # nosec B603 B607
                ["virsh", "list", "--all"],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )

            if result.returncode == 0:
                # Parse virsh output
                lines = result.stdout.strip().split("\n")
                # Skip header lines
                for line in lines[2:]:
                    line = line.strip()
                    if not line:
                        continue

                    parts = line.split()
                    if len(parts) >= 2:
                        # Format: "ID  Name  State"
                        # ID can be "-" for stopped VMs
                        vm_id = parts[0] if parts[0] != "-" else None
                        name = parts[1]
                        state = (
                            " ".join(parts[2:]).lower() if len(parts) > 2 else "unknown"
                        )

                        if "running" in state:
                            status = "running"
                        elif "shut off" in state or "stopped" in state:
                            status = "stopped"
                        else:
                            status = state

                        vms.append(
                            {
                                "child_type": "kvm",
                                "child_name": name,
                                "status": status,
                                "vm_id": vm_id,
                            }
                        )

        except FileNotFoundError:
            self.logger.debug("virsh command not found")
        except Exception as error:
            self.logger.debug("Error listing KVM VMs: %s", error)

        return vms

    def list_virtualbox_vms(self) -> List[Dict[str, Any]]:
        """
        List VirtualBox virtual machines (cross-platform).

        Returns:
            List of VirtualBox VM information dicts
        """
        vms = []

        try:
            # Find VBoxManage
            vboxmanage = shutil.which("VBoxManage")
            if not vboxmanage and platform.system().lower() == "windows":
                common_paths = [
                    os.path.join(
                        os.environ.get("ProgramFiles", ""),
                        "Oracle",
                        "VirtualBox",
                        "VBoxManage.exe",
                    ),
                    os.path.join(
                        os.environ.get("ProgramFiles(x86)", ""),
                        "Oracle",
                        "VirtualBox",
                        "VBoxManage.exe",
                    ),
                ]
                for path in common_paths:
                    if os.path.exists(path):
                        vboxmanage = path
                        break

            if not vboxmanage:
                return vms

            # Get list of VMs
            creationflags = (
                subprocess.CREATE_NO_WINDOW
                if hasattr(subprocess, "CREATE_NO_WINDOW")
                and platform.system().lower() == "windows"
                else 0
            )
            result = subprocess.run(  # nosec B603 B607
                [vboxmanage, "list", "vms"],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
                creationflags=creationflags,
            )

            if result.returncode != 0:
                return vms

            # Parse output: "VMName" {uuid}
            for line in result.stdout.strip().split("\n"):
                line = line.strip()
                if not line:
                    continue

                # Extract name and UUID
                match = re.match(r'"(.+)"\s+\{([^}]+)\}', line)
                if not match:
                    continue

                name = match.group(1)
                uuid = match.group(2)
                status = self._get_virtualbox_vm_status(vboxmanage, uuid, creationflags)

                vms.append(
                    {
                        "child_type": "virtualbox",
                        "child_name": name,
                        "status": status,
                        "vm_id": uuid,
                    }
                )

        except Exception as error:
            self.logger.debug("Error listing VirtualBox VMs: %s", error)

        return vms

    def _get_virtualbox_vm_status(
        self, vboxmanage: str, uuid: str, creationflags: int
    ) -> str:
        """
        Get the status of a VirtualBox VM.

        Args:
            vboxmanage: Path to VBoxManage executable
            uuid: VM UUID
            creationflags: Subprocess creation flags

        Returns:
            VM status string
        """
        state_result = subprocess.run(  # nosec B603 B607
            [vboxmanage, "showvminfo", uuid, "--machinereadable"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
            creationflags=creationflags,
        )

        if state_result.returncode != 0:
            return "unknown"

        for state_line in state_result.stdout.split("\n"):
            if state_line.startswith("VMState="):
                state_value = state_line.split("=")[1].strip('"')
                if state_value == "running":
                    return "running"
                if state_value in ["poweroff", "aborted", "saved"]:
                    return "stopped"
                return state_value

        return "unknown"
