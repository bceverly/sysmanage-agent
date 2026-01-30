"""
Child host listing methods for various virtualization platforms.
"""

import json
import os
import platform
import re
import shutil
import subprocess  # nosec B404 # Required for system command execution
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# Import WSL listing functionality from extracted module
from .child_host_listing_wsl import WSLListing

# Import bhyve metadata functions
from .child_host_bhyve_creation import (
    load_bhyve_metadata,
)

# Module-level constants for repeated string literals
_ORACLE_LINUX = "Oracle Linux"

# VMM metadata directory for storing hostname/distribution info
VMM_METADATA_DIR = "/var/vmm/metadata"

# Allowlist of safe directories for VirtualBox executable
VBOX_SAFE_PATHS = [
    # Linux/Unix
    "/usr/bin",
    "/usr/local/bin",
    "/opt/VirtualBox",
    # macOS
    "/usr/local/bin",
    "/Applications/VirtualBox.app/Contents/MacOS",
    # Windows (checked separately via environment)
]


def is_safe_vbox_path(path: str) -> bool:
    """
    Validate that a VBoxManage path is in a safe location.

    Args:
        path: Path to the VBoxManage executable

    Returns:
        True if the path is in a known safe directory, False otherwise
    """
    if not path:
        return False

    # Normalize the path
    normalized = os.path.normpath(os.path.abspath(path))

    # Check Unix/Linux/macOS safe paths
    for safe_dir in VBOX_SAFE_PATHS:
        if normalized.startswith(safe_dir + os.sep) or normalized.startswith(
            safe_dir + "/"
        ):
            return True

    # Check Windows paths - must be in Program Files under Oracle\VirtualBox
    if platform.system().lower() == "windows":
        lower_path = normalized.lower()
        if "\\oracle\\virtualbox\\" in lower_path or lower_path.endswith(
            "\\oracle\\virtualbox"
        ):
            # Verify it's under a Program Files directory
            if (
                "\\program files\\" in lower_path
                or "\\program files (x86)\\" in lower_path
            ):
                return True

    return False


class ChildHostListing:
    """Methods to list child hosts on various platforms."""

    def __init__(self, logger):
        """Initialize with logger."""
        self.logger = logger
        # Delegate WSL functionality to extracted module
        self._wsl_listing = WSLListing(logger)

    def list_wsl_instances(self) -> List[Dict[str, Any]]:
        """
        List all WSL instances on Windows.

        Returns:
            List of WSL instance information dicts
        """
        return self._wsl_listing.list_wsl_instances()

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

    def _extract_ips_from_interface(
        self, iface_data: Dict[str, Any], ipv4: Optional[str], ipv6: Optional[str]
    ) -> Tuple[Optional[str], Optional[str]]:
        """
        Extract IP addresses from a single network interface.

        Args:
            iface_data: Interface data from container state
            ipv4: Current IPv4 address (may be None)
            ipv6: Current IPv6 address (may be None)

        Returns:
            Tuple of (ipv4_address, ipv6_address)
        """
        for addr in iface_data.get("addresses", []):
            family = addr.get("family")
            if family == "inet" and not ipv4:
                ipv4 = addr.get("address")
            elif family == "inet6" and not ipv6:
                addr_val = addr.get("address", "")
                if not addr_val.startswith("fe80:"):
                    ipv6 = addr_val
        return ipv4, ipv6

    def _extract_container_ips(
        self, container: Dict[str, Any], status: str
    ) -> Tuple[Optional[str], Optional[str]]:
        """
        Extract IPv4 and IPv6 addresses from container state.

        Args:
            container: Container data dict from lxc list
            status: Container status string

        Returns:
            Tuple of (ipv4_address, ipv6_address), either can be None
        """
        if status != "running":
            return None, None

        state = container.get("state")
        if not state:
            return None, None

        ipv4_address = None
        ipv6_address = None
        network = state.get("network", {})

        for iface_name, iface_data in network.items():
            if iface_name == "lo":
                continue
            ipv4_address, ipv6_address = self._extract_ips_from_interface(
                iface_data, ipv4_address, ipv6_address
            )
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
            "oraclelinux": _ORACLE_LINUX,
            "oracle": _ORACLE_LINUX,
            "ol": _ORACLE_LINUX,
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

    def _parse_kvm_vm_status(self, state: str) -> str:
        """
        Map KVM/virsh state to normalized status.

        Args:
            state: Raw state string from virsh output

        Returns:
            Normalized status string
        """
        if "running" in state:
            return "running"
        if "shut off" in state or "stopped" in state:
            return "stopped"
        return state

    def _parse_kvm_vm_line(self, line: str) -> Optional[Dict[str, Any]]:
        """
        Parse a single line from virsh list output.

        Args:
            line: A line from virsh list --all output

        Returns:
            VM dict or None if line is invalid
        """
        line = line.strip()
        if not line:
            return None

        parts = line.split()
        if len(parts) < 2:
            return None

        # Format: "ID  Name  State"
        # ID can be "-" for stopped VMs
        vm_id = parts[0] if parts[0] != "-" else None
        name = parts[1]
        state = " ".join(parts[2:]).lower() if len(parts) > 2 else "unknown"
        status = self._parse_kvm_vm_status(state)

        return {
            "child_type": "kvm",
            "child_name": name,
            "status": status,
            "vm_id": vm_id,
        }

    def list_kvm_vms(self) -> List[Dict[str, Any]]:
        """
        List KVM/QEMU virtual machines on Linux.

        Returns:
            List of KVM VM information dicts
        """
        vms = []

        try:
            result = subprocess.run(  # nosec B603 B607
                ["virsh", "list", "--all"],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )

            if result.returncode == 0:
                lines = result.stdout.strip().split("\n")
                # Skip header lines (first two)
                for line in lines[2:]:
                    vm_info = self._parse_kvm_vm_line(line)
                    if vm_info:
                        vms.append(vm_info)

        except FileNotFoundError:
            self.logger.debug("virsh command not found")
        except Exception as error:
            self.logger.debug("Error listing KVM VMs: %s", error)

        return vms

    def _find_vboxmanage_path(self) -> Optional[str]:
        """
        Find the VBoxManage executable path.

        Returns:
            Path to VBoxManage or None if not found
        """
        vboxmanage = shutil.which("VBoxManage")
        if vboxmanage:
            return vboxmanage

        if platform.system().lower() != "windows":
            return None

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
                return path
        return None

    def _get_subprocess_creationflags(self) -> int:
        """Get appropriate subprocess creation flags for the current platform."""
        if (
            hasattr(subprocess, "CREATE_NO_WINDOW")
            and platform.system().lower() == "windows"
        ):
            return subprocess.CREATE_NO_WINDOW
        return 0

    def _parse_virtualbox_vm_line(
        self, line: str, vboxmanage: str, creationflags: int
    ) -> Optional[Dict[str, Any]]:
        """
        Parse a single line from VBoxManage list vms output.

        Args:
            line: A line from VBoxManage output
            vboxmanage: Path to VBoxManage executable
            creationflags: Subprocess creation flags

        Returns:
            VM dict or None if line is invalid
        """
        line = line.strip()
        if not line:
            return None

        # NOSONAR - regex operates on trusted internal data
        match = re.match(r'"(.+)"\s+\{([^}]+)\}', line)
        if not match:
            return None

        name = match.group(1)
        uuid = match.group(2)
        status = self._get_virtualbox_vm_status(vboxmanage, uuid, creationflags)

        return {
            "child_type": "virtualbox",
            "child_name": name,
            "status": status,
            "vm_id": uuid,
        }

    def list_virtualbox_vms(self) -> List[Dict[str, Any]]:
        """
        List VirtualBox virtual machines (cross-platform).

        Returns:
            List of VirtualBox VM information dicts
        """
        vms = []

        try:
            vboxmanage = self._find_vboxmanage_path()

            # Validate the path is in a safe location to prevent PATH hijacking
            if not vboxmanage or not is_safe_vbox_path(vboxmanage):
                if vboxmanage:
                    self.logger.warning(
                        "VBoxManage found at untrusted path: %s", vboxmanage
                    )
                return vms

            creationflags = self._get_subprocess_creationflags()
            result = subprocess.run(  # nosec B603 B607
                [  # nosemgrep: dangerous-subprocess-use-tainted-env-args
                    vboxmanage,
                    "list",
                    "vms",
                ],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
                creationflags=creationflags,
            )

            if result.returncode != 0:
                return vms

            for line in result.stdout.strip().split("\n"):
                vm_info = self._parse_virtualbox_vm_line(
                    line, vboxmanage, creationflags
                )
                if vm_info:
                    vms.append(vm_info)

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
        state_result = subprocess.run(  # nosec B603 B607  # nosemgrep: dangerous-subprocess-use-tainted-env-args
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

    def _parse_vmm_vm_line(self, line: str) -> Optional[Dict[str, Any]]:
        """
        Parse a single line from vmctl status output.

        Args:
            line: A line from vmctl status output

        Returns:
            VM dict or None if line is invalid
        """
        line = line.strip()
        if not line:
            return None

        parts = line.split()
        if len(parts) < 9:
            return None

        # 9 columns: ID, PID, VCPUS, MAXMEM, CURMEM, TTY, OWNER, STATE, NAME
        vm_id = parts[0]
        vcpus = parts[2]
        max_mem = parts[3]
        cur_mem = parts[4]
        tty = parts[5]
        owner = parts[6]
        state = parts[7]
        name = parts[8]

        # Use STATE column for status
        if state == "running":
            status = "running"
        else:
            status = "stopped"
            vm_id = None

        # Get stored metadata (hostname, distribution) if available
        metadata = self._get_vmm_metadata(name)
        hostname = metadata.get("hostname") if metadata else None
        distribution = metadata.get("distribution") if metadata else None

        return {
            "child_type": "vmm",
            "child_name": name,
            "status": status,
            "vm_id": vm_id,
            "vcpus": vcpus,
            "memory": max_mem,
            "current_memory": cur_mem,
            "tty": tty if tty != "-" else None,
            "owner": owner,
            "hostname": hostname,
            "distribution": distribution,
        }

    def list_vmm_vms(self) -> List[Dict[str, Any]]:
        """
        List VMM virtual machines on OpenBSD.

        Parses the output of 'vmctl status' to enumerate VMs.

        Returns:
            List of VMM VM information dicts with:
            - child_type: 'vmm'
            - child_name: VM name
            - status: running/stopped
            - vm_id: VM ID (if running)
            - memory: Memory allocation
            - vcpus: Number of vCPUs
        """
        vms = []

        try:
            result = subprocess.run(  # nosec B603 B607
                ["vmctl", "status"],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )

            if result.returncode != 0:
                self.logger.debug("vmctl status failed: %s", result.stderr)
                return vms

            lines = result.stdout.strip().split("\n")
            if len(lines) < 2:
                return vms

            # Skip header line
            for line in lines[1:]:
                vm_info = self._parse_vmm_vm_line(line)
                if vm_info:
                    vms.append(vm_info)

            self.logger.info("Found %d VMM VMs", len(vms))

        except FileNotFoundError:
            self.logger.debug("vmctl command not found")
        except Exception as error:
            self.logger.debug("Error listing VMM VMs: %s", error)

        return vms

    def _get_vmm_metadata(self, vm_name: str) -> Optional[Dict[str, Any]]:
        """
        Read VM metadata from stored JSON file.

        The metadata is stored when VM is created and includes hostname
        and distribution info that vmctl status doesn't provide.

        Args:
            vm_name: Name of the VM

        Returns:
            Dict with hostname, distribution, etc. or None if not found
        """
        try:
            metadata_file = Path(VMM_METADATA_DIR) / f"{vm_name}.json"
            if not metadata_file.exists():
                return None

            with open(metadata_file, "r", encoding="utf-8") as metadata_fp:
                return json.load(metadata_fp)

        except Exception as error:
            self.logger.debug("Error reading VMM metadata for '%s': %s", vm_name, error)
            return None

    def _create_bhyve_vm_dict(self, vm_name: str, status: str) -> Dict[str, Any]:
        """
        Create a bhyve VM dictionary with metadata.

        Args:
            vm_name: Name of the VM
            status: VM status (running/stopped)

        Returns:
            VM information dictionary
        """
        metadata = load_bhyve_metadata(vm_name, self.logger)
        hostname = metadata.get("hostname") if metadata else None
        distribution = metadata.get("distribution") if metadata else None

        return {
            "child_type": "bhyve",
            "child_name": vm_name,
            "status": status,
            "hostname": hostname,
            "distribution": distribution,
        }

    def _list_running_bhyve_vms(self) -> Tuple[List[Dict[str, Any]], set]:
        """
        List running bhyve VMs from /dev/vmm directory.

        Returns:
            Tuple of (list of VM dicts, set of running VM names)
        """
        vms = []
        running_vms = set()
        vmm_dir = "/dev/vmm"

        if not os.path.isdir(vmm_dir):
            return vms, running_vms

        try:
            for vm_name in os.listdir(vmm_dir):
                running_vms.add(vm_name)
                vms.append(self._create_bhyve_vm_dict(vm_name, "running"))
        except PermissionError:
            self.logger.debug("Permission denied reading /dev/vmm")

        return vms, running_vms

    def _is_valid_bhyve_vm_dir(self, vm_base_dir: str, entry: str) -> bool:
        """
        Check if a directory entry represents a valid bhyve VM.

        Args:
            vm_base_dir: Base VM directory path
            entry: Directory entry name

        Returns:
            True if this is a valid VM directory
        """
        # Skip hidden directories and special directories
        if entry.startswith(".") or entry in ("images", "cloud-init", "metadata"):
            return False

        vm_dir = os.path.join(vm_base_dir, entry)
        if not os.path.isdir(vm_dir):
            return False

        # Check if there's a disk image in this directory
        disk_path = os.path.join(vm_dir, f"{entry}.img")
        return os.path.exists(disk_path)

    def _list_stopped_bhyve_vms(self, running_vms: set) -> List[Dict[str, Any]]:
        """
        List stopped bhyve VMs from /vm directory.

        Args:
            running_vms: Set of running VM names to exclude

        Returns:
            List of stopped VM dicts
        """
        vms = []
        vm_base_dir = "/vm"

        if not os.path.isdir(vm_base_dir):
            return vms

        try:
            for entry in os.listdir(vm_base_dir):
                if not self._is_valid_bhyve_vm_dir(vm_base_dir, entry):
                    continue
                if entry not in running_vms:
                    vms.append(self._create_bhyve_vm_dict(entry, "stopped"))
        except PermissionError:
            self.logger.debug("Permission denied reading /vm")

        return vms

    def list_bhyve_vms(self) -> List[Dict[str, Any]]:
        """
        List bhyve virtual machines on FreeBSD.

        Enumerates VMs by:
        1. Checking /dev/vmm directory for running VMs
        2. Checking /vm directory for VM disk images (to find stopped VMs)
        3. Reading metadata files for hostname and distribution info

        Returns:
            List of bhyve VM information dicts with:
            - child_type: 'bhyve'
            - child_name: VM name
            - status: running/stopped
            - hostname: FQDN (from metadata, if available)
            - distribution: dict with distribution_name and distribution_version
        """
        try:
            running_vms_list, running_vms_set = self._list_running_bhyve_vms()
            stopped_vms_list = self._list_stopped_bhyve_vms(running_vms_set)

            vms = running_vms_list + stopped_vms_list
            self.logger.info("Found %d bhyve VMs", len(vms))
            return vms

        except Exception as error:
            self.logger.debug("Error listing bhyve VMs: %s", error)
            return []
