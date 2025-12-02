"""
Child Host Operations for SysManage Agent.

This module provides functionality for managing virtual machines, containers,
and WSL instances as "child hosts" of the parent system.

Supported child host types:
- WSL v2 (Windows Subsystem for Linux)
- LXD/LXC containers (future)
- VirtualBox VMs (future)
- Hyper-V VMs (future)
- VMM/vmd (OpenBSD, future)
- bhyve (FreeBSD, future)
- KVM/QEMU (Linux, future)
"""

import json
import logging
import os
import platform
import re
import shutil
import subprocess  # nosec B404 # Required for system command execution
from typing import Any, Dict, List, Optional

from src.i18n import _


class ChildHostOperations:
    """
    Handles child host management operations including virtualization
    detection and child host enumeration.
    """

    def __init__(self, agent_instance):
        """
        Initialize the child host operations module.

        Args:
            agent_instance: Reference to the main SysManageAgent instance
        """
        self.agent = agent_instance
        self.logger = logging.getLogger(__name__)
        self.logger.info(_("Child host operations module initialized"))

    async def check_virtualization_support(
        self, _parameters: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Check what virtualization technologies are supported on this host.

        Returns information about:
        - WSL support (Windows only)
        - LXD/LXC support (Linux only)
        - VirtualBox support (cross-platform)
        - Hyper-V support (Windows only)
        - KVM/QEMU support (Linux only)
        - bhyve support (FreeBSD only)
        - VMM/vmd support (OpenBSD only)

        Returns:
            Dict containing:
            - success: bool
            - supported_types: List of supported child host types
            - capabilities: Dict with detailed capability info per type
            - reboot_required: bool (e.g., if WSL needs to be enabled)
        """
        self.logger.info(_("Checking virtualization support"))

        try:
            os_type = platform.system().lower()
            supported_types = []
            capabilities = {}
            reboot_required = False

            if os_type == "windows":
                # Check Windows virtualization options
                wsl_info = self._check_wsl_support()
                if wsl_info["available"]:
                    supported_types.append("wsl")
                    capabilities["wsl"] = wsl_info
                    if wsl_info.get("needs_enable"):
                        reboot_required = True

                hyperv_info = self._check_hyperv_support()
                if hyperv_info["available"]:
                    supported_types.append("hyperv")
                    capabilities["hyperv"] = hyperv_info

            elif os_type == "linux":
                # Check Linux virtualization options
                lxd_info = self._check_lxd_support()
                if lxd_info["available"]:
                    supported_types.append("lxd")
                    capabilities["lxd"] = lxd_info

                kvm_info = self._check_kvm_support()
                if kvm_info["available"]:
                    supported_types.append("kvm")
                    capabilities["kvm"] = kvm_info

            elif os_type == "freebsd":
                # Check FreeBSD virtualization options
                bhyve_info = self._check_bhyve_support()
                if bhyve_info["available"]:
                    supported_types.append("bhyve")
                    capabilities["bhyve"] = bhyve_info

            elif os_type == "openbsd":
                # Check OpenBSD virtualization options
                vmm_info = self._check_vmm_support()
                if vmm_info["available"]:
                    supported_types.append("vmm")
                    capabilities["vmm"] = vmm_info

            # VirtualBox can be on any platform
            vbox_info = self._check_virtualbox_support()
            if vbox_info["available"]:
                supported_types.append("virtualbox")
                capabilities["virtualbox"] = vbox_info

            return {
                "success": True,
                "os_type": os_type,
                "supported_types": supported_types,
                "capabilities": capabilities,
                "reboot_required": reboot_required,
            }

        except Exception as error:
            self.logger.error(_("Error checking virtualization support: %s"), error)
            return {
                "success": False,
                "error": str(error),
                "supported_types": [],
                "capabilities": {},
            }

    def _check_wsl_support(self) -> Dict[str, Any]:
        """
        Check WSL (Windows Subsystem for Linux) support.

        Returns:
            Dict with WSL availability and status info
        """
        result = {
            "available": False,
            "enabled": False,
            "version": None,
            "needs_enable": False,
            "default_version": None,
        }

        try:
            # Check if running on Windows
            if platform.system().lower() != "windows":
                return result

            # Check if wsl.exe exists
            wsl_path = os.path.join(
                os.environ.get("SystemRoot", "C:\\Windows"), "System32", "wsl.exe"
            )
            if not os.path.exists(wsl_path):
                # WSL not available at all
                self.logger.debug("WSL executable not found at %s", wsl_path)
                return result

            # WSL binary exists, so WSL is potentially available
            result["available"] = True

            # Check WSL status using wsl --status
            try:
                status_result = subprocess.run(  # nosec B603 B607
                    ["wsl", "--status"],
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

                if status_result.returncode == 0:
                    result["enabled"] = True
                    output = status_result.stdout

                    # Parse default version from output
                    if (
                        "Default Version: 2" in output
                        or "Default Version: WSL 2" in output
                    ):
                        result["default_version"] = 2
                        result["version"] = "2"
                    elif (
                        "Default Version: 1" in output
                        or "Default Version: WSL 1" in output
                    ):
                        result["default_version"] = 1
                        result["version"] = "1"
                    else:
                        # Try to detect version from output
                        if "WSL 2" in output:
                            result["version"] = "2"
                            result["default_version"] = 2
                        else:
                            result["version"] = "2"  # Assume WSL 2 for modern Windows
                            result["default_version"] = 2

                    self.logger.info(
                        "WSL is enabled, default version: %s", result["default_version"]
                    )
                else:
                    # WSL exists but not enabled or needs configuration
                    result["enabled"] = False
                    result["needs_enable"] = True
                    self.logger.info("WSL is available but not fully enabled")

            except subprocess.TimeoutExpired:
                self.logger.warning("WSL status check timed out")
                result["enabled"] = False
                result["needs_enable"] = True

            except FileNotFoundError:
                # wsl command not found in PATH
                result["enabled"] = False
                result["needs_enable"] = True

        except Exception as error:
            self.logger.error("Error checking WSL support: %s", error)

        return result

    def _check_hyperv_support(self) -> Dict[str, Any]:
        """
        Check Hyper-V support on Windows.

        Returns:
            Dict with Hyper-V availability info
        """
        result = {
            "available": False,
            "enabled": False,
        }

        try:
            if platform.system().lower() != "windows":
                return result

            # Check if Hyper-V is available using PowerShell
            ps_command = (
                "Get-WindowsOptionalFeature -FeatureName Microsoft-Hyper-V-All "
                "-Online | Select-Object -ExpandProperty State"
            )

            ps_result = subprocess.run(  # nosec B603 B607
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

            if ps_result.returncode == 0:
                state = ps_result.stdout.strip()
                result["available"] = True
                result["enabled"] = state.lower() == "enabled"

        except Exception as error:
            self.logger.debug("Error checking Hyper-V support: %s", error)

        return result

    def _check_lxd_support(self) -> Dict[str, Any]:
        """
        Check LXD/LXC container support on Linux.

        Returns:
            Dict with LXD availability info
        """
        result = {
            "available": False,
            "installed": False,
            "initialized": False,
        }

        try:
            if platform.system().lower() != "linux":
                return result

            # Check if lxd/lxc is installed
            lxc_path = shutil.which("lxc")
            if lxc_path:
                result["available"] = True
                result["installed"] = True

                # Check if LXD is initialized
                lxc_result = subprocess.run(  # nosec B603 B607
                    ["lxc", "info"],
                    capture_output=True,
                    text=True,
                    timeout=10,
                    check=False,
                )
                result["initialized"] = lxc_result.returncode == 0

        except Exception as error:
            self.logger.debug("Error checking LXD support: %s", error)

        return result

    def _check_kvm_support(self) -> Dict[str, Any]:
        """
        Check KVM/QEMU support on Linux.

        Returns:
            Dict with KVM availability info
        """
        result = {
            "available": False,
            "kvm_module_loaded": False,
            "libvirt_installed": False,
        }

        try:
            if platform.system().lower() != "linux":
                return result

            # Check if KVM kernel module is loaded
            if os.path.exists("/dev/kvm"):
                result["kvm_module_loaded"] = True
                result["available"] = True

            # Check if libvirt is installed
            virsh_path = shutil.which("virsh")
            if virsh_path:
                result["libvirt_installed"] = True

        except Exception as error:
            self.logger.debug("Error checking KVM support: %s", error)

        return result

    def _check_bhyve_support(self) -> Dict[str, Any]:
        """
        Check bhyve support on FreeBSD.

        Returns:
            Dict with bhyve availability info
        """
        result = {
            "available": False,
        }

        try:
            if platform.system().lower() != "freebsd":
                return result

            # Check if bhyve is available
            bhyve_path = shutil.which("bhyve")
            if bhyve_path:
                result["available"] = True

        except Exception as error:
            self.logger.debug("Error checking bhyve support: %s", error)

        return result

    def _check_vmm_support(self) -> Dict[str, Any]:
        """
        Check VMM/vmd support on OpenBSD.

        Returns:
            Dict with VMM availability info
        """
        result = {
            "available": False,
        }

        try:
            if platform.system().lower() != "openbsd":
                return result

            # Check if vmctl is available
            vmctl_path = shutil.which("vmctl")
            if vmctl_path:
                result["available"] = True

        except Exception as error:
            self.logger.debug("Error checking VMM support: %s", error)

        return result

    def _check_virtualbox_support(self) -> Dict[str, Any]:
        """
        Check VirtualBox support (cross-platform).

        Returns:
            Dict with VirtualBox availability info
        """
        result = {
            "available": False,
            "version": None,
        }

        try:
            # Check for VBoxManage
            vboxmanage = shutil.which("VBoxManage")
            if not vboxmanage:
                # On Windows, try common installation paths
                if platform.system().lower() == "windows":
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

            if vboxmanage:
                result["available"] = True

                # Get version
                version_result = subprocess.run(  # nosec B603 B607
                    [vboxmanage, "--version"],
                    capture_output=True,
                    text=True,
                    timeout=10,
                    check=False,
                )
                if version_result.returncode == 0:
                    result["version"] = version_result.stdout.strip()

        except Exception as error:
            self.logger.debug("Error checking VirtualBox support: %s", error)

        return result

    async def list_child_hosts(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """
        List all child hosts (VMs, containers, WSL instances) on this system.

        Args:
            parameters: Optional filter parameters
                - child_type: Filter by type (e.g., 'wsl', 'lxd')

        Returns:
            Dict containing:
            - success: bool
            - child_hosts: List of child host information
        """
        self.logger.info(_("Listing child hosts"))

        try:
            child_type_filter = parameters.get("child_type")
            child_hosts = []
            os_type = platform.system().lower()

            if os_type == "windows":
                # Get WSL instances
                if not child_type_filter or child_type_filter == "wsl":
                    wsl_instances = self._list_wsl_instances()
                    child_hosts.extend(wsl_instances)

                # Get Hyper-V VMs (if enabled)
                if not child_type_filter or child_type_filter == "hyperv":
                    hyperv_vms = self._list_hyperv_vms()
                    child_hosts.extend(hyperv_vms)

            elif os_type == "linux":
                # Get LXD containers
                if not child_type_filter or child_type_filter == "lxd":
                    lxd_containers = self._list_lxd_containers()
                    child_hosts.extend(lxd_containers)

                # Get KVM/QEMU VMs
                if not child_type_filter or child_type_filter == "kvm":
                    kvm_vms = self._list_kvm_vms()
                    child_hosts.extend(kvm_vms)

            # VirtualBox VMs (cross-platform)
            if not child_type_filter or child_type_filter == "virtualbox":
                vbox_vms = self._list_virtualbox_vms()
                child_hosts.extend(vbox_vms)

            return {
                "success": True,
                "child_hosts": child_hosts,
                "count": len(child_hosts),
            }

        except Exception as error:
            self.logger.error(_("Error listing child hosts: %s"), error)
            return {
                "success": False,
                "error": str(error),
                "child_hosts": [],
            }

    def _list_wsl_instances(self) -> List[Dict[str, Any]]:
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

                    instance = {
                        "child_type": "wsl",
                        "child_name": name,
                        "status": mapped_status,
                        "is_default": is_default,
                        "wsl_version": version,
                        "distribution": self._parse_wsl_distribution(name),
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

    def _list_hyperv_vms(self) -> List[Dict[str, Any]]:
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

    def _list_lxd_containers(self) -> List[Dict[str, Any]]:
        """
        List LXD/LXC containers on Linux.

        Returns:
            List of LXD container information dicts
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
                    # Map LXD status to our status
                    status = container.get("status", "").lower()
                    if status == "running":
                        mapped_status = "running"
                    elif status == "stopped":
                        mapped_status = "stopped"
                    else:
                        mapped_status = status

                    containers.append(
                        {
                            "child_type": "lxd",
                            "child_name": container.get("name"),
                            "status": mapped_status,
                            "type": container.get("type"),  # container or vm
                            "architecture": container.get("architecture"),
                        }
                    )

        except json.JSONDecodeError:
            self.logger.debug("No LXD containers found or invalid JSON output")
        except FileNotFoundError:
            self.logger.debug("lxc command not found")
        except Exception as error:
            self.logger.debug("Error listing LXD containers: %s", error)

        return containers

    def _list_kvm_vms(self) -> List[Dict[str, Any]]:
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

    def _list_virtualbox_vms(self) -> List[Dict[str, Any]]:
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
