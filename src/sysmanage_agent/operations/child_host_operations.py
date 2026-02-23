"""
Child Host Operations for SysManage Agent.

This module provides functionality for managing virtual machines, containers,
and WSL instances as "child hosts" of the parent system.

Supported child host types:
- WSL v2 (Windows Subsystem for Linux)
- LXD/LXC containers (Ubuntu 22.04+)
- VirtualBox VMs (future)
- Hyper-V VMs (future)
- VMM/vmd (OpenBSD, future)
- bhyve (FreeBSD, future)
- KVM/QEMU (Linux, future)
"""

from __future__ import annotations

import json
import logging
import platform
from typing import Any, Dict

from src.sysmanage_agent.operations.child_host_types import (
    VmmResourceConfig,
    VmmServerConfig,
    VmmVmConfig,
)
from src.sysmanage_agent.operations.child_host_kvm_types import KvmVmConfig
from src.sysmanage_agent.operations.child_host_bhyve_types import BhyveVmConfig

from src.i18n import _

# Module-level constants for repeated error messages
_UNSUPPORTED_CHILD_TYPE = _("Unsupported child host type: %s")

# pylint: disable=wrong-import-position
# These imports are placed after constants to avoid circular imports
from src.sysmanage_agent.operations.child_host_listing import ChildHostListing
from src.sysmanage_agent.operations.child_host_virtualization_checks import (
    VirtualizationChecks,
)
from src.sysmanage_agent.operations.child_host_wsl import WslOperations

# Unix-only child host backends (KVM, LXD, VMM, bhyve use Unix-only modules)
if platform.system() != "Windows":
    from src.sysmanage_agent.operations.child_host_kvm import KvmOperations
    from src.sysmanage_agent.operations.child_host_lxd import LxdOperations
    from src.sysmanage_agent.operations.child_host_vmm import VmmOperations
    from src.sysmanage_agent.operations.child_host_bhyve import BhyveOperations
else:
    KvmOperations = None  # type: ignore[misc,assignment]  # pylint: disable=invalid-name
    LxdOperations = None  # type: ignore[misc,assignment]  # pylint: disable=invalid-name
    VmmOperations = None  # type: ignore[misc,assignment]  # pylint: disable=invalid-name
    BhyveOperations = None  # type: ignore[misc,assignment]  # pylint: disable=invalid-name

# pylint: enable=wrong-import-position


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

        # Initialize helper modules
        self.virtualization_checks = VirtualizationChecks(self.logger)
        self.listing_helper = ChildHostListing(self.logger)
        self.wsl_ops = WslOperations(
            self.agent, self.logger, self.virtualization_checks
        )
        # Unix-only backends - only initialize on non-Windows platforms
        if platform.system() != "Windows":
            self.lxd_ops = LxdOperations(
                self.agent, self.logger, self.virtualization_checks
            )
            self.vmm_ops = VmmOperations(
                self.agent, self.logger, self.virtualization_checks
            )
            self.kvm_ops = KvmOperations(
                self.agent, self.logger, self.virtualization_checks
            )
            self.bhyve_ops = BhyveOperations(
                self.agent, self.logger, self.virtualization_checks
            )
        else:
            self.lxd_ops = None
            self.vmm_ops = None
            self.kvm_ops = None
            self.bhyve_ops = None

    async def check_virtualization_support(  # NOSONAR - async required by interface
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

            # Check platform-specific virtualization
            reboot_required = self._check_platform_virtualization(
                os_type, supported_types, capabilities
            )

            # VirtualBox can be on any platform
            self._check_virtualbox(supported_types, capabilities)

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

    def _check_platform_virtualization(
        self, os_type: str, supported_types: list, capabilities: dict
    ) -> bool:
        """Check platform-specific virtualization support."""
        reboot_required = False

        if os_type == "windows":
            reboot_required = self._check_windows_virtualization(
                supported_types, capabilities
            )
        elif os_type == "linux":
            self._check_linux_virtualization(supported_types, capabilities)
        elif os_type == "freebsd":
            self._check_freebsd_virtualization(supported_types, capabilities)
        elif os_type == "openbsd":
            self._check_openbsd_virtualization(supported_types, capabilities)

        return reboot_required

    def _check_windows_virtualization(
        self, supported_types: list, capabilities: dict
    ) -> bool:
        """Check Windows virtualization options (WSL, Hyper-V)."""
        reboot_required = False

        wsl_info = self.virtualization_checks.check_wsl_support()
        if wsl_info["available"]:
            supported_types.append("wsl")
            capabilities["wsl"] = wsl_info
            if wsl_info.get("needs_enable"):
                reboot_required = True

        hyperv_info = self.virtualization_checks.check_hyperv_support()
        if hyperv_info["available"]:
            supported_types.append("hyperv")
            capabilities["hyperv"] = hyperv_info

        return reboot_required

    def _check_linux_virtualization(
        self, supported_types: list, capabilities: dict
    ) -> None:
        """Check Linux virtualization options (LXD, KVM)."""
        lxd_info = self.virtualization_checks.check_lxd_support()
        if lxd_info["available"]:
            supported_types.append("lxd")
            capabilities["lxd"] = lxd_info

        kvm_info = self.virtualization_checks.check_kvm_support()
        if kvm_info["available"]:
            supported_types.append("kvm")
            capabilities["kvm"] = kvm_info

    def _check_freebsd_virtualization(
        self, supported_types: list, capabilities: dict
    ) -> None:
        """Check FreeBSD virtualization options (bhyve)."""
        bhyve_info = self.virtualization_checks.check_bhyve_support()
        if bhyve_info["available"]:
            supported_types.append("bhyve")
            capabilities["bhyve"] = bhyve_info

    def _check_openbsd_virtualization(
        self, supported_types: list, capabilities: dict
    ) -> None:
        """Check OpenBSD virtualization options (VMM/vmd)."""
        vmm_info = self.virtualization_checks.check_vmm_support()
        if vmm_info["available"]:
            supported_types.append("vmm")
            capabilities["vmm"] = vmm_info

    def _check_virtualbox(self, supported_types: list, capabilities: dict) -> None:
        """Check VirtualBox support (cross-platform)."""
        vbox_info = self.virtualization_checks.check_virtualbox_support()
        if vbox_info["available"]:
            supported_types.append("virtualbox")
            capabilities["virtualbox"] = vbox_info

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
            os_type = platform.system().lower()

            # Collect child hosts from platform-specific sources
            child_hosts = self._collect_platform_child_hosts(os_type, child_type_filter)

            # VirtualBox VMs (cross-platform)
            self._collect_virtualbox_vms(child_hosts, child_type_filter)

            # Send proactive update to server
            await self._send_child_hosts_update()

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

    def _collect_platform_child_hosts(
        self, os_type: str, child_type_filter: str | None
    ) -> list:
        """Collect child hosts based on platform."""
        child_hosts = []

        if os_type == "windows":
            self._collect_windows_child_hosts(child_hosts, child_type_filter)
        elif os_type == "linux":
            self._collect_linux_child_hosts(child_hosts, child_type_filter)
        elif os_type == "openbsd":
            self._collect_openbsd_child_hosts(child_hosts, child_type_filter)
        elif os_type == "freebsd":
            self._collect_freebsd_child_hosts(child_hosts, child_type_filter)

        return child_hosts

    def _collect_windows_child_hosts(
        self, child_hosts: list, child_type_filter: str | None
    ) -> None:
        """Collect Windows child hosts (WSL, Hyper-V)."""
        if not child_type_filter or child_type_filter == "wsl":
            child_hosts.extend(self.listing_helper.list_wsl_instances())
        if not child_type_filter or child_type_filter == "hyperv":
            child_hosts.extend(self.listing_helper.list_hyperv_vms())

    def _collect_linux_child_hosts(
        self, child_hosts: list, child_type_filter: str | None
    ) -> None:
        """Collect Linux child hosts (LXD, KVM)."""
        if not child_type_filter or child_type_filter == "lxd":
            child_hosts.extend(self.listing_helper.list_lxd_containers())
        if not child_type_filter or child_type_filter == "kvm":
            child_hosts.extend(self.listing_helper.list_kvm_vms())

    def _collect_openbsd_child_hosts(
        self, child_hosts: list, child_type_filter: str | None
    ) -> None:
        """Collect OpenBSD child hosts (VMM)."""
        if not child_type_filter or child_type_filter == "vmm":
            child_hosts.extend(self.listing_helper.list_vmm_vms())

    def _collect_freebsd_child_hosts(
        self, child_hosts: list, child_type_filter: str | None
    ) -> None:
        """Collect FreeBSD child hosts (bhyve)."""
        if not child_type_filter or child_type_filter == "bhyve":
            child_hosts.extend(self.listing_helper.list_bhyve_vms())

    def _collect_virtualbox_vms(
        self, child_hosts: list, child_type_filter: str | None
    ) -> None:
        """Collect VirtualBox VMs (cross-platform)."""
        if not child_type_filter or child_type_filter == "virtualbox":
            child_hosts.extend(self.listing_helper.list_virtualbox_vms())

    async def _send_child_hosts_update(self) -> None:
        """Send proactive child host list update to server."""
        try:
            if hasattr(self.agent, "child_host_collector"):
                await self.agent.child_host_collector.send_child_hosts_update()
                self.logger.info(_("Sent child host list update to server"))
        except Exception as error:
            self.logger.warning(_("Failed to send child host list update: %s"), error)

    async def create_child_host(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """
        Create a new child host (WSL instance, container, or VM).

        Args:
            parameters: Creation parameters including:
                - child_type: Type of child host ('wsl', 'lxd', etc.)
                - distribution: Distribution identifier (e.g., 'Ubuntu-24.04')
                - hostname: Hostname for the child host
                - username: Non-root username to create
                - password: Password for the user
                - install_path: Optional custom install location
                - server_url: URL for the sysmanage server
                - server_port: Port for the sysmanage server
                - use_https: Whether to use HTTPS for server connection
                - agent_install_commands: JSON array of commands to install agent

        Returns:
            Dict containing:
            - success: bool
            - child_name: Name of created child host
            - error: Error message if failed
        """
        child_type = parameters.get("child_type", "wsl")
        distribution = parameters.get("distribution")
        hostname = parameters.get("hostname")
        username = parameters.get("username")
        # Accept pre-hashed password from server (security: no clear text in transit)
        password_hash = parameters.get("password_hash")
        server_url = parameters.get("server_url")
        server_port = parameters.get("server_port", 8443)
        use_https = parameters.get("use_https", True)
        agent_install_commands = parameters.get("agent_install_commands", [])
        # Auto-approve token for automatic host approval when child connects
        auto_approve_token = parameters.get("auto_approve_token")

        # Handle agent_install_commands as JSON string (backward compatibility)
        if isinstance(agent_install_commands, str):
            try:
                agent_install_commands = json.loads(agent_install_commands)
            except json.JSONDecodeError:
                agent_install_commands = []

        self.logger.info(
            _("Creating child host: type=%s, distribution=%s, hostname=%s"),
            child_type,
            distribution,
            hostname,
        )

        if child_type == "vmm":
            # For VMM, vm_name comes from hostname or explicit parameter
            vm_name = parameters.get("vm_name") or hostname.split(".")[0]
            iso_url = parameters.get("iso_url", "")
            # VMM has separate root password (falls back to user password if not provided)
            root_password_hash = parameters.get("root_password_hash", password_hash)

            # Create sub-configs for server and resource settings
            server_cfg = VmmServerConfig(
                server_url=server_url,
                server_port=server_port,
                use_https=use_https,
            )
            resource_cfg = VmmResourceConfig(
                memory=parameters.get("memory", "1G"),
                disk_size=parameters.get("disk_size", "20G"),
                cpus=parameters.get("cpus", 1),
            )

            config = VmmVmConfig(
                distribution=distribution,
                vm_name=vm_name,
                hostname=hostname,
                username=username,
                password_hash=password_hash,
                agent_install_commands=agent_install_commands,
                iso_url=iso_url,
                root_password_hash=root_password_hash,
                server_config=server_cfg,
                resource_config=resource_cfg,
                auto_approve_token=auto_approve_token,
            )
            return await self.vmm_ops.create_vmm_vm(config)

        if child_type == "kvm":
            # For KVM, vm_name comes from hostname or explicit parameter
            vm_name = parameters.get("vm_name") or hostname.split(".")[0]
            cloud_image_url = parameters.get("cloud_image_url", "")

            config = KvmVmConfig(
                distribution=distribution,
                vm_name=vm_name,
                hostname=hostname,
                username=username,
                password_hash=password_hash,
                server_url=server_url,
                agent_install_commands=agent_install_commands,
                server_port=server_port,
                use_https=use_https,
                cloud_image_url=cloud_image_url,
                memory=parameters.get("memory", "2G"),
                disk_size=parameters.get("disk_size", "20G"),
                cpus=parameters.get("cpus", 2),
                auto_approve_token=auto_approve_token,
            )
            return await self.kvm_ops.create_vm(config)

        if child_type == "bhyve":
            # For bhyve, vm_name comes from hostname or explicit parameter
            vm_name = parameters.get("vm_name") or hostname.split(".")[0]
            cloud_image_url = parameters.get("cloud_image_url", "")

            config = BhyveVmConfig(
                distribution=distribution,
                vm_name=vm_name,
                hostname=hostname,
                username=username,
                password_hash=password_hash,
                server_url=server_url,
                agent_install_commands=agent_install_commands,
                server_port=server_port,
                use_https=use_https,
                cloud_image_url=cloud_image_url,
                memory=parameters.get("memory", "1G"),
                disk_size=parameters.get("disk_size", "20G"),
                cpus=parameters.get("cpus", 1),
                auto_approve_token=auto_approve_token,
            )
            return await self.bhyve_ops.create_bhyve_vm(config)

        return {
            "success": False,
            "error": _UNSUPPORTED_CHILD_TYPE % child_type,
        }

    async def enable_wsl(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """
        Enable WSL on a Windows system.

        This is called when the user clicks "Enable WSL" in the UI.

        Args:
            parameters: Optional parameters (unused)

        Returns:
            Dict with success status and whether reboot is required
        """
        return await self.wsl_ops.enable_wsl(parameters)

    async def initialize_lxd(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """
        Initialize LXD on an Ubuntu system.

        This is called when the user clicks "Enable LXD" in the UI.
        It installs LXD via snap if not installed, and runs lxd init --auto.

        Args:
            parameters: Optional parameters (unused)

        Returns:
            Dict with success status and whether user needs to re-login
        """
        self.logger.info(_("Initializing LXD"))
        return await self.lxd_ops.initialize_lxd(parameters)

    async def initialize_vmm(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """
        Initialize VMM/vmd on an OpenBSD system.

        This is called when the user clicks "Enable VMM" in the UI.
        It enables and starts the vmd daemon.

        Args:
            parameters: Optional parameters (unused)

        Returns:
            Dict with success status and whether reboot is required
        """
        self.logger.info(_("Initializing VMM/vmd"))
        return await self.vmm_ops.initialize_vmd(parameters)

    async def initialize_kvm(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """
        Initialize KVM/libvirt on a Linux system.

        This is called when the user clicks "Enable KVM" in the UI.
        It installs libvirt packages, enables and starts libvirtd,
        and configures the default network.

        Args:
            parameters: Optional parameters (unused)

        Returns:
            Dict with success status
        """
        self.logger.info(_("Initializing KVM/libvirt"))
        return await self.kvm_ops.initialize_kvm(parameters)

    async def initialize_bhyve(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """
        Initialize bhyve on a FreeBSD system.

        This is called when the user clicks "Enable bhyve" in the UI.
        It loads vmm.ko and configures /boot/loader.conf for persistence.

        Args:
            parameters: Optional parameters (unused)

        Returns:
            Dict with success status
        """
        self.logger.info(_("Initializing bhyve"))
        return await self.bhyve_ops.initialize_bhyve(parameters)

    async def disable_bhyve(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """
        Disable bhyve on a FreeBSD system.

        This is called when the user clicks "Disable bhyve" in the UI.
        It unloads vmm.ko and removes the configuration from /boot/loader.conf.
        Note: This will fail if any VMs are running.

        Args:
            parameters: Optional parameters (unused)

        Returns:
            Dict with success status
        """
        self.logger.info(_("Disabling bhyve"))
        return await self.bhyve_ops.disable_bhyve(parameters)

    async def enable_kvm_modules(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """
        Enable KVM by loading kernel modules via modprobe.

        This is called when the user clicks "Enable KVM Modules" in the UI.
        It loads the kvm and kvm_intel/kvm_amd kernel modules.

        Args:
            parameters: Optional parameters (unused)

        Returns:
            Dict with success status
        """
        self.logger.info(_("Enabling KVM kernel modules"))
        return await self.kvm_ops.enable_kvm_modules(parameters)

    async def disable_kvm_modules(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """
        Disable KVM by unloading kernel modules via modprobe -r.

        This is called when the user clicks "Disable KVM Modules" in the UI.
        It unloads the kvm and kvm_intel/kvm_amd kernel modules.
        Note: This will fail if any VMs are running.

        Args:
            parameters: Optional parameters (unused)

        Returns:
            Dict with success status
        """
        self.logger.info(_("Disabling KVM kernel modules"))
        return await self.kvm_ops.disable_kvm_modules(parameters)

    async def setup_kvm_networking(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """
        Configure KVM networking based on the specified mode.

        Args:
            parameters: Dict with:
                - mode: 'nat' (default) or 'bridged'
                - network_name: Name for the network (default: 'default' for NAT)
                - bridge: Linux bridge interface name (required for bridged mode)

        Returns:
            Dict with success status and network details
        """
        self.logger.info(_("Setting up KVM networking"))
        return await self.kvm_ops.setup_kvm_networking(parameters)

    async def list_kvm_networks(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """
        List all configured KVM/libvirt networks.

        Returns:
            Dict with success status and list of networks
        """
        self.logger.info(_("Listing KVM networks"))
        return await self.kvm_ops.list_kvm_networks(parameters)

    async def start_child_host(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """
        Start a stopped child host.

        Args:
            parameters: Dict containing:
                - child_type: Type of child host ('wsl', 'lxd', etc.)
                - child_name: Name of the child host to start

        Returns:
            Dict with success status
        """
        child_type = parameters.get("child_type", "wsl")

        self.logger.info(
            _("Starting child host: type=%s, name=%s"),
            child_type,
            parameters.get("child_name"),
        )

        if child_type == "wsl":
            return await self.wsl_ops.start_child_host(parameters)

        if child_type == "lxd":
            return await self.lxd_ops.start_child_host(parameters)

        if child_type == "vmm":
            return await self.vmm_ops.start_child_host(parameters)

        if child_type == "kvm":
            return await self.kvm_ops.start_child_host(parameters)

        if child_type == "bhyve":
            return await self.bhyve_ops.start_child_host(parameters)

        return {
            "success": False,
            "error": _UNSUPPORTED_CHILD_TYPE % child_type,
        }

    async def stop_child_host(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """
        Stop a running child host.

        Args:
            parameters: Dict containing:
                - child_type: Type of child host ('wsl', 'lxd', etc.)
                - child_name: Name of the child host to stop

        Returns:
            Dict with success status
        """
        child_type = parameters.get("child_type", "wsl")

        self.logger.info(
            _("Stopping child host: type=%s, name=%s"),
            child_type,
            parameters.get("child_name"),
        )

        if child_type == "wsl":
            return await self.wsl_ops.stop_child_host(parameters)

        if child_type == "lxd":
            return await self.lxd_ops.stop_child_host(parameters)

        if child_type == "vmm":
            return await self.vmm_ops.stop_child_host(parameters)

        if child_type == "kvm":
            return await self.kvm_ops.stop_child_host(parameters)

        if child_type == "bhyve":
            return await self.bhyve_ops.stop_child_host(parameters)

        return {
            "success": False,
            "error": _UNSUPPORTED_CHILD_TYPE % child_type,
        }

    async def restart_child_host(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """
        Restart a child host.

        Args:
            parameters: Dict containing:
                - child_type: Type of child host ('wsl', 'lxd', etc.)
                - child_name: Name of the child host to restart

        Returns:
            Dict with success status
        """
        child_type = parameters.get("child_type", "wsl")

        self.logger.info(
            _("Restarting child host: type=%s, name=%s"),
            child_type,
            parameters.get("child_name"),
        )

        if child_type == "wsl":
            return await self.wsl_ops.restart_child_host(parameters)

        if child_type == "lxd":
            return await self.lxd_ops.restart_child_host(parameters)

        if child_type == "vmm":
            return await self.vmm_ops.restart_child_host(parameters)

        if child_type == "kvm":
            return await self.kvm_ops.restart_child_host(parameters)

        if child_type == "bhyve":
            return await self.bhyve_ops.restart_child_host(parameters)

        return {
            "success": False,
            "error": _UNSUPPORTED_CHILD_TYPE % child_type,
        }

    async def delete_child_host(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """
        Delete a child host. This permanently removes the child host and all its data.

        Args:
            parameters: Dict containing:
                - child_type: Type of child host ('wsl', 'lxd', etc.)
                - child_name: Name of the child host to delete

        Returns:
            Dict with success status
        """
        child_type = parameters.get("child_type", "wsl")

        self.logger.info(
            _("Deleting child host: type=%s, name=%s"),
            child_type,
            parameters.get("child_name"),
        )

        result = None
        if child_type == "wsl":
            result = await self.wsl_ops.delete_child_host(parameters)
        elif child_type == "lxd":
            result = await self.lxd_ops.delete_child_host(parameters)
        elif child_type == "vmm":
            result = await self.vmm_ops.delete_child_host(parameters)
        elif child_type == "kvm":
            result = await self.kvm_ops.delete_child_host(parameters)
        elif child_type == "bhyve":
            result = await self.bhyve_ops.delete_child_host(parameters)
        else:
            return {
                "success": False,
                "error": _UNSUPPORTED_CHILD_TYPE % child_type,
            }

        # Send updated child host list to server after successful delete
        if result and result.get("success"):
            try:
                if hasattr(self.agent, "child_host_collector"):
                    await self.agent.child_host_collector.send_child_hosts_update()
                    self.logger.info(_("Sent updated child host list after delete"))
            except Exception as error:
                self.logger.warning(
                    _("Failed to send child host list update: %s"), error
                )

        return result
