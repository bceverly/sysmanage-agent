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

import logging
import platform
from typing import Any, Dict

from src.i18n import _
from src.sysmanage_agent.operations.child_host_listing import ChildHostListing
from src.sysmanage_agent.operations.child_host_virtualization_checks import (
    VirtualizationChecks,
)
from src.sysmanage_agent.operations.child_host_wsl import WslOperations


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

            elif os_type == "linux":
                # Check Linux virtualization options
                lxd_info = self.virtualization_checks.check_lxd_support()
                if lxd_info["available"]:
                    supported_types.append("lxd")
                    capabilities["lxd"] = lxd_info

                kvm_info = self.virtualization_checks.check_kvm_support()
                if kvm_info["available"]:
                    supported_types.append("kvm")
                    capabilities["kvm"] = kvm_info

            elif os_type == "freebsd":
                # Check FreeBSD virtualization options
                bhyve_info = self.virtualization_checks.check_bhyve_support()
                if bhyve_info["available"]:
                    supported_types.append("bhyve")
                    capabilities["bhyve"] = bhyve_info

            elif os_type == "openbsd":
                # Check OpenBSD virtualization options
                vmm_info = self.virtualization_checks.check_vmm_support()
                if vmm_info["available"]:
                    supported_types.append("vmm")
                    capabilities["vmm"] = vmm_info

            # VirtualBox can be on any platform
            vbox_info = self.virtualization_checks.check_virtualbox_support()
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
                    wsl_instances = self.listing_helper.list_wsl_instances()
                    child_hosts.extend(wsl_instances)

                # Get Hyper-V VMs (if enabled)
                if not child_type_filter or child_type_filter == "hyperv":
                    hyperv_vms = self.listing_helper.list_hyperv_vms()
                    child_hosts.extend(hyperv_vms)

            elif os_type == "linux":
                # Get LXD containers
                if not child_type_filter or child_type_filter == "lxd":
                    lxd_containers = self.listing_helper.list_lxd_containers()
                    child_hosts.extend(lxd_containers)

                # Get KVM/QEMU VMs
                if not child_type_filter or child_type_filter == "kvm":
                    kvm_vms = self.listing_helper.list_kvm_vms()
                    child_hosts.extend(kvm_vms)

            # VirtualBox VMs (cross-platform)
            if not child_type_filter or child_type_filter == "virtualbox":
                vbox_vms = self.listing_helper.list_virtualbox_vms()
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
        password = parameters.get("password")
        server_url = parameters.get("server_url")
        agent_install_commands = parameters.get("agent_install_commands", [])

        self.logger.info(
            _("Creating child host: type=%s, distribution=%s, hostname=%s"),
            child_type,
            distribution,
            hostname,
        )

        if child_type == "wsl":
            return await self.wsl_ops.create_wsl_instance(
                distribution=distribution,
                hostname=hostname,
                username=username,
                password=password,
                server_url=server_url,
                agent_install_commands=agent_install_commands,
                listing_helper=self.listing_helper,
            )

        # Future: Add support for other child types
        return {
            "success": False,
            "error": _("Unsupported child host type: %s") % child_type,
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
