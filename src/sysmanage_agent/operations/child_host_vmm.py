"""
VMM/vmd-specific child host operations for OpenBSD hosts.
"""

import os
import subprocess  # nosec B404 # Required for system command execution
from pathlib import Path

from src.database.base import get_database_manager
from src.i18n import _
from src.sysmanage_agent.operations.child_host_types import VmmVmConfig
from src.sysmanage_agent.operations.child_host_vmm_github import GitHubVersionChecker
from src.sysmanage_agent.operations.child_host_vmm_httpd_autoinstall import (
    HttpdAutoinstallSetup,
)
from src.sysmanage_agent.operations.child_host_vmm_network_helpers import (
    select_unused_subnet,
)
from src.sysmanage_agent.operations.child_host_vmm_lifecycle import (
    VmmLifecycleOperations,
)
from src.sysmanage_agent.operations.child_host_vmm_site_builder import (
    SiteTarballBuilder,
)
from src.sysmanage_agent.operations.child_host_vmm_ssh import VmmSshOperations
from src.sysmanage_agent.operations.child_host_vmm_vm_creator import VmmVmCreator


class VmmOperations:
    """VMM/vmd-specific operations for child host management on OpenBSD."""

    def __init__(self, agent_instance, logger, virtualization_checks):
        """
        Initialize VMM operations.

        Args:
            agent_instance: Reference to the main SysManageAgent instance
            logger: Logger instance
            virtualization_checks: VirtualizationChecks instance
        """
        self.agent = agent_instance
        self.logger = logger
        self.virtualization_checks = virtualization_checks
        self.ssh_ops = VmmSshOperations(logger)
        self.lifecycle = VmmLifecycleOperations(logger, virtualization_checks)
        self.github_checker = GitHubVersionChecker(logger)
        self.site_builder = SiteTarballBuilder(
            logger, get_database_manager().get_session()
        )
        self.httpd_setup = HttpdAutoinstallSetup(logger)

        # Create VM creator with all dependencies
        self.vm_creator = VmmVmCreator(
            agent_instance=agent_instance,
            logger=logger,
            virtualization_checks=virtualization_checks,
            httpd_setup=self.httpd_setup,
            github_checker=self.github_checker,
            site_builder=self.site_builder,
        )

    async def initialize_vmd(self, _parameters: dict) -> dict:
        """
        Initialize VMM/vmd on OpenBSD: enable and start the vmd daemon.

        This is called when the user clicks "Enable VMM" in the UI.

        Creates persistent configuration:
        - /etc/hostname.bridge0 for bridge interface persistence across reboots
        - /etc/vm.conf with local switch configuration for vmd

        Returns:
            Dict with success status and any required actions (like reboot)
        """
        try:
            self.logger.info(_("Initializing VMM/vmd"))

            # Check current VMM status
            vmm_check = self.virtualization_checks.check_vmm_support()

            if not vmm_check.get("available"):
                return {
                    "success": False,
                    "error": _(
                        "VMM is not available on this system (requires OpenBSD)"
                    ),
                }

            # Check if kernel supports VMM
            if not vmm_check.get("kernel_supported"):
                return {
                    "success": False,
                    "error": _(
                        "VMM kernel support is not enabled. "
                        "Ensure your CPU supports hardware virtualization (VMX/SVM) "
                        "and the kernel has VMM support compiled in."
                    ),
                    "needs_reboot": True,
                }

            # If already running, nothing to do
            if vmm_check.get("running"):
                self.logger.info(_("vmd is already running"))
                return {
                    "success": True,
                    "message": _("VMM/vmd is already enabled and running"),
                    "already_enabled": True,
                }

            # Step 1: Select subnet for VM network
            self.logger.info(_("Selecting subnet for VM network"))
            subnet_info = select_unused_subnet(self.logger)
            gateway_ip = subnet_info["gateway_ip"]
            self.logger.info(_("Using gateway IP: %s"), gateway_ip)

            # Step 2: Create /etc/hostname.vether0 for persistence
            self.logger.info(_("Creating /etc/hostname.vether0 for gateway"))
            try:
                with open(
                    "/etc/hostname.vether0", "w", encoding="utf-8"
                ) as vether_file:
                    vether_file.write(f"inet {gateway_ip} 255.255.255.0\n")
                os.chmod("/etc/hostname.vether0", 0o640)
                self.logger.info(_("Created /etc/hostname.vether0"))
            except Exception as vether_error:
                self.logger.error(
                    _("Failed to create /etc/hostname.vether0: %s"), vether_error
                )
                return {
                    "success": False,
                    "error": _("Failed to create /etc/hostname.vether0: %s")
                    % str(vether_error),
                }

            # Step 3: Create /etc/hostname.bridge0 with vether0 added
            self.logger.info(_("Creating /etc/hostname.bridge0 for persistence"))
            try:
                with open(
                    "/etc/hostname.bridge0", "w", encoding="utf-8"
                ) as bridge_file:
                    bridge_file.write("up\nadd vether0\n")
                os.chmod("/etc/hostname.bridge0", 0o640)
                self.logger.info(_("Created /etc/hostname.bridge0"))
            except Exception as bridge_file_error:
                self.logger.error(
                    _("Failed to create /etc/hostname.bridge0: %s"), bridge_file_error
                )
                return {
                    "success": False,
                    "error": _("Failed to create /etc/hostname.bridge0: %s")
                    % str(bridge_file_error),
                }

            # Step 4: Enable IP forwarding persistently
            self.logger.info(_("Enabling IP forwarding"))
            try:
                sysctl_conf = Path("/etc/sysctl.conf")
                sysctl_content = ""
                if sysctl_conf.exists():
                    sysctl_content = sysctl_conf.read_text(encoding="utf-8")
                if "net.inet.ip.forwarding=1" not in sysctl_content:
                    with open(sysctl_conf, "a", encoding="utf-8") as sysctl_file:
                        sysctl_file.write("net.inet.ip.forwarding=1\n")
                    self.logger.info(_("Added IP forwarding to /etc/sysctl.conf"))

                # Enable immediately
                subprocess.run(  # nosec B603 B607
                    ["sysctl", "net.inet.ip.forwarding=1"],
                    capture_output=True,
                    timeout=10,
                    check=False,
                )
            except Exception as sysctl_error:
                self.logger.warning(
                    _("Failed to configure IP forwarding: %s"), sysctl_error
                )

            # Step 5: Create vether0 interface now
            self.logger.info(_("Creating vether0 interface"))
            subprocess.run(  # nosec B603 B607
                ["ifconfig", "vether0", "create"],
                capture_output=True,
                timeout=10,
                check=False,
            )
            subprocess.run(  # nosec B603 B607
                ["sh", "/etc/netstart", "vether0"],
                capture_output=True,
                timeout=30,
                check=False,
            )

            # Step 6: Create bridge0 interface
            self.logger.info(_("Creating bridge0 interface"))
            bridge_result = subprocess.run(  # nosec B603 B607
                ["sh", "/etc/netstart", "bridge0"],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )

            if bridge_result.returncode != 0:
                self.logger.warning(
                    _("netstart bridge0 returned non-zero (may already exist): %s"),
                    bridge_result.stderr or bridge_result.stdout,
                )

            # Step 7: Ensure vether0 is added to bridge0
            subprocess.run(  # nosec B603 B607
                ["ifconfig", "bridge0", "add", "vether0"],
                capture_output=True,
                timeout=10,
                check=False,
            )

            # Step 8: Create /etc/vm.conf with local switch configuration
            self.logger.info(_("Creating /etc/vm.conf"))
            vm_conf_content = """# SysManage vmd config for autoinstall
switch "local" {
    interface bridge0
}
"""
            try:
                with open("/etc/vm.conf", "w", encoding="utf-8") as vm_conf_file:
                    vm_conf_file.write(vm_conf_content)
                self.logger.info(_("Created /etc/vm.conf"))
            except Exception as vm_conf_error:
                self.logger.error(_("Failed to create /etc/vm.conf: %s"), vm_conf_error)
                return {
                    "success": False,
                    "error": _("Failed to create /etc/vm.conf: %s")
                    % str(vm_conf_error),
                }

            # Step 9: Enable vmd service using rcctl
            if not vmm_check.get("enabled"):
                self.logger.info(_("Enabling vmd service"))
                enable_result = subprocess.run(  # nosec B603 B607
                    ["rcctl", "enable", "vmd"],
                    capture_output=True,
                    text=True,
                    timeout=30,
                    check=False,
                )

                if enable_result.returncode != 0:
                    error_msg = (
                        enable_result.stderr or enable_result.stdout or "Unknown error"
                    )
                    self.logger.error(_("Failed to enable vmd: %s"), error_msg)
                    return {
                        "success": False,
                        "error": _("Failed to enable vmd service: %s") % error_msg,
                    }

                self.logger.info(_("vmd service enabled"))

            # Step 10: Start vmd service using rcctl
            self.logger.info(_("Starting vmd service"))
            start_result = subprocess.run(  # nosec B603 B607
                ["rcctl", "start", "vmd"],
                capture_output=True,
                text=True,
                timeout=60,
                check=False,
            )

            if start_result.returncode != 0:
                error_msg = (
                    start_result.stderr or start_result.stdout or "Unknown error"
                )
                self.logger.error(_("Failed to start vmd: %s"), error_msg)
                return {
                    "success": False,
                    "error": _("Failed to start vmd service: %s") % error_msg,
                }

            self.logger.info(_("vmd service started"))

            # Verify vmd is now running
            verify_result = self.virtualization_checks.check_vmm_support()

            if verify_result.get("running"):
                self.logger.info(_("VMM/vmd is ready for use"))
                return {
                    "success": True,
                    "message": _("VMM/vmd has been enabled and started"),
                    "needs_reboot": False,
                }

            return {
                "success": False,
                "error": _("vmd was started but verification failed"),
            }

        except subprocess.TimeoutExpired:
            self.logger.error(_("Timeout while initializing vmd"))
            return {
                "success": False,
                "error": _("Timeout while initializing vmd service"),
            }
        except Exception as error:
            self.logger.error(_("Error initializing vmd: %s"), error)
            return {
                "success": False,
                "error": _("Error initializing vmd: %s") % str(error),
            }

    async def check_vmd_ready(self) -> dict:
        """
        Check if vmd is operational and ready to create VMs.

        Returns:
            Dict with success status and vmd status info
        """
        return await self.lifecycle.check_vmd_ready()

    async def get_vm_status(self, vm_name: str) -> dict:
        """
        Get the status of a specific VM.

        Args:
            vm_name: Name of the VM to check

        Returns:
            Dict with VM status info including running state, memory, CPUs
        """
        return await self.lifecycle.get_vm_status(vm_name)

    async def start_child_host(self, parameters: dict) -> dict:
        """
        Start a stopped VMM virtual machine.

        Args:
            parameters: Dict containing child_name and optional wait flag

        Returns:
            Dict with success status
        """
        child_name = parameters.get("child_name")
        wait = parameters.get("wait", True)
        if not child_name:
            return {
                "success": False,
                "error": _("VM name is required"),
            }

        return await self.lifecycle.start_vm(child_name, wait=wait)

    async def stop_child_host(self, parameters: dict) -> dict:
        """
        Stop a running VMM virtual machine.

        Args:
            parameters: Dict containing child_name, force flag, and wait flag

        Returns:
            Dict with success status
        """
        child_name = parameters.get("child_name")
        force = parameters.get("force", False)
        wait = parameters.get("wait", True)

        if not child_name:
            return {
                "success": False,
                "error": _("VM name is required"),
            }

        return await self.lifecycle.stop_vm(child_name, force=force, wait=wait)

    async def restart_child_host(self, parameters: dict) -> dict:
        """
        Restart a VMM virtual machine.

        Args:
            parameters: Dict containing child_name

        Returns:
            Dict with success status
        """
        child_name = parameters.get("child_name")
        if not child_name:
            return {
                "success": False,
                "error": _("VM name is required"),
            }

        return await self.lifecycle.restart_vm(child_name)

    async def delete_child_host(self, parameters: dict) -> dict:
        """
        Delete a VMM virtual machine.

        Args:
            parameters: Dict containing child_name and delete_disk flag

        Returns:
            Dict with success status
        """
        child_name = parameters.get("child_name")
        delete_disk = parameters.get("delete_disk", True)
        if not child_name:
            return {
                "success": False,
                "error": _("VM name is required"),
            }

        return await self.lifecycle.delete_vm(child_name, delete_disk=delete_disk)

    async def create_vmm_vm(self, config: VmmVmConfig) -> dict:
        """
        Create a new VMM virtual machine with HTTP-based autoinstall.

        Delegates to VmmVmCreator for the full creation workflow.

        Args:
            config: VmmVmConfig with all VM settings

        Returns:
            Dict with success status and details
        """
        return await self.vm_creator.create_vmm_vm(config)
