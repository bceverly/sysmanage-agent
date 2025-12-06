"""
VMM/vmd-specific child host operations for OpenBSD hosts.
"""

import subprocess  # nosec B404 # Required for system command execution
from typing import Any, Dict

from src.i18n import _


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

    async def initialize_vmd(self, _parameters: Dict[str, Any]) -> Dict[str, Any]:
        """
        Initialize VMM/vmd on OpenBSD: enable and start the vmd daemon.

        This is called when the user clicks "Enable VMM" in the UI.

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

            # Step 1: Enable vmd service using rcctl
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

            # Step 2: Start vmd service using rcctl
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

    async def start_child_host(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """
        Start a stopped VMM virtual machine.

        Args:
            parameters: Dict containing:
                - child_name: Name of the VM to start

        Returns:
            Dict with success status
        """
        child_name = parameters.get("child_name")
        if not child_name:
            return {
                "success": False,
                "error": _("VM name is required"),
            }

        self.logger.info(_("Starting VMM VM: %s"), child_name)

        try:
            # Start the VM using vmctl
            result = subprocess.run(  # nosec B603 B607
                ["vmctl", "start", child_name],
                capture_output=True,
                text=True,
                timeout=60,
                check=False,
            )

            if result.returncode == 0:
                self.logger.info(_("VM %s started successfully"), child_name)
                return {
                    "success": True,
                    "message": _("VM %s started") % child_name,
                }

            error_msg = result.stderr or result.stdout or "Unknown error"
            self.logger.error(_("Failed to start VM %s: %s"), child_name, error_msg)
            return {
                "success": False,
                "error": _("Failed to start VM: %s") % error_msg,
            }

        except subprocess.TimeoutExpired:
            return {
                "success": False,
                "error": _("Timeout starting VM %s") % child_name,
            }
        except Exception as error:
            return {
                "success": False,
                "error": _("Error starting VM: %s") % str(error),
            }

    async def stop_child_host(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """
        Stop a running VMM virtual machine.

        Args:
            parameters: Dict containing:
                - child_name: Name of the VM to stop
                - force: If True, force stop the VM

        Returns:
            Dict with success status
        """
        child_name = parameters.get("child_name")
        force = parameters.get("force", False)

        if not child_name:
            return {
                "success": False,
                "error": _("VM name is required"),
            }

        self.logger.info(_("Stopping VMM VM: %s (force=%s)"), child_name, force)

        try:
            # Build vmctl stop command
            cmd = ["vmctl", "stop"]
            if force:
                cmd.append("-f")
            cmd.append(child_name)

            result = subprocess.run(  # nosec B603 B607
                cmd,
                capture_output=True,
                text=True,
                timeout=120,  # Longer timeout for graceful shutdown
                check=False,
            )

            if result.returncode == 0:
                self.logger.info(_("VM %s stopped successfully"), child_name)
                return {
                    "success": True,
                    "message": _("VM %s stopped") % child_name,
                }

            error_msg = result.stderr or result.stdout or "Unknown error"
            self.logger.error(_("Failed to stop VM %s: %s"), child_name, error_msg)
            return {
                "success": False,
                "error": _("Failed to stop VM: %s") % error_msg,
            }

        except subprocess.TimeoutExpired:
            return {
                "success": False,
                "error": _("Timeout stopping VM %s") % child_name,
            }
        except Exception as error:
            return {
                "success": False,
                "error": _("Error stopping VM: %s") % str(error),
            }

    async def restart_child_host(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """
        Restart a VMM virtual machine.

        Args:
            parameters: Dict containing:
                - child_name: Name of the VM to restart

        Returns:
            Dict with success status
        """
        child_name = parameters.get("child_name")
        if not child_name:
            return {
                "success": False,
                "error": _("VM name is required"),
            }

        self.logger.info(_("Restarting VMM VM: %s"), child_name)

        # Stop the VM first
        stop_result = await self.stop_child_host(parameters)
        if not stop_result.get("success"):
            return stop_result

        # Then start it
        start_result = await self.start_child_host(parameters)
        if not start_result.get("success"):
            return start_result

        return {
            "success": True,
            "message": _("VM %s restarted") % child_name,
        }

    async def delete_child_host(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """
        Delete a VMM virtual machine.

        Args:
            parameters: Dict containing:
                - child_name: Name of the VM to delete
                - delete_disk: If True, also delete the disk image

        Returns:
            Dict with success status
        """
        child_name = parameters.get("child_name")
        if not child_name:
            return {
                "success": False,
                "error": _("VM name is required"),
            }

        self.logger.info(_("Deleting VMM VM: %s"), child_name)

        try:
            # First, try to stop the VM if it's running
            # Using force to ensure it stops
            stop_params = {"child_name": child_name, "force": True}
            await self.stop_child_host(stop_params)

            # Note: vmctl doesn't have a "delete" command
            # VMs defined in vm.conf need to be removed from the config file
            # For now, we just stop the VM - full deletion requires
            # removing from vm.conf and optionally deleting disk images
            # This will be enhanced in Phase 6

            self.logger.info(_("VM %s has been stopped"), child_name)
            return {
                "success": True,
                "message": _(
                    "VM %s has been stopped. "
                    "Manual cleanup of vm.conf and disk images may be required."
                )
                % child_name,
            }

        except Exception as error:
            return {
                "success": False,
                "error": _("Error deleting VM: %s") % str(error),
            }
