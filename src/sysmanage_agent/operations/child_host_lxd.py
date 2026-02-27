"""
LXD-specific child host operations for Ubuntu hosts.
"""

import asyncio
import os
import pwd
from typing import Any, Dict, Optional

from src.i18n import _
from src.sysmanage_agent.core.agent_utils import run_command_async

# Module-level constants for repeated error messages
_CONTAINER_NAME_REQUIRED = _("Container name is required")


class LxdOperations:
    """LXD-specific operations for child host management on Ubuntu."""

    def __init__(self, agent_instance, logger, virtualization_checks):
        """
        Initialize LXD operations.

        Args:
            agent_instance: Reference to the main SysManageAgent instance
            logger: Logger instance
            virtualization_checks: VirtualizationChecks instance
        """
        self.agent = agent_instance
        self.logger = logger
        self.virtualization_checks = virtualization_checks

    async def initialize_lxd(self, _parameters: dict) -> dict:
        """Initialize LXD on Ubuntu: install via snap, run lxd init, configure firewall."""
        try:
            self.logger.info(_("Initializing LXD"))

            # Check current LXD status
            lxd_check = self.virtualization_checks.check_lxd_support()

            if not lxd_check.get("available"):
                return {
                    "success": False,
                    "error": _(
                        "LXD is not available on this system (requires Ubuntu 22.04+)"
                    ),
                }

            # Step 1: Install LXD via snap if not installed
            install_result = await self._ensure_lxd_installed(lxd_check)
            if install_result and not install_result.get("success"):
                return install_result

            # Step 2: Add current user to lxd group if not already
            await self._ensure_user_in_lxd_group(lxd_check)

            # Step 3: Initialize LXD if not already initialized
            init_result = await self._ensure_lxd_initialized(lxd_check)
            if init_result and not init_result.get("success"):
                return init_result

            # Step 4: Configure default profile for container compatibility
            await self._configure_default_profile()

            # Step 5: Configure firewall for LXD networking
            firewall_result = self._configure_lxd_firewall()
            if not firewall_result.get("success"):
                self.logger.warning(
                    "Firewall configuration issue: %s", firewall_result.get("error")
                )
                # Continue anyway - containers may still work or user can fix manually

            # Verify LXD is now working
            return self._verify_lxd_ready(lxd_check, firewall_result)

        except asyncio.TimeoutError:
            self.logger.error(_("LXD initialization timed out"))
            return {
                "success": False,
                "error": _("LXD initialization timed out"),
            }
        except Exception as error:
            self.logger.error(_("Error initializing LXD: %s"), error)
            return {
                "success": False,
                "error": str(error),
            }

    async def _ensure_lxd_installed(self, lxd_check: dict) -> Optional[Dict[str, Any]]:
        """Install LXD via snap if not already installed."""
        if lxd_check.get("installed"):
            return None

        if not lxd_check.get("snap_available"):
            return {
                "success": False,
                "error": _("Snap is not available to install LXD"),
            }

        self.logger.info(_("Installing LXD via snap"))
        install_result = await run_command_async(
            ["sudo", "snap", "install", "lxd"],
            timeout=300,  # 5 minutes for download/install
        )

        if install_result.returncode != 0:
            error_msg = (
                install_result.stderr or install_result.stdout or "Unknown error"
            )
            self.logger.error(_("Failed to install LXD: %s"), error_msg)
            return {
                "success": False,
                "error": _("Failed to install LXD: %s") % error_msg,
            }

        self.logger.info(_("LXD installed successfully"))
        return None

    async def _ensure_user_in_lxd_group(self, lxd_check: dict) -> None:
        """Add current user to lxd group if not already a member."""
        if lxd_check.get("user_in_group"):
            return

        self.logger.info(_("Adding current user to lxd group"))
        username = pwd.getpwuid(os.getuid()).pw_name

        usermod_result = await run_command_async(
            ["sudo", "usermod", "-aG", "lxd", username],
            timeout=30,
        )

        if usermod_result.returncode != 0:
            self.logger.warning(
                _("Could not add user to lxd group: %s"),
                usermod_result.stderr or usermod_result.stdout,
            )
            # Continue anyway - the user may need to log out/in

    async def _ensure_lxd_initialized(
        self, lxd_check: dict
    ) -> Optional[Dict[str, Any]]:
        """Initialize LXD if not already initialized."""
        if lxd_check.get("initialized"):
            return None

        self.logger.info(_("Initializing LXD with default settings"))
        init_result = await run_command_async(
            ["sudo", "lxd", "init", "--auto"],
            timeout=120,  # 2 minutes for init
        )

        if init_result.returncode != 0:
            error_msg = init_result.stderr or init_result.stdout or "Unknown error"
            self.logger.error(_("Failed to initialize LXD: %s"), error_msg)
            return {
                "success": False,
                "error": _("Failed to initialize LXD: %s") % error_msg,
            }

        self.logger.info(_("LXD initialized successfully"))
        return None

    async def _configure_default_profile(self) -> None:
        """Configure the LXD default profile for container compatibility.

        Sets security.nesting=true so containers can run sudo and nested
        operations (e.g. Ubuntu Pro attach, package management).
        Sets boot.autostart=true so containers restart after host reboot.
        """
        self.logger.info(
            _("Configuring LXD default profile for container compatibility")
        )

        result = await run_command_async(
            ["lxc", "profile", "set", "default", "security.nesting", "true"],
            timeout=30,
        )

        if result.returncode != 0:
            self.logger.warning(
                _("Could not set security.nesting on default profile: %s"),
                result.stderr or result.stdout,
            )
        else:
            self.logger.info(
                _("LXD default profile configured with security.nesting=true")
            )

        # Enable autostart so containers restart after host reboot
        autostart_result = await run_command_async(
            ["lxc", "profile", "set", "default", "boot.autostart", "true"],
            timeout=30,
        )

        if autostart_result.returncode != 0:
            self.logger.warning(
                _("Could not set boot.autostart on default profile: %s"),
                autostart_result.stderr or autostart_result.stdout,
            )
        else:
            self.logger.info(
                _("LXD default profile configured with boot.autostart=true")
            )

    def _verify_lxd_ready(self, lxd_check: dict, firewall_result: dict) -> dict:
        """Verify LXD is working and return final result."""
        verify_result = self.virtualization_checks.check_lxd_support()

        if verify_result.get("installed") and verify_result.get("initialized"):
            self.logger.info(_("LXD is ready for use"))
            return {
                "success": True,
                "message": _("LXD has been installed and initialized"),
                "user_needs_relogin": not lxd_check.get("user_in_group"),
                "firewall_configured": firewall_result.get("success", False),
            }

        return {
            "success": False,
            "error": _("LXD initialization completed but verification failed"),
        }

    def _configure_lxd_firewall(self) -> dict:
        """
        Configure firewall for LXD container networking.

        Uses existing firewall infrastructure to configure:
        - IP forwarding
        - NAT masquerade for the lxdbr0 subnet
        - UFW rules to allow traffic from/to lxdbr0

        Returns:
            Dict with success status and message
        """
        try:
            import platform  # pylint: disable=import-outside-toplevel

            if platform.system() != "Linux":
                return {
                    "success": True,
                    "message": "Firewall configuration not needed on non-Linux",
                }

            # Use the existing firewall operations infrastructure
            # pylint: disable=import-outside-toplevel
            from src.sysmanage_agent.operations.firewall_linux import (
                LinuxFirewallOperations,
            )

            firewall_ops = LinuxFirewallOperations(self.agent, self.logger)
            result = firewall_ops.configure_lxd_firewall("lxdbr0")

            if result.get("success"):
                self.logger.info(_("Firewall configured for LXD networking"))
            else:
                self.logger.warning(
                    _("Firewall configuration warning: %s"), result.get("error")
                )

            return result

        except Exception as error:
            self.logger.error(_("Error configuring firewall for LXD: %s"), error)
            return {"success": False, "error": str(error)}

    async def start_child_host(self, parameters: dict) -> dict:
        """Start a stopped LXD container."""
        container_name = parameters.get("child_name")
        if not container_name:
            return {"success": False, "error": _CONTAINER_NAME_REQUIRED}

        try:
            self.logger.info("Starting LXD container: %s", container_name)

            result = await run_command_async(
                ["lxc", "start", container_name],
                timeout=60,
            )

            if result.returncode == 0:
                return {
                    "success": True,
                    "child_name": container_name,
                    "child_type": "lxd",
                    "message": _("Container started"),
                }

            return {
                "success": False,
                "child_name": container_name,
                "child_type": "lxd",
                "error": result.stderr
                or result.stdout
                or _("Failed to start container"),
            }

        except asyncio.TimeoutError:
            return {
                "success": False,
                "child_name": container_name,
                "child_type": "lxd",
                "error": _("Start operation timed out"),
            }
        except Exception as error:
            return {
                "success": False,
                "child_name": container_name,
                "child_type": "lxd",
                "error": str(error),
            }

    async def stop_child_host(self, parameters: dict) -> dict:
        """Stop a running LXD container."""
        container_name = parameters.get("child_name")
        if not container_name:
            return {"success": False, "error": _CONTAINER_NAME_REQUIRED}

        try:
            self.logger.info("Stopping LXD container: %s", container_name)

            result = await run_command_async(
                ["lxc", "stop", container_name],
                timeout=60,
            )

            if result.returncode == 0:
                return {
                    "success": True,
                    "child_name": container_name,
                    "child_type": "lxd",
                    "message": _("Container stopped"),
                }

            return {
                "success": False,
                "child_name": container_name,
                "child_type": "lxd",
                "error": result.stderr
                or result.stdout
                or _("Failed to stop container"),
            }

        except asyncio.TimeoutError:
            return {
                "success": False,
                "child_name": container_name,
                "child_type": "lxd",
                "error": _("Stop operation timed out"),
            }
        except Exception as error:
            return {
                "success": False,
                "child_name": container_name,
                "child_type": "lxd",
                "error": str(error),
            }

    async def restart_child_host(self, parameters: dict) -> dict:
        """Restart an LXD container."""
        container_name = parameters.get("child_name")
        if not container_name:
            return {"success": False, "error": _CONTAINER_NAME_REQUIRED}

        try:
            self.logger.info("Restarting LXD container: %s", container_name)

            result = await run_command_async(
                ["lxc", "restart", container_name],
                timeout=120,
            )

            if result.returncode == 0:
                return {
                    "success": True,
                    "child_name": container_name,
                    "child_type": "lxd",
                    "message": _("Container restarted"),
                }

            return {
                "success": False,
                "child_name": container_name,
                "child_type": "lxd",
                "error": result.stderr
                or result.stdout
                or _("Failed to restart container"),
            }

        except asyncio.TimeoutError:
            return {
                "success": False,
                "child_name": container_name,
                "child_type": "lxd",
                "error": _("Restart operation timed out"),
            }
        except Exception as error:
            return {
                "success": False,
                "child_name": container_name,
                "child_type": "lxd",
                "error": str(error),
            }

    async def delete_child_host(self, parameters: dict) -> dict:
        """Delete an LXD container permanently."""
        container_name = parameters.get("child_name")
        if not container_name:
            return {"success": False, "error": _CONTAINER_NAME_REQUIRED}

        try:
            self.logger.info("Deleting LXD container: %s", container_name)

            # Use --force to stop and delete in one step
            result = await run_command_async(
                ["lxc", "delete", container_name, "--force"],
                timeout=120,
            )

            if result.returncode == 0:
                return {
                    "success": True,
                    "child_name": container_name,
                    "child_type": "lxd",
                    "message": _("Container deleted"),
                }

            return {
                "success": False,
                "child_name": container_name,
                "child_type": "lxd",
                "error": result.stderr
                or result.stdout
                or _("Failed to delete container"),
            }

        except asyncio.TimeoutError:
            return {
                "success": False,
                "child_name": container_name,
                "child_type": "lxd",
                "error": _("Delete operation timed out"),
            }
        except Exception as error:
            return {
                "success": False,
                "child_name": container_name,
                "child_type": "lxd",
                "error": str(error),
            }
