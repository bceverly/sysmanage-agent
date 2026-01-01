"""
LXD-specific child host operations for Ubuntu hosts.
"""

import os
import pwd
import subprocess  # nosec B404 # Required for system command execution

from src.i18n import _
from src.sysmanage_agent.operations.child_host_lxd_container_creator import (
    LxdContainerCreator,
)
from src.sysmanage_agent.operations.child_host_types import LxdContainerConfig


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
        self.container_creator = LxdContainerCreator(agent_instance, logger)

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
            if not lxd_check.get("installed"):
                if not lxd_check.get("snap_available"):
                    return {
                        "success": False,
                        "error": _("Snap is not available to install LXD"),
                    }

                self.logger.info(_("Installing LXD via snap"))
                install_result = subprocess.run(  # nosec B603 B607
                    ["sudo", "snap", "install", "lxd"],
                    capture_output=True,
                    text=True,
                    timeout=300,  # 5 minutes for download/install
                    check=False,
                )

                if install_result.returncode != 0:
                    error_msg = (
                        install_result.stderr
                        or install_result.stdout
                        or "Unknown error"
                    )
                    self.logger.error(_("Failed to install LXD: %s"), error_msg)
                    return {
                        "success": False,
                        "error": _("Failed to install LXD: %s") % error_msg,
                    }

                self.logger.info(_("LXD installed successfully"))

            # Step 2: Add current user to lxd group if not already
            if not lxd_check.get("user_in_group"):
                self.logger.info(_("Adding current user to lxd group"))
                username = pwd.getpwuid(os.getuid()).pw_name

                usermod_result = subprocess.run(  # nosec B603 B607
                    ["sudo", "usermod", "-aG", "lxd", username],
                    capture_output=True,
                    text=True,
                    timeout=30,
                    check=False,
                )

                if usermod_result.returncode != 0:
                    self.logger.warning(
                        _("Could not add user to lxd group: %s"),
                        usermod_result.stderr or usermod_result.stdout,
                    )
                    # Continue anyway - the user may need to log out/in

            # Step 3: Initialize LXD if not already initialized
            if not lxd_check.get("initialized"):
                self.logger.info(_("Initializing LXD with default settings"))
                init_result = subprocess.run(  # nosec B603 B607
                    ["sudo", "lxd", "init", "--auto"],
                    capture_output=True,
                    text=True,
                    timeout=120,  # 2 minutes for init
                    check=False,
                )

                if init_result.returncode != 0:
                    error_msg = (
                        init_result.stderr or init_result.stdout or "Unknown error"
                    )
                    self.logger.error(_("Failed to initialize LXD: %s"), error_msg)
                    return {
                        "success": False,
                        "error": _("Failed to initialize LXD: %s") % error_msg,
                    }

                self.logger.info(_("LXD initialized successfully"))

            # Step 4: Configure firewall for LXD networking
            firewall_result = self._configure_lxd_firewall()
            if not firewall_result.get("success"):
                self.logger.warning(
                    "Firewall configuration issue: %s", firewall_result.get("error")
                )
                # Continue anyway - containers may still work or user can fix manually

            # Verify LXD is now working
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

        except subprocess.TimeoutExpired:
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

    async def create_lxd_container(self, config: LxdContainerConfig) -> dict:
        """
        Create a new LXD container with full installation flow.

        Delegates to LxdContainerCreator for the full creation workflow.

        Args:
            config: LxdContainerConfig with all container settings

        Returns:
            Dict with success status and details
        """
        return await self.container_creator.create_lxd_container(config)

    async def start_child_host(self, parameters: dict) -> dict:
        """Start a stopped LXD container."""
        container_name = parameters.get("child_name")
        if not container_name:
            return {"success": False, "error": _("Container name is required")}

        try:
            self.logger.info("Starting LXD container: %s", container_name)

            result = subprocess.run(  # nosec B603 B607
                ["lxc", "start", container_name],
                capture_output=True,
                text=True,
                timeout=60,
                check=False,
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

        except subprocess.TimeoutExpired:
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
            return {"success": False, "error": _("Container name is required")}

        try:
            self.logger.info("Stopping LXD container: %s", container_name)

            result = subprocess.run(  # nosec B603 B607
                ["lxc", "stop", container_name],
                capture_output=True,
                text=True,
                timeout=60,
                check=False,
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

        except subprocess.TimeoutExpired:
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
            return {"success": False, "error": _("Container name is required")}

        try:
            self.logger.info("Restarting LXD container: %s", container_name)

            result = subprocess.run(  # nosec B603 B607
                ["lxc", "restart", container_name],
                capture_output=True,
                text=True,
                timeout=120,
                check=False,
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

        except subprocess.TimeoutExpired:
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
            return {"success": False, "error": _("Container name is required")}

        try:
            self.logger.info("Deleting LXD container: %s", container_name)

            # Use --force to stop and delete in one step
            result = subprocess.run(  # nosec B603 B607
                ["lxc", "delete", container_name, "--force"],
                capture_output=True,
                text=True,
                timeout=120,
                check=False,
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

        except subprocess.TimeoutExpired:
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
