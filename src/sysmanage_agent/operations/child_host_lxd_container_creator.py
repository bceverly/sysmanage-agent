"""
LXD container creation and configuration.

This module handles the complete LXD container creation workflow including:
- Container launch and network setup
- Hostname configuration
- User creation and management
- Agent installation and configuration
- Service management
"""

import asyncio
import json
import subprocess  # nosec B404
import time
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from src.i18n import _
from src.sysmanage_agent.core.agent_utils import run_command_async
from src.sysmanage_agent.operations.child_host_config_generator import (
    generate_agent_config,
)
from src.sysmanage_agent.operations.child_host_types import LxdContainerConfig


class LxdContainerCreator:
    """Handles LXD container creation workflow."""

    def __init__(self, agent_instance, logger):
        """
        Initialize container creator.

        Args:
            agent_instance: Reference to main SysManageAgent
            logger: Logger instance
        """
        self.agent = agent_instance
        self.logger = logger

    async def create_lxd_container(
        self,
        config: LxdContainerConfig,
    ) -> Dict[str, Any]:
        """
        Create a new LXD container with full installation flow.

        Workflow:
        1. Validate configuration
        2. Launch container from distribution image
        3. Wait for container to be ready with network
        4. Set hostname
        5. Create user with sudo access
        6. Install sysmanage-agent (if commands provided)
        7. Configure agent
        8. Start agent service

        Args:
            config: LxdContainerConfig with all container settings

        Returns:
            Dict with success status and details
        """
        # Extract config values for convenience
        distribution = config.distribution
        container_name = config.container_name
        hostname = config.hostname
        username = config.username
        password = config.password
        server_url = config.server_url
        agent_install_commands = config.agent_install_commands
        server_port = config.server_port
        use_https = config.use_https
        auto_approve_token = config.auto_approve_token

        try:
            # Validate inputs
            validation_result = self._validate_config(config)
            if not validation_result.get("success"):
                return validation_result

            # Derive FQDN hostname
            fqdn_hostname = self._get_fqdn_hostname(hostname, server_url)
            if fqdn_hostname != hostname:
                self.logger.info(
                    "Using FQDN hostname '%s' (user provided '%s')",
                    fqdn_hostname,
                    hostname,
                )

            # Check if container already exists
            await self._send_progress(
                "checking_existing", _("Checking for existing container...")
            )
            if self._container_exists(container_name):
                return {
                    "success": False,
                    "error": _("Container '%s' already exists") % container_name,
                }

            # Launch the container
            await self._send_progress(
                "launching_container",
                _("Launching container %s from %s...") % (container_name, distribution),
            )
            launch_result = await self._launch_container(distribution, container_name)
            if not launch_result.get("success"):
                return launch_result

            # Wait for container to be running and have network
            await self._send_progress(
                "waiting_for_network", _("Waiting for container to start...")
            )
            if not self._wait_for_container_ready(container_name, timeout=60):
                return {
                    "success": False,
                    "error": _("Container failed to start properly"),
                }

            # Set hostname
            await self._send_progress(
                "setting_hostname", _("Setting hostname to %s...") % fqdn_hostname
            )
            hostname_result = await self._set_container_hostname(
                container_name, fqdn_hostname
            )
            if not hostname_result.get("success"):
                self.logger.warning(
                    "Hostname configuration failed: %s", hostname_result.get("error")
                )
                # Continue anyway

            # Create the user
            await self._send_progress(
                "creating_user", _("Creating user %s...") % username
            )
            user_result = await self._create_user(container_name, username, password)
            if not user_result.get("success"):
                return user_result

            # Install sysmanage-agent
            if agent_install_commands:
                await self._send_progress(
                    "installing_agent", _("Installing sysmanage-agent...")
                )
                agent_result = await self._install_agent(
                    container_name, agent_install_commands
                )
                if not agent_result.get("success"):
                    self.logger.warning(
                        "Agent installation failed: %s", agent_result.get("error")
                    )
                    # Continue anyway - admin can install manually

            # Configure agent
            if server_url:
                await self._send_progress(
                    "configuring_agent", _("Configuring sysmanage-agent...")
                )
                config_result = await self._configure_agent(
                    container_name,
                    server_url,
                    fqdn_hostname,
                    server_port,
                    use_https,
                    auto_approve_token,
                )
                if not config_result.get("success"):
                    self.logger.warning(
                        "Agent configuration failed: %s", config_result.get("error")
                    )

            # Start agent service
            await self._send_progress("starting_agent", _("Starting agent service..."))
            start_result = await self._start_agent_service(container_name)
            if not start_result.get("success"):
                self.logger.warning(
                    "Agent service start failed: %s", start_result.get("error")
                )

            await self._send_progress("complete", _("Container creation complete"))

            return {
                "success": True,
                "child_name": container_name,
                "child_type": "lxd",
                "hostname": fqdn_hostname,
                "username": username,
                "message": _("LXD container '%s' created successfully")
                % container_name,
            }

        except Exception as error:
            self.logger.error(_("Error creating LXD container: %s"), error)
            return {"success": False, "error": str(error)}

    # =========================================================================
    # Validation and Utility Methods
    # =========================================================================

    def _validate_config(self, config: LxdContainerConfig) -> Dict[str, Any]:
        """Validate container configuration."""
        if not config.distribution:
            return {"success": False, "error": _("Distribution is required")}
        if not config.container_name:
            return {"success": False, "error": _("Container name is required")}
        if not config.hostname:
            return {"success": False, "error": _("Hostname is required")}
        if not config.username:
            return {"success": False, "error": _("Username is required")}
        if not config.password:
            return {"success": False, "error": _("Password is required")}
        return {"success": True}

    def _get_fqdn_hostname(self, hostname: str, server_url: str) -> str:
        """Derive FQDN hostname from server URL if not already FQDN."""
        if "." in hostname:
            return hostname

        try:
            parsed = urlparse(server_url)
            server_host = parsed.hostname or ""
            if "." in server_host:
                parts = server_host.split(".")
                if len(parts) >= 2:
                    domain = ".".join(parts[-2:])
                    return f"{hostname}.{domain}"
        except Exception:  # nosec B110
            pass

        return hostname

    def _container_exists(self, container_name: str) -> bool:
        """Check if a container with the given name already exists."""
        try:
            result = subprocess.run(  # nosec B603 B607
                ["lxc", "info", container_name],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            return result.returncode == 0
        except Exception:
            return False

    async def _send_progress(self, step: str, message: str):
        """Send progress update to server."""
        try:
            if hasattr(self.agent, "send_message"):
                progress_message = self.agent.create_message(
                    "child_host_creation_progress",
                    {
                        "step": step,
                        "message": message,
                    },
                )
                await self.agent.send_message(progress_message)
        except Exception as error:
            self.logger.debug("Failed to send progress update: %s", error)

    # =========================================================================
    # Container Launch and Setup Methods
    # =========================================================================

    async def _launch_container(
        self, distribution: str, container_name: str
    ) -> Dict[str, Any]:
        """
        Launch a new privileged LXD container using LXD's default network.

        Creates a privileged container using the default lxdbr0 NAT bridge,
        which provides DHCP addresses to containers.
        """
        try:
            self.logger.info(
                "Launching LXD container: %s from %s", container_name, distribution
            )

            # Verify lxdbr0 (LXD's default bridge) exists
            bridge_check = await run_command_async(
                ["ip", "link", "show", "lxdbr0"],
                timeout=10,
            )
            if bridge_check.returncode != 0:
                return {
                    "success": False,
                    "error": _(
                        "LXD bridge lxdbr0 not found. Please re-initialize LXD."
                    ),
                }

            # Launch container (uses default profile with lxdbr0)
            result = await run_command_async(
                ["lxc", "launch", distribution, container_name],
                timeout=600,  # 10 minutes for image download
            )

            if result.returncode != 0:
                error_msg = result.stderr or result.stdout or "Unknown error"
                self.logger.error("Container launch failed: %s", error_msg)
                return {"success": False, "error": error_msg}

            # Make the container privileged
            priv_result = await run_command_async(
                ["lxc", "config", "set", container_name, "security.privileged", "true"],
                timeout=30,
            )

            if priv_result.returncode != 0:
                self.logger.warning(
                    "Failed to set privileged mode: %s",
                    priv_result.stderr or priv_result.stdout,
                )

            # Restart container to apply privileged mode
            restart_result = await run_command_async(
                ["lxc", "restart", container_name],
                timeout=60,
            )

            if restart_result.returncode == 0:
                self.logger.info(
                    "Container %s launched successfully with lxdbr0 NAT networking",
                    container_name,
                )
                return {"success": True}

            # If restart failed, container may still be usable
            self.logger.warning(
                "Container restart after privileged mode failed: %s",
                restart_result.stderr or restart_result.stdout,
            )
            return {"success": True}

        except asyncio.TimeoutError:
            return {"success": False, "error": _("Container launch timed out")}
        except Exception as error:
            return {"success": False, "error": str(error)}

    def _check_container_has_ip(self, container: Dict[str, Any]) -> Optional[str]:
        """Check if container has a usable IP address and return it."""
        state = container.get("state", {})
        network = state.get("network", {})

        for iface_name, iface_data in network.items():
            if iface_name == "lo":
                continue
            for addr in iface_data.get("addresses", []):
                family = addr.get("family")
                if family == "inet":
                    return f"IPv4 {addr.get('address')}"
                if family == "inet6":
                    addr_val = addr.get("address", "")
                    if not addr_val.startswith("fe80:"):
                        return f"IPv6 {addr_val}"
        return None

    def _wait_for_container_ready(self, container_name: str, timeout: int = 60) -> bool:
        """Wait for container to be running and have network connectivity."""
        start_time = time.time()
        while time.time() - start_time < timeout:
            try:
                result = subprocess.run(  # nosec B603 B607
                    ["lxc", "list", container_name, "--format", "json"],
                    capture_output=True,
                    text=True,
                    timeout=10,
                    check=False,
                )

                if result.returncode != 0:
                    time.sleep(2)
                    continue

                containers = json.loads(result.stdout)
                if not containers:
                    time.sleep(2)
                    continue

                container = containers[0]
                if container.get("status", "").lower() != "running":
                    time.sleep(2)
                    continue

                ip_info = self._check_container_has_ip(container)
                if ip_info:
                    self.logger.info(
                        "Container %s is ready with %s", container_name, ip_info
                    )
                    return True

            except Exception as error:
                self.logger.debug("Error checking container status: %s", error)

            time.sleep(2)

        self.logger.warning("Container %s did not become ready in time", container_name)
        return False

    # =========================================================================
    # Container Configuration Methods
    # =========================================================================

    async def _set_container_hostname(
        self, container_name: str, hostname: str
    ) -> Dict[str, Any]:
        """Set the hostname (FQDN) inside the container."""
        try:
            # Extract short hostname from FQDN
            short_hostname = hostname.split(".")[0] if "." in hostname else hostname

            # Write FQDN to /etc/hostname
            await run_command_async(
                [
                    "lxc",
                    "exec",
                    container_name,
                    "--",
                    "sh",
                    "-c",
                    f"echo '{hostname}' > /etc/hostname",
                ],
                timeout=30,
            )

            # Update /etc/hosts with both FQDN and short name
            hosts_entry = f"127.0.1.1\\t{hostname}\\t{short_hostname}"
            await run_command_async(
                [
                    "lxc",
                    "exec",
                    container_name,
                    "--",
                    "sh",
                    "-c",
                    f"sed -i '/^127.0.1.1/d' /etc/hosts && "
                    f"echo -e '{hosts_entry}' >> /etc/hosts",
                ],
                timeout=30,
            )

            # Set the hostname using the hostname command
            await run_command_async(
                [
                    "lxc",
                    "exec",
                    container_name,
                    "--",
                    "hostname",
                    hostname,
                ],
                timeout=30,
            )

            return {"success": True}

        except Exception as error:
            return {"success": False, "error": str(error)}

    async def _create_user(
        self, container_name: str, username: str, password: str
    ) -> Dict[str, Any]:
        """Create a user inside the container with sudo access."""
        try:
            # Create user with home directory
            result = await run_command_async(
                [
                    "lxc",
                    "exec",
                    container_name,
                    "--",
                    "useradd",
                    "-m",
                    "-s",
                    "/bin/bash",
                    username,
                ],
                timeout=30,
            )

            if result.returncode != 0 and "already exists" not in result.stderr:
                return {
                    "success": False,
                    "error": _("Failed to create user: %s") % result.stderr,
                }

            # Set password
            result = await run_command_async(
                [
                    "lxc",
                    "exec",
                    container_name,
                    "--",
                    "sh",
                    "-c",
                    f"echo '{username}:{password}' | chpasswd",
                ],
                timeout=30,
            )

            if result.returncode != 0:
                return {
                    "success": False,
                    "error": _("Failed to set password: %s") % result.stderr,
                }

            # Add to sudo group (try both sudo and wheel for different distros)
            await run_command_async(
                [
                    "lxc",
                    "exec",
                    container_name,
                    "--",
                    "usermod",
                    "-aG",
                    "sudo",
                    username,
                ],
                timeout=30,
            )

            await run_command_async(
                [
                    "lxc",
                    "exec",
                    container_name,
                    "--",
                    "usermod",
                    "-aG",
                    "wheel",
                    username,
                ],
                timeout=30,
            )

            return {"success": True}

        except Exception as error:
            return {"success": False, "error": str(error)}

    # =========================================================================
    # Agent Installation and Configuration
    # =========================================================================

    async def _install_agent(
        self, container_name: str, commands: List[str]
    ) -> Dict[str, Any]:
        """Install the sysmanage-agent using provided commands."""
        try:
            for cmd in commands:
                self.logger.info("Running install command: %s", cmd)
                result = await run_command_async(
                    ["lxc", "exec", container_name, "--", "sh", "-c", cmd],
                    timeout=300,  # 5 minutes per command
                )

                if result.returncode != 0:
                    self.logger.warning(
                        "Install command failed: %s - %s",
                        cmd,
                        result.stderr or result.stdout,
                    )
                    # Continue trying other commands

            return {"success": True}

        except asyncio.TimeoutError:
            return {"success": False, "error": _("Agent installation timed out")}
        except Exception as error:
            return {"success": False, "error": str(error)}

    async def _configure_agent(
        self,
        container_name: str,
        server_url: str,
        _hostname: str,  # pylint: disable=unused-argument
        server_port: int,
        use_https: bool,
        auto_approve_token: str = None,
    ) -> Dict[str, Any]:
        """Configure the sysmanage-agent inside the container."""
        try:
            # Create agent config using unified generator
            # LXD containers are typically Ubuntu-based
            config_yaml = generate_agent_config(
                hostname=server_url,
                port=server_port,
                use_https=use_https,
                os_type="ubuntu",
                auto_approve_token=auto_approve_token,
                verify_ssl=False,
            )

            # Write config file
            result = await run_command_async(
                [
                    "lxc",
                    "exec",
                    container_name,
                    "--",
                    "sh",
                    "-c",
                    f"mkdir -p /etc && "
                    f"cat > /etc/sysmanage-agent.yaml << 'EOF'\n{config_yaml}EOF",
                ],
                timeout=30,
            )

            if result.returncode != 0:
                return {
                    "success": False,
                    "error": _("Failed to write agent config: %s") % result.stderr,
                }

            return {"success": True}

        except Exception as error:
            return {"success": False, "error": str(error)}

    async def _start_agent_service(self, container_name: str) -> Dict[str, Any]:
        """Start the sysmanage-agent service inside the container."""
        try:
            result = await run_command_async(
                [
                    "lxc",
                    "exec",
                    container_name,
                    "--",
                    "systemctl",
                    "enable",
                    "--now",
                    "sysmanage-agent",
                ],
                timeout=60,
            )

            if result.returncode != 0:
                return {
                    "success": False,
                    "error": _("Failed to start agent service: %s") % result.stderr,
                }

            return {"success": True}

        except Exception as error:
            return {"success": False, "error": str(error)}
