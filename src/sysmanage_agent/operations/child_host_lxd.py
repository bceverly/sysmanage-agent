"""
LXD-specific child host operations for Ubuntu hosts.
"""

# pylint: disable=too-many-lines

import json
import os
import pwd
import subprocess  # nosec B404 # Required for system command execution
import time
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from src.i18n import _
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

    async def initialize_lxd(self, _parameters: Dict[str, Any]) -> Dict[str, Any]:
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
            # This enables IP forwarding, NAT masquerade, and UFW rules for lxdbr0
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

    def _configure_lxd_firewall(self) -> Dict[str, Any]:
        """
        Configure firewall for LXD container networking.

        This uses the existing firewall infrastructure to configure:
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

    async def create_lxd_container(
        self,
        config: LxdContainerConfig,
    ) -> Dict[str, Any]:
        """
        Create a new LXD container with the full installation flow.

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
        try:
            # Validate inputs
            if not distribution:
                return {"success": False, "error": _("Distribution is required")}
            if not container_name:
                return {"success": False, "error": _("Container name is required")}
            if not hostname:
                return {"success": False, "error": _("Hostname is required")}
            if not username:
                return {"success": False, "error": _("Username is required")}
            if not password:
                return {"success": False, "error": _("Password is required")}

            # Derive FQDN hostname if user didn't provide a domain
            fqdn_hostname = self._get_fqdn_hostname(hostname, server_url)
            if fqdn_hostname != hostname:
                self.logger.info(
                    "Using FQDN hostname '%s' (user provided '%s')",
                    fqdn_hostname,
                    hostname,
                )

            # Send progress update
            await self._send_progress("checking_lxd", _("Checking LXD status..."))

            # Step 1: Check LXD is available and initialized
            lxd_check = self.virtualization_checks.check_lxd_support()
            if not lxd_check.get("available"):
                return {
                    "success": False,
                    "error": _("LXD is not available on this system"),
                }

            if not lxd_check.get("initialized"):
                return {
                    "success": False,
                    "error": _("LXD is not initialized. Please enable LXD first."),
                }

            # Step 2: Check if container already exists
            await self._send_progress(
                "checking_existing", _("Checking for existing container...")
            )
            if self._container_exists(container_name):
                return {
                    "success": False,
                    "error": _("Container '%s' already exists") % container_name,
                }

            # Step 3: Launch the container
            await self._send_progress(
                "launching_container",
                _("Launching container %s from %s...") % (container_name, distribution),
            )
            launch_result = await self._launch_container(distribution, container_name)
            if not launch_result.get("success"):
                return launch_result

            # Step 4: Wait for container to be running and have network
            await self._send_progress(
                "waiting_for_network", _("Waiting for container to start...")
            )
            if not self._wait_for_container_ready(container_name, timeout=60):
                return {
                    "success": False,
                    "error": _("Container failed to start properly"),
                }

            # Step 5: Set hostname
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

            # Step 6: Create the user
            await self._send_progress(
                "creating_user", _("Creating user %s...") % username
            )
            user_result = await self._create_user(container_name, username, password)
            if not user_result.get("success"):
                return user_result

            # Step 7: Install sysmanage-agent
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

            # Step 8: Configure agent
            if server_url:
                await self._send_progress(
                    "configuring_agent", _("Configuring sysmanage-agent...")
                )
                config_result = await self._configure_agent(
                    container_name, server_url, fqdn_hostname, server_port, use_https
                )
                if not config_result.get("success"):
                    self.logger.warning(
                        "Agent configuration failed: %s", config_result.get("error")
                    )

            # Step 9: Start agent service
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

    async def _send_progress(self, step: str, message: str):
        """Send a progress update to the server."""
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

    def _get_fqdn_hostname(self, hostname: str, server_url: str) -> str:
        """
        Derive FQDN hostname from server URL domain if not already FQDN.

        Args:
            hostname: User-provided hostname
            server_url: Server URL to derive domain from

        Returns:
            FQDN hostname
        """
        if "." in hostname:
            return hostname

        # Extract domain from server_url
        try:
            parsed = urlparse(server_url)
            server_host = parsed.hostname or ""
            if "." in server_host:
                # Get domain part (e.g., t14.theeverlys.com -> theeverlys.com)
                parts = server_host.split(".")
                if len(parts) >= 2:
                    domain = ".".join(parts[-2:])
                    return f"{hostname}.{domain}"
        except Exception:  # nosec B110 - returns original hostname on parse failure
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

    def _get_host_primary_interface(self) -> str:
        """
        Get the host's primary network interface (the one with the default route).

        Returns:
            Interface name (e.g., 'eth0', 'wlp3s0', 'enp0s3')
        """
        try:
            # Use ip route to find the interface with the default route
            result = subprocess.run(  # nosec B603 B607
                ["ip", "route", "get", "8.8.8.8"],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )

            if result.returncode == 0:
                # Output is like: "8.8.8.8 via 192.168.1.1 dev eth0 src 192.168.1.100"
                parts = result.stdout.split()
                if "dev" in parts:
                    dev_index = parts.index("dev")
                    if dev_index + 1 < len(parts):
                        return parts[dev_index + 1]

            # Fallback: try common interface names
            for iface in ["eth0", "enp0s3", "ens33", "wlan0", "wlp3s0"]:
                check = subprocess.run(  # nosec B603 B607
                    ["ip", "link", "show", iface],
                    capture_output=True,
                    timeout=5,
                    check=False,
                )
                if check.returncode == 0:
                    return iface

            return "eth0"  # Ultimate fallback

        except Exception as error:
            self.logger.warning("Error detecting primary interface: %s", error)
            return "eth0"

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

            # Step 1: Verify lxdbr0 (LXD's default bridge) exists
            bridge_check = subprocess.run(  # nosec B603 B607
                ["ip", "link", "show", "lxdbr0"],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            if bridge_check.returncode != 0:
                return {
                    "success": False,
                    "error": _(
                        "LXD bridge lxdbr0 not found. Please re-initialize LXD."
                    ),
                }

            # Step 2: Launch container directly (uses default profile with lxdbr0)
            # The --no-profiles flag is NOT used so we get the default network config
            result = subprocess.run(  # nosec B603 B607
                ["lxc", "launch", distribution, container_name],
                capture_output=True,
                text=True,
                timeout=600,  # 10 minutes for image download
                check=False,
            )

            if result.returncode != 0:
                error_msg = result.stderr or result.stdout or "Unknown error"
                self.logger.error("Container launch failed: %s", error_msg)
                return {"success": False, "error": error_msg}

            # Step 3: Make the container privileged
            priv_result = subprocess.run(  # nosec B603 B607
                ["lxc", "config", "set", container_name, "security.privileged", "true"],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )

            if priv_result.returncode != 0:
                self.logger.warning(
                    "Failed to set privileged mode: %s",
                    priv_result.stderr or priv_result.stdout,
                )

            # Step 4: Restart container to apply privileged mode
            restart_result = subprocess.run(  # nosec B603 B607
                ["lxc", "restart", container_name],
                capture_output=True,
                text=True,
                timeout=60,
                check=False,
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

        except subprocess.TimeoutExpired:
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

    async def _set_container_hostname(
        self, container_name: str, hostname: str
    ) -> Dict[str, Any]:
        """Set the hostname (FQDN) inside the container."""
        try:
            # Extract short hostname from FQDN
            short_hostname = hostname.split(".")[0] if "." in hostname else hostname

            # Step 1: Write FQDN to /etc/hostname (more reliable than hostnamectl in containers)
            subprocess.run(  # nosec B603 B607
                [
                    "lxc",
                    "exec",
                    container_name,
                    "--",
                    "sh",
                    "-c",
                    f"echo '{hostname}' > /etc/hostname",
                ],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )

            # Step 2: Update /etc/hosts with both FQDN and short name
            # First remove any existing 127.0.1.1 line, then add our entry
            hosts_entry = f"127.0.1.1\\t{hostname}\\t{short_hostname}"
            subprocess.run(  # nosec B603 B607
                [
                    "lxc",
                    "exec",
                    container_name,
                    "--",
                    "sh",
                    "-c",
                    f"sed -i '/^127.0.1.1/d' /etc/hosts && echo -e '{hosts_entry}' >> /etc/hosts",
                ],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )

            # Step 3: Set the hostname using the hostname command (immediate effect)
            subprocess.run(  # nosec B603 B607
                [
                    "lxc",
                    "exec",
                    container_name,
                    "--",
                    "hostname",
                    hostname,
                ],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
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
            result = subprocess.run(  # nosec B603 B607
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
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )

            if result.returncode != 0 and "already exists" not in result.stderr:
                return {
                    "success": False,
                    "error": _("Failed to create user: %s") % result.stderr,
                }

            # Set password
            result = subprocess.run(  # nosec B603 B607
                [
                    "lxc",
                    "exec",
                    container_name,
                    "--",
                    "sh",
                    "-c",
                    f"echo '{username}:{password}' | chpasswd",
                ],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )

            if result.returncode != 0:
                return {
                    "success": False,
                    "error": _("Failed to set password: %s") % result.stderr,
                }

            # Add to sudo group (try both sudo and wheel for different distros)
            subprocess.run(  # nosec B603 B607
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
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )

            subprocess.run(  # nosec B603 B607
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
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )

            return {"success": True}

        except Exception as error:
            return {"success": False, "error": str(error)}

    async def _install_agent(
        self, container_name: str, commands: List[str]
    ) -> Dict[str, Any]:
        """Install the sysmanage-agent using provided commands."""
        try:
            for cmd in commands:
                self.logger.info("Running install command: %s", cmd)
                result = subprocess.run(  # nosec B603 B607
                    ["lxc", "exec", container_name, "--", "sh", "-c", cmd],
                    capture_output=True,
                    text=True,
                    timeout=300,  # 5 minutes per command
                    check=False,
                )

                if result.returncode != 0:
                    self.logger.warning(
                        "Install command failed: %s - %s",
                        cmd,
                        result.stderr or result.stdout,
                    )
                    # Continue trying other commands

            return {"success": True}

        except subprocess.TimeoutExpired:
            return {"success": False, "error": _("Agent installation timed out")}
        except Exception as error:
            return {"success": False, "error": str(error)}

    async def _configure_agent(
        self,
        container_name: str,
        server_url: str,
        hostname: str,
        server_port: int,
        use_https: bool,
    ) -> Dict[str, Any]:
        """Configure the sysmanage-agent inside the container."""
        try:
            # Create agent config
            config_yaml = f"""server:
  hostname: "{server_url}"
  port: {server_port}
  use_https: {str(use_https).lower()}
hostname: "{hostname}"
websocket:
  reconnect_delay: 5
  max_reconnect_delay: 300
privileged_mode: true
script_execution:
  enabled: true
  allowed_shells:
    - "bash"
    - "sh"
"""

            # Write config file
            result = subprocess.run(  # nosec B603 B607
                [
                    "lxc",
                    "exec",
                    container_name,
                    "--",
                    "sh",
                    "-c",
                    f"mkdir -p /etc && cat > /etc/sysmanage-agent.yaml << 'EOF'\n{config_yaml}EOF",
                ],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
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
            result = subprocess.run(  # nosec B603 B607
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
                capture_output=True,
                text=True,
                timeout=60,
                check=False,
            )

            if result.returncode != 0:
                return {
                    "success": False,
                    "error": _("Failed to start agent service: %s") % result.stderr,
                }

            return {"success": True}

        except Exception as error:
            return {"success": False, "error": str(error)}

    async def start_child_host(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
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
                return {"success": True, "message": _("Container started")}

            return {
                "success": False,
                "error": result.stderr
                or result.stdout
                or _("Failed to start container"),
            }

        except subprocess.TimeoutExpired:
            return {"success": False, "error": _("Start operation timed out")}
        except Exception as error:
            return {"success": False, "error": str(error)}

    async def stop_child_host(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
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
                return {"success": True, "message": _("Container stopped")}

            return {
                "success": False,
                "error": result.stderr
                or result.stdout
                or _("Failed to stop container"),
            }

        except subprocess.TimeoutExpired:
            return {"success": False, "error": _("Stop operation timed out")}
        except Exception as error:
            return {"success": False, "error": str(error)}

    async def restart_child_host(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
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
                return {"success": True, "message": _("Container restarted")}

            return {
                "success": False,
                "error": result.stderr
                or result.stdout
                or _("Failed to restart container"),
            }

        except subprocess.TimeoutExpired:
            return {"success": False, "error": _("Restart operation timed out")}
        except Exception as error:
            return {"success": False, "error": str(error)}

    async def delete_child_host(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
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
                return {"success": True, "message": _("Container deleted")}

            return {
                "success": False,
                "error": result.stderr
                or result.stdout
                or _("Failed to delete container"),
            }

        except subprocess.TimeoutExpired:
            return {"success": False, "error": _("Delete operation timed out")}
        except Exception as error:
            return {"success": False, "error": str(error)}
