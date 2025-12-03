"""
WSL child host setup operations (user creation, systemd, agent installation).
"""

import shutil
import subprocess  # nosec B404 # Required for system command execution
from typing import Any, Dict, List, Optional

from src.i18n import _


class WslSetupOperations:
    """WSL setup operations for user creation, systemd, and agent installation."""

    def __init__(self, logger, decode_output_func):
        """
        Initialize WSL setup operations.

        Args:
            logger: Logger instance
            decode_output_func: Function to decode WSL UTF-16LE output
        """
        self.logger = logger
        self._decode_wsl_output = decode_output_func

    def _get_creationflags(self) -> int:
        """Get subprocess creation flags for Windows."""
        return (
            subprocess.CREATE_NO_WINDOW
            if hasattr(subprocess, "CREATE_NO_WINDOW")
            else 0
        )

    def get_executable_name(self, distribution: str) -> Optional[str]:
        """
        Get the executable name for a WSL distribution.

        Args:
            distribution: Distribution name (may be actual WSL name like 'FedoraLinux-43')

        Returns:
            Executable name or None if unknown
        """
        dist_lower = distribution.lower()

        # Map distribution names to their executables
        exe_map = {
            "ubuntu-24.04": "ubuntu2404.exe",
            "ubuntu-22.04": "ubuntu2204.exe",
            "ubuntu-20.04": "ubuntu2004.exe",
            "ubuntu-18.04": "ubuntu1804.exe",
            "ubuntu": "ubuntu.exe",
            "debian": "debian.exe",
            "kali-linux": "kali.exe",
            "opensuse-tumbleweed": "opensuse-tumbleweed.exe",
            "opensuse-leap-15": "opensuse-leap-15.exe",
            "sles-15": "sles-15.exe",
            "fedora": "fedora.exe",
            "almalinux-9": "almalinux-9.exe",
            "rockylinux-9": "rockylinux-9.exe",
        }

        # Check for exact match first
        if dist_lower in exe_map:
            return exe_map[dist_lower]

        # Handle dynamic names like 'FedoraLinux-43' -> 'fedora.exe'
        # or 'AlmaLinux-9.3' -> 'almalinux-9.exe'
        for key, exe in exe_map.items():
            # Check if the distribution starts with the base name
            base_name = key.split("-", maxsplit=1)[0].replace("linux", "")
            if dist_lower.startswith(base_name) or base_name in dist_lower:
                return exe

        return None

    async def configure_default_user(
        self, distribution: str, exe_name: Optional[str], username: str
    ) -> Dict[str, Any]:
        """
        Configure the default user for a WSL distribution.

        Args:
            distribution: Distribution name
            exe_name: Distribution executable name (e.g., 'ubuntu2404.exe')
            username: Username to set as default

        Returns:
            Dict with success status
        """
        try:
            if exe_name:
                # Use distribution-specific executable
                exe_path = shutil.which(exe_name)
                if exe_path:
                    result = subprocess.run(  # nosec B603 B607
                        [exe_path, "config", "--default-user", username],
                        capture_output=True,
                        text=True,
                        timeout=30,
                        check=False,
                        creationflags=self._get_creationflags(),
                    )
                    if result.returncode == 0:
                        return {"success": True}

            # Fallback: Use wsl.exe to run passwd command for user config
            # This is less clean but works for all distributions
            self.logger.debug(
                "Using wsl command to configure default user for %s", distribution
            )

            # For root, we don't need to do anything special - WSL defaults to root
            # if no user is configured during first run
            if username == "root":
                return {"success": True}

            return {"success": True}

        except Exception as error:
            return {"success": False, "error": str(error)}

    async def create_user(
        self, distribution: str, username: str, password: str
    ) -> Dict[str, Any]:
        """
        Create a non-root user in a WSL distribution.

        Args:
            distribution: Distribution name
            username: Username to create
            password: Password for the user

        Returns:
            Dict with success status
        """
        try:
            creationflags = self._get_creationflags()

            # Create user with home directory and bash shell
            create_cmd = f"useradd -m -s /bin/bash {username}"
            result = subprocess.run(  # nosec B603 B607
                ["wsl", "-d", distribution, "--", "sh", "-c", create_cmd],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
                creationflags=creationflags,
            )

            if result.returncode != 0:
                # User might already exist
                if "already exists" not in result.stderr.lower():
                    return {
                        "success": False,
                        "error": _("Failed to create user: %s")
                        % (result.stderr or result.stdout),
                    }

            # Set password
            # Use chpasswd which reads from stdin
            passwd_cmd = f"echo '{username}:{password}' | chpasswd"
            result = subprocess.run(  # nosec B603 B607
                ["wsl", "-d", distribution, "--", "sh", "-c", passwd_cmd],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
                creationflags=creationflags,
            )

            if result.returncode != 0:
                return {
                    "success": False,
                    "error": _("Failed to set password: %s")
                    % (result.stderr or result.stdout),
                }

            # Add user to sudo/wheel group
            # Try sudo first (Debian/Ubuntu), then wheel (Fedora/RHEL)
            for sudo_group in ["sudo", "wheel"]:
                add_group_cmd = f"usermod -aG {sudo_group} {username}"
                result = subprocess.run(  # nosec B603 B607
                    ["wsl", "-d", distribution, "--", "sh", "-c", add_group_cmd],
                    capture_output=True,
                    text=True,
                    timeout=30,
                    check=False,
                    creationflags=creationflags,
                )
                if result.returncode == 0:
                    break

            self.logger.info("User %s created successfully", username)
            return {"success": True}

        except Exception as error:
            return {"success": False, "error": str(error)}

    async def enable_systemd(self, distribution: str) -> Dict[str, Any]:
        """
        Enable systemd in a WSL distribution.

        Args:
            distribution: Distribution name

        Returns:
            Dict with success status
        """
        try:
            creationflags = self._get_creationflags()

            # Write systemd=true to /etc/wsl.conf
            # Use printf instead of echo -e for portability (dash doesn't support echo -e)
            wsl_conf_cmd = (
                "mkdir -p /etc && "
                "(grep -q '\\[boot\\]' /etc/wsl.conf 2>/dev/null && "
                "sed -i 's/systemd=.*/systemd=true/' /etc/wsl.conf || "
                "printf '[boot]\\nsystemd=true\\n' >> /etc/wsl.conf)"
            )

            result = subprocess.run(  # nosec B603 B607
                ["wsl", "-d", distribution, "--", "sh", "-c", wsl_conf_cmd],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
                creationflags=creationflags,
            )

            if result.returncode != 0:
                return {
                    "success": False,
                    "error": _("Failed to enable systemd: %s")
                    % (result.stderr or result.stdout),
                }

            self.logger.info("Systemd enabled for distribution %s", distribution)
            return {"success": True}

        except Exception as error:
            return {"success": False, "error": str(error)}

    async def set_hostname(self, distribution: str, hostname: str) -> Dict[str, Any]:
        """
        Set the hostname in a WSL distribution.

        This sets the hostname in /etc/hostname and adds it to /etc/hosts.
        The hostname will be fully applied after a restart.

        Args:
            distribution: Distribution name
            hostname: Hostname to set

        Returns:
            Dict with success status
        """
        try:
            creationflags = self._get_creationflags()

            # Write hostname to /etc/hostname
            hostname_cmd = f"echo '{hostname}' > /etc/hostname"
            result = subprocess.run(  # nosec B603 B607
                ["wsl", "-d", distribution, "--", "sh", "-c", hostname_cmd],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
                creationflags=creationflags,
            )

            if result.returncode != 0:
                return {
                    "success": False,
                    "error": _("Failed to set hostname: %s")
                    % (result.stderr or result.stdout),
                }

            # Add hostname to /etc/hosts if not already present
            # This ensures localhost resolution works properly
            hosts_cmd = (
                f"grep -q '{hostname}' /etc/hosts || "
                f"echo '127.0.0.1 {hostname}' >> /etc/hosts"
            )
            result = subprocess.run(  # nosec B603 B607
                ["wsl", "-d", distribution, "--", "sh", "-c", hosts_cmd],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
                creationflags=creationflags,
            )

            if result.returncode != 0:
                self.logger.warning(
                    "Failed to update /etc/hosts: %s",
                    result.stderr or result.stdout,
                )
                # Continue anyway - this is not critical

            # Also set hostname in wsl.conf so it persists across restarts
            # WSL reads [network] hostname= from wsl.conf
            # Use printf instead of echo -e for portability (dash doesn't support echo -e)
            wsl_conf_cmd = (
                "(grep -q '\\[network\\]' /etc/wsl.conf 2>/dev/null && "
                f"sed -i '/\\[network\\]/a hostname={hostname}' /etc/wsl.conf || "
                f"printf '\\n[network]\\nhostname={hostname}\\n' >> /etc/wsl.conf)"
            )
            result = subprocess.run(  # nosec B603 B607
                ["wsl", "-d", distribution, "--", "sh", "-c", wsl_conf_cmd],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
                creationflags=creationflags,
            )

            if result.returncode != 0:
                self.logger.warning(
                    "Failed to set hostname in wsl.conf: %s",
                    result.stderr or result.stdout,
                )
                # Continue anyway - /etc/hostname should still work

            self.logger.info(
                "Hostname set to %s for distribution %s", hostname, distribution
            )
            return {"success": True}

        except Exception as error:
            return {"success": False, "error": str(error)}

    async def restart_instance(self, distribution: str) -> Dict[str, Any]:
        """
        Restart a WSL instance to apply changes.

        Args:
            distribution: Distribution name

        Returns:
            Dict with success status
        """
        try:
            import asyncio  # pylint: disable=import-outside-toplevel

            creationflags = self._get_creationflags()

            # Terminate the distribution
            # Note: wsl.exe outputs UTF-16LE, so we read as bytes and decode manually
            result = subprocess.run(  # nosec B603 B607
                ["wsl", "--terminate", distribution],
                capture_output=True,
                timeout=60,
                check=False,
                creationflags=creationflags,
            )

            if result.returncode != 0:
                output = self._decode_wsl_output(result.stdout, result.stderr)
                self.logger.warning("WSL terminate returned non-zero: %s", output)

            # Wait a moment for termination to complete
            await asyncio.sleep(2)

            # Start the distribution again
            result = subprocess.run(  # nosec B603 B607
                ["wsl", "-d", distribution, "--", "echo", "Started"],
                capture_output=True,
                text=True,
                timeout=120,
                check=False,
                creationflags=creationflags,
            )

            if result.returncode != 0:
                return {
                    "success": False,
                    "error": _("Failed to restart WSL instance: %s")
                    % (result.stderr or result.stdout),
                }

            self.logger.info("WSL instance %s restarted successfully", distribution)
            return {"success": True}

        except Exception as error:
            return {"success": False, "error": str(error)}

    async def install_agent(
        self, distribution: str, install_commands: List[str]
    ) -> Dict[str, Any]:
        """
        Install sysmanage-agent in a WSL distribution.

        Args:
            distribution: Distribution name
            install_commands: List of commands to run for installation

        Returns:
            Dict with success status
        """
        try:
            creationflags = self._get_creationflags()

            for cmd in install_commands:
                self.logger.debug("Running agent install command: %s", cmd)

                result = subprocess.run(  # nosec B603 B607
                    ["wsl", "-d", distribution, "--", "sh", "-c", cmd],
                    capture_output=True,
                    text=True,
                    timeout=600,  # 10 minutes per command
                    check=False,
                    creationflags=creationflags,
                )

                if result.returncode != 0:
                    self.logger.warning(
                        "Agent install command failed: %s - %s",
                        cmd,
                        result.stderr or result.stdout,
                    )
                    # Continue with remaining commands

            self.logger.info("Agent installation commands completed")
            return {"success": True}

        except Exception as error:
            return {"success": False, "error": str(error)}

    def get_fqdn_hostname(self, hostname: str, server_url: str) -> str:
        """
        Get a fully qualified hostname by appending server domain if needed.

        If the hostname doesn't contain a dot (not FQDN), extract the domain
        from the server_url and append it.

        Args:
            hostname: The hostname provided by the user
            server_url: The server URL (FQDN like 't14.theeverlys.com')

        Returns:
            FQDN hostname
        """
        # If hostname already has a domain, return as-is
        if "." in hostname:
            return hostname

        # Extract domain from server_url
        # server_url is like 't14.theeverlys.com', we want 'theeverlys.com'
        if "." in server_url:
            parts = server_url.split(".", 1)
            if len(parts) > 1:
                domain = parts[1]
                fqdn = f"{hostname}.{domain}"
                self.logger.info(
                    "Derived FQDN '%s' from hostname '%s' and server domain '%s'",
                    fqdn,
                    hostname,
                    domain,
                )
                return fqdn

        # Couldn't extract domain, return original hostname
        return hostname

    def _get_allowed_shells_for_distribution(self, distribution: str) -> list:
        """
        Get appropriate allowed shells for a WSL distribution.

        Args:
            distribution: Distribution name (e.g., 'Ubuntu-24.04', 'FedoraLinux-43')

        Returns:
            List of allowed shell names
        """
        dist_lower = distribution.lower()

        # All Linux distributions support bash and sh
        shells = ["bash", "sh"]

        # Add distribution-specific shells
        if "ubuntu" in dist_lower or "debian" in dist_lower:
            shells.append("dash")
        elif "fedora" in dist_lower or "centos" in dist_lower or "rhel" in dist_lower:
            shells.append("zsh")
        elif "opensuse" in dist_lower or "suse" in dist_lower:
            shells.append("zsh")
        elif "alpine" in dist_lower:
            shells.append("ash")

        return shells

    async def configure_agent(
        self,
        distribution: str,
        server_url: str,
        hostname: str,
        server_port: int = 8443,
        use_https: bool = True,
    ) -> Dict[str, Any]:
        """
        Configure sysmanage-agent in a WSL distribution.

        Args:
            distribution: Distribution name
            server_url: URL of the sysmanage server
            hostname: Hostname for this agent
            server_port: Port of the sysmanage server (default 8443)
            use_https: Whether to use HTTPS for server connection (default True)

        Returns:
            Dict with success status
        """
        try:
            creationflags = self._get_creationflags()

            # Derive FQDN if hostname doesn't have a domain
            fqdn_hostname = self.get_fqdn_hostname(hostname, server_url)

            # Get appropriate shells for this distribution
            allowed_shells = self._get_allowed_shells_for_distribution(distribution)
            shells_yaml = "\n".join(f"    - {shell}" for shell in allowed_shells)

            # Create the configuration file with enhanced settings for WSL
            use_https_str = "true" if use_https else "false"
            config_content = f"""# Sysmanage Agent Configuration
# Auto-generated during WSL child host creation

server:
  hostname: "{server_url}"
  port: {server_port}
  use_https: {use_https_str}
  verify_ssl: {use_https_str}

agent:
  hostname_override: "{fqdn_hostname}"

# WebSocket settings - longer ping interval for WSL to reduce overhead
# while staying within the server's "down" detection window
websocket:
  ping_interval: 45
  reconnect_interval: 10

# Script execution settings - run privileged for system management
script_execution:
  enabled: true
  allowed_shells:
{shells_yaml}

# Feature flags - enable all management features
features:
  auto_update: false
  firewall_management: true
  certificate_management: true
  script_execution: true
"""

            # Write configuration file
            # Escape quotes and newlines for shell
            escaped_content = config_content.replace("'", "'\"'\"'")
            config_cmd = f"echo '{escaped_content}' > /etc/sysmanage-agent.yaml"

            result = subprocess.run(  # nosec B603 B607
                ["wsl", "-d", distribution, "--", "sh", "-c", config_cmd],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
                creationflags=creationflags,
            )

            if result.returncode != 0:
                return {
                    "success": False,
                    "error": _("Failed to write agent config: %s")
                    % (result.stderr or result.stdout),
                }

            self.logger.info(
                "Agent configured with server %s, hostname %s",
                server_url,
                fqdn_hostname,
            )
            return {"success": True}

        except Exception as error:
            return {"success": False, "error": str(error)}

    async def start_agent_service(self, distribution: str) -> Dict[str, Any]:
        """
        Start the sysmanage-agent service in a WSL distribution.

        Args:
            distribution: Distribution name

        Returns:
            Dict with success status
        """
        try:
            creationflags = self._get_creationflags()

            # Enable and start the service
            start_cmd = "systemctl enable --now sysmanage-agent || true"

            result = subprocess.run(  # nosec B603 B607
                ["wsl", "-d", distribution, "--", "sh", "-c", start_cmd],
                capture_output=True,
                text=True,
                timeout=60,
                check=False,
                creationflags=creationflags,
            )

            if result.returncode != 0:
                self.logger.warning(
                    "Agent service start may have failed: %s",
                    result.stderr or result.stdout,
                )

            return {"success": True}

        except Exception as error:
            return {"success": False, "error": str(error)}
