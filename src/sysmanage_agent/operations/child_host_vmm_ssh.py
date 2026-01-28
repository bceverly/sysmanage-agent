"""
SSH-related operations for VMM VM creation and management.

This module contains helper functions for SSH-based communication with
VMM virtual machines during setup and agent installation.
"""

import asyncio
import time
from typing import Any, Dict, List

from src.i18n import _
from src.sysmanage_agent.core.agent_utils import run_command_async


class VmmSshOperations:
    """SSH operations for VMM VMs."""

    def __init__(self, logger):
        """
        Initialize SSH operations.

        Args:
            logger: Logger instance
        """
        self.logger = logger

    async def wait_for_ssh(
        self, ip_address: str, timeout: int = 300
    ) -> Dict[str, Any]:  # NOSONAR - timeout parameter is part of the established API
        """
        Wait for SSH to become available on the VM.

        Args:
            ip_address: IP address to connect to
            timeout: Maximum time to wait in seconds

        Returns:
            Dict with success status
        """
        start_time = time.time()

        while time.time() - start_time < timeout:
            try:
                # Try to connect to SSH port
                result = await run_command_async(
                    [
                        "nc",
                        "-z",
                        "-w",
                        "5",
                        ip_address,
                        "22",
                    ],
                    timeout=10,
                )

                if result.returncode == 0:
                    self.logger.info(_("SSH is available on %s"), ip_address)
                    # Give sshd a moment to fully initialize
                    await asyncio.sleep(5)
                    return {"success": True}

            except Exception as error:
                self.logger.debug("SSH check error: %s", error)

            await asyncio.sleep(5)

        return {
            "success": False,
            "error": _("Timeout waiting for SSH to become available"),
        }

    async def run_ssh_command(
        self,
        ip_address: str,
        username: str,
        password: str,
        command: str,
    ) -> Dict[str, Any]:
        """
        Run a command on the VM via SSH.

        Uses sshpass for password authentication.

        Args:
            ip_address: VM IP address
            username: SSH username
            password: SSH password
            command: Command to execute

        Returns:
            Dict with success status, stdout, and stderr
        """
        try:
            # Use sshpass for password authentication
            # Note: For production, consider using SSH keys
            result = await run_command_async(
                [
                    "sshpass",
                    "-p",
                    password,
                    "ssh",
                    "-o",
                    "StrictHostKeyChecking=no",
                    "-o",
                    "UserKnownHostsFile=/dev/null",
                    "-o",
                    "ConnectTimeout=30",
                    f"{username}@{ip_address}",
                    command,
                ],
                timeout=300,
            )

            return {
                "success": result.returncode == 0,
                "stdout": result.stdout,
                "stderr": result.stderr,
                "returncode": result.returncode,
                "error": result.stderr if result.returncode != 0 else None,
            }

        except asyncio.TimeoutError:
            return {
                "success": False,
                "error": _("SSH command timed out"),
            }
        except Exception as error:
            return {"success": False, "error": str(error)}

    async def install_agent_via_ssh(
        self,
        ip_address: str,
        username: str,
        password: str,
        commands: List[str],
    ) -> Dict[str, Any]:
        """
        Install sysmanage-agent via SSH.

        Args:
            ip_address: VM IP address
            username: SSH username
            password: SSH password
            commands: List of installation commands

        Returns:
            Dict with success status
        """
        try:
            for cmd in commands:
                self.logger.info(_("Running install command: %s"), cmd)

                # Run command with sudo if not already root
                if username != "root" and not cmd.startswith("sudo"):
                    cmd = f"sudo {cmd}"

                result = await self.run_ssh_command(ip_address, username, password, cmd)

                if not result.get("success"):
                    self.logger.warning(
                        _("Install command failed: %s - %s"),
                        cmd,
                        result.get("stderr") or result.get("error"),
                    )
                    # Continue trying other commands

            return {"success": True}

        except Exception as error:
            return {"success": False, "error": str(error)}

    async def configure_agent_via_ssh(
        self,
        ip_address: str,
        username: str,
        password: str,
        server_url: str,
        hostname: str,
        server_port: int,
        use_https: bool,
    ) -> Dict[str, Any]:
        """
        Configure the sysmanage-agent via SSH.

        Args:
            ip_address: VM IP address
            username: SSH username
            password: SSH password
            server_url: sysmanage server URL
            hostname: VM hostname
            server_port: Server port
            use_https: Whether to use HTTPS

        Returns:
            Dict with success status
        """
        try:
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
    - "ksh"
"""

            # Write config file
            # Use heredoc-style to handle multi-line content
            write_cmd = (
                f"cat > /etc/sysmanage-agent.yaml << 'SYSMANAGE_EOF'\n"
                f"{config_yaml}SYSMANAGE_EOF"
            )

            if username != "root":
                escaped_cmd = write_cmd.replace('"', '\\"')
                write_cmd = f'sudo sh -c "{escaped_cmd}"'

            result = await self.run_ssh_command(
                ip_address, username, password, write_cmd
            )

            if not result.get("success"):
                return {
                    "success": False,
                    "error": _("Failed to write agent config: %s")
                    % result.get("error"),
                }

            return {"success": True}

        except Exception as error:
            return {"success": False, "error": str(error)}

    async def start_agent_service_via_ssh(
        self,
        ip_address: str,
        username: str,
        password: str,
    ) -> Dict[str, Any]:
        """
        Start the sysmanage-agent service via SSH.

        Handles both systemd (Linux) and rcctl (OpenBSD) init systems.

        Args:
            ip_address: VM IP address
            username: SSH username
            password: SSH password

        Returns:
            Dict with success status
        """
        try:
            # First, try to detect the init system
            detect_result = await self.run_ssh_command(
                ip_address, username, password, "which systemctl rcctl 2>/dev/null"
            )

            stdout = detect_result.get("stdout", "")

            if "systemctl" in stdout:
                # Linux with systemd
                start_cmd = "systemctl enable --now sysmanage-agent"
            elif "rcctl" in stdout:
                # OpenBSD with rcctl
                start_cmd = (
                    "rcctl enable sysmanage_agent && rcctl start sysmanage_agent"
                )
            else:
                # Fallback: try systemd first, then rcctl
                start_cmd = (
                    "systemctl enable --now sysmanage-agent 2>/dev/null || "
                    "(rcctl enable sysmanage_agent && rcctl start sysmanage_agent)"
                )

            if username != "root":
                start_cmd = f"sudo sh -c '{start_cmd}'"

            result = await self.run_ssh_command(
                ip_address, username, password, start_cmd
            )

            if not result.get("success"):
                return {
                    "success": False,
                    "error": _("Failed to start agent service: %s")
                    % result.get("error"),
                }

            return {"success": True}

        except Exception as error:
            return {"success": False, "error": str(error)}
