"""
Utility functions for the SysManage agent to reduce main.py complexity.
"""

import asyncio
import logging
import os
import socket
import ssl
import sys
from typing import Dict, Any

import aiohttp

from i18n import _
from database.models import Priority


class UpdateChecker:
    """Handles periodic update checking logic."""

    def __init__(self, agent, logger: logging.Logger):
        self.agent = agent
        self.logger = logger

    async def perform_periodic_check(self) -> bool:
        """
        Perform a single periodic update check.
        Returns True if successful, False otherwise.
        """
        if not (self.agent.running and self.agent.connected):
            return False

        self.logger.info(_("Performing periodic update check"))
        try:
            update_result = await self.agent.check_updates()
            if update_result.get("total_updates", 0) > 0:
                self.logger.info(
                    _("Found %d available updates during periodic check"),
                    update_result["total_updates"],
                )
            return True
        except Exception as e:
            self.logger.error(_("Error during periodic update check: %s"), e)
            return False

    async def run_update_checker_loop(self):
        """Main update checker loop."""
        self.logger.debug("Update checker started")

        update_check_interval = self.agent.config.get_update_check_interval()
        last_check_time = asyncio.get_event_loop().time()

        while self.agent.running:
            try:
                current_time = asyncio.get_event_loop().time()

                # Check if it's time for an update check
                if current_time - last_check_time >= update_check_interval:
                    await self.perform_periodic_check()
                    last_check_time = current_time

                # Sleep for a shorter interval to check timing more frequently
                await asyncio.sleep(
                    60
                )  # Check every minute if it's time for update check

            except asyncio.CancelledError:
                self.logger.debug("Update checker cancelled")
                raise
            except Exception as e:
                self.logger.error(_("Update checker error: %s"), e)
                # Wait before next attempt instead of terminating
                await asyncio.sleep(30)
                continue


class AuthenticationHelper:
    """Handles authentication token management."""

    def __init__(self, agent, logger: logging.Logger):
        self.agent = agent
        self.logger = logger

    def build_auth_url(self) -> str:
        """Build authentication URL from server config."""
        server_config = self.agent.config.get_server_config()
        hostname = server_config.get("hostname", "localhost")
        port = server_config.get("port", 8000)
        use_https = server_config.get("use_https", False)

        protocol = "https" if use_https else "http"
        return f"{protocol}://{hostname}:{port}/agent/auth"

    async def get_auth_token(self) -> str:
        """Get authentication token for WebSocket connection."""
        auth_url = self.build_auth_url()
        server_config = self.agent.config.get_server_config()
        use_https = server_config.get("use_https", False)

        # Set up SSL context if needed
        ssl_context = None
        if use_https:
            ssl_context = ssl.create_default_context()
            if not self.agent.config.should_verify_ssl():
                ssl_context.check_hostname = False
                ssl_context.verify_mode = ssl.CERT_NONE

        # Get hostname to send in header
        system_hostname = socket.gethostname()

        connector = aiohttp.TCPConnector(ssl=ssl_context)
        async with aiohttp.ClientSession(connector=connector) as session:
            headers = {"x-agent-hostname": system_hostname}

            async with session.post(auth_url, headers=headers) as response:
                if response.status == 200:
                    data = await response.json()
                    return data.get("connection_token", "")

                raise ConnectionError(
                    _("Auth failed with status %s: %s")
                    % (response.status, await response.text())
                )


class MessageProcessor:
    """Handles WebSocket message processing."""

    def __init__(self, agent, logger: logging.Logger):
        self.agent = agent
        self.logger = logger

    async def handle_command(self, message: Dict[str, Any]):
        """Handle command from server and send response."""
        command_id = message.get("message_id")
        command_data = message.get("data", {})
        command_type = command_data.get("command_type")
        parameters = command_data.get("parameters", {})

        self.logger.info(
            _("Received command: %s with parameters: %s"), command_type, parameters
        )

        try:
            result = await self._dispatch_command(command_type, parameters)
        except Exception as e:
            result = {"success": False, "error": str(e)}

        # Send result back to server
        response = self.agent.create_message(
            "command_result", {"command_id": command_id, **result}
        )
        await self.agent.send_message(response)

    async def _dispatch_command(
        self, command_type: str, parameters: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Dispatch command to appropriate handler."""
        if command_type == "execute_shell":
            return await self.agent.execute_shell_command(parameters)
        if command_type == "get_system_info":
            return await self.agent.get_detailed_system_info()
        if command_type == "install_package":
            return await self.agent.install_package(parameters)
        if command_type == "update_system":
            return await self.agent.update_system()
        if command_type == "restart_service":
            return await self.agent.restart_service(parameters)
        if command_type == "reboot_system":
            return await self.agent.reboot_system()
        if command_type == "shutdown_system":
            return await self.agent.shutdown_system()
        if command_type == "update_os_version":
            return await self.agent.update_os_version()
        if command_type == "update_hardware":
            return await self.agent.update_hardware()
        if command_type == "update_user_access":
            return await self.agent.update_user_access()
        if command_type == "check_updates":
            return await self.agent.check_updates()
        if command_type == "apply_updates":
            return await self.agent.apply_updates(parameters)
        if command_type == "execute_script":
            result = await self.agent.execute_script(parameters)
            # Send script execution result as a separate message for better tracking
            await self._send_script_execution_result(parameters, result)
            return result
        if command_type == "check_reboot_status":
            return await self.agent.check_reboot_status()
        if command_type == "collect_diagnostics":
            return await self.agent.collect_diagnostics(parameters)

        return {
            "success": False,
            "error": _("Unknown command type: %s") % command_type,
        }

    async def _send_script_execution_result(
        self, parameters: Dict[str, Any], result: Dict[str, Any]
    ):
        """
        Send script execution result as a dedicated high-priority message.

        This ensures script results are properly tracked and queued separately
        from regular command results, improving reliability.
        """
        try:
            # Extract execution details
            execution_id = parameters.get("execution_id")
            script_name = parameters.get("script_name", "Unknown")

            # Build script execution result message
            result_message = {
                "message_type": "script_execution_result",
                "hostname": socket.gethostname(),
                "execution_id": execution_id,
                "script_name": script_name,
                "success": result.get("success", False),
                "exit_code": result.get("exit_code"),
                "stdout": result.get("stdout", ""),
                "stderr": result.get("stderr", ""),
                "execution_time": result.get("execution_time"),
                "shell_used": result.get("shell_used"),
                "error": result.get("error"),
                "timeout": result.get("timeout", False),
                "timestamp": parameters.get("timestamp"),  # Include original timestamp
            }

            # Queue the script execution result message with high priority
            await self.agent.message_handler.queue_outbound_message(
                result_message, priority=Priority.HIGH
            )

            self.logger.info(
                _("Queued script execution result for execution_id: %s"), execution_id
            )

        except Exception as e:
            self.logger.error(_("Failed to queue script execution result: %s"), e)


def is_running_privileged() -> bool:
    """
    Detect if the agent is running with elevated/privileged access.

    Returns:
        bool: True if running with elevated privileges, False otherwise
    """
    try:
        if sys.platform == "win32":
            # Windows - check if running as administrator
            import ctypes

            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        else:
            # Unix-like systems - check if running as root (UID 0)
            return os.geteuid() == 0
    except Exception:
        # If we can't determine privilege level, assume non-privileged for security
        return False
