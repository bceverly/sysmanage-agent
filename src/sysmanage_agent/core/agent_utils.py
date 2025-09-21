"""
Utility functions for the SysManage agent to reduce main.py complexity.
"""

import asyncio
import logging
import os
import socket
import ssl
import sys
from datetime import datetime, timezone
from typing import Dict, Any

import aiohttp

from src.i18n import _
from src.database.models import Priority, ScriptExecution
from src.database.base import get_database_manager
from src.sysmanage_agent.collection.package_collection import PackageCollector


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


class PackageCollectionScheduler:
    """Handles periodic package collection logic."""

    def __init__(self, agent, logger: logging.Logger):
        self.agent = agent
        self.logger = logger
        self.package_collector = PackageCollector()

    async def perform_package_collection(self) -> bool:
        """
        Perform a single package collection run.
        Returns True if successful, False otherwise.
        """
        if not self.agent.config.is_package_collection_enabled():
            self.logger.debug("Package collection is disabled in configuration")
            return False

        self.logger.info(_("Starting package collection"))
        try:
            success = self.package_collector.collect_all_available_packages()
            if success:
                self.logger.info(_("Package collection completed successfully"))
            else:
                self.logger.warning(_("Package collection completed with some issues"))
            return success
        except Exception as e:
            self.logger.error(_("Error during package collection: %s"), e)
            return False

    async def run_package_collection_loop(self):
        """Main package collection loop."""
        self.logger.debug("Package collection scheduler started")

        if not self.agent.config.is_package_collection_enabled():
            self.logger.info("Package collection is disabled - scheduler will not run")
            return

        # Run collection at startup if configured
        if self.agent.config.is_package_collection_at_startup_enabled():
            self.logger.info("Running initial package collection at startup")
            await self.perform_package_collection()

        package_collection_interval = (
            self.agent.config.get_package_collection_interval()
        )
        last_collection_time = asyncio.get_event_loop().time()

        while self.agent.running:
            try:
                current_time = asyncio.get_event_loop().time()

                # Check if it's time for package collection
                if current_time - last_collection_time >= package_collection_interval:
                    await self.perform_package_collection()
                    last_collection_time = current_time

                # Sleep for a shorter interval to check timing more frequently
                await asyncio.sleep(
                    300
                )  # Check every 5 minutes if it's time for package collection

            except asyncio.CancelledError:
                self.logger.debug("Package collection scheduler cancelled")
                raise
            except Exception as e:
                self.logger.error(_("Package collection scheduler error: %s"), e)
                # Wait before next attempt instead of terminating
                await asyncio.sleep(60)
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

        # Send result back to server (skip for script execution as it sends dedicated result)
        if command_type != "execute_script":
            # Extract standard command result fields, put everything else in result field
            success = result.get("success", True)
            error = result.get("error")
            exit_code = result.get("exit_code")

            # Create a clean result payload - remove standard fields from result data
            result_data = {
                k: v
                for k, v in result.items()
                if k not in ["success", "error", "exit_code"]
            }

            response = self.agent.create_message(
                "command_result",
                {
                    "command_id": command_id,
                    "success": success,
                    "result": result_data if result_data else None,
                    "error": error,
                    "exit_code": exit_code,
                },
            )
            await self.agent.send_message(response)

    def _get_command_handlers(self) -> Dict[str, Any]:
        """Get mapping of command types to their handlers."""
        return {
            "execute_shell": self.agent.execute_shell_command,
            "get_system_info": lambda params: self.agent.get_detailed_system_info(),
            "install_package": self.agent.install_package,
            "install_packages": self.agent.install_packages,  # New UUID-based handler
            "uninstall_packages": self.agent.uninstall_packages,  # New UUID-based uninstall handler
            "update_system": lambda params: self.agent.update_system(),
            "restart_service": self.agent.restart_service,
            "reboot_system": lambda params: self.agent.reboot_system(),
            "shutdown_system": lambda params: self.agent.shutdown_system(),
            "update_os_version": lambda params: self.agent.update_os_version(),
            "update_hardware": lambda params: self.agent.update_hardware(),
            "update_user_access": lambda params: self.agent.update_user_access(),
            "check_updates": lambda params: self.agent.check_updates(),
            "apply_updates": self.agent.apply_updates,
            "ubuntu_pro_attach": self.agent.ubuntu_pro_attach,
            "ubuntu_pro_detach": self.agent.ubuntu_pro_detach,
            "ubuntu_pro_enable_service": self.agent.ubuntu_pro_enable_service,
            "ubuntu_pro_disable_service": self.agent.ubuntu_pro_disable_service,
            "execute_script": self._handle_execute_script,
            "check_reboot_status": lambda params: self.agent.check_reboot_status(),
            "collect_diagnostics": self.agent.collect_diagnostics,
            "collect_available_packages": lambda params: self.agent.collect_available_packages(),
        }

    async def _handle_execute_script(
        self, parameters: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Handle script execution with UUID tracking."""
        # Check if this execution UUID has already been processed
        execution_uuid = parameters.get("execution_uuid")
        if execution_uuid and await self._check_execution_uuid_processed(
            execution_uuid
        ):
            self.logger.warning(
                _("Script execution UUID %s already processed, skipping duplicate"),
                execution_uuid,
            )
            return {
                "success": True,
                "message": "Already processed",
                "duplicate": True,
            }

        # Store the execution UUID before processing
        if execution_uuid:
            await self._store_execution_uuid(parameters)

        result = await self.agent.execute_script(parameters)

        # Send script execution result as a separate message for better tracking
        await self._send_script_execution_result(parameters, result)
        return result

    async def _dispatch_command(
        self, command_type: str, parameters: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Dispatch command to appropriate handler."""
        # Handle generic_command wrapper - unwrap nested commands
        if command_type == "generic_command":
            nested_command_type = parameters.get("command_type")
            nested_parameters = parameters.get("parameters", {})
            self.logger.debug(
                f"Unwrapping generic_command: {nested_command_type} with params: {nested_parameters}"
            )
            if nested_command_type:
                return await self._dispatch_command(
                    nested_command_type, nested_parameters
                )

            return {
                "success": False,
                "error": _("Generic command missing nested command_type"),
            }

        # Get command handlers
        handlers = self._get_command_handlers()
        handler = handlers.get(command_type)

        if handler:
            return await handler(parameters)

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
            execution_uuid = parameters.get("execution_uuid")
            script_name = parameters.get("script_name", "Unknown")

            # Get host_id from database and FQDN from registration system
            host_approval = self.agent.get_host_approval_from_db()
            system_info = self.agent.registration.get_system_info()
            fqdn = system_info.get("fqdn", socket.gethostname())

            # Build script execution result message with host_id and FQDN
            result_message = {
                "message_type": "script_execution_result",
                "hostname": fqdn,  # Use FQDN instead of short hostname
                "execution_id": execution_id,
                "execution_uuid": execution_uuid,  # Include the UUID for tracking
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

            # Add host_id if available (preferred over hostname validation)
            if host_approval and host_approval.host_id:
                result_message["host_id"] = host_approval.host_id

            # Queue the script execution result message with high priority
            await self.agent.message_handler.queue_outbound_message(
                result_message, priority=Priority.HIGH
            )

            self.logger.info(
                _("Queued script execution result for execution_id: %s"), execution_id
            )

        except Exception as e:
            self.logger.error(_("Failed to queue script execution result: %s"), e)

    async def _check_execution_uuid_processed(self, execution_uuid: str) -> bool:
        """Check if an execution UUID has already been processed."""
        try:
            db_manager = get_database_manager()
            session = db_manager.get_session()
            try:
                execution = (
                    session.query(ScriptExecution)
                    .filter(ScriptExecution.execution_uuid == execution_uuid)
                    .first()
                )
                return execution is not None
            finally:
                session.close()
        except Exception as e:
            self.logger.error(_("Error checking execution UUID: %s"), e)
            return False  # Allow processing if we can't check

    async def _store_execution_uuid(self, parameters: Dict[str, Any]):
        """Store execution UUID and metadata in database."""
        try:
            execution_id = parameters.get("execution_id")
            execution_uuid = parameters.get("execution_uuid")
            script_name = parameters.get("script_name", "Unknown")
            shell_type = parameters.get("shell_type")

            if not execution_uuid:
                self.logger.warning(_("No execution UUID provided, cannot track"))
                return

            db_manager = get_database_manager()
            session = db_manager.get_session()
            try:
                # Check if already exists
                existing = (
                    session.query(ScriptExecution)
                    .filter(ScriptExecution.execution_uuid == execution_uuid)
                    .first()
                )

                if existing:
                    self.logger.warning(
                        _("Execution UUID %s already exists in database"),
                        execution_uuid,
                    )
                    return

                # Store new execution record
                execution_record = ScriptExecution(
                    execution_id=execution_id,
                    execution_uuid=execution_uuid,
                    script_name=script_name,
                    shell_type=shell_type,
                    status="pending",
                    received_at=datetime.now(timezone.utc),
                )

                session.add(execution_record)
                session.commit()

                self.logger.info(
                    _("Stored execution UUID %s for tracking"), execution_uuid
                )
            finally:
                session.close()

        except Exception as e:
            self.logger.error(_("Error storing execution UUID: %s"), e)


def is_running_privileged() -> bool:
    """
    Detect if the agent is running with elevated/privileged access.

    Returns:
        bool: True if running with elevated privileges, False otherwise
    """
    try:
        if sys.platform == "win32":
            # Windows - check if running as administrator
            import ctypes  # pylint: disable=import-outside-toplevel

            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        # Unix-like systems - check if running as root (UID 0)
        return os.geteuid() == 0
    except Exception:
        # If we can't determine privilege level, assume non-privileged for security
        return False
