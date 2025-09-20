"""
This module is the main entry point for the SysManage agent that will run
on all clients. It provides real-time bidirectional communication with the
SysManage server using WebSockets with concurrent send/receive operations.
"""

import asyncio
import json
import logging
import os
import platform
import secrets
import socket
import ssl
import uuid
from datetime import datetime, timezone
from typing import Dict, Any

import aiohttp
import websockets
import yaml

from src.sysmanage_agent.core.config import ConfigManager
from src.sysmanage_agent.registration.registration import ClientRegistration
from src.i18n import _, set_language
from src.sysmanage_agent.registration.discovery import discovery_client
from src.security.certificate_store import CertificateStore
from src.sysmanage_agent.utils.verbosity_logger import get_logger
from src.sysmanage_agent.core.agent_utils import (
    UpdateChecker,
    PackageCollectionScheduler,
    AuthenticationHelper,
    MessageProcessor,
    is_running_privileged,
)
from src.sysmanage_agent.operations.update_operations import UpdateOperations
from src.sysmanage_agent.operations.system_operations import SystemOperations
from src.sysmanage_agent.operations.script_operations import ScriptOperations
from src.sysmanage_agent.communication.message_handler import QueuedMessageHandler
from src.sysmanage_agent.collection.update_detection import UpdateDetector
from src.database.init import initialize_database
from src.database.base import get_database_manager
from src.database.models import HostApproval, ScriptExecution, MessageQueue
from src.sysmanage_agent.utils.logging_formatter import UTCTimestampFormatter


class SysManageAgent:  # pylint: disable=too-many-public-methods
    """Main agent class for SysManage fleet management."""

    def __init__(self, config_file: str = "sysmanage-agent.yaml"):
        # Try to discover server if no config file exists
        self.config_file = config_file
        # Setup minimal logging first - our VerbosityLogger will handle most output
        logging.basicConfig(
            level=logging.WARNING
        )  # Only warnings/errors during startup

        self.logger = get_logger(__name__, None)  # Will pass config_manager later
        if not self.try_load_config(config_file):
            self.logger.info(_("No configuration found, attempting auto-discovery..."))
            if not self.auto_discover_and_configure():
                raise RuntimeError(
                    _(
                        "Unable to configure agent: no config file and auto-discovery failed"
                    )
                )

        # Load configuration (now guaranteed to exist)
        self.config = ConfigManager(self.config_file)

        # Set language from configuration
        configured_language = self.config.get_language()
        set_language(configured_language)

        # Setup proper logging with config
        self.setup_logging()

        # Update logger to use config manager for verbosity
        self.logger = get_logger(__name__, self.config)

        # Initialize database
        if not initialize_database(self.config):
            raise RuntimeError(_("Failed to initialize agent database"))

        # Initialize agent properties
        self.agent_id = str(uuid.uuid4())
        self.websocket = None
        self.connected = False
        self.running = False
        self.connection_failures = 0

        # Registration state tracking
        self.registration_status = None
        self.needs_registration = False
        self.last_registration_time = None
        self.registration_confirmed = (
            False  # Track if we have received registration_success
        )

        # Initialize registration handler
        self.registration = ClientRegistration(self.config)

        # Initialize certificate store
        self.cert_store = CertificateStore()

        # Initialize utility classes
        self.update_checker_util = UpdateChecker(self, self.logger)
        self.package_collection_scheduler = PackageCollectionScheduler(
            self, self.logger
        )
        self.auth_helper = AuthenticationHelper(self, self.logger)
        self.message_processor = MessageProcessor(self, self.logger)

        # Initialize operation modules
        self.update_ops = UpdateOperations(self)
        self.system_ops = SystemOperations(self)
        self.script_ops = ScriptOperations(self)

        # Initialize message handler with persistent queues
        self.message_handler = QueuedMessageHandler(self)

        # Get server URL from config
        self.server_url = self.config.get_server_url()

        self.logger.info("%s ID: %s", _("Starting SysManage Agent"), self.agent_id)
        self.logger.info("Server URL: %s", self.server_url)

    def try_load_config(self, config_file: str) -> bool:
        """Try to load configuration file."""
        return os.path.exists(config_file)

    def auto_discover_and_configure(self) -> bool:
        """Auto-discover server and create configuration."""

        # Setup basic logging for discovery process
        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        )

        # Apply UTC timestamp formatter to all handlers
        utc_formatter = UTCTimestampFormatter(
            "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
        )
        for handler in logging.getLogger().handlers:
            handler.setFormatter(utc_formatter)

        logger = logging.getLogger(__name__)

        logger.info("Starting auto-discovery process...")

        try:
            # Discover servers
            discovered_servers = asyncio.run(discovery_client.discover_servers())

            if not discovered_servers:
                logger.error("No SysManage servers found on the network")
                return False

            # Select best server
            best_server = discovery_client.select_best_server(discovered_servers)
            if not best_server:
                logger.error("Unable to select a server from discovered servers")
                return False

            logger.info("Selected server at %s", best_server.get("server_ip"))

            # Create configuration from discovery
            config_data = discovery_client.create_agent_config_from_discovery(
                best_server
            )

            # Write configuration file
            with open(self.config_file, "w", encoding="utf-8") as f:
                yaml.dump(config_data, f, default_flow_style=False, sort_keys=False)

            logger.info("Configuration written to %s", self.config_file)
            return True

        except Exception as e:
            logger.error("Auto-discovery failed: %s", e)
            return False

    def setup_logging(self):
        """Setup logging based on configuration with verbosity support."""
        log_level = self.config.get_log_level()
        log_file = self.config.get_log_file()

        # Clear any existing handlers to prevent double logging
        root_logger = logging.getLogger()
        for handler in root_logger.handlers[:]:
            root_logger.removeHandler(handler)

        # Only set up basic file logging if specified - our VerbosityLogger handles console output
        if log_file:
            file_handler = logging.FileHandler(log_file)
            file_handler.setLevel(getattr(logging, log_level.upper()))
            file_handler.setFormatter(
                UTCTimestampFormatter("%(levelname)s: %(name)s: %(message)s")
            )
            root_logger.addHandler(file_handler)
            root_logger.setLevel(getattr(logging, log_level.upper()))

    def create_message(
        self, message_type: str, data: Dict[str, Any] = None
    ) -> Dict[str, Any]:
        """Create a standardized message."""
        self.logger.debug("AGENT_DEBUG: Creating message of type: %s", message_type)
        message_data = data or {}

        # Include host_id if available and not already present
        if "host_id" not in message_data:
            self.logger.debug(
                "AGENT_DEBUG: No host_id in message_data, attempting to retrieve from database"
            )
            # Skip async context check for now - just proceed with sync approach
            # This code block exists for potential future enhancement
            # where we might handle async context differently

            # For now, we'll get the host_id and host_token synchronously
            stored_host_id = self.get_stored_host_id_sync()
            stored_host_token = self.get_stored_host_token_sync()
            self.logger.debug(
                "AGENT_DEBUG: Retrieved stored_host_id",
            )
            if stored_host_id:
                message_data["host_id"] = stored_host_id
                self.logger.debug(
                    "AGENT_DEBUG: Added host_id %s to message data", stored_host_id
                )
            if stored_host_token:
                message_data["host_token"] = stored_host_token
                self.logger.debug("AGENT_DEBUG: Added host_token to message data")

            if not stored_host_id and not stored_host_token:
                self.logger.debug(
                    "AGENT_DEBUG: No stored host_id or host_token found - message will be sent without authentication"
                )
        else:
            self.logger.debug(
                "AGENT_DEBUG: host_id already present in message_data: %s",
                message_data.get("host_id"),
            )

        message_id = str(uuid.uuid4())
        message = {
            "message_type": message_type,
            "message_id": message_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "data": message_data,
        }

        # Log the final message structure (truncated for large messages)
        data_size = len(str(message_data))
        if data_size > 1000:
            self.logger.debug(
                "AGENT_DEBUG: Created message %s of type %s with %s bytes of data",
                message_id,
                message_type,
                data_size,
            )
        else:
            self.logger.debug(
                "AGENT_DEBUG: Created message %s of type %s with data: %s",
                message_id,
                message_type,
                message_data,
            )

        return message

    def create_system_info_message(self):
        """Create system info message."""
        system_info = self.registration.get_system_info()
        return self.create_message("system_info", system_info)

    async def _check_server_health(self) -> bool:
        """Check if server is available by testing the root endpoint."""
        try:
            # Build health check URL - use base server URL without /api prefix
            # since health check should be unauthenticated
            server_config = self.config.get_server_config()
            hostname = server_config.get("hostname", "localhost")
            port = server_config.get("port", 8000)
            use_https = server_config.get("use_https", False)
            protocol = "https" if use_https else "http"
            http_url = f"{protocol}://{hostname}:{port}"

            # Create SSL context if needed
            ssl_context = None
            if http_url.startswith("https://"):
                ssl_context = ssl.create_default_context()
                if not self.config.should_verify_ssl():
                    ssl_context.check_hostname = False
                    ssl_context.verify_mode = ssl.CERT_NONE

            connector = aiohttp.TCPConnector(ssl=ssl_context)
            timeout = aiohttp.ClientTimeout(total=5)  # 5 second timeout

            async with aiohttp.ClientSession(
                connector=connector, timeout=timeout
            ) as session:
                async with session.get(f"{http_url}/") as response:
                    return response.status == 200
        except Exception as e:
            self.logger.debug("Server health check failed: %s", e)
            return False

    def create_heartbeat_message(self):
        """Create heartbeat message."""
        # Include system info in heartbeat to allow server to recreate deleted hosts
        system_info = self.registration.get_system_info()
        return self.create_message(
            "heartbeat",
            {
                "agent_status": "healthy",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "hostname": system_info["hostname"],
                "ipv4": system_info["ipv4"],
                "ipv6": system_info["ipv6"],
                "is_privileged": is_running_privileged(),
                "script_execution_enabled": self.config.is_script_execution_enabled(),
                "enabled_shells": self.config.get_allowed_shells(),
            },
        )

    async def send_message(self, message: Dict[str, Any]):
        """Send a message to the server using persistent queue."""
        try:
            # Queue message for reliable delivery
            message_id = await self.message_handler.queue_outbound_message(message)
            self.logger.debug(
                "Queued message: %s (ID: %s)", message.get("message_type"), message_id
            )
            return True
        except Exception as e:
            self.logger.error("Failed to queue message: %s", e)
            return False

    async def handle_command(self, message: Dict[str, Any]):
        """Handle command from server."""
        await self.message_processor.handle_command(message)

    async def execute_shell_command(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Execute a shell command."""
        return await self.system_ops.execute_shell_command(parameters)

    async def get_detailed_system_info(self) -> Dict[str, Any]:
        """Get detailed system information."""
        return await self.system_ops.get_detailed_system_info()

    async def install_package(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Install a package using the appropriate package manager."""
        return await self.system_ops.install_package(parameters)

    async def update_system(self) -> Dict[str, Any]:
        """Update the system using the default package manager."""
        return await self.system_ops.update_system()

    async def restart_service(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Restart a system service."""
        return await self.system_ops.restart_service(parameters)

    async def reboot_system(self) -> Dict[str, Any]:
        """Reboot the system."""
        return await self.system_ops.reboot_system()

    async def shutdown_system(self) -> Dict[str, Any]:
        """Shutdown the system."""
        return await self.system_ops.shutdown_system()

    async def ubuntu_pro_attach(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Attach Ubuntu Pro subscription using provided token."""
        return await self.system_ops.ubuntu_pro_attach(parameters)

    async def ubuntu_pro_detach(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Detach Ubuntu Pro subscription."""
        return await self.system_ops.ubuntu_pro_detach(parameters)

    async def ubuntu_pro_enable_service(
        self, parameters: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Enable Ubuntu Pro service."""
        return await self.system_ops.ubuntu_pro_enable_service(parameters)

    async def ubuntu_pro_disable_service(
        self, parameters: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Disable Ubuntu Pro service."""
        return await self.system_ops.ubuntu_pro_disable_service(parameters)

    async def execute_script(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Execute a script with proper security controls."""
        return await self.script_ops.execute_script(parameters)

    async def send_initial_data_updates(self):
        """Send initial data updates after WebSocket connection."""
        try:
            self.logger.info(_("Sending initial OS version data..."))

            # Send OS version data
            self.logger.debug("AGENT_DEBUG: About to collect OS version info")
            os_info = self.registration.get_os_version_info()
            self.logger.debug("AGENT_DEBUG: OS info collected: %s", os_info)
            # Add hostname to OS data for server processing
            system_info = self.registration.get_system_info()
            os_info["hostname"] = system_info["hostname"]
            self.logger.debug("AGENT_DEBUG: OS info with hostname: %s", os_info)
            os_message = self.create_message("os_version_update", os_info)
            self.logger.debug(
                "AGENT_DEBUG: About to send OS version message: %s",
                os_message["message_id"],
            )
            await self.send_message(os_message)
            self.logger.debug("AGENT_DEBUG: OS version message sent successfully")

            # Allow queue processing tasks to run
            await asyncio.sleep(0)

            self.logger.info(_("Sending initial hardware data..."))

            # Send hardware data
            self.logger.debug("AGENT_DEBUG: About to collect hardware info")
            hardware_info = self.registration.get_hardware_info()
            self.logger.debug(
                "AGENT_DEBUG: Hardware info collected with keys: %s",
                list(hardware_info.keys()),
            )
            # Add hostname to hardware data for server processing
            system_info = self.registration.get_system_info()
            hardware_info["hostname"] = system_info["hostname"]
            self.logger.info("Hardware info keys: %s", list(hardware_info.keys()))
            self.logger.info(
                "Storage devices count: %s",
                len(hardware_info.get("storage_devices", [])),
            )
            self.logger.info(
                "Network interfaces count: %s",
                len(hardware_info.get("network_interfaces", [])),
            )
            # Log detailed CPU information
            self.logger.debug(
                "AGENT_DEBUG: CPU vendor: %s", hardware_info.get("cpu_vendor", "N/A")
            )
            self.logger.debug(
                "AGENT_DEBUG: CPU model: %s", hardware_info.get("cpu_model", "N/A")
            )
            self.logger.debug(
                "AGENT_DEBUG: CPU cores: %s", hardware_info.get("cpu_cores", "N/A")
            )
            self.logger.debug(
                "AGENT_DEBUG: Memory total: %s MB",
                hardware_info.get("memory_total_mb", "N/A"),
            )
            hardware_message = self.create_message("hardware_update", hardware_info)
            self.logger.debug(
                "AGENT_DEBUG: About to send hardware message: %s",
                hardware_message["message_id"],
            )
            await self.send_message(hardware_message)
            self.logger.debug("AGENT_DEBUG: Hardware message sent successfully")

            # Allow time for the large hardware message to be sent before sending more data
            await asyncio.sleep(2)

            self.logger.info(_("Sending initial user access data..."))

            # Send user access data
            self.logger.debug("AGENT_DEBUG: About to collect user access info")
            user_access_info = self.registration.get_user_access_info()
            self.logger.debug(
                "AGENT_DEBUG: User access info collected with keys: %s",
                list(user_access_info.keys()),
            )
            # Add hostname to user access data for server processing
            system_info = self.registration.get_system_info()
            user_access_info["hostname"] = system_info["hostname"]
            self.logger.info("User access info keys: %s", list(user_access_info.keys()))
            self.logger.info(
                "Users count: %s",
                user_access_info.get("total_users", 0),
            )
            self.logger.info(
                "Groups count: %s",
                user_access_info.get("total_groups", 0),
            )
            # Log detailed user/group counts
            self.logger.debug(
                "AGENT_DEBUG: Regular users: %s",
                user_access_info.get("regular_users", "N/A"),
            )
            self.logger.debug(
                "AGENT_DEBUG: System users: %s",
                user_access_info.get("system_users", "N/A"),
            )
            self.logger.debug(
                "AGENT_DEBUG: Regular groups: %s",
                user_access_info.get("regular_groups", "N/A"),
            )
            self.logger.debug(
                "AGENT_DEBUG: System groups: %s",
                user_access_info.get("system_groups", "N/A"),
            )
            user_access_message = self.create_message(
                "user_access_update", user_access_info
            )
            self.logger.debug(
                "AGENT_DEBUG: About to send user access message: %s",
                user_access_message["message_id"],
            )
            await self.send_message(user_access_message)
            self.logger.debug("AGENT_DEBUG: User access message sent successfully")

            # Allow time for the large user access message to be sent before sending more data
            await asyncio.sleep(2)

            self.logger.info(_("Sending initial software inventory data..."))

            # Send software inventory data
            self.logger.debug("AGENT_DEBUG: About to collect software inventory info")
            software_info = self.registration.get_software_inventory_info()
            self.logger.debug(
                "AGENT_DEBUG: Software info collected with keys: %s",
                list(software_info.keys()),
            )
            # Add hostname to software inventory data for server processing
            system_info = self.registration.get_system_info()
            software_info["hostname"] = system_info["hostname"]
            self.logger.info(
                "Software inventory info keys: %s", list(software_info.keys())
            )
            self.logger.info(
                "Software packages count: %s",
                software_info.get("total_packages", 0),
            )
            # Log sample software packages
            software_packages = software_info.get("software_packages", [])
            if software_packages:
                self.logger.debug(
                    "AGENT_DEBUG: First 3 software packages: %s", software_packages[:3]
                )
            else:
                self.logger.debug("AGENT_DEBUG: No software packages found!")
            software_message = self.create_message(
                "software_inventory_update", software_info
            )
            self.logger.debug(
                "AGENT_DEBUG: About to send software inventory message: %s",
                software_message["message_id"],
            )
            await self.send_message(software_message)
            self.logger.debug(
                "AGENT_DEBUG: Software inventory message sent successfully"
            )

            self.logger.info(_("Sending initial update check..."))

            # Send initial update check
            try:
                update_result = await self.check_updates()
                if update_result.get("total_updates", 0) > 0:
                    self.logger.info(
                        "Found %d available updates during initial check",
                        update_result["total_updates"],
                    )
                else:
                    self.logger.info("No updates found during initial check")
            except Exception as e:
                self.logger.error("Failed to perform initial update check: %s", e)

            self.logger.info(_("Initial data updates sent successfully"))
        except Exception as e:
            self.logger.error(_("Failed to send initial data updates: %s"), e)

    async def update_os_version(self) -> Dict[str, Any]:
        """Gather and send updated OS version information to the server."""
        try:
            # Get fresh OS version info
            os_info = self.registration.get_os_version_info()
            # Add hostname to OS data for server processing
            system_info = self.registration.get_system_info()
            os_info["hostname"] = system_info["hostname"]

            # Create OS version message
            os_message = self.create_message("os_version_update", os_info)

            # Send OS version update to server
            await self.send_message(os_message)

            return {"success": True, "result": "OS version information sent"}
        except Exception as e:
            self.logger.error("Failed to update OS version: %s", e)
            return {"success": False, "error": str(e)}

    async def update_hardware(self) -> Dict[str, Any]:
        """Gather and send updated hardware information to the server."""
        try:
            # Get fresh hardware info
            hardware_info = self.registration.get_hardware_info()
            # Add hostname to hardware data for server processing
            system_info = self.registration.get_system_info()
            hardware_info["hostname"] = system_info["hostname"]

            # Create hardware message
            hardware_message = self.create_message("hardware_update", hardware_info)

            # Send hardware update to server
            await self.send_message(hardware_message)

            return {"success": True, "result": "Hardware information sent"}
        except Exception as e:
            self.logger.error("Failed to update hardware: %s", e)
            return {"success": False, "error": str(e)}

    async def update_user_access(self) -> Dict[str, Any]:
        """Gather and send updated user access information to the server."""
        try:
            # Get fresh user access info
            user_access_info = self.registration.get_user_access_info()
            # Add hostname to user access data for server processing
            system_info = self.registration.get_system_info()
            user_access_info["hostname"] = system_info["hostname"]

            # Create user access message
            user_access_message = self.create_message(
                "user_access_update", user_access_info
            )

            # Send user access update to server
            await self.send_message(user_access_message)

            return {"success": True, "result": "User access information sent"}
        except Exception as e:
            self.logger.error("Failed to update user access: %s", e)
            return {"success": False, "error": str(e)}

    async def _handle_server_error(self, data: Dict[str, Any]) -> None:
        """Handle error messages from server."""
        error_data = data.get("data", {})
        error_code = error_data.get("error_code", "unknown")
        error_message = error_data.get("error_message", "No error message provided")

        # Check if this is a stale error message
        message_timestamp = data.get("timestamp")
        self.logger.debug(
            "Error message timestamp validation - timestamp: %s, last_registration_time: %s",
            message_timestamp,
            self.last_registration_time,
        )

        if message_timestamp and self.last_registration_time:
            try:
                # Parse the message timestamp
                if isinstance(message_timestamp, str):
                    # Handle ISO format timestamps
                    if message_timestamp.endswith("+00:00"):
                        message_timestamp = message_timestamp[:-6] + "Z"
                    msg_time = datetime.fromisoformat(
                        message_timestamp.replace("Z", "+00:00")
                    )
                else:
                    msg_time = message_timestamp

                # Ensure both timestamps are timezone-aware
                if msg_time.tzinfo is None:
                    msg_time = msg_time.replace(tzinfo=timezone.utc)
                if self.last_registration_time.tzinfo is None:
                    self.last_registration_time = self.last_registration_time.replace(
                        tzinfo=timezone.utc
                    )

                self.logger.debug(
                    "Timestamp comparison - msg_time: %s, last_registration: %s",
                    msg_time,
                    self.last_registration_time,
                )

                # If the error message is older than our last registration, ignore it
                if msg_time < self.last_registration_time:
                    self.logger.info(
                        "Ignoring stale error message [%s] from %s (registration at %s)",
                        error_code,
                        msg_time,
                        self.last_registration_time,
                    )
                    return

                self.logger.debug(
                    "Error message is NOT stale - msg_time: %s >= last_registration: %s",
                    msg_time,
                    self.last_registration_time,
                )
            except (ValueError, TypeError) as e:
                self.logger.warning(
                    "Could not parse message timestamp for stale check: %s", e
                )
        else:
            if not message_timestamp:
                self.logger.debug("No timestamp in error message, processing normally")
            if not self.last_registration_time:
                self.logger.debug(
                    "No last_registration_time set, processing error normally"
                )

        self.logger.error("Server error [%s]: %s", error_code, error_message)

        # Handle specific error codes from server
        if error_code == "host_not_registered":
            await self._handle_host_not_registered()
        elif error_code == "host_not_approved":
            self.logger.warning(
                "Host registration is pending approval. Will continue periodic attempts."
            )
        elif error_code == "missing_hostname":
            self.logger.error(
                "Server reports missing hostname in message. This is a bug."
            )
        elif error_code == "queue_error":
            self.logger.error("Server failed to queue message: %s", error_message)

    async def _handle_host_not_registered(self) -> None:
        """Handle host_not_registered error by clearing state and triggering re-registration."""
        self.logger.warning(
            "Server reports host is not registered. Clearing stored host_id and triggering re-registration..."
        )

        # Clear stored host_id from database
        try:
            await self.clear_stored_host_id()
            self.logger.info("Stored host_id cleared from database")
        except Exception as e:
            self.logger.error("Error clearing stored host_id: %s", e)

        # Clear any existing registration state and force re-registration
        self.registration_status = None
        self.registration_confirmed = False
        self.registration.registered = False
        # Schedule re-registration on next connection attempt
        self.needs_registration = True
        # Disconnect immediately to trigger reconnection with re-registration
        self.logger.info("Disconnecting to trigger re-registration...")
        self.running = False

    async def message_receiver(self):
        """Handle incoming messages from server."""
        self.logger.debug("Message receiver started")
        try:
            while self.running:
                message = await self.websocket.recv()
                self.logger.debug("Received: %s", message)

                try:
                    data = json.loads(message)
                    message_type = data.get("message_type")

                    if message_type == "command":
                        await self.handle_command(data)
                    elif message_type == "ping":
                        # Respond to ping
                        pong = self.create_message(
                            "pong", {"ping_id": data.get("message_id")}
                        )
                        await self.send_message(pong)
                    elif message_type == "ack":
                        ack_data = data.get("data", {})
                        # Try to get the queue_id or message_id that was acknowledged
                        queue_id = data.get("queue_id")
                        acked_msg_id = (
                            ack_data.get("acked_message_id")
                            or ack_data.get("message_id")
                            or data.get("message_id", "unknown")
                        )
                        status = data.get("status", "unknown")

                        if queue_id:
                            self.logger.debug(
                                "Server acknowledged message queue_id: %s (status: %s)",
                                queue_id,
                                status,
                            )
                        else:
                            self.logger.debug(
                                "Server acknowledged message: %s (status: %s)",
                                acked_msg_id,
                                status,
                            )
                    elif message_type == "error":
                        await self._handle_server_error(data)
                        if self.needs_registration:
                            return
                    elif message_type == "host_approved":
                        await self.handle_host_approval(data)
                    elif message_type == "registration_success":
                        await self.handle_registration_success(data)
                    elif message_type == "diagnostic_result_ack":
                        status = data.get("status", "unknown")
                        self.logger.debug(
                            "Server confirmed diagnostic processing: %s", status
                        )
                    else:
                        self.logger.warning("Unknown message type: %s", message_type)

                except json.JSONDecodeError:
                    self.logger.error("Invalid JSON received: %s", message)
                except Exception as e:
                    self.logger.error("Error processing message: %s", e)

        except websockets.ConnectionClosed:
            self.logger.info(
                "WEBSOCKET_COMMUNICATION_ERROR: Connection to server closed"
            )
            self.connected = False
            self.websocket = None
        except Exception as e:
            self.logger.error("WEBSOCKET_UNKNOWN_ERROR: Message receiver error: %s", e)
            self.connected = False
            self.websocket = None

    async def message_sender(self):
        """Handle periodic outgoing messages to server."""
        self.logger.debug("Message sender started")

        # Send initial system info
        system_info = self.create_system_info_message()
        await self.send_message(system_info)

        # Send periodic heartbeats
        ping_interval = self.config.get_ping_interval()
        while self.running:
            try:
                await asyncio.sleep(ping_interval)
                if self.running and self.connected:
                    heartbeat = self.create_heartbeat_message()
                    success = await self.send_message(heartbeat)
                    if not success:
                        self.logger.warning("Heartbeat failed, connection may be lost")
                        # Don't break, let the connection handling in run() deal with it
                        return
            except asyncio.CancelledError:
                # Graceful shutdown - re-raise to propagate cancellation
                self.logger.debug("Message sender cancelled")
                raise
            except Exception as e:
                self.logger.error("Message sender error: %s", e)
                # Don't break the loop on non-critical errors, but return to trigger reconnection
                return

    async def update_checker(self):
        """Handle periodic update checking."""
        await self.update_checker_util.run_update_checker_loop()

    async def data_collector(self):
        """Handle periodic data collection and sending."""
        self.logger.debug("Data collector started")

        # Send periodic data updates every 5 minutes
        data_collection_interval = 300  # 5 minutes

        while self.running:
            try:
                await asyncio.sleep(data_collection_interval)
                if self.running and self.connected:
                    self.logger.debug("AGENT_DEBUG: Starting periodic data collection")

                    # Send software inventory update
                    try:
                        self.logger.debug(
                            "AGENT_DEBUG: Collecting software inventory data"
                        )
                        software_info = self.registration.get_software_inventory_info()
                        software_info["hostname"] = self.registration.get_system_info()[
                            "hostname"
                        ]

                        # Add host_id if available
                        host_approval = self.get_host_approval_from_db()
                        if host_approval:
                            software_info["host_id"] = host_approval.host_id

                        software_message = self.create_message(
                            "software_inventory_update", software_info
                        )

                        self.logger.debug(
                            "AGENT_DEBUG: Sending periodic software inventory message: %s",
                            software_message["message_id"],
                        )
                        success = await self.send_message(software_message)
                        if success:
                            self.logger.debug(
                                "AGENT_DEBUG: Periodic software inventory sent successfully"
                            )
                        else:
                            self.logger.warning(
                                "Failed to send periodic software inventory data"
                            )

                    except Exception as e:
                        self.logger.error(
                            "Error collecting/sending software inventory: %s", e
                        )

                    # Send user access update
                    try:
                        self.logger.debug("AGENT_DEBUG: Collecting user access data")
                        user_info = self.registration.get_user_access_info()
                        user_info["hostname"] = self.registration.get_system_info()[
                            "hostname"
                        ]

                        # Add host_id if available
                        host_approval = self.get_host_approval_from_db()
                        if host_approval:
                            user_info["host_id"] = host_approval.host_id

                        user_message = self.create_message(
                            "user_access_update", user_info
                        )

                        self.logger.debug(
                            "AGENT_DEBUG: Sending periodic user access message: %s",
                            user_message["message_id"],
                        )
                        success = await self.send_message(user_message)
                        if success:
                            self.logger.debug(
                                "AGENT_DEBUG: Periodic user access data sent successfully"
                            )
                        else:
                            self.logger.warning(
                                "Failed to send periodic user access data"
                            )

                    except Exception as e:
                        self.logger.error(
                            "Error collecting/sending user access data: %s", e
                        )

                    # Send hardware update (if hardware info has changed)
                    try:
                        self.logger.debug("AGENT_DEBUG: Collecting hardware data")
                        hardware_info = self.registration.get_hardware_info()
                        hardware_info["hostname"] = self.registration.get_system_info()[
                            "hostname"
                        ]

                        # Add host_id if available
                        host_approval = self.get_host_approval_from_db()
                        if host_approval:
                            hardware_info["host_id"] = host_approval.host_id

                        hardware_message = self.create_message(
                            "hardware_update", hardware_info
                        )

                        self.logger.debug(
                            "AGENT_DEBUG: Sending periodic hardware message: %s",
                            hardware_message["message_id"],
                        )
                        success = await self.send_message(hardware_message)
                        if success:
                            self.logger.debug(
                                "AGENT_DEBUG: Periodic hardware data sent successfully"
                            )
                        else:
                            self.logger.warning("Failed to send periodic hardware data")

                    except Exception as e:
                        self.logger.error(
                            "Error collecting/sending hardware data: %s", e
                        )

                    # Send OS version update
                    try:
                        self.logger.debug(
                            "AGENT_DEBUG: About to collect OS version info"
                        )
                        os_info = self.registration.get_os_version_info()
                        self.logger.debug("AGENT_DEBUG: OS info collected: %s", os_info)

                        os_message = {
                            "message_type": "os_version_update",
                            "message_id": str(uuid.uuid4()),
                            "timestamp": datetime.now(timezone.utc).isoformat(),
                            "data": os_info,
                        }

                        self.logger.debug(
                            "AGENT_DEBUG: Sending periodic OS version message: %s",
                            os_message["message_id"],
                        )
                        success = await self.send_message(os_message)

                        if success:
                            self.logger.debug(
                                "AGENT_DEBUG: Periodic OS version data sent successfully"
                            )
                        else:
                            self.logger.warning(
                                "Failed to send periodic OS version data"
                            )

                    except Exception as e:
                        self.logger.error(
                            "Error collecting/sending OS version data: %s", e
                        )

                    self.logger.debug("AGENT_DEBUG: Periodic data collection completed")

            except asyncio.CancelledError:
                # Graceful shutdown - re-raise to propagate cancellation
                self.logger.debug("Data collector cancelled")
                raise
            except Exception as e:
                self.logger.error("Data collector error: %s", e)
                # Don't break the loop on non-critical errors, but return to trigger reconnection
                return

    async def package_collector(self):
        """Handle periodic package collection."""
        await self.package_collection_scheduler.run_package_collection_loop()

    async def get_auth_token(self) -> str:
        """Get authentication token for WebSocket connection."""
        return await self.auth_helper.get_auth_token()

    async def fetch_certificates(self, host_id: int) -> bool:
        """Fetch certificates from server after approval."""
        try:
            server_config = self.config.get_server_config()
            hostname = server_config.get("hostname", "localhost")
            port = server_config.get("port", 8000)
            use_https = server_config.get("use_https", False)

            # Build certificate URL - authenticated endpoint requires /api prefix
            protocol = "https" if use_https else "http"
            cert_url = (
                f"{protocol}://{hostname}:{port}/api/certificates/client/{host_id}"
            )

            # Set up SSL context if needed
            ssl_context = None
            if use_https:
                ssl_context = ssl.create_default_context()
                if not self.config.should_verify_ssl():
                    ssl_context.check_hostname = False
                    ssl_context.verify_mode = ssl.CERT_NONE

            # Get authentication token
            auth_token = await self.get_auth_token()

            connector = aiohttp.TCPConnector(ssl=ssl_context)
            async with aiohttp.ClientSession(connector=connector) as session:
                headers = {"Authorization": f"Bearer {auth_token}"}

                async with session.get(cert_url, headers=headers) as response:
                    if response.status == 200:
                        cert_data = await response.json()
                        self.cert_store.store_certificates(cert_data)
                        self.logger.info(
                            "Certificates retrieved and stored successfully"
                        )
                        return True
                    if response.status == 403:
                        self.logger.warning(
                            "Host not yet approved for certificate retrieval"
                        )
                        return False
                    self.logger.error(
                        "Failed to fetch certificates: HTTP %s", response.status
                    )
                    return False

        except Exception as e:
            self.logger.error("Error fetching certificates: %s", e)
            return False

    async def ensure_certificates(self) -> bool:
        """Ensure agent has valid certificates for mTLS."""
        # Check if we already have valid certificates
        if self.cert_store.has_certificates():
            self.logger.debug("Valid certificates already available")
            return True

        # If no certificates, we need to check if host is approved and fetch them
        self.logger.info(
            "No valid certificates found, checking host approval status..."
        )

        # Get server fingerprint first for security validation
        try:
            server_config = self.config.get_server_config()
            hostname = server_config.get("hostname", "localhost")
            port = server_config.get("port", 8000)
            use_https = server_config.get("use_https", False)

            protocol = "https" if use_https else "http"
            fingerprint_url = (
                f"{protocol}://{hostname}:{port}/certificates/server-fingerprint"
            )

            ssl_context = None
            if use_https:
                ssl_context = ssl.create_default_context()
                if not self.config.should_verify_ssl():
                    ssl_context.check_hostname = False
                    ssl_context.verify_mode = ssl.CERT_NONE

            connector = aiohttp.TCPConnector(ssl=ssl_context)
            async with aiohttp.ClientSession(connector=connector) as session:
                async with session.get(fingerprint_url) as response:
                    if response.status == 200:
                        data = await response.json()
                        server_fingerprint = data.get("fingerprint")
                        self.logger.info(
                            "Retrieved server fingerprint for validation: %s",
                            "***REDACTED***" if server_fingerprint else "None",
                        )
                        # We'll store it when we get the full cert data

        except Exception as e:
            self.logger.error("Failed to get server fingerprint: %s", type(e).__name__)
            return False

        # Check if we can find our host ID from previous registration
        # This is a simplified approach - in a real implementation you might
        # store the host ID during registration
        system_info = self.registration.get_system_info()
        hostname = system_info["hostname"]

        # For now, we'll try to fetch with a known host ID or wait for manual approval
        # This would be improved with a more sophisticated approval checking mechanism
        self.logger.warning(
            "Certificate-based authentication requires manual host approval"
        )
        self.logger.warning("Please approve this host in the SysManage web interface")
        return False

    async def check_updates(self) -> Dict[str, Any]:
        """Check for available updates for installed packages."""
        return await self.update_ops.check_updates()

    async def apply_updates(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Apply updates for specified packages."""
        return await self.update_ops.apply_updates(parameters)

    async def check_reboot_status(self) -> Dict[str, Any]:
        """Check if the system requires a reboot."""
        try:
            detector = UpdateDetector()
            requires_reboot = detector.check_reboot_required()

            result = {
                "success": True,
                "reboot_required": requires_reboot,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }

            # Send reboot status update to server
            await self.send_reboot_status_update(requires_reboot)

            return result

        except Exception as e:
            self.logger.error(_("Failed to check reboot status: %s"), e)
            return {
                "success": False,
                "error": str(e),
                "reboot_required": False,
            }

    async def send_reboot_status_update(self, requires_reboot: bool) -> None:
        """Send reboot status update to server."""
        try:
            self.logger.info(_("Sending reboot status update: %s"), requires_reboot)

            # Get hostname for server processing
            system_info = self.registration.get_system_info()
            hostname = system_info.get("hostname", "unknown")

            reboot_data = {
                "hostname": hostname,
                "reboot_required": requires_reboot,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }

            reboot_message = self.create_message("reboot_status_update", reboot_data)
            await self.send_message(reboot_message)

            self.logger.debug("Reboot status message sent successfully")

        except Exception as e:
            self.logger.error(_("Failed to send reboot status update: %s"), e)

    async def collect_diagnostics(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Collect system diagnostics and send to server."""
        try:
            collection_id = parameters.get("collection_id")
            collection_types = parameters.get("collection_types", [])

            self.logger.info(
                _("Starting diagnostics collection for ID: %s"), collection_id
            )
            self.logger.info(_("Collection types requested: %s"), collection_types)

            # Dictionary to store collected data
            system_info = self.registration.get_system_info()
            diagnostic_data = {
                "collection_id": collection_id,
                "success": True,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "hostname": system_info["hostname"],
            }

            # Collect requested diagnostic data
            for i, collection_type in enumerate(collection_types, 1):
                try:
                    self.logger.info(
                        _("Starting collection %d/%d: %s"),
                        i,
                        len(collection_types),
                        collection_type,
                    )
                    start_time = datetime.now(timezone.utc)

                    if collection_type == "system_logs":
                        self.logger.info("Collecting system logs...")
                        diagnostic_data["system_logs"] = (
                            await self._collect_system_logs()
                        )
                    elif collection_type == "configuration_files":
                        self.logger.info("Collecting configuration files...")
                        diagnostic_data["configuration_files"] = (
                            await self._collect_configuration_files()
                        )
                    elif collection_type == "network_info":
                        self.logger.info("Collecting network information...")
                        diagnostic_data["network_info"] = (
                            await self._collect_network_info()
                        )
                    elif collection_type == "process_info":
                        self.logger.info("Collecting process information...")
                        diagnostic_data["process_info"] = (
                            await self._collect_process_info()
                        )
                    elif collection_type == "disk_usage":
                        self.logger.info("Collecting disk usage information...")
                        diagnostic_data["disk_usage"] = await self._collect_disk_usage()
                    elif collection_type == "environment_variables":
                        self.logger.info("Collecting environment variables...")
                        diagnostic_data["environment_variables"] = (
                            await self._collect_environment_variables()
                        )
                    elif collection_type == "agent_logs":
                        self.logger.info("Collecting agent logs...")
                        diagnostic_data["agent_logs"] = await self._collect_agent_logs()
                    elif collection_type == "error_logs":
                        self.logger.info("Collecting error logs...")
                        diagnostic_data["error_logs"] = await self._collect_error_logs()
                    else:
                        self.logger.warning(
                            _("Unknown collection type: %s"), collection_type
                        )
                        continue

                    elapsed = (datetime.now(timezone.utc) - start_time).total_seconds()
                    self.logger.info(
                        _("Completed collection of %s in %.2f seconds"),
                        collection_type,
                        elapsed,
                    )

                except Exception as e:
                    elapsed = (datetime.now(timezone.utc) - start_time).total_seconds()
                    self.logger.error(
                        _("Failed to collect %s after %.2f seconds: %s"),
                        collection_type,
                        elapsed,
                        e,
                    )
                    # Continue collecting other types even if one fails

            # Calculate collection statistics
            self.logger.info("Calculating collection statistics...")
            collection_size = 0
            files_collected = 0
            for key, value in diagnostic_data.items():
                if isinstance(value, (dict, list)) and key != "collection_id":
                    collection_size += len(str(value))
                    if isinstance(value, dict) and "files" in value:
                        files_collected += len(value.get("files", []))
                    elif isinstance(value, list):
                        files_collected += len(value)

            diagnostic_data["collection_size_bytes"] = collection_size
            diagnostic_data["files_collected"] = files_collected

            self.logger.info(
                "Collection statistics: %d bytes, %d files/entries collected",
                collection_size,
                files_collected,
            )

            # Send diagnostic data to server
            self.logger.info("Preparing to send diagnostic data to server...")
            send_start_time = datetime.now(timezone.utc)
            diagnostic_message = self.create_message(
                "diagnostic_collection_result", diagnostic_data
            )

            self.logger.info(
                "Sending diagnostic message (ID: %s)...",
                diagnostic_message.get("message_id"),
            )
            await self.send_message(diagnostic_message)

            send_elapsed = (
                datetime.now(timezone.utc) - send_start_time
            ).total_seconds()
            self.logger.info("Diagnostic message sent in %.2f seconds", send_elapsed)

            self.logger.info(
                _("Diagnostics collection completed for ID: %s"), collection_id
            )

            return {
                "success": True,
                "collection_id": collection_id,
                "message": "Diagnostics collected and sent to server",
            }

        except Exception as e:
            self.logger.error(_("Failed to collect diagnostics: %s"), e)

            # Send error result to server if we have collection_id
            if parameters.get("collection_id"):
                system_info = self.registration.get_system_info()
                error_data = {
                    "collection_id": parameters["collection_id"],
                    "success": False,
                    "error": str(e),
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "hostname": system_info["hostname"],
                }
                try:
                    error_message = self.create_message(
                        "diagnostic_collection_result", error_data
                    )
                    await self.send_message(error_message)
                except Exception as send_error:
                    self.logger.error(_("Failed to send error message: %s"), send_error)

            return {"success": False, "error": str(e)}

    async def collect_available_packages(self) -> Dict[str, Any]:
        """Collect and return available packages from all package managers."""
        try:
            # Trigger package collection
            success = (
                await self.package_collection_scheduler.perform_package_collection()
            )
            if not success:
                return {"success": False, "error": "Package collection failed"}

            # Get packages for transmission
            packages = (
                self.package_collection_scheduler.package_collector.get_packages_for_transmission()
            )

            # Get current OS information from registration system
            system_info = self.registration.get_system_info()
            os_info = system_info.get("os_info", {})

            # Determine OS name and version
            os_name = os_info.get("distribution", "Unknown")
            os_version = os_info.get("distribution_version", "Unknown")

            return {
                "success": True,
                "packages": packages,
                "package_managers": packages,  # Server expects this key name
                "os_name": os_name,
                "os_version": os_version,
                "hostname": system_info.get("hostname", socket.gethostname()),
                "total_packages": sum(len(pkg_list) for pkg_list in packages.values()),
            }
        except Exception as e:
            self.logger.error(_("Error collecting available packages: %s"), e)
            return {"success": False, "error": str(e)}

    async def _collect_system_logs(self) -> Dict[str, Any]:
        """Collect system log information."""
        try:
            system_logs = {}
            current_platform = platform.system()

            if current_platform == "Windows":
                # Get Windows Event Log entries
                self.logger.info(
                    "Collecting Windows System Event Log (this may take 10-30 seconds)..."
                )
                start_time = datetime.now(timezone.utc)
                result = await self.system_ops.execute_shell_command(
                    {
                        "command": 'powershell -Command "Get-WinEvent -LogName System -MaxEvents 100 | Select-Object TimeCreated, LevelDisplayName, Id, TaskDisplayName, Message | ConvertTo-Json"'
                    }
                )
                elapsed = (datetime.now(timezone.utc) - start_time).total_seconds()
                if result.get("success"):
                    system_logs["windows_system_log"] = result.get("result", {}).get(
                        "stdout", ""
                    )
                    self.logger.info(
                        "Windows System Event Log collected in %.2f seconds", elapsed
                    )
                else:
                    self.logger.warning(
                        "Windows System Event Log collection failed after %.2f seconds",
                        elapsed,
                    )

                # Get Application Event Log entries
                self.logger.info("Collecting Windows Application Event Log...")
                start_time = datetime.now(timezone.utc)
                result = await self.system_ops.execute_shell_command(
                    {
                        "command": 'powershell -Command "Get-WinEvent -LogName Application -MaxEvents 50 | Select-Object TimeCreated, LevelDisplayName, Id, TaskDisplayName, Message | ConvertTo-Json"'
                    }
                )
                elapsed = (datetime.now(timezone.utc) - start_time).total_seconds()
                if result.get("success"):
                    system_logs["windows_application_log"] = result.get(
                        "result", {}
                    ).get("stdout", "")
                    self.logger.info(
                        "Windows Application Event Log collected in %.2f seconds",
                        elapsed,
                    )
                else:
                    self.logger.warning(
                        "Windows Application Event Log collection failed after %.2f seconds",
                        elapsed,
                    )

                # Get Security Event Log entries (may require admin privileges)
                self.logger.info(
                    "Collecting Windows Security Event Log (may require admin privileges)..."
                )
                start_time = datetime.now(timezone.utc)
                result = await self.system_ops.execute_shell_command(
                    {
                        "command": "powershell -Command \"try { Get-WinEvent -LogName Security -MaxEvents 50 | Select-Object TimeCreated, LevelDisplayName, Id, TaskDisplayName, Message | ConvertTo-Json } catch { 'Security logs not accessible - admin privileges required' }\""
                    }
                )
                elapsed = (datetime.now(timezone.utc) - start_time).total_seconds()
                if result.get("success"):
                    system_logs["windows_security_log"] = result.get("result", {}).get(
                        "stdout", ""
                    )
                    self.logger.info(
                        "Windows Security Event Log collected in %.2f seconds", elapsed
                    )
                else:
                    self.logger.warning(
                        "Windows Security Event Log collection failed after %.2f seconds",
                        elapsed,
                    )

            else:
                # Linux/Unix systems
                # Try to get recent system log entries
                result = await self.system_ops.execute_shell_command(
                    {"command": "journalctl --since '1 hour ago' --no-pager -n 100"}
                )
                if result.get("success"):
                    system_logs["journalctl_recent"] = result.get("result", {}).get(
                        "stdout", ""
                    )

                # Get kernel messages
                result = await self.system_ops.execute_shell_command(
                    {"command": "dmesg | tail -n 50"}
                )
                if result.get("success"):
                    system_logs["dmesg_recent"] = result.get("result", {}).get(
                        "stdout", ""
                    )

                # Get auth log if available
                result = await self.system_ops.execute_shell_command(
                    {
                        "command": "tail -n 50 /var/log/auth.log 2>/dev/null || tail -n 50 /var/log/secure 2>/dev/null || echo 'Auth logs not accessible'"
                    }
                )
                if result.get("success"):
                    system_logs["auth_log"] = result.get("result", {}).get("stdout", "")

            return system_logs

        except Exception as e:
            self.logger.error(_("Error collecting system logs: %s"), e)
            return {"error": str(e)}

    async def _collect_configuration_files(self) -> Dict[str, Any]:
        """Collect relevant configuration files."""
        try:
            config_files = {}
            current_platform = platform.system()

            if current_platform == "Windows":
                # Get Windows network configuration
                result = await self.system_ops.execute_shell_command(
                    {"command": "ipconfig /all"}
                )
                if result.get("success"):
                    config_files["network_config"] = result.get("result", {}).get(
                        "stdout", ""
                    )

                # Get Windows services configuration (key system services)
                result = await self.system_ops.execute_shell_command(
                    {
                        "command": "powershell -Command \"Get-Service | Where-Object {$_.Status -eq 'Running'} | Select-Object Name, Status, StartType | ConvertTo-Json\""
                    }
                )
                if result.get("success"):
                    config_files["services_config"] = result.get("result", {}).get(
                        "stdout", ""
                    )

                # Get Windows firewall configuration
                result = await self.system_ops.execute_shell_command(
                    {"command": "netsh advfirewall show allprofiles"}
                )
                if result.get("success"):
                    config_files["firewall_config"] = result.get("result", {}).get(
                        "stdout", ""
                    )

            else:
                # Linux/Unix systems
                # Get network configuration
                result = await self.system_ops.execute_shell_command(
                    {
                        "command": "cat /etc/network/interfaces 2>/dev/null || cat /etc/sysconfig/network-scripts/ifcfg-* 2>/dev/null || echo 'Network config not found'"
                    }
                )
                if result.get("success"):
                    config_files["network_config"] = result.get("result", {}).get(
                        "stdout", ""
                    )

                # Get SSH configuration
                result = await self.system_ops.execute_shell_command(
                    {
                        "command": "cat /etc/ssh/sshd_config 2>/dev/null || echo 'SSH config not accessible'"
                    }
                )
                if result.get("success"):
                    config_files["ssh_config"] = result.get("result", {}).get(
                        "stdout", ""
                    )

            # Get agent configuration (our own config) - works on both platforms
            try:
                with open("config.yaml", "r", encoding="utf-8") as f:
                    config_files["agent_config"] = f.read()
            except Exception:
                config_files["agent_config"] = "Agent config not readable"

            return config_files

        except Exception as e:
            self.logger.error(_("Error collecting configuration files: %s"), e)
            return {"error": str(e)}

    async def _collect_network_info(self) -> Dict[str, Any]:
        """Collect network information."""
        try:
            network_info = {}
            current_platform = platform.system()

            if current_platform == "Windows":
                # Get network interfaces
                self.logger.info("Collecting network interfaces (ipconfig /all)...")
                start_time = datetime.now(timezone.utc)
                result = await self.system_ops.execute_shell_command(
                    {"command": "ipconfig /all"}
                )
                elapsed = (datetime.now(timezone.utc) - start_time).total_seconds()
                if result.get("success"):
                    network_info["interfaces"] = result.get("result", {}).get(
                        "stdout", ""
                    )
                    self.logger.info(
                        "Network interfaces collected in %.2f seconds", elapsed
                    )
                else:
                    self.logger.warning(
                        "Network interfaces collection failed after %.2f seconds",
                        elapsed,
                    )

                # Get routing table
                self.logger.info("Collecting routing table (route print)...")
                start_time = datetime.now(timezone.utc)
                result = await self.system_ops.execute_shell_command(
                    {"command": "route print"}
                )
                elapsed = (datetime.now(timezone.utc) - start_time).total_seconds()
                if result.get("success"):
                    network_info["routes"] = result.get("result", {}).get("stdout", "")
                    self.logger.info("Routing table collected in %.2f seconds", elapsed)
                else:
                    self.logger.warning(
                        "Routing table collection failed after %.2f seconds", elapsed
                    )

                # Get network connections
                self.logger.info("Collecting network connections (netstat -an)...")
                start_time = datetime.now(timezone.utc)
                result = await self.system_ops.execute_shell_command(
                    {"command": "netstat -an"}
                )
                elapsed = (datetime.now(timezone.utc) - start_time).total_seconds()
                if result.get("success"):
                    network_info["connections"] = result.get("result", {}).get(
                        "stdout", ""
                    )
                    self.logger.info(
                        "Network connections collected in %.2f seconds", elapsed
                    )
                else:
                    self.logger.warning(
                        "Network connections collection failed after %.2f seconds",
                        elapsed,
                    )

                # Get DNS configuration (using safer command)
                self.logger.info(
                    "Collecting DNS configuration (ipconfig /displaydns)..."
                )
                start_time = datetime.now(timezone.utc)
                result = await self.system_ops.execute_shell_command(
                    {"command": "ipconfig /displaydns"}
                )
                elapsed = (datetime.now(timezone.utc) - start_time).total_seconds()
                if result.get("success"):
                    network_info["dns_config"] = result.get("result", {}).get(
                        "stdout", ""
                    )
                    self.logger.info(
                        "DNS configuration collected in %.2f seconds", elapsed
                    )
                else:
                    # Fallback to getting DNS servers from network adapters
                    self.logger.info("Trying alternative DNS configuration method...")
                    start_time = datetime.now(timezone.utc)
                    result = await self.system_ops.execute_shell_command(
                        {
                            "command": 'powershell -Command "Get-DnsClientServerAddress | ConvertTo-Json"'
                        }
                    )
                    elapsed = (datetime.now(timezone.utc) - start_time).total_seconds()
                    if result.get("success"):
                        network_info["dns_config"] = result.get("result", {}).get(
                            "stdout", ""
                        )
                        self.logger.info(
                            "DNS configuration (alternative) collected in %.2f seconds",
                            elapsed,
                        )
                    else:
                        self.logger.warning(
                            "DNS configuration collection failed after %.2f seconds",
                            elapsed,
                        )
                        network_info["dns_config"] = "DNS configuration not available"

            else:
                # Linux/Unix systems
                # Get network interfaces
                result = await self.system_ops.execute_shell_command(
                    {"command": "ip addr show"}
                )
                if result.get("success"):
                    network_info["interfaces"] = result.get("result", {}).get(
                        "stdout", ""
                    )

                # Get routing table
                result = await self.system_ops.execute_shell_command(
                    {"command": "ip route show"}
                )
                if result.get("success"):
                    network_info["routes"] = result.get("result", {}).get("stdout", "")

                # Get network connections
                result = await self.system_ops.execute_shell_command(
                    {"command": "ss -tulpn"}
                )
                if result.get("success"):
                    network_info["connections"] = result.get("result", {}).get(
                        "stdout", ""
                    )

                # Get DNS configuration
                result = await self.system_ops.execute_shell_command(
                    {
                        "command": "cat /etc/resolv.conf 2>/dev/null || echo 'DNS config not accessible'"
                    }
                )
                if result.get("success"):
                    network_info["dns_config"] = result.get("result", {}).get(
                        "stdout", ""
                    )

            return network_info

        except Exception as e:
            self.logger.error(_("Error collecting network info: %s"), e)
            return {"error": str(e)}

    async def _collect_process_info(self) -> Dict[str, Any]:
        """Collect process information."""
        try:
            process_info = {}

            # Get process list
            result = await self.system_ops.execute_shell_command(
                {"command": "ps aux --sort=-%cpu | head -n 20"}
            )
            if result.get("success"):
                process_info["top_processes_cpu"] = result.get("result", {}).get(
                    "stdout", ""
                )

            # Get memory usage
            result = await self.system_ops.execute_shell_command(
                {"command": "ps aux --sort=-%mem | head -n 20"}
            )
            if result.get("success"):
                process_info["top_processes_memory"] = result.get("result", {}).get(
                    "stdout", ""
                )

            # Get system load
            result = await self.system_ops.execute_shell_command({"command": "uptime"})
            if result.get("success"):
                process_info["system_load"] = result.get("result", {}).get("stdout", "")

            # Get memory info
            result = await self.system_ops.execute_shell_command({"command": "free -h"})
            if result.get("success"):
                process_info["memory_info"] = result.get("result", {}).get("stdout", "")

            return process_info

        except Exception as e:
            self.logger.error(_("Error collecting process info: %s"), e)
            return {"error": str(e)}

    async def _collect_disk_usage(self) -> Dict[str, Any]:
        """Collect disk usage information."""
        try:
            disk_info = {}
            current_platform = platform.system()

            if current_platform == "Windows":
                # Get filesystem usage
                self.logger.info("Collecting Windows filesystem usage...")
                start_time = datetime.now(timezone.utc)
                result = await self.system_ops.execute_shell_command(
                    {
                        "command": "powershell -Command \"Get-WmiObject -Class Win32_LogicalDisk | Select-Object DeviceID, Size, FreeSpace, @{Name='UsedSpace';Expression={$_.Size - $_.FreeSpace}} | ConvertTo-Json\""
                    }
                )
                elapsed = (datetime.now(timezone.utc) - start_time).total_seconds()
                if result.get("success"):
                    disk_info["filesystem_usage"] = result.get("result", {}).get(
                        "stdout", ""
                    )
                    self.logger.info(
                        "Windows filesystem usage collected in %.2f seconds", elapsed
                    )
                else:
                    self.logger.warning(
                        "Windows filesystem usage collection failed after %.2f seconds",
                        elapsed,
                    )

                # Get disk performance counters
                self.logger.info("Collecting Windows disk performance counters...")
                start_time = datetime.now(timezone.utc)
                result = await self.system_ops.execute_shell_command(
                    {
                        "command": "powershell -Command \"Get-Counter -Counter '\\LogicalDisk(*)\\% Disk Time' -MaxSamples 1 | ConvertTo-Json\""
                    }
                )
                elapsed = (datetime.now(timezone.utc) - start_time).total_seconds()
                if result.get("success"):
                    disk_info["io_stats"] = result.get("result", {}).get("stdout", "")
                    self.logger.info(
                        "Windows disk performance counters collected in %.2f seconds",
                        elapsed,
                    )
                else:
                    self.logger.warning(
                        "Windows disk performance counters collection failed after %.2f seconds",
                        elapsed,
                    )

                # Get largest directories using PowerShell (this can be very slow)
                self.logger.info(
                    "Collecting largest directories (this may take 30+ seconds)..."
                )
                start_time = datetime.now(timezone.utc)
                result = await self.system_ops.execute_shell_command(
                    {
                        "command": "powershell -Command \"Get-ChildItem -Path C:\\ -Directory | Get-ChildItem -Recurse -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum | Select-Object @{Name='Path';Expression={$_.PSPath}}, @{Name='Size';Expression={$_.Sum}} | Sort-Object Size -Descending | Select-Object -First 10 | ConvertTo-Json\""
                    }
                )
                elapsed = (datetime.now(timezone.utc) - start_time).total_seconds()
                if result.get("success"):
                    disk_info["largest_directories"] = result.get("result", {}).get(
                        "stdout", ""
                    )
                    self.logger.info(
                        "Largest directories analysis completed in %.2f seconds",
                        elapsed,
                    )
                else:
                    self.logger.warning(
                        "Largest directories analysis failed after %.2f seconds",
                        elapsed,
                    )

            else:
                # Linux/Unix systems
                # Get filesystem usage
                result = await self.system_ops.execute_shell_command(
                    {"command": "df -h"}
                )
                if result.get("success"):
                    disk_info["filesystem_usage"] = result.get("result", {}).get(
                        "stdout", ""
                    )

                # Get disk I/O stats
                result = await self.system_ops.execute_shell_command(
                    {
                        "command": "iostat -x 1 1 2>/dev/null || echo 'iostat not available'"
                    }
                )
                if result.get("success"):
                    disk_info["io_stats"] = result.get("result", {}).get("stdout", "")

                # Get largest files/directories
                result = await self.system_ops.execute_shell_command(
                    {
                        "command": "du -h /var /tmp /home 2>/dev/null | sort -hr | head -n 10 || echo 'Disk usage analysis not available'"
                    }
                )
                if result.get("success"):
                    disk_info["largest_directories"] = result.get("result", {}).get(
                        "stdout", ""
                    )

            return disk_info

        except Exception as e:
            self.logger.error(_("Error collecting disk usage: %s"), e)
            return {"error": str(e)}

    async def _collect_environment_variables(self) -> Dict[str, Any]:
        """Collect environment variables (filtered for security)."""
        try:
            env_vars = {}
            current_platform = platform.system()

            if current_platform == "Windows":
                # Get safe environment variables (exclude sensitive ones)
                result = await self.system_ops.execute_shell_command(
                    {
                        "command": "powershell -Command \"Get-ChildItem Env: | Where-Object {$_.Name -match '^(PATH|HOME|USERNAME|COMPUTERNAME|PROCESSOR_|OS|TEMP|TMP)$'} | Sort-Object Name | ConvertTo-Json\""
                    }
                )
                if result.get("success"):
                    env_vars["safe_env_vars"] = result.get("result", {}).get(
                        "stdout", ""
                    )

                # Get Python path if available
                result = await self.system_ops.execute_shell_command(
                    {
                        "command": "python -c \"import sys; print('\\n'.join(sys.path))\" 2>NUL || echo Python path not available"
                    }
                )
                if result.get("success"):
                    env_vars["python_path"] = result.get("result", {}).get("stdout", "")

            else:
                # Linux/Unix systems
                # Get safe environment variables (exclude sensitive ones)
                result = await self.system_ops.execute_shell_command(
                    {
                        "command": "env | grep -E '^(PATH|HOME|USER|SHELL|LANG|LC_|TZ|TERM)=' | sort"
                    }
                )
                if result.get("success"):
                    env_vars["safe_env_vars"] = result.get("result", {}).get(
                        "stdout", ""
                    )

                # Get Python path if available
                result = await self.system_ops.execute_shell_command(
                    {
                        "command": "python3 -c 'import sys; print(\"\\n\".join(sys.path))' 2>/dev/null || echo 'Python path not available'"
                    }
                )
                if result.get("success"):
                    env_vars["python_path"] = result.get("result", {}).get("stdout", "")

            return env_vars

        except Exception as e:
            self.logger.error(_("Error collecting environment variables: %s"), e)
            return {"error": str(e)}

    async def _collect_agent_logs(self) -> Dict[str, Any]:
        """Collect agent log information."""
        try:
            agent_logs = {}

            # Get recent agent logs
            try:
                with open("logs/agent.log", "r", encoding="utf-8") as f:
                    # Get last 100 lines
                    lines = f.readlines()
                    agent_logs["recent_logs"] = "".join(lines[-100:])
            except Exception:
                agent_logs["recent_logs"] = "Agent logs not accessible"

            # Get agent status
            agent_logs["agent_status"] = {
                "running": self.running,
                "connected": self.connected,
                "reconnect_attempts": getattr(self, "reconnect_attempts", 0),
                "last_ping": getattr(self, "last_ping", None),
                "uptime": datetime.now(timezone.utc).isoformat(),
            }

            return agent_logs

        except Exception as e:
            self.logger.error(_("Error collecting agent logs: %s"), e)
            return {"error": str(e)}

    async def _collect_error_logs(self) -> Dict[str, Any]:
        """Collect error logs from various sources."""
        try:
            error_logs = {}

            # Get system error logs
            result = await self.system_ops.execute_shell_command(
                {"command": "journalctl -p err --since '1 hour ago' --no-pager -n 50"}
            )
            if result.get("success"):
                error_logs["system_errors"] = result.get("result", {}).get("stdout", "")

            # Get kernel errors
            result = await self.system_ops.execute_shell_command(
                {"command": "dmesg | grep -i error | tail -n 20"}
            )
            if result.get("success"):
                error_logs["kernel_errors"] = result.get("result", {}).get("stdout", "")

            # Get agent error logs
            try:
                with open("logs/agent.log", "r", encoding="utf-8") as f:
                    lines = f.readlines()
                    error_lines = [line for line in lines if "ERROR" in line.upper()]
                    error_logs["agent_errors"] = "".join(error_lines[-50:])
            except Exception:
                error_logs["agent_errors"] = "Agent error logs not accessible"

            return error_logs

        except Exception as e:
            self.logger.error(_("Error collecting error logs: %s"), e)
            return {"error": str(e)}

    async def handle_host_approval(self, message: Dict[str, Any]) -> None:
        """Handle host approval notification from server."""
        try:
            data = message.get("data", {})
            host_id = data.get("host_id")
            approval_status = data.get("approval_status", "approved")
            certificate = data.get("certificate")

            self.logger.info(
                _("Received host approval notification: host_id=%s, status=%s"),
                host_id,
                approval_status,
            )

            # Store the approval information in the database
            await self.store_host_approval(host_id, approval_status, certificate)

            self.logger.info(
                _("Host approval information stored successfully. Host ID: %s"), host_id
            )

        except Exception as e:
            self.logger.error(_("Error processing host approval notification: %s"), e)

    async def clear_host_approval(self) -> None:
        """Clear all host approval records from local database."""
        try:
            db_manager = get_database_manager()
            session = db_manager.get_session()
            try:
                # Delete all existing host approval records
                session.query(HostApproval).delete()
                session.commit()
                self.logger.debug("Host approval records cleared from database")
            finally:
                session.close()
        except Exception as e:
            self.logger.error(_("Error clearing host approval records: %s"), e)
            raise

    async def store_host_approval(
        self,
        host_id: int,
        approval_status: str,
        certificate: str = None,
        host_token: str = None,
    ) -> None:
        """Store host approval information in local database."""
        try:
            db_manager = get_database_manager()
            session = db_manager.get_session()
            try:
                # Check if we already have an approval record
                existing_approval = session.query(HostApproval).first()

                if existing_approval:
                    # Update existing record
                    existing_approval.host_id = host_id
                    existing_approval.host_token = host_token
                    existing_approval.approval_status = approval_status
                    existing_approval.certificate = certificate
                    existing_approval.updated_at = datetime.now(timezone.utc)

                    if approval_status == "approved":
                        existing_approval.approved_at = datetime.now(timezone.utc)
                else:
                    # Create new approval record
                    new_approval = HostApproval(
                        host_id=host_id,
                        host_token=host_token,
                        approval_status=approval_status,
                        certificate=certificate,
                        approved_at=(
                            datetime.now(timezone.utc)
                            if approval_status == "approved"
                            else None
                        ),
                        created_at=datetime.now(timezone.utc),
                        updated_at=datetime.now(timezone.utc),
                    )
                    session.add(new_approval)

                session.commit()
                self.logger.debug(
                    _("Host approval record stored in database: host_id=%s"), host_id
                )

            finally:
                session.close()

        except Exception as e:
            self.logger.error(_("Error storing host approval in database: %s"), e)
            raise

    async def handle_registration_success(self, message: Dict[str, Any]) -> None:
        """Handle registration success notification from server."""
        try:
            self.logger.info(
                _("Received registration success notification from server")
            )

            # Record the registration timestamp
            self.last_registration_time = datetime.now(timezone.utc)

            # Extract host_id and host_token from registration success if available
            host_id = message.get("host_id")
            host_token = message.get("host_token")
            approved = message.get("approved", False)

            if (host_id or host_token) and approved:
                self.logger.info(
                    "Registration approved",
                )

                # Clear any existing host approval and store the new one
                await self.clear_stored_host_id()
                await self.store_host_approval(
                    host_id, "approved", host_token=host_token
                )
                self.logger.info("Host approval stored for host_id: %s", host_id)

                # Mark registration as confirmed and send initial data
                self.registration_confirmed = True
                self.logger.info(
                    "Registration confirmed, sending initial inventory data..."
                )
                await self.send_initial_data_updates()

            elif host_id or host_token:
                self.logger.info(
                    "Registration received but approval pending",
                )
                await self.clear_stored_host_id()
                await self.store_host_approval(
                    host_id, "pending", host_token=host_token
                )
                self.registration_confirmed = True
            else:
                self.logger.info(
                    "Registration success but no host_id provided - approval may come separately"
                )

        except Exception as e:
            self.logger.error(
                _("Error processing registration success notification: %s"), e
            )

    async def get_stored_host_id(self) -> int:
        """Get the stored host_id from local database."""
        try:
            db_manager = get_database_manager()
            session = db_manager.get_session()
            try:
                approval = (
                    session.query(HostApproval)
                    .filter(
                        HostApproval.approval_status == "approved",
                        HostApproval.host_id.isnot(None),
                    )
                    .first()
                )

                if approval and approval.has_host_id:
                    return approval.host_id

                return None

            finally:
                session.close()

        except Exception as e:
            self.logger.error(_("Error retrieving stored host_id: %s"), e)
            return None

    async def get_stored_host_token(self) -> str:
        """Get the stored host_token from local database."""
        try:
            db_manager = get_database_manager()
            session = db_manager.get_session()
            try:
                approval = (
                    session.query(HostApproval)
                    .filter(
                        HostApproval.approval_status == "approved",
                        HostApproval.host_token.isnot(None),
                    )
                    .first()
                )

                if approval and approval.host_token:
                    return approval.host_token

                return None

            finally:
                session.close()

        except Exception:
            self.logger.error(_("Error retrieving stored credentials"))
            return None

    def get_stored_host_token_sync(self) -> str:
        """Get the stored host_token from local database synchronously."""
        try:
            db_manager = get_database_manager()
            session = db_manager.get_session()
            try:
                approval = (
                    session.query(HostApproval)
                    .filter(
                        HostApproval.approval_status == "approved",
                        HostApproval.host_token.isnot(None),
                    )
                    .first()
                )

                if approval and approval.host_token:
                    return approval.host_token

                return None

            finally:
                session.close()

        except Exception:
            self.logger.error(_("Error retrieving stored credentials"))
            return None

    def get_host_approval_from_db(self):
        """Get the host approval record from local database."""
        try:
            db_manager = get_database_manager()
            session = db_manager.get_session()
            try:
                approval = (
                    session.query(HostApproval)
                    .filter(
                        HostApproval.approval_status == "approved",
                        HostApproval.host_id.isnot(None),
                    )
                    .first()
                )

                return approval

            finally:
                session.close()

        except Exception as e:
            self.logger.error(_("Error retrieving host approval: %s"), type(e).__name__)
            return None

    def get_stored_host_id_sync(self) -> int:
        """Get the stored host_id from local database synchronously."""
        try:
            db_manager = get_database_manager()
            session = db_manager.get_session()
            try:
                approval = (
                    session.query(HostApproval)
                    .filter(
                        HostApproval.approval_status == "approved",
                        HostApproval.host_id.isnot(None),
                    )
                    .first()
                )

                if approval and approval.has_host_id:
                    return approval.host_id

                return None

            finally:
                session.close()

        except Exception as e:
            self.logger.error(_("Error retrieving stored host_id synchronously: %s"), e)
            return None

    async def clear_stored_host_id(self) -> None:
        """Clear the stored host_id from local database and related data."""
        try:
            db_manager = get_database_manager()
            session = db_manager.get_session()
            try:
                # Find and remove all host approval records
                approvals = session.query(HostApproval).all()
                for approval in approvals:
                    session.delete(approval)

                # Clear any pending script executions since they're tied to the old host
                script_executions = session.query(ScriptExecution).all()
                for execution in script_executions:
                    session.delete(execution)

                # Clear any queued messages with host_id data
                queued_messages = session.query(MessageQueue).all()
                for message in queued_messages:
                    try:
                        # Parse message data to check for host_id
                        message_data = json.loads(message.message_data)
                        if "host_id" in message_data:
                            # Remove messages containing the old host_id
                            session.delete(message)
                    except (json.JSONDecodeError, KeyError):
                        # Keep messages that can't be parsed or don't have host_id
                        pass

                session.commit()
                self.logger.info(
                    _("Host approval records and related data cleared from database")
                )

            finally:
                session.close()

        except Exception as e:
            self.logger.error(_("Error clearing host approval records: %s"), e)
            raise

    async def run(self):
        """Main agent execution loop."""
        system_info = self.registration.get_system_info()

        self.logger.info(_("Starting SysManage Agent"))
        self.logger.info("Agent ID: %s", self.agent_id)
        self.logger.info("Hostname: %s", system_info["hostname"])
        self.logger.info("Platform: %s", system_info["platform"])
        self.logger.info("IPv4: %s", system_info["ipv4"])
        self.logger.info("IPv6: %s", system_info["ipv6"])

        # Attempt registration with server
        self.logger.info(_("Registering with SysManage server..."))
        if not await self.registration.register_with_retry():
            self.logger.error(_("Failed to register with server. Exiting."))
            return

        self.logger.info(_("Registration successful, checking certificates..."))

        # Check if we have certificates for secure authentication
        # For now, we'll continue with token-based auth but log certificate status
        if self.cert_store.has_certificates():
            self.logger.info(
                _("Valid certificates found - secure authentication available")
            )
        else:
            self.logger.info(
                _("No certificates found - using token-based authentication")
            )
            self.logger.info(
                _(
                    "For enhanced security, approve this host to enable certificate-based auth"
                )
            )

        self.logger.info(_("Starting WebSocket connection..."))

        base_reconnect_interval = self.config.get_reconnect_interval()

        while True:
            try:
                # Check if server is available before attempting connection
                if not await self._check_server_health():
                    self.logger.warning(
                        "Server health check failed, waiting before retry..."
                    )
                    await asyncio.sleep(5)
                    continue

                # Check if we need to re-register due to host_not_registered error
                if self.needs_registration:
                    self.logger.info(
                        "Re-registration required, attempting to register..."
                    )
                    if not await self.registration.register_with_retry():
                        self.logger.error(
                            "Failed to re-register with server. Will retry on next connection attempt."
                        )
                        await asyncio.sleep(10)  # Short wait before trying again
                        continue
                    self.needs_registration = False
                    self.logger.info("Re-registration successful")

                # Get authentication token
                auth_token = await self.get_auth_token()
                self.logger.info("Got authentication token for WebSocket connection")

                # Add token to WebSocket URL
                websocket_url = f"{self.server_url}?token={auth_token}"

                # Create SSL context based on configuration
                ssl_context = None
                if self.server_url.startswith("wss://"):
                    ssl_context = ssl.create_default_context()

                    # If we have certificates, use them for mutual TLS
                    cert_paths = self.cert_store.load_certificates()
                    if cert_paths:
                        client_cert_path, client_key_path, ca_cert_path = cert_paths
                        ssl_context.load_cert_chain(client_cert_path, client_key_path)
                        ssl_context.load_verify_locations(ca_cert_path)
                        ssl_context.check_hostname = True
                        ssl_context.verify_mode = ssl.CERT_REQUIRED
                        self.logger.info("Using mutual TLS with client certificates")
                    elif not self.config.should_verify_ssl():
                        ssl_context.check_hostname = False
                        ssl_context.verify_mode = ssl.CERT_NONE

                # Set up WebSocket connection with proper timeouts and ping/pong
                ping_interval = self.config.get_ping_interval()
                ping_timeout = ping_interval / 2  # Half of ping interval for timeout

                async with websockets.connect(
                    websocket_url,
                    ssl=ssl_context,
                    ping_interval=ping_interval,
                    ping_timeout=ping_timeout,
                    close_timeout=10,
                ) as websocket:
                    self.websocket = websocket
                    self.connected = True
                    self.running = True
                    self.connection_failures = (
                        0  # Reset failure count on successful connection
                    )
                    self.logger.info(_("Connected to server successfully"))

                    # Notify message handler that connection is established
                    try:
                        await self.message_handler.on_connection_established()
                    except Exception as e:
                        self.logger.error(
                            "Failed to start queue processing: %s", e, exc_info=True
                        )

                    # Wait for registration_success before sending inventory data
                    self.logger.info(
                        _(
                            "Connected to server, waiting for registration confirmation..."
                        )
                    )

                    # Run sender, receiver, update checker, data collector, and package collector concurrently with proper error handling
                    try:
                        sender_task = asyncio.create_task(self.message_sender())
                        receiver_task = asyncio.create_task(self.message_receiver())
                        update_checker_task = asyncio.create_task(self.update_checker())
                        data_collector_task = asyncio.create_task(self.data_collector())
                        package_collector_task = asyncio.create_task(
                            self.package_collector()
                        )

                        # Wait for either sender or receiver to complete (connection tasks only)
                        # Update checker, data collector, and package collector run independently and don't trigger disconnection
                        done, pending = await asyncio.wait(
                            [sender_task, receiver_task],
                            return_when=asyncio.FIRST_COMPLETED,
                        )

                        # Cancel the background tasks when connection fails
                        update_checker_task.cancel()
                        data_collector_task.cancel()
                        package_collector_task.cancel()
                        try:
                            await update_checker_task
                        except asyncio.CancelledError:
                            pass
                        try:
                            await data_collector_task
                        except asyncio.CancelledError:
                            pass
                        try:
                            await package_collector_task
                        except asyncio.CancelledError:
                            pass

                        # Cancel any remaining connection tasks
                        for task in pending:
                            task.cancel()
                            try:
                                await task
                            except asyncio.CancelledError:
                                pass

                        # Check if any connection task had an exception
                        for task in done:
                            if task.exception():
                                raise task.exception()

                    except asyncio.CancelledError:
                        self.logger.debug("Connection tasks cancelled")
                        raise

            except websockets.ConnectionClosed:
                self.logger.warning(
                    "WEBSOCKET_COMMUNICATION_ERROR: WebSocket connection closed by server"
                )
            except websockets.InvalidStatusCode as e:
                self.logger.error(
                    "WEBSOCKET_PROTOCOL_ERROR: WebSocket connection rejected: %s", e
                )
            except Exception as e:
                self.logger.error("WEBSOCKET_UNKNOWN_ERROR: Connection error: %s", e)

            # Clean up connection state
            self.connected = False
            self.websocket = None
            self.running = False
            self.connection_failures += 1

            # Notify message handler that connection is lost
            try:
                await self.message_handler.on_connection_lost()
            except Exception as e:
                self.logger.error(
                    "Error notifying message handler of connection loss: %s", e
                )

            self.logger.info(
                "Connection attempt %d failed, current failure count: %d",
                self.connection_failures,
                self.connection_failures,
            )

            # Only reconnect if auto-reconnect is enabled
            if self.config.should_auto_reconnect():
                # Calculate exponential backoff with jitter
                reconnect_interval = min(
                    base_reconnect_interval * (2 ** min(self.connection_failures, 6)),
                    300,
                )
                # Add jitter to prevent thundering herd (using secrets for cryptographic randomness)
                jitter = 0.5 + (secrets.randbelow(1000) / 1000.0)  # 0.5 to 1.5
                reconnect_interval *= jitter

                self.logger.info(
                    "Reconnecting in %.1f seconds (attempt %d)",
                    reconnect_interval,
                    self.connection_failures + 1,
                )
                await asyncio.sleep(reconnect_interval)
            else:
                self.logger.info("Auto-reconnect disabled, exiting...")
                break


if __name__ == "__main__":
    agent = SysManageAgent()
    asyncio.run(agent.run())
