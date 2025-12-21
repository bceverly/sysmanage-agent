"""
This module is the main entry point for the SysManage agent that will run
on all clients. It provides real-time bidirectional communication with the
SysManage server using WebSockets with concurrent send/receive operations.
"""

# pylint: disable=too-many-lines

import asyncio
import json
import logging
import os
import secrets
import ssl
import uuid
from datetime import datetime, timezone
from typing import Any, Dict

import aiohttp
import websockets
import yaml

from src.database.base import get_database_manager  # pylint: disable=unused-import
from src.database.init import initialize_database
from src.database.models import HostApproval  # pylint: disable=unused-import
from src.i18n import _, set_language
from src.security.certificate_store import CertificateStore
from src.sysmanage_agent.collection.antivirus_collection import AntivirusCollector
from src.sysmanage_agent.collection.certificate_collection import CertificateCollector
from src.sysmanage_agent.collection.role_detection import RoleDetector
from src.sysmanage_agent.communication.data_collector import DataCollector
from src.sysmanage_agent.communication.message_handler import MessageHandler
from src.sysmanage_agent.core.agent_utils import (
    AuthenticationHelper,
    MessageProcessor,
    PackageCollectionScheduler,
    UpdateChecker,
    is_running_privileged,
)
from src.sysmanage_agent.core.config import ConfigManager
from src.sysmanage_agent.diagnostics.diagnostic_collector import DiagnosticCollector
from src.sysmanage_agent.operations.child_host_operations import ChildHostOperations
from src.sysmanage_agent.operations.firewall_operations import FirewallOperations
from src.sysmanage_agent.operations.script_operations import ScriptOperations
from src.sysmanage_agent.operations.system_operations import SystemOperations
from src.sysmanage_agent.operations.update_manager import UpdateManager
from src.sysmanage_agent.registration.discovery import discovery_client
from src.sysmanage_agent.registration.registration import ClientRegistration
from src.sysmanage_agent.registration.registration_manager import RegistrationManager
from src.sysmanage_agent.utils.logging_formatter import UTCTimestampFormatter
from src.sysmanage_agent.utils.verbosity_logger import get_logger


class SysManageAgent:  # pylint: disable=too-many-public-methods,too-many-instance-attributes
    """Main agent class for SysManage fleet management."""

    def __init__(self, config_file: str = "sysmanage-agent.yaml"):
        # Try to discover server if no config file exists
        self.config_file = config_file
        # Setup minimal logging first - file only, no console output
        logging.basicConfig(
            level=logging.WARNING,
            handlers=[],  # Explicitly no handlers to prevent console output
        )

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
            # Log the actual error for debugging
            self.logger.error("Database initialization failed - check logs for details")
            raise RuntimeError(_("Failed to initialize agent database"))

        # Initialize registration manager (must be before cleanup as cleanup uses it)
        self.registration_manager = RegistrationManager(self)

        # Clean up any corrupt data from the database (e.g., invalid UUIDs)
        self.registration_manager.cleanup_corrupt_database_entries()

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
        # Use SYSMANAGE_CONFIG_DIR if set (for snap confinement), otherwise use default
        config_dir = os.environ.get("SYSMANAGE_CONFIG_DIR")
        self.cert_store = CertificateStore(config_dir=config_dir)

        # Initialize utility classes
        self.update_checker_util = UpdateChecker(self, self.logger)
        self.package_collection_scheduler = PackageCollectionScheduler(
            self, self.logger
        )
        self.auth_helper = AuthenticationHelper(self, self.logger)
        self.message_processor = MessageProcessor(self, self.logger)

        # Initialize certificate collector
        self.certificate_collector = CertificateCollector()

        # Initialize role detector
        self.role_detector = RoleDetector()

        # Initialize antivirus collector
        self.antivirus_collector = AntivirusCollector()

        # Initialize operation modules
        self.update_manager = UpdateManager(self)
        self.system_ops = SystemOperations(self)
        self.script_ops = ScriptOperations(self)
        self.firewall_ops = FirewallOperations(self)
        self.child_host_ops = ChildHostOperations(self)

        # Initialize diagnostic collector
        self.diagnostic_collector = DiagnosticCollector(self)

        # Initialize data collector
        self.data_collector = DataCollector(self)

        # Initialize message handler with persistent queues
        self.message_handler = MessageHandler(self)

        # Get server URL from config
        self.server_url = self.config.get_server_url()

        self.logger.info("%s ID: %s", _("Starting SysManage Agent"), self.agent_id)
        self.logger.info("Server URL: %s", self.server_url)

    def try_load_config(self, config_file: str) -> bool:
        """Try to load configuration file."""
        return os.path.exists(config_file)

    def auto_discover_and_configure(self) -> bool:
        """Auto-discover server and create configuration."""

        # Setup basic logging for discovery process - file only, no console
        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
            handlers=[],  # Explicitly no handlers to prevent console output
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
            with open(self.config_file, "w", encoding="utf-8") as file_handle:
                yaml.dump(
                    config_data, file_handle, default_flow_style=False, sort_keys=False
                )

            logger.info("Configuration written to %s", self.config_file)
            return True

        except Exception as error:
            logger.error("Auto-discovery failed: %s", error)
            return False

    def setup_logging(self):
        """Setup logging based on configuration with verbosity support."""
        log_level = self.config.get_log_level()
        log_file = self.config.get_log_file()

        # Default to /var/log for system service, or local logs/ for development
        if not log_file:
            # Check environment variable first (highest priority)
            env_log_dir = os.environ.get("SYSMANAGE_LOG_DIR")
            if env_log_dir:
                os.makedirs(env_log_dir, exist_ok=True)
                log_file = os.path.join(env_log_dir, "agent.log")
            # Try /var/log/sysmanage-agent (system service)
            elif os.path.exists("/var/log/sysmanage-agent"):
                log_file = "/var/log/sysmanage-agent/agent.log"
            # Fallback to local logs/ directory
            else:
                logs_dir = os.path.join(os.getcwd(), "logs")
                os.makedirs(logs_dir, exist_ok=True)
                log_file = os.path.join(logs_dir, "agent.log")

        # Parse log level - handle pipe-separated levels (use first one)
        if "|" in log_level:
            log_level = log_level.split("|")[0].strip()

        # Clear any existing handlers to prevent double logging
        root_logger = logging.getLogger()
        for handler in root_logger.handlers[:]:
            root_logger.removeHandler(handler)

        # Always set up file logging - write all output to file
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(getattr(logging, log_level.upper()))
        file_handler.setFormatter(
            UTCTimestampFormatter("[%(asctime)s UTC] %(levelname)s: %(message)s")
        )
        root_logger.addHandler(file_handler)
        root_logger.setLevel(getattr(logging, log_level.upper()))

        # Also log to console if running as a daemon (for snap logs, systemd journal, etc.)
        # Check if SYSMANAGE_LOG_CONSOLE environment variable is set
        if os.environ.get("SYSMANAGE_LOG_CONSOLE", "").lower() in ("1", "true", "yes"):
            console_handler = logging.StreamHandler()
            console_handler.setLevel(getattr(logging, log_level.upper()))
            console_handler.setFormatter(
                UTCTimestampFormatter("[%(asctime)s UTC] %(levelname)s: %(message)s")
            )
            root_logger.addHandler(console_handler)

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
            stored_host_id = self.registration_manager.get_stored_host_id_sync()
            stored_host_token = self.registration_manager.get_stored_host_token_sync()
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
        except Exception as error:
            self.logger.debug("Server health check failed: %s", error)
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
        except Exception as error:
            self.logger.error("Failed to queue message: %s", error)
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

    async def install_packages(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Install multiple packages using the appropriate package manager."""
        return await self.system_ops.install_packages(parameters)

    async def uninstall_packages(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Uninstall multiple packages using the appropriate package manager."""
        return await self.system_ops.uninstall_packages(parameters)

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

    async def deploy_ssh_keys(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Deploy SSH keys to a user account."""
        return await self.system_ops.deploy_ssh_keys(parameters)

    async def deploy_certificates(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Deploy SSL certificates to the system."""
        return await self.system_ops.deploy_certificates(parameters)

    async def deploy_opentelemetry(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Deploy OpenTelemetry collector to the system."""
        return await self.system_ops.deploy_opentelemetry(parameters)

    async def remove_opentelemetry(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Remove OpenTelemetry collector from the system."""
        return await self.system_ops.remove_opentelemetry(parameters)

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
        await self.data_collector.send_initial_data_updates()

    async def update_os_version(self) -> Dict[str, Any]:
        """Gather and send updated OS version information to the server."""
        return await self.data_collector.update_os_version()

    async def update_hardware(self) -> Dict[str, Any]:
        """Gather and send updated hardware information to the server."""
        return await self.data_collector.update_hardware()

    async def update_user_access(self) -> Dict[str, Any]:
        """Gather and send updated user access information to the server."""
        return await self.data_collector.update_user_access()

    async def _handle_server_error(self, data: Dict[str, Any]) -> None:
        """Handle error messages from server."""
        # Server sends error_type and message at top level, not in data field
        error_code = data.get("error_type", "unknown")
        error_message = data.get("message", "No error message provided")

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
            except (ValueError, TypeError) as error:
                self.logger.warning(
                    "Could not parse message timestamp for stale check: %s", error
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
        except Exception as error:
            self.logger.error("Error clearing stored host_id: %s", error)

        # Clear any existing registration state and force re-registration
        self.registration_status = None
        self.registration_confirmed = False
        self.registration.registered = False
        # Schedule re-registration on next connection attempt
        self.needs_registration = True
        # Disconnect immediately to trigger reconnection with re-registration
        self.logger.info("Disconnecting to trigger re-registration...")
        self.running = False

    async def message_receiver(self):  # pylint: disable=too-many-branches
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
                    elif message_type == "available_packages_batch_queued":
                        status = data.get("status", "unknown")
                        self.logger.debug(
                            "Server confirmed packages batch queued: %s", status
                        )
                    elif message_type == "available_packages_batch_start_queued":
                        status = data.get("status", "unknown")
                        self.logger.debug(
                            "Server confirmed packages batch start queued: %s", status
                        )
                    elif message_type == "available_packages_batch_end_queued":
                        status = data.get("status", "unknown")
                        self.logger.debug(
                            "Server confirmed packages batch end queued: %s", status
                        )
                    else:
                        self.logger.warning("Unknown message type: %s", message_type)

                except json.JSONDecodeError:
                    self.logger.error("Invalid JSON received: %s", message)
                except Exception as error:
                    self.logger.error("Error processing message: %s", error)

        except websockets.ConnectionClosed:
            self.logger.info(
                "WEBSOCKET_COMMUNICATION_ERROR: Connection to server closed"
            )
            self.connected = False
            self.websocket = None
        except Exception as error:
            self.logger.error(
                "WEBSOCKET_UNKNOWN_ERROR: Message receiver error: %s", error
            )
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
            except Exception as error:
                self.logger.error("Message sender error: %s", error)
                # Don't break the loop on non-critical errors, but return to trigger reconnection
                return

    async def update_checker(self):
        """Delegate to data_collector."""
        return await self.data_collector.update_checker()

    async def _send_software_inventory_update(self):
        """Delegate to data_collector."""
        await self.data_collector._send_software_inventory_update()  # pylint: disable=protected-access

    async def _send_user_access_update(self):
        """Delegate to data_collector."""
        await self.data_collector._send_user_access_update()  # pylint: disable=protected-access

    async def _send_hardware_update(self):
        """Delegate to data_collector."""
        await self.data_collector._send_hardware_update()  # pylint: disable=protected-access

    async def _send_certificate_update(self):
        """Delegate to data_collector."""
        await self.data_collector._send_certificate_update()  # pylint: disable=protected-access

    async def _send_role_update(self):
        """Delegate to data_collector."""
        await self.data_collector._send_role_update()  # pylint: disable=protected-access

    async def _send_os_version_update(self):
        """Delegate to data_collector."""
        await self.data_collector._send_os_version_update()  # pylint: disable=protected-access

    async def _send_reboot_status_update(self):
        """Delegate to data_collector."""
        await self.data_collector._send_reboot_status_update()  # pylint: disable=protected-access

    async def _send_third_party_repository_update(self):
        """Delegate to data_collector."""
        await self.data_collector._send_third_party_repository_update()  # pylint: disable=protected-access

    async def _send_antivirus_status_update(self):
        """Delegate to data_collector."""
        await self.data_collector._send_antivirus_status_update()  # pylint: disable=protected-access

    async def _collect_and_send_periodic_data(self):
        """Delegate to data_collector."""
        await self.data_collector._collect_and_send_periodic_data()  # pylint: disable=protected-access

    async def package_collector(self):
        """Delegate to data_collector."""
        return await self.data_collector.package_collector()

    async def child_host_heartbeat(self):
        """Delegate to data_collector for frequent child host status updates."""
        return await self.data_collector.child_host_heartbeat()

    async def get_auth_token(self) -> str:
        """Get authentication token for WebSocket connection."""
        return await self.registration_manager.get_auth_token()

    async def fetch_certificates(self, host_id: str) -> bool:
        """Fetch certificates from server after approval."""
        return await self.registration_manager.fetch_certificates(host_id)

    async def ensure_certificates(self) -> bool:
        """Ensure agent has valid certificates for mTLS."""
        return await self.registration_manager.ensure_certificates()

    async def check_updates(self) -> Dict[str, Any]:
        """Check for available updates for installed packages."""
        return await self.update_manager.check_updates()

    async def apply_updates(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Apply updates for specified packages."""
        return await self.update_manager.apply_updates(parameters)

    async def check_reboot_status(self) -> Dict[str, Any]:
        """Check if the system requires a reboot."""
        return await self.update_manager.check_reboot_status()

    async def send_reboot_status_update(self, requires_reboot: bool) -> None:
        """Send reboot status update to server."""
        await self.update_manager.send_reboot_status_update(requires_reboot)

    async def collect_diagnostics(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Collect system diagnostics and send to server."""
        return await self.diagnostic_collector.collect_diagnostics(parameters)

    async def collect_available_packages(self) -> Dict[str, Any]:
        """Delegate to data_collector."""
        return await self.data_collector.collect_available_packages()

    async def _send_available_packages_paginated(
        self,
        package_managers: Dict[str, list],
        os_name: str,
        os_version: str,
        total_packages: int,
    ) -> bool:
        """Send available packages using pagination to avoid large message issues."""
        return await self.data_collector._send_available_packages_paginated(  # pylint: disable=protected-access
            package_managers, os_name, os_version, total_packages
        )

    async def collect_certificates(self) -> Dict[str, Any]:
        """Delegate to data_collector."""
        return await self.data_collector.collect_certificates()

    async def collect_roles(self) -> Dict[str, Any]:
        """Delegate to data_collector."""
        return await self.data_collector.collect_roles()

    async def list_third_party_repositories(
        self, parameters: Dict[str, Any] = None
    ) -> Dict[str, Any]:
        """List all third-party repositories on the system."""
        return await self.system_ops.list_third_party_repositories(parameters or {})

    async def add_third_party_repository(
        self, parameters: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Add a third-party repository to the system."""
        return await self.system_ops.add_third_party_repository(parameters)

    async def delete_third_party_repositories(
        self, parameters: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Delete third-party repositories from the system."""
        return await self.system_ops.delete_third_party_repositories(parameters)

    async def enable_third_party_repositories(
        self, parameters: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Enable third-party repositories on the system."""
        return await self.system_ops.enable_third_party_repositories(parameters)

    async def disable_third_party_repositories(
        self, parameters: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Disable third-party repositories on the system."""
        return await self.system_ops.disable_third_party_repositories(parameters)

    async def deploy_antivirus(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Deploy antivirus software to the system."""
        return await self.system_ops.deploy_antivirus(parameters)

    async def enable_antivirus(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Enable antivirus service(s)."""
        return await self.system_ops.enable_antivirus(parameters)

    async def disable_antivirus(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Disable antivirus service(s)."""
        return await self.system_ops.disable_antivirus(parameters)

    async def remove_antivirus(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Remove antivirus software from the system."""
        return await self.system_ops.remove_antivirus(parameters)

    async def create_host_user(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Create a new user account on the host."""
        return await self.system_ops.create_host_user(parameters)

    async def create_host_group(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Create a new group on the host."""
        return await self.system_ops.create_host_group(parameters)

    async def delete_host_user(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Delete a user account from the host."""
        return await self.system_ops.delete_host_user(parameters)

    async def delete_host_group(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Delete a group from the host."""
        return await self.system_ops.delete_host_group(parameters)

    async def deploy_firewall(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Deploy (install and enable) firewall on the system."""
        return await self.firewall_ops.deploy_firewall(parameters)

    async def enable_firewall(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Enable firewall and ensure agent communication ports are open."""
        return await self.firewall_ops.enable_firewall(parameters)

    async def disable_firewall(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Disable firewall on the system."""
        return await self.firewall_ops.disable_firewall(parameters)

    async def restart_firewall(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Restart firewall service on the system."""
        return await self.firewall_ops.restart_firewall(parameters)

    async def apply_firewall_roles(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Apply firewall roles by setting open ports based on assigned roles."""
        return await self.firewall_ops.apply_firewall_roles(parameters)

    async def remove_firewall_ports(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Remove specific firewall ports (used when a firewall role is removed)."""
        return await self.firewall_ops.remove_firewall_ports(parameters)

    async def attach_to_graylog(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Attach host to Graylog log aggregation server."""
        # pylint: disable=import-outside-toplevel
        from src.sysmanage_agent.operations.graylog_attachment import (
            GraylogAttachmentOperations,
        )

        graylog_ops = GraylogAttachmentOperations(self, self.logger)
        return await graylog_ops.attach_to_graylog(parameters)

    async def enable_package_manager(
        self, parameters: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Enable an additional package manager on this host."""
        # pylint: disable=import-outside-toplevel
        from src.sysmanage_agent.operations.package_manager_operations import (
            PackageManagerOperations,
        )

        pm_ops = PackageManagerOperations(self, self.logger)
        return await pm_ops.enable_package_manager(parameters)

    async def handle_host_approval(self, message: Dict[str, Any]) -> None:
        """Handle host approval notification from server."""
        await self.registration_manager.handle_host_approval(message)

    async def clear_host_approval(self) -> None:
        """Clear all host approval records from local database."""
        await self.registration_manager.clear_host_approval()

    async def store_host_approval(
        self,
        host_id: str,
        approval_status: str,
        certificate: str = None,
        host_token: str = None,
    ) -> None:
        """Store host approval information in local database."""
        await self.registration_manager.store_host_approval(
            host_id, approval_status, certificate, host_token
        )

    async def handle_registration_success(self, message: Dict[str, Any]) -> None:
        """Handle registration success notification from server."""
        await self.registration_manager.handle_registration_success(message)

    async def get_stored_host_id(self) -> str:
        """Get the stored host_id from local database."""
        return await self.registration_manager.get_stored_host_id()

    async def get_stored_host_token(self) -> str:
        """Get the stored host_token from local database."""
        return await self.registration_manager.get_stored_host_token()

    def get_stored_host_token_sync(self) -> str:
        """Get the stored host_token from local database synchronously."""
        return self.registration_manager.get_stored_host_token_sync()

    async def call_server_api(
        self, endpoint: str, method: str = "POST", data: Dict[str, Any] = None
    ) -> Dict[str, Any]:
        """
        Centralized method for making API calls to the server.

        Args:
            endpoint: API endpoint (without /api prefix, e.g., "agent/installation-complete")
            method: HTTP method (GET, POST, PUT, DELETE)
            data: Request payload (for POST/PUT requests)

        Returns:
            Response data as dictionary, or None if request failed
        """
        return await self.registration_manager.call_server_api(endpoint, method, data)

    def get_host_approval_from_db(self):
        """Get the host approval record from local database."""
        return self.registration_manager.get_host_approval_from_db()

    def get_stored_host_id_sync(self) -> str:
        """Get the stored host_id from local database synchronously."""
        return self.registration_manager.get_stored_host_id_sync()

    def cleanup_corrupt_database_entries(self) -> None:
        """Clean up any corrupt entries from database (e.g., invalid UUIDs)."""
        self.registration_manager.cleanup_corrupt_database_entries()

    async def clear_stored_host_id(self) -> None:
        """Clear the stored host_id from local database and related data."""
        await self.registration_manager.clear_stored_host_id()

    async def run(
        self,
    ):  # pylint: disable=too-many-locals,too-many-branches,too-many-statements
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
                    except Exception as error:
                        self.logger.error(
                            "Failed to start queue processing: %s", error, exc_info=True
                        )

                    # Wait for registration_success before sending inventory data
                    self.logger.info(
                        _(
                            "Connected to server, waiting for registration confirmation..."
                        )
                    )

                    # Run sender, receiver, update checker, data collector, package collector, and child host heartbeat concurrently with proper error handling
                    # IMPORTANT: Use message_handler's methods which properly queue commands
                    # instead of blocking on command execution
                    try:
                        sender_task = asyncio.create_task(
                            self.message_handler.message_sender()
                        )
                        receiver_task = asyncio.create_task(
                            self.message_handler.message_receiver()
                        )
                        update_checker_task = asyncio.create_task(self.update_checker())
                        data_collector_task = asyncio.create_task(
                            self._collect_and_send_periodic_data()
                        )
                        package_collector_task = asyncio.create_task(
                            self.package_collector()
                        )
                        child_host_heartbeat_task = asyncio.create_task(
                            self.child_host_heartbeat()
                        )

                        # Wait for either sender or receiver to complete (connection tasks only)
                        # Update checker, data collector, package collector, and child host heartbeat run independently and don't trigger disconnection
                        done, pending = await asyncio.wait(
                            [sender_task, receiver_task],
                            return_when=asyncio.FIRST_COMPLETED,
                        )

                        # Cancel the background tasks when connection fails
                        update_checker_task.cancel()
                        data_collector_task.cancel()
                        package_collector_task.cancel()
                        child_host_heartbeat_task.cancel()
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
                        try:
                            await child_host_heartbeat_task
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
            except websockets.InvalidStatusCode as error:
                self.logger.error(
                    "WEBSOCKET_PROTOCOL_ERROR: WebSocket connection rejected: %s", error
                )
            except Exception as error:
                self.logger.error(
                    "WEBSOCKET_UNKNOWN_ERROR: Connection error: %s", error
                )

            # Clean up connection state
            self.connected = False
            self.websocket = None
            self.running = False
            self.connection_failures += 1

            # Notify message handler that connection is lost
            try:
                await self.message_handler.on_connection_lost()
            except Exception as error:
                self.logger.error(
                    "Error notifying message handler of connection loss: %s", error
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
    # Check for config file in standard locations
    # Priority: 1) Environment variable, 2) Platform-specific system location, 3) Current directory
    config_path = os.getenv("SYSMANAGE_CONFIG")  # pylint: disable=invalid-name
    if not config_path:
        # Platform-specific system config paths
        if os.name == "nt":  # Windows
            system_config = r"C:\ProgramData\SysManage\sysmanage-agent.yaml"  # pylint: disable=invalid-name
        else:  # Unix-like (Linux, macOS, BSD)
            system_config = "/etc/sysmanage-agent.yaml"  # pylint: disable=invalid-name

        # Try system location first, then fall back to current directory
        if os.path.exists(system_config):
            config_path = system_config  # pylint: disable=invalid-name
        else:
            config_path = "sysmanage-agent.yaml"  # pylint: disable=invalid-name

    agent = SysManageAgent(config_path)
    asyncio.run(agent.run())
