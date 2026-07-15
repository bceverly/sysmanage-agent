"""
This module is the main entry point for the SysManage agent that will run
on all clients. It provides real-time bidirectional communication with the
SysManage server using WebSockets with concurrent send/receive operations.
"""

import asyncio
import logging
import os
import secrets
import ssl
import sys
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
from src.sysmanage_agent.collection.public_ip_fetcher import (
    public_ip_refresh_service,
)
from src.sysmanage_agent.collection.role_detection import RoleDetector
from src.sysmanage_agent.communication.data_collector import DataCollector
from src.sysmanage_agent.communication.message_handler import MessageHandler
from src.sysmanage_agent.core.agent_delegators import AgentDelegatorMixin
from src.sysmanage_agent.core.agent_utils import (
    AuthenticationHelper,
    MessageProcessor,
    PackageCollectionScheduler,
    UpdateChecker,
    is_running_privileged,
    reconcile_inflight_journal,
)
from src.sysmanage_agent.core.config import ConfigManager
from src.sysmanage_agent.diagnostics.diagnostic_collector import DiagnosticCollector
from src.sysmanage_agent.operations.child_host_ops_stub import ChildHostOperations
from src.sysmanage_agent.operations.custom_metrics_operations import (
    CustomMetricsOperations,
)
from src.sysmanage_agent.operations.script_operations import ScriptOperations
from src.sysmanage_agent.operations.system_operations import SystemOperations
from src.sysmanage_agent.operations.update_manager import UpdateManager
from src.sysmanage_agent.registration.discovery import discovery_client
from src.sysmanage_agent.registration.registration import ClientRegistration
from src.sysmanage_agent.registration.registration_manager import RegistrationManager
from src.sysmanage_agent.utils.log_rotation import GzipTimedRotatingFileHandler
from src.sysmanage_agent.utils.logging_formatter import UTCTimestampFormatter
from src.sysmanage_agent.utils.native_logging import build_native_handler
from src.sysmanage_agent.utils.verbosity_logger import get_logger


class SysManageAgent(
    AgentDelegatorMixin
):  # pylint: disable=too-many-instance-attributes
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

        # Server-pushed logging overrides (from logging_config_update messages);
        # win over the yaml file when set.  Populated by apply_logging_config.
        self._logging_overrides = {}

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
        self._autostart_task = None
        self._public_ip_task = None

        # Registration state tracking
        self.registration_status = None
        self.needs_registration = False
        self.last_registration_time = None
        self.registration_confirmed = (
            False  # Track if we have received registration_success
        )
        # host_not_registered resilience: a single such error from the server is
        # frequently spurious (a transient tenant-routing miss for a host that
        # genuinely lives in its tenant DB).  We only discard our identity and
        # re-register after the error PERSISTS across this many strikes; any
        # message that proves the server recognizes us resets the count.  This
        # keeps an existing host from re-registering with missing/bad tenant info
        # (burning enrollment-token uses and, once exhausted, spawning a phantom
        # server-scoped duplicate).  See message_handler._handle_host_not_registered.
        self.host_not_registered_strikes = 0

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
        self.custom_metrics_ops = CustomMetricsOperations(self)
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
            logger.exception("Auto-discovery failed: %s", error)
            return False

    def setup_logging(self):
        """Setup logging based on configuration with verbosity support.

        Server-pushed overrides (``self._logging_overrides``, set by
        ``apply_logging_config`` from a ``logging_config_update`` message) win
        over the yaml file, so a change made in the server UI takes effect here
        without a restart.  See ``apply_logging_config``.
        """
        overrides = getattr(self, "_logging_overrides", None) or {}
        log_level = overrides.get("log_level") or self.config.get_log_level()
        # Parse log level - handle pipe-separated levels (use first one)
        if "|" in log_level:
            log_level = log_level.split("|")[0].strip()
        level = log_level.upper()
        log_file = self.config.get_log_file() or self._default_log_file()

        # Clear existing handlers first so re-running setup_logging doesn't
        # double-log or leak the open file handle (a ResourceWarning otherwise).
        root_logger = logging.getLogger()
        self._reset_root_handlers(root_logger)
        formatter = UTCTimestampFormatter(
            "[%(asctime)s UTC] %(levelname)s: %(message)s"
        )

        # File logging: rotate daily, gzip old logs, keep 14 days.  Fall back to
        # console-only if the path isn't writable (e.g. left root-owned).
        try:
            file_handler = GzipTimedRotatingFileHandler(
                log_file, when="midnight", backupCount=14
            )
            file_handler.setLevel(level)
            file_handler.setFormatter(formatter)
            root_logger.addHandler(file_handler)
        except OSError as exc:
            print(
                f"WARNING: cannot write to {log_file} ({exc}); logging to console.",
                file=sys.stderr,
            )
            root_logger.addHandler(logging.StreamHandler())
        root_logger.setLevel(level)

        # Also log to console when running as a daemon (snap/systemd), if asked.
        if os.environ.get("SYSMANAGE_LOG_CONSOLE", "").lower() in ("1", "true", "yes"):
            console_handler = logging.StreamHandler()
            console_handler.setLevel(level)
            console_handler.setFormatter(formatter)
            root_logger.addHandler(console_handler)

        self._add_native_handler(root_logger, level, overrides)

    @staticmethod
    def _default_log_file() -> str:
        """Default log path: ``$SYSMANAGE_LOG_DIR`` (highest priority), the
        system ``/var/log/sysmanage-agent`` dir, else a local ``logs/`` dir."""
        env_log_dir = os.environ.get("SYSMANAGE_LOG_DIR")
        if env_log_dir:
            os.makedirs(env_log_dir, exist_ok=True)
            return os.path.join(env_log_dir, "agent.log")
        if os.path.exists("/var/log/sysmanage-agent"):
            return "/var/log/sysmanage-agent/agent.log"
        logs_dir = os.path.join(os.getcwd(), "logs")
        os.makedirs(logs_dir, exist_ok=True)
        return os.path.join(logs_dir, "agent.log")

    @staticmethod
    def _reset_root_handlers(root_logger: logging.Logger) -> None:
        """Detach and close every existing root handler (close before remove —
        removeHandler alone leaks the open log file)."""
        for handler in root_logger.handlers[:]:
            handler.close()
            root_logger.removeHandler(handler)

    def _add_native_handler(
        self, root_logger: logging.Logger, level: str, overrides: dict
    ) -> None:
        """Attach the OS-native sink (journald / syslog / Windows Event Log)
        when enabled.  Server overrides (DB) win over the yaml file."""
        if "native_enabled" in overrides:
            native_enabled = bool(overrides.get("native_enabled"))
        else:
            native_enabled = self.config.get_log_native()
        if not native_enabled:
            return
        native_handler = build_native_handler(
            target=overrides.get("native_target")
            or self.config.get_log_native_target(),
            identifier=overrides.get("native_identifier")
            or self.config.get_log_native_identifier(),
            # Remote-syslog forwarding (Phase 14.5) — only used when the target
            # is ``syslog_remote``; ignored by the local sinks.
            host=overrides.get("syslog_host") or self.config.get_log_syslog_host(),
            port=overrides.get("syslog_port") or self.config.get_log_syslog_port(),
            facility=overrides.get("syslog_facility")
            or self.config.get_log_syslog_facility(),
            protocol=overrides.get("syslog_protocol")
            or self.config.get_log_syslog_protocol(),
        )
        if native_handler is None:
            print(
                "WARNING: platform-native logging requested but unavailable; "
                "continuing with file logging.",
                file=sys.stderr,
            )
            return
        native_handler.setLevel(level)
        root_logger.addHandler(native_handler)

    def apply_logging_config(self, logging_cfg: dict):
        """Apply a server-pushed logging configuration live (no restart).

        Called when a ``logging_config_update`` message arrives.  Stores the
        config as overrides (which win over the yaml file) and re-runs
        ``setup_logging`` so the new level / native sink take effect immediately.
        """
        if not isinstance(logging_cfg, dict):
            return
        self._logging_overrides = logging_cfg
        try:
            self.setup_logging()
            self.logger.info(
                _("Applied server logging config: level=%s native=%s target=%s"),
                logging_cfg.get("log_level"),
                logging_cfg.get("native_enabled"),
                logging_cfg.get("native_target"),
            )
        except Exception as error:  # pylint: disable=broad-exception-caught
            self.logger.error(_("Failed to apply server logging config: %s"), error)

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
                ssl_context = ssl.create_default_context()  # NOSONAR
                ssl_context.minimum_version = ssl.TLSVersion.TLSv1_2
                if not self.config.should_verify_ssl():
                    ssl_context.check_hostname = (
                        False  # NOSONAR - intentionally configurable
                    )
                    ssl_context.verify_mode = (
                        ssl.CERT_NONE
                    )  # NOSONAR - intentionally configurable

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

    def _parse_server_error_timestamp(self, message_timestamp) -> datetime:
        """Parse a server error message timestamp into a timezone-aware datetime."""
        if isinstance(message_timestamp, str):
            if message_timestamp.endswith("+00:00"):
                message_timestamp = message_timestamp[:-6] + "Z"
            msg_time = datetime.fromisoformat(message_timestamp.replace("Z", "+00:00"))
        else:
            msg_time = message_timestamp

        if msg_time.tzinfo is None:
            msg_time = msg_time.replace(tzinfo=timezone.utc)
        return msg_time

    def _is_stale_error_message(self, data: Dict[str, Any], error_code: str) -> bool:
        """Check if an error message is stale (older than last registration)."""
        message_timestamp = data.get("timestamp")
        self.logger.debug(
            "Error message timestamp validation - timestamp: %s, last_registration_time: %s",
            message_timestamp,
            self.last_registration_time,
        )

        if not message_timestamp or not self.last_registration_time:
            if not message_timestamp:
                self.logger.debug("No timestamp in error message, processing normally")
            if not self.last_registration_time:
                self.logger.debug(
                    "No last_registration_time set, processing error normally"
                )
            return False

        try:
            msg_time = self._parse_server_error_timestamp(message_timestamp)

            if self.last_registration_time.tzinfo is None:
                self.last_registration_time = self.last_registration_time.replace(
                    tzinfo=timezone.utc
                )

            self.logger.debug(
                "Timestamp comparison - msg_time: %s, last_registration: %s",
                msg_time,
                self.last_registration_time,
            )

            if msg_time < self.last_registration_time:
                self.logger.info(
                    "Ignoring stale error message [%s] from %s (registration at %s)",
                    error_code,
                    msg_time,
                    self.last_registration_time,
                )
                return True

            self.logger.debug(
                "Error message is NOT stale - msg_time: %s >= last_registration: %s",
                msg_time,
                self.last_registration_time,
            )
        except (ValueError, TypeError) as error:
            self.logger.warning(
                "Could not parse message timestamp for stale check: %s", error
            )

        return False

    def bump_host_not_registered_strike(self) -> int:
        """Increment and return the consecutive host_not_registered strike count.

        Used by the message handler to tolerate transient/spurious not-registered
        errors before discarding this host's identity (see
        message_handler._handle_host_not_registered)."""
        self.host_not_registered_strikes += 1
        return self.host_not_registered_strikes

    def reset_host_not_registered_strikes(self) -> None:
        """Clear the strike count — the server has proven it recognizes this host."""
        self.host_not_registered_strikes = 0

    async def _handle_server_error(self, data: Dict[str, Any]) -> None:
        """Handle error messages from server."""
        error_code = data.get("error_type", "unknown")
        error_message = data.get("message", "No error message provided")

        if self._is_stale_error_message(data, error_code):
            return

        self.logger.error("Server error [%s]: %s", error_code, error_message)

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

    def _create_ssl_context(self):
        """Create SSL context for WebSocket connection."""
        ssl_context = ssl.create_default_context()  # NOSONAR
        ssl_context.minimum_version = ssl.TLSVersion.TLSv1_2

        cert_paths = self.cert_store.load_certificates()
        if cert_paths:
            client_cert_path, client_key_path, ca_cert_path = cert_paths
            ssl_context.load_cert_chain(client_cert_path, client_key_path)
            ssl_context.load_verify_locations(ca_cert_path)
            ssl_context.check_hostname = True
            ssl_context.verify_mode = ssl.CERT_REQUIRED
            self.logger.info("Using mutual TLS with client certificates")
        elif not self.config.should_verify_ssl():
            ssl_context.check_hostname = False  # NOSONAR - intentionally configurable
            ssl_context.verify_mode = (
                ssl.CERT_NONE
            )  # NOSONAR - intentionally configurable

        return ssl_context

    async def _autostart_child_hosts(self):
        """Background task to auto-start child host VMs after connection."""
        try:
            await self.child_host_ops.autostart_child_hosts()
        except Exception as error:
            self.logger.warning("Failed to auto-start child hosts: %s", error)

    async def _queue_cleanup_loop(self):
        """Periodically purge old completed queue messages so the local agent DB
        doesn't grow without bound (the queue is otherwise never pruned — this
        was observed to reach 21 GB).  Runs daily; first pass after a short delay
        so it doesn't compete with startup."""
        await asyncio.sleep(300)  # let startup settle
        while True:
            try:
                deleted = await self.message_handler.cleanup_old_messages()
                if deleted:
                    self.logger.info("Purged %d old completed queue messages", deleted)
            except Exception as exc:  # pylint: disable=broad-except
                self.logger.warning("Queue cleanup failed: %s", exc)
            await asyncio.sleep(86400)  # daily

    async def _run_agent_tasks(self):
        """Run all concurrent agent tasks and handle their lifecycle."""
        sender_task = asyncio.create_task(self.message_handler.message_sender())
        receiver_task = asyncio.create_task(self.message_handler.message_receiver())
        update_checker_task = asyncio.create_task(self.update_checker())
        # data_collector() is the LOOP variant — it waits for the
        # initial sleep (5 min) BEFORE collecting, which gives the
        # WebSocket handshake time to complete.  Previously this
        # scheduled the one-shot ``_collect_and_send_periodic_data``
        # which raced ``self.agent.connected`` and silently bailed,
        # so OS / hardware / software inventory never landed on the
        # server (Hosts page stayed at "OS Updated: never").
        data_collector_task = asyncio.create_task(self.data_collector.data_collector())
        package_collector_task = asyncio.create_task(self.package_collector())
        child_host_heartbeat_task = asyncio.create_task(self.child_host_heartbeat())
        queue_cleanup_task = asyncio.create_task(self._queue_cleanup_loop())
        # Custom Metrics & Graphs Slice 3: load the persisted enabled set and
        # run the per-cadence scheduler as a background task.
        self.custom_metrics_ops.load_persisted_metrics()
        custom_metrics_task = asyncio.create_task(
            self.custom_metrics_ops.run_metrics_loop()
        )

        done, pending = await asyncio.wait(
            [sender_task, receiver_task],
            return_when=asyncio.FIRST_COMPLETED,
        )

        # Cancel all background and remaining connection tasks
        background_tasks = [
            update_checker_task,
            data_collector_task,
            package_collector_task,
            child_host_heartbeat_task,
            queue_cleanup_task,
            custom_metrics_task,
        ]
        for task in background_tasks:
            task.cancel()
        for task in pending:
            task.cancel()

        # Await all cancelled tasks, collecting exceptions
        all_cancelled = background_tasks + list(pending)
        results = await asyncio.gather(*all_cancelled, return_exceptions=True)
        for result in results:
            if isinstance(result, Exception) and not isinstance(
                result, asyncio.CancelledError
            ):
                self.logger.warning("Task error during shutdown: %s", result)

        # Check if any connection task had an exception
        for task in done:
            if task.exception():
                raise task.exception()

    async def _handle_connection_error(self, base_reconnect_interval: float) -> bool:
        """Handle connection cleanup and reconnection logic. Returns False to break the loop."""
        self.connected = False
        self.websocket = None
        self.running = False
        self.connection_failures += 1

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

        if not self.config.should_auto_reconnect():
            self.logger.info("Auto-reconnect disabled, exiting...")
            return False

        reconnect_interval = min(
            base_reconnect_interval * (2 ** min(self.connection_failures, 6)),
            300,
        )
        jitter = 0.5 + (secrets.randbelow(1000) / 1000.0)
        reconnect_interval *= jitter

        self.logger.info(
            "Reconnecting in %.1f seconds (attempt %d)",
            reconnect_interval,
            self.connection_failures + 1,
        )
        await asyncio.sleep(reconnect_interval)
        return True

    async def _establish_websocket_connection(self):
        """Establish a WebSocket connection and run agent tasks."""
        if not await self._check_server_health():
            self.logger.warning("Server health check failed, waiting before retry...")
            await asyncio.sleep(5)
            return

        if self.needs_registration:
            self.logger.info("Re-registration required, attempting to register...")
            if not await self.registration.register_with_retry():
                self.logger.error(
                    "Failed to re-register with server. Will retry on next connection attempt."
                )
                await asyncio.sleep(10)
                return
            self.needs_registration = False
            self.logger.info("Re-registration successful")

        auth_token = await self.get_auth_token()
        self.logger.info("Got authentication token for WebSocket connection")
        websocket_url = f"{self.server_url}?token={auth_token}"

        ssl_context = None
        if self.server_url.startswith("wss://"):
            ssl_context = self._create_ssl_context()

        ping_interval = self.config.get_ping_interval()
        ping_timeout = ping_interval / 2

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
            self.connection_failures = 0
            self.logger.info(_("Connected to server successfully"))

            try:
                await self.message_handler.on_connection_established()
            except Exception as error:
                self.logger.error(
                    "Failed to start queue processing: %s", error, exc_info=True
                )

            # Launch VM autostart as a background task so it doesn't block
            # the agent's message processing (VM startup can take 30+ seconds)
            self._autostart_task = asyncio.create_task(self._autostart_child_hosts())

            self.logger.info(
                _("Connected to server, waiting for registration confirmation...")
            )

            try:
                await self._run_agent_tasks()
            except asyncio.CancelledError:
                self.logger.debug("Connection tasks cancelled")
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

        # Phase 11.6: reconcile any in-flight subprocess journal entries
        # left behind by a prior agent run.  Runs before the WebSocket is
        # established so dead subprocesses get a synthetic command_result
        # queued for delivery as soon as we connect, clearing the
        # server's DISPATCHED row instead of leaving it hung forever.
        try:
            await reconcile_inflight_journal(self)
        except Exception as error:  # pylint: disable=broad-exception-caught
            self.logger.error(_("In-flight journal reconciliation failed: %s"), error)

        # Phase 12.7: launch the public-IP refresh service.  Fires an
        # immediate fetch so the first heartbeat carries the value, then
        # re-fetches every 24h to catch dynamic-IP rotations.  On airgapped
        # agents the fetch silently returns None and the heartbeat just
        # omits public_ip — no penalty.
        try:
            self._public_ip_task = asyncio.create_task(public_ip_refresh_service())
            self.logger.info("Public-IP refresh service started")
        except Exception as error:  # pylint: disable=broad-exception-caught
            self.logger.warning("Failed to start public-IP refresh service: %s", error)

        self.logger.info(_("Registering with SysManage server..."))
        if not await self.registration.register_with_retry():
            self.logger.error(_("Failed to register with server. Exiting."))
            return

        self.logger.info(_("Registration successful, checking certificates..."))

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
                await self._establish_websocket_connection()

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

            should_continue = await self._handle_connection_error(
                base_reconnect_interval
            )
            if not should_continue:
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
