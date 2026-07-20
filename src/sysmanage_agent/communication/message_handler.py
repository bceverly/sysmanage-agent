# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""
Message Handler with Persistent Queue Integration.
Provides reliable message delivery with queue-based persistence and message processing.
"""

import asyncio
import json
import logging
import ssl
import uuid
from datetime import datetime, timezone
from typing import Any, Dict

import aiohttp
import websockets

from src.database.queue_manager import MessageQueueManager
from src.i18n import _
from src.sysmanage_agent.collection import public_ip_fetcher
from src.sysmanage_agent.communication.message_handler_queue import (
    MessageHandlerQueueMixin,
)
from src.sysmanage_agent.communication.message_logging_helpers import (
    log_child_host_received,
    log_duplicate_message,
)
from src.sysmanage_agent.core.agent_utils import is_running_privileged
from src.sysmanage_agent.core.version import get_agent_version

# How many consecutive host_not_registered errors the agent tolerates (reconnecting
# with its identity intact so the server can re-resolve it) before concluding the
# host is genuinely gone and discarding host_id to re-register.  Keeps a spurious /
# transient server-side tenant-routing miss from wiping a valid host's identity and
# spawning phantom duplicates.
HOST_NOT_REGISTERED_STRIKE_LIMIT = 3


class MessageHandler(MessageHandlerQueueMixin):
    """
    Message handler that integrates persistent queues with WebSocket communication.

    Handles message creation, sending, receiving, and error handling for the agent.
    Ensures all messages are persisted before sending and replayed on reconnection.
    """

    def __init__(self, agent_instance):
        """
        Initialize the message handler.

        Args:
            agent_instance: Reference to the main SysManageAgent instance
        """
        self.agent = agent_instance
        self.logger = logging.getLogger(__name__)
        self.queue_manager = MessageQueueManager()

        # Queue processing state
        self.queue_processor_running = False
        self.processing_task = None

        # Inbound queue processing state
        self.inbound_queue_processor_running = False
        self.inbound_processing_task = None

        self.logger.info(_("Message handler initialized"))

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
            stored_host_id = self.agent.registration_manager.get_stored_host_id_sync()
            stored_host_token = (
                self.agent.registration_manager.get_stored_host_token_sync()
            )
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
        system_info = self.agent.registration.get_system_info()
        return self.create_message("system_info", system_info)

    def create_heartbeat_message(self):
        """Create heartbeat message."""
        # Include system info in heartbeat to allow server to recreate deleted hosts
        system_info = self.agent.registration.get_system_info()
        # Phase 12.7: include the cached public IP so the server can
        # resolve it to (country, subdivision, city, lat/lon) via the
        # GeoLite2 chain.  ``public_ip_fetcher.get()`` returns the
        # last value fetched by the background refresh service (or
        # None on airgapped agents — server-side just skips the geo
        # update in that case).
        payload = {
            "agent_status": "healthy",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "hostname": system_info["hostname"],
            "ipv4": system_info["ipv4"],
            "ipv6": system_info["ipv6"],
            "is_privileged": is_running_privileged(),
            "script_execution_enabled": self.agent.config.is_script_execution_enabled(),
            "enabled_shells": self.agent.config.get_allowed_shells(),
            "agent_version": get_agent_version(),
        }
        public_ip = public_ip_fetcher.get()
        if public_ip:
            payload["public_ip"] = public_ip
        return self.create_message("heartbeat", payload)

    async def send_message(self, message: Dict[str, Any]):
        """Send a message to the server using persistent queue."""
        try:
            # Queue message for reliable delivery
            message_id = await self.queue_outbound_message(message)
            self.logger.debug(
                "Queued message: %s (ID: %s)", message.get("message_type"), message_id
            )
            return True
        except Exception as error:
            self.logger.error(_("Failed to queue message: %s"), error)
            return False

    async def handle_command(self, message: Dict[str, Any]):
        """Handle command from server."""
        await self.agent.message_processor.handle_command(message)

    async def _send_command_acknowledgment(self, message_id: str) -> bool:
        """
        Queue an acknowledgment to the server confirming receipt of a command.

        Goes through the standard outbound queue rather than ``send_message_direct``
        to honor the architectural rule that all agent → server traffic flows
        through the SQLite outbound queue.  ``queue_outbound_message`` already
        gives ack-class messages priority handling so the server still sees the
        ack quickly enough to stop its retry loop.

        Args:
            message_id: The server's message_id that we're acknowledging

        Returns:
            bool: True if acknowledgment was queued successfully
        """
        try:
            ack_message = {
                "message_type": "command_acknowledgment",
                "message_id": message_id,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }

            success = await self.send_message(ack_message)

            if success:
                self.logger.info(
                    _("Queued command acknowledgment for message: %s"), message_id
                )
            else:
                self.logger.warning(
                    _("Failed to queue command acknowledgment for message: %s"),
                    message_id,
                )

            return success

        except Exception as error:
            self.logger.error(
                _("Error queueing command acknowledgment for %s: %s"),
                message_id,
                error,
            )
            return False

    async def _check_server_health(self) -> bool:
        """Check if server is available by testing the root endpoint."""
        try:
            # Build health check URL - use base server URL without /api prefix
            # since health check should be unauthenticated
            server_config = self.agent.config.get_server_config()
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
                if not self.agent.config.should_verify_ssl():
                    ssl_context.check_hostname = False  # NOSONAR
                    ssl_context.verify_mode = ssl.CERT_NONE  # NOSONAR

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

    async def _handle_server_error(self, data: Dict[str, Any]) -> None:
        """Handle error messages from server."""
        # Server sends error_type and message at top level, not in data field
        error_code = data.get("error_type", "unknown")
        error_message = data.get("message", "No error message provided")

        # Check if this is a stale error message
        if self._is_stale_error_message(data, error_code):
            return

        self.logger.error(_("Server error [%s]: %s"), error_code, error_message)

        # Handle specific error codes from server
        await self._dispatch_server_error(error_code, error_message)

    def _is_stale_error_message(self, data: Dict[str, Any], error_code: str) -> bool:
        """Check if an error message is stale (older than our last registration).

        Returns:
            True if the message is stale and should be ignored, False otherwise.
        """
        message_timestamp = data.get("timestamp")
        self.logger.debug(
            "Error message timestamp validation - timestamp: %s, last_registration_time: %s",
            message_timestamp,
            self.agent.last_registration_time,
        )

        if not message_timestamp or not self.agent.last_registration_time:
            if not message_timestamp:
                self.logger.debug("No timestamp in error message, processing normally")
            if not self.agent.last_registration_time:
                self.logger.debug(
                    "No last_registration_time set, processing error normally"
                )
            return False

        try:
            msg_time = self._parse_message_timestamp(message_timestamp)

            self.logger.debug(
                "Timestamp comparison - msg_time: %s, last_registration: %s",
                msg_time,
                self.agent.last_registration_time,
            )

            # If the error message is older than our last registration, ignore it
            if msg_time < self.agent.last_registration_time:
                self.logger.info(
                    _("Ignoring stale error message [%s] from %s (registration at %s)"),
                    error_code,
                    msg_time,
                    self.agent.last_registration_time,
                )
                return True

            self.logger.debug(
                "Error message is NOT stale - msg_time: %s >= last_registration: %s",
                msg_time,
                self.agent.last_registration_time,
            )
        except (ValueError, TypeError) as error:
            self.logger.warning(
                _("Could not parse message timestamp for stale check: %s"), error
            )

        return False

    def _parse_message_timestamp(self, message_timestamp) -> datetime:
        """Parse a message timestamp string into a timezone-aware datetime.

        Also ensures self.agent.last_registration_time is timezone-aware as a side effect.

        Returns:
            A timezone-aware datetime object.
        """
        if isinstance(message_timestamp, str):
            # Handle ISO format timestamps
            if message_timestamp.endswith("+00:00"):
                message_timestamp = message_timestamp[:-6] + "Z"
            msg_time = datetime.fromisoformat(message_timestamp.replace("Z", "+00:00"))
        else:
            msg_time = message_timestamp

        # Ensure both timestamps are timezone-aware
        if msg_time.tzinfo is None:
            msg_time = msg_time.replace(tzinfo=timezone.utc)
        if self.agent.last_registration_time.tzinfo is None:
            self.agent.last_registration_time = (
                self.agent.last_registration_time.replace(tzinfo=timezone.utc)
            )

        return msg_time

    async def _dispatch_server_error(self, error_code: str, error_message: str) -> None:
        """Dispatch handling for specific server error codes."""
        if error_code == "host_not_registered":
            await self._handle_host_not_registered()
        elif error_code == "host_not_approved":
            self.logger.warning(
                _(
                    "Host registration is pending approval. Will continue periodic attempts."
                )
            )
        elif error_code == "missing_hostname":
            self.logger.error(
                _("Server reports missing hostname in message. This is a bug.")
            )
        elif error_code == "queue_error":
            self.logger.error(_("Server failed to queue message: %s"), error_message)

    async def _handle_host_not_registered(self) -> None:
        """React to a host_not_registered error from the server.

        A SINGLE such error is frequently spurious: under multi-tenancy the server
        resolves a host's tenant database from its host_id, and a transient routing
        miss (or a handler that doesn't consult the tenant index) reports a host
        that genuinely lives in its tenant DB as "not registered".  Blindly
        clearing our host_id and re-registering on the first error is the ROOT of
        the phantom-duplicate churn: it discards the tenant binding, burns an
        enrollment-token use on every reconnect, and once the token is exhausted a
        token-less re-registration lands server-scoped (the phantom duplicate).

        So we tolerate a few strikes, reconnecting WITHOUT dropping our identity —
        which lets the server re-resolve us from the still-present host_id — and
        only treat the host as genuinely gone (clear + re-register) once the error
        PERSISTS.  Any inbound message the server only sends to a recognized host
        resets the strike count (see _dispatch_received_message)."""
        strikes = self.agent.bump_host_not_registered_strike()

        if strikes < HOST_NOT_REGISTERED_STRIKE_LIMIT:
            self.logger.warning(
                _(
                    "Server reported host_not_registered (strike %(n)d/%(limit)d) — "
                    "reconnecting WITHOUT discarding host_id so the server can "
                    "re-resolve this host from its tenant index; will re-register "
                    "only if it persists."
                ),
                {"n": strikes, "limit": HOST_NOT_REGISTERED_STRIKE_LIMIT},
            )
            # Disconnect to force a fresh connection; identity is preserved.
            self.agent.running = False
            return

        self.logger.warning(
            _(
                "host_not_registered persisted (%(n)d strikes) — treating this host "
                "as genuinely gone; clearing stored host_id and re-registering."
            ),
            {"n": strikes},
        )

        # Clear stored host_id from database
        try:
            await self.agent.clear_stored_host_id()
            self.logger.info(_("Stored host_id cleared from database"))
        except Exception as error:
            self.logger.error(_("Error clearing stored host_id: %s"), error)

        # Clear any existing registration state and force re-registration
        self.agent.reset_host_not_registered_strikes()
        self.agent.registration_status = None
        self.agent.registration_confirmed = False
        self.agent.registration.registered = False
        # Schedule re-registration on next connection attempt
        self.agent.needs_registration = True
        # Disconnect immediately to trigger reconnection with re-registration
        self.logger.info(_("Disconnecting to trigger re-registration..."))
        self.agent.running = False

    async def _handle_broadcast_message(self, data: Dict[str, Any]) -> None:
        """Handle a Phase 8.5 BROADCAST message from the server.

        Broadcasts are server-fanned-out one-to-many messages used for
        operator-initiated fleet actions like ``refresh_inventory`` or
        a global banner.  The action semantic is encoded in
        ``data["broadcast_action"]``;  the agent picks how to react.

        Currently supported actions:

          ``refresh_inventory``   Re-collect software inventory + push
                                  an out-of-band ``software_inventory_update``
                                  via the existing data collector.
          ``banner``              Log the message at INFO level so it's
                                  visible in agent logs / journalctl.
          (anything else)         Logged as warning, no action taken.

        New broadcast actions are added by name here — keeping the
        dispatch in one place makes the supported-actions list easy to
        document and audit."""
        broadcast_id = data.get("broadcast_id", "unknown")
        action = data.get("broadcast_action", "")
        self.logger.info(
            _("Received broadcast %s action=%s issued_by=%s"),
            broadcast_id,
            action,
            data.get("issued_by", "unknown"),
        )

        if action == "refresh_inventory":
            try:
                await self.agent.data_collector.send_software_inventory_update()
                self.logger.info(
                    _("Broadcast %s: software inventory refreshed"), broadcast_id
                )
            except AttributeError:
                # Older agent builds may not expose
                # ``send_software_inventory_update``.  Best-effort:
                # fall back to a no-op.
                self.logger.warning(
                    _(
                        "Broadcast %s: inventory refresh requested but "
                        "data_collector lacks send_software_inventory_update"
                    ),
                    broadcast_id,
                )
            except Exception as exc:  # pylint: disable=broad-exception-caught
                self.logger.error(
                    _("Broadcast %s: inventory refresh failed: %s"),
                    broadcast_id,
                    exc,
                )
        elif action == "banner":
            message = data.get("message") or "(no message)"
            # Structural diagnostic marker, not user prose — keep untranslated.
            self.logger.info("[BANNER] %s", message)
        else:
            self.logger.warning(
                _("Broadcast %s: unknown action '%s' — ignored"),
                broadcast_id,
                action,
            )

    async def _handle_command_message(self, data: Dict[str, Any]) -> None:
        """
        Handle a command message from the server.

        Processes the command (or acknowledges a duplicate) and triggers
        inbound queue processing if needed.

        Args:
            data: Parsed message data
        """
        # Get the queue_message_id for acknowledgment (this is what the server tracks)
        queue_message_id = data.get("queue_message_id") or data.get("message_id")

        # Extract command details for logging
        command_data = data.get("data", {})
        command_type = command_data.get("command_type")
        params = command_data.get("parameters", {})

        # Detailed logging for create_child_host commands
        if command_type == "create_child_host":
            log_child_host_received(self.logger, data, queue_message_id, params)

        # Check for duplicate messages (server retry)
        if queue_message_id and self.queue_manager.is_duplicate_message(
            queue_message_id
        ):
            log_duplicate_message(self.logger, command_type, params, queue_message_id)
            await self._send_command_acknowledgment(queue_message_id)
            return  # Duplicate handled

        # Queue command for reliable processing
        await self.queue_inbound_message(data)

        if command_type == "create_child_host":
            # Structural diagnostic marker (field=value trace), not user prose.
            self.logger.info(
                ">>> [CREATE_CHILD_HOST_QUEUED] vm_name=%s queue_message_id=%s",
                params.get("vm_name"),
                queue_message_id,
            )

        # Send acknowledgment to server to confirm receipt
        if queue_message_id:
            await self._send_command_acknowledgment(queue_message_id)

        # Trigger inbound queue processing if not already running
        if not self.inbound_queue_processor_running:
            self.inbound_processing_task = asyncio.create_task(
                self.process_inbound_queue()
            )

    async def message_receiver(self):  # pylint: disable=too-many-branches
        """Handle incoming messages from server.

        Exits cleanly on ``ConnectionClosed`` (the outer ``run()`` loop
        treats that as a normal completion and reconnects).  Any other
        exception is logged and **re-raised** so the connection-error
        path in ``_run_agent_tasks`` / ``run()`` gets a chance to tear
        down + reconnect.  Without the re-raise, the receiver task
        quietly dies, the sender task keeps the WS pumping outbound
        traffic, and inbound commands silently disappear forever
        (observed: ``'NoneType' object has no attribute 'recv'`` race
        when ``self.agent.websocket`` is cleared mid-loop by another
        coroutine — the resulting ``AttributeError`` was being
        swallowed and the agent stopped processing all server
        commands until manual restart).
        """
        self.logger.debug("Message receiver started")
        try:
            while self.agent.running:
                # Defensive: if a concurrent disconnect cleared the
                # websocket between iterations, surface that as a
                # ConnectionClosed rather than letting recv() raise an
                # AttributeError on None.
                ws = self.agent.websocket
                if ws is None:
                    self.logger.info(
                        _(
                            "Message receiver: websocket cleared by concurrent "
                            "disconnect; exiting receive loop to allow reconnect"
                        )
                    )
                    raise websockets.ConnectionClosed(None, None)
                message = await ws.recv()
                self.logger.debug("Received: %s", message)

                try:
                    data = json.loads(message)
                    should_exit = await self._dispatch_received_message(data)
                    if should_exit:
                        return

                except json.JSONDecodeError:
                    self.logger.error(_("Invalid JSON received: %s"), message)
                except Exception as error:  # pylint: disable=broad-exception-caught
                    self.logger.error(_("Error processing message: %s"), error)

        except websockets.ConnectionClosed:
            self.logger.info(
                _("WEBSOCKET_COMMUNICATION_ERROR: Connection to server closed")
            )
            self.agent.connected = False
            self.agent.websocket = None
            # Returning normally here is intentional — the outer
            # ``_run_agent_tasks`` waits with FIRST_COMPLETED and ``run()``
            # reconnects via _handle_connection_error.
        except Exception as error:
            self.logger.error(
                _("WEBSOCKET_UNKNOWN_ERROR: Message receiver error: %s"), error
            )
            self.agent.connected = False
            self.agent.websocket = None
            # Re-raise so ``_run_agent_tasks`` sees the failure via
            # ``task.exception()`` and propagates it to ``run()``'s
            # connection-error handler.  Previously this was swallowed,
            # leaving the receiver task dead but the sender alive — the
            # net effect was inbound commands silently disappearing
            # until the agent was manually restarted.
            raise

    async def _dispatch_received_message(self, data: Dict[str, Any]) -> bool:
        """Dispatch a received message to the appropriate handler.

        Returns:
            True if the message receiver loop should exit, False otherwise.
        """
        message_type = data.get("message_type")

        # Proof-of-life: any message the server only sends to a REGISTERED,
        # recognized host clears accumulated host_not_registered strikes, so a
        # transient/spurious not-registered error can't snowball into an identity
        # wipe.  Excludes ping/broadcast (connection-level, not host-specific) and
        # error (which may itself be host_not_registered).
        if message_type in self._host_recognized_message_types():
            self.agent.reset_host_not_registered_strikes()

        if message_type == "command":
            await self._handle_command_message(data)
        elif message_type == "broadcast":
            await self._handle_broadcast_message(data)
        elif message_type == "ping":
            pong = self.create_message("pong", {"ping_id": data.get("message_id")})
            await self.send_message(pong)
        elif message_type == "ack":
            self._handle_ack_message(data)
        elif message_type == "error":
            await self._handle_server_error(data)
            if self.agent.needs_registration:
                return True
        elif message_type == "host_approved":
            await self.agent.handle_host_approval(data)
        elif message_type == "registration_success":
            await self.agent.handle_registration_success(data)
        elif message_type == "logging_config_update":
            # The payload is nested under the envelope's "data" key (same as
            # command/ack messages), not at the top level.
            self.agent.apply_logging_config(data.get("data", {}).get("logging") or {})
        elif message_type in self._get_status_confirmation_types():
            self._handle_status_confirmation(message_type, data)
        else:
            self.logger.warning(_("Unknown message type: %s"), message_type)

        return False

    def _host_recognized_message_types(self) -> set:
        """Message types the server only sends to a registered, recognized host.

        Receiving any of these proves the server knows this host, so it resets the
        host_not_registered strike counter.  Deliberately excludes ping/broadcast
        (connection-level, not host-specific) and error."""
        return {
            "command",
            "ack",
            "host_approved",
            "registration_success",
        } | set(self._get_status_confirmation_types())

    def _get_status_confirmation_types(self) -> dict:
        """Return mapping of status confirmation message types to log descriptions."""
        return {
            "diagnostic_result_ack": "diagnostic processing",
            "available_packages_batch_queued": "packages batch queued",
            "available_packages_batch_start_queued": "packages batch start queued",
            "available_packages_batch_end_queued": "packages batch end queued",
        }

    def _handle_status_confirmation(
        self, message_type: str, data: Dict[str, Any]
    ) -> None:
        """Handle status confirmation messages from the server."""
        status = data.get("status", "unknown")
        description = self._get_status_confirmation_types()[message_type]
        self.logger.debug("Server confirmed %s: %s", description, status)

    def _handle_ack_message(self, data: Dict[str, Any]) -> None:
        """Handle an acknowledgment message from the server."""
        ack_data = data.get("data", {})
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

    async def message_sender(self):
        """Handle periodic outgoing messages to server."""
        self.logger.debug("Message sender started")

        # Send initial system info
        system_info = self.create_system_info_message()
        await self.send_message(system_info)

        # Send periodic heartbeats
        ping_interval = self.agent.config.get_ping_interval()
        while self.agent.running:
            try:
                await asyncio.sleep(ping_interval)
                if self.agent.running and self.agent.connected:
                    heartbeat = self.create_heartbeat_message()
                    success = await self.send_message(heartbeat)
                    if not success:
                        self.logger.warning(
                            _("Heartbeat failed, connection may be lost")
                        )
                        # Don't break, let the connection handling in run() deal with it
                        return
            except asyncio.CancelledError:
                # Graceful shutdown - re-raise to propagate cancellation
                self.logger.debug("Message sender cancelled")
                raise
            except Exception as error:
                self.logger.error(_("Message sender error: %s"), error)
                # Don't break the loop on non-critical errors, but return to trigger reconnection
                return

    def close(self):
        """Clean up resources."""
        try:
            # Cancel outbound processing task
            if self.processing_task and not self.processing_task.done():
                self.processing_task.cancel()
            # Cancel inbound processing task
            if self.inbound_processing_task and not self.inbound_processing_task.done():
                self.inbound_processing_task.cancel()
            if hasattr(self.queue_manager, "db_manager"):
                self.queue_manager.db_manager.close()
        except Exception as error:
            self.logger.error(_("Error closing message handler: %s"), error)
