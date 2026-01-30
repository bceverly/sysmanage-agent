"""
Message Handler with Persistent Queue Integration.
Provides reliable message delivery with queue-based persistence and message processing.
"""

# pylint: disable=too-many-lines

import asyncio
import json
import logging
import ssl
import uuid
from datetime import datetime, timezone
from typing import Any, Dict

import aiohttp
import websockets

from src.database.models import Priority, QueueDirection
from src.database.queue_manager import MessageQueueManager
from src.i18n import _
from src.sysmanage_agent.core.agent_utils import is_running_privileged


class MessageHandler:
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
        return self.create_message(
            "heartbeat",
            {
                "agent_status": "healthy",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "hostname": system_info["hostname"],
                "ipv4": system_info["ipv4"],
                "ipv6": system_info["ipv6"],
                "is_privileged": is_running_privileged(),
                "script_execution_enabled": self.agent.config.is_script_execution_enabled(),
                "enabled_shells": self.agent.config.get_allowed_shells(),
            },
        )

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
            self.logger.error("Failed to queue message: %s", error)
            return False

    async def handle_command(self, message: Dict[str, Any]):
        """Handle command from server."""
        await self.agent.message_processor.handle_command(message)

    async def _send_command_acknowledgment(self, message_id: str) -> bool:
        """
        Send acknowledgment to server confirming receipt of a command.

        This allows the server to know the command was received and stop retrying.

        Args:
            message_id: The server's message_id that we're acknowledging

        Returns:
            bool: True if acknowledgment was sent successfully
        """
        try:
            ack_message = {
                "message_type": "command_acknowledgment",
                "message_id": message_id,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }

            # Send directly to avoid queuing overhead for simple acks
            success = await self.send_message_direct(ack_message)

            if success:
                self.logger.info(
                    "Sent command acknowledgment for message: %s", message_id
                )
            else:
                self.logger.warning(
                    "Failed to send command acknowledgment for message: %s", message_id
                )

            return success

        except Exception as error:
            self.logger.error(
                "Error sending command acknowledgment for %s: %s", message_id, error
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

        self.logger.error("Server error [%s]: %s", error_code, error_message)

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
                    "Ignoring stale error message [%s] from %s (registration at %s)",
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
                "Could not parse message timestamp for stale check: %s", error
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
            await self.agent.clear_stored_host_id()
            self.logger.info("Stored host_id cleared from database")
        except Exception as error:
            self.logger.error("Error clearing stored host_id: %s", error)

        # Clear any existing registration state and force re-registration
        self.agent.registration_status = None
        self.agent.registration_confirmed = False
        self.agent.registration.registered = False
        # Schedule re-registration on next connection attempt
        self.agent.needs_registration = True
        # Disconnect immediately to trigger reconnection with re-registration
        self.logger.info("Disconnecting to trigger re-registration...")
        self.agent.running = False

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
            self._log_child_host_received(data, queue_message_id, params)

        # Check for duplicate messages (server retry)
        if queue_message_id and self.queue_manager.is_duplicate_message(
            queue_message_id
        ):
            self._log_duplicate_message(command_type, params, queue_message_id)
            await self._send_command_acknowledgment(queue_message_id)
            return  # Duplicate handled

        # Queue command for reliable processing
        await self.queue_inbound_message(data)

        if command_type == "create_child_host":
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

    def _log_child_host_received(
        self, data: Dict[str, Any], queue_message_id: str, params: Dict[str, Any]
    ) -> None:
        """Log detailed info when a create_child_host command is received."""
        timestamp = datetime.now(timezone.utc).isoformat()
        self.logger.info(
            ">>> [CREATE_CHILD_HOST_RECEIVED] timestamp=%s queue_message_id=%s "
            "message_id=%s vm_name=%s hostname=%s child_host_id=%s",
            timestamp,
            queue_message_id,
            data.get("message_id"),
            params.get("vm_name"),
            params.get("hostname"),
            params.get("child_host_id"),
        )

    def _log_duplicate_message(
        self, command_type: str, params: Dict[str, Any], queue_message_id: str
    ) -> None:
        """Log when a duplicate message is skipped."""
        if command_type == "create_child_host":
            self.logger.info(
                ">>> [CREATE_CHILD_HOST_DUPLICATE] Skipping duplicate vm_name=%s "
                "queue_message_id=%s",
                params.get("vm_name"),
                queue_message_id,
            )
        self.logger.info("Skipping duplicate command message: %s", queue_message_id)

    async def message_receiver(self):  # pylint: disable=too-many-branches
        """Handle incoming messages from server."""
        self.logger.debug("Message receiver started")
        try:
            while self.agent.running:
                message = await self.agent.websocket.recv()
                self.logger.debug("Received: %s", message)

                try:
                    data = json.loads(message)
                    should_exit = await self._dispatch_received_message(data)
                    if should_exit:
                        return

                except json.JSONDecodeError:
                    self.logger.error("Invalid JSON received: %s", message)
                except Exception as error:
                    self.logger.error("Error processing message: %s", error)

        except websockets.ConnectionClosed:
            self.logger.info(
                "WEBSOCKET_COMMUNICATION_ERROR: Connection to server closed"
            )
            self.agent.connected = False
            self.agent.websocket = None
        except Exception as error:
            self.logger.error(
                "WEBSOCKET_UNKNOWN_ERROR: Message receiver error: %s", error
            )
            self.agent.connected = False
            self.agent.websocket = None

    async def _dispatch_received_message(self, data: Dict[str, Any]) -> bool:
        """Dispatch a received message to the appropriate handler.

        Returns:
            True if the message receiver loop should exit, False otherwise.
        """
        message_type = data.get("message_type")

        if message_type == "command":
            await self._handle_command_message(data)
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
        elif message_type in self._get_status_confirmation_types():
            self._handle_status_confirmation(message_type, data)
        else:
            self.logger.warning("Unknown message type: %s", message_type)

        return False

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

    # Queue management methods (from QueuedMessageHandler)

    async def queue_outbound_message(
        self,
        message: Dict[str, Any],
        priority: Priority = Priority.NORMAL,
        correlation_id: str = None,
    ) -> str:
        """
        Queue an outbound message for delivery to server.

        Args:
            message: Message to queue
            priority: Message priority
            correlation_id: Optional correlation ID for request/response tracking

        Returns:
            str: Message ID of queued message
        """
        message_type = message.get("message_type", "unknown")

        # Priority mapping based on message type
        if message_type == "heartbeat":
            priority = Priority.HIGH
        elif message_type == "command_result":
            priority = Priority.HIGH
        elif message_type == "script_execution_result":
            priority = Priority.HIGH  # Script results are time-sensitive
        elif message_type == "system_info":
            priority = Priority.NORMAL
        elif message_type == "error":
            priority = Priority.URGENT

        # Run blocking database operation in thread to avoid blocking event loop
        message_id = await asyncio.to_thread(
            self.queue_manager.enqueue_message,
            message_type=message_type,
            message_data=message,
            direction=QueueDirection.OUTBOUND,
            priority=priority,
            correlation_id=correlation_id,
        )

        self.logger.info(
            "Queued outbound message: %s (ID: %s)", message_type, message_id
        )

        # Trigger queue processing if connected
        if self.agent.connected and not self.queue_processor_running:
            self.logger.info(
                "Creating queue processing task from queue_outbound_message"
            )
            try:
                task = asyncio.create_task(self.process_outbound_queue())
                self.logger.info("Task created from queue_outbound_message: %s", task)
            except Exception as error:
                self.logger.error(
                    "Failed to create task from queue_outbound_message: %s", error
                )

        return message_id

    async def queue_inbound_message(self, message: Dict[str, Any]) -> str:
        """
        Queue an inbound message received from server.

        Args:
            message: Message received from server

        Returns:
            str: Message ID of queued message
        """
        message_type = message.get("message_type", "unknown")

        # Run blocking database operation in thread to avoid blocking event loop
        message_id = await asyncio.to_thread(
            self.queue_manager.enqueue_message,
            message_type=message_type,
            message_data=message,
            direction=QueueDirection.INBOUND,
            priority=Priority.NORMAL,
            correlation_id=message.get("correlation_id"),
            reply_to=message.get("reply_to"),
        )

        self.logger.debug(
            "Queued inbound message: %s (ID: %s)", message_type, message_id
        )
        return message_id

    async def process_inbound_queue(self):
        """
        Process queued inbound messages (commands from server).
        Processes messages one at a time to ensure reliable execution.
        """
        if self.inbound_queue_processor_running:
            self.logger.debug("Inbound queue processor already running, exiting")
            return  # Already running

        self.inbound_queue_processor_running = True
        self.logger.info("Starting inbound queue processing")

        try:
            while self.agent.running:
                # Get pending inbound messages ordered by priority
                messages = self.queue_manager.dequeue_messages(
                    direction=QueueDirection.INBOUND, limit=1, priority_order=True
                )

                if not messages:
                    # No messages to process, exit the loop
                    # Will be restarted when new messages arrive
                    break

                for message in messages:
                    if not self.agent.running:
                        break  # Agent shutting down
                    await self._process_single_inbound_message(message)

                # Small delay between processing messages to prevent CPU spinning
                await asyncio.sleep(0.1)

        except Exception as error:
            self.logger.error("Error in inbound queue processor: %s", error)
        finally:
            self.inbound_queue_processor_running = False
            self.logger.debug("Inbound queue processing stopped")

    async def _process_single_inbound_message(self, message) -> None:
        """Process a single inbound message from the queue."""
        # Mark message as being processed
        if not self.queue_manager.mark_processing(message.message_id):
            self.logger.warning(
                "Could not mark inbound message %s as processing",
                message.message_id,
            )
            return  # Already processed or failed to mark

        try:
            # Deserialize message data
            message_data = self.queue_manager.deserialize_message_data(message)

            self.logger.info(
                "Processing queued inbound command: %s (queue_id: %s)",
                message_data.get("data", {}).get("command_type", "unknown"),
                message.message_id,
            )

            # Process the command
            await self.handle_command(message_data)

            # Mark message as completed
            self.queue_manager.mark_completed(message.message_id)
            self.logger.info(
                "Successfully processed inbound message: %s",
                message.message_id,
            )

        except Exception as error:
            # Mark message as failed with retry
            error_msg = f"Exception processing inbound message: {str(error)}"
            self.queue_manager.mark_failed(message.message_id, error_msg, retry=True)
            self.logger.error(
                "Error processing inbound message %s: %s",
                message.message_id,
                error,
            )

    async def send_message_direct(self, message: Dict[str, Any]) -> bool:
        """
        Send message directly over WebSocket (bypassing queue).

        Args:
            message: Message to send

        Returns:
            bool: True if sent successfully, False otherwise
        """
        if not self.agent.connected or not self.agent.websocket:
            self.logger.warning(_("Cannot send message: not connected to server"))
            return False

        try:
            await self.agent.websocket.send(json.dumps(message))
            self.logger.debug("Sent message directly: %s", message.get("message_type"))
            return True
        except Exception as error:
            self.logger.error(_("Failed to send message directly: %s"), error)
            # Mark connection as broken
            self.agent.connected = False
            self.agent.websocket = None
            return False

    async def process_outbound_queue(self):
        """
        Process queued outbound messages and send them to server.
        Only processes messages when connected.
        """
        self.logger.info(
            "Process outbound queue called, current running status: %s",
            self.queue_processor_running,
        )
        if self.queue_processor_running:
            self.logger.info("Queue processor already running, exiting")
            return  # Already running

        self.queue_processor_running = True
        self.logger.info("Starting outbound queue processing")
        self.logger.info("Agent connected status: %s", self.agent.connected)

        try:
            while self.agent.connected:
                # Get pending messages ordered by priority
                messages = self.queue_manager.dequeue_messages(
                    direction=QueueDirection.OUTBOUND, limit=10, priority_order=True
                )

                if not messages:
                    # No messages to process, wait a bit
                    await asyncio.sleep(1)
                    continue

                for message in messages:
                    if not self.agent.connected:
                        break  # Connection lost during processing

                    send_failed = await self._process_single_outbound_message(message)
                    if send_failed:
                        break  # Connection is likely broken

                # Delay between message sends to prevent WebSocket buffer overflow
                await asyncio.sleep(1.0)

        except Exception as error:
            self.logger.error(_("Error in queue processor: %s"), error)
        finally:
            self.queue_processor_running = False
            self.logger.debug("Outbound queue processing stopped")

    async def _process_single_outbound_message(self, message) -> bool:
        """Process a single outbound message from the queue.

        Returns:
            True if the send failed (connection likely broken), False otherwise.
        """
        # Mark message as being processed
        if not self.queue_manager.mark_processing(message.message_id):
            return False  # Already processed or failed to mark

        try:
            # Deserialize message data
            message_data = self.queue_manager.deserialize_message_data(message)

            # Send message
            success = await self.send_message_direct(message_data)

            if success:
                self.queue_manager.mark_completed(message.message_id)
                self.logger.info(
                    "Successfully sent queued message: %s",
                    message.message_id,
                )
                return False

            # Mark message as failed, will retry according to retry policy
            self.queue_manager.mark_failed(
                message.message_id,
                "Failed to send over WebSocket",
                retry=True,
            )
            return True  # Connection is likely broken

        except Exception as error:
            error_msg = f"Exception processing message: {str(error)}"
            self.queue_manager.mark_failed(message.message_id, error_msg, retry=True)
            self.logger.error(
                _("Error processing queued message %s: %s"),
                message.message_id,
                error,
            )
            return False

    async def on_connection_established(  # NOSONAR - async required by caller interface
        self,
    ):
        """
        Called when WebSocket connection is established.
        Recovers stuck messages and starts processing queued messages.

        Note: async is required because callers await this method.
        """
        self.logger.info(_("Connection established, starting queue processing"))

        # Recover any messages stuck in 'in_progress' state from previous crash/disconnect
        try:
            recovered = self.queue_manager.recover_stuck_messages(stale_minutes=10)
            if recovered > 0:
                self.logger.info(
                    "Recovered %d stuck messages on connection establishment", recovered
                )
        except Exception as error:
            self.logger.error("Error recovering stuck messages: %s", error)

        # Start outbound queue processing task
        if not self.queue_processor_running:
            self.logger.info(
                "Creating outbound queue processing task from on_connection_established"
            )
            try:
                self.processing_task = asyncio.create_task(
                    self.process_outbound_queue()
                )
                self.logger.info(
                    "Outbound queue processing task created successfully: %s",
                    self.processing_task,
                )
            except Exception as error:
                self.logger.error(
                    "Failed to create outbound queue processing task: %s",
                    error,
                    exc_info=True,
                )
        else:
            self.logger.info(
                "Outbound queue processor already running, not starting another"
            )

        # Start inbound queue processing task (to handle any pending commands)
        if not self.inbound_queue_processor_running:
            self.logger.info(
                "Creating inbound queue processing task from on_connection_established"
            )
            try:
                self.inbound_processing_task = asyncio.create_task(
                    self.process_inbound_queue()
                )
                self.logger.info(
                    "Inbound queue processing task created successfully: %s",
                    self.inbound_processing_task,
                )
            except Exception as error:
                self.logger.error(
                    "Failed to create inbound queue processing task: %s",
                    error,
                    exc_info=True,
                )
        else:
            self.logger.info(
                "Inbound queue processor already running, not starting another"
            )

    async def on_connection_lost(self):
        """
        Called when WebSocket connection is lost.
        Stops outbound queue processing (inbound continues to process any pending commands).
        """
        self.logger.info(_("Connection lost, stopping outbound queue processing"))

        # Stop outbound queue processing
        if self.processing_task and not self.processing_task.done():
            self.processing_task.cancel()
            try:
                await self.processing_task
            except asyncio.CancelledError:  # NOSONAR
                pass

        # Reset the outbound queue processor flag so it can start again on reconnection
        self.queue_processor_running = False

        # Note: We intentionally do NOT stop inbound queue processing here.
        # Inbound commands should continue to process even when disconnected,
        # as they have already been received and queued.

    def get_queue_statistics(self) -> Dict[str, Any]:
        """
        Get queue statistics for monitoring.

        Returns:
            Dict[str, Any]: Queue statistics
        """
        outbound_stats = self.queue_manager.get_queue_stats(QueueDirection.OUTBOUND)
        inbound_stats = self.queue_manager.get_queue_stats(QueueDirection.INBOUND)

        return {
            "outbound": outbound_stats,
            "inbound": inbound_stats,
            "total": {
                "pending": outbound_stats["pending"] + inbound_stats["pending"],
                "in_progress": outbound_stats["in_progress"]
                + inbound_stats["in_progress"],
                "completed": outbound_stats["completed"] + inbound_stats["completed"],
                "failed": outbound_stats["failed"] + inbound_stats["failed"],
            },
        }

    async def cleanup_old_messages(  # NOSONAR - async required by caller interface
        self, older_than_days: int = 7
    ) -> int:
        """
        Clean up old completed messages.

        Note: async is required because callers await this method.

        Args:
            older_than_days: Remove messages older than this many days

        Returns:
            int: Number of messages cleaned up
        """
        return self.queue_manager.cleanup_old_messages(older_than_days)

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
