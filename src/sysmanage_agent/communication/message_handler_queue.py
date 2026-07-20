# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""
Store-and-forward queue mixin for the message handler.

Provides the persistent-queue methods (outbound/inbound enqueue, queue
processors, connection lifecycle hooks, statistics and cleanup) that
:class:`~src.sysmanage_agent.communication.message_handler.MessageHandler`
mixes in.  These methods rely on attributes/methods set up by
``MessageHandler`` (``self.agent``, ``self.logger``, ``self.queue_manager``,
``self.handle_command``, ``self.send_message_direct``, and the various queue
processor state flags), which is fine because the mixin is combined into that
class at runtime.
"""

import asyncio
import json
from typing import Any, Dict

from src.database.models import Priority, QueueDirection
from src.i18n import _


class MessageHandlerQueueMixin:
    """Persistent store-and-forward queue behavior for ``MessageHandler``."""

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

        # Priority mapping based on message type.
        #
        # ``system_info`` is the WebSocket registration handshake — it
        # binds the connection to a host on the server, populates
        # ``connection.hostname`` / ``connection.host_id``, and unlocks
        # processing for every other inbound message type.  It MUST go
        # out before any other queued message on a fresh connection;
        # giving it ``Priority.NORMAL`` previously meant the outbound
        # drain shipped 11 other inventory messages first and registration
        # arrived ~2 seconds late, so on the server side everything that
        # raced ahead landed with a NULL ``_connection_info.hostname``
        # and was dropped by the inbound processor as
        # "Missing hostname and host_id".  ``URGENT`` puts it at the
        # head of the queue so it always wins the drain order.
        if message_type == "system_info":
            priority = Priority.URGENT
        elif message_type == "heartbeat":
            priority = Priority.HIGH
        elif message_type == "command_result":
            priority = Priority.HIGH
        elif message_type == "script_execution_result":
            priority = Priority.HIGH  # Script results are time-sensitive
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
            _("Queued outbound message: %s (ID: %s)"), message_type, message_id
        )

        # Trigger queue processing if connected
        if self.agent.connected and not self.queue_processor_running:
            self.logger.info(
                _("Creating queue processing task from queue_outbound_message")
            )
            try:
                task = asyncio.create_task(self.process_outbound_queue())
                self.logger.info(
                    _("Task created from queue_outbound_message: %s"), task
                )
            except Exception as error:
                self.logger.error(
                    _("Failed to create task from queue_outbound_message: %s"), error
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
        self.logger.info(_("Starting inbound queue processing"))

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
            self.logger.error(_("Error in inbound queue processor: %s"), error)
        finally:
            self.inbound_queue_processor_running = False
            self.logger.debug("Inbound queue processing stopped")

    async def _process_single_inbound_message(self, message) -> None:
        """Process a single inbound message from the queue."""
        # Mark message as being processed
        if not self.queue_manager.mark_processing(message.message_id):
            self.logger.warning(
                _("Could not mark inbound message %s as processing"),
                message.message_id,
            )
            return  # Already processed or failed to mark

        try:
            # Deserialize message data
            message_data = self.queue_manager.deserialize_message_data(message)

            self.logger.info(
                _("Processing queued inbound command: %s (queue_id: %s)"),
                message_data.get("data", {}).get("command_type", "unknown"),
                message.message_id,
            )

            # Process the command
            await self.handle_command(message_data)

            # Mark message as completed
            self.queue_manager.mark_completed(message.message_id)
            self.logger.info(
                _("Successfully processed inbound message: %s"),
                message.message_id,
            )

        except Exception as error:
            # Mark message as failed with retry
            error_msg = f"Exception processing inbound message: {str(error)}"
            self.queue_manager.mark_failed(message.message_id, error_msg, retry=True)
            self.logger.error(
                _("Error processing inbound message %s: %s"),
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
            _("Process outbound queue called, current running status: %s"),
            self.queue_processor_running,
        )
        if self.queue_processor_running:
            self.logger.info(_("Queue processor already running, exiting"))
            return  # Already running

        self.queue_processor_running = True
        self.logger.info(_("Starting outbound queue processing"))
        self.logger.info(_("Agent connected status: %s"), self.agent.connected)

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
                    _("Successfully sent queued message: %s"),
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
                    _("Recovered %d stuck messages on connection establishment"),
                    recovered,
                )
        except Exception as error:
            self.logger.error(_("Error recovering stuck messages: %s"), error)

        # Start outbound queue processing task
        if not self.queue_processor_running:
            self.logger.info(
                _(
                    "Creating outbound queue processing task from on_connection_established"
                )
            )
            try:
                self.processing_task = asyncio.create_task(
                    self.process_outbound_queue()
                )
                self.logger.info(
                    _("Outbound queue processing task created successfully: %s"),
                    self.processing_task,
                )
            except Exception as error:
                self.logger.error(
                    _("Failed to create outbound queue processing task: %s"),
                    error,
                    exc_info=True,
                )
        else:
            self.logger.info(
                _("Outbound queue processor already running, not starting another")
            )

        # Start inbound queue processing task (to handle any pending commands)
        if not self.inbound_queue_processor_running:
            self.logger.info(
                _(
                    "Creating inbound queue processing task from on_connection_established"
                )
            )
            try:
                self.inbound_processing_task = asyncio.create_task(
                    self.process_inbound_queue()
                )
                self.logger.info(
                    _("Inbound queue processing task created successfully: %s"),
                    self.inbound_processing_task,
                )
            except Exception as error:
                self.logger.error(
                    _("Failed to create inbound queue processing task: %s"),
                    error,
                    exc_info=True,
                )
        else:
            self.logger.info(
                _("Inbound queue processor already running, not starting another")
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
