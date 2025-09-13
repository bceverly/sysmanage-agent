"""
Message Handler with Persistent Queue Integration.
Provides reliable message delivery with queue-based persistence.
"""

import asyncio
import json
import logging
from typing import Dict, Any

from database.queue_manager import MessageQueueManager
from database.models import QueueDirection, Priority
from i18n import _


class QueuedMessageHandler:
    """
    Message handler that integrates persistent queues with WebSocket communication.

    Ensures all messages are persisted before sending and replayed on reconnection.
    """

    def __init__(self, agent, database_path: str = None):
        """
        Initialize the queued message handler.

        Args:
            agent: Reference to the main SysManageAgent instance
            database_path: Optional path to database file
        """
        self.agent = agent
        self.logger = logging.getLogger(__name__)
        self.queue_manager = MessageQueueManager(database_path)

        # Queue processing state
        self.queue_processor_running = False
        self.processing_task = None

        self.logger.info(_("Queued message handler initialized"))

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

        message_id = self.queue_manager.enqueue_message(
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
            except Exception as e:
                self.logger.error(
                    "Failed to create task from queue_outbound_message: %s", e
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

        message_id = self.queue_manager.enqueue_message(
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
        except Exception as e:
            self.logger.error(_("Failed to send message directly: %s"), e)
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

                    # Mark message as being processed
                    if not self.queue_manager.mark_processing(message.message_id):
                        continue  # Already processed or failed to mark

                    try:
                        # Deserialize message data
                        message_data = self.queue_manager.deserialize_message_data(
                            message
                        )

                        # Send message
                        success = await self.send_message_direct(message_data)

                        if success:
                            # Mark message as completed
                            self.queue_manager.mark_completed(message.message_id)
                            self.logger.info(
                                "Successfully sent queued message: %s",
                                message.message_id,
                            )
                        else:
                            # Mark message as failed, will retry according to retry policy
                            self.queue_manager.mark_failed(
                                message.message_id,
                                "Failed to send over WebSocket",
                                retry=True,
                            )
                            # Connection is likely broken, exit processing loop
                            break

                    except Exception as e:
                        # Mark message as failed
                        error_msg = f"Exception processing message: {str(e)}"
                        self.queue_manager.mark_failed(
                            message.message_id, error_msg, retry=True
                        )
                        self.logger.error(
                            _("Error processing queued message %s: %s"),
                            message.message_id,
                            e,
                        )

                # Delay between message sends to prevent WebSocket buffer overflow
                await asyncio.sleep(1.0)

        except Exception as e:
            self.logger.error(_("Error in queue processor: %s"), e)
        finally:
            self.queue_processor_running = False
            self.logger.debug("Outbound queue processing stopped")

    async def on_connection_established(self):
        """
        Called when WebSocket connection is established.
        Starts processing queued messages.
        """
        self.logger.info(_("Connection established, starting queue processing"))

        # Start queue processing task
        if not self.queue_processor_running:
            self.logger.info(
                "Creating queue processing task from on_connection_established"
            )
            try:
                self.processing_task = asyncio.create_task(
                    self.process_outbound_queue()
                )
                self.logger.info(
                    "Queue processing task created successfully: %s",
                    self.processing_task,
                )
            except Exception as e:
                self.logger.error(
                    "Failed to create queue processing task: %s", e, exc_info=True
                )
        else:
            self.logger.info("Queue processor already running, not starting another")

    async def on_connection_lost(self):
        """
        Called when WebSocket connection is lost.
        Stops queue processing.
        """
        self.logger.info(_("Connection lost, stopping queue processing"))

        # Stop queue processing
        if self.processing_task and not self.processing_task.done():
            self.processing_task.cancel()
            try:
                await self.processing_task
            except asyncio.CancelledError:
                pass

        # Reset the queue processor flag so it can start again on reconnection
        self.queue_processor_running = False

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

    async def cleanup_old_messages(self, older_than_days: int = 7) -> int:
        """
        Clean up old completed messages.

        Args:
            older_than_days: Remove messages older than this many days

        Returns:
            int: Number of messages cleaned up
        """
        return self.queue_manager.cleanup_old_messages(older_than_days)

    def close(self):
        """Clean up resources."""
        try:
            if self.processing_task and not self.processing_task.done():
                self.processing_task.cancel()
            if hasattr(self.queue_manager, "db_manager"):
                self.queue_manager.db_manager.close()
        except Exception as e:
            self.logger.error(_("Error closing message handler: %s"), e)
