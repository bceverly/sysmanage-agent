"""
Base test class for message handler tests.
Provides common setup to avoid code duplication.
"""

from unittest.mock import Mock, AsyncMock, patch

from src.sysmanage_agent.communication.message_handler import QueuedMessageHandler


class MessageHandlerTestBase:
    """Base class for message handler tests with common setup."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_agent = Mock()  # pylint: disable=attribute-defined-outside-init
        self.mock_agent.connected = True
        self.mock_agent.websocket = AsyncMock()

        with patch(
            "src.sysmanage_agent.communication.message_handler.MessageQueueManager"
        ):
            # pylint: disable=attribute-defined-outside-init
            self.handler = QueuedMessageHandler(self.mock_agent, "/tmp/test.db")

        self.handler.queue_manager = Mock()
        self.handler.queue_processor_running = False
        # Ensure processing_task is properly initialized
        self.handler.processing_task = None
