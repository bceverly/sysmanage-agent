"""
Base test class for message handler tests.
Provides common setup to avoid code duplication.
"""

from unittest.mock import AsyncMock, Mock, patch

from src.sysmanage_agent.communication.message_handler import MessageHandler


class MessageHandlerTestBase:
    """Base class for message handler tests with common setup."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_agent = Mock()  # pylint: disable=attribute-defined-outside-init
        self.mock_agent.connected = True
        self.mock_agent.websocket = AsyncMock()
        self.mock_agent.registration_manager = Mock()
        self.mock_agent.registration_manager.get_stored_host_id_sync = Mock(
            return_value="test-host-id"
        )
        self.mock_agent.registration_manager.get_stored_host_token_sync = Mock(
            return_value="test-host-token"
        )

        with patch(
            "src.sysmanage_agent.communication.message_handler.MessageQueueManager"
        ):
            # pylint: disable=attribute-defined-outside-init
            self.handler = MessageHandler(self.mock_agent)

        self.handler.queue_manager = Mock()
        self.handler.queue_processor_running = False
        # Ensure processing_task is properly initialized
        self.handler.processing_task = None
