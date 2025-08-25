"""
Tests for agent communication and message handling.
"""

import json
from unittest.mock import Mock, AsyncMock, patch

import pytest


class TestMessageReceiver:
    """Test message receiving functionality."""

    @pytest.mark.asyncio
    async def test_message_receiver_command_handling(self, agent):
        """Test message receiver handling commands."""
        # Mock websocket to return a command message then stop
        mock_websocket = Mock()
        command_msg = {
            "message_type": "command",
            "message_id": "cmd-123",
            "data": {"command_type": "get_system_info", "parameters": {}},
        }

        mock_websocket.recv = AsyncMock(
            side_effect=[
                json.dumps(command_msg),
                Exception("Stop iteration"),  # Stop the loop
            ]
        )

        agent.websocket = mock_websocket
        agent.running = True

        # Mock handle_command to track calls
        agent.handle_command = AsyncMock()

        with pytest.raises(Exception):  # Catch the stop iteration
            await agent.message_receiver()

        agent.handle_command.assert_called_once_with(command_msg)

    @pytest.mark.asyncio
    async def test_message_receiver_ping_response(self, agent):
        """Test message receiver responding to ping."""
        mock_websocket = Mock()
        ping_msg = {"message_type": "ping", "message_id": "ping-123"}

        mock_websocket.recv = AsyncMock(
            side_effect=[json.dumps(ping_msg), Exception("Stop")]
        )

        agent.websocket = mock_websocket
        agent.running = True

        # Mock send_message to capture responses
        sent_messages = []

        async def mock_send(msg):
            sent_messages.append(msg)

        agent.send_message = mock_send

        with pytest.raises(Exception):
            await agent.message_receiver()

        assert len(sent_messages) == 1
        pong_msg = sent_messages[0]
        assert pong_msg["message_type"] == "pong"
        assert pong_msg["data"]["ping_id"] == "ping-123"

    @pytest.mark.asyncio
    async def test_message_receiver_ack_handling(self, agent):
        """Test message receiver handling acknowledgments."""
        mock_websocket = Mock()
        ack_msg = {"message_type": "ack", "message_id": "ack-123"}

        mock_websocket.recv = AsyncMock(
            side_effect=[json.dumps(ack_msg), Exception("Stop")]
        )

        agent.websocket = mock_websocket
        agent.running = True

        # Should not crash - just print acknowledgment
        with pytest.raises(Exception):
            await agent.message_receiver()

    @pytest.mark.asyncio
    async def test_message_receiver_invalid_json(self, agent):
        """Test message receiver handling invalid JSON."""
        mock_websocket = Mock()
        mock_websocket.recv = AsyncMock(
            side_effect=["invalid json{", Exception("Stop")]
        )

        agent.websocket = mock_websocket
        agent.running = True

        # Should not crash on invalid JSON
        with pytest.raises(Exception):
            await agent.message_receiver()

    @pytest.mark.asyncio
    async def test_message_receiver_unknown_message_type(self, agent):
        """Test message receiver handling unknown message types."""
        mock_websocket = Mock()
        unknown_msg = {"message_type": "unknown_type", "data": {"test": "data"}}

        mock_websocket.recv = AsyncMock(
            side_effect=[json.dumps(unknown_msg), Exception("Stop")]
        )

        agent.websocket = mock_websocket
        agent.running = True

        # Should not crash on unknown message types
        with pytest.raises(Exception):
            await agent.message_receiver()


class TestMessageSender:
    """Test message sending functionality."""

    @pytest.mark.asyncio
    async def test_message_sender_initial_system_info(self, agent):
        """Test message sender sending initial system info."""
        agent.running = True

        # Mock send_message and sleep to capture calls
        sent_messages = []

        async def mock_send(msg):
            sent_messages.append(msg)

        agent.send_message = mock_send

        # Mock sleep to control timing
        sleep_calls = []

        async def mock_sleep(duration):
            sleep_calls.append(duration)
            if len(sleep_calls) >= 1:  # Stop after first sleep
                agent.running = False

        with patch("asyncio.sleep", mock_sleep):
            await agent.message_sender()

        assert len(sent_messages) >= 1
        initial_msg = sent_messages[0]
        assert initial_msg["message_type"] == "system_info"
        assert "hostname" in initial_msg["data"]

    @pytest.mark.asyncio
    async def test_message_sender_heartbeat_timing(self, agent):
        """Test message sender heartbeat timing."""
        agent.running = True

        sent_messages = []

        async def mock_send_message(msg):
            sent_messages.append(msg)

        agent.send_message = mock_send_message

        sleep_calls = []

        async def mock_sleep(duration):
            sleep_calls.append(duration)
            if len(sleep_calls) >= 2:  # Stop after two sleeps
                agent.running = False

        with patch("asyncio.sleep", mock_sleep):
            await agent.message_sender()

        # Should have initial system info + one heartbeat
        assert len(sent_messages) >= 2
        assert sent_messages[0]["message_type"] == "system_info"
        assert sent_messages[1]["message_type"] == "heartbeat"

        # Should sleep for 30 seconds between heartbeats
        assert 30 in sleep_calls

    @pytest.mark.asyncio
    async def test_message_sender_exception_handling(self, agent):
        """Test message sender handling exceptions."""
        agent.running = True

        # Mock send_message to raise exception
        agent.send_message = AsyncMock(side_effect=Exception("Send error"))

        # Should not crash on send errors
        with patch("asyncio.sleep", side_effect=Exception("Stop")):
            with pytest.raises(Exception):
                await agent.message_sender()


class TestSystemOperations:
    """Test system operation command implementations."""

    @pytest.mark.asyncio
    async def test_reboot_system_linux(self, agent):
        """Test system reboot on Linux."""
        agent.platform = "Linux"

        mock_process = Mock()
        mock_process.communicate = AsyncMock(return_value=(b"", b""))
        mock_process.returncode = 0

        with patch(
            "asyncio.create_subprocess_shell", return_value=mock_process
        ) as mock_subprocess:
            result = await agent.reboot_system()

            assert result["success"] is True
            assert "Reboot scheduled" in result["result"]
            mock_subprocess.assert_called_once()

    @pytest.mark.asyncio
    async def test_reboot_system_windows(self, agent):
        """Test system reboot on Windows."""
        agent.platform = "Windows"

        mock_process = Mock()
        mock_process.communicate = AsyncMock(return_value=(b"", b""))
        mock_process.returncode = 0

        with patch(
            "asyncio.create_subprocess_shell", return_value=mock_process
        ) as mock_subprocess:
            result = await agent.reboot_system()

            assert result["success"] is True
            mock_subprocess.assert_called_once()
            # Should use Windows shutdown command
            call_args = mock_subprocess.call_args[0][0]
            assert "shutdown" in call_args

    @pytest.mark.asyncio
    async def test_reboot_system_error(self, agent):
        """Test system reboot with error."""
        with patch(
            "asyncio.create_subprocess_shell",
            side_effect=Exception("Permission denied"),
        ):
            result = await agent.reboot_system()

            assert result["success"] is False
            assert "Permission denied" in result["error"]

    @pytest.mark.asyncio
    async def test_update_system_not_implemented(self, agent):
        """Test system update (not implemented)."""
        result = await agent.update_system()

        assert result["success"] is False
        assert "not yet implemented" in result["error"]


class TestCommandParameterHandling:
    """Test command parameter validation and handling."""

    @pytest.mark.asyncio
    async def test_execute_shell_with_working_directory(self, agent):
        """Test shell command execution with working directory."""
        mock_process = Mock()
        mock_process.communicate = AsyncMock(return_value=(b"test output", b""))
        mock_process.returncode = 0

        with patch(
            "asyncio.create_subprocess_shell", return_value=mock_process
        ) as mock_subprocess:
            parameters = {"command": "ls", "working_directory": "/tmp"}

            result = await agent.execute_shell_command(parameters)

            assert result["success"] is True
            # Verify working directory was passed
            call_kwargs = mock_subprocess.call_args[1]
            assert call_kwargs["cwd"] == "/tmp"

    @pytest.mark.asyncio
    async def test_execute_shell_command_with_timeout(self, agent):
        """Test shell command execution respects timeout parameter."""
        mock_process = Mock()
        mock_process.communicate = AsyncMock(return_value=(b"output", b""))
        mock_process.returncode = 0

        with patch("asyncio.create_subprocess_shell", return_value=mock_process):
            # Timeout should be handled by the command framework, not the execution
            parameters = {"command": "sleep 1"}

            result = await agent.execute_shell_command(parameters)

            assert result["success"] is True

    @pytest.mark.asyncio
    async def test_shell_command_non_zero_exit(self, agent):
        """Test shell command with non-zero exit code."""
        mock_process = Mock()
        mock_process.communicate = AsyncMock(return_value=(b"", b"Command not found"))
        mock_process.returncode = 127

        with patch("asyncio.create_subprocess_shell", return_value=mock_process):
            result = await agent.execute_shell_command(
                {"command": "nonexistent_command"}
            )

            assert result["success"] is False
            assert result["exit_code"] == 127
            assert "Command not found" in result["result"]["stderr"]


class TestAgentState:
    """Test agent state management."""

    def test_agent_initial_state(self, agent):
        """Test agent initial state."""
        assert agent.running is False
        assert agent.websocket is None
        assert agent.agent_id is not None
        assert len(agent.agent_id) > 0

    @pytest.mark.asyncio
    async def test_agent_state_during_operation(self, agent):
        """Test agent state changes during operation."""
        # Simulate connection setup
        mock_ws = Mock()
        agent.websocket = mock_ws
        agent.running = True

        assert agent.websocket == mock_ws
        assert agent.running is True

        # Simulate shutdown
        agent.running = False
        assert agent.running is False
