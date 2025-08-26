"""
Pytest configuration and shared fixtures for SysManage agent tests.
"""

import asyncio
import sys
import tempfile
import os
from unittest.mock import Mock, AsyncMock, MagicMock

import pytest

# Mock the aiohttp module if not available
if "aiohttp" not in sys.modules:
    sys.modules["aiohttp"] = MagicMock()
    sys.modules["aiohttp.ClientSession"] = MagicMock()
    sys.modules["aiohttp.ClientError"] = Exception

# Import after mocking to avoid import errors
from main import SysManageAgent  # pylint: disable=wrong-import-position


@pytest.fixture
def agent():
    """Create a SysManage agent instance for testing."""
    # Create a secure temporary file for testing
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
        f.write(
            """
server:
  hostname: "test.example.com"
  port: 8000
  use_https: false
  api_path: "/api"
client:
  registration_retry_interval: 1
  max_registration_retries: 1
logging:
  level: "INFO"
websocket:
  auto_reconnect: false
  reconnect_interval: 1
  ping_interval: 5
"""
        )
        temp_config_path = f.name

    try:
        agent_instance = SysManageAgent(temp_config_path)
        yield agent_instance
    finally:
        # Clean up temporary file
        if os.path.exists(temp_config_path):
            os.unlink(temp_config_path)


@pytest.fixture
def mock_websocket():
    """Create a mock WebSocket connection."""
    mock_ws = Mock()
    mock_ws.send = AsyncMock()
    mock_ws.recv = AsyncMock()
    mock_ws.close = AsyncMock()
    return mock_ws


@pytest.fixture
def sample_system_info():
    """Sample system information data."""
    return {
        "hostname": "test.example.com",
        "platform": "Linux",
        "ipv4": "192.168.1.100",
        "ipv6": "2001:db8::1",
        "architecture": "x86_64",
    }


@pytest.fixture
def sample_command_message():
    """Sample command message from server."""
    return {
        "message_type": "command",
        "message_id": "cmd-123",
        "timestamp": "2024-01-01T00:00:00.000000",
        "data": {
            "command_type": "execute_shell",
            "parameters": {"command": "echo hello"},
            "timeout": 300,
        },
    }


@pytest.fixture
def event_loop():
    """Create an event loop for async tests."""
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


@pytest.fixture
def mock_subprocess():
    """Mock subprocess for command execution tests."""
    mock_process = Mock()
    mock_process.communicate = AsyncMock(return_value=(b"Hello World\n", b""))
    mock_process.returncode = 0
    return mock_process
