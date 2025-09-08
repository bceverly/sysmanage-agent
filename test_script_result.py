#!/usr/bin/env python3

"""
Test script to simulate sending a script execution result message
to verify the improved connection stability fixes.
"""

import asyncio
import json
import socket
import sys
import os

# Add current directory to path to import modules
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from message_handler import QueuedMessageHandler
from database.models import Priority


async def test_script_result_message():
    """Test sending a script execution result message."""

    # Mock agent object with basic attributes
    class MockAgent:
        def __init__(self):
            self.connected = True
            self.websocket = None  # Will be set to None to test queueing

    mock_agent = MockAgent()

    # Create message handler
    handler = QueuedMessageHandler(mock_agent, database_path="agent.db")

    # Get hostname for test
    hostname = socket.gethostname()

    # Create test script execution result message
    result_message = {
        "message_type": "script_execution_result",
        "hostname": hostname,
        "execution_id": "test-8b976880-1757264566.814612",  # Using the ID we just created
        "script_name": "Test Improved Handling",
        "success": True,
        "exit_code": 0,
        "stdout": "Testing improved handling\nHostname: mac.theeverlys.com\nTime: Sat Sep  7 13:05:00 EDT 2025\n",
        "stderr": "",
        "execution_time": 0.123,
        "shell_used": "/bin/bash",
        "error": None,
        "timeout": False,
        "timestamp": "2025-09-07T17:05:00.000Z",
    }

    print("Queuing script execution result message...")
    print(f"Message: {json.dumps(result_message, indent=2)}")

    try:
        # Queue the message with high priority
        message_id = await handler.queue_outbound_message(
            result_message, priority=Priority.HIGH
        )

        print(
            f"✅ Successfully queued script execution result message with ID: {message_id}"
        )
        print(f"✅ Message will be sent when agent reconnects to server")

        # Get queue stats
        stats = handler.get_queue_statistics()
        print(f"Queue stats: {json.dumps(stats, indent=2)}")

    except Exception as e:
        print(f"❌ Error queuing message: {e}")
        return False

    finally:
        handler.close()

    return True


if __name__ == "__main__":
    result = asyncio.run(test_script_result_message())
    sys.exit(0 if result else 1)
