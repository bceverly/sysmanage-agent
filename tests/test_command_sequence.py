"""
Unit tests for src.sysmanage_agent.operations.generic_deployment module.
Tests for the GenericDeployment.execute_command_sequence() handler.
"""

# pylint: disable=protected-access,attribute-defined-outside-init

from unittest.mock import AsyncMock, Mock, patch

import pytest

from src.sysmanage_agent.operations.generic_deployment import GenericDeployment


class TestExecuteCommandSequence:
    """Test cases for GenericDeployment.execute_command_sequence() method."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_agent = Mock()
        self.mock_agent.send_message = AsyncMock()
        self.mock_agent.create_message = Mock(return_value={"type": "test"})
        self.mock_agent.execute_shell_command = AsyncMock(
            return_value={"success": True, "result": {"stdout": "output"}}
        )
        self.deployment = GenericDeployment(self.mock_agent)

    @pytest.mark.asyncio
    async def test_sequence_all_steps_succeed(self):
        """3 shell steps all succeed, verify completed_steps == 3."""
        parameters = {
            "steps": [
                {"type": "shell", "command": "echo step1", "description": "Step 1"},
                {"type": "shell", "command": "echo step2", "description": "Step 2"},
                {"type": "shell", "command": "echo step3", "description": "Step 3"},
            ]
        }

        result = await self.deployment.execute_command_sequence(parameters)

        assert result["success"] is True
        assert result["completed_steps"] == 3
        assert result["total_steps"] == 3
        assert len(result["errors"]) == 0

    @pytest.mark.asyncio
    async def test_sequence_stops_on_failure(self):
        """3 steps, step 2 fails, verify completed_steps == 1 and step 3 not executed."""
        self.mock_agent.execute_shell_command = AsyncMock(
            side_effect=[
                {"success": True, "result": {"stdout": "ok"}},
                {"success": False, "error": "command failed"},
                {"success": True, "result": {"stdout": "should not run"}},
            ]
        )

        parameters = {
            "steps": [
                {"type": "shell", "command": "echo step1", "description": "Step 1"},
                {"type": "shell", "command": "false", "description": "Step 2"},
                {"type": "shell", "command": "echo step3", "description": "Step 3"},
            ]
        }

        result = await self.deployment.execute_command_sequence(parameters)

        assert result["success"] is False
        assert result["completed_steps"] == 1
        assert len(result["errors"]) > 0
        # Step 3 should not have been executed - only 2 results
        assert len(result["results"]) == 2

    @pytest.mark.asyncio
    async def test_sequence_empty_steps(self):
        """Empty steps list, expect success False."""
        result = await self.deployment.execute_command_sequence({"steps": []})

        assert result["success"] is False
        assert "No steps provided" in result.get("error", "")

    @pytest.mark.asyncio
    async def test_sequence_shell_step(self):
        """Single shell step, verify agent.execute_shell_command called with correct params."""
        parameters = {
            "steps": [
                {
                    "type": "shell",
                    "command": "systemctl restart myapp",
                    "timeout": 60,
                    "description": "Restart app",
                },
            ]
        }

        result = await self.deployment.execute_command_sequence(parameters)

        assert result["success"] is True
        self.mock_agent.execute_shell_command.assert_called_once_with(
            {"command": "systemctl restart myapp", "timeout": 60}
        )

    @pytest.mark.asyncio
    async def test_sequence_deploy_file_step(self):
        """Step with type 'deploy_file', verify _deploy_single_file called."""
        with patch.object(
            self.deployment,
            "_deploy_single_file",
            new_callable=AsyncMock,
            return_value={"success": True, "path": "/etc/app.conf"},
        ) as mock_deploy:
            parameters = {
                "steps": [
                    {
                        "type": "deploy_file",
                        "path": "/etc/app.conf",
                        "content": "key=value",
                        "permissions": "0644",
                        "description": "Deploy config",
                    },
                ]
            }

            result = await self.deployment.execute_command_sequence(parameters)

            assert result["success"] is True
            mock_deploy.assert_called_once_with(
                {
                    "path": "/etc/app.conf",
                    "content": "key=value",
                    "permissions": "0644",
                    "owner_uid": 0,
                    "owner_gid": 0,
                }
            )

    @pytest.mark.asyncio
    @patch(
        "src.sysmanage_agent.operations.generic_deployment.asyncio.sleep",
        new_callable=AsyncMock,
    )
    async def test_sequence_wait_condition_success(self, mock_sleep):
        """wait_condition step where match found on 2nd attempt."""
        self.mock_agent.execute_shell_command = AsyncMock(
            side_effect=[
                {"success": True, "result": {"stdout": "starting"}},
                {"success": True, "result": {"stdout": "service is running"}},
            ]
        )

        parameters = {
            "steps": [
                {
                    "type": "wait_condition",
                    "command": "systemctl status myapp",
                    "match": "running",
                    "timeout": 120,
                    "interval": 5,
                    "description": "Wait for app",
                },
            ]
        }

        result = await self.deployment.execute_command_sequence(parameters)

        assert result["success"] is True
        assert result["completed_steps"] == 1
        # Sleep called once (between 1st and 2nd attempt)
        mock_sleep.assert_called_once_with(5)

    @pytest.mark.asyncio
    @patch(
        "src.sysmanage_agent.operations.generic_deployment.asyncio.sleep",
        new_callable=AsyncMock,
    )
    async def test_sequence_wait_condition_timeout(self, _mock_sleep):
        """wait_condition step that times out."""
        self.mock_agent.execute_shell_command = AsyncMock(
            return_value={"success": True, "result": {"stdout": "still starting"}}
        )

        parameters = {
            "steps": [
                {
                    "type": "wait_condition",
                    "command": "systemctl status myapp",
                    "match": "running",
                    "timeout": 10,
                    "interval": 5,
                    "description": "Wait for app",
                },
            ]
        }

        result = await self.deployment.execute_command_sequence(parameters)

        assert result["success"] is False
        assert result["completed_steps"] == 0
        assert any("timed out" in err for err in result["errors"])

    @pytest.mark.asyncio
    async def test_sequence_progress_messages(self):
        """Verify progress messages sent during execution."""
        parameters = {
            "steps": [
                {"type": "shell", "command": "echo hello", "description": "Say hello"},
            ]
        }

        result = await self.deployment.execute_command_sequence(parameters)

        assert result["success"] is True
        # create_message called for per-step progress + final progress
        assert self.mock_agent.create_message.call_count >= 2
        assert self.mock_agent.send_message.call_count >= 2

    @pytest.mark.asyncio
    async def test_sequence_with_child_host_id(self):
        """Verify child_host_id passed in progress messages."""
        child_id = "abc-123-def-456"
        parameters = {
            "steps": [
                {"type": "shell", "command": "echo hi", "description": "Greet"},
            ],
            "child_host_id": child_id,
        }

        result = await self.deployment.execute_command_sequence(parameters)

        assert result["success"] is True
        # Verify child_host_id appears in at least one create_message call
        found_child_id = False
        for call in self.mock_agent.create_message.call_args_list:
            args, _kwargs = call
            # create_message(message_type, data) - data is args[1]
            if len(args) >= 2 and isinstance(args[1], dict):
                if args[1].get("child_host_id") == child_id:
                    found_child_id = True
                    break
        assert found_child_id, "child_host_id not found in any progress message"

    @pytest.mark.asyncio
    async def test_sequence_unknown_step_type(self):
        """Step with unknown type returns failure."""
        parameters = {
            "steps": [
                {
                    "type": "reboot_and_pray",
                    "description": "Unknown operation",
                },
            ]
        }

        result = await self.deployment.execute_command_sequence(parameters)

        assert result["success"] is False
        assert result["completed_steps"] == 0
        assert any("Unknown step type" in err for err in result["errors"])
