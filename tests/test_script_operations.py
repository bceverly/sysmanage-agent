"""
Tests for the thin script-execution shim.

The agent's script_operations.py was reduced in Phase 5 to a translator
that reformats legacy ``execute_script`` messages into deploy plans for
the existing apply_deployment_plan handler.  These tests cover the new
shape only — shell detection / subprocess management is now the server's
job and is exercised in:
  * sysmanage-professional-plus/module-source/automation_engine tests
  * sysmanage/tests/test_script_plan_builder.py
"""

# pylint: disable=missing-class-docstring,missing-function-docstring,redefined-outer-name

from unittest.mock import AsyncMock, MagicMock

import pytest

from src.sysmanage_agent.operations.script_operations import ScriptOperations


@pytest.fixture
def fake_agent_ok():
    agent = MagicMock()
    agent.config.get_max_script_timeout.return_value = 600
    agent.apply_deployment_plan = AsyncMock(
        return_value={
            "success": True,
            "results": {
                "commands": [
                    {
                        "success": True,
                        "returncode": 0,
                        "stdout": "ok",
                        "stderr": "",
                    },
                    {"success": True, "returncode": 0},  # cleanup
                ]
            },
            "errors": [],
        }
    )
    return agent


@pytest.fixture
def fake_agent_failed():
    agent = MagicMock()
    agent.config.get_max_script_timeout.return_value = 600
    agent.apply_deployment_plan = AsyncMock(
        return_value={"success": False, "errors": ["boom"], "results": {}}
    )
    return agent


class TestScriptShim:
    @pytest.mark.asyncio
    async def test_missing_script_content_rejected(self, fake_agent_ok):
        script_ops = ScriptOperations(fake_agent_ok)
        out = await script_ops.execute_script({})
        assert out["success"] is False
        assert "script_content" in out["error"]
        fake_agent_ok.apply_deployment_plan.assert_not_called()

    @pytest.mark.asyncio
    async def test_bash_default_delegates(self, fake_agent_ok):
        script_ops = ScriptOperations(fake_agent_ok)
        out = await script_ops.execute_script({"script_content": "echo hi"})
        assert out["success"] is True
        assert out["exit_code"] == 0
        # Inspect the deploy plan that was handed to apply_deployment_plan
        call = fake_agent_ok.apply_deployment_plan.call_args
        plan = call.args[0]["plan"]
        assert plan["files"][0]["content"] == "echo hi"
        assert plan["commands"][0]["argv"][0] == "/bin/bash"

    @pytest.mark.asyncio
    async def test_powershell_plan(self, fake_agent_ok):
        script_ops = ScriptOperations(fake_agent_ok)
        await script_ops.execute_script(
            {
                "script_content": "Write-Host hi",
                "shell_type": "powershell",
            }
        )
        plan = fake_agent_ok.apply_deployment_plan.call_args.args[0]["plan"]
        assert plan["files"][0]["path"].endswith(".ps1")
        assert plan["commands"][0]["argv"][0] == "powershell"

    @pytest.mark.asyncio
    async def test_cmd_plan(self, fake_agent_ok):
        script_ops = ScriptOperations(fake_agent_ok)
        await script_ops.execute_script(
            {
                "script_content": "echo hi",
                "shell_type": "cmd",
            }
        )
        plan = fake_agent_ok.apply_deployment_plan.call_args.args[0]["plan"]
        assert plan["files"][0]["path"].endswith(".bat")
        assert plan["commands"][0]["argv"][0] == "cmd.exe"

    @pytest.mark.asyncio
    async def test_timeout_capped_to_max(self, fake_agent_ok):
        fake_agent_ok.config.get_max_script_timeout.return_value = 60
        script_ops = ScriptOperations(fake_agent_ok)
        await script_ops.execute_script({"script_content": "echo", "timeout": 9999})
        plan = fake_agent_ok.apply_deployment_plan.call_args.args[0]["plan"]
        assert plan["commands"][0]["timeout"] == 60

    @pytest.mark.asyncio
    async def test_timeout_passes_through_when_below_max(self, fake_agent_ok):
        script_ops = ScriptOperations(fake_agent_ok)
        await script_ops.execute_script({"script_content": "echo", "timeout": 42})
        plan = fake_agent_ok.apply_deployment_plan.call_args.args[0]["plan"]
        assert plan["commands"][0]["timeout"] == 42

    @pytest.mark.asyncio
    async def test_failed_delegation_surfaces_error(self, fake_agent_failed):
        script_ops = ScriptOperations(fake_agent_failed)
        out = await script_ops.execute_script({"script_content": "echo"})
        assert out["success"] is False
        assert "boom" in out["error"]

    @pytest.mark.asyncio
    async def test_legacy_response_shape_preserved(self, fake_agent_ok):
        # Ensure the response dict has the keys legacy callers expect.
        script_ops = ScriptOperations(fake_agent_ok)
        out = await script_ops.execute_script({"script_content": "echo"})
        assert {"success", "exit_code", "stdout", "stderr"} <= set(out.keys())

    @pytest.mark.asyncio
    async def test_agent_without_apply_plan_handler_fails_gracefully(self):
        # Pre-Phase-3 agent (no apply_deployment_plan attr).  Spec the
        # mock so missing attrs raise AttributeError instead of being
        # auto-created.
        agent = MagicMock(spec=["config"])
        agent.config.get_max_script_timeout.return_value = 600
        script_ops = ScriptOperations(agent)
        out = await script_ops.execute_script({"script_content": "echo"})
        assert out["success"] is False
        assert "apply_deployment_plan" in out["error"]
