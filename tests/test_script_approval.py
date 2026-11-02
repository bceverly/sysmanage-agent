# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""A host that requires approval for scripts runs only approved ones."""

from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest

from src.sysmanage_agent.operations import script_approval
from src.sysmanage_agent.operations.generic_deployment import GenericDeployment
from src.sysmanage_agent.operations.script_operations import ScriptOperations


def _agent(required: bool):
    config = Mock()
    config.is_script_approval_required.return_value = required
    config.get_max_script_timeout.return_value = 3600
    return SimpleNamespace(config=config)


SCRIPT_PLAN = {"kind": "script", "files": [], "commands": []}


def test_an_unapproved_script_is_refused_when_approval_is_required():
    refused = script_approval.check_script(_agent(True), {"script_content": "id"})
    assert refused["success"] is False
    assert "requires approval" in refused["error"]


def test_an_approved_script_runs():
    agent = _agent(True)
    assert script_approval.check_script(agent, {"approval_id": "a1"}) is None


def test_nothing_is_held_when_approval_is_not_required():
    agent = _agent(False)
    assert script_approval.check_script(agent, {}) is None
    assert script_approval.check_plan(agent, {"plan": SCRIPT_PLAN}) is None


def test_a_stub_agent_without_configuration_is_not_held():
    assert script_approval.check_script(SimpleNamespace(), {}) is None


def test_only_a_plan_marked_as_a_script_is_held():
    agent = _agent(True)
    assert script_approval.check_plan(agent, {"plan": {"packages": ["vim"]}}) is None
    assert script_approval.check_plan(agent, {"plan": SCRIPT_PLAN})["success"] is False


def test_a_script_plan_carries_its_approval_in_the_plan_or_the_command():
    agent = _agent(True)
    marked = dict(SCRIPT_PLAN, approval_id="a1")
    assert script_approval.check_plan(agent, {"plan": marked}) is None
    assert (
        script_approval.check_plan(agent, {"plan": SCRIPT_PLAN, "approval_id": "a1"})
        is None
    )


@pytest.mark.asyncio
async def test_execute_script_refuses_before_building_anything():
    agent = _agent(True)
    agent.apply_deployment_plan = AsyncMock()
    result = await ScriptOperations(agent).execute_script({"script_content": "id"})
    assert result["success"] is False
    agent.apply_deployment_plan.assert_not_called()


@pytest.mark.asyncio
async def test_apply_deployment_plan_refuses_an_unapproved_script_plan():
    deployment = GenericDeployment(_agent(True))
    result = await deployment.apply_deployment_plan({"plan": SCRIPT_PLAN})
    assert result["success"] is False
    assert "requires approval" in result["error"]


def test_a_quoted_true_in_the_yaml_still_requires_approval():
    agent = _agent(True)
    agent.config.is_script_approval_required.return_value = "true"
    assert script_approval.check_script(agent, {})["success"] is False
    agent.config.is_script_approval_required.return_value = "no"
    assert script_approval.check_script(agent, {}) is None
