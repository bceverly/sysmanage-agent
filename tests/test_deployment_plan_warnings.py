# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""A best-effort step's failure is a WARNING, not an error.

Production, 2026-10-17: an antivirus plan installed ClamAV and started both
services, yet its result said ``success: True`` AND carried
``errors: ["Command 'refresh ClamAV signature database' exited 1: sudo: I'm
sorry ..."]`` -- the failed step was marked ``ignore_errors``, so the plan
was right to succeed, but nobody reading the result could tell which.
"""

from unittest.mock import AsyncMock, Mock, patch

import pytest

from src.sysmanage_agent.operations.generic_deployment import GenericDeployment


def _spawner(failing: str):
    async def _fake(*argv, **_kwargs):
        proc = AsyncMock()
        proc.returncode = 1 if argv and argv[-1] == failing else 0
        proc.pid = 4242
        proc.communicate = AsyncMock(
            return_value=(
                b"",
                b"sudo: I'm sorry sysmanage-agent." if proc.returncode else b"",
            )
        )
        proc.kill = Mock()
        proc.wait = AsyncMock()
        return proc

    return _fake


def _deployment():
    agent = Mock()
    agent.send_message = AsyncMock()
    return GenericDeployment(agent)


@pytest.mark.asyncio
async def test_an_ignored_failure_is_a_warning_and_the_plan_succeeds():
    plan = {
        "commands": [
            {"argv": ["refresh"], "ignore_errors": True, "description": "refresh sigs"},
            {"argv": ["after"]},
        ]
    }
    with patch("asyncio.create_subprocess_exec", new=_spawner("refresh")):
        result = await _deployment().apply_deployment_plan({"plan": plan})
    assert result["success"] is True
    assert result["errors"] == []
    assert len(result["warnings"]) == 1
    assert "refresh sigs" in result["warnings"][0]
    assert result["results"]["commands"][0]["ignored"] is True
    assert "ignored" not in result["results"]["commands"][1]


@pytest.mark.asyncio
async def test_a_required_failure_is_an_error_and_the_plan_fails():
    plan = {"commands": [{"argv": ["needed"], "description": "needed step"}]}
    with patch("asyncio.create_subprocess_exec", new=_spawner("needed")):
        result = await _deployment().apply_deployment_plan({"plan": plan})
    assert result["success"] is False
    assert result["failed_step"] == "commands"
    assert "needed step" in result["errors"][0]
    assert result["warnings"] == []


@pytest.mark.asyncio
async def test_optional_packages_that_fail_are_warnings():
    deployment = _deployment()
    deployment.agent.install_package = AsyncMock(
        return_value={"success": False, "error": "no such package"}
    )
    plan = {"packages": [{"name": "nice-to-have", "optional": True}]}
    result = await deployment.apply_deployment_plan({"plan": plan})
    assert result["success"] is True
    assert result["errors"] == []
    assert any("nice-to-have" in w for w in result["warnings"])


@pytest.mark.asyncio
async def test_a_required_package_that_fails_is_still_an_error():
    deployment = _deployment()
    deployment.agent.install_package = AsyncMock(
        return_value={"success": False, "error": "no such package"}
    )
    plan = {"packages": ["clamav"]}
    result = await deployment.apply_deployment_plan({"plan": plan})
    assert result["success"] is False
    assert result["failed_step"] == "packages"
    assert result["errors"] and result["warnings"] == []


def _exits(code: int):
    async def _fake(*_argv, **_kwargs):
        proc = AsyncMock()
        proc.returncode = code
        proc.pid = 4243
        proc.communicate = AsyncMock(return_value=(b"", b""))
        proc.kill = Mock()
        proc.wait = AsyncMock()
        return proc

    return _fake


@pytest.mark.asyncio
async def test_a_declared_ok_exit_code_is_success_not_a_warning():
    """``pkill -x clamd`` exits 1 when no clamd runs -- the normal case on a
    first install -- and the plan says so with ``ok_exit_codes``."""
    plan = {"commands": [{"argv": ["pkill", "-x", "clamd"], "ok_exit_codes": [0, 1]}]}
    with patch("asyncio.create_subprocess_exec", new=_exits(1)):
        result = await _deployment().apply_deployment_plan({"plan": plan})
    assert result["success"] is True
    assert result["warnings"] == [] and result["errors"] == []
    assert result["results"]["commands"][0]["success"] is True


@pytest.mark.asyncio
@pytest.mark.parametrize("codes", [None, [], "0,1", [True], [0.5]])
async def test_without_valid_ok_exit_codes_only_zero_succeeds(codes):
    spec = {"argv": ["tool"]}
    if codes is not None:
        spec["ok_exit_codes"] = codes
    with patch("asyncio.create_subprocess_exec", new=_exits(1)):
        result = await _deployment().apply_deployment_plan(
            {"plan": {"commands": [spec]}}
        )
    assert result["success"] is False
