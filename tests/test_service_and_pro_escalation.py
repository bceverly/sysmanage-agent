# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""Two unprivileged-agent failures seen on beast (2026-10-16):

* antivirus plan service steps ran ``systemctl enable/start`` without sudo,
  so polkit refused them ("requires interactive authentication");
* ``pro enable livepatch`` on an already-enabled host exits 1 and prints
  "... already enabled - nothing to do." on STDOUT, so the agent logged
  "Failed to enable Ubuntu Pro service livepatch: " with an empty reason.
"""

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.sysmanage_agent.core import agent_privileges
from src.sysmanage_agent.operations.ubuntu_pro_operations import (
    UbuntuProOperations,
    _already_in_state,
    _pro_output,
)

SYSTEMCTL = ["/usr/bin/systemctl", "enable", "clamav-daemon"]


class TestServiceEscalation:
    def test_unprivileged_systemctl_goes_through_sudo(self):
        with patch.object(
            agent_privileges.os, "geteuid", return_value=999, create=True
        ):
            assert (
                agent_privileges.escalate_service_cmd(SYSTEMCTL)
                == ["sudo", "-n"] + SYSTEMCTL
            )

    def test_root_runs_it_directly(self):
        with patch.object(agent_privileges.os, "geteuid", return_value=0, create=True):
            assert agent_privileges.escalate_service_cmd(SYSTEMCTL) == SYSTEMCTL

    def test_windows_sc_is_never_prefixed(self):
        cmd = [r"C:\Windows\System32\sc.exe", "start", "svc"]
        with patch.object(
            agent_privileges.os, "geteuid", return_value=999, create=True
        ):
            assert agent_privileges.escalate_service_cmd(cmd) == cmd

    @pytest.mark.asyncio
    async def test_the_service_control_path_uses_it(self):
        from src.sysmanage_agent.core import agent_utils

        processor = agent_utils.MessageProcessor.__new__(agent_utils.MessageProcessor)
        processor.logger = MagicMock()
        ran = {}

        async def fake_run(cmd, timeout):
            ran["cmd"] = cmd
            return SimpleNamespace(returncode=0, stdout="", stderr="")

        with patch.object(
            agent_utils.bsd_service_control, "bsd_system", return_value=None
        ), patch.object(
            agent_utils.MessageProcessor,
            "_build_service_control_cmd",
            return_value=list(SYSTEMCTL),
        ), patch.object(
            agent_utils, "run_command_async", side_effect=fake_run
        ), patch.object(
            agent_privileges.os, "geteuid", return_value=999, create=True
        ):
            result = await processor._process_service_control_action(
                "enable", "clamav-daemon"
            )
        assert result["success"] is True
        assert ran["cmd"][:2] == ["sudo", "-n"]


def _shell(success, stdout="", stderr=""):
    return {"success": success, "result": {"stdout": stdout, "stderr": stderr}}


ALREADY = (
    "One moment, checking your subscription first\n"
    "Livepatch is already enabled - nothing to do.\n"
    "See: sudo pro status\nCould not enable Livepatch.\n"
)


class TestProOutcome:
    def test_already_enabled_is_the_requested_state(self):
        assert _already_in_state(_shell(False, stdout=ALREADY))

    def test_a_real_failure_is_not(self):
        assert not _already_in_state(
            _shell(False, stdout="This machine is not attached")
        )

    def test_the_reason_falls_back_to_stdout(self):
        assert _pro_output(_shell(False, stdout="not attached")) == "not attached"
        assert _pro_output(_shell(False, stdout="x", stderr="boom")) == "boom"

    @pytest.mark.asyncio
    async def test_enable_reports_success_and_escalates_noninteractively(self):
        agent = MagicMock()
        agent.system_ops.execute_shell_command = AsyncMock(
            return_value=_shell(False, stdout=ALREADY)
        )
        ops = UbuntuProOperations(agent)
        ops._send_os_update_after_pro_change = AsyncMock()
        result = await ops.ubuntu_pro_enable_service({"service": "livepatch"})
        assert result["success"] is True
        sent = agent.system_ops.execute_shell_command.await_args.args[0]["command"]
        assert sent.startswith("sudo -n pro enable livepatch")

    @pytest.mark.asyncio
    async def test_a_failure_carries_what_pro_said(self):
        agent = MagicMock()
        agent.system_ops.execute_shell_command = AsyncMock(
            return_value=_shell(
                False, stdout="This machine is not attached to a Pro subscription."
            )
        )
        result = await UbuntuProOperations(agent).ubuntu_pro_enable_service(
            {"service": "livepatch"}
        )
        assert result["success"] is False
        assert "not attached" in result["error"]
