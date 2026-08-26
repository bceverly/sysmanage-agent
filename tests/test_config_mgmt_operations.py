# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""Applying configuration profiles locally (Phase 20.1).

The security-relevant property is that ``-c local`` is PINNED into the argv.
Pull-style makes every host its own controller, so a profile carrying a stray
``hosts:`` entry must not be able to turn into an outbound SSH attempt -- that
would spend the Phase 19 "agent->server, 443 only, no inbound" guarantee at the
point where it is least visible.  It is asserted rather than trusted.

The rest of these pin behaviour that was OBSERVED against real binaries
(ansible-core 2.21.3, dsc 3.2.3) rather than assumed:

  * dsc logs to stderr with ANSI colour and results to stdout, so the streams
    must stay separate or the JSON parse dies;
  * a failing dsc run prints NOTHING to stdout, so its verdict has to come
    from the exit code;
  * dsc takes its input on stdin via ``--file -`` because PowerShell 5.1
    strips the quotes out of an inline ``--input`` JSON argument.
"""

import asyncio
import json
import logging
import os
import types
from unittest.mock import patch

import pytest

from src.sysmanage_agent.operations import config_mgmt_operations as ops_mod
from src.sysmanage_agent.operations.config_mgmt_operations import ConfigMgmtOperations

MOD = "src.sysmanage_agent.operations.config_mgmt_operations"
PLAYBOOK = "- hosts: localhost\n  tasks: []\n"


def make_ops():
    return ConfigMgmtOperations(
        types.SimpleNamespace(logger=logging.getLogger("test-cfg"))
    )


class FakeProc:
    """Stands in for an asyncio subprocess."""

    def __init__(self, rc=0, stdout=b"", stderr=b"", hang=False):
        self.returncode = rc
        self._stdout = stdout
        self._stderr = stderr
        self._hang = hang
        self.killed = False
        self.waited = False
        self.stdin_received = None
        self.pid = 1234

    async def communicate(self, input=None):  # pylint: disable=redefined-builtin
        self.stdin_received = input
        if self._hang:
            await asyncio.sleep(3600)
        return self._stdout, self._stderr

    def kill(self):
        self.killed = True

    async def wait(self):
        self.waited = True
        return self.returncode


def spawn_patch(proc, captured):
    async def _spawn(*argv, **kwargs):
        captured["argv"] = list(argv)
        captured["kwargs"] = kwargs
        return proc

    return _spawn


class TestGuards:
    @pytest.mark.asyncio
    async def test_no_executor_reports_a_reason_rather_than_raising(self):
        with patch(f"{MOD}.locator.find_executor", return_value=None):
            result = await make_ops().apply_config_profile(
                {"profile": {"playbook": PLAYBOOK}}
            )
        assert result["success"] is False
        assert result["reason"] == ops_mod.REASON_NO_EXECUTOR

    @pytest.mark.asyncio
    async def test_empty_profile_is_refused_before_spawning_anything(self):
        captured = {}
        with patch(
            f"{MOD}.locator.find_executor", return_value="/usr/bin/ansible-playbook"
        ), patch(
            f"{MOD}.asyncio.create_subprocess_exec", spawn_patch(FakeProc(), captured)
        ):
            result = await make_ops().apply_config_profile({"profile": {}})
        assert result["reason"] == ops_mod.REASON_EMPTY_PROFILE
        assert captured == {}

    @pytest.mark.asyncio
    async def test_whitespace_only_playbook_counts_as_empty(self):
        with patch(
            f"{MOD}.locator.find_executor", return_value="/usr/bin/ansible-playbook"
        ):
            result = await make_ops().apply_config_profile(
                {"profile": {"playbook": "   \n "}}
            )
        assert result["reason"] == ops_mod.REASON_EMPTY_PROFILE


class TestAnsibleInvocation:
    async def _run(self, captured, params=None, proc=None):
        proc = proc or FakeProc(0, b'{"type":"recap","ok":1}\n')
        with patch(f"{MOD}.platform.system", return_value="Linux"), patch(
            f"{MOD}.locator.find_executor", return_value="/usr/bin/ansible-playbook"
        ), patch(f"{MOD}.asyncio.create_subprocess_exec", spawn_patch(proc, captured)):
            return await make_ops().apply_config_profile(
                params or {"profile": {"playbook": PLAYBOOK}}
            )

    @pytest.mark.asyncio
    async def test_local_connection_is_pinned_into_the_argv(self):
        # The whole "443 only, no inbound" guarantee rests on this.
        captured = {}
        await self._run(captured)
        argv = captured["argv"]
        assert "-c" in argv and argv[argv.index("-c") + 1] == "local"
        assert "-i" in argv and argv[argv.index("-i") + 1] == "localhost,"

    @pytest.mark.asyncio
    async def test_the_playbook_never_reaches_a_shell(self):
        captured = {}
        await self._run(captured)
        assert captured["argv"][0] == "/usr/bin/ansible-playbook"
        assert not any(a in ("sh", "bash", "-c ") for a in captured["argv"][:1])

    @pytest.mark.asyncio
    async def test_check_mode_adds_check_and_is_reported_back(self):
        captured = {}
        result = await self._run(
            captured, {"profile": {"playbook": PLAYBOOK}, "check_mode": True}
        )
        assert "--check" in captured["argv"]
        assert result["check_mode"] is True

    @pytest.mark.asyncio
    async def test_normal_mode_does_not_add_check(self):
        captured = {}
        await self._run(captured)
        assert "--check" not in captured["argv"]

    @pytest.mark.asyncio
    async def test_callback_env_is_set_so_output_is_parseable(self):
        captured = {}
        await self._run(captured)
        env = captured["kwargs"]["env"]
        assert env["ANSIBLE_STDOUT_CALLBACK"] == "sysmanage_json"
        assert env["ANSIBLE_CALLBACK_PLUGINS"].endswith("ansible_callbacks")
        # ANSI escapes in the stream would break json.loads on every line.
        assert env["ANSIBLE_NOCOLOR"] == "1"

    @pytest.mark.asyncio
    async def test_the_temp_profile_is_removed_even_on_failure(self):
        captured = {}
        await self._run(captured, proc=FakeProc(2, b""))
        # The playbook path was the last argv entry; nothing may survive.
        written = [a for a in captured["argv"] if a.endswith("profile.yml")]
        assert written and not os.path.exists(written[0])
        assert not os.path.exists(os.path.dirname(written[0]))

    @pytest.mark.asyncio
    async def test_stderr_is_kept_only_when_the_run_failed(self):
        captured = {}
        bad = await self._run(captured, proc=FakeProc(2, b"", b"boom"))
        assert bad["success"] is False and bad["stderr"] == "boom"
        good = await self._run(captured, proc=FakeProc(0, b'{"type":"recap","ok":1}\n'))
        assert good["success"] is True and "stderr" not in good

    @pytest.mark.asyncio
    async def test_a_timeout_kills_and_reaps_the_child(self):
        # An unwaited child is the zombie/Popen leak that had to be fixed on
        # the BSDs; a timeout path that forgets to reap reintroduces it.
        captured = {}
        proc = FakeProc(hang=True)
        with patch(f"{MOD}.platform.system", return_value="Linux"), patch(
            f"{MOD}.locator.find_executor", return_value="/usr/bin/ansible-playbook"
        ), patch(f"{MOD}.asyncio.create_subprocess_exec", spawn_patch(proc, captured)):
            result = await make_ops().apply_config_profile(
                {"profile": {"playbook": PLAYBOOK}, "timeout": 0.01}
            )
        assert result["reason"] == ops_mod.REASON_TIMEOUT
        assert proc.killed is True
        assert proc.waited is True


class TestDscInvocation:
    async def _run(self, proc, captured, check_mode=False, resources=None):
        with patch(f"{MOD}.platform.system", return_value="Windows"), patch(
            f"{MOD}.locator.find_executor", return_value="C:\\dsc\\dsc.exe"
        ), patch(f"{MOD}.asyncio.create_subprocess_exec", spawn_patch(proc, captured)):
            return await make_ops().apply_config_profile(
                {
                    "profile": {
                        "resources": (
                            resources
                            if resources is not None
                            else [{"name": "n", "type": "T", "properties": {}}]
                        )
                    },
                    "check_mode": check_mode,
                }
            )

    @pytest.mark.asyncio
    async def test_input_goes_over_stdin_not_as_an_inline_argument(self):
        # PowerShell 5.1 strips the embedded quotes from an inline --input
        # JSON; dsc then tries to parse it as YAML and dies.
        captured = {}
        proc = FakeProc(0, json.dumps({"hadErrors": False, "results": []}).encode())
        await self._run(proc, captured)
        assert captured["argv"][-2:] == ["--file", "-"]
        assert "--input" not in captured["argv"]
        assert json.loads(proc.stdin_received.decode())["resources"]

    @pytest.mark.asyncio
    async def test_check_mode_uses_test_rather_than_set(self):
        captured = {}
        await self._run(
            FakeProc(0, json.dumps({"hadErrors": False, "results": []}).encode()),
            captured,
            check_mode=True,
        )
        assert "test" in captured["argv"] and "set" not in captured["argv"]

    @pytest.mark.asyncio
    async def test_streams_are_captured_separately(self):
        # dsc writes ANSI-coloured logs to stderr; folding them into stdout
        # corrupts the JSON parse.
        captured = {}
        await self._run(
            FakeProc(0, json.dumps({"hadErrors": False, "results": []}).encode()),
            captured,
        )
        # Both are PIPE (the same sentinel), so the property to assert is that
        # stderr is NOT redirected INTO stdout -- asyncio.subprocess.STDOUT is
        # what would merge them and corrupt the JSON.
        assert captured["kwargs"]["stderr"] == asyncio.subprocess.PIPE
        assert captured["kwargs"]["stderr"] != asyncio.subprocess.STDOUT
        assert captured["kwargs"]["stdout"] == asyncio.subprocess.PIPE

    @pytest.mark.asyncio
    async def test_a_failing_run_with_no_stdout_is_still_a_failure(self):
        # Observed: dsc exits 2 and prints nothing at all to stdout.
        captured = {}
        result = await self._run(FakeProc(2, b"", b"\x1b[31mERROR\x1b[0m"), captured)
        assert result["success"] is False
        assert result["reason"] == "dsc_no_output"
        assert result["exit_code"] == 2

    @pytest.mark.asyncio
    async def test_changed_properties_drive_the_changed_flag(self):
        captured = {}
        doc = {
            "hadErrors": False,
            "results": [
                {"name": "a", "result": {"changedProperties": ["x"]}},
                {"name": "b", "result": {"changedProperties": []}},
            ],
        }
        result = await self._run(FakeProc(0, json.dumps(doc).encode()), captured)
        assert result["changed"] is True
        assert result["recap"] == {
            "ok": 1,
            "changed": 1,
            "failed": 0,
            "skipped": 0,
            "unreachable": 0,
        }

    @pytest.mark.asyncio
    async def test_empty_changed_properties_means_unchanged(self):
        # Both observed forms of "nothing moved": null and [].
        captured = {}
        for empty in (None, []):
            doc = {
                "hadErrors": False,
                "results": [{"name": "a", "result": {"changedProperties": empty}}],
            }
            result = await self._run(FakeProc(0, json.dumps(doc).encode()), captured)
            assert result["changed"] is False

    @pytest.mark.asyncio
    async def test_had_errors_fails_the_run_even_on_exit_zero(self):
        captured = {}
        doc = {"hadErrors": True, "results": []}
        result = await self._run(FakeProc(0, json.dumps(doc).encode()), captured)
        assert result["success"] is False
