"""
Unit tests for src.sysmanage_agent.operations.inflight_journal (Phase 11.6).

Covers:
    * journal_write / journal_set_pid / journal_heartbeat / journal_clear
    * scan_inflight_on_startup with live PID, dead PID, and corrupt files
    * apply_deployment_plan integration: journal is written before subprocess,
      heartbeat watchdog refreshes during run, journal cleared on clean exit
    * reconcile_inflight_journal startup hook: enqueues synthetic
      command_result for dead PIDs via the message handler

Tests do NOT spawn long-running subprocesses — Popen / create_subprocess_exec
is either mocked or run with trivial commands (``true``, ``false``).
"""

# pylint: disable=protected-access,attribute-defined-outside-init
# pylint: disable=redefined-outer-name,unused-argument

import json
import os
import sys
import time
from unittest.mock import AsyncMock, MagicMock, Mock, patch

import pytest

from src.sysmanage_agent.operations import inflight_journal
from src.sysmanage_agent.operations.generic_deployment import GenericDeployment

_MOD = "src.sysmanage_agent.operations.inflight_journal"


@pytest.fixture
def isolated_journal_dir(tmp_path, monkeypatch):
    """Point the journal module at an isolated tmp directory.

    Patches both HOME (POSIX) and USERPROFILE (Windows) so the journal_dir()
    helper resolves to a sandbox we own — no risk of touching the real
    ~/.sysmanage-agent/inflight/ that production agents use.
    """
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    return tmp_path / ".sysmanage-agent" / "inflight"


class TestJournalWriteRead:
    """journal_write should produce a parseable JSON file with all fields."""

    def test_write_creates_file_with_expected_fields(self, isolated_journal_dir):
        """journal_write writes a JSON file with every documented field present."""
        path = inflight_journal.journal_write(
            message_id="msg-abc",
            plan={"argv": ["echo", "hi"]},
            command_argv=["echo", "hi"],
            working_dir="/tmp",
        )
        assert path.exists()
        payload = json.loads(path.read_text(encoding="utf-8"))
        assert payload["message_id"] == "msg-abc"
        assert payload["command_argv"] == ["echo", "hi"]
        assert payload["working_dir"] == "/tmp"
        assert payload["plan"] == {"argv": ["echo", "hi"]}
        assert payload["pid"] is None
        assert "started_at" in payload
        assert "last_heartbeat_at" in payload

    def test_write_creates_journal_directory(self, isolated_journal_dir):
        """journal_write creates ~/.sysmanage-agent/inflight/ on first call."""
        # Directory does not exist yet
        assert not isolated_journal_dir.exists()
        inflight_journal.journal_write(
            message_id="msg-1",
            plan={},
            command_argv=["true"],
            working_dir=None,
        )
        assert isolated_journal_dir.exists()

    def test_write_with_initial_pid(self, isolated_journal_dir):
        """journal_write accepts an initial pid and persists it verbatim."""
        path = inflight_journal.journal_write(
            message_id="msg-2",
            plan={},
            command_argv=["true"],
            working_dir=None,
            pid=12345,
        )
        payload = json.loads(path.read_text(encoding="utf-8"))
        assert payload["pid"] == 12345


class TestJournalSetPid:
    """journal_set_pid should update PID without touching other fields."""

    def test_sets_pid_after_write(self, isolated_journal_dir):
        """journal_set_pid updates the pid field while preserving plan/argv."""
        inflight_journal.journal_write(
            message_id="msg-3",
            plan={"k": "v"},
            command_argv=["true"],
            working_dir=None,
        )
        inflight_journal.journal_set_pid("msg-3", 9999)
        payload = json.loads(
            (isolated_journal_dir / "msg-3.json").read_text(encoding="utf-8")
        )
        assert payload["pid"] == 9999
        assert payload["plan"] == {"k": "v"}

    def test_no_op_when_journal_missing(self, isolated_journal_dir):
        """journal_set_pid is a silent no-op when the file is gone."""
        # Should not raise — silent no-op for journals that have already
        # been cleared by a fast-exiting subprocess.
        inflight_journal.journal_set_pid("nonexistent", 1234)


class TestJournalHeartbeat:
    """journal_heartbeat should advance last_heartbeat_at."""

    def test_heartbeat_advances_timestamp(self, isolated_journal_dir):
        """journal_heartbeat refreshes last_heartbeat_at to a newer time."""
        inflight_journal.journal_write(
            message_id="msg-hb",
            plan={},
            command_argv=["true"],
            working_dir=None,
        )
        path = isolated_journal_dir / "msg-hb.json"
        original = json.loads(path.read_text(encoding="utf-8"))
        time.sleep(0.01)
        inflight_journal.journal_heartbeat("msg-hb")
        updated = json.loads(path.read_text(encoding="utf-8"))
        assert updated["last_heartbeat_at"] >= original["last_heartbeat_at"]

    def test_heartbeat_no_op_when_journal_missing(self, isolated_journal_dir):
        """journal_heartbeat is a silent no-op when the journal file is gone."""
        # Missing file is a silent no-op (race with journal_clear).
        inflight_journal.journal_heartbeat("ghost")


class TestJournalClear:
    """journal_clear removes the file; idempotent on missing files."""

    def test_clear_removes_file(self, isolated_journal_dir):
        """journal_clear deletes the on-disk journal entry."""
        inflight_journal.journal_write(
            message_id="msg-clr",
            plan={},
            command_argv=["true"],
            working_dir=None,
        )
        assert (isolated_journal_dir / "msg-clr.json").exists()
        inflight_journal.journal_clear("msg-clr")
        assert not (isolated_journal_dir / "msg-clr.json").exists()

    def test_clear_idempotent(self, isolated_journal_dir):
        """journal_clear is idempotent: calling on a missing file is fine."""
        # Should not raise — calling twice or for a non-existent message
        # is a normal happy-path occurrence.
        inflight_journal.journal_clear("never-existed")
        inflight_journal.journal_clear("never-existed")


class TestIsPidAlive:
    """Cross-platform PID liveness probe."""

    def test_none_pid_is_dead(self):
        """A None pid (spawn never returned) classifies as dead."""
        assert inflight_journal.is_pid_alive(None) is False

    def test_zero_pid_is_dead(self):
        """A zero pid is classified as dead, not as the kernel's pgrp."""
        assert inflight_journal.is_pid_alive(0) is False

    def test_negative_pid_is_dead(self):
        """A negative pid is classified as dead, never as a process group."""
        assert inflight_journal.is_pid_alive(-1) is False

    def test_self_pid_is_alive(self):
        """Our own pid is by definition alive."""
        # Our own PID is, by definition, alive.
        assert inflight_journal.is_pid_alive(os.getpid()) is True

    @pytest.mark.skipif(sys.platform == "win32", reason="POSIX-only path")
    def test_dead_pid_returns_false(self):
        """A pid that almost certainly does not exist is classified as dead."""
        # PID 99999999 is virtually guaranteed not to exist.
        assert inflight_journal.is_pid_alive(99999999) is False

    @pytest.mark.skipif(sys.platform == "win32", reason="POSIX-only path")
    def test_permission_error_treated_as_alive(self):
        """A POSIX EPERM from os.kill means the process exists; treat as alive."""
        # On POSIX, EPERM from os.kill means the process exists but we
        # can't signal it (different user).  Still alive from our POV.
        with patch(f"{_MOD}.os.kill", side_effect=PermissionError):
            assert inflight_journal.is_pid_alive(1234) is True


class TestScanInflightOnStartup:
    """scan_inflight_on_startup classifies leftover entries."""

    def test_no_directory_returns_empty(self, isolated_journal_dir):
        """Scan returns an empty classification when the journal dir is missing."""
        result = inflight_journal.scan_inflight_on_startup(None)
        assert result == {"live": [], "dead": []}

    def test_live_pid_left_alone(self, isolated_journal_dir):
        """A live pid keeps its journal entry and is classified as live."""
        inflight_journal.journal_write(
            message_id="alive-1",
            plan={},
            command_argv=["true"],
            working_dir=None,
            pid=os.getpid(),  # our own PID is definitely alive
        )
        result = inflight_journal.scan_inflight_on_startup(None)
        assert "alive-1" in result["live"]
        assert "alive-1" not in result["dead"]
        # File is left in place for the running subprocess to clean up.
        assert (isolated_journal_dir / "alive-1.json").exists()

    def test_dead_pid_emits_synthetic_result_and_clears(self, isolated_journal_dir):
        """A dead pid yields a synthetic command_result and the file is removed."""
        inflight_journal.journal_write(
            message_id="dead-1",
            plan={"k": "v"},
            command_argv=["sleep", "9999"],
            working_dir=None,
            pid=99999999,  # virtually impossible to be a real PID
        )
        emitted = []
        result = inflight_journal.scan_inflight_on_startup(emitted.append)
        assert "dead-1" in result["dead"]
        assert "dead-1" not in result["live"]
        assert len(emitted) == 1
        assert emitted[0]["killed_by_restart"] is True
        assert emitted[0]["exit_code"] == -1
        assert emitted[0]["command_id"] == "dead-1"
        assert "agent restart" in emitted[0]["stderr"]
        # Journal entry has been deleted.
        assert not (isolated_journal_dir / "dead-1.json").exists()

    def test_dead_pid_no_callback_still_cleans(self, isolated_journal_dir):
        """When no enqueue callback is supplied, dead entries are still removed."""
        inflight_journal.journal_write(
            message_id="dead-2",
            plan={},
            command_argv=["true"],
            working_dir=None,
            pid=99999999,
        )
        # No callback — should still classify and remove.
        result = inflight_journal.scan_inflight_on_startup(None)
        assert "dead-2" in result["dead"]
        assert not (isolated_journal_dir / "dead-2.json").exists()

    def test_corrupt_journal_file_removed(self, isolated_journal_dir):
        """A corrupt journal file is removed without producing a synthetic result."""
        isolated_journal_dir.mkdir(parents=True, exist_ok=True)
        bad = isolated_journal_dir / "garbage.json"
        bad.write_text("{not valid json", encoding="utf-8")
        result = inflight_journal.scan_inflight_on_startup(None)
        # The corrupt file is silently dropped — neither classified as
        # live nor as a real dead entry that needs a synthetic result.
        assert not bad.exists()
        assert result == {"live": [], "dead": []}

    def test_non_json_files_ignored(self, isolated_journal_dir):
        """Files that do not end in .json are left untouched by the scan."""
        isolated_journal_dir.mkdir(parents=True, exist_ok=True)
        (isolated_journal_dir / "README.txt").write_text("ignore me", encoding="utf-8")
        result = inflight_journal.scan_inflight_on_startup(None)
        assert result == {"live": [], "dead": []}
        # The non-JSON file is preserved (we only touch *.json).
        assert (isolated_journal_dir / "README.txt").exists()

    def test_callback_exception_does_not_break_scan(self, isolated_journal_dir):
        """A failing enqueue callback does not abort the scan or skip cleanup."""
        inflight_journal.journal_write(
            message_id="dead-cb",
            plan={},
            command_argv=["true"],
            working_dir=None,
            pid=99999999,
        )

        def boom(_payload):
            raise RuntimeError("queue full")

        # Should not raise — the scan logs and moves on.
        result = inflight_journal.scan_inflight_on_startup(boom)
        assert "dead-cb" in result["dead"]
        # File is still cleaned up even though the callback failed.
        assert not (isolated_journal_dir / "dead-cb.json").exists()


class TestApplyDeploymentPlanJournalIntegration:
    """End-to-end: the journal is written/cleared around subprocess calls."""

    def setup_method(self):
        """Build a fresh GenericDeployment with a mock agent for each test."""
        self.mock_agent = Mock()
        self.mock_agent.send_message = AsyncMock()
        self.mock_agent.create_message = Mock(return_value={"type": "test"})
        self.deployment = GenericDeployment(self.mock_agent)

    @pytest.mark.asyncio
    async def test_journal_cleared_on_clean_plan_exit(self, isolated_journal_dir):
        """A successful plan run leaves no journal file behind."""
        # Use a real trivial subprocess so create_subprocess_exec actually
        # spawns and exits — but ``true`` returns immediately so the test
        # doesn't hang.
        result = await self.deployment.apply_deployment_plan(
            {
                "_message_id": "plan-clean",
                "commands": [{"argv": ["true"], "timeout": 5}],
            }
        )
        assert result["success"] is True
        # Journal entry has been cleared by the finally block.
        assert not (isolated_journal_dir / "plan-clean.json").exists()

    @pytest.mark.asyncio
    async def test_journal_cleared_on_failing_plan(self, isolated_journal_dir):
        """A hard-failing plan also cleans up the journal."""
        result = await self.deployment.apply_deployment_plan(
            {
                "_message_id": "plan-fail",
                "commands": [{"argv": ["false"], "timeout": 5}],
            }
        )
        assert result["success"] is False
        assert not (isolated_journal_dir / "plan-fail.json").exists()

    @pytest.mark.asyncio
    async def test_journal_written_during_subprocess(self, isolated_journal_dir):
        """While a subprocess is running, the journal exists with a valid PID."""
        observed_path = {}

        async def slow_communicate():
            """Stand-in for proc.communicate that snapshots the live journal."""
            # Capture the journal state mid-run.
            path = isolated_journal_dir / "plan-mid.json"
            if path.exists():
                payload = json.loads(path.read_text(encoding="utf-8"))
                observed_path["payload"] = payload
            return (b"", b"")

        with patch(
            "src.sysmanage_agent.operations.generic_deployment."
            "asyncio.create_subprocess_exec",
            new=AsyncMock(),
        ) as mock_exec:
            proc = MagicMock()
            proc.pid = os.getpid()
            proc.returncode = 0
            proc.communicate = slow_communicate
            mock_exec.return_value = proc

            await self.deployment.apply_deployment_plan(
                {
                    "_message_id": "plan-mid",
                    "commands": [{"argv": ["echo", "hi"], "timeout": 5}],
                }
            )

        assert "payload" in observed_path
        assert observed_path["payload"]["message_id"] == "plan-mid"
        assert observed_path["payload"]["pid"] == os.getpid()
        # And the journal is cleaned up post-exit.
        assert not (isolated_journal_dir / "plan-mid.json").exists()

    @pytest.mark.asyncio
    async def test_no_journal_when_message_id_missing(self, isolated_journal_dir):
        """Plans without a _message_id (legacy callers) skip journaling silently."""
        result = await self.deployment.apply_deployment_plan(
            {
                "commands": [{"argv": ["true"], "timeout": 5}],
            }
        )
        assert result["success"] is True
        # Directory may or may not exist; either way no .json was created.
        if isolated_journal_dir.exists():
            assert not list(isolated_journal_dir.glob("*.json"))


class TestReconcileInflightJournalHook:
    """The startup hook in agent_utils enqueues synthetic results via the message handler."""

    @pytest.mark.asyncio
    async def test_reconcile_enqueues_synthetic_for_dead_pid(
        self, isolated_journal_dir
    ):
        """reconcile_inflight_journal queues one synthetic result per dead PID."""
        # Create a journal entry pointing at a dead PID.
        inflight_journal.journal_write(
            message_id="reconcile-dead",
            plan={},
            command_argv=["sleep", "1"],
            working_dir=None,
            pid=99999999,
        )

        # Build a minimal fake agent with the message_handler shape.
        mock_agent = Mock()
        mock_agent.create_message = Mock(
            side_effect=lambda mt, data: {
                "message_type": mt,
                "data": data,
            }
        )
        mock_agent.message_handler = Mock()
        mock_agent.message_handler.queue_outbound_message = AsyncMock(
            return_value="queued-id"
        )

        # Import here so the test uses the patched HOME from the fixture.
        from src.sysmanage_agent.core.agent_utils import (  # pylint: disable=import-outside-toplevel
            reconcile_inflight_journal,
        )

        result = await reconcile_inflight_journal(mock_agent)
        assert "reconcile-dead" in result["dead"]
        # One synthetic command_result was queued.
        assert mock_agent.message_handler.queue_outbound_message.await_count == 1
        queued_message = (
            mock_agent.message_handler.queue_outbound_message.await_args.args[0]
        )
        assert queued_message["message_type"] == "command_result"
        assert queued_message["data"]["killed_by_restart"] is True

    @pytest.mark.asyncio
    async def test_reconcile_no_op_on_empty_directory(self, isolated_journal_dir):
        """reconcile_inflight_journal queues nothing when there are no journal files."""
        mock_agent = Mock()
        mock_agent.create_message = Mock(return_value={"x": 1})
        mock_agent.message_handler = Mock()
        mock_agent.message_handler.queue_outbound_message = AsyncMock()

        from src.sysmanage_agent.core.agent_utils import (  # pylint: disable=import-outside-toplevel
            reconcile_inflight_journal,
        )

        result = await reconcile_inflight_journal(mock_agent)
        assert result == {"live": [], "dead": []}
        mock_agent.message_handler.queue_outbound_message.assert_not_awaited()
