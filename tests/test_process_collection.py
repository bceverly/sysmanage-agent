"""Tests for the running-process collector (Phase 13.3)."""

# pylint: disable=redefined-outer-name,protected-access

from unittest.mock import Mock, patch

import psutil
import pytest

from src.sysmanage_agent.collection import process_collection
from src.sysmanage_agent.collection.process_collection import ProcessCollector


class _Ctx:
    """Minimal context manager standing in for ``proc.oneshot()``."""

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


def _fake_proc(pid, name, *, cpu, mem=1.0, rss=1024, user="root"):
    """Build a Mock psutil.Process with the attributes the collector reads."""
    proc = Mock()
    proc.pid = pid
    proc.cpu_percent.return_value = cpu  # returned for both prime + read
    proc.oneshot.return_value = _Ctx()
    mem_info = Mock()
    mem_info.rss = rss
    proc.as_dict.return_value = {
        "pid": pid,
        "ppid": 1,
        "name": name,
        "username": user,
        "status": "running",
        "memory_percent": mem,
        "memory_info": mem_info,
        "cmdline": [name, "--flag"],
        "create_time": 1_700_000_000.0,
    }
    return proc


@pytest.fixture
def collector():
    """Return a ProcessCollector instance."""
    return ProcessCollector()


class TestCollectProcesses:
    """Tests for ProcessCollector.collect_processes."""

    def test_normalises_and_scales_cpu(self, collector):
        """A process row is normalised and CPU% is scaled by core count."""
        proc = _fake_proc(1234, "python3", cpu=80.0, mem=2.5, rss=2048)
        with patch.object(
            process_collection.psutil, "process_iter", return_value=[proc]
        ), patch.object(
            process_collection.psutil, "cpu_count", return_value=4
        ), patch.object(
            process_collection.time, "sleep"
        ):
            procs, truncated = collector.collect_processes()

        assert truncated is False
        assert len(procs) == 1
        row = procs[0]
        assert row["pid"] == 1234
        assert row["name"] == "python3"
        assert row["cpu_percent"] == 20.0  # 80 / 4 cores
        assert row["memory_percent"] == 2.5
        assert row["memory_rss_bytes"] == 2048
        assert row["command_line"] == "python3 --flag"
        assert row["started_at"] is not None

    def test_sorted_by_cpu_desc(self, collector):
        """Processes are returned sorted by CPU% descending."""
        procs_in = [
            _fake_proc(1, "low", cpu=1.0),
            _fake_proc(2, "high", cpu=90.0),
            _fake_proc(3, "mid", cpu=50.0),
        ]
        with patch.object(
            process_collection.psutil, "process_iter", return_value=procs_in
        ), patch.object(
            process_collection.psutil, "cpu_count", return_value=1
        ), patch.object(
            process_collection.time, "sleep"
        ):
            procs, _ = collector.collect_processes()
        assert [p["name"] for p in procs] == ["high", "mid", "low"]

    def test_truncation_flag_and_cap(self, collector, monkeypatch):
        """Snapshot is capped at MAX_PROCESSES and flags truncation."""
        monkeypatch.setattr(process_collection, "MAX_PROCESSES", 2)
        procs_in = [_fake_proc(i, f"p{i}", cpu=float(i)) for i in range(5)]
        with patch.object(
            process_collection.psutil, "process_iter", return_value=procs_in
        ), patch.object(
            process_collection.psutil, "cpu_count", return_value=1
        ), patch.object(
            process_collection.time, "sleep"
        ):
            procs, truncated = collector.collect_processes()
        assert truncated is True
        assert len(procs) == 2  # capped

    def test_skips_vanished_process(self, collector):
        """A process that disappears mid-scan is skipped, not fatal."""
        good = _fake_proc(1, "ok", cpu=5.0)
        gone = Mock()
        gone.pid = 2
        gone.cpu_percent.side_effect = psutil.NoSuchProcess(2)
        with patch.object(
            process_collection.psutil, "process_iter", return_value=[good, gone]
        ), patch.object(
            process_collection.psutil, "cpu_count", return_value=1
        ), patch.object(
            process_collection.time, "sleep"
        ):
            procs, _ = collector.collect_processes()
        assert [p["pid"] for p in procs] == [1]


class TestKillProcess:
    """Tests for ProcessCollector.kill_process."""

    def test_terminate_success(self, collector):
        """Default kill sends SIGTERM (terminate)."""
        proc = Mock()
        proc.name.return_value = "python3"
        with patch.object(process_collection.psutil, "Process", return_value=proc):
            result = collector.kill_process(1234)
        assert result["success"] is True
        assert result["signal"] == "SIGTERM"
        proc.terminate.assert_called_once()
        proc.kill.assert_not_called()

    def test_force_uses_sigkill(self, collector):
        """force=True sends SIGKILL (kill)."""
        proc = Mock()
        proc.name.return_value = "python3"
        with patch.object(process_collection.psutil, "Process", return_value=proc):
            result = collector.kill_process(1234, force=True)
        assert result["success"] is True
        assert result["signal"] == "SIGKILL"
        proc.kill.assert_called_once()

    def test_no_such_process(self, collector):
        """Killing a non-existent PID fails cleanly."""
        with patch.object(
            process_collection.psutil,
            "Process",
            side_effect=psutil.NoSuchProcess(99),
        ):
            result = collector.kill_process(99)
        assert result["success"] is False

    def test_name_mismatch_refused(self, collector):
        """A PID whose live name differs from expected_name is not killed."""
        proc = Mock()
        proc.name.return_value = "sshd"  # not what the operator expected
        with patch.object(process_collection.psutil, "Process", return_value=proc):
            result = collector.kill_process(1234, expected_name="python3")
        assert result["success"] is False
        proc.terminate.assert_not_called()
        proc.kill.assert_not_called()

    def test_access_denied(self, collector):
        """An AccessDenied from psutil yields a failure result."""
        proc = Mock()
        proc.name.return_value = "root-proc"
        proc.terminate.side_effect = psutil.AccessDenied(1)
        with patch.object(process_collection.psutil, "Process", return_value=proc):
            result = collector.kill_process(1)
        assert result["success"] is False
