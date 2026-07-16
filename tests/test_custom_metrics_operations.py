# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""
Tests for custom-metric collection operations (Custom Metrics & Graphs Slice 3).

Covers the ``sync_custom_metrics`` handler and the per-metric run path in
``custom_metrics_operations.py``:

* sync replaces the whole set (and an empty sync clears it),
* a script returning "42" -> ok sample with value 42.0,
* a nonzero exit -> error sample,
* non-numeric stdout -> error sample,
* a missing interpreter -> error sample,
* the scheduler tick batches samples and sends them via the agent.

``asyncio.create_subprocess_exec`` and ``shutil.which`` are mocked so no real
subprocess runs, and the persistence layer is patched so no real database is
touched.
"""

# pylint: disable=missing-class-docstring,missing-function-docstring,redefined-outer-name,protected-access

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.sysmanage_agent.operations.custom_metrics_operations import (
    CustomMetricsOperations,
)


@pytest.fixture
def metrics_ops():
    agent = MagicMock()
    agent.running = True
    agent.create_message = MagicMock(
        side_effect=lambda mtype, data: {"message_type": mtype, "data": data}
    )
    agent.send_message = AsyncMock(return_value=True)
    ops = CustomMetricsOperations(agent)
    return ops


def _proc(returncode: int, stdout: str = "", stderr: str = ""):
    """Build a fake process whose communicate() yields the given output."""
    proc = MagicMock()
    proc.returncode = returncode
    proc.communicate = AsyncMock(
        return_value=(stdout.encode("utf-8"), stderr.encode("utf-8"))
    )
    proc.kill = MagicMock()
    proc.wait = AsyncMock(return_value=None)
    return proc


def _metric(metric_id="m1", script="echo 42", interpreter="sh", cadence=60):
    return {
        "id": metric_id,
        "name": f"name-{metric_id}",
        "script": script,
        "interpreter": interpreter,
        "cadence_seconds": cadence,
    }


class TestSync:
    @pytest.mark.asyncio
    async def test_sync_replaces_set(self, metrics_ops):
        with patch.object(metrics_ops, "_persist_metrics") as persist:
            result = await metrics_ops.sync_custom_metrics(
                {"metrics": [_metric("m1"), _metric("m2")]}
            )
        assert result["success"] is True
        assert result["metric_count"] == 2
        assert set(metrics_ops._metrics) == {"m1", "m2"}
        persist.assert_called_once()

        # A second sync with a different set REPLACES (does not merge).
        with patch.object(metrics_ops, "_persist_metrics"):
            result = await metrics_ops.sync_custom_metrics({"metrics": [_metric("m3")]})
        assert result["metric_count"] == 1
        assert set(metrics_ops._metrics) == {"m3"}

    @pytest.mark.asyncio
    async def test_empty_sync_clears(self, metrics_ops):
        with patch.object(metrics_ops, "_persist_metrics"):
            await metrics_ops.sync_custom_metrics({"metrics": [_metric("m1")]})
            assert metrics_ops._metrics
            result = await metrics_ops.sync_custom_metrics({"metrics": []})
        assert result["metric_count"] == 0
        assert metrics_ops._metrics == {}

    @pytest.mark.asyncio
    async def test_cadence_floor_enforced(self, metrics_ops):
        with patch.object(metrics_ops, "_persist_metrics"):
            await metrics_ops.sync_custom_metrics(
                {"metrics": [_metric("m1", cadence=5)]}
            )
        assert metrics_ops._metrics["m1"]["cadence_seconds"] == 60

    @pytest.mark.asyncio
    async def test_invalid_interpreter_skipped(self, metrics_ops):
        with patch.object(metrics_ops, "_persist_metrics"):
            result = await metrics_ops.sync_custom_metrics(
                {"metrics": [_metric("m1", interpreter="perl")]}
            )
        assert result["metric_count"] == 0
        assert result["skipped"] == 1


class TestRunMetric:
    @pytest.mark.asyncio
    async def test_ok_sample(self, metrics_ops):
        metric = metrics_ops._normalize_metric(_metric("m1", script="echo 42"))
        with patch("shutil.which", return_value="/bin/sh"), patch(
            "asyncio.create_subprocess_exec",
            AsyncMock(return_value=_proc(0, "42\n")),
        ):
            sample = await metrics_ops._run_metric(metric)
        assert sample["status"] == "ok"
        assert sample["value"] == 42.0
        assert sample["error_detail"] is None
        assert sample["metric_id"] == "m1"
        assert sample["collected_at"]

    @pytest.mark.asyncio
    async def test_nonzero_exit_error_sample(self, metrics_ops):
        metric = metrics_ops._normalize_metric(_metric("m1"))
        with patch("shutil.which", return_value="/bin/sh"), patch(
            "asyncio.create_subprocess_exec",
            AsyncMock(return_value=_proc(1, "", "boom")),
        ):
            sample = await metrics_ops._run_metric(metric)
        assert sample["status"] == "error"
        assert sample["value"] is None
        assert "boom" in sample["error_detail"]

    @pytest.mark.asyncio
    async def test_non_numeric_stdout_error_sample(self, metrics_ops):
        metric = metrics_ops._normalize_metric(_metric("m1"))
        with patch("shutil.which", return_value="/bin/sh"), patch(
            "asyncio.create_subprocess_exec",
            AsyncMock(return_value=_proc(0, "not-a-number\n")),
        ):
            sample = await metrics_ops._run_metric(metric)
        assert sample["status"] == "error"
        assert sample["value"] is None
        assert sample["error_detail"]

    @pytest.mark.asyncio
    async def test_interpreter_missing_error_sample(self, metrics_ops):
        metric = metrics_ops._normalize_metric(
            _metric("m1", interpreter="bash", script="echo 1")
        )
        with patch("shutil.which", return_value=None):
            sample = await metrics_ops._run_metric(metric)
        assert sample["status"] == "error"
        assert sample["value"] is None
        assert "bash" in sample["error_detail"]

    @pytest.mark.asyncio
    async def test_last_nonempty_line_parsed(self, metrics_ops):
        metric = metrics_ops._normalize_metric(_metric("m1"))
        with patch("shutil.which", return_value="/bin/sh"), patch(
            "asyncio.create_subprocess_exec",
            AsyncMock(return_value=_proc(0, "progress...\n\n3.14\n")),
        ):
            sample = await metrics_ops._run_metric(metric)
        assert sample["status"] == "ok"
        assert sample["value"] == 3.14


class TestTickAndSend:
    @pytest.mark.asyncio
    async def test_tick_runs_due_and_sends_batch(self, metrics_ops):
        with patch.object(metrics_ops, "_persist_metrics"):
            await metrics_ops.sync_custom_metrics(
                {"metrics": [_metric("m1"), _metric("m2")]}
            )
        with patch("shutil.which", return_value="/bin/sh"), patch(
            "asyncio.create_subprocess_exec",
            AsyncMock(return_value=_proc(0, "7\n")),
        ):
            await metrics_ops._tick()

        # Both metrics were "never run" so both fire on the first tick, and a
        # single batched message is sent.
        metrics_ops.agent.send_message.assert_awaited_once()
        sent = metrics_ops.agent.create_message.call_args[0]
        assert sent[0] == "custom_metric_samples"
        samples = sent[1]["samples"]
        assert len(samples) == 2
        assert all(s["value"] == 7.0 for s in samples)

    @pytest.mark.asyncio
    async def test_tick_no_metrics_sends_nothing(self, metrics_ops):
        await metrics_ops._tick()
        metrics_ops.agent.send_message.assert_not_awaited()
