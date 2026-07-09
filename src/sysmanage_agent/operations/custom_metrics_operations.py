"""
Custom-metric collection operations module for SysManage agent.

Handles the ``sync_custom_metrics`` command the server's Pro+
``observability_engine`` enqueues (Custom Metrics & Graphs Slice 3).

Contract
--------
* Server -> agent: ``command_type="sync_custom_metrics"`` with
  ``parameters={"metrics": [{"id", "name", "script", "interpreter",
  "cadence_seconds"}]}``.  This is the host's COMPLETE enabled set; the
  agent REPLACES its whole in-memory + persisted set (an empty list clears
  everything).
* The agent runs ``<interpreter> -c <script>`` (interpreter in
  {sh, bash, python3}) on each metric's cadence, parsing a SINGLE numeric
  stdout value.  A nonzero exit OR non-numeric stdout produces an errored
  sample (``value=null``, ``status="error"``, failure text in
  ``error_detail``); otherwise ``status="ok"`` with the float value.
* Agent -> server: ``message_type="custom_metric_samples"`` with payload
  ``{"samples": [{"metric_id", "value", "status", "error_detail",
  "collected_at"}]}`` (``collected_at`` is ISO-8601 UTC).

Design notes
------------
* Persistence: the enabled set is written to the ``custom_metrics`` table in
  the agent's local SQLite database so the scheduler survives an agent
  restart without waiting for the next server sync.
* Scheduling: a single async loop ticks once per second and runs each metric
  when its cadence has elapsed (mirrors the ``UpdateChecker`` /
  ``PackageCollectionScheduler`` pattern in ``agent_utils.py``).  A 60s floor
  is enforced on every cadence.
* Cross-platform: when the requested interpreter is not available (e.g.
  ``sh``/``bash`` on a bare Windows host) the run yields an error sample with
  a clear ``error_detail`` instead of crashing.  ``python3`` works
  everywhere.
* The script's stdout is NEVER logged beyond the single parsed number or the
  error detail.
"""

from __future__ import annotations

import asyncio
import logging
import shutil
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from src.database.base import get_database_manager
from src.database.models import CustomMetric
from src.i18n import _

# Interpreters we are willing to run, mapped to the argv used to run a script
# body passed on stdin/inline.  We use ``-c`` for all three: POSIX ``sh`` /
# ``bash`` accept ``-c <string>`` and ``python3`` accepts ``-c <string>`` too.
_ALLOWED_INTERPRETERS = ("sh", "bash", "python3")

# Never let a single metric run wedge the scheduler.
_RUN_TIMEOUT_SECONDS = 30

# Server may send anything; clamp to a sane floor so a misconfigured metric
# can't hammer the host.
_CADENCE_FLOOR_SECONDS = 60


class CustomMetricsOperations:
    """Runs custom metric scripts on a cadence and reports samples back."""

    def __init__(self, agent_instance):
        """Initialize custom-metric operations with the agent instance."""
        self.agent = agent_instance
        self.logger = logging.getLogger(__name__)

        # The current enabled set, keyed by metric_id.  Each value is a dict
        # with keys: metric_id, name, script, interpreter, cadence_seconds.
        self._metrics: Dict[str, Dict[str, Any]] = {}

        # Per-metric monotonic timestamp of the last run (event-loop clock).
        # None means "never run" so it fires on the first tick.
        self._last_run: Dict[str, Optional[float]] = {}

        # Guards mutation of the metric set from the sync handler vs the
        # scheduler loop.
        self._lock = asyncio.Lock()

    # ================================================================
    # sync_custom_metrics handler
    # ================================================================

    async def sync_custom_metrics(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """
        Replace the agent's entire custom-metric set with the server's set.

        Parameters:
            metrics: list of {id, name, script, interpreter, cadence_seconds}.
                     The COMPLETE enabled set; an empty/missing list clears
                     everything.

        Returns:
            {success, metric_count} acknowledgement.
        """
        raw_metrics = parameters.get("metrics") or []

        normalized: Dict[str, Dict[str, Any]] = {}
        skipped = 0
        for entry in raw_metrics:
            metric = self._normalize_metric(entry)
            if metric is None:
                skipped += 1
                continue
            normalized[metric["metric_id"]] = metric

        async with self._lock:
            self._metrics = normalized
            # Reset run bookkeeping: brand-new metrics fire on the next tick,
            # dropped metrics stop firing.
            self._last_run = {mid: None for mid in normalized}

        # Persist the new set so it survives a restart.
        self._persist_metrics(normalized)

        self.logger.info(
            _("Synced custom metrics: %d active, %d skipped (invalid)"),
            len(normalized),
            skipped,
        )

        return {
            "success": True,
            "metric_count": len(normalized),
            "skipped": skipped,
        }

    @staticmethod
    def _normalize_metric(entry: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Validate + normalize one server metric entry, or None if invalid."""
        if not isinstance(entry, dict):
            return None
        metric_id = entry.get("id") or entry.get("metric_id")
        script = entry.get("script")
        interpreter = entry.get("interpreter")
        if not metric_id or not script or interpreter not in _ALLOWED_INTERPRETERS:
            return None
        try:
            cadence = int(entry.get("cadence_seconds") or _CADENCE_FLOOR_SECONDS)
        except (TypeError, ValueError):
            cadence = _CADENCE_FLOOR_SECONDS
        cadence = max(cadence, _CADENCE_FLOOR_SECONDS)
        return {
            "metric_id": str(metric_id),
            "name": entry.get("name") or str(metric_id),
            "script": script,
            "interpreter": interpreter,
            "cadence_seconds": cadence,
        }

    # ================================================================
    # persistence
    # ================================================================

    def _persist_metrics(self, metrics: Dict[str, Dict[str, Any]]) -> None:
        """Replace the persisted custom-metric set in the local database."""
        try:
            db_manager = get_database_manager()
            session = db_manager.get_session()
            try:
                # REPLACE semantics: wipe the table then insert the new set.
                session.query(CustomMetric).delete()
                now = datetime.now(timezone.utc)
                for metric in metrics.values():
                    session.add(
                        CustomMetric(
                            metric_id=metric["metric_id"],
                            name=metric["name"],
                            script=metric["script"],
                            interpreter=metric["interpreter"],
                            cadence_seconds=metric["cadence_seconds"],
                            created_at=now,
                            updated_at=now,
                        )
                    )
                session.commit()
            finally:
                session.close()
        except Exception as error:  # pylint: disable=broad-exception-caught
            self.logger.error(_("Failed to persist custom metrics: %s"), error)

    def load_persisted_metrics(self) -> int:
        """
        Load the persisted metric set into memory (called at agent startup).

        Returns the number of metrics loaded.
        """
        try:
            db_manager = get_database_manager()
            session = db_manager.get_session()
            try:
                rows = session.query(CustomMetric).all()
                loaded: Dict[str, Dict[str, Any]] = {}
                for row in rows:
                    cadence = max(
                        int(row.cadence_seconds or _CADENCE_FLOOR_SECONDS),
                        _CADENCE_FLOOR_SECONDS,
                    )
                    loaded[row.metric_id] = {
                        "metric_id": row.metric_id,
                        "name": row.name,
                        "script": row.script,
                        "interpreter": row.interpreter,
                        "cadence_seconds": cadence,
                    }
            finally:
                session.close()
        except Exception as error:  # pylint: disable=broad-exception-caught
            self.logger.error(_("Failed to load persisted custom metrics: %s"), error)
            return 0

        self._metrics = loaded
        self._last_run = {mid: None for mid in loaded}
        if loaded:
            self.logger.info(
                _("Loaded %d persisted custom metric(s) at startup"), len(loaded)
            )
        return len(loaded)

    # ================================================================
    # running a single metric
    # ================================================================

    async def _run_metric(self, metric: Dict[str, Any]) -> Dict[str, Any]:
        """
        Run one metric's script and return a sample dict.

        Sample shape:
            {metric_id, value, status, error_detail, collected_at}
        """
        metric_id = metric["metric_id"]
        interpreter = metric["interpreter"]
        script = metric["script"]
        collected_at = datetime.now(timezone.utc).isoformat()

        interp_path = shutil.which(interpreter)
        if not interp_path:
            # e.g. sh/bash absent on a bare Windows host.
            return self._error_sample(
                metric_id,
                collected_at,
                _("interpreter '%s' not available on this host") % interpreter,
            )

        try:
            returncode, stdout, stderr = await self._exec_script(interp_path, script)
        except Exception as error:  # pylint: disable=broad-exception-caught
            # Never crash the scheduler on a single metric failure.
            return self._error_sample(
                metric_id,
                collected_at,
                _("failed to run metric: %s") % error,
            )

        if returncode != 0:
            detail = stderr.strip() or _("script exited with code %s") % returncode
            return self._error_sample(metric_id, collected_at, detail)

        value = self._parse_numeric(stdout)
        if value is None:
            return self._error_sample(
                metric_id,
                collected_at,
                _("script stdout was not a single numeric value"),
            )

        return {
            "metric_id": metric_id,
            "value": value,
            "status": "ok",
            "error_detail": None,
            "collected_at": collected_at,
        }

    @staticmethod
    async def _exec_script(interp_path: str, script: str) -> Tuple[int, str, str]:
        """
        Run ``<interp_path> -c <script>`` with a bounded timeout.

        Returns ``(returncode, stdout, stderr)``.  A timeout returns rc=124
        with a note in stderr.  The script body is passed as a single argv
        element (``-c``) — never via a shell string — so there is no shell
        interpolation of the script content by us.
        """
        proc = await asyncio.create_subprocess_exec(
            interp_path,
            "-c",
            script,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout_b, stderr_b = await asyncio.wait_for(
                proc.communicate(), timeout=_RUN_TIMEOUT_SECONDS
            )
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            return 124, "", "metric script timed out"

        stdout = (stdout_b or b"").decode("utf-8", "replace")
        stderr = (stderr_b or b"").decode("utf-8", "replace")
        return proc.returncode or 0, stdout, stderr

    @staticmethod
    def _parse_numeric(stdout: str) -> Optional[float]:
        """
        Parse the LAST non-empty stdout line as a float.

        Returns the float value, or None if there is no parseable numeric
        line.  We take the last non-empty line so a script that echoes
        progress before printing its final number still parses.
        """
        last_line = None
        for line in stdout.splitlines():
            stripped = line.strip()
            if stripped:
                last_line = stripped
        if last_line is None:
            return None
        try:
            return float(last_line)
        except ValueError:
            return None

    @staticmethod
    def _error_sample(metric_id: str, collected_at: str, detail: str) -> Dict[str, Any]:
        """Build an errored sample dict."""
        return {
            "metric_id": metric_id,
            "value": None,
            "status": "error",
            "error_detail": detail,
            "collected_at": collected_at,
        }

    # ================================================================
    # scheduler loop
    # ================================================================

    async def run_metrics_loop(self) -> None:
        """
        Main custom-metrics scheduler loop.

        Ticks once per second; runs each metric when its cadence has elapsed.
        Samples produced within a tick are batched into a single
        ``custom_metric_samples`` message.  Integrated with the agent's event
        loop exactly like the other background tasks (see main.py
        ``_run_agent_tasks``).
        """
        self.logger.debug("Custom-metrics scheduler started")

        while getattr(self.agent, "running", False):
            try:
                await self._tick()
                await asyncio.sleep(1)
            except asyncio.CancelledError:
                self.logger.debug("Custom-metrics scheduler cancelled")
                raise
            except Exception as error:  # pylint: disable=broad-exception-caught
                self.logger.error(_("Custom-metrics scheduler error: %s"), error)
                await asyncio.sleep(5)
                continue

    async def _tick(self) -> None:
        """Run any metrics whose cadence has elapsed and send their samples."""
        now = asyncio.get_event_loop().time()

        # Snapshot the due metrics under the lock so a concurrent sync can't
        # mutate the dict mid-iteration.
        due: List[Dict[str, Any]] = []
        async with self._lock:
            for metric_id, metric in self._metrics.items():
                last = self._last_run.get(metric_id)
                if last is None or (now - last) >= metric["cadence_seconds"]:
                    due.append(metric)
                    self._last_run[metric_id] = now

        if not due:
            return

        samples = []
        for metric in due:
            samples.append(await self._run_metric(metric))

        if samples:
            await self._send_samples(samples)

    async def _send_samples(self, samples: List[Dict[str, Any]]) -> None:
        """Send a batch of samples to the server as ``custom_metric_samples``."""
        try:
            message = self.agent.create_message(
                "custom_metric_samples", {"samples": samples}
            )
            await self.agent.send_message(message)
            self.logger.debug("Sent %d custom metric sample(s) to server", len(samples))
        except Exception as error:  # pylint: disable=broad-exception-caught
            self.logger.error(_("Failed to send custom metric samples: %s"), error)
