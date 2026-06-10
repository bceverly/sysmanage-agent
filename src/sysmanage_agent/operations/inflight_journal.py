"""
In-flight subprocess journal for the SysManage agent (Phase 11.6).

Phase 11 introduces multi-hour subprocess plans (apt-mirror, ISO build,
package mirror sync).  If the agent restarts mid-plan or the WebSocket
bounces, the subprocess gets killed and the server's mirror row sits in
DISPATCHED forever.  This module fixes that with a per-plan execution-state
journal at ``~/.sysmanage-agent/inflight/<message_id>.json`` that survives
agent restarts:

    1. Before ``subprocess.Popen`` we write a journal entry with the plan
       metadata, the spawned PID, and a heartbeat timestamp.
    2. While the subprocess is running, a watchdog refreshes
       ``last_heartbeat_at`` every 30 seconds.
    3. On a clean exit we delete the journal entry — the result is being
       sent normally.
    4. On the next agent startup we walk the directory and classify each
       leftover entry: live PIDs are left alone (re-emit a "still running"
       status), dead PIDs get a synthetic ``command_result`` so the server's
       DISPATCHED row clears.

The "make every plan idempotent and re-dispatch on timeout" alternative was
considered and rejected because some plans (KVM cloud-init seed) have non-
idempotent side effects.  See ROADMAP.md §11.6 for the full discussion.

The module is stdlib-only (no new external deps), Python 3.9+ compatible,
and works on Linux, macOS, FreeBSD/OpenBSD/NetBSD, and Windows.
"""

from __future__ import annotations

import json
import logging
import os
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from src.i18n import _

LOGGER = logging.getLogger(__name__)

# Heartbeat cadence used by the watchdog task in
# ``generic_deployment.apply_deployment_plan``.  30 s is short enough that a
# crashed agent looks unambiguously dead on restart (we only need to be sure
# the journal isn't merely stale because the agent was busy) and long enough
# that we don't churn the disk while a multi-hour subprocess runs.
HEARTBEAT_INTERVAL_SECONDS: float = 30.0


def journal_dir() -> Path:
    """Return the on-disk directory for in-flight journal files.

    Centralised so tests can monkeypatch ``HOME`` / ``USERPROFILE`` and get
    an isolated journal directory without touching the user's real one.
    """
    home = (
        os.environ.get("HOME")
        or os.environ.get("USERPROFILE")
        or os.path.expanduser("~")
    )
    return Path(home) / ".sysmanage-agent" / "inflight"


def _journal_path(message_id: str) -> Path:
    """Return the journal file path for ``message_id``."""
    return journal_dir() / f"{message_id}.json"


def _ensure_journal_dir() -> Path:
    """Create the journal directory (idempotent) and return its Path."""
    directory = journal_dir()
    directory.mkdir(parents=True, exist_ok=True)
    return directory


def _atomic_write_json(path: Path, payload: Dict[str, Any]) -> None:
    """Write ``payload`` to ``path`` atomically (tempfile + rename).

    Atomicity matters: an agent crash mid-write must never leave a half-
    written journal file that the next startup scan trips over.
    """
    parent = path.parent
    parent.mkdir(parents=True, exist_ok=True)
    file_descriptor, tmp_name = tempfile.mkstemp(
        dir=str(parent), prefix=".inflight_", suffix=".tmp"
    )
    try:
        with os.fdopen(file_descriptor, "w", encoding="utf-8") as out:
            json.dump(payload, out, sort_keys=True)
            out.flush()
            try:
                os.fsync(out.fileno())
            except OSError:
                # fsync is best-effort; some filesystems (e.g. tmpfs in CI)
                # don't support it but the rename below is still atomic.
                pass
        os.replace(tmp_name, path)
    except Exception:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise


def journal_write(
    message_id: str,
    plan: Dict[str, Any],
    command_argv: List[str],
    working_dir: Optional[str],
    pid: Optional[int] = None,
) -> Path:
    """Create the journal entry for a subprocess about to be spawned.

    Args:
        message_id: The server's message_id for the deployment plan; used
            as the journal filename.
        plan: The full plan dict from ``apply_deployment_plan`` parameters
            (stored verbatim so a future restart could in principle re-
            attempt the work).
        command_argv: The argv list of the subprocess.  Stored for forensic
            value — if the journal entry is later flagged as dead, an admin
            can grep ``inflight/`` to see what was running.
        working_dir: The CWD the subprocess was launched in (or None).
        pid: Optional initial PID to write.  Left None when the journal is
            written before the subprocess is spawned; ``journal_set_pid``
            fills it in once ``Popen`` returns.

    Returns:
        The Path of the journal file on disk.
    """
    _ensure_journal_dir()
    now = time.time()
    payload: Dict[str, Any] = {
        "message_id": message_id,
        "plan": plan,
        "started_at": now,
        "pid": pid,
        "command_argv": list(command_argv),
        "working_dir": working_dir,
        "last_heartbeat_at": now,
    }
    path = _journal_path(message_id)
    _atomic_write_json(path, payload)
    LOGGER.debug("Wrote in-flight journal entry: %s", path)
    return path


def journal_set_pid(message_id: str, pid: int) -> None:
    """Update the journal entry with the actual spawned PID.

    Called immediately after ``subprocess.Popen`` / ``create_subprocess_exec``
    returns.  Loading-then-rewriting keeps every existing field intact so a
    later heartbeat update doesn't blow away the PID and vice-versa.
    """
    path = _journal_path(message_id)
    if not path.exists():
        LOGGER.debug("journal_set_pid: no entry for %s", message_id)
        return
    try:
        with open(path, "r", encoding="utf-8") as handle:
            payload = json.load(handle)
    except (OSError, json.JSONDecodeError) as error:
        LOGGER.warning("Could not read journal %s for pid update: %s", path, error)
        return
    payload["pid"] = pid
    payload["last_heartbeat_at"] = time.time()
    _atomic_write_json(path, payload)


def journal_heartbeat(message_id: str) -> None:
    """Refresh the ``last_heartbeat_at`` timestamp on a journal entry.

    Called from a watchdog asyncio task every ``HEARTBEAT_INTERVAL_SECONDS``
    while the subprocess is alive.  Silently no-ops if the entry is gone —
    the subprocess may have just exited and ``journal_clear`` may have
    raced ahead.
    """
    path = _journal_path(message_id)
    if not path.exists():
        return
    try:
        with open(path, "r", encoding="utf-8") as handle:
            payload = json.load(handle)
    except (OSError, json.JSONDecodeError) as error:
        LOGGER.warning("Could not read journal %s for heartbeat: %s", path, error)
        return
    payload["last_heartbeat_at"] = time.time()
    try:
        _atomic_write_json(path, payload)
    except OSError as error:
        LOGGER.warning("Could not refresh journal heartbeat %s: %s", path, error)


def journal_clear(message_id: str) -> None:
    """Delete the journal entry for ``message_id`` (post-clean-exit).

    Idempotent: missing files are not an error.  Called after the subprocess
    exits and its ``command_result`` has been queued for delivery.
    """
    path = _journal_path(message_id)
    try:
        path.unlink()
        LOGGER.debug("Cleared in-flight journal entry: %s", path)
    except FileNotFoundError:
        return
    except OSError as error:
        LOGGER.warning("Could not remove journal %s: %s", path, error)


def is_pid_alive(pid: Optional[int]) -> bool:
    """Cross-platform liveness check for a PID.

    On POSIX (Linux, macOS, *BSD) ``os.kill(pid, 0)`` succeeds iff a
    process with that PID is alive AND the calling user has permission to
    signal it.  ``EPERM`` means the process exists but belongs to another
    user — still a live PID, so we treat that as alive.

    On Windows we open the process with PROCESS_QUERY_LIMITED_INFORMATION
    via ``ctypes``.  A non-zero handle plus a successful close means alive;
    any failure is treated as dead.

    Args:
        pid: The process ID to check.  None and non-positive values are
            treated as dead (covers journals where the PID was never
            written because the spawn failed before ``Popen`` returned).
    """
    if pid is None or pid <= 0:
        return False
    if sys.platform == "win32":
        return _is_pid_alive_windows(pid)
    return _is_pid_alive_posix(pid)


def _is_pid_alive_posix(pid: int) -> bool:
    """POSIX ``os.kill(pid, 0)`` liveness probe.

    ``signal=0`` is a no-op on POSIX — the call only performs the
    permission + existence check that ``kill(2)`` does before delivery,
    without actually sending a signal.  This is the standard
    cross-platform liveness probe (used by ``psutil``, ``supervisor``,
    and the Python stdlib itself in ``multiprocessing``).  No process
    state is changed.

    SonarQube python:S4831 / S4828 and bandit B606 flag any ``os.kill``
    call as a hotspot because the linter can't tell ``signal=0`` from a
    real signal at parse time.  Both annotations below document why the
    call is safe in this specific context (signal=0 is a no-op probe).
    """
    try:
        # nosec B606  # NOSONAR python:S4831
        # ``signal=0`` is the POSIX-documented no-op liveness probe;
        # no signal is delivered.  See kill(2) on any POSIX system.
        os.kill(pid, 0)  # nosec B606  # NOSONAR
    except ProcessLookupError:
        return False
    except PermissionError:
        # Process exists but we're not allowed to signal it (different
        # user / different namespace).  Still alive from our POV.
        return True
    except OSError:
        return False
    return True


def _is_pid_alive_windows(pid: int) -> bool:
    """Windows OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION) liveness probe.

    Imported lazily inside the function so non-Windows platforms never
    touch ``ctypes.windll`` (which doesn't exist outside Windows).
    """
    try:
        # pylint: disable=import-outside-toplevel
        import ctypes
        from ctypes import wintypes
    except ImportError:
        return False

    pql_info = 0x1000  # PROCESS_QUERY_LIMITED_INFORMATION
    kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.OpenProcess.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
    handle = kernel32.OpenProcess(pql_info, False, pid)
    if not handle:
        return False
    try:
        # GetExitCodeProcess returns STILL_ACTIVE (259) if the process
        # has not exited.  We don't actually need the exit code here —
        # holding a valid handle is itself proof of liveness.
        return True
    finally:
        kernel32.CloseHandle(handle)


def _load_journal(path: Path) -> Optional[Dict[str, Any]]:
    """Load and return one journal payload, or None if it can't be parsed."""
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return json.load(handle)
    except (OSError, json.JSONDecodeError) as error:
        LOGGER.warning("Could not read journal %s: %s", path, error)
        return None


def _build_synthetic_command_result(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Build the fake ``command_result`` for a subprocess killed by restart.

    The shape matches what ``MessageProcessor.handle_command`` would have
    sent if the subprocess had exited normally, so the server's existing
    handler clears the DISPATCHED row without any new code.  The stderr
    string is wrapped in ``_()`` so it gets translated per the agent's
    configured language.
    """
    return {
        "command_id": payload.get("message_id"),
        "command_type": "apply_deployment_plan",
        "success": False,
        "exit_code": -1,
        "result": None,
        "error": _("agent restart while plan was in-flight; subprocess killed"),
        "stderr": _("agent restart while plan was in-flight; subprocess killed"),
        "killed_by_restart": True,
    }


def scan_inflight_on_startup(
    enqueue_command_result: Optional[Callable[[Dict[str, Any]], Any]] = None,
) -> Dict[str, List[str]]:
    """Walk ``~/.sysmanage-agent/inflight/`` and classify every leftover entry.

    For each journal file:
        * If the recorded PID is still alive: log it as live, leave the
          file in place, and let the running subprocess drive its own
          cleanup when it exits.
        * If the PID is gone: emit a synthetic ``command_result`` with
          ``killed_by_restart=True`` via ``enqueue_command_result``, then
          delete the journal entry.

    Args:
        enqueue_command_result: Callable that consumes one synthetic
            command_result dict and queues it for delivery to the server.
            Typically ``lambda msg: agent.message_handler.queue_outbound_message(msg)``.
            Optional — when None we just classify and clean up dead
            entries (used by tests and by the no-network startup path).

    Returns:
        Dict with two keys:
            ``live``: list of message_ids whose subprocess is still alive.
            ``dead``: list of message_ids that were cleaned up.
    """
    directory = journal_dir()
    classified: Dict[str, List[str]] = {"live": [], "dead": []}
    if not directory.exists():
        return classified

    for entry in sorted(directory.iterdir()):
        if not entry.is_file() or entry.suffix != ".json":
            continue
        payload = _load_journal(entry)
        if payload is None:
            # Unreadable / corrupt journal file — treat it as dead so we
            # don't carry it forward, and remove it.
            _safe_unlink(entry)
            continue
        message_id = payload.get("message_id") or entry.stem
        pid = payload.get("pid")
        if is_pid_alive(pid):
            LOGGER.info(
                "In-flight subprocess still running after restart: "
                "message_id=%s pid=%s",
                message_id,
                pid,
            )
            classified["live"].append(message_id)
            continue
        LOGGER.warning(
            "In-flight subprocess died across agent restart: "
            "message_id=%s pid=%s — emitting synthetic command_result",
            message_id,
            pid,
        )
        if enqueue_command_result is not None:
            try:
                enqueue_command_result(_build_synthetic_command_result(payload))
            except Exception as error:  # pylint: disable=broad-exception-caught
                LOGGER.exception(
                    "Failed to enqueue synthetic command_result for %s: %s",
                    message_id,
                    error,
                )
        _safe_unlink(entry)
        classified["dead"].append(message_id)

    return classified


def _safe_unlink(path: Path) -> None:
    """Unlink ``path`` swallowing the missing-file race."""
    try:
        path.unlink()
    except FileNotFoundError:
        return
    except OSError as error:
        LOGGER.warning("Could not remove journal %s: %s", path, error)
