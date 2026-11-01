# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""Cache for the Ubuntu Pro / Livepatch status queries.

``get_system_info()`` -- which 37 call sites use, most of them only for the
hostname -- reads the OS info, and that ran ``sudo pro status --all`` (about 8
seconds on beast) plus ``sudo canonical-livepatch status`` on EVERY call.  The
agent ran both back to back all day, roughly every 10 seconds (beast,
2026-10-19): the journal was nothing but sudo sessions, and the box spent its
time asking a question whose answer changes a few times a year.

A status answer is reused for ``TTL_SECONDS``.  The agent's own Pro actions
(attach, detach, enable, disable) call :func:`invalidate`, so what the
operator just changed shows on the next report rather than minutes later.

A failure is kept too, for ``FAILURE_TTL_SECONDS``: the first version cached
only answers that succeeded, so where ``pro status`` takes longer than the
agent waits (nas, 2026-10-27: 20-30 seconds) every call timed out, nothing
was kept, and the storm came back -- one ``sudo pro status`` every 10
seconds, each leaving a ``pro`` running after its sudo was killed, and every
message the agent handled waiting out the timeout first.

An expired answer is served at once while ONE background thread asks again
(stale-while-revalidate).  Asking in the caller's place still froze the agent:
``get_system_info()`` runs on the event loop from dozens of places, and every
five minutes one of them waited for ``sudo pro status`` -- 37 seconds from the
agent on ubiquiti -- while the loop answered no pings, so the server dropped
the websocket every 5-40 minutes (production, 2026-11-01).  Only a key never
asked (startup, before the agent connects, or right after :func:`invalidate`)
is asked in the caller's place.
"""

import logging
import subprocess  # nosec B404
import threading
import time
from typing import Callable, Dict, Set, Tuple

TTL_SECONDS = 300.0
FAILURE_TTL_SECONDS = 300.0
TIMED_OUT = 124  # the returncode kept for a query that timed out
NOT_FOUND = 127  # ... and for one whose command is not installed

logger = logging.getLogger(__name__)

_lock = threading.Lock()
_cache: Dict[Tuple[str, ...], Tuple[float, subprocess.CompletedProcess]] = {}
_refreshing: Set[Tuple[str, ...]] = set()  # keys a background thread is asking


def _ask(argv: list, run: Callable[[list], subprocess.CompletedProcess]):
    """``run(argv)``, with a timeout or a missing command as a failed answer."""
    try:
        return run(argv)
    except subprocess.TimeoutExpired as error:
        logger.warning(
            "%s timed out after %ss; asking again in %d minutes",
            " ".join(argv), error.timeout, FAILURE_TTL_SECONDS // 60,
        )  # fmt: skip
        return subprocess.CompletedProcess(argv, TIMED_OUT, "", "timed out")
    except FileNotFoundError:
        return subprocess.CompletedProcess(argv, NOT_FOUND, "", "not installed")


def _keep(key: Tuple[str, ...], result: subprocess.CompletedProcess) -> None:
    good = result.returncode == 0 and bool(result.stdout)
    ttl = TTL_SECONDS if good else FAILURE_TTL_SECONDS
    with _lock:
        _cache[key] = (time.monotonic() + ttl, result)


def _refresh(key, argv, run) -> None:
    try:
        _keep(key, _ask(argv, run))
    finally:
        with _lock:
            _refreshing.discard(key)


def cached_run(
    argv: list, run: Callable[[list], subprocess.CompletedProcess]
) -> subprocess.CompletedProcess:
    """``run(argv)``, or its answer from the last ``TTL_SECONDS`` (an answer
    that succeeded) or ``FAILURE_TTL_SECONDS`` (one that did not).

    A timeout or a missing command comes back as a non-zero result
    (``TIMED_OUT`` / ``NOT_FOUND``) rather than raising, and is kept like any
    other failure, so a slow or absent ``pro`` is asked once per period.  An
    expired answer is returned as it is while a background thread asks again.
    """
    key = tuple(argv)
    with _lock:
        hit = _cache.get(key)
        if hit is not None:
            if time.monotonic() >= hit[0] and key not in _refreshing:
                _refreshing.add(key)
                threading.Thread(
                    target=_refresh,
                    args=(key, argv, run),
                    name="pro-status-refresh",
                    daemon=True,
                ).start()
            return hit[1]
    result = _ask(argv, run)
    _keep(key, result)
    return result


def wait_for_refreshes(timeout: float = 5.0) -> None:
    """Wait until no background refresh is running (tests, shutdown)."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        with _lock:
            if not _refreshing:
                return
        time.sleep(0.01)


def invalidate() -> None:
    """Forget every cached answer (the agent just changed Ubuntu Pro)."""
    with _lock:
        _cache.clear()
