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
"""

import logging
import subprocess  # nosec B404
import threading
import time
from typing import Callable, Dict, Tuple

TTL_SECONDS = 300.0
FAILURE_TTL_SECONDS = 300.0
TIMED_OUT = 124  # the returncode kept for a query that timed out
NOT_FOUND = 127  # ... and for one whose command is not installed

logger = logging.getLogger(__name__)

_lock = threading.Lock()
_cache: Dict[Tuple[str, ...], Tuple[float, subprocess.CompletedProcess]] = {}


def cached_run(
    argv: list, run: Callable[[list], subprocess.CompletedProcess]
) -> subprocess.CompletedProcess:
    """``run(argv)``, or its answer from the last ``TTL_SECONDS`` (an answer
    that succeeded) or ``FAILURE_TTL_SECONDS`` (one that did not).

    A timeout or a missing command comes back as a non-zero result
    (``TIMED_OUT`` / ``NOT_FOUND``) rather than raising, and is kept like any
    other failure, so a slow or absent ``pro`` is asked once per period.
    """
    key = tuple(argv)
    now = time.monotonic()
    with _lock:
        hit = _cache.get(key)
        if hit is not None and now < hit[0]:
            return hit[1]
    try:
        result = run(argv)
    except subprocess.TimeoutExpired as error:
        logger.warning(
            "%s timed out after %ss; asking again in %d minutes",
            " ".join(argv), error.timeout, FAILURE_TTL_SECONDS // 60,
        )  # fmt: skip
        result = subprocess.CompletedProcess(argv, TIMED_OUT, "", "timed out")
    except FileNotFoundError:
        result = subprocess.CompletedProcess(argv, NOT_FOUND, "", "not installed")
    good = result.returncode == 0 and bool(result.stdout)
    ttl = TTL_SECONDS if good else FAILURE_TTL_SECONDS
    with _lock:
        _cache[key] = (time.monotonic() + ttl, result)
    return result


def invalidate() -> None:
    """Forget every cached answer (the agent just changed Ubuntu Pro)."""
    with _lock:
        _cache.clear()
