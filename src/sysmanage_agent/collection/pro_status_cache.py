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
"""

import subprocess  # nosec B404
import threading
import time
from typing import Callable, Dict, Tuple

TTL_SECONDS = 300.0

_lock = threading.Lock()
_cache: Dict[Tuple[str, ...], Tuple[float, subprocess.CompletedProcess]] = {}


def cached_run(
    argv: list, run: Callable[[list], subprocess.CompletedProcess]
) -> subprocess.CompletedProcess:
    """``run(argv)``, or its answer from the last ``TTL_SECONDS``.

    Only an answer that succeeded is kept: a timeout or a refusal raises or
    returns non-zero and is asked again next time.
    """
    key = tuple(argv)
    now = time.monotonic()
    with _lock:
        hit = _cache.get(key)
        if hit is not None and now - hit[0] < TTL_SECONDS:
            return hit[1]
    result = run(argv)
    if result.returncode == 0 and result.stdout:
        with _lock:
            _cache[key] = (time.monotonic(), result)
    return result


def invalidate() -> None:
    """Forget every cached answer (the agent just changed Ubuntu Pro)."""
    with _lock:
        _cache.clear()
