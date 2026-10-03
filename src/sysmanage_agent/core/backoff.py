# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""How long to wait before trying the server again (server Phase 22.1).

WHY
---
Every retry path waited a fixed time or a narrowly jittered one: reconnects
x U(0.5, 1.5), registration a flat 30 s then an exit into systemd's flat 10 s
restart, polling errors a flat 15 s, a failed health check a flat 5 s with no
backoff at all.  A fleet that fails together -- the server restarts, a link
drops -- then retries together, in waves, for as long as the outage lasts.

HOW
---
Full jitter: wait a uniformly random time between a small floor and an
exponentially growing ceiling.  A crowd that failed in the same second spreads
over the whole window instead of returning in clumps.  A server that says how
long to wait (``Retry-After`` on a 429 / 503) is believed, with a little
jitter on top.  After a CLEAN close -- the server going away for a restart --
the first window is wide: the server is coming back and every agent knows it
at the same instant.
"""

import secrets

FLOOR_SECONDS = 1.0
CEILING_SECONDS = 300.0
# After the server closed the connection on purpose (going away / restart /
# try again later), spread the first reconnect over this window.
CLEAN_CLOSE_WINDOW_SECONDS = 60.0
CLEAN_CLOSE_CODES = (1001, 1012, 1013)
HINT_JITTER = 0.2  # a server hint, plus up to 20%

_random = secrets.SystemRandom()


class ServerUnavailable(ConnectionError):
    """The server could not be reached or used (health check, registration):
    try again after the usual backoff, not at once."""


def full_jitter(base: float, attempt: int, ceiling: float = CEILING_SECONDS) -> float:
    """A random wait in [floor, min(ceiling, base x 2^attempt)]."""
    top = min(ceiling, max(base, FLOOR_SECONDS) * (2 ** max(0, min(attempt, 16))))
    return _random.uniform(min(FLOOR_SECONDS, top), top)


def with_hint(delay: float, hint: float) -> float:
    """At least what the server asked for (jittered), else ``delay``."""
    if hint and hint > 0:
        return max(delay, hint * _random.uniform(1.0, 1.0 + HINT_JITTER))
    return delay


def reconnect_delay(base: float, failures: int, clean_close: bool = False,
                    hint: float = 0.0) -> float:  # fmt: skip
    """How long to wait before reconnecting after ``failures`` failures."""
    delay = full_jitter(base, failures)
    if clean_close and failures <= 1:
        delay = _random.uniform(FLOOR_SECONDS, CLEAN_CLOSE_WINDOW_SECONDS)
    return with_hint(delay, hint)


def is_clean_close(error: BaseException) -> bool:
    """Did the server close the connection on purpose (restart, overload)?"""
    # The close frames, not ``error.code`` (deprecated in websockets 13+).
    return any(
        getattr(getattr(error, attr, None), "code", None) in CLEAN_CLOSE_CODES
        for attr in ("rcvd", "sent")
    )


def jittered(seconds: float, spread: float = 0.2) -> float:
    """``seconds`` varied by up to +/-``spread`` (a fraction)."""
    return seconds * _random.uniform(1.0 - spread, 1.0 + spread)
