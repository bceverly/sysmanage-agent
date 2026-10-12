# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""
The agent's half of the server's clock-offset measurement (Phase 23.3 S1).

The server stamps ``clock.t1`` on a message at the moment it writes it to the
socket.  The agent stamps t2 the moment that message arrives and t3 the
moment its next heartbeat LEAVES, and echoes all three; the server stamps t4
on arrival.  Then

    offset = ((t2 - t1) + (t3 - t4)) / 2

which is the host's clock minus the server's, with ALL queue residence
between t2 and t3 excluded -- heartbeats sit in the persistent outbound queue
for an unknown time, and that must not matter.  Measured in the S0 spike: the
median of such samples within 2 ms of ground truth on five OSes, with replies
held up to 2 s.

Two guards keep a sample honest:

* ``hold`` -- the MONOTONIC time between t2 and t3.  If the host's clock is
  stepped while the pair waits (an NTP step, a manual ``date -s``), wall-clock
  t3 - t2 no longer equals ``hold`` and the server discards the sample.
* a pair is used ONCE and expires after ``MAX_AGE`` seconds, so one old
  receipt never produces a stream of stale, identical samples.

The stamps are taken at the socket edges ONLY -- in the receive loop and in
``send_message_direct`` -- never when a message is created or queued.
"""

from __future__ import annotations

import time
from typing import Any, Dict, Optional

# A receipt older than this is not echoed: the host may have drifted since.
MAX_AGE = 15 * 60


class ClockProbe:
    """Holds the latest (t1, t2) receipt until a heartbeat carries it out."""

    def __init__(self) -> None:
        self._t1: Optional[float] = None
        self._t2: Optional[float] = None
        self._received_mono: Optional[float] = None

    def received(self, message: Dict[str, Any], t2: float, mono: float) -> None:
        """Note a server message's ``clock.t1``, stamped ``t2`` on arrival.

        ``t2``/``mono`` are taken by the caller immediately after the socket
        read, before parsing -- parse time must count as network, not host."""
        clock = message.get("clock") if isinstance(message, dict) else None
        t1 = clock.get("t1") if isinstance(clock, dict) else None
        if isinstance(t1, (int, float)) and not isinstance(t1, bool):
            self._t1, self._t2, self._received_mono = float(t1), t2, mono

    def stamp(self, message: Dict[str, Any]) -> Dict[str, Any]:
        """Attach ``clock`` to an outgoing heartbeat at the moment it is sent.

        Other message types pass through untouched; a heartbeat with no fresh
        receipt goes out without ``clock`` (an older server never sends t1)."""
        if message.get("message_type") != "heartbeat" or self._t1 is None:
            return message
        now_mono = time.monotonic()
        hold = now_mono - self._received_mono
        if hold > MAX_AGE:
            self._clear()
            return message
        message["clock"] = {
            "t1": self._t1,
            "t2": self._t2,
            "t3": time.time(),
            "hold": hold,
        }
        self._clear()
        return message

    def _clear(self) -> None:
        self._t1 = self._t2 = self._received_mono = None
