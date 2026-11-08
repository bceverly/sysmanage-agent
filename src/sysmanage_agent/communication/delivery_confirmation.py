# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""Keep each message until the server says it is stored (2026-11-06).

The agent used to delete a message from its queue as soon as the WebSocket
write succeeded.  When the server could not store it -- its database
restarting, upgrading or paused for a backup -- the message was lost from
both ends: command results, script output, backup results.

Now, when the server says it confirms (``delivery_confirmation`` in
``registration_success``; the agent says the same in its ``system_info``), a
sent message is kept as ``sent`` until ``message_stored`` names it:

* ``stored`` -- delete it, as before;
* ``rejected`` -- the server will never take it (it failed validation):
  kept as failed, for diagnosis, and never resent;
* no answer within :data:`CONFIRM_TIMEOUT_SECONDS`, or a new connection --
  back to pending, and sent again.  A resend does not count against the
  message's retries: waiting out an outage is not a failure, and nothing
  waiting for confirmation is ever expired.  The server stores a message id
  only once, so a resend whose first copy arrived is harmless.

A server that does not confirm is treated exactly as before: deleted once
written.
"""

import time
from typing import Dict, List, Optional, Tuple

FLAG = "delivery_confirmation"
SUPPORTED = 1
MESSAGE_TYPE = "message_stored"
STORED = "stored"
REJECTED = "rejected"
CONFIRM_TIMEOUT_SECONDS = 120
# How often the outbound loop looks for confirmations that never came.
RECHECK_SECONDS = 15


class Awaiting:
    """The messages sent on this connection and not yet confirmed: queue row
    id by the message id on the wire (a command acknowledgment's is the
    command's, so several rows can share one)."""

    def __init__(self, clock=time.monotonic):
        self.enabled = False
        self._clock = clock
        self._by_wire: Dict[str, List[str]] = {}
        self._sent: Dict[str, Tuple[str, float]] = {}
        self._next_check = 0.0

    def server_says(self, registration: dict) -> None:
        """``registration_success`` tells whether this server confirms.  One
        that does not (an older server) will never confirm what was sent
        before it said so: let those go back to pending now."""
        self.enabled = bool((registration or {}).get(FLAG))
        if not self.enabled:
            self.reset()

    def sent(self, wire_id: Optional[str], queue_id: str) -> bool:
        """Track ``queue_id`` until confirmed; False when it cannot be (no
        confirmation, or no id to be confirmed by) -- delete it on write."""
        if not self.enabled or not wire_id:
            return False
        self._by_wire.setdefault(str(wire_id), []).append(queue_id)
        self._sent[queue_id] = (str(wire_id), self._clock())
        return True

    def confirmed(self, wire_id: Optional[str]) -> List[str]:
        """The queue rows ``wire_id`` confirms (none: not ours, or already)."""
        rows = self._by_wire.pop(str(wire_id), []) if wire_id else []
        for queue_id in rows:
            self._sent.pop(queue_id, None)
        return rows

    def overdue(self) -> List[str]:
        """Rows sent longer than the timeout ago, forgotten here so they can
        be sent again."""
        cutoff = self._clock() - CONFIRM_TIMEOUT_SECONDS
        late = [q for q, (_wire, at) in self._sent.items() if at <= cutoff]
        self._forget(late)
        return late

    def due_for_check(self) -> bool:
        now = self._clock()
        if now < self._next_check:
            return False
        self._next_check = now + RECHECK_SECONDS
        return True

    def tracked(self) -> List[str]:
        return list(self._sent)

    def reset(self) -> None:
        """A new connection: nothing sent on the old one will be confirmed."""
        self._by_wire.clear()
        self._sent.clear()

    def _forget(self, queue_ids: List[str]) -> None:
        for queue_id in queue_ids:
            wire_id, _at = self._sent.pop(queue_id)
            rows = self._by_wire.get(wire_id, [])
            if queue_id in rows:
                rows.remove(queue_id)
            if not rows:
                self._by_wire.pop(wire_id, None)
