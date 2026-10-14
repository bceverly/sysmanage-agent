# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""
Hardware events in real time (Phase 23.1 S3): listen where the operating
system announces hardware problems, and report at once.

``collection/hardware_events.py`` turns each platform's source (the Linux
kernel log, FreeBSD's devd, the Windows System log) into evidence lines.
This loop runs that source on a worker thread and, on the first match:

* waits ``DEBOUNCE`` seconds for the rest of the burst -- a failing disk
  rarely says one thing -- de-duplicating identical lines;
* sends at most one triggered report per ``MIN_GAP`` seconds, still
  gathering while it waits (a storm of I/O errors is ONE report, with its
  first ``MAX_EVIDENCE`` distinct lines);
* re-collects the hardware health and sends it with the evidence, changed or
  not, ahead of the queue (``_send_hardware_health_update(evidence=...)``).

The sources need privilege (``/dev/kmsg`` and devd are root's; the System
log is an administrator's), so an unprivileged agent keeps the periodic
report and says so once.  The loop outlives a reconnect only as long as the
connection's other background tasks: it is started and cancelled with them.
"""

from __future__ import annotations

import asyncio
import logging
import threading
import time
from typing import Awaitable, Callable, Dict, List, Optional, Tuple

from src.i18n import _
from src.sysmanage_agent.collection import hardware_events

logger = logging.getLogger(__name__)

DEBOUNCE = 5.0
MIN_GAP = 60.0
MAX_EVIDENCE = 20

Sender = Callable[..., Awaitable[None]]


class HardwareEventLoop:
    """Listen, gather, send."""

    def __init__(  # pylint: disable=too-many-arguments,too-many-positional-arguments
        self,
        send: Sender,
        privileged: Callable[[], bool],
        source: Optional[Tuple[str, hardware_events.LineSource]] = None,
        debounce: float = DEBOUNCE,
        min_gap: float = MIN_GAP,
        clock: Callable[[], float] = time.monotonic,
    ):
        self._send = send
        self._privileged = privileged
        self._source = source
        self._debounce = debounce
        self._min_gap = min_gap
        self._clock = clock
        self._last_sent: Optional[float] = None

    @classmethod
    def for_agent(cls, agent) -> "HardwareEventLoop":
        """The loop for a running agent: its data collector sends, and the
        sources need it privileged."""
        # pylint: disable-next=import-outside-toplevel  # agent_utils imports a lot
        from src.sysmanage_agent.core.agent_utils import is_running_privileged

        # pylint: disable-next=protected-access
        return cls(
            agent.data_collector._send_hardware_health_update, is_running_privileged
        )

    async def run(self) -> None:
        found = self._source or hardware_events.source_for()
        if found is None:
            return  # no event source on this platform: the periodic report
        name, reader = found
        if not self._privileged():
            logger.info(
                _("Hardware events from %s need a privileged agent; "
                  "the periodic report continues"),
                name,
            )  # fmt: skip
            return
        queue: "asyncio.Queue[Dict[str, str]]" = asyncio.Queue()
        stop = threading.Event()
        pump = asyncio.ensure_future(
            asyncio.to_thread(_pump, reader, stop, asyncio.get_running_loop(), queue)
        )
        logger.info(_("Listening for hardware events (%s)"), name)
        try:
            while True:
                first = await queue.get()
                if "error" in first:
                    logger.warning(
                        _("Hardware event source %s stopped: %s"), name, first["error"]
                    )
                    return
                await self._send(evidence=await self._gather(queue, first))
                self._last_sent = self._clock()
        finally:
            stop.set()
            pump.cancel()

    async def _gather(self, queue, first: Dict[str, str]) -> List[Dict[str, str]]:
        """The burst that started with ``first``: distinct lines, until the
        debounce has passed AND the minimum gap since the last send."""
        batch: List[Dict[str, str]] = []
        seen = set()

        def add(event: Dict[str, str]) -> None:
            if "error" in event or event.get("text") in seen:
                return
            seen.add(event.get("text"))
            if len(batch) < MAX_EVIDENCE:
                batch.append(event)

        add(first)
        deadline = self._clock() + self._debounce
        if self._last_sent is not None:
            deadline = max(deadline, self._last_sent + self._min_gap)
        while (remaining := deadline - self._clock()) > 0:
            try:
                add(await asyncio.wait_for(queue.get(), timeout=remaining))
            except asyncio.TimeoutError:
                break
        return batch


def _pump(reader, stop: threading.Event, loop, queue) -> None:
    """Worker thread: feed the source's evidence into the event loop."""
    try:
        for event in reader(stop.is_set):
            loop.call_soon_threadsafe(queue.put_nowait, event)
    except Exception as exc:  # pylint: disable=broad-exception-caught
        if not stop.is_set():
            loop.call_soon_threadsafe(queue.put_nowait, {"error": str(exc)})
