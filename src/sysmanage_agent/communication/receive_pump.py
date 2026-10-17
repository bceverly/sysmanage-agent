# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""
Read the websocket independently of handling what it delivers.

The clock measurement (Phase 23.3) needs t2 -- when a server message ARRIVED.
The receive loop used to call ``recv()`` only after the previous message had
been handled, so while a slow handler ran, the next message waited in the
library's buffer and its t2 was stamped late.  That wait counted as network
delay on the server-to-agent leg, so a busy agent looked like a clock running
ahead: 2026-10-17, during an antivirus deploy, a host read +4.03 s with an
8.06 s round trip -- the offset was exactly half the delay -- while its own
time service was synchronized to the millisecond.

A reader task now does nothing but ``recv()`` and stamp, handing each frame
to the dispatcher through a queue, so arrival time is arrival time whatever
the dispatcher is doing.  Order is preserved: one reader, one consumer.
"""

from __future__ import annotations

import asyncio
import time
from typing import Any, Optional, Tuple

import websockets

Frame = Tuple[Any, float, float]  # (raw message, wall t2, monotonic t2)


async def read_frames(agent, inbox: "asyncio.Queue[Frame]", on_cleared) -> None:
    """Receive until the agent stops; ConnectionClosed (or any other error)
    propagates to whoever awaits this task."""
    while agent.running:
        # A concurrent disconnect can clear the websocket between reads:
        # surface it as a closed connection, not an AttributeError on None.
        ws = agent.websocket
        if ws is None:
            on_cleared()
            raise websockets.ConnectionClosed(None, None)
        message = await ws.recv()
        # Stamped before parsing and before any handling (see module doc).
        inbox.put_nowait((message, time.time(), time.monotonic()))


async def next_frame(
    inbox: "asyncio.Queue[Frame]", reader: "asyncio.Task[None]"
) -> Optional[Frame]:
    """The next received frame, in order.  When the reader has ended, any
    frames it queued first are still returned; after them its exception is
    raised, or None when it stopped normally (the agent is shutting down)."""
    if not inbox.empty():
        return inbox.get_nowait()
    if reader.done():
        reader.result()  # re-raises ConnectionClosed or the error
        return None
    getter = asyncio.ensure_future(inbox.get())
    done, _ = await asyncio.wait({getter, reader}, return_when=asyncio.FIRST_COMPLETED)
    if getter in done:
        return getter.result()
    getter.cancel()
    if not inbox.empty():
        return inbox.get_nowait()
    reader.result()
    return None
