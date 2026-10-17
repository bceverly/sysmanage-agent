# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""Frames are stamped when they ARRIVE, not when the dispatcher gets to them.

2026-10-17: during an antivirus deploy a host read +4.03 s with an 8.06 s
round trip -- the next server message waited behind a slow handler and its
t2 was stamped late, so the wait counted as network delay."""

import asyncio
import time
from types import SimpleNamespace

import pytest
import websockets

from src.sysmanage_agent.communication import receive_pump


class FakeSocket:
    def __init__(self):
        self.frames: asyncio.Queue = asyncio.Queue()

    async def recv(self):
        item = await self.frames.get()
        if isinstance(item, Exception):
            raise item
        return item


def _agent(ws):
    return SimpleNamespace(running=True, websocket=ws)


@pytest.mark.asyncio
async def test_a_frame_is_stamped_while_the_previous_one_is_still_handled():
    ws = FakeSocket()
    inbox: asyncio.Queue = asyncio.Queue()
    reader = asyncio.create_task(
        receive_pump.read_frames(_agent(ws), inbox, lambda: None)
    )
    ws.frames.put_nowait("first")
    first = await receive_pump.next_frame(inbox, reader)
    assert first[0] == "first"
    # The dispatcher is busy with "first" for 0.3 s; "second" arrives meanwhile.
    arrived = time.time()
    ws.frames.put_nowait("second")
    await asyncio.sleep(0.3)
    second = await receive_pump.next_frame(inbox, reader)
    assert second[0] == "second"
    assert second[1] - arrived < 0.1  # stamped on arrival, not 0.3 s later
    reader.cancel()


@pytest.mark.asyncio
async def test_order_is_preserved():
    ws = FakeSocket()
    inbox: asyncio.Queue = asyncio.Queue()
    reader = asyncio.create_task(
        receive_pump.read_frames(_agent(ws), inbox, lambda: None)
    )
    for name in ("a", "b", "c"):
        ws.frames.put_nowait(name)
    got = [(await receive_pump.next_frame(inbox, reader))[0] for _ in range(3)]
    assert got == ["a", "b", "c"]
    reader.cancel()


@pytest.mark.asyncio
async def test_frames_queued_before_a_close_are_still_delivered_then_it_raises():
    ws = FakeSocket()
    inbox: asyncio.Queue = asyncio.Queue()
    reader = asyncio.create_task(
        receive_pump.read_frames(_agent(ws), inbox, lambda: None)
    )
    ws.frames.put_nowait("last words")
    ws.frames.put_nowait(websockets.ConnectionClosed(None, None))
    await asyncio.sleep(0.05)
    assert (await receive_pump.next_frame(inbox, reader))[0] == "last words"
    with pytest.raises(websockets.ConnectionClosed):
        await receive_pump.next_frame(inbox, reader)


@pytest.mark.asyncio
async def test_a_cleared_websocket_is_a_closed_connection():
    cleared = []
    agent = SimpleNamespace(running=True, websocket=None)
    inbox: asyncio.Queue = asyncio.Queue()
    reader = asyncio.create_task(
        receive_pump.read_frames(agent, inbox, lambda: cleared.append(True))
    )
    with pytest.raises(websockets.ConnectionClosed):
        await receive_pump.next_frame(inbox, reader)
    assert cleared == [True]


@pytest.mark.asyncio
async def test_a_stopped_agent_ends_quietly():
    agent = SimpleNamespace(running=False, websocket=FakeSocket())
    inbox: asyncio.Queue = asyncio.Queue()
    reader = asyncio.create_task(receive_pump.read_frames(agent, inbox, lambda: None))
    assert await receive_pump.next_frame(inbox, reader) is None
