"""
This module is the main entry point for the SysManage agent that will run
on all clients.  It connects back to the server and communicates
bidirectionally over WebSockets.
"""
import asyncio
import websockets

async def handler(websocket):
    while True:
        message = await websocket.recv()
        print(message)

async def main():
    url = "ws://api.sysmanage.com:6443/agent/connect"
    async with websockets.connect(url) as ws:
        await handler(ws)
        await asyncio.Future()

if __name__ == "__main__":
    asyncio.run(main())