"""
This module is the main entry point for the SysManage agent that will run
on all clients.  It connects back to the server and communicates
bidirectionally over WebSockets.
"""
from time import sleep
from websockets.sync.client import connect

if __name__ == "__main__":
    with connect("wss://api.sysmanage.org:6443/agent/connect") as websocket:
        while True:
            sleep(5)
            websocket.send("Hello world!")
            message = websocket.recv()
            print(f"Received: {message}")
