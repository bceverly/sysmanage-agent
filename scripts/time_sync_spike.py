#!/usr/bin/env python3
# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""Phase 23.3 S0 spike: can the server measure a host's clock offset itself?

Standard library only, so it runs unchanged on Linux, the BSDs, macOS and
Windows.  Three modes:

  server   plays the SysManage server on one machine.
  client   plays the agent: runs the NTP-style four-timestamp exchange with
           the server, holding each reply a RANDOM time between receive and
           send to stand in for the agent's persistent outbound queue, and
           measures ground truth independently (both machines' SNTP offset
           against the same public reference).
  services prints the host's own time-service status, raw, for parser
           fixtures.

The question the spike answers: stamping at the socket edges only (t1 server
send, t2 agent receive, t3 agent send, t4 server receive), does

    offset = ((t2 - t1) + (t3 - t4)) / 2      delay = (t4 - t1) - (t3 - t2)

recover the true offset to well inside the 1 s warning bound -- over Wi-Fi,
with queue residence between t2 and t3 -- so the product can measure every
clock without trusting the host's own time service?

    python3 time_sync_spike.py server --port 47123
    python3 time_sync_spike.py client --server 192.168.4.20:47123 --rounds 30
    python3 time_sync_spike.py services
"""

import argparse
import json
import platform
import random
import shutil
import socket
import statistics
import struct
import subprocess  # nosec B404 -- fixed, absolute-path commands only
import sys
import time

REFERENCE = "time.cloudflare.com"
NTP_EPOCH = 2208988800  # seconds from 1900 to 1970


def sntp_offset(server=REFERENCE, tries=4):
    """This machine's offset from ``server`` (reference - local), seconds,
    median of ``tries`` SNTP queries -- the independent ground truth."""
    results = []
    for _ in range(tries):
        packet = b"\x23" + 47 * b"\0"  # LI=0, VN=4, mode=3 (client)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(3)
            t1 = time.time()
            sock.sendto(packet, (server, 123))
            data, _ = sock.recvfrom(512)
            t4 = time.time()
        if len(data) < 48:
            continue
        recv_s, recv_f, tx_s, tx_f = struct.unpack("!IIII", data[32:48])
        t2 = recv_s - NTP_EPOCH + recv_f / 2**32
        t3 = tx_s - NTP_EPOCH + tx_f / 2**32
        results.append(((t2 - t1) + (t3 - t4)) / 2)
        time.sleep(0.2)
    return statistics.median(results) if results else None


def _send(conn, obj):
    conn.sendall((json.dumps(obj) + "\n").encode())


def _recv(stream):
    line = stream.readline()
    return json.loads(line) if line else None


def serve(port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as lsock:
        lsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        lsock.bind(("0.0.0.0", port))  # nosec B104 -- lab spike only
        lsock.listen()
        print(f"spike server on :{port}", flush=True)
        while True:
            conn, addr = lsock.accept()
            with conn, conn.makefile("r") as stream:
                hello = _recv(stream)
                rounds = hello["rounds"]
                samples = []
                for _ in range(rounds):
                    t1 = time.time()
                    _send(conn, {"t1": t1})  # t1 stamped at the socket edge
                    reply = _recv(stream)
                    t4 = time.time()  # stamped on arrival, before any queue
                    offset = ((reply["t2"] - t1) + (reply["t3"] - t4)) / 2
                    delay = (t4 - t1) - (reply["t3"] - reply["t2"])
                    samples.append(
                        {
                            "offset": offset,
                            "delay": delay,
                            "held": reply["t3"] - reply["t2"],
                        }
                    )
                truth_server = sntp_offset()
                _send(conn, {"samples": samples, "server_sntp": truth_server})
                print(f"{addr[0]}: {rounds} rounds", flush=True)


def client(server, rounds, max_hold):
    host, port = server.rsplit(":", 1)
    truth_client = sntp_offset()
    with socket.create_connection((host, int(port)), timeout=30) as conn, conn.makefile(
        "r"
    ) as stream:
        _send(conn, {"rounds": rounds})
        for _ in range(rounds):
            msg = _recv(stream)
            t2 = time.time()  # stamped on receipt
            # Queue residence: the real agent sends its reply with the NEXT
            # heartbeat, seconds later.  The formula must not care.
            time.sleep(random.uniform(0, max_hold))  # nosec B311 -- not crypto
            t3 = time.time()  # stamped as it leaves
            _send(conn, {"t1": msg["t1"], "t2": t2, "t3": t3})
        result = _recv(stream)
    samples = result["samples"]
    offsets = [s["offset"] for s in samples]
    delays = [s["delay"] for s in samples]
    # Ground truth: client - server = (ref - server) - (ref - client).
    truth = None
    if truth_client is not None and result["server_sntp"] is not None:
        truth = result["server_sntp"] - truth_client
    measured = statistics.median(offsets)
    report = {
        "host": socket.gethostname(),
        "os": f"{platform.system()} {platform.release()}",
        "rounds": rounds,
        "max_hold_s": max_hold,
        "measured_offset_ms": round(measured * 1000, 3),
        "truth_offset_ms": None if truth is None else round(truth * 1000, 3),
        "error_ms": None if truth is None else round((measured - truth) * 1000, 3),
        "offset_spread_ms": round((max(offsets) - min(offsets)) * 1000, 3),
        "delay_median_ms": round(statistics.median(delays) * 1000, 3),
        "delay_max_ms": round(max(delays) * 1000, 3),
        "worst_single_error_ms": (
            None
            if truth is None
            else round(max(abs(o - truth) for o in offsets) * 1000, 3)
        ),
    }
    print(json.dumps(report, indent=1))


# What each OS's own time service says about itself.  Absolute paths are
# resolved with shutil.which so a non-login PATH (NetBSD, cron) still finds
# /usr/sbin tools.
SERVICE_COMMANDS = [
    ["chronyc", "-n", "tracking"],
    ["chronyc", "-n", "sources"],
    ["ntpq", "-n", "-c", "rv"],
    ["ntpq", "-n", "-p"],
    ["ntpctl", "-s", "status"],
    ["ntpctl", "-s", "peers"],
    ["timedatectl", "show-timesync", "--all"],
    ["timedatectl", "show"],
    ["w32tm", "/query", "/status"],
    ["w32tm", "/query", "/source"],
    ["systemsetup", "-getusingnetworktime"],
    ["sntp", REFERENCE],
]


def _which(name):
    found = shutil.which(name)
    if found:
        return found
    for directory in (
        "/usr/sbin",
        "/sbin",
        "/usr/bin",
        "/usr/local/sbin",
        "/usr/local/bin",
    ):
        candidate = f"{directory}/{name}"
        if shutil.which(candidate):
            return candidate
    return None


def services():
    print(f"# {socket.gethostname()} {platform.system()} {platform.release()}")
    for command in SERVICE_COMMANDS:
        path = _which(command[0])
        if path is None:
            continue
        try:
            out = subprocess.run(  # nosec B603 -- fixed argv, resolved path
                [path, *command[1:]],
                capture_output=True,
                text=True,
                timeout=20,
                check=False,
            )
            text = (out.stdout + out.stderr).strip()
            print(f"\n$ {' '.join(command)}   (rc={out.returncode})\n{text}")
        except (OSError, subprocess.TimeoutExpired) as exc:
            print(f"\n$ {' '.join(command)}   FAILED: {exc}")


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = parser.add_subparsers(dest="mode", required=True)
    s = sub.add_parser("server")
    s.add_argument("--port", type=int, default=47123)
    c = sub.add_parser("client")
    c.add_argument("--server", required=True)
    c.add_argument("--rounds", type=int, default=30)
    c.add_argument("--max-hold", type=float, default=2.0)
    sub.add_parser("services")
    args = parser.parse_args()
    if args.mode == "server":
        serve(args.port)
    elif args.mode == "client":
        client(args.server, args.rounds, args.max_hold)
    else:
        services()
    return 0


if __name__ == "__main__":
    sys.exit(main())
