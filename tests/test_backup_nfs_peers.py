# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""Hosts behind NAT (25.8): the reach check reports its own end of the
connection and holds it open on request, and the storage host lists who it
sees on its NFS port, read without privileges."""

# pylint: disable=protected-access

import asyncio
from unittest.mock import patch

from src.sysmanage_agent.backup import nfs_peers
from src.sysmanage_agent.backup import storage_reach
from src.sysmanage_agent.communication import message_handler_queue
from src.sysmanage_agent.core import capabilities, capability_probes

# Lines from nas's /proc/net/tcp (2026-11-06): its two NFS clients, a
# listening socket and an ssh session.
PROC_TCP = """\
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:0801 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1 1
   1: 0A04A8C0:0801 6D04A8C0:029A 01 00000000:00000000 00:00000000 00000000     0        0 0 2
   2: 0A04A8C0:0801 0B04A8C0:02A1 01 00000000:00000000 00:00000000 00000000     0        0 0 2
   3: 0A04A8C0:0016 8404A8C0:AA94 01 00000000:00000000 00:00000000 00000000     0        0 3 1
"""
# An IPv4 client on the IPv6 socket, as ::ffff:192.168.4.50 port 1000.
PROC_TCP6 = """\
  sl  local_address                         remote_address                        st
   0: 0000000000000000FFFF00000A04A8C0:0801 0000000000000000FFFF00003204A8C0:03E8 01
"""
NETSTAT = """\
Active Internet connections (including servers)
Proto     Recv-Q Send-Q Local Address          Foreign Address        (state)
tcp4           0      0 192.168.4.212.2049     192.168.4.11.818       ESTABLISHED
tcp4           0     72 192.168.4.212.22       192.168.4.132.43700    ESTABLISHED
tcp6           0      0 *.2049                 *.*                    LISTEN
"""


def test_linux_lists_only_established_connections_to_port_2049():
    assert nfs_peers.linux_peers(PROC_TCP, PROC_TCP6) == [
        {"address": "192.168.4.109", "port": 666},
        {"address": "192.168.4.11", "port": 673},
        {"address": "192.168.4.50", "port": 1000},
    ]


def test_freebsd_lists_them_from_netstat():
    assert nfs_peers.bsd_peers(NETSTAT) == [{"address": "192.168.4.11", "port": 818}]


def test_peers_reads_the_platform_table_and_refuses_elsewhere():
    files = {"/proc/net/tcp": PROC_TCP, "/proc/net/tcp6": ""}
    found = nfs_peers.peers("Linux", read=files.get)
    assert found["success"] and len(found["peers"]) == 2
    assert nfs_peers.peers("FreeBSD", netstat=lambda: NETSTAT)["peers"] == [
        {"address": "192.168.4.11", "port": 818}]  # fmt: skip
    assert nfs_peers.peers("Darwin") == {"success": False, "peers": [],
                                         "error": "wrong_platform"}  # fmt: skip
    assert nfs_peers.unavailable_reason(None, "Darwin") == "wrong_platform"
    assert nfs_peers.unavailable_reason(None, "FreeBSD") is None


def test_it_is_its_own_capability_and_runs_in_the_express_lane():
    assert capabilities.CAPABILITY_GROUPS["backup_peers"] == ("list_nfs_peers",)
    assert "list_nfs_peers" in capability_probes._REASONED_LOCATORS
    assert message_handler_queue.is_express(
        {"data": {"command_type": "list_nfs_peers"}}
    )


class _Writer:
    def __init__(self, sockname=("192.168.122.133", 818)):
        self.closed_at = None
        self.sockname = sockname

    def get_extra_info(self, name):
        return self.sockname if name == "sockname" else None

    def close(self):
        self.closed_at = asyncio.get_running_loop().time()

    async def wait_closed(self):
        return None


def test_the_answer_names_this_end_of_the_connection():
    writer = _Writer()

    async def connect(_host, _port):
        return None, writer

    answer = asyncio.run(storage_reach.check({"address": "192.168.4.10"}, connect))
    assert (answer["local_address"], answer["local_port"]) == ("192.168.122.133", 818)
    assert writer.closed_at is not None  # not held: closed at once


def test_a_held_connection_stays_open_that_long_then_closes():
    writer = _Writer()

    async def connect(_host, _port):
        return None, writer

    async def scenario():
        start = asyncio.get_running_loop().time()
        answer = await storage_reach.check(
            {"address": "192.168.4.10", "hold_seconds": 1}, connect
        )
        assert answer["reachable"] and writer.closed_at is None  # answered, still open
        await asyncio.gather(*storage_reach._HELD)
        return writer.closed_at - start

    held = asyncio.run(scenario())
    assert 0.9 <= held < 3


def test_a_hold_is_bounded_and_only_a_whole_number():
    assert (
        storage_reach._hold_seconds({"hold_seconds": 10_000})
        == storage_reach.MAX_HOLD_SECONDS
    )
    for bad in (True, "60", -5, 0, None, 1.5):
        assert storage_reach._hold_seconds({"hold_seconds": bad}) == 0
    with patch.object(storage_reach, "MAX_HOLD_SECONDS", 7):
        assert storage_reach._hold_seconds({"hold_seconds": 60}) == 7
