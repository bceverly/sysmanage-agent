# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""Can this host reach its backup storage? A TCP connection to the NFS port
of the address the server sent, and nothing else."""

# pylint: disable=protected-access

import asyncio

import pytest

from src.sysmanage_agent.backup import storage_reach
from src.sysmanage_agent.communication import message_handler_queue
from src.sysmanage_agent.core import capabilities, capability_probes


class _Writer:
    def __init__(self):
        self.closed = False

    def close(self):
        self.closed = True

    async def wait_closed(self):
        return None


def _check(address, connect, timeout=1.0):
    return asyncio.run(storage_reach.check({"address": address}, connect, timeout))


def test_a_reachable_storage_host_is_connected_to_and_let_go():
    seen, writer = [], _Writer()

    async def connect(host, port):
        seen.append((host, port))
        return None, writer

    answer = _check("192.168.4.10", connect)
    assert answer == {"success": True, "reachable": True, "address": "192.168.4.10",
                      "port": 2049, "error": None}  # fmt: skip
    assert seen == [("192.168.4.10", 2049)] and writer.closed


def test_a_refused_or_unrouted_connection_is_unreachable():
    async def refused(_host, _port):
        raise ConnectionRefusedError(111, "Connection refused")

    answer = _check("nas.lab", refused)
    assert answer["success"] is True and answer["reachable"] is False
    assert answer["error"] == "Connection refused"


def test_no_answer_in_time_is_unreachable():
    async def hangs(_host, _port):
        await asyncio.sleep(10)

    answer = _check("192.168.4.10", hangs, timeout=0.05)
    assert answer["reachable"] is False and answer["error"] == "timeout"


@pytest.mark.parametrize(
    "address",
    [None, "", "http://nas", "nas:2049", "nas;rm -rf /", "-nas", 12, "a" * 300],
)
def test_only_an_ip_or_a_host_name_is_tried(address):
    async def never(_host, _port):
        raise AssertionError("must not connect")

    answer = _check(address, never)
    assert answer["success"] is False and answer["error"] == "invalid_address"


def test_ipv6_and_names_are_valid():
    assert storage_reach.valid_address("fd00::10")
    assert storage_reach.valid_address("nas.theeverlys.com")


def test_every_agent_but_windows_can_check():
    assert storage_reach.unavailable_reason(None, "Linux") is None
    assert storage_reach.unavailable_reason(None, "FreeBSD") is None
    assert storage_reach.unavailable_reason(None, "Windows") == "wrong_platform"


def test_the_check_is_its_own_capability_and_runs_in_the_express_lane():
    assert capabilities.CAPABILITY_GROUPS["backup_reach"] == ("check_backup_storage",)
    assert "check_backup_storage" in capability_probes._REASONED_LOCATORS
    assert message_handler_queue.is_express(
        {"data": {"command_type": "check_backup_storage"}}
    )
