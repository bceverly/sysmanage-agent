# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""Passive ARP / IPv6 neighbor listening on Linux needs a raw socket, not
root.  The packaged agent runs as an unprivileged user and its systemd unit
grants CAP_NET_RAW (AmbientCapabilities), so the agent tests by opening the
AF_PACKET socket; the BSDs and macOS still need root for a BPF device.
Before this every packaged Linux agent reported "the agent is not running as
root" (production, 2026-10-16)."""

import configparser
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from src.sysmanage_agent.collection import network_discovery_collection as nd

ROOT = Path(__file__).resolve().parents[1]
LINUX_UNITS = sorted(ROOT.glob("installer/*/sysmanage-agent.service"))


def _start(system, root, packet=None, bpf=None):
    collector = nd.NetworkDiscoveryCollector()
    with patch.object(nd.platform, "system", return_value=system), patch.object(
        nd, "_is_root", return_value=root
    ), patch.object(
        nd, "_PacketListener", **(packet or {"return_value": MagicMock()})
    ) as packet_listener, patch.object(
        nd, "BpfListener", **(bpf or {"return_value": MagicMock()})
    ) as bpf_listener, patch.object(
        nd, "_MulticastListener", return_value=MagicMock(sockets={})
    ), patch.object(
        nd, "local_interfaces", return_value=[]
    ):
        methods = collector.start()
    return methods, packet_listener, bpf_listener


def test_an_unprivileged_linux_agent_with_the_capability_listens():
    methods, packet, _ = _start("Linux", root=False)
    assert packet.called
    assert methods["arp_listen"] == nd.OK and methods["nd_listen"] == nd.OK


def test_root_on_linux_still_listens():
    methods, packet, _ = _start("Linux", root=True)
    assert packet.called and methods["arp_listen"] == nd.OK


def test_without_the_capability_linux_says_why():
    methods, _, _ = _start(
        "Linux", root=False, packet={"side_effect": PermissionError("EPERM")}
    )
    assert methods["arp_listen"] == nd.NOT_ROOT
    assert methods["nd_listen"] == nd.NOT_ROOT


def test_another_socket_failure_falls_back_too():
    methods, _, _ = _start(
        "Linux", root=True, packet={"side_effect": OSError("no such device")}
    )
    assert methods["arp_listen"] == nd.NOT_ROOT


@pytest.mark.parametrize("system", ["FreeBSD", "OpenBSD", "NetBSD", "Darwin"])
def test_bsd_and_macos_still_need_root_and_do_not_try_bpf(system):
    methods, _, bpf = _start(system, root=False)
    assert not bpf.called
    assert methods["arp_listen"] == nd.NOT_ROOT


def test_the_linux_units_were_found():
    assert {p.parent.name for p in LINUX_UNITS} >= {"ubuntu", "centos", "opensuse"}


@pytest.mark.parametrize("unit", LINUX_UNITS, ids=lambda p: p.parent.name)
def test_every_unprivileged_linux_unit_grants_only_cap_net_raw(unit):
    parser = configparser.ConfigParser(strict=False, interpolation=None)
    parser.optionxform = str
    parser.read(unit, encoding="utf-8")
    service = parser["Service"]
    assert service.get("User") != "root"
    assert service.get("AmbientCapabilities") == "CAP_NET_RAW"
    # A bounding set would cap every sudo command the agent runs as well.
    assert "CapabilityBoundingSet" not in service
    # sudo cannot escalate under NoNewPrivileges.
    assert service.get("NoNewPrivileges", "no").lower() not in ("yes", "true", "1")
