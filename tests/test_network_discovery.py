# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""Passive network discovery (Phase 21.6 S1).

What fails silently if got wrong:

  * an unreadable neighbor cache must read as NOT MEASURED (None), never as an
    empty network ([]);
  * macOS prints MACs without leading zeros -- unpadded, the server drops them;
  * an mDNS/SSDP sighting heard over a plain socket has no MAC; the cache must
    supply it (and its interface), or the device can never be matched;
  * container / VM plumbing must not be reported as the operator's network;
  * the agent must stay OFF until the server turns it on, and stay off across
    a restart if it was turned off.
"""

import json
import socket
import struct
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.sysmanage_agent.collection import network_discovery_collection as nd
from src.sysmanage_agent.collection import network_neighbor_cache as cache
from src.sysmanage_agent.operations import network_discovery_operations as ops

# --------------------------------------------------------------------------
# neighbor cache
# --------------------------------------------------------------------------


class TestNeighborCache:
    def test_linux_json_skips_failed_and_incomplete(self):
        text = json.dumps(
            [
                {
                    "dst": "10.0.0.1",
                    "dev": "eth0",
                    "lladdr": "aa:bb:cc:00:00:01",
                    "state": ["REACHABLE"],
                },
                {"dst": "10.0.0.2", "dev": "eth0", "state": ["FAILED"]},
                {
                    "dst": "10.0.0.3",
                    "dev": "eth0",
                    "lladdr": "aa:bb:cc:00:00:03",
                    "state": ["INCOMPLETE"],
                },
            ]
        )
        assert cache.parse_ip_neigh_json(text) == [
            {"ip": "10.0.0.1", "mac": "aa:bb:cc:00:00:01", "interface": "eth0"}
        ]

    def test_a_stale_old_address_comes_after_the_confirmed_new_one(self):
        # A DHCP renumber: the old address lingers as STALE for the same MAC.
        text = json.dumps(
            [
                {"dst": "10.0.0.22", "dev": "eth0", "lladdr": "aa:bb:cc:00:00:16",
                 "state": ["STALE"]},
                {"dst": "10.0.0.21", "dev": "eth0", "lladdr": "aa:bb:cc:00:00:15",
                 "state": ["DELAY"]},
                {"dst": "10.0.0.23", "dev": "eth0", "lladdr": "aa:bb:cc:00:00:16",
                 "state": ["REACHABLE"]},
            ]
        )  # fmt: skip
        # DELAY too: a sweep just touched it, and it has not answered yet.
        assert [r["ip"] for r in cache.parse_ip_neigh_json(text)] == [
            "10.0.0.23",
            "10.0.0.22",
            "10.0.0.21",
        ]

    def test_bsd_pads_macos_octets_and_accepts_linux_arp(self):
        text = (
            "? (192.168.4.1) at 0:1a:2b:3:4:5 on en0 ifscope [ethernet]\n"
            "? (10.0.0.2) at aa:bb:cc:dd:ee:ff [ether] on eth0\n"
            "? (10.0.0.3) at (incomplete) on eth0\n"
        )
        assert cache.parse_bsd_arp(text) == [
            {"ip": "192.168.4.1", "mac": "00:1a:2b:03:04:05", "interface": "en0"},
            {"ip": "10.0.0.2", "mac": "aa:bb:cc:dd:ee:ff", "interface": "eth0"},
        ]

    def test_windows_skips_static_pseudo_neighbors(self):
        text = (
            "Interface: 192.168.4.132 --- 0xb\n"
            "  Internet Address      Physical Address      Type\n"
            "  192.168.4.1           aa-bb-cc-dd-ee-ff     dynamic\n"
            "  192.168.4.255         ff-ff-ff-ff-ff-ff     static\n"
        )
        assert cache.parse_windows_arp(text) == [
            {
                "ip": "192.168.4.1",
                "mac": "aa-bb-cc-dd-ee-ff",
                "interface": "192.168.4.132",
            }
        ]

    def test_no_tool_is_not_measured_rather_than_empty(self):
        with patch.object(
            cache.platform, "system", return_value="NetBSD"
        ), patch.object(cache, "_binary", return_value=None):
            assert cache.read_neighbor_cache() is None

    def test_a_failing_command_is_not_measured(self):
        with patch.object(
            cache.platform, "system", return_value="FreeBSD"
        ), patch.object(cache, "_binary", return_value="/usr/sbin/arp"), patch.object(
            cache, "_run", return_value=None
        ):
            assert cache.read_neighbor_cache() is None


# --------------------------------------------------------------------------
# wire parsing
# --------------------------------------------------------------------------

MAC_A = bytes.fromhex("001a2b3c4d5e")


def _eth(src, ethertype, body):
    return b"\xff" * 6 + src + struct.pack("!H", ethertype) + body


def _arp(sender_ip):
    return (
        struct.pack("!HHBBH", 1, 0x0800, 6, 4, 1)
        + MAC_A
        + socket.inet_aton(sender_ip)
        + b"\x00" * 6
        + socket.inet_aton("10.0.0.1")
    )


def _udp(src_ip, sport, dport, payload):
    ip = (
        bytes([0x45, 0])
        + struct.pack("!H", 28 + len(payload))
        + b"\x00" * 5
        + bytes([17])
        + b"\x00\x00"
    )
    ip += socket.inet_aton(src_ip) + socket.inet_aton("224.0.0.251")
    return ip + struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload


def _mdns_answer():
    def name(*labels):
        return b"".join(bytes([len(x)]) + x.encode() for x in labels) + b"\x00"

    return struct.pack("!HHHHHH", 0, 0x8400, 0, 1, 0, 0) + name("_ipp", "_tcp", "local")


def _listener():
    listener = nd._PacketListener.__new__(nd._PacketListener)
    listener.sink = nd._Accumulator()
    return listener


class TestWire:
    def test_arp_sender_is_recorded_with_its_ip(self):
        listener = _listener()
        listener._frame(_eth(MAC_A, 0x0806, _arp("10.0.0.9")), "eth0")
        devices, _ = listener.sink.drain()
        row = devices["00:1a:2b:3c:4d:5e"]
        assert row["ips"] == ["10.0.0.9"] and row["methods"] == {"arp_listen"}

    def test_an_address_probe_has_a_mac_but_no_ip(self):
        listener = _listener()
        listener._frame(_eth(MAC_A, 0x0806, _arp("0.0.0.0")), "eth0")  # nosec B104
        devices, _ = listener.sink.drain()
        assert devices["00:1a:2b:3c:4d:5e"]["ips"] == []

    def test_mdns_answer_yields_its_service_type(self):
        listener = _listener()
        listener._frame(
            _eth(MAC_A, 0x0800, _udp("10.0.0.9", 5353, 5353, _mdns_answer())), "eth0"
        )
        devices, _ = listener.sink.drain()
        assert devices["00:1a:2b:3c:4d:5e"]["mdns"] == ["_ipp._tcp"]

    def test_ssdp_evidence_keeps_server_and_type(self):
        payload = b"NOTIFY * HTTP/1.1\r\nNT: urn:x:device:Printer:1\r\nSERVER: Acme/1.0\r\nHOST: x\r\n\r\n"
        assert nd.ssdp_evidence(payload) == [
            "NT: urn:x:device:Printer:1",
            "SERVER: Acme/1.0",
        ]

    def test_ipv6_neighbor_solicitation_is_noted(self):
        body = bytearray(64)
        body[6] = 58  # next header ICMPv6
        body[8:24] = socket.inet_pton(socket.AF_INET6, "fe80::21a:2bff:fe3c:4d5e")
        body[40] = 135  # neighbor solicitation
        listener = _listener()
        listener._frame(_eth(MAC_A, 0x86DD, bytes(body)), "eth0")
        devices, _ = listener.sink.drain()
        assert devices["00:1a:2b:3c:4d:5e"]["methods"] == {"nd_listen"}


class TestInterfacesAndBounds:
    @pytest.mark.parametrize(
        "name", ["docker0", "veth12ab", "virbr0", "tun0", "lo", "br-3f2a", "wg0"]
    )
    def test_plumbing_is_skipped(self, name):
        assert nd.skipped_interface(name)

    @pytest.mark.parametrize("name", ["eth0", "wlp0s20f3", "en0", "Ethernet 2", "igb0"])
    def test_real_interfaces_are_kept(self, name):
        assert not nd.skipped_interface(name)

    def test_the_accumulator_is_bounded_and_says_so(self):
        sink = nd._Accumulator()
        with patch.object(nd, "MAX_DEVICES", 2):
            for i in range(3):
                sink.note(str(i), str(i), None, "eth0", "arp_listen")
        devices, overflowed = sink.drain()
        assert len(devices) == 2 and overflowed


class TestCacheMerge:
    IFACES = [
        {
            "name": "Ethernet 2",
            "mac": "aa-bb-cc-00-11-22",
            "ip": "192.168.4.132",
            "prefix": 24,
        }
    ]

    def test_an_ip_only_sighting_gets_its_mac_and_interface_from_the_cache(self):
        devices = {"ip:192.168.4.9": {"mac": None, "ips": ["192.168.4.9"], "interface": None,
                                      "methods": {"mdns"}, "count": 1, "mdns": ["_ipp._tcp"], "ssdp": []}}  # fmt: skip
        rows = [
            {
                "ip": "192.168.4.9",
                "mac": "00-1A-2B-3C-4D-5E",
                "interface": "192.168.4.132",
            }
        ]
        nd._merge_cache(devices, rows, self.IFACES)
        (device,) = devices.values()
        assert device["mac"] == "00:1a:2b:3c:4d:5e"
        assert device["interface"] == "Ethernet 2"  # Windows labels by IP; mapped back
        assert device["methods"] == {"mdns", "cache"}
        assert device["mdns"] == ["_ipp._tcp"]

    def test_ip_only_sightings_of_ourselves_or_off_subnet_are_dropped(self):
        # Found live: our own SSDP loops back, and an LXD bridge's multicast
        # reaches a socket bound to every address.
        def row(ip):
            return {"mac": None, "ips": [ip], "interface": None, "methods": {"ssdp"},
                    "count": 1, "mdns": [], "ssdp": []}  # fmt: skip

        devices = {"ip:192.168.4.132": row("192.168.4.132"), "ip:10.49.179.1": row("10.49.179.1"),
                   "ip:192.168.4.20": row("192.168.4.20")}  # fmt: skip
        nd._merge_cache(devices, [], self.IFACES)
        assert list(devices) == ["ip:192.168.4.20"]
        assert devices["ip:192.168.4.20"]["interface"] == "Ethernet 2"

    def test_cache_rows_on_skipped_interfaces_are_ignored(self):
        devices = {}
        nd._merge_cache(
            devices,
            [{"ip": "172.17.0.2", "mac": "02:42:ac:11:00:02", "interface": "docker0"}],
            self.IFACES,
        )
        assert devices == {}

    def test_snapshot_reports_blind_spots_and_resets(self):
        collector = nd.NetworkDiscoveryCollector()
        collector._methods = {
            "arp_listen": nd.NOT_ROOT,
            "sweep": "unavailable:disabled",
        }
        collector.sink.note(
            "00:1a:2b:3c:4d:5e", "00:1a:2b:3c:4d:5e", "10.0.0.9", "eth0", "arp_listen"
        )
        ifaces = [
            {"name": "eth0", "mac": "aa:bb:cc:00:11:22", "ip": "10.0.0.5", "prefix": 24}
        ]
        with patch.object(nd, "local_interfaces", return_value=ifaces), patch.object(
            nd, "read_neighbor_cache", return_value=None
        ):
            report = collector.snapshot()
            again = collector.snapshot()
        assert report["methods"]["cache"] == nd.UNREADABLE
        assert report["methods"]["arp_listen"] == nd.NOT_ROOT
        assert [o["mac"] for o in report["observations"]] == ["00:1a:2b:3c:4d:5e"]
        assert again["observations"] == []

    def test_without_root_linux_says_why_arp_is_unavailable(self):
        fake = MagicMock(sockets={"mdns": object()})
        collector = nd.NetworkDiscoveryCollector()
        with patch.object(nd.platform, "system", return_value="Linux"), patch.object(
            nd, "_is_root", return_value=False
        ), patch.object(nd, "_MulticastListener", return_value=fake), patch.object(
            nd, "local_interfaces", return_value=[]
        ):
            methods = collector.start()
        assert methods["arp_listen"] == nd.NOT_ROOT
        assert methods["mdns"] == nd.OK and methods["ssdp"] == nd.PORT_IN_USE
        assert methods["sweep"] == "unavailable:disabled"
        fake.start.assert_called_once()


# --------------------------------------------------------------------------
# operations
# --------------------------------------------------------------------------


@pytest.fixture
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    return tmp_path


def _ops(collector=None):
    agent = MagicMock()
    agent.registration_manager.get_host_approval_from_db.return_value = SimpleNamespace(
        host_id="h-1"
    )
    agent.create_message.side_effect = lambda kind, data: {
        "message_type": kind,
        "data": data,
    }
    agent.send_message = AsyncMock(return_value=True)
    collector = collector or MagicMock(running=True)
    collector.start.return_value = {"arp_listen": "ok"}
    collector.snapshot.return_value = {"observations": [{"mac": "00:1a:2b:3c:4d:5e"}]}
    return ops.NetworkDiscoveryOperations(agent, collector=collector)


class TestOperations:
    def test_off_until_the_server_says_otherwise(self, home):
        operations = _ops()
        operations.load_persisted()
        assert not operations.enabled
        operations.collector.start.assert_not_called()

    @pytest.mark.asyncio
    async def test_enabling_starts_listening_and_survives_a_restart(self, home):
        operations = _ops()
        reply = await operations.configure_network_discovery(
            {"enabled": True, "report_interval_seconds": 5}
        )
        assert reply["enabled"] and reply["methods"] == {"arp_listen": "ok"}
        assert reply["report_interval_seconds"] == ops.MIN_INTERVAL_SECONDS  # clamped
        restarted = _ops()
        restarted.load_persisted()
        assert restarted.enabled and restarted.interval == ops.MIN_INTERVAL_SECONDS
        restarted.collector.start.assert_called_once()

    @pytest.mark.asyncio
    async def test_disabling_stops_and_stays_off_after_a_restart(self, home):
        operations = _ops()
        await operations.configure_network_discovery({"enabled": True})
        await operations.configure_network_discovery({"enabled": False})
        operations.collector.stop.assert_called()
        restarted = _ops()
        restarted.load_persisted()
        assert not restarted.enabled

    def test_a_corrupt_state_file_means_off(self, home):
        ops.state_path().parent.mkdir(parents=True)
        ops.state_path().write_text("{not json", encoding="utf-8")
        operations = _ops()
        operations.load_persisted()
        assert not operations.enabled

    @pytest.mark.asyncio
    async def test_a_report_carries_the_host_and_goes_out(self, home):
        operations = _ops()
        assert await operations.send_report()
        message = operations.agent.send_message.call_args[0][0]
        assert message["message_type"] == "network_discovery_report"
        assert message["data"]["host_id"] == "h-1"

    @pytest.mark.asyncio
    async def test_no_approval_no_report(self, home):
        operations = _ops()
        operations.agent.registration_manager.get_host_approval_from_db.return_value = (
            None
        )
        assert not await operations.send_report()
        operations.agent.send_message.assert_not_called()

    def test_the_command_advertises_the_capability(self):
        from src.sysmanage_agent.core.capabilities import (
            command_to_group,
        )  # noqa: PLC0415

        assert command_to_group()["configure_network_discovery"] == "network_discovery"


# --------------------------------------------------------------------------
# active sweep (S4)
# --------------------------------------------------------------------------

from src.sysmanage_agent.collection import network_sweep as sweep  # noqa: E402

IFACES = [
    {"name": "wlan0", "mac": "aa:bb:cc:00:11:22", "ip": "192.168.4.132", "prefix": 24}
]


class TestSweep:
    def test_only_an_own_on_link_ipv4_network_may_be_swept(self):
        assert sweep.check("192.168.4.0/24", IFACES) == {
            "cidr": "192.168.4.0/24", "interface": "wlan0", "reason": None,
        }  # fmt: skip
        assert sweep.check("10.0.0.0/24", IFACES)["reason"] == "not_on_link"
        assert (
            sweep.check("192.168.4.0/25", IFACES)["reason"] == "not_on_link"
        )  # not EXACTLY ours
        assert sweep.check("fd00::/64", IFACES)["reason"] == "ipv6_not_supported"
        assert (
            sweep.check("10.0.0.0/16", [dict(IFACES[0], ip="10.0.0.5", prefix=16)])[
                "reason"
            ]
            == "too_large"
        )
        assert sweep.check("junk", IFACES)["reason"] == "invalid_network"

    def test_the_rate_is_clamped_never_exceeded(self):
        assert (sweep.clamp_rate(5000), sweep.clamp_rate(0), sweep.clamp_rate("x")) == (
            200,
            1,
            50,
        )

    def test_every_address_but_our_own_is_probed_at_the_rate(self):
        hits, naps = [], []
        sent = sweep.sweep(
            "10.0.0.0/29", 100, "10.0.0.3", sender=hits.append, sleeper=naps.append
        )
        assert sent == 5 and "10.0.0.3" not in hits and len(hits) == 5
        assert naps[:5] == [0.01] * 5  # paced
        assert naps[-1] == sweep._SETTLE_SECONDS

    def test_only_neighbors_inside_the_range_are_reported(self):
        cache = [
            {"ip": "192.168.4.9", "mac": "00-1A-2B-3C-4D-5E", "interface": "wlan0"},
            {"ip": "10.9.9.9", "mac": "00:1a:2b:00:00:09", "interface": "wlan0"},
        ]
        found = sweep.observations_in("192.168.4.0/24", "wlan0", cache)
        assert [o["mac"] for o in found] == ["00:1a:2b:3c:4d:5e"]
        assert found[0]["methods"] == ["sweep"]
        # An unreadable cache is a FAILED sweep, not an empty network.
        with patch.object(sweep, "read_neighbor_cache", return_value=None):
            assert sweep.observations_in("192.168.4.0/24", "wlan0") is None


class TestSweepCommand:
    def _ops(self):
        operations = _ops()
        operations.enabled = True
        operations.collector.methods = {"arp_listen": "ok"}
        return operations

    def _reported(self, operations):
        return operations.agent.send_message.call_args[0][0]["data"]

    @pytest.mark.asyncio
    async def test_a_refusal_is_reported_so_the_run_closes(self, home):
        operations = self._ops()
        with patch.object(ops, "local_interfaces", return_value=IFACES):
            reply = await operations.run_network_sweep(
                {"run_id": "r1", "cidr": "10.0.0.0/24", "rate": 50}
            )
        assert reply["status"] == "refused" and reply["reason"] == "not_on_link"
        data = self._reported(operations)
        assert data["sweep"] == {
            "run_id": "r1",
            "cidr": "10.0.0.0/24",
            "status": "refused",
            "probed": 0,
            "reason": "not_on_link",
        }
        assert data["observations"] == []

    @pytest.mark.asyncio
    async def test_a_completed_sweep_reports_what_it_found(self, home):
        operations = self._ops()
        found = [
            {
                "mac": "00:1a:2b:3c:4d:5e",
                "ips": ["192.168.4.9"],
                "interface": "wlan0",
                "methods": ["sweep"],
                "count": 1,
            }
        ]
        with patch.object(ops, "local_interfaces", return_value=IFACES), patch.object(
            ops.network_sweep, "sweep", return_value=253
        ) as probe, patch.object(
            ops.network_sweep, "observations_in", return_value=found
        ):
            reply = await operations.run_network_sweep(
                {"run_id": "r2", "cidr": "192.168.4.0/24", "rate": 9999}
            )
        assert reply == {"success": True, "run_id": "r2", "status": "completed"}
        assert probe.call_args[0] == (
            "192.168.4.0/24",
            200,
            "192.168.4.132",
        )  # rate clamped, own IP skipped
        data = self._reported(operations)
        assert data["sweep"]["status"] == "completed" and data["sweep"]["probed"] == 253
        assert data["observations"] == found
        assert data["methods"] == {"arp_listen": "ok", "sweep": "ok"}
        assert operations._sweeping is False

    @pytest.mark.asyncio
    async def test_not_while_discovery_is_off_or_already_sweeping(self, home):
        operations = self._ops()
        operations.enabled = False
        with patch.object(ops, "local_interfaces", return_value=IFACES):
            off = await operations.run_network_sweep(
                {"run_id": "r3", "cidr": "192.168.4.0/24"}
            )
            operations.enabled, operations._sweeping = True, True
            busy = await operations.run_network_sweep(
                {"run_id": "r4", "cidr": "192.168.4.0/24"}
            )
        assert (off["reason"], busy["reason"]) == ("discovery_disabled", "busy")

    def test_the_sweep_command_is_advertised(self):
        from src.sysmanage_agent.core.capabilities import (
            command_to_group,
        )  # noqa: PLC0415

        assert command_to_group()["run_network_sweep"] == "network_discovery"


class TestBridgeSkipping:
    """S5: found live -- a custom-named libvirt bridge (smdisc1) was listened
    on because only NAME prefixes were checked."""

    def _sysfs(self, tmp_path, bridge, ports):
        for port, physical in ports.items():
            (tmp_path / port).mkdir(parents=True, exist_ok=True)
            if physical:
                (tmp_path / port / "device").mkdir()
        (tmp_path / bridge / "brif").mkdir(parents=True)
        for port in ports:
            (tmp_path / bridge / "brif" / port).mkdir()
        return str(tmp_path)

    def test_a_bridge_of_only_taps_is_plumbing_whatever_its_name(self, tmp_path):
        sysfs = self._sysfs(tmp_path, "smdisc1", {"vnet5": False, "vnet6": False})
        assert nd.virtual_only_bridge("smdisc1", sysfs)

    def test_a_bridge_over_a_real_nic_is_the_lan(self, tmp_path):
        sysfs = self._sysfs(tmp_path, "br0", {"eth0": True, "vnet1": False})
        assert not nd.virtual_only_bridge("br0", sysfs)

    def test_an_ordinary_interface_is_not_a_bridge(self, tmp_path):
        (tmp_path / "eth0" / "device").mkdir(parents=True)
        assert not nd.virtual_only_bridge("eth0", str(tmp_path))

    def test_skipping_uses_the_bridge_rule_and_caches_it(self):
        nd._bridge_cache.clear()
        with patch.object(nd.platform, "system", return_value="Linux"), patch.object(
            nd, "virtual_only_bridge", return_value=True
        ) as probe:
            assert nd.skipped_interface("smdisc1") and nd.skipped_interface("smdisc1")
        assert probe.call_count == 1  # cached: this runs for every captured frame
        nd._bridge_cache.clear()


# --------------------------------------------------------------------------
# BPF capture on the BSDs and macOS (S6)
# --------------------------------------------------------------------------

from src.sysmanage_agent.collection import network_bpf as bpf  # noqa: E402

ARP_FRAME = _eth(MAC_A, 0x0806, _arp("10.0.0.9"))


def _bpf_buffer(frames, stamp, alignment, pad_header=0):
    """Records exactly as the kernel lays them out on a given platform."""
    out = b""
    for frame in frames:
        hdrlen = stamp + 10 + pad_header
        record = b"\x00" * stamp + struct.pack("=IIH", len(frame), len(frame), hdrlen)
        record += b"\x00" * (hdrlen - len(record)) + frame
        out += record + b"\x00" * (bpf._align(len(record), alignment) - len(record))
    return out


class TestBpf:
    @pytest.mark.parametrize(
        "system,stamp,alignment",
        [("Darwin", 8, 4), ("OpenBSD", 8, 4), ("FreeBSD", 16, 8), ("NetBSD", 16, 8)],
    )
    def test_each_platforms_header_layout(self, system, stamp, alignment):
        with patch.object(bpf.struct, "calcsize", return_value=8):  # a 64-bit long
            assert bpf.layout(system) == (stamp, alignment)
        # Two frames of awkward lengths so the alignment padding matters.
        frames = [ARP_FRAME, ARP_FRAME[:43]]
        buffer = _bpf_buffer(frames, stamp, alignment, pad_header=2)
        assert list(bpf.records(buffer, stamp, alignment)) == frames

    def test_the_wrong_layout_does_not_silently_yield_the_frames(self):
        buffer = _bpf_buffer([ARP_FRAME], 16, 8)
        assert list(bpf.records(buffer, 8, 4)) != [ARP_FRAME]

    def test_a_malformed_record_stops_the_walk(self):
        assert list(bpf.records(b"\x00" * 64, 8, 4)) == []

    def test_a_busy_unit_is_skipped_and_the_interface_bound(self):
        tried = []

        def opener(path, _flags):
            tried.append(path)
            if path == "/dev/bpf":
                raise FileNotFoundError(path)
            if path == "/dev/bpf0":
                raise OSError(16, "busy")
            return 99

        with patch("fcntl.ioctl", return_value=struct.pack("I", 4096)) as ioctl:
            assert bpf.open_device("em0", opener) == (99, 4096)
        assert tried == ["/dev/bpf", "/dev/bpf0", "/dev/bpf1"]
        assert ioctl.call_args_list[0][0][1] == bpf.BIOCSETIF
        assert ioctl.call_args_list[0][0][2].startswith(b"em0\x00")

    def test_the_module_imports_without_fcntl(self):
        # Windows has no fcntl; the collector imports this module everywhere,
        # so a top-level import crashed the agent at startup on Windows.
        import builtins
        import importlib

        real_import = builtins.__import__

        def no_fcntl(name, *args, **kwargs):
            if name == "fcntl":
                raise ImportError("No module named 'fcntl'")
            return real_import(name, *args, **kwargs)

        with patch.object(builtins, "__import__", no_fcntl):
            importlib.reload(bpf)
        importlib.reload(bpf)

    def test_own_frames_are_dropped_and_others_parsed(self):
        seen = []
        listener = bpf.BpfListener.__new__(bpf.BpfListener)
        listener.parse = lambda frame, iface: seen.append((frame[6:12].hex(":"), iface))
        listener.stamp, listener.alignment = 8, 4
        listener.own_macs = {"aa:bb:cc:00:11:22"}
        mine = _eth(bytes.fromhex("aabbcc001122"), 0x0806, _arp("10.0.0.5"))
        listener._drain(_bpf_buffer([mine, ARP_FRAME], 8, 4), "en0")
        assert seen == [("00:1a:2b:3c:4d:5e", "en0")]

    def test_a_bsd_agent_running_as_root_captures_with_bpf(self):
        fake = MagicMock()
        collector = nd.NetworkDiscoveryCollector()
        with patch.object(nd.platform, "system", return_value="FreeBSD"), patch.object(
            nd, "_is_root", return_value=True
        ), patch.object(nd, "BpfListener", return_value=fake) as made, patch.object(
            nd, "local_interfaces", return_value=[]
        ):
            methods = collector.start()
        assert methods["arp_listen"] == nd.OK and made.called
        fake.start.assert_called_once()

    @pytest.mark.parametrize(
        "system,reason",
        [
            ("Darwin", "unavailable:not_root"),
            ("Windows", "unavailable:unsupported_platform"),
        ],
    )
    def test_without_capture_the_reason_is_accurate(self, system, reason):
        collector = nd.NetworkDiscoveryCollector()
        with patch.object(nd.platform, "system", return_value=system), patch.object(
            nd, "_is_root", return_value=False
        ), patch.object(
            nd, "_MulticastListener", return_value=MagicMock(sockets={})
        ), patch.object(
            nd, "local_interfaces", return_value=[]
        ):
            assert collector.start()["arp_listen"] == reason
