# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""Device hostnames for network discovery (ROADMAP, 2026-10-17).

What fails silently if got wrong:

  * a name the device is LOOKING FOR (an mDNS known answer, an LLMNR or
    NetBIOS query) shown as the name it HAS -- every laptop would be called
    after the printer it prints to;
  * a Bonjour sleep proxy answering for a sleeping Mac given the Mac's name;
  * a DHCP name keyed by anything but the client's chaddr (a DISCOVER comes
    from 0.0.0.0), or a RELAYED request's client -- on another segment --
    reported as being on this one;
  * a malformed packet raising out of a parser and killing the capture thread;
  * reverse DNS (active) running without the operator's opt-in.
"""

import random
import socket
import struct
from unittest.mock import MagicMock

import pytest

from src.sysmanage_agent.collection import network_discovery_collection as nd
from src.sysmanage_agent.collection import network_names as names
from src.sysmanage_agent.operations import network_discovery_operations as ops

SRC = "192.168.4.20"
OTHER = "192.168.4.99"
MAC = "00:1a:2b:3c:4d:5e"

# --------------------------------------------------------------------------
# packet builders
# --------------------------------------------------------------------------


def _name(text):
    out = b""
    for label in text.split("."):
        raw = label.encode()
        out += bytes([len(raw)]) + raw
    return out + b"\x00"


def _rr(owner, rtype, rdata, owner_wire=None):
    wire = owner_wire if owner_wire is not None else _name(owner)
    return wire + struct.pack("!HHIH", rtype, 1, 120, len(rdata)) + rdata


def _a(ip):
    return socket.inet_aton(ip)


def _srv(target):
    return struct.pack("!HHH", 0, 0, 631) + _name(target)


def _dns(flags, answers=(), additional=(), questions=(), authority=()):
    header = struct.pack(
        "!HHHHHH", 0, flags, len(questions), len(answers), len(authority),
        len(additional),
    )  # fmt: skip
    body = b"".join(_name(q) + struct.pack("!HH", 255, 1) for q in questions)
    return (
        header + body + b"".join(answers) + b"".join(authority) + b"".join(additional)
    )


RESPONSE = 0x8400  # QR + AA, as mDNS responders send


def _netbios_encode(name, suffix=0x00):
    raw = name.upper().ljust(15).encode()[:15] + bytes([suffix])
    return "".join(chr(65 + (b >> 4)) + chr(65 + (b & 0x0F)) for b in raw)


def _netbios(name, opcode=5, response=False, group=False, ip=SRC, suffix=0x00):
    flags = (opcode << 11) | 0x0110 | (0x8000 if response else 0)
    question = _name(_netbios_encode(name, suffix)) + struct.pack("!HH", 0x20, 1)
    nb_flags = 0x8000 if group else 0
    rdata = struct.pack("!H", nb_flags) + _a(ip)
    additional = b"\xc0\x0c" + struct.pack("!HHIH", 0x20, 1, 300000, 6) + rdata
    return struct.pack("!HHHHHH", 1, flags, 1, 0, 0, 1) + question + additional


def _dhcp(options, msg_type=1, chaddr=MAC, ciaddr="0.0.0.0", op=1):
    head = struct.pack("!BBBB", op, 1, 6, 0) + b"\x00" * 8
    head += _a(ciaddr) + b"\x00" * 12
    head += bytes.fromhex(chaddr.replace(":", "")) + b"\x00" * 10
    head += b"\x00" * 192 + b"\x63\x82\x53\x63"
    opts = bytes([53, 1, msg_type])
    for code, value in options:
        opts += bytes([code, len(value)]) + value
    return head + opts + b"\xff"


# --------------------------------------------------------------------------
# mDNS
# --------------------------------------------------------------------------


class TestMdns:
    def test_a_record_for_the_senders_own_address(self):
        packet = _dns(RESPONSE, answers=[_rr("brother-hl.local", 1, _a(SRC))])
        assert names.mdns_names(packet, SRC) == ["brother-hl.local"]

    def test_an_address_record_for_someone_else_is_not_the_senders_name(self):
        # A known answer in a query, or a sleep proxy: another device's record.
        packet = _dns(0, questions=["_ipp._tcp.local"],
                      answers=[_rr("other.local", 1, _a(OTHER))])  # fmt: skip
        assert names.mdns_names(packet, SRC) == []

    def test_aaaa_record(self):
        v6 = "fe80::21a:2bff:fe3c:4d5e"
        packet = _dns(
            RESPONSE,
            answers=[_rr("tv.local", 28, socket.inet_pton(socket.AF_INET6, v6))],
        )
        assert names.mdns_names(packet, v6) == ["tv.local"]

    def test_reverse_ptr_for_the_senders_address(self):
        owner = ".".join(reversed(SRC.split("."))) + ".in-addr.arpa"
        packet = _dns(RESPONSE, answers=[_rr(owner, 12, _name("nas.local"))])
        assert names.mdns_names(packet, SRC) == ["nas.local"]

    def test_reverse_ptr_for_another_address_is_ignored(self):
        owner = ".".join(reversed(OTHER.split("."))) + ".in-addr.arpa"
        packet = _dns(RESPONSE, answers=[_rr(owner, 12, _name("nas.local"))])
        assert names.mdns_names(packet, SRC) == []

    def test_service_ptr_instance_names_are_not_host_names(self):
        packet = _dns(RESPONSE, answers=[
            _rr("_ipp._tcp.local", 12, _name("Brother HL-L2350DW._ipp._tcp.local"))
        ])  # fmt: skip
        assert names.mdns_names(packet, SRC) == []

    def test_srv_target_with_compression(self):
        # SRV target "printer.local" points back at the owner's ".local".
        owner = _name("Printer._ipp._tcp.local")
        local_at = 12 + len(_name("Printer._ipp._tcp"))  # ".local" label offset
        target = b"\x07printer" + struct.pack("!H", 0xC000 | (local_at - 1))
        rdata = struct.pack("!HHH", 0, 0, 631) + target
        packet = _dns(RESPONSE, answers=[_rr(None, 33, rdata, owner_wire=owner)])
        assert names.mdns_names(packet, SRC) == ["printer.local"]

    def test_srv_and_a_together_give_one_name(self):
        packet = _dns(RESPONSE, answers=[_rr("P._ipp._tcp.local", 33, _srv("printer.local"))],
                      additional=[_rr("printer.local", 1, _a(SRC))])  # fmt: skip
        assert names.mdns_names(packet, SRC) == ["printer.local"]

    def test_sleep_proxy_srv_for_a_sleeping_mac_is_not_the_proxys_name(self):
        packet = _dns(RESPONSE,
                      answers=[_rr("Mac._smb._tcp.local", 33, _srv("macbook.local"))],
                      additional=[_rr("macbook.local", 1, _a(OTHER))])  # fmt: skip
        assert names.mdns_names(packet, SRC) == []

    def test_srv_in_a_query_is_ignored(self):
        packet = _dns(0, answers=[_rr("P._ipp._tcp.local", 33, _srv("printer.local"))])
        assert names.mdns_names(packet, SRC) == []

    def test_pointer_loop_does_not_hang(self):
        # One answer whose owner name is a pointer to itself.
        packet = (
            struct.pack("!HHHHHH", 0, RESPONSE, 0, 1, 0, 0) + b"\xc0\x0c" + b"\x00" * 10
        )
        assert names.mdns_names(packet, SRC) == []


# --------------------------------------------------------------------------
# LLMNR, NetBIOS
# --------------------------------------------------------------------------


class TestLlmnr:
    def test_response_naming_the_sender(self):
        packet = _dns(
            0x8000, questions=["desktop-7"], answers=[_rr("desktop-7", 1, _a(SRC))]
        )
        assert names.llmnr_names(packet, SRC) == ["desktop-7"]

    def test_a_query_is_what_the_sender_looks_for(self):
        assert names.llmnr_names(_dns(0, questions=["wpad"]), SRC) == []


class TestNetbios:
    def test_workstation_registration(self):
        assert names.netbios_names(_netbios("DESKTOP-7"), SRC) == ["DESKTOP-7"]

    def test_refresh_counts_too(self):
        assert names.netbios_names(_netbios("DESKTOP-7", opcode=8), SRC) == [
            "DESKTOP-7"
        ]

    def test_group_names_are_workgroups(self):
        assert names.netbios_names(_netbios("WORKGROUP", group=True), SRC) == []

    def test_domain_suffixes_are_not_hosts(self):
        assert names.netbios_names(_netbios("CORP", suffix=0x1C), SRC) == []

    def test_a_query_or_a_reply_is_not_a_registration(self):
        assert names.netbios_names(_netbios("PRINTER", opcode=0), SRC) == []
        assert names.netbios_names(_netbios("DESKTOP-7", response=True), SRC) == []

    def test_registration_for_another_address_is_ignored(self):
        assert names.netbios_names(_netbios("DESKTOP-7", ip=OTHER), SRC) == []


# --------------------------------------------------------------------------
# DHCP
# --------------------------------------------------------------------------


class TestDhcp:
    def test_discover_host_name_keyed_by_chaddr(self):
        out = names.dhcp_client_names(_dhcp([(12, b"brians-iphone")]))
        assert out == {"mac": MAC, "ip": None, "names": [("brians-iphone", "dhcp")]}

    def test_request_fqdn_ascii_and_host_name(self):
        fqdn = bytes([0x01, 0, 0]) + b"laptop.corp.example"
        out = names.dhcp_client_names(
            _dhcp([(81, fqdn), (12, b"laptop")], msg_type=3, ciaddr="192.168.4.30")
        )
        assert out["ip"] == "192.168.4.30"
        assert out["names"] == [
            ("laptop.corp.example", "dhcp_fqdn"),
            ("laptop", "dhcp"),
        ]

    def test_fqdn_in_dns_wire_encoding(self):
        fqdn = bytes([0x05, 0, 0]) + _name("laptop.corp.example")
        out = names.dhcp_client_names(_dhcp([(81, fqdn)]))
        assert out["names"] == [("laptop.corp.example", "dhcp_fqdn")]

    def test_server_replies_and_releases_are_ignored(self):
        assert names.dhcp_client_names(_dhcp([(12, b"x")], op=2)) is None
        assert names.dhcp_client_names(_dhcp([(12, b"x")], msg_type=7)) is None

    def test_a_relayed_request_is_from_another_segment(self):
        packet = bytearray(_dhcp([(12, b"far-away")]))
        packet[24:28] = _a("10.9.0.1")  # giaddr
        assert names.dhcp_client_names(bytes(packet)) is None

    def test_no_name_no_result(self):
        assert names.dhcp_client_names(_dhcp([])) is None

    def test_truncated_option_is_dropped_whole(self):
        packet = _dhcp([(12, b"laptop")])[:-4]
        assert names.dhcp_client_names(packet) is None


# --------------------------------------------------------------------------
# hostile input
# --------------------------------------------------------------------------


class TestMalformed:
    @pytest.mark.parametrize(
        "parser",
        [
            lambda p: names.mdns_names(p, SRC),
            lambda p: names.llmnr_names(p, SRC),
            lambda p: names.netbios_names(p, SRC),
            names.dhcp_client_names,
        ],
    )
    def test_garbage_and_every_truncation_never_raise(self, parser):
        samples = [
            _dns(RESPONSE, answers=[_rr("tv.local", 1, _a(SRC))],
                 additional=[_rr("P._ipp._tcp.local", 33, _srv("tv.local"))]),
            _netbios("DESKTOP-7"),
            _dhcp([(81, bytes([5, 0, 0]) + _name("a.b")), (12, b"host")]),
        ]  # fmt: skip
        rng = random.Random(1987)
        for sample in samples:
            for cut in range(len(sample)):
                parser(sample[:cut])
            for _ in range(300):
                mutated = bytearray(sample)
                for _ in range(rng.randint(1, 8)):
                    mutated[rng.randrange(len(mutated))] = rng.randrange(256)
                parser(bytes(mutated))
        for _ in range(300):
            parser(bytes(rng.randrange(256) for _ in range(rng.randint(0, 600))))

    def test_record_count_bomb_is_refused(self):
        packet = struct.pack("!HHHHHH", 0, RESPONSE, 0, 0xFFFF, 0, 0)
        assert names.mdns_names(packet, SRC) == []

    @pytest.mark.parametrize(
        "value",
        ["", "localhost", "192.168.4.20", "has space", "a/b", "x" * 300, "bad\x01"],
    )
    def test_clean_name_refuses(self, value):
        assert names.clean_name(value) is None


# --------------------------------------------------------------------------
# the collector
# --------------------------------------------------------------------------


def _frame(src_mac, src_ip, sport, dport, payload, dst_ip="255.255.255.255"):
    udp = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload
    ip = struct.pack("!BBHHHBBH", 0x45, 0, 20 + len(udp), 0, 0, 64, 17, 0)
    ip += socket.inet_aton(src_ip) + socket.inet_aton(dst_ip)
    eth = b"\xff" * 6 + bytes.fromhex(src_mac.replace(":", "")) + b"\x08\x00"
    return eth + ip + udp


def _only(sink):
    devices, _overflowed = sink.drain()
    return devices


class TestCollector:
    def test_dhcp_is_keyed_by_chaddr_not_the_frame_source(self):
        sink = nd._Accumulator()
        other_nic = "00:aa:bb:cc:dd:ee"
        nd.parse_frame(
            sink, _frame(other_nic, "0.0.0.0", 68, 67, _dhcp([(12, b"phone")])), "eth0"
        )
        devices = _only(sink)
        assert list(devices) == [MAC]
        row = devices[MAC]
        assert row["methods"] == {"dhcp"} and row["ips"] == []
        assert [(h["name"], h["source"]) for h in row["hostnames"]] == [
            ("phone", "dhcp")
        ]
        assert row["hostnames"][0]["seen_at"].endswith("Z")

    def test_mdns_netbios_llmnr_frames(self):
        sink = nd._Accumulator()
        mdns = _dns(RESPONSE, answers=[_rr("tv.local", 1, _a(SRC))])
        llmnr = _dns(
            0x8000, questions=["desktop-7"], answers=[_rr("desktop-7", 1, _a(SRC))]
        )
        nd.parse_frame(sink, _frame(MAC, SRC, 5353, 5353, mdns, "224.0.0.251"), "eth0")
        nd.parse_frame(sink, _frame(MAC, SRC, 137, 137, _netbios("DESKTOP-7")), "eth0")
        nd.parse_frame(sink, _frame(MAC, SRC, 5355, 50000, llmnr, OTHER), "eth0")
        row = _only(sink)[MAC]
        assert row["methods"] == {"mdns", "netbios", "llmnr"}
        assert [(h["name"], h["source"]) for h in row["hostnames"]] == [
            ("tv.local", "mdns"), ("DESKTOP-7", "netbios"), ("desktop-7", "llmnr"),
        ]  # fmt: skip

    def test_a_netbios_query_is_not_a_sighting(self):
        sink = nd._Accumulator()
        nd.parse_frame(
            sink, _frame(MAC, SRC, 137, 137, _netbios("PRINTER", opcode=0)), "eth0"
        )
        assert _only(sink) == {}

    def test_garbage_frames_never_raise(self):
        sink = nd._Accumulator()
        rng = random.Random(7)
        for port in (67, 68, 137, 5353, 5355):
            for _ in range(200):
                junk = bytes(rng.randrange(256) for _ in range(rng.randint(0, 400)))
                nd.parse_frame(sink, _frame(MAC, SRC, port, port, junk), "eth0")

    def test_names_are_bounded_and_repeats_move_seen_at(self):
        hostnames = []
        nd.note_names(hostnames, [("a", "dhcp")], "2026-10-17T00:00:00Z")
        nd.note_names(hostnames, [("A", "dhcp")], "2026-10-17T01:00:00Z")
        nd.note_names(hostnames, [("a", "mdns")], "2026-10-17T01:00:00Z")
        assert hostnames == [
            {"name": "a", "source": "dhcp", "seen_at": "2026-10-17T01:00:00Z"},
            {"name": "a", "source": "mdns", "seen_at": "2026-10-17T01:00:00Z"},
        ]
        nd.note_names(hostnames, [(f"h{i}", "dhcp") for i in range(50)], "t")
        assert len(hostnames) == nd.MAX_HOSTNAMES

    def test_observation_carries_hostnames_and_fold_merges_them(self):
        into = {
            "mac": MAC,
            "ips": [],
            "methods": {"cache"},
            "count": 1,
            "mdns": [],
            "ssdp": [],
            "ssdp_searches": [],
            "hostnames": [],
            "interface": "eth0",
        }
        other = dict(
            into,
            methods={"mdns"},
            hostnames=[{"name": "tv.local", "source": "mdns", "seen_at": "t"}],
        )
        nd._fold(into, other)  # fmt: skip
        assert nd._observation(into)["hostnames"] == [
            {"name": "tv.local", "source": "mdns", "seen_at": "t"}
        ]


# --------------------------------------------------------------------------
# reverse DNS: active, behind the opt-in only
# --------------------------------------------------------------------------


class TestReverseNames:
    def test_rate_limited_cached_and_bounded(self):
        calls, sleeps = [], []

        def resolver(ip):
            calls.append(ip)
            return (
                "host-" + ip.replace(".", "-") + ".lan." if ip != "10.0.0.3" else None
            )

        reverse = names.ReverseNames(resolver=resolver, sleeper=sleeps.append)
        found = reverse.lookup(["10.0.0.1", "10.0.0.2", "10.0.0.3"])
        assert found == {
            "10.0.0.1": "host-10-0-0-1.lan",
            "10.0.0.2": "host-10-0-0-2.lan",
        }
        assert sleeps == [0.1, 0.1]
        reverse.lookup(["10.0.0.1", "10.0.0.3"])
        assert calls == ["10.0.0.1", "10.0.0.2", "10.0.0.3"]  # answers remembered
        many = [f"10.1.{i // 256}.{i % 256}" for i in range(200)]
        reverse.lookup(many)
        assert len(calls) == 3 + names.PTR_MAX_PER_REPORT

    def test_a_hung_resolver_is_abandoned(self, monkeypatch):
        monkeypatch.setattr(names, "PTR_TIMEOUT_SECONDS", 0.05)
        import threading

        gate = threading.Event()
        reverse = names.ReverseNames(resolver=lambda ip: gate.wait(5) and "late")
        assert reverse.lookup(["10.0.0.1"]) == {}
        gate.set()

    def _collector(self):
        collector = nd.NetworkDiscoveryCollector()
        collector._reverse = MagicMock()
        collector._reverse.lookup.return_value = {"192.168.4.9": "printer.lan"}
        collector.sink.note(MAC, MAC, "fe80::1", "eth0", "nd_listen")
        collector.sink.note(MAC, MAC, "192.168.4.9", "eth0", "arp_listen")
        named = "00:1a:2b:3c:4d:5f"
        collector.sink.note(named, named, "192.168.4.8", "eth0", "mdns",
                            names=[("tv.local", "mdns")])  # fmt: skip
        return collector

    def _snapshot(self, collector, monkeypatch):
        monkeypatch.setattr(nd, "read_neighbor_cache", lambda: [])
        monkeypatch.setattr(nd, "local_interfaces", lambda: [])
        return {o["mac"]: o for o in collector.snapshot()["observations"]}

    def test_off_by_default(self, monkeypatch):
        collector = self._collector()
        self._snapshot(collector, monkeypatch)
        collector._reverse.lookup.assert_not_called()

    def test_on_asks_only_for_unnamed_devices_by_ipv4(self, monkeypatch):
        collector = self._collector()
        collector.name_lookups = True
        out = self._snapshot(collector, monkeypatch)
        collector._reverse.lookup.assert_called_once_with(["192.168.4.9"])
        assert [(h["name"], h["source"]) for h in out[MAC]["hostnames"]] == [
            ("printer.lan", "ptr")
        ]

    @pytest.mark.asyncio
    async def test_the_server_switch_reaches_the_collector_and_survives_restart(
        self, tmp_path, monkeypatch
    ):
        monkeypatch.setenv("HOME", str(tmp_path))
        collector = MagicMock(running=True)
        collector.start.return_value = {}
        operations = ops.NetworkDiscoveryOperations(MagicMock(), collector=collector)
        reply = await operations.configure_network_discovery(
            {"enabled": True, "report_interval_seconds": 300, "name_lookups": True}
        )
        assert reply["name_lookups"] is True and collector.name_lookups is True
        await operations.configure_network_discovery({"enabled": True})
        assert collector.name_lookups is False  # an older server: absent = off
        await operations.configure_network_discovery(
            {"enabled": True, "name_lookups": True}
        )
        again = MagicMock()
        ops.NetworkDiscoveryOperations(MagicMock(), collector=again).load_persisted()
        assert again.name_lookups is True
