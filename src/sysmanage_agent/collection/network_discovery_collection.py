# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""
Passive network discovery -- Phase 21.6 S1.

What devices are on the segments this host sits on?  The agent LISTENS; it
sends nothing.  Which methods to use was measured, not assumed (21.6 S0, on
two virtual segments and a real home LAN):

  * ARP listening   found 26 of 31 devices on a live LAN -- 15 by nothing
                    else.  Needs raw capture: Linux AF_PACKET as root here.
  * neighbor cache  free and portable, but only holds hosts this machine
                    talked to (``network_neighbor_cache``).
  * mDNS / SSDP     fewer devices, but the best evidence of WHAT a device is
                    (service types, UPnP server strings).
  * IPv6 ND         a bonus where the switch floods it; never relied upon.

No passive method reliably finds a SILENT device -- only an active sweep does,
and that is an opt-in, audited server decision (21.6 S4), never done here.
So the report always carries ``methods``: what this host could and could not
do, so the server states the blind spots instead of implying completeness.

Listening is CONTINUOUS between reports: a 60 s window missed ~30% of the
devices a 4-minute one found.  Memory is bounded (``MAX_DEVICES``).

Interfaces that are container or VM plumbing (docker, veth, virbr, tun, ...)
are skipped: the question is "what is on my network", and every container on
a Docker bridge reported as an unmanaged device would bury the answer.
"""

import ipaddress
import logging
import os
import platform
import socket
import struct
import threading
import time
from typing import Any, Dict, List, Optional, Tuple

import psutil

from src.i18n import _
from src.sysmanage_agent.collection.network_bpf import BpfListener
from src.sysmanage_agent.collection.network_neighbor_cache import read_neighbor_cache

logger = logging.getLogger(__name__)

MAX_DEVICES = 4096
MAX_EVIDENCE = 20

OK = "ok"
NOT_ROOT = "unavailable:not_root"
UNSUPPORTED = "unavailable:unsupported_platform"
PORT_IN_USE = "unavailable:port_in_use"
UNREADABLE = "unavailable:unreadable"

_ETH_P_ALL = 0x0003
_ETH_P_ARP = 0x0806
_ETH_P_IP = 0x0800
_ETH_P_IPV6 = 0x86DD
_MDNS = ("224.0.0.251", 5353)
_SSDP = ("239.255.255.250", 1900)
# Where raw capture exists (S6): AF_PACKET on Linux, BPF everywhere else.
_CAPTURE_SYSTEMS = ("Linux", "Darwin", "FreeBSD", "OpenBSD", "NetBSD", "DragonFly")
_SKIP_PREFIXES = (
    "lo", "docker", "br-", "veth", "virbr", "lxdbr", "lxcbr", "vnet", "tap",
    "tun", "wg", "zt", "tailscale", "cni", "flannel", "cali", "kube", "podman",
)  # fmt: skip


_SYSFS_NET = "/sys/class/net"
_BRIDGE_TTL = 60.0
_bridge_cache: Dict[str, Tuple[float, bool]] = {}


def virtual_only_bridge(name: str, sysfs: str = _SYSFS_NET) -> bool:
    """Linux: a bridge none of whose ports is a physical NIC (S5).

    That is VM or container plumbing whatever it is called -- the live S4 run
    listened on a custom-named libvirt bridge (``smdisc1``) that the name
    prefixes missed.  A bridge WITH a physical port (``br0`` over ``eth0``)
    is the operator's real LAN and is kept.  A port is physical when sysfs
    gives it a ``device`` link; taps and veths have none.
    """
    bridge_dir = os.path.join(sysfs, name, "brif")
    if not os.path.isdir(bridge_dir):
        return False
    ports = os.listdir(bridge_dir)
    return not any(os.path.exists(os.path.join(sysfs, p, "device")) for p in ports)


def _cached_virtual_bridge(name: str) -> bool:
    now = time.monotonic()
    hit = _bridge_cache.get(name)
    if hit is not None and now - hit[0] < _BRIDGE_TTL:
        return hit[1]
    value = platform.system() == "Linux" and virtual_only_bridge(name)
    _bridge_cache[name] = (now, value)
    return value


def skipped_interface(name: str) -> bool:
    """Container / VM / VPN plumbing, not a network an operator means.

    Named plumbing is caught by prefix; on Linux a bridge with only virtual
    ports is caught by what it IS, whatever it is called.  Called per captured
    frame, so the sysfs check is cached per interface for a minute.
    """
    return name.lower().startswith(_SKIP_PREFIXES) or _cached_virtual_bridge(name)


def _mac_text(raw: bytes) -> str:
    return ":".join(f"{b:02x}" for b in raw)


def mdns_services(payload: bytes) -> List[str]:
    """Service types (``_ipp._tcp``) named in a DNS message.

    Best effort, deliberately: a label scan, not a DNS parser.  It only has
    to surface what a device advertises; it never decides anything.
    """
    labels, current = [], []
    for byte in payload[12:]:
        if 32 < byte < 127:
            current.append(chr(byte))
            continue
        if current:
            labels.append("".join(current))
        current = []
    found = []
    for first, second in zip(labels, labels[1:]):
        if first.startswith("_") and second in ("_tcp", "_udp"):
            service = f"{first}.{second}"
            if service not in found and first != "_services":
                found.append(service)
    return found[:MAX_EVIDENCE]


def ssdp_evidence(payload: bytes) -> List[str]:
    """The SERVER and NT/ST lines of an SSDP message: what the device is."""
    keep = []
    for line in payload[:2048].decode("latin-1", "replace").split("\r\n"):
        if line.lower().startswith(("server:", "nt:", "st:")):
            text = line.strip()[:128]
            if text not in keep:
                keep.append(text)
    return keep[:MAX_EVIDENCE]


class _Accumulator:
    """Thread-safe, bounded map of devices seen since the last report."""

    def __init__(self):
        self._lock = threading.Lock()
        self._devices: Dict[str, Dict[str, Any]] = {}
        self.overflowed = False

    def note(self, key, mac, ip, iface, method, mdns=None, ssdp=None):
        with self._lock:
            row = self._devices.get(key)
            if row is None:
                if len(self._devices) >= MAX_DEVICES:
                    self.overflowed = True
                    return
                row = {"mac": mac, "ips": [], "interface": iface, "methods": set(),
                       "count": 0, "mdns": [], "ssdp": []}  # fmt: skip
                self._devices[key] = row
            if ip and ip not in row["ips"] and len(row["ips"]) < 10:
                row["ips"].append(ip)
            row["methods"].add(method)
            row["count"] += 1
            for kind, items in (("mdns", mdns or []), ("ssdp", ssdp or [])):
                for item in items:
                    if item not in row[kind] and len(row[kind]) < MAX_EVIDENCE:
                        row[kind].append(item)

    def drain(self) -> Tuple[Dict[str, Dict[str, Any]], bool]:
        with self._lock:
            devices, self._devices = self._devices, {}
            overflowed, self.overflowed = self.overflowed, False
        return devices, overflowed


class _PacketListener(threading.Thread):
    """Linux, root: one AF_PACKET socket sees ARP, ND, mDNS and SSDP with the
    sender's MAC.  Frames this host sent are ignored."""

    def __init__(self, sink: _Accumulator):
        super().__init__(name="netdisc-packets", daemon=True)
        self.sink = sink
        self.stop_event = threading.Event()
        self.sock = socket.socket(  # pylint: disable=no-member
            socket.AF_PACKET, socket.SOCK_RAW, socket.htons(_ETH_P_ALL)
        )
        self.sock.settimeout(1.0)

    def run(self):
        while not self.stop_event.is_set():
            try:
                frame, addr = self.sock.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError as error:
                logger.warning(_("Network discovery capture stopped: %s"), error)
                return
            if (
                addr[2] == socket.PACKET_OUTGOING or len(frame) < 34
            ):  # pylint: disable=no-member
                continue
            if skipped_interface(addr[0]):
                continue
            self._frame(frame, addr[0])
        self.sock.close()

    def _frame(self, frame: bytes, iface: str):
        parse_frame(self.sink, frame, iface)


def parse_frame(sink: "_Accumulator", frame: bytes, iface: str) -> None:
    """One Ethernet frame -> a sighting, whatever captured it (AF_PACKET on
    Linux, BPF on the BSDs and macOS).  ARP, IPv6 ND, mDNS and SSDP, each
    with the sender's MAC."""
    if len(frame) < 34:
        return
    mac = _mac_text(frame[6:12])
    ethertype = struct.unpack("!H", frame[12:14])[0]
    body = frame[14:]
    if ethertype == _ETH_P_ARP and len(body) >= 28:
        sender_ip = socket.inet_ntoa(body[14:18])
        # 0.0.0.0 is an address-conflict probe: the MAC is real, the IP not yet.
        ip = None if sender_ip == "0.0.0.0" else sender_ip  # nosec B104
        sink.note(mac, mac, ip, iface, "arp_listen")
    elif ethertype == _ETH_P_IPV6 and len(body) >= 41 and body[6] == 58:
        if 133 <= body[40] <= 136:
            src = socket.inet_ntop(socket.AF_INET6, body[8:24])
            sink.note(mac, mac, src, iface, "nd_listen")
    elif ethertype == _ETH_P_IP and body[9] == 17:
        _parse_udp(sink, body, mac, iface)


def _parse_udp(sink: "_Accumulator", body: bytes, mac: str, iface: str) -> None:
    ihl = (body[0] & 0x0F) * 4
    if len(body) < ihl + 8:
        return
    sport, dport = struct.unpack("!HH", body[ihl : ihl + 4])
    src = socket.inet_ntoa(body[12:16])
    payload = body[ihl + 8 :]
    if _MDNS[1] in (sport, dport):
        sink.note(mac, mac, src, iface, "mdns", mdns=mdns_services(payload))
    elif _SSDP[1] in (sport, dport):
        sink.note(mac, mac, src, iface, "ssdp", ssdp=ssdp_evidence(payload))


class _MulticastListener(threading.Thread):
    """Everywhere else: plain UDP multicast sockets for mDNS and SSDP.

    Portable and unprivileged, but a socket reports the sender's IP only; the
    MAC is filled in from the neighbor cache at report time."""

    def __init__(self, sink: _Accumulator, local_ips: List[str]):
        super().__init__(name="netdisc-multicast", daemon=True)
        self.sink = sink
        self.stop_event = threading.Event()
        self.sockets = {}
        for kind, (group, port) in (("mdns", _MDNS), ("ssdp", _SSDP)):
            sock = self._open(group, port, local_ips)
            if sock is not None:
                self.sockets[kind] = sock

    @staticmethod
    def _open(group: str, port: int, local_ips: List[str]):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            if hasattr(socket, "SO_REUSEPORT"):
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            sock.bind(("", port))
            for local in local_ips:
                membership = socket.inet_aton(group) + socket.inet_aton(local)
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, membership)
            sock.settimeout(1.0)
            return sock
        except OSError as error:
            logger.info(
                "network discovery: cannot listen on %s/%s: %s", group, port, error
            )
            sock.close()
            return None

    def run(self):
        while not self.stop_event.is_set() and self.sockets:
            for kind, sock in list(self.sockets.items()):
                try:
                    payload, (src, _port) = sock.recvfrom(9000)
                except socket.timeout:
                    continue
                except OSError:
                    continue
                if kind == "mdns":
                    self.sink.note(
                        "ip:" + src,
                        None,
                        src,
                        None,
                        "mdns",
                        mdns=mdns_services(payload),
                    )
                else:
                    self.sink.note(
                        "ip:" + src,
                        None,
                        src,
                        None,
                        "ssdp",
                        ssdp=ssdp_evidence(payload),
                    )
        for sock in self.sockets.values():
            sock.close()


def local_interfaces() -> List[Dict[str, Any]]:
    """This host's own interfaces: name, MAC, first IPv4 and its prefix."""
    out = []
    for name, addrs in (psutil.net_if_addrs() or {}).items():
        if skipped_interface(name):
            continue
        entry = {"name": name, "mac": None, "ip": None, "prefix": None}
        for addr in addrs:
            if addr.family == psutil.AF_LINK and addr.address:
                entry["mac"] = addr.address
            elif addr.family == socket.AF_INET and entry["ip"] is None:
                entry["ip"] = addr.address
                entry["prefix"] = _prefix(addr.netmask)
        if entry["ip"]:
            out.append(entry)
    return out


def _prefix(netmask: Optional[str]) -> Optional[int]:
    try:
        return bin(struct.unpack("!I", socket.inet_aton(netmask))[0]).count("1")
    except (OSError, TypeError):
        return None


def _is_root() -> bool:
    geteuid = getattr(os, "geteuid", None)
    return bool(geteuid) and geteuid() == 0


class NetworkDiscoveryCollector:
    """Listens between reports; ``snapshot()`` returns and resets."""

    def __init__(self):
        self.sink = _Accumulator()
        self._listener: Optional[threading.Thread] = None
        self._methods: Dict[str, str] = {}
        self._window_start: Optional[float] = None

    @property
    def running(self) -> bool:
        return self._listener is not None

    @property
    def methods(self) -> Dict[str, str]:
        """What this host can and cannot do, as last started."""
        return dict(self._methods)

    def start(self) -> Dict[str, str]:
        """Start listening; returns what this host can and cannot do."""
        if self._listener is not None:
            return dict(self._methods)
        self._window_start = time.monotonic()
        methods = {"sweep": "unavailable:disabled"}
        self._listener = self._raw_listener()
        if self._listener is not None:
            methods.update(arp_listen=OK, nd_listen=OK, mdns=OK, ssdp=OK)
        else:
            reason = NOT_ROOT if platform.system() in _CAPTURE_SYSTEMS else UNSUPPORTED
            methods.update(arp_listen=reason, nd_listen=reason)
            ips = [i["ip"] for i in local_interfaces()]
            listener = _MulticastListener(self.sink, ips)
            methods["mdns"] = OK if "mdns" in listener.sockets else PORT_IN_USE
            methods["ssdp"] = OK if "ssdp" in listener.sockets else PORT_IN_USE
            self._listener = listener
        self._listener.start()
        self._methods = methods
        logger.info("network discovery started: %s", methods)
        return dict(methods)

    def _raw_listener(self) -> Optional[threading.Thread]:
        """Raw capture where the platform has it and we are root: AF_PACKET
        on Linux, BPF on the BSDs and macOS (S6).  None means fall back to
        plain multicast sockets -- mDNS/SSDP only, no ARP listening."""
        system = platform.system()
        if system not in _CAPTURE_SYSTEMS or not _is_root():
            return None
        try:
            if system == "Linux":
                return _PacketListener(self.sink)
            return BpfListener(
                local_interfaces(),
                lambda frame, iface: parse_frame(self.sink, frame, iface),
            )
        except OSError as error:
            logger.warning(_("Network discovery raw capture unavailable: %s"), error)
            return None

    def stop(self) -> None:
        listener, self._listener = self._listener, None
        if listener is not None:
            listener.stop_event.set()
            listener.join(timeout=3)
            logger.info("network discovery stopped")

    def snapshot(self) -> Dict[str, Any]:
        """Everything seen since the last snapshot, as a report payload."""
        now = time.monotonic()
        window = int(now - (self._window_start or now))
        self._window_start = now
        devices, overflowed = self.sink.drain()
        interfaces = local_interfaces()
        methods = dict(self._methods)
        cache = read_neighbor_cache()
        methods["cache"] = OK if cache is not None else UNREADABLE
        _merge_cache(devices, cache or [], interfaces)
        if overflowed:
            logger.warning(
                _(
                    "Network discovery saw more than %d devices in one window; "
                    "the rest were not recorded"
                ),
                MAX_DEVICES,
            )
        return {
            "interfaces": interfaces,
            "methods": methods,
            "window_seconds": window or None,
            "observations": [_observation(d) for d in devices.values()],
        }


def _merge_cache(devices, cache, interfaces) -> None:
    """Fold the neighbor cache in, and give IP-only sightings their MAC."""
    by_ip = {i["ip"]: i["name"] for i in interfaces}
    names = {i["name"] for i in interfaces}
    mac_of_ip = {}
    for row in cache:
        iface = row.get("interface")
        iface = by_ip.get(iface, iface)  # Windows labels interfaces by IP
        if iface not in names:
            continue
        mac = row["mac"].lower().replace("-", ":")
        mac_of_ip[row["ip"]] = (mac, iface)
        entry = devices.setdefault(
            mac,
            {"mac": mac, "ips": [], "interface": iface, "methods": set(),
             "count": 0, "mdns": [], "ssdp": []},  # fmt: skip
        )
        if row["ip"] not in entry["ips"]:
            entry["ips"].append(row["ip"])
        entry["methods"].add("cache")
        entry["count"] += 1
    for key in [k for k in devices if k.startswith("ip:")]:
        row = devices[key]
        found = mac_of_ip.get(row["ips"][0]) if row["ips"] else None
        if found is None:
            # Heard over a plain socket and not in the cache. Our OWN
            # announcements loop back, and a socket bound to every address
            # also hears the interfaces we deliberately skip (an LXD bridge,
            # say): keep it only if it is someone else on a monitored subnet.
            iface = _interface_for(row["ips"][0] if row["ips"] else None, interfaces)
            if iface is None:
                devices.pop(key)
            else:
                row["interface"] = iface
            continue  # the server keys it by IP
        mac, iface = found
        if mac in devices:
            _fold(devices[mac], devices.pop(key))
        else:
            row["mac"], row["interface"] = mac, iface
            devices[mac] = devices.pop(key)


def _interface_for(ip: Optional[str], interfaces) -> Optional[str]:
    """The monitored interface whose subnet holds ``ip`` -- never our own."""
    if not ip:
        return None
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    for iface in interfaces:
        if iface["ip"] == ip:
            return None  # ourselves
        if iface["prefix"] is None:
            continue
        net = ipaddress.ip_network(f"{iface['ip']}/{iface['prefix']}", strict=False)
        if addr in net:
            return iface["name"]
    return None


def _fold(into, other) -> None:
    into["methods"] |= other["methods"]
    into["count"] += other["count"]
    for ip in other["ips"]:
        if ip not in into["ips"]:
            into["ips"].append(ip)
    for kind in ("mdns", "ssdp"):
        into[kind] += [x for x in other[kind] if x not in into[kind]]


def _observation(device: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "mac": device["mac"],
        "ips": device["ips"],
        "interface": device["interface"],
        "methods": sorted(device["methods"]),
        "count": device["count"],
        "evidence": {"mdns_services": device["mdns"], "ssdp": device["ssdp"]},
    }
