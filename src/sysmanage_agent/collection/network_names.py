# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""
The names devices announce about themselves -- ROADMAP "Device hostnames in
Network Discovery" (2026-10-17).

Everything here reads a packet the collector already captured; nothing is
sent.  Each parser returns the names the SENDER uses for itself, never names
it is looking for or names it knows about other devices:

  * mDNS (UDP 5353)    A/AAAA owner names whose address is the sender's own,
                       reverse-PTR records (``4.4.168.192.in-addr.arpa`` ->
                       ``printer.local``) for the sender's own address, and
                       SRV targets in a response, unless the same packet puts
                       that target at another address (a Bonjour sleep proxy
                       answering for a sleeping Mac).
  * DHCP (UDP 67/68)   option 12 (host name) and option 81 (client FQDN) of a
                       client's DISCOVER / REQUEST / INFORM, keyed by the
                       client hardware address (``chaddr``), since the client
                       may not have an IP yet.  Relayed requests are skipped:
                       their client is on another segment.
  * NetBIOS (UDP 137)  name registrations and refreshes for a unique
                       workstation / server name at the sender's own address
                       (group names are workgroups, not hosts).
  * LLMNR (UDP 5355)   responses whose address record is the sender's own.
                       Queries are skipped: they carry the name SOUGHT.

Agent-supplied data meets attacker-supplied packets here, so every parser is
pure Python, bounds-checked, and returns an empty list on anything malformed:
a bad frame must never stop the capture thread.
"""

import ipaddress
import socket
import struct
import threading
import time
from typing import Dict, List, Optional, Set, Tuple

SOURCE_MDNS = "mdns"
SOURCE_DHCP = "dhcp"
SOURCE_DHCP_FQDN = "dhcp_fqdn"
SOURCE_NETBIOS = "netbios"
SOURCE_LLMNR = "llmnr"
SOURCE_PTR = "ptr"

MAX_NAME = 253
MAX_NAMES_PER_PACKET = 8
_MAX_RECORDS = 64  # far more than any real announcement carries
_MAX_POINTERS = 16  # compression jumps per name; a loop ends here

_TYPE_A = 1
_TYPE_PTR = 12
_TYPE_AAAA = 28
_TYPE_SRV = 33
_TYPE_NB = 0x20

_DHCP_MAGIC = b"\x63\x82\x53\x63"
_DHCP_CLIENT_MESSAGES = (1, 3, 8)  # DISCOVER, REQUEST, INFORM
_NETBIOS_REGISTER_OPCODES = (5, 8, 9)  # registration, refresh (two codes)
_NETBIOS_HOST_SUFFIXES = (0x00, 0x20)  # workstation, file server


class _Malformed(Exception):
    """Raised inside a parser; never escapes one."""


def clean_name(value) -> Optional[str]:
    """A name fit to show, or None.

    Trailing dot dropped; no whitespace, control characters or path
    separators; nothing that is really an address; never ``localhost``.
    """
    if isinstance(value, bytes):
        value = value.decode("utf-8", "replace")
    if not isinstance(value, str):
        return None
    name = value.strip().rstrip(".")
    if not name or len(name) > MAX_NAME or "\ufffd" in name:
        return None
    if any(not ch.isprintable() or ch.isspace() or ch in "/\\" for ch in name):
        return None
    if name.lower() in ("localhost", "localhost.localdomain", "local"):
        return None
    try:
        ipaddress.ip_address(name)
        return None
    except ValueError:
        return name


# ---------------------------------------------------------------------------
# DNS wire format (mDNS, LLMNR, NetBIOS share it)
# ---------------------------------------------------------------------------


def _read_name(data: bytes, offset: int) -> Tuple[str, int]:
    """``(name, offset after it)``; follows compression pointers, bounded."""
    labels: List[str] = []
    end = None
    jumps = 0
    total = 0
    while True:
        if offset >= len(data):
            raise _Malformed("name runs past the packet")
        length = data[offset]
        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(data):
                raise _Malformed("truncated pointer")
            jumps += 1
            if jumps > _MAX_POINTERS:
                raise _Malformed("pointer loop")
            if end is None:
                end = offset + 2
            offset = ((length & 0x3F) << 8) | data[offset + 1]
            continue
        if length & 0xC0:
            raise _Malformed("reserved label type")
        if length == 0:
            return ".".join(labels), (end if end is not None else offset + 1)
        label = data[offset + 1 : offset + 1 + length]
        if len(label) != length:
            raise _Malformed("truncated label")
        total += length + 1
        if total > 255:
            raise _Malformed("name too long")
        labels.append(label.decode("utf-8", "replace"))
        offset += 1 + length


def _records(data: bytes):
    """``(flags, [(section, name, type, rdata_offset, rdata), ...])``."""
    if len(data) < 12:
        raise _Malformed("short header")
    flags, qdcount, ancount, nscount, arcount = struct.unpack("!2xHHHHH", data[:12])
    if qdcount + ancount + nscount + arcount > _MAX_RECORDS:
        raise _Malformed("too many records")
    offset = 12
    for _ in range(qdcount):
        _name, offset = _read_name(data, offset)
        offset += 4
    out = []
    for section, count in (("an", ancount), ("ns", nscount), ("ar", arcount)):
        for _ in range(count):
            name, offset = _read_name(data, offset)
            if offset + 10 > len(data):
                raise _Malformed("truncated record header")
            rtype, _klass, _ttl, rdlength = struct.unpack(
                "!HHIH", data[offset : offset + 10]
            )
            offset += 10
            rdata = data[offset : offset + rdlength]
            if len(rdata) != rdlength:
                raise _Malformed("truncated rdata")
            out.append((section, name, rtype, offset, rdata))
            offset += rdlength
    return flags, out


def _address(rtype: int, rdata: bytes) -> Optional[str]:
    if rtype == _TYPE_A and len(rdata) == 4:
        return socket.inet_ntoa(rdata)
    if rtype == _TYPE_AAAA and len(rdata) == 16:
        return str(ipaddress.IPv6Address(rdata))
    return None


def _reverse_owner(name: str) -> Optional[str]:
    """The address a reverse-PTR owner name stands for, or None."""
    lowered = name.lower()
    try:
        if lowered.endswith(".in-addr.arpa"):
            parts = lowered[: -len(".in-addr.arpa")].split(".")
            if len(parts) == 4:
                return str(ipaddress.IPv4Address(".".join(reversed(parts))))
        elif lowered.endswith(".ip6.arpa"):
            nibbles = lowered[: -len(".ip6.arpa")].split(".")
            if len(nibbles) == 32:
                hexed = "".join(reversed(nibbles))
                return str(ipaddress.IPv6Address(int(hexed, 16)))
    except ValueError:
        return None
    return None


def _same(address: Optional[str], src: str) -> bool:
    if address is None:
        return False
    try:
        return ipaddress.ip_address(address) == ipaddress.ip_address(src)
    except ValueError:
        return False


def _add(found: List[str], name: Optional[str]) -> None:
    name = clean_name(name)
    if name and name.lower() not in (n.lower() for n in found):
        found.append(name)


def _is_host_name(name: str) -> bool:
    """``printer.local`` -- one label then ``.local``; not a service name."""
    labels = name.rstrip(".").split(".")
    return (
        len(labels) == 2
        and labels[1].lower() == "local"
        and not labels[0].startswith("_")
    )


def mdns_names(payload: bytes, src: str) -> List[str]:
    """The host names an mDNS sender uses for ITSELF (see the module doc)."""
    try:
        flags, records = _records(payload)
    except (_Malformed, struct.error, ValueError, IndexError):
        return []
    response = bool(flags & 0x8000)
    addresses: Dict[str, Set[str]] = {}
    for _section, name, rtype, _offset, rdata in records:
        address = _address(rtype, rdata)
        if address is not None:
            addresses.setdefault(name.lower(), set()).add(address)
    found: List[str] = []
    for _section, name, rtype, offset, rdata in records:
        try:
            _mdns_record(found, payload, src, response, addresses,
                         (name, rtype, offset, rdata))  # fmt: skip
        except (_Malformed, struct.error, ValueError, IndexError):
            continue
    return found[:MAX_NAMES_PER_PACKET]


def _mdns_record(found, payload, src, response, addresses, record) -> None:
    name, rtype, offset, rdata = record
    if rtype in (_TYPE_A, _TYPE_AAAA):
        if _same(_address(rtype, rdata), src):
            _add(found, name)
    elif rtype == _TYPE_PTR:
        if _same(_reverse_owner(name), src):
            target, _end = _read_name(payload, offset)
            _add(found, target)
    elif rtype == _TYPE_SRV and response and len(rdata) > 6:
        target, _end = _read_name(payload, offset + 6)
        elsewhere = addresses.get(target.lower(), set())
        if _is_host_name(target) and all(_same(a, src) for a in elsewhere):
            _add(found, target)


def llmnr_names(payload: bytes, src: str) -> List[str]:
    """Names in an LLMNR RESPONSE whose address record is the sender's."""
    try:
        flags, records = _records(payload)
    except (_Malformed, struct.error, ValueError, IndexError):
        return []
    if not flags & 0x8000:
        return []  # a query: the name is what the sender LOOKS FOR
    found: List[str] = []
    for section, name, rtype, _offset, rdata in records:
        if section == "an" and _same(_address(rtype, rdata), src):
            _add(found, name)
    return found[:MAX_NAMES_PER_PACKET]


# ---------------------------------------------------------------------------
# NetBIOS name service (UDP 137)
# ---------------------------------------------------------------------------


def _netbios_decode(encoded: str) -> Optional[Tuple[str, int]]:
    """First-level decoding (RFC 1001 14.1): ``(name, suffix)`` or None."""
    first = encoded.split(".", 1)[0]
    if len(first) != 32 or any(not "A" <= ch <= "P" for ch in first.upper()):
        return None
    first = first.upper()
    raw = bytes(
        ((ord(first[i]) - 65) << 4) | (ord(first[i + 1]) - 65) for i in range(0, 32, 2)
    )
    name = raw[:15].decode("latin-1").rstrip(" \x00")
    return (name, raw[15]) if name else None


def netbios_names(payload: bytes, src: str) -> List[str]:
    """Unique host names a NetBIOS sender registers at its own address."""
    try:
        flags, records = _records(payload)
    except (_Malformed, struct.error, ValueError, IndexError):
        return []
    opcode = (flags >> 11) & 0x0F
    if opcode not in _NETBIOS_REGISTER_OPCODES or flags & 0x8000:
        return []  # only the registrant's own request; no queries, no replies
    found: List[str] = []
    for _section, name, rtype, _offset, rdata in records:
        if rtype != _TYPE_NB or len(rdata) < 6:
            continue
        decoded = _netbios_decode(name)
        if decoded is None or decoded[1] not in _NETBIOS_HOST_SUFFIXES:
            continue
        nb_flags = struct.unpack("!H", rdata[:2])[0]
        if nb_flags & 0x8000:
            continue  # a group name: a workgroup or domain, not a host
        if _same(socket.inet_ntoa(rdata[2:6]), src):
            _add(found, decoded[0])
    return found[:MAX_NAMES_PER_PACKET]


# ---------------------------------------------------------------------------
# DHCP (UDP 67/68)
# ---------------------------------------------------------------------------


def _dhcp_options(payload: bytes) -> Dict[int, bytes]:
    options: Dict[int, bytes] = {}
    offset = 240
    while offset < len(payload):
        code = payload[offset]
        if code == 255:
            break
        if code == 0:
            offset += 1
            continue
        if offset + 1 >= len(payload):
            raise _Malformed("truncated option")
        length = payload[offset + 1]
        value = payload[offset + 2 : offset + 2 + length]
        if len(value) != length:
            raise _Malformed("truncated option value")
        options.setdefault(code, value)
        offset += 2 + length
    return options


def _client_fqdn(value: bytes) -> Optional[str]:
    """Option 81 (RFC 4702): flags, two deprecated RCODEs, then the name."""
    if len(value) < 4:
        return None
    if value[0] & 0x04:  # E bit: canonical DNS wire encoding
        labels: List[str] = []
        offset = 3
        while offset < len(value) and value[offset]:
            length = value[offset]
            label = value[offset + 1 : offset + 1 + length]
            if length > 63 or len(label) != length:
                return None
            labels.append(label.decode("utf-8", "replace"))
            offset += 1 + length
        return ".".join(labels) or None
    return value[3:].decode("ascii", "replace")


def dhcp_client_names(payload: bytes) -> Optional[Dict[str, object]]:
    """``{"mac", "ip", "names": [(name, source), ...]}`` from a client's
    DISCOVER / REQUEST / INFORM, or None.

    ``ip`` is ``ciaddr`` (the address the client already holds) or None --
    never the requested address, which the server has not granted yet.
    """
    try:
        return _dhcp(payload)
    except (_Malformed, struct.error, ValueError, IndexError):
        return None


def _dhcp(payload: bytes) -> Optional[Dict[str, object]]:
    if len(payload) < 240 or payload[0] != 1 or payload[236:240] != _DHCP_MAGIC:
        return None  # not a BOOTREQUEST
    if payload[1] != 1 or payload[2] != 6:
        return None  # not Ethernet
    if payload[24:28] != b"\x00\x00\x00\x00":
        # Relayed (giaddr set): the client is on ANOTHER segment, and this
        # agent only reports what is on its own.
        return None
    options = _dhcp_options(payload)
    kind = options.get(53, b"")
    if len(kind) != 1 or kind[0] not in _DHCP_CLIENT_MESSAGES:
        return None
    names: List[Tuple[str, str]] = []
    for code, source, decode in (
        (81, SOURCE_DHCP_FQDN, _client_fqdn),
        (12, SOURCE_DHCP, lambda v: v.rstrip(b"\x00").decode("ascii", "replace")),
    ):
        if code in options:
            name = clean_name(decode(options[code]))
            if name:
                names.append((name, source))
    if not names:
        return None
    mac = ":".join(f"{b:02x}" for b in payload[28:34])
    ciaddr = socket.inet_ntoa(payload[12:16])
    return {
        "mac": mac,
        "ip": None if ciaddr == "0.0.0.0" else ciaddr,
        "names": names,
    }


# ---------------------------------------------------------------------------
# Reverse DNS -- ACTIVE, so only behind the operator's sweep opt-in
# ---------------------------------------------------------------------------

PTR_TIMEOUT_SECONDS = 1.0
PTR_MAX_PER_REPORT = 64
PTR_BUDGET_SECONDS = 15.0
PTR_RATE_PER_SECOND = 10
PTR_CACHE_SECONDS = 3600.0
PTR_CACHE_MAX = 4096  # one entry per address; MAX_DEVICES is 4096 too


def _gethostbyaddr(ip: str) -> Optional[str]:
    try:
        return socket.gethostbyaddr(ip)[0]
    except (OSError, UnicodeError, ValueError):
        return None


def _bounded(resolver, ip: str, timeout: float) -> Optional[str]:
    """``resolver(ip)`` in a daemon thread, given up on after ``timeout``.

    ``gethostbyaddr`` takes no timeout and a dead resolver can hold it for
    many seconds; a daemon thread left behind costs nothing at exit.
    """
    result: List[Optional[str]] = [None]

    def run():
        result[0] = resolver(ip)

    worker = threading.Thread(target=run, name="netdisc-ptr", daemon=True)
    worker.start()
    worker.join(timeout)
    return None if worker.is_alive() else result[0]


class ReverseNames:
    """PTR lookups for devices that have an address and no name.

    Through the agent's own resolver, at most ``PTR_RATE_PER_SECOND`` a
    second, ``PTR_MAX_PER_REPORT`` and ``PTR_BUDGET_SECONDS`` per report,
    each answered or abandoned within ``PTR_TIMEOUT_SECONDS``.  Answers --
    including "no name" -- are remembered for an hour, so a quiet network
    is not asked about the same address every report.
    """

    def __init__(self, resolver=None, clock=time.monotonic, sleeper=time.sleep):
        self.resolver = resolver or _gethostbyaddr
        self.clock = clock
        self.sleeper = sleeper
        self._cache: Dict[str, Tuple[float, Optional[str]]] = {}

    def lookup(self, ips: List[str]) -> Dict[str, str]:
        """``{ip: name}`` for whichever of ``ips`` have a usable PTR name."""
        start = self.clock()
        found: Dict[str, str] = {}
        asked = 0
        for ip in ips:
            hit = self._cache.get(ip)
            if hit is not None and self.clock() - hit[0] < PTR_CACHE_SECONDS:
                if hit[1]:
                    found[ip] = hit[1]
                continue
            if asked >= PTR_MAX_PER_REPORT or self.clock() - start > PTR_BUDGET_SECONDS:
                break
            if asked:
                self.sleeper(1.0 / PTR_RATE_PER_SECOND)
            asked += 1
            name = clean_name(_bounded(self.resolver, ip, PTR_TIMEOUT_SECONDS))
            self._cache[ip] = (self.clock(), name)
            if name:
                found[ip] = name
        if len(self._cache) > PTR_CACHE_MAX:
            self._cache.clear()  # bounded; refilled at the next reports
        return found
