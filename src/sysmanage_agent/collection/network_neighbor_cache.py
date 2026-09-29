# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""
Read the operating system's neighbor (ARP / NDP) cache -- Phase 21.6.

The cheapest discovery method there is: every OS keeps this table anyway, so
reading it costs one command and sends nothing on the wire.  Its limit was
measured in the 21.6 S0 spike: it only holds hosts THIS machine exchanged
traffic with, so on its own it never finds a silent device.  It is also how a
host that cannot capture packets (Windows, or any agent not running as root)
still learns the MAC behind an address it heard over mDNS or SSDP.

Platforms:
  * Linux          ``ip -j neigh`` (IPv4 + IPv6, JSON)
  * macOS / BSDs   ``arp -an``   (IPv4)
  * Windows        ``arp -a``    (IPv4)

Binaries are resolved to absolute paths: NetBSD's non-root PATH omits
``/usr/sbin``, and a bare ``arp`` there fails as "not found" -- which would
read as an empty network instead of a missing tool.

Every parser returns ``[{"ip", "mac", "interface"}]`` and never raises; an
unreadable cache returns ``None`` (not measured) rather than ``[]`` (measured
and empty), so the caller can report the method as unavailable.
"""

import json
import logging
import os
import platform
import re
import shutil
import subprocess  # nosec B404 - fixed argv lists, no shell
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

_TIMEOUT = 15
_SBIN = ("/usr/sbin", "/sbin", "/usr/bin", "/bin")
# "? (10.0.0.1) at 0:1a:2b:3:4:5 on en0 ..." (macOS drops leading zeros);
# Linux's own arp adds "[ether]" before "on".
_BSD_LINE = re.compile(
    r"\((?P<ip>[0-9.]+)\) at (?P<mac>[0-9a-fA-F]{1,2}(?::[0-9a-fA-F]{1,2}){5})"
    r"(?: \[\w+\])? on (?P<iface>\S+)"
)
# Neighbor states that mean "this MAC answers at this address NOW".
_CONFIRMED = {"REACHABLE", "PERMANENT", "NOARP"}
_WIN_IFACE = re.compile(r"^Interface:\s*(?P<ip>[0-9.]+)")
_WIN_LINE = re.compile(
    r"^\s*(?P<ip>[0-9.]+)\s+(?P<mac>[0-9a-fA-F]{2}(?:-[0-9a-fA-F]{2}){5})\s+(?P<kind>\w+)"
)


def _binary(name: str) -> Optional[str]:
    found = shutil.which(name)
    if found:
        return found
    for directory in _SBIN:
        candidate = os.path.join(directory, name)
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    return None


def _run(argv: List[str]) -> Optional[str]:
    try:
        result = subprocess.run(  # nosec B603 - fixed argv, absolute path
            argv, capture_output=True, text=True, timeout=_TIMEOUT, check=False
        )
    except (OSError, subprocess.SubprocessError) as error:
        logger.debug("neighbor cache: %s failed: %s", argv[0], error)
        return None
    if result.returncode != 0:
        logger.debug("neighbor cache: %s exited %s", argv[0], result.returncode)
        return None
    return result.stdout


def parse_ip_neigh_json(text: str) -> List[Dict[str, str]]:
    """Linux ``ip -j neigh`` output.

    Unconfirmed entries come LAST.  After a DHCP renumber the old address
    lingers beside the new one for the same MAC, and whichever comes first is
    the address the device is shown at (found by the 21.6 exit-gate run, which
    showed a renumbered device at its old address).  Not just STALE: a sweep
    touches the old address, moving it through DELAY and PROBE -- still
    carrying the MAC -- for seconds before it FAILS, which is exactly when the
    sweep reads the cache back.
    """
    fresh, stale = [], []
    for entry in json.loads(text or "[]"):
        state = entry.get("state") or []
        if "lladdr" not in entry or "FAILED" in state or "INCOMPLETE" in state:
            continue
        confirmed = bool(_CONFIRMED.intersection(state))
        (fresh if confirmed else stale).append(
            {"ip": entry["dst"], "mac": entry["lladdr"], "interface": entry.get("dev")}
        )
    return fresh + stale


def parse_bsd_arp(text: str) -> List[Dict[str, str]]:
    """macOS / FreeBSD / OpenBSD / NetBSD ``arp -an`` output.

    Octets are zero-padded here: macOS prints ``0:1a:2b:3:4:5``, which the
    server would otherwise reject as malformed and silently drop."""
    rows = []
    for line in (text or "").splitlines():
        match = _BSD_LINE.search(line)
        if match:
            mac = ":".join(octet.zfill(2) for octet in match["mac"].split(":"))
            rows.append({"ip": match["ip"], "mac": mac, "interface": match["iface"]})
    return rows


def parse_windows_arp(text: str) -> List[Dict[str, str]]:
    """Windows ``arp -a`` output.  Static entries are skipped: those are the
    broadcast and multicast pseudo-neighbors Windows lists for every
    interface, not devices."""
    rows = []
    interface = None
    for line in (text or "").splitlines():
        header = _WIN_IFACE.match(line)
        if header:
            interface = header["ip"]
            continue
        match = _WIN_LINE.match(line)
        if match and match["kind"].lower() == "dynamic":
            rows.append(
                {"ip": match["ip"], "mac": match["mac"], "interface": interface}
            )
    return rows


def read_neighbor_cache() -> Optional[List[Dict[str, str]]]:
    """This host's neighbor cache, or None when it could not be read."""
    system = platform.system()
    if system == "Linux":
        ip_bin = _binary("ip")
        if ip_bin:
            text = _run([ip_bin, "-j", "neigh", "show"])
            if text is not None:
                try:
                    return parse_ip_neigh_json(text)
                except ValueError:
                    logger.warning("neighbor cache: unparseable 'ip -j neigh' output")
        # No iproute2 (minimal containers): fall through to arp.
    arp_bin = _binary("arp")
    if arp_bin is None:
        return None
    if system == "Windows":
        text = _run([arp_bin, "-a"])
        return None if text is None else parse_windows_arp(text)
    text = _run([arp_bin, "-an"])
    return None if text is None else parse_bsd_arp(text)
