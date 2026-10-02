# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""
One operator-requested active sweep -- Phase 21.6 S4.

The only way to find a device that never speaks (21.6 S0): send one empty UDP
datagram to every address of an on-link network and let the kernel's own ARP
resolution do the probing, then read the neighbor cache.  No raw sockets, so
it works on every platform the agent runs on.

It is also the only discovery method that puts traffic on a network, so the
agent re-checks what the server already validated before it sends anything:

  * the range must be EXACTLY one of this host's own on-link IPv4 networks --
    a routed range would come back with the router's MAC for every address;
  * at most ``MAX_ADDRESSES`` addresses, at ``MIN_RATE``..``MAX_RATE`` per
    second (the rate is clamped, never exceeded).

A refusal is reported back with its reason rather than silently skipped, so
the operator's run record always closes.
"""

import ipaddress
import logging
import socket
import time
from typing import Any, Dict, List, Optional

from src.sysmanage_agent.collection.network_neighbor_cache import read_neighbor_cache

logger = logging.getLogger(__name__)

MAX_ADDRESSES = 4096
MIN_RATE = 1
MAX_RATE = 200
DEFAULT_RATE = 50
_SETTLE_SECONDS = 3  # let outstanding ARP resolutions finish
_DISCARD_PORT = 9


def on_link_interface(cidr: str, interfaces: List[Dict[str, Any]]) -> Optional[str]:
    """The name of this host's interface that sits on ``cidr``, or None."""
    for iface in interfaces:
        if not iface.get("ip") or iface.get("prefix") is None:
            continue
        own = ipaddress.ip_network(f"{iface['ip']}/{iface['prefix']}", strict=False)
        if str(own) == cidr:
            return iface["name"]
    return None


def check(cidr: Any, interfaces: List[Dict[str, Any]]) -> Dict[str, Any]:
    """``{"cidr", "interface", "reason"}`` -- reason is None when it may run."""
    try:
        net = ipaddress.ip_network(str(cidr), strict=False)
    except ValueError:
        return {"cidr": None, "interface": None, "reason": "invalid_network"}
    if net.version != 4:
        return {"cidr": str(net), "interface": None, "reason": "ipv6_not_supported"}
    if net.num_addresses > MAX_ADDRESSES:
        return {"cidr": str(net), "interface": None, "reason": "too_large"}
    iface = on_link_interface(str(net), interfaces)
    if iface is None:
        return {"cidr": str(net), "interface": None, "reason": "not_on_link"}
    return {"cidr": str(net), "interface": iface, "reason": None}


def clamp_rate(rate: Any) -> int:
    try:
        value = int(rate)
    except (TypeError, ValueError):
        return DEFAULT_RATE
    return max(MIN_RATE, min(MAX_RATE, value))


def sweep(cidr: str, rate: int, own_ip: str, sender=None, sleeper=time.sleep) -> int:
    """Send one datagram per address; returns how many were sent.

    ``sender``/``sleeper`` are injectable so tests never touch a network.
    """
    net = ipaddress.ip_network(cidr, strict=False)
    sock = None
    if sender is None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        def sender(address):
            try:
                sock.sendto(b"", (address, _DISCARD_PORT))
            except OSError:
                pass  # unreachable/refused is fine: the ARP request already went out

    sent = 0
    try:
        for host in net.hosts():
            address = str(host)
            if address == own_ip:
                continue
            sender(address)
            sent += 1
            sleeper(1.0 / rate)
    finally:
        if sock is not None:
            sock.close()
    sleeper(_SETTLE_SECONDS)
    return sent


def observations_in(
    cidr: str, interface: str, cache=None
) -> Optional[List[Dict[str, Any]]]:
    """Neighbor-cache entries inside ``cidr``, as ``sweep`` sightings.

    None when the cache could not be read -- the sweep then FAILED, it did not
    find an empty network.
    """
    rows = read_neighbor_cache() if cache is None else cache
    if rows is None:
        return None
    net = ipaddress.ip_network(cidr, strict=False)
    out = []
    for row in rows:
        try:
            inside = ipaddress.ip_address(row["ip"]) in net
        except ValueError:
            continue
        if inside:
            out.append(
                {
                    "mac": row["mac"].lower().replace("-", ":"),
                    "ips": [row["ip"]],
                    "interface": interface,
                    "methods": ["sweep"],
                    "count": 1,
                    "evidence": {"mdns_services": [], "ssdp": []},
                }
            )
    return out
