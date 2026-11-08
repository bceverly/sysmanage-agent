# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""Who this storage host sees connected to its NFS port (25.8).

A backed-up host behind NAT reaches port 2049 fine, but its traffic arrives
from the gateway's address, which its export does not name, so the mount is
refused while the reach check says all is well (found 2026-11-03: netbsd, a
libvirt VM behind beast's NAT, seen by nas as 192.168.4.11).  While a host
holds its reach-check connection open, the server asks this host who is
connected (``list_nfs_peers``) and finds that connection by its source port.

Read without privileges and without running anything privileged:
``/proc/net/tcp`` and ``tcp6`` on Linux (every socket, the kernel's NFS
server's included); ``netstat -an -p tcp`` on FreeBSD.  Only established
connections to the local port 2049 are listed, never anything else.
"""

import ipaddress
import platform
import subprocess  # nosec B404 - one fixed argv, no shell
from typing import Any, Callable, Dict, List, Optional

NFS_PORT = 2049
ESTABLISHED = "01"  # /proc/net/tcp's state code
LIMIT = 500


def _proc_address(field: str, six: bool) -> Optional[tuple]:
    """``(address, port)`` from /proc/net/tcp's ``HEX:PORT``."""
    try:
        raw, port = field.split(":")
        data = bytes.fromhex(raw)
    except ValueError:
        return None
    if six:
        # Four 32-bit words, each in host (little-endian) order.
        data = b"".join(data[i : i + 4][::-1] for i in range(0, 16, 4))
        address = ipaddress.IPv6Address(data)
        mapped = address.ipv4_mapped
        text = str(mapped) if mapped is not None else str(address)
    else:
        text = str(ipaddress.IPv4Address(data[::-1]))
    return text, int(port, 16)


def linux_peers(tcp: str, tcp6: str = "") -> List[Dict[str, Any]]:
    """Established connections to local port 2049 from /proc/net/tcp{,6}."""
    found = []
    for text, six in ((tcp, False), (tcp6, True)):
        for line in (text or "").splitlines()[1:]:
            fields = line.split()
            if len(fields) < 4 or fields[3] != ESTABLISHED:
                continue
            local = _proc_address(fields[1], six)
            remote = _proc_address(fields[2], six)
            if local and remote and local[1] == NFS_PORT:
                found.append({"address": remote[0], "port": remote[1]})
    return found[:LIMIT]


def _split_bsd(endpoint: str) -> Optional[tuple]:
    """FreeBSD netstat's ``a.b.c.d.port`` / ``v6addr.port``."""
    address, dot, port = endpoint.rpartition(".")
    if not dot or not port.isdigit():
        return None
    try:
        return str(ipaddress.ip_address(address)), int(port)
    except ValueError:
        return None


def bsd_peers(netstat: str) -> List[Dict[str, Any]]:
    """Established connections to local port 2049 from ``netstat -an``."""
    found = []
    for line in (netstat or "").splitlines():
        fields = line.split()
        if (
            len(fields) < 6
            or not fields[0].startswith("tcp")
            or fields[5] != "ESTABLISHED"
        ):
            continue
        local, remote = _split_bsd(fields[3]), _split_bsd(fields[4])
        if local and remote and local[1] == NFS_PORT:
            found.append({"address": remote[0], "port": remote[1]})
    return found[:LIMIT]


def _read(path: str) -> str:
    try:
        with open(path, "r", encoding="ascii", errors="replace") as handle:
            return handle.read()
    except OSError:
        return ""


def _netstat() -> str:
    try:
        done = subprocess.run(  # nosec B603 B607 - fixed argv
            ["netstat", "-an", "-p", "tcp"],
            capture_output=True, text=True, timeout=30, check=False,
        )  # fmt: skip
    except (OSError, subprocess.SubprocessError):
        return ""
    return done.stdout


def peers(
    system: Optional[str] = None, read: Callable = _read, netstat: Callable = _netstat
) -> Dict[str, Any]:
    """``{"success", "peers": [{"address", "port"}], "error"}``."""
    system = system or platform.system()
    if system == "Linux":
        found = linux_peers(read("/proc/net/tcp"), read("/proc/net/tcp6"))
    elif system == "FreeBSD":
        found = bsd_peers(netstat())
    else:
        return {"success": False, "peers": [], "error": "wrong_platform"}
    return {"success": True, "peers": found, "error": None}


def unavailable_reason(
    _lookup: Optional[Callable] = None, system: Optional[str] = None
) -> Optional[str]:
    """Only a storage host's platforms serve NFS: Linux and FreeBSD."""
    if (system or platform.system()) in ("Linux", "FreeBSD"):
        return None
    return "wrong_platform"
