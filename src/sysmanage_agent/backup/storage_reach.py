# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""Can this host reach its backup storage? (ROADMAP Phase 24)

A backed-up host mounts its repository from the storage host over NFSv4,
which is one TCP port: 2049.  The server sends the address it would have
this host mount from -- the storage host's, nothing else -- and the agent
tries to open a TCP connection to that port, briefly, and closes it.  No
NFS is spoken and nothing is mounted.  A host with no network path there
(production, 2026-10-30: the server's own cloud droplet and the home NAS)
is then not offered backups, rather than failing every night.

Behind NAT (25.8): a host on a private network behind another reaches port
2049 fine, but the storage host sees its traffic come from the gateway and
refuses the mount (its export names the host's own address).  So the answer
also carries this end of the connection (``local_address``/``local_port``),
and when the server asks (``hold_seconds``) the connection is kept open that
long, while the storage host's agent lists who it sees on port 2049
(backup/nfs_peers.py): the server finds this connection there by its source
port and compares the address the storage host sees.
"""

import asyncio
import ipaddress
import platform
import re
from typing import Any, Callable, Dict, Optional

from src.sysmanage_agent.backup import restate_probe

NFS_PORT = 2049
CONNECT_SECONDS = 5.0
# How long the connection may be held open for the storage side to look.
MAX_HOLD_SECONDS = 120
# Held connections, kept referenced until they close (a bare task can be
# collected mid-run).
_HELD: set = set()
# A host name as DNS allows it: letters, digits and hyphens per label.
_HOST_NAME = re.compile(
    r"^(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$"
)


def valid_address(address: Any) -> bool:
    """An IP address or a host name -- never a URL, a port or anything else."""
    if not isinstance(address, str) or not address:
        return False
    try:
        ipaddress.ip_address(address)
        return True
    except ValueError:
        return bool(_HOST_NAME.match(address))


def unavailable_reason(
    _lookup: Optional[Callable] = None, system: Optional[str] = None
) -> Optional[str]:
    """Windows never backs up (restate does not run there); everywhere else
    the check is a plain TCP connection, which every agent can make."""
    if (system or platform.system()) == "Windows":
        return restate_probe.REASON_WRONG_PLATFORM
    return None


async def _open(connect: Callable, address: str):
    """``connect`` to port 2049, given CONNECT_SECONDS at most -- inside a
    timeout context where Python has one (3.11+), ``wait_for`` on 3.9/3.10."""
    if hasattr(asyncio, "timeout"):
        async with asyncio.timeout(CONNECT_SECONDS):
            return await connect(address, NFS_PORT)
    return await asyncio.wait_for(connect(address, NFS_PORT), CONNECT_SECONDS)


async def check(
    parameters: Dict[str, Any],
    connect: Callable = asyncio.open_connection,
) -> Dict[str, Any]:
    """``{"success", "reachable", "address", "port", "error"}`` for the
    address the server sent (port 2049 always)."""
    address = (parameters or {}).get("address")
    if not valid_address(address):
        return {"success": False, "reachable": None, "address": None,
                "port": NFS_PORT, "error": "invalid_address"}  # fmt: skip
    try:
        _reader, writer = await _open(connect, address)
    except asyncio.TimeoutError:
        return _answer(address, False, "timeout")
    except OSError as error:
        return _answer(address, False, (error.strerror or str(error))[:200])
    answer = _answer(address, True, None)
    local = _local_end(writer)
    if local is not None:
        answer["local_address"], answer["local_port"] = local
    hold = _hold_seconds(parameters)
    if hold:
        task = asyncio.ensure_future(_close(writer, hold))
        _HELD.add(task)
        task.add_done_callback(_HELD.discard)
    else:
        await _close(writer, 0)
    return answer


def _hold_seconds(parameters: Dict[str, Any]) -> int:
    value = (parameters or {}).get("hold_seconds")
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        return 0
    return min(value, MAX_HOLD_SECONDS)


def _local_end(writer) -> Optional[tuple]:
    """``(address, port)`` of this end of the connection, or None."""
    try:
        name = writer.get_extra_info("sockname")
    except AttributeError:
        return None
    if isinstance(name, tuple) and len(name) >= 2 and isinstance(name[1], int):
        return str(name[0]), name[1]
    return None


async def _close(writer, after: float) -> None:
    if after:
        await asyncio.sleep(after)
    writer.close()
    try:
        await writer.wait_closed()
    except OSError:
        pass  # connected is what was asked; how it closed does not matter


def _answer(address: str, reachable: bool, error: Optional[str]) -> Dict[str, Any]:
    return {"success": True, "reachable": reachable, "address": address,
            "port": NFS_PORT, "error": error}  # fmt: skip
