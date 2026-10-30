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
"""

import asyncio
import ipaddress
import platform
import re
from typing import Any, Callable, Dict, Optional

from src.sysmanage_agent.backup import restate_probe

NFS_PORT = 2049
CONNECT_SECONDS = 5.0
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


async def check(
    parameters: Dict[str, Any],
    connect: Callable = asyncio.open_connection,
    timeout: float = CONNECT_SECONDS,
) -> Dict[str, Any]:
    """``{"success", "reachable", "address", "port", "error"}`` for the
    address the server sent (port 2049 always)."""
    address = (parameters or {}).get("address")
    if not valid_address(address):
        return {"success": False, "reachable": None, "address": None,
                "port": NFS_PORT, "error": "invalid_address"}  # fmt: skip
    try:
        _reader, writer = await asyncio.wait_for(connect(address, NFS_PORT), timeout)
    except asyncio.TimeoutError:
        return _answer(address, False, "timeout")
    except OSError as error:
        return _answer(address, False, (error.strerror or str(error))[:200])
    writer.close()
    try:
        await writer.wait_closed()
    except OSError:
        pass  # connected is what was asked; how it closed does not matter
    return _answer(address, True, None)


def _answer(address: str, reachable: bool, error: Optional[str]) -> Dict[str, Any]:
    return {"success": True, "reachable": reachable, "address": address,
            "port": NFS_PORT, "error": error}  # fmt: skip
