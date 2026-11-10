# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""Which of a host policy's repositories a job reads (Pro+ backup_engine).

Encryption starts a NEW repository (restate cannot convert one in place), and
the plain one before it stays restorable.  A restore or a snapshot listing
says ``previous: true`` to read that one; everything else -- captures, and
any request that does not say so -- uses the current repository.  The agent
only ever reads a repository the server configured it with; a request cannot
name a path.

Through restate-proxy (25.5) a read job -- restore, browse, compare, verify
-- names the repository's URL instead (``remote``), with no mount; whether it
may is ``reads_remote``: the target is on the proxy, this restate reads
through one, and the host has made its token for that repository.  The
capture and its snapshot listing go the same way once ``captures_remote``
(restate 3.2.0.0 captures through a proxy, and the server says so): their
job files name the URL from the start, and nothing is ever mounted.
"""

from typing import Any, Dict, Optional, Tuple

from src.sysmanage_agent.backup import proxy_access as access
from src.sysmanage_agent.backup import restate_contract as contract
from src.sysmanage_agent.backup.job_validation import PolicyError

Choice = Tuple[str, Optional[Dict[str, Any]], bool]


def choose(
    policy: Dict[str, Any], params: Dict[str, Any], remote: bool = False
) -> Choice:
    """``(repository, nfs source or None, previous)`` for this request:
    through the proxy (a URL, no source) when ``remote``."""
    wanted = params.get("previous", False)
    if not isinstance(wanted, bool):
        raise PolicyError("previous must be true or false")
    url = access.url_for(policy.get("proxy"), wanted) if remote else None
    if url:
        return url, None, wanted
    if not wanted:
        return policy["repository"], policy.get("nfs"), False
    previous = policy.get("previous")
    if not previous:
        raise PolicyError("this host has no previous repository")
    return previous["repository"], previous.get("nfs"), True


def for_record(policy: Dict[str, Any], record: Dict[str, Any]) -> Choice:
    """The repository a running job was started against (its record says)."""
    return choose(
        policy,
        {"previous": bool(record.get("previous"))},
        remote=bool(record.get("remote")),
    )


# The configured host jobs that name the repository: through the proxy
# when the host captures through it (estimate reads the live host only).
REMOTE_JOBS = ("capture", "snapshots")


def captures_remote(
    policy: Dict[str, Any],
    tokens: Optional[Dict[str, Any]],
    features: Optional[Dict[str, Any]],
) -> bool:
    """Whether this host's capture goes through the proxy: the server says
    so (``proxy.capture``), its restate can, and its token is made."""
    proxy = policy.get("proxy") or {}
    return (
        policy.get("role") == "host"
        and proxy.get("capture") is True
        and contract.captures_remote(features)
        and bool((tokens or {}).get("current"))
    )


def reads_remote(
    policy: Dict[str, Any], params: Dict[str, Any], features: Optional[Dict[str, Any]]
) -> bool:
    """Whether this read job goes through the proxy."""
    previous = params.get("previous") is True
    tokens = policy.get("proxy_tokens") or {}
    return (
        contract.reads_remote(features)
        and access.url_for(policy.get("proxy"), previous) is not None
        and bool(tokens.get("previous" if previous else "current"))
    )
