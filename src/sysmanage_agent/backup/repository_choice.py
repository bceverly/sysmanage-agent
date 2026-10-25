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
"""

from typing import Any, Dict, Optional, Tuple

from src.sysmanage_agent.backup.job_validation import PolicyError

Choice = Tuple[str, Optional[Dict[str, Any]], bool]


def choose(policy: Dict[str, Any], params: Dict[str, Any]) -> Choice:
    """``(repository, nfs source or None, previous)`` for this request."""
    wanted = params.get("previous", False)
    if not isinstance(wanted, bool):
        raise PolicyError("previous must be true or false")
    if not wanted:
        return policy["repository"], policy.get("nfs"), False
    previous = policy.get("previous")
    if not previous:
        raise PolicyError("this host has no previous repository")
    return previous["repository"], previous.get("nfs"), True


def for_record(policy: Dict[str, Any], record: Dict[str, Any]) -> Choice:
    """The repository a running job was started against (its record says)."""
    return choose(policy, {"previous": bool(record.get("previous"))})
