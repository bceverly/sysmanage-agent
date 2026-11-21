# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""A backed-up host reading its own off-site copy (server ROADMAP 27.3).

A storage host copies each snapshot of a host's repository into a repository
on ANOTHER storage host (``replicas``).  When the host's own storage host is
gone -- a site loss -- the host restores, or browses, from that copy: through
the far side's restate-proxy over HTTPS, with a READ TOKEN of its own that
the far side's grant names with ``operations = read``, and nothing mounted.

The server names the copies at configure (``offsite``: ``id``, ``url``,
optionally ``ca`` and ``pin_sha256``), checked exactly as replicas are; this
host makes one read token per copy, installs it root's alone and reports
only its SHA-256 (``offsite_tokens``).  A restore or a browse job then says
``offsite: <id>`` to read that copy instead of the host's own repository.
A token is never put in a reply, a log or a command line.
"""

import posixpath
from typing import Any, Callable, Dict, Iterable, List, Optional

from src.i18n import _
from src.sysmanage_agent.backup import job_validation as v
from src.sysmanage_agent.backup import proxy_access as access
from src.sysmanage_agent.backup import replicas
from src.sysmanage_agent.backup import restate_contract as contract

OFFSITE_INFIX = ".offsite."
# What policies.json keeps: a CA only as a flag, as for replicas.
saved = replicas.saved


class OffsiteRefused(v.PolicyError):
    """A read job's ``offsite`` cannot be honored; ``reason`` is the
    refusal's code (key_files.refusal_code reads it)."""

    reason = "invalid_request"


class OffsiteUnknown(OffsiteRefused):
    """The job names an off-site copy this policy was not configured with."""

    reason = "not_configured"


class OffsiteUnreadable(OffsiteRefused):
    """This restate cannot read a repository through restate-proxy."""

    reason = "tool_outdated"


# --- what the server sends -----------------------------------------------


def check_offsite(role: str, value: Any) -> Optional[List[Dict[str, Any]]]:
    """A host policy's off-site copies, each checked as a replica is; None
    when the server sent none (an older server: nothing changes)."""
    if value is None:
        return None
    if role != "host":
        raise v.PolicyError("only a host policy may have offsite")
    if not isinstance(value, list) or len(value) > replicas.MAX_REPLICAS:
        raise v.PolicyError(
            f"offsite must be a list of at most {replicas.MAX_REPLICAS}"
        )
    checked = [replicas.check_replica(item) for item in value]
    if len({entry["id"] for entry in checked}) != len(checked):
        raise v.PolicyError("offsite names one copy twice")
    return checked


# --- the host's files -----------------------------------------------------


def token_path(policy_id: str, offsite_id: str) -> str:
    """This host's read token for one off-site copy of one policy."""
    name = f"{policy_id}{OFFSITE_INFIX}{offsite_id}.token"
    return posixpath.join(access.TOKEN_DIR, name)


def ca_path(policy_id: str, offsite_id: str) -> str:
    """The CA that copy's proxy certificate is trusted by."""
    name = f"{policy_id}{OFFSITE_INFIX}{offsite_id}.pem"
    return posixpath.join(access.CA_DIR, name)


def files_of(policy_id: str, offsite_id: str) -> List[str]:
    return [token_path(policy_id, offsite_id), ca_path(policy_id, offsite_id)]


def stale_ids(
    policy_id: str,
    wanted: Iterable[str],
    known: Iterable[str],
    listdir: Callable[[str], List[str]],
) -> List[str]:
    """The off-site copy ids this policy has files for that the server no
    longer lists."""
    return replicas.stale_ids(policy_id, wanted, known, listdir, OFFSITE_INFIX)


# --- the read job ---------------------------------------------------------


def requested(params: Dict[str, Any]) -> Optional[str]:
    """The off-site copy a read job names, or None (its own repository)."""
    wanted = params.get("offsite")
    if wanted is None:
        return None
    offsite_id = v.check_uuid(wanted, "offsite")
    if params.get("previous") is True:
        raise OffsiteRefused(
            _(
                "An off-site copy holds the current repository only; it "
                "cannot be read as the previous one."
            )
        )
    return offsite_id


def find(offsite: Any, offsite_id: str) -> Dict[str, Any]:
    """The saved off-site copy ``offsite_id`` of a policy."""
    for entry in offsite if isinstance(offsite, list) else []:
        if isinstance(entry, dict) and entry.get("id") == offsite_id:
            return entry
    raise OffsiteUnknown(
        _("That off-site copy is not configured for this backup policy.")
    )


def source(
    policy_id: str,
    policy: Dict[str, Any],
    offsite_id: str,
    features: Optional[Dict[str, Any]],
) -> Dict[str, Any]:
    """``{"repository", "keys"}`` for a read job of ``policy`` from its
    off-site copy ``offsite_id``: the copy's URL and the token file, CA or
    pin the job reaches it with."""
    entry = find(policy.get("offsite"), offsite_id)
    if not contract.reads_remote(features):
        raise OffsiteUnreadable(
            _(
                "This restate cannot read an off-site copy through "
                "restate-proxy; upgrade restate."
            )
        )
    keys: Dict[str, Any] = {"repository_token_file": token_path(policy_id, offsite_id)}
    if entry.get("ca"):
        keys["repository_ca_file"] = ca_path(policy_id, offsite_id)
    if entry.get("pin_sha256"):
        keys["repository_pin_sha256"] = access.pin_base64(
            replicas.check_pin(entry["pin_sha256"])
        )
    return {"repository": replicas.check_url(entry.get("url")), "keys": keys}
