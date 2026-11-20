# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""Off-site copies of a storage host's repositories (server ROADMAP 27.3).

A storage host copies each snapshot of a repository it holds into a second
repository on ANOTHER storage host, reached through that host's restate-proxy
over HTTPS, with restate's ``copy`` (append-only on the far side: a re-run
copies nothing twice).  The server names the replicas at configure
(``replicas``: ``id``, ``url``, optionally ``ca`` and ``pin_sha256``); this
storage host makes a COPY TOKEN of its own for each one -- the same generator
a backed-up host uses, installed root's alone -- and reports only its
SHA-256 (``copy_tokens``), which the far side's grant names.  A ``copy`` run
then names a replica and a snapshot, and the agent writes that run's job.

Everything the server sends is checked again here: the URL is ``https`` to a
DNS name, an IPv4 address or a bracketed IPv6 one, with an optional port and
exactly ``/v1/<client>``, nothing else; the CA is PEM certificates of bounded
size and never a key; the pin is 64 hex digits.  A token is never put in a
reply, a log or a command line.
"""

import ipaddress
import posixpath
import re
from typing import Any, Callable, Dict, Iterable, List, Optional

from cryptography import x509

from src.sysmanage_agent.backup import job_builder
from src.sysmanage_agent.backup import job_validation as v
from src.sysmanage_agent.backup import proxy_access as access

COPY_ACTION = "copy"
MAX_REPLICAS = 16
REPLICA_KEYS = {"id", "url", "ca", "pin_sha256"}
REPLICA_INFIX = ".replica."

_URL = re.compile(
    r"^https://(\[[0-9A-Fa-f:.]{2,45}\]|[A-Za-z0-9.-]{1,253})(?::([0-9]{1,5}))?"
    r"/v1/([A-Za-z0-9][A-Za-z0-9._-]{0,127})\Z"
)
_IPV4_LIKE = re.compile(r"^[0-9.]+$")
_PIN = re.compile(r"^[0-9A-Fa-f]{64}\Z")
_CERT = "-----BEGIN CERTIFICATE-----"
_UUID = r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"


class ReplicaUnknown(v.PolicyError):
    """A copy run names a replica this policy was not configured with."""


# --- what the server sends -----------------------------------------------


def check_url(value: Any) -> str:
    """A replica's restate-proxy URL: ``https://HOST[:PORT]/v1/CLIENT``."""
    what = "replica url"
    match = _URL.match(value) if isinstance(value, str) else None
    if not match:
        raise v.PolicyError(f"{what} must be https://HOST[:PORT]/v1/CLIENT")
    host, port = match.group(1), match.group(2)
    if host.startswith("["):
        try:
            if ipaddress.ip_address(host[1:-1]).version != 6:
                raise ValueError(host)
        except ValueError as error:
            raise v.PolicyError(f"{what} has a bad IPv6 address") from error
    elif _IPV4_LIKE.match(host):
        try:
            ipaddress.IPv4Address(host)
        except ValueError as error:
            raise v.PolicyError(f"{what} has a bad IPv4 address") from error
    elif not access.valid_host_name(host):
        raise v.PolicyError(f"{what} has a bad host name")
    if port is not None and not 1 <= int(port) <= 65535:
        raise v.PolicyError(f"{what} has a bad port")
    return value


def check_ca(value: Any) -> str:
    """One or more PEM certificates -- never a key -- that the replica's
    proxy certificate is trusted by, for this copy alone."""
    what = "replica ca must be PEM certificates"
    if (
        not isinstance(value, str)
        or len(value) > access.MAX_CA_BYTES
        or not value.lstrip().startswith(_CERT)
        or "PRIVATE KEY" in value
    ):
        raise v.PolicyError(what)
    try:
        x509.load_pem_x509_certificates(value.encode("ascii"))
    except ValueError as error:  # UnicodeEncodeError too
        raise v.PolicyError(what) from error
    return value.strip() + "\n"


def check_pin(value: Any) -> str:
    """The SHA-256 of the replica proxy's public key, as 64 hex digits."""
    if not isinstance(value, str) or not _PIN.match(value):
        raise v.PolicyError("replica pin_sha256 must be 64 hex digits")
    return value.lower()


def check_replica(value: Any) -> Dict[str, Any]:
    """One replica, checked and normalized."""
    if not isinstance(value, dict) or not {"id", "url"} <= set(value) <= REPLICA_KEYS:
        raise v.PolicyError("a replica must have id and url, and optionally ca "
                            "and pin_sha256")  # fmt: skip
    out: Dict[str, Any] = {
        "id": v.check_uuid(value["id"], "replica id"),
        "url": check_url(value["url"]),
    }
    if value.get("ca") is not None:
        out["ca"] = check_ca(value["ca"])
    if value.get("pin_sha256") is not None:
        out["pin_sha256"] = check_pin(value["pin_sha256"])
    return out


def check_replicas(value: Any) -> Optional[List[Dict[str, Any]]]:
    """A storage policy's ``replicas``; None when the server sent none (an
    older server: nothing about replicas changes)."""
    if value is None:
        return None
    if not isinstance(value, list) or len(value) > MAX_REPLICAS:
        raise v.PolicyError(f"replicas must be a list of at most {MAX_REPLICAS}")
    checked = [check_replica(item) for item in value]
    if len({r["id"] for r in checked}) != len(checked):
        raise v.PolicyError("replicas names one replica twice")
    return checked


def saved(replicas: Optional[List[Dict[str, Any]]]) -> Optional[List[Dict[str, Any]]]:
    """What policies.json keeps of the replicas: a CA only as a flag (the
    certificate itself is in its file)."""
    if replicas is None:
        return None
    return [{**r, "ca": True} if r.get("ca") else dict(r) for r in replicas]


# --- the storage host's files --------------------------------------------


def token_path(policy_id: str, replica_id: str) -> str:
    """This storage host's copy token for one replica of one policy."""
    name = f"{policy_id}{REPLICA_INFIX}{replica_id}.token"
    return posixpath.join(access.TOKEN_DIR, name)


def ca_path(policy_id: str, replica_id: str) -> str:
    """The CA that replica's proxy certificate is trusted by."""
    name = f"{policy_id}{REPLICA_INFIX}{replica_id}.pem"
    return posixpath.join(access.CA_DIR, name)


def files_of(policy_id: str, replica_id: str) -> List[str]:
    return [token_path(policy_id, replica_id), ca_path(policy_id, replica_id)]


def stale_ids(
    policy_id: str,
    wanted: Iterable[str],
    known: Iterable[str],
    listdir: Callable[[str], List[str]],
) -> List[str]:
    """The replica ids this policy has files for -- the ones the agent
    recorded (``known``) and any it finds in the token and CA directories --
    that the server no longer lists."""
    found = set(known)
    pattern = re.compile(
        re.escape(policy_id + REPLICA_INFIX) + f"({_UUID})" + r"\.(?:token|pem)\Z"
    )
    for directory in (access.TOKEN_DIR, access.CA_DIR):
        try:
            names = listdir(directory)
        except OSError:
            continue
        found |= {m.group(1) for m in map(pattern.match, names) if m}
    return sorted(found - set(wanted))


# --- the copy run ---------------------------------------------------------


def find(replicas: Any, replica_id: str) -> Dict[str, Any]:
    """The saved replica ``replica_id`` of a policy (refused when it has no
    such replica)."""
    for replica in replicas if isinstance(replicas, list) else []:
        if isinstance(replica, dict) and replica.get("id") == replica_id:
            return replica
    raise ReplicaUnknown("replica_id is not one of this policy's replicas")


def build_copy_job(
    params: Any,
    *,
    repository: str,
    replicas: Any,
    state_dir: str,
    group: str,
) -> Dict[str, Any]:
    """One snapshot of this policy's repository copied into a replica,
    through its restate-proxy with this host's copy token for it.

    The snapshot is named ``REPOSITORY::NAME`` and there is no
    ``repository`` key: restate refuses a job that names its repository
    both ways.  The replica's URL is checked again as it is used.
    """
    if not isinstance(params, dict):
        raise v.PolicyError(job_builder.NOT_AN_OBJECT)
    policy_id = v.check_uuid(params.get("policy_id"), "policy_id")
    replica_id = v.check_uuid(params.get("replica_id"), "replica_id")
    name = v.check_snapshot(params.get("snapshot"))
    replica = find(replicas, replica_id)
    job: Dict[str, Any] = {
        "command": COPY_ACTION,
        "snapshot": f"{repository}::{name}",
        "copy_to": check_url(replica.get("url")),
        "repository_token_file": token_path(policy_id, replica_id),
    }
    if replica.get("ca"):
        job["repository_ca_file"] = ca_path(policy_id, replica_id)
    if replica.get("pin_sha256"):
        job["repository_pin_sha256"] = access.pin_base64(
            check_pin(replica["pin_sha256"])
        )
    job.update(
        job_builder._reports(  # pylint: disable=protected-access
            state_dir, policy_id, COPY_ACTION, group
        )
    )
    return job
