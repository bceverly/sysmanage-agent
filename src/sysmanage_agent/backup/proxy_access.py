# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""restate-proxy: reaching a repository over HTTPS (server ROADMAP 25.5).

The storage host runs ``restate-proxy``; a backed-up host reads its own
repository at ``https://PROXY/v1/<client>`` with a token.  Everything here is
checked again, whatever the server checked:

* **The host's side.**  The server sends the proxy's URL for this host (and
  for the repository before Pro+ encryption), and optionally a site CA or a
  pinned key.  The host makes each token itself -- 32 random bytes,
  base64url, ``rsp_`` -- installs it root's alone, and reports only its
  SHA-256; the token never leaves the host.  Read jobs (restore, browse,
  compare, verify) then name the URL and the token file instead of a mount,
  and so do the capture and its snapshot listing once the server says
  ``capture`` (this host's restate captures through a proxy, 3.2.0.0):
  such a host never mounts its storage.
* **The storage host's side.**  The server sends this host's grants and the
  target's clients.  The agent writes one ``/etc/restate/proxy.d/<client>.conf``
  per grant, naming the repository it already serves, and removes every grant
  it labelled for the target whose client is no longer the target's -- a host
  that left, or was deleted -- and all of them when the target is back on NFS.
  It never touches a grant someone wrote by hand.
"""

import base64
import hashlib
import ipaddress
import os
import posixpath
import re
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional

from cryptography import x509

from src.sysmanage_agent.backup.job_validation import PolicyError

TOKEN_DIR = "/etc/restate/tokens"
CA_DIR = "/etc/restate/proxy-ca"
GRANTS_DIR = "/etc/restate/proxy.d"
PROXY_CERT = "/etc/restate/proxy.crt"
PROXY_KEY = "/etc/restate/proxy.key"
PREVIOUS_SUFFIX = ".previous"
LABEL_PREFIX = "sysmanage-agent target "
OPERATIONS = ("append", "read")
MAX_CA_BYTES = 64 * 1024
CERT_WARN_DAYS = 21

_CLIENT = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9._-]{0,63}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
_HOSTNAME = re.compile(
    r"^(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$"
)
_URL = re.compile(
    r"^https://(\[[0-9A-Fa-f:.]+\]|[^/:\[\]]+)(?::(\d{1,5}))?/v1/([^/]+)$"
)
_REPO_DIR = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,254}$")
_CERT = "-----BEGIN CERTIFICATE-----"


# --- checking what the server sent ---------------------------------------


def valid_host_name(value: Any) -> bool:
    return isinstance(value, str) and bool(_HOSTNAME.match(value))


def _check_url(value: Any, what: str) -> str:
    match = _URL.match(value) if isinstance(value, str) else None
    if not match:
        raise PolicyError(f"{what} must be https://HOST[:PORT]/v1/CLIENT")
    host, port, client = match.groups()
    if host.startswith("["):
        try:
            if ipaddress.ip_address(host[1:-1]).version != 6:
                raise ValueError(host)
        except ValueError as error:
            raise PolicyError(f"{what} has a bad IPv6 address") from error
    elif not _HOSTNAME.match(host):
        raise PolicyError(f"{what} has a bad host name")
    if port is not None and not 1 <= int(port) <= 65535:
        raise PolicyError(f"{what} has a bad port")
    if not _CLIENT.match(client):
        raise PolicyError(f"{what} has a bad client name")
    return value


def check_ca(value: Any) -> str:
    """A PEM CA certificate, never a key: what the proxy's certificate is
    trusted by, for this host's jobs alone."""
    if (
        not isinstance(value, str)
        or len(value) > MAX_CA_BYTES
        or not value.lstrip().startswith(_CERT)
        or "PRIVATE KEY" in value
    ):
        raise PolicyError("proxy ca must be a PEM certificate")
    try:
        x509.load_pem_x509_certificate(value.encode("ascii"))
    except (ValueError, UnicodeEncodeError) as error:
        raise PolicyError("proxy ca must be a PEM certificate") from error
    return value.strip() + "\n"


def check_host_proxy(value: Any) -> Optional[Dict[str, Any]]:
    """A backed-up host's ``target.proxy``: ``url``, optionally
    ``previous_url`` (the same client with ``.previous``), ``pin_sha256``,
    ``ca`` and ``capture`` (the capture goes through it too).  None when the
    server sent none."""
    if value is None:
        return None
    if not isinstance(value, dict) or not set(value) <= {
        "url", "previous_url", "pin_sha256", "ca", "capture", "granted"
    } or "url" not in value:  # fmt: skip
        raise PolicyError("proxy must have url, and optionally previous_url, "
                          "pin_sha256, ca, capture and granted")  # fmt: skip
    out: Dict[str, Any] = {"url": _check_url(value["url"], "proxy url")}
    if value.get("granted") is not None:
        out["granted"] = _check_granted(value["granted"])
    if value.get("capture") is not None:
        if not isinstance(value["capture"], bool):
            raise PolicyError("proxy capture must be true or false")
        out["capture"] = value["capture"]
    if value.get("previous_url") is not None:
        if value["previous_url"] != out["url"] + PREVIOUS_SUFFIX:
            raise PolicyError("proxy previous_url must be url + .previous")
        out["previous_url"] = value["previous_url"]
    pin = value.get("pin_sha256")
    if pin is not None:
        if not isinstance(pin, str) or not _SHA256.match(pin):
            raise PolicyError("proxy pin_sha256 must be 64 hex digits")
        out["pin_sha256"] = pin
    if value.get("ca") is not None:
        out["ca"] = check_ca(value["ca"])
    return out


_BANDWIDTH = re.compile(
    r"^(?:(\d{2})-(\d{2}) )?(unlimited|([1-9]\d{0,6})(KiB|MiB|GiB)/s)$"
)
_RATE_SCALE = {"KiB": 1 << 10, "MiB": 1 << 20, "GiB": 1 << 30}
MIN_RATE = 64 << 10  # restate-proxy's least rate
MAX_BANDWIDTH_RULES = 25


def _hours(start: int, end: int) -> int:
    """The hours from ``start`` up to ``end`` (across midnight when ``end``
    is not after ``start``), as a bit mask: restate-proxy's reading."""
    mask, hour = 0, start
    while hour != end % 24 or mask == 0:
        mask |= 1 << hour
        hour = (hour + 1) % 24
    return mask


def check_bandwidth(value: Any) -> List[str]:
    """A grant's ``bandwidth`` lines (Pro+, server 25.7), checked as
    restate-proxy checks them: ``RATE`` or ``HH-HH RATE``, at least 64KiB/s
    or ``unlimited``, no hour in two ranges, one ``RATE`` alone at most."""
    if not isinstance(value, list) or not 1 <= len(value) <= MAX_BANDWIDTH_RULES:
        raise PolicyError("a proxy grant's bandwidth must be 1 to 25 rules")
    taken, default = 0, False
    for rule in value:
        match = _BANDWIDTH.match(rule) if isinstance(rule, str) else None
        if not match:
            raise PolicyError(
                "a proxy grant's bandwidth rule is not RATE or HH-HH RATE"
            )
        start, end, _rate, number, unit = match.groups()
        if number and int(number) * _RATE_SCALE[unit] < MIN_RATE:
            raise PolicyError("a proxy grant's bandwidth rate is under 64KiB/s")
        if start is None:
            if default:
                raise PolicyError(
                    "a proxy grant's bandwidth has two rates for the rest"
                )
            default = True
            continue
        first, last = int(start), int(end)
        if first > 23 or last > 24 or first == last:
            raise PolicyError("a proxy grant's bandwidth hours are not 00 to 24")
        hours = _hours(first, last)
        if hours & taken:
            raise PolicyError("a proxy grant's bandwidth names an hour twice")
        taken |= hours
    return list(value)


def limits_supported(features: Optional[Dict[str, Any]]) -> bool:
    """Whether this host's restate-proxy reads a grant's ``bandwidth``: its
    restate lists the key in ``grant_keys`` (restate 3.2.1.4).  An older
    proxy refuses a grant with a key it does not know, so none is written."""
    keys = (features or {}).get("grant_keys")
    return isinstance(keys, list) and "bandwidth" in keys


def _check_grant(grant: Any) -> Dict[str, Any]:
    if not isinstance(grant, dict) or not set(grant) <= {
        "client", "token_sha256", "operations", "repo_dir", "bandwidth"
    }:  # fmt: skip
        raise PolicyError("a proxy grant has unknown keys")
    client = grant.get("client")
    if not isinstance(client, str) or not _CLIENT.match(client):
        raise PolicyError("a proxy grant's client is not a client name")
    hashes = grant.get("token_sha256")
    if (
        not isinstance(hashes, list)
        or not 1 <= len(hashes) <= 2
        or not all(isinstance(h, str) and _SHA256.match(h) for h in hashes)
    ):
        raise PolicyError("a proxy grant needs one or two token hashes")
    operations = grant.get("operations")
    if (
        not isinstance(operations, list)
        or not operations
        or not set(operations) <= set(OPERATIONS)
    ):
        raise PolicyError("a proxy grant's operations must be append and/or read")
    repo_dir = grant.get("repo_dir")
    if repo_dir is not None and (
        not isinstance(repo_dir, str) or not _REPO_DIR.match(repo_dir)
    ):
        raise PolicyError("a proxy grant's repo_dir must be a single directory name")
    checked = {"client": client, "token_sha256": list(dict.fromkeys(hashes)),
               "operations": [o for o in OPERATIONS if o in operations],
               "repo_dir": repo_dir}  # fmt: skip
    if "bandwidth" in grant:
        checked["bandwidth"] = check_bandwidth(grant["bandwidth"])
    return checked


def check_storage_proxy(value: Any) -> Optional[Dict[str, Any]]:
    """A storage host's ``target.proxy``: ``target_id``, ``enabled``, this
    host's ``grants``, every one of the target's ``clients``, and
    ``export``: false when the host captures through the proxy too (25.5),
    so it needs no NFS export and prepare makes its repository instead.
    None when the server sent none (an older server)."""
    if value is None:
        return None
    keys = {"target_id", "enabled", "grants", "clients"}
    if not isinstance(value, dict) or not keys <= set(value) <= keys | {
        "export",
        "cert",
    }:
        raise PolicyError("proxy must have target_id, enabled, grants and clients")
    target_id = value["target_id"]
    if not isinstance(target_id, str) or not _UUID.match(target_id):
        raise PolicyError("proxy target_id is not a UUID")
    if not isinstance(value["enabled"], bool):
        raise PolicyError("proxy enabled must be true or false")
    export = value.get("export", True)
    if not isinstance(export, bool):
        raise PolicyError("proxy export must be true or false")
    grants, clients = value["grants"], value["clients"]
    if not isinstance(grants, list) or len(grants) > 2:
        raise PolicyError("proxy grants must be a list of at most two")
    if (
        not isinstance(clients, list)
        or len(clients) > 100000
        or not all(isinstance(c, str) and _CLIENT.match(c) for c in clients)
    ):
        raise PolicyError("proxy clients must be client names")
    checked = [_check_grant(g) for g in grants]
    if any(g["client"] not in clients for g in checked):
        raise PolicyError("a proxy grant's client is not one of the target's")
    # pylint: disable=import-outside-toplevel
    from src.sysmanage_agent.backup import proxy_service  # noqa: PLC0415

    return {"target_id": target_id, "enabled": value["enabled"],
            "grants": checked if value["enabled"] else [],
            "clients": sorted(set(clients)),
            "export": export or not value["enabled"],
            "cert": proxy_service.check_cert(value.get("cert"))
            if value["enabled"] else None}  # fmt: skip


def needs_export(policy: Dict[str, Any]) -> bool:
    """A storage policy's host still mounts its repository over NFS."""
    proxy = policy.get("proxy") or {}
    return proxy.get("export", True) is not False


# --- the host's tokens and read jobs -------------------------------------


# A host's token is replaced this often (25.5): by a next token, granted on
# the storage host before the host uses it.
ROTATE_AFTER_SECONDS = 90 * 24 * 3600
MAX_GRANTED = 8


def _check_granted(value: Any) -> List[str]:
    """The token hashes the storage host's grant for this host holds."""
    if (
        not isinstance(value, list)
        or len(value) > MAX_GRANTED
        or not all(isinstance(h, str) and _SHA256.match(h) for h in value)
    ):
        raise PolicyError("proxy granted must be a list of SHA-256 hashes")
    return list(value)


def new_token() -> str:
    """32 random bytes, base64url without padding, prefixed ``rsp_``."""
    return "rsp_" + base64.urlsafe_b64encode(os.urandom(32)).decode("ascii").rstrip("=")


def token_sha256(token: str) -> str:
    """What a grant names: the SHA-256 of the token exactly as written."""
    return hashlib.sha256(token.encode("ascii")).hexdigest()


def token_path(policy_id: str, previous: bool = False) -> str:
    name = f"{policy_id}{PREVIOUS_SUFFIX if previous else ''}.token"
    return posixpath.join(TOKEN_DIR, name)


def ca_path(policy_id: str) -> str:
    return posixpath.join(CA_DIR, f"{policy_id}.pem")


def url_for(proxy: Optional[Dict[str, Any]], previous: bool) -> Optional[str]:
    if not proxy:
        return None
    return proxy.get("previous_url") if previous else proxy.get("url")


def pin_base64(pin_hex: str) -> str:
    """The pinned key as restate takes it -- the base64 of its SHA-256, as
    ``openssl`` prints it and curl's ``--pinnedpubkey sha256//`` reads it --
    from the hex SysManage keeps every SPKI hash in."""
    return base64.b64encode(bytes.fromhex(pin_hex)).decode("ascii")


def job_keys(policy_id: str, proxy: Dict[str, Any], previous: bool) -> Dict[str, Any]:
    """The keys a job adds to reach its repository through the proxy."""
    keys: Dict[str, Any] = {"repository_token_file": token_path(policy_id, previous)}
    if proxy.get("ca"):
        keys["repository_ca_file"] = ca_path(policy_id)
    if proxy.get("pin_sha256"):
        keys["repository_pin_sha256"] = pin_base64(proxy["pin_sha256"])
    return keys


# --- the storage host's grants -------------------------------------------


def label(target_id: str) -> str:
    return LABEL_PREFIX + target_id


def grant_path(client: str) -> str:
    return posixpath.join(GRANTS_DIR, f"{client}.conf")


def grant_repository(policy: Dict[str, Any], grant: Dict[str, Any]) -> str:
    """The repository a grant names: the one this storage policy serves, or
    the one before Pro+ encryption beside it, under the same mount point."""
    if not grant.get("repo_dir"):
        return policy["repository"]
    repository = posixpath.join(policy["mount_point"], grant["repo_dir"])
    if posixpath.dirname(repository) != policy["mount_point"]:
        raise PolicyError("a proxy grant's repository escapes the mount point")
    return repository


def render_grant(
    repository: str, grant: Dict[str, Any], target_id: str, limits: bool = False
) -> str:
    """The grant file.  ``bandwidth`` lines only when ``limits`` (this
    host's restate-proxy reads them, ``limits_supported``)."""
    lines = [
        "# Written by sysmanage-agent (restate-proxy, SysManage 25.5). Do not edit:",
        "# the agent rewrites or removes it.",
        f"repository = {repository}",
        f"operations = {', '.join(grant['operations'])}",
    ]
    lines += [f"token_sha256 = {h}" for h in grant["token_sha256"]]
    if limits:
        lines += [f"bandwidth = {rule}" for rule in grant.get("bandwidth") or []]
    lines.append(f"label = {label(target_id)}")
    return "\n".join(lines) + "\n"


def grant_label(text: Optional[str]) -> Optional[str]:
    """The ``label`` of a grant file, if it has one."""
    for line in (text or "").splitlines():
        key, sep, value = line.partition("=")
        if sep and key.strip() == "label":
            return value.strip()
    return None


def stale_grants(
    target_id: str,
    clients: List[str],
    listdir: Callable[[str], List[str]],
    read_text: Callable[[str], Optional[str]],
) -> List[str]:
    """The grant files this agent wrote for the target whose client is not
    one of the target's any more."""
    try:
        names = listdir(GRANTS_DIR)
    except OSError:
        return []
    wanted = set(clients)
    ours = label(target_id)
    stale = []
    for name in sorted(names):
        client = name[: -len(".conf")] if name.endswith(".conf") else None
        if not client or not _CLIENT.match(client) or client in wanted:
            continue
        path = grant_path(client)
        if grant_label(read_text(path)) == ours:
            stale.append(path)
    return stale


# --- the storage audit ---------------------------------------------------


def _finding(code: str, level: str, **params) -> Dict[str, Any]:
    return {"code": code, "level": level, "params": params}


def certificate_finding(
    pem: Optional[bytes], now: Optional[datetime] = None
) -> Dict[str, Any]:
    """The proxy's certificate: readable, valid, and not near expiry."""
    if not pem:
        return _finding("proxy_certificate", "error", problem="missing")
    try:
        cert = x509.load_pem_x509_certificate(pem)
    except ValueError:
        return _finding("proxy_certificate", "error", problem="unreadable")
    now = now or datetime.now(timezone.utc)
    days = (cert.not_valid_after_utc - now).days
    if days < 0:
        return _finding("proxy_certificate", "error", problem="expired", days=days)
    if days < CERT_WARN_DAYS:
        return _finding("proxy_certificate", "warning", problem="expiring", days=days)
    return _finding("proxy_certificate", "ok", days=days)


def grant_findings(
    grants: List[Dict[str, Any]], checked: Optional[Dict[str, Any]]
) -> List[Dict[str, Any]]:
    """Each of this host's grants as ``restate-proxy --check-grants --json``
    reads it: there, and good."""
    if checked is None:
        return [_finding("proxy_grants", "warning", problem="not_checked")]
    entries = {
        e.get("client"): e for e in checked.get("grants") or [] if isinstance(e, dict)
    }
    out = []
    for grant in grants:
        entry = entries.get(grant["client"])
        if entry is None:
            out.append(_finding("proxy_grants", "error", problem="missing",
                                client=grant["client"]))  # fmt: skip
        elif not entry.get("ok"):
            out.append(_finding("proxy_grants", "error", problem="refused",
                                client=grant["client"],
                                error=str(entry.get("error") or "")[:200]))  # fmt: skip
        else:
            out.append(_finding("proxy_grants", "ok", client=grant["client"]))
    return out
