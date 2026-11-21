# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""Remove a moved host's old repository from this storage host (27.3).

A host that moves to another target with its backups leaves its old
repository where it was, kept as it is for a while; when that time is up the
server asks the old storage host to remove it.  This module decides what may
be removed and how; ``BackupStorageActionsMixin._retire`` runs it.

The server names the repository, but the agent removes only one it served
itself for that policy, so a server can never point it at anything else:

* **forget** (the host moved to another storage host): the repository must
  be the one the policy is configured with here.  Its job files, rules
  file, key file, export and proxy grants go with it, and the agent forgets
  the policy.
* **keep** (the host moved to another target on this same storage host):
  the repository must be one the policy was configured with here before
  (``former``, recorded when a configure gave it another), never its
  current one.

Either way it must hold a restate repository (its ``restate-repository``
marker, looked for as root: the agent's own account cannot enter a
repository), and it must not contain or lie inside any repository another
policy here uses, nor be a backed-up host's.  Other storage entries naming
exactly that repository -- the copy a move made there, an off-site copy
whose row the server has since dropped -- name the same directory and are
forgotten with it (the server never asks while a live copy is there).  One
that is gone already counts as removed.

How, by what the repository is: its own ZFS dataset is destroyed (with its
seals: the server asks only once the old target's seal retention is over);
its own btrfs subvolume is deleted; a plain directory is removed.  On Linux
the append-only and immutable flags restate ``protect`` set are cleared
first (``chattr -a -i -R``); on FreeBSD the repository's ACL does not bind
root.
"""

import posixpath
from typing import Any, Callable, Dict, List, Optional

from src.i18n import _

from src.sysmanage_agent.backup import job_builder
from src.sysmanage_agent.backup import proxy_access
from src.sysmanage_agent.backup import restate_contract as contract
from src.sysmanage_agent.backup import storage_prepare

ACTION = "retire"
# What restate init leaves at the top of every repository.
MARKER = "restate-repository"
STORAGE_ROLE = "storage"
GONE = "gone"
MISSING, REPOSITORY, OTHER = "missing", "repository", "other"


class RetireRefused(Exception):
    """The repository may not be removed: ``code`` + why."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def _overlaps(one: str, other: str) -> bool:
    return one == other or one.startswith(other + "/") or other.startswith(one + "/")


def _clean(repository: Any) -> str:
    if not isinstance(repository, str) or not repository.startswith("/"):
        raise RetireRefused(
            "invalid_request", _("The repository must be an absolute path.")
        )
    if posixpath.normpath(repository) != repository or "/../" in repository + "/":
        raise RetireRefused(
            "invalid_request", _("The repository path is not normalized.")
        )
    if repository.count("/") < 2:
        raise RetireRefused("invalid_request", _("That path is not a repository."))
    return repository


def _shares(entry: Any, repository: str) -> bool:
    return (
        isinstance(entry, dict)
        and entry.get("role") == STORAGE_ROLE
        and entry.get("repository") == repository
    )


def sharers(policies: Dict[str, Any], policy_id: str, repository: str) -> List[str]:
    """The other storage entries that name exactly ``repository``."""
    return sorted(
        other_id
        for other_id, entry in policies.items()
        if other_id != policy_id and _shares(entry, repository)
    )


def _in_use(policies: Dict[str, Any], repository: str):
    for entry in policies.values():
        if not isinstance(entry, dict):
            continue
        paths = [
            entry.get("repository"),
            (entry.get("previous") or {}).get("repository"),
        ]
        if _shares(entry, repository):
            paths = paths[1:]  # the same directory: it goes with it
        for path in paths:
            if isinstance(path, str) and _overlaps(repository, path):
                raise RetireRefused(
                    "in_use",
                    _("%s is in use by a backup policy on this storage host.") % path,
                )


def check(
    policies: Dict[str, Any], policy_id: str, repository: Any, forget: bool
) -> Dict[str, Any]:
    """The policy's saved entry, once ``repository`` may be removed for it;
    else RetireRefused."""
    repository = _clean(repository)
    entry = policies.get(policy_id)
    if not isinstance(entry, dict) or entry.get("role") != STORAGE_ROLE:
        raise RetireRefused(
            "not_configured",
            _("This storage host does not keep a repository for that policy."),
        )
    if forget:
        if entry.get("repository") != repository:
            raise RetireRefused(
                "not_ours", _("That is not the repository this policy uses here.")
            )
    elif repository not in (entry.get("former") or []):
        raise RetireRefused(
            "not_ours",
            _("This storage host never kept that repository for this policy."),
        )
    _in_use(policies, repository)
    return entry


def former(old: Optional[Dict[str, Any]], new: Dict[str, Any]) -> List[str]:
    """The repositories a storage policy was configured with here before
    (``new`` is about to be saved over ``old``), never its new one."""
    kept = list((old or {}).get("former") or [])
    previous = (old or {}).get("repository")
    if (
        new.get("role") == STORAGE_ROLE
        and (old or {}).get("role") == STORAGE_ROLE
        and isinstance(previous, str)
        and previous != new.get("repository")
        and previous not in kept
    ):
        kept.append(previous)
    return [path for path in kept if path != new.get("repository")]


def probe_argv(repository: str) -> List[str]:
    """Run as root: prints the marker's path if ``repository`` holds one."""
    return ["find", repository, "-maxdepth", "1", "-name", MARKER, "-type", "f"]


def probe_state(code: int, out: str, err: str) -> str:
    """``MISSING``, ``REPOSITORY`` or ``OTHER`` from ``probe_argv``'s run;
    OSError when it could not look."""
    if code == 0:
        return REPOSITORY if out.strip() else OTHER
    if "No such file" in (err or ""):
        return MISSING
    raise OSError(err or f"find exited {code}")


def plan(
    repository: str,
    *,
    system: str,
    state: str,
    datasets: Dict[str, str],
    is_subvolume: Callable[[str], bool],
) -> Dict[str, Any]:
    """``{"kind", "commands", "host_namespace"}``: how to remove it (no
    commands when it is gone already).  ``state`` is ``probe_state``'s."""
    if state == MISSING:
        return {"kind": GONE, "commands": [], "host_namespace": False}
    if state != REPOSITORY:
        raise RetireRefused(
            "not_a_repository",
            _("%s does not hold a restate repository; it was left alone.") % repository,
        )
    dataset = datasets.get(repository)
    if dataset and "/" in dataset:
        return {"kind": storage_prepare.ZFS, "host_namespace": True,
                "commands": [["zfs", "destroy", "-r", dataset]]}  # fmt: skip
    thaw = [["chattr", "-a", "-i", "-R", repository]] if system == "Linux" else []
    if system == "Linux" and is_subvolume(repository):
        return {"kind": storage_prepare.BTRFS, "host_namespace": False,
                "commands": thaw + [["btrfs", "subvolume", "delete", repository]]}  # fmt: skip
    return {"kind": storage_prepare.PLAIN, "host_namespace": False,
            "commands": thaw + [["rm", "-rf", "--", repository]]}  # fmt: skip


def forget_files(policy_id: str, entry: Dict[str, Any]) -> List[str]:
    """Every file the agent installed for this storage policy."""
    actions = set(entry.get("actions") or []) | {"seal"}
    paths = [contract.job_path(policy_id, action) for action in sorted(actions)]
    paths += [job_builder.rules_path(policy_id), contract.key_path(policy_id)]
    return paths


def export_file(policy_id: str) -> str:
    return storage_prepare.exports_file(policy_id)


def grants_for(
    repository: str,
    listdir: Callable[[str], List[str]],
    read_text: Callable[[str], Optional[str]],
) -> List[str]:
    """The restate-proxy grant files that name ``repository``."""
    try:
        names = listdir(proxy_access.GRANTS_DIR)
    except OSError:
        return []
    wanted = f"repository = {repository}"
    found = []
    for name in sorted(names):
        if not name.endswith(".conf"):
            continue
        path = posixpath.join(proxy_access.GRANTS_DIR, name)
        lines = (read_text(path) or "").splitlines()
        if any(line.strip() == wanted for line in lines):
            found.append(path)
    return found
