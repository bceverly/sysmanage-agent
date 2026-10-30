# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""Prepare a host's repository on the storage host (24.1/24.5).

The storage audit (``storage_audit``) says what is wrong; this is the
administrator-started action that fixes the per-host part of it, so nobody
builds exports by hand.  It only acts on the CONFIGURED storage policy --
the repository, the backed-up host's address and the service account were
validated when the policy was installed; the server sends nothing else.

What it does, by the storage path's filesystem:

* **ZFS** (FreeBSD or Linux): the repository becomes its own dataset, a child
  of the dataset mounted at the storage path, with ``sharenfs`` exporting it
  to the backed-up host's address only and mapping every client to the
  service account.  Run again, it re-exports (the host's address changed).
* **btrfs** (Linux): its own subvolume, exported through
  ``/etc/exports.d/sysmanage-<policy>.exports`` and ``exportfs -ra``.
* **any other Linux filesystem**: a directory with its own export (the audit
  keeps warning that it shares a filesystem).
* **FreeBSD without ZFS**: refused -- FreeBSD exports whole filesystems, so a
  repository without its own dataset cannot have its own export.

Then the repository directory is made ``root:<account>`` and append-only for
the hosts: the host can add files but not remove or rename what it does not
own (restate ``protect`` later takes finished packs and snapshots from it).
On Linux that is mode 0770 plus the append-only flag (``chattr +a``), never
the sticky bit: a Linux NFS client with ``fs.protected_regular=2`` (the
Ubuntu and systemd default) refuses to open a file it just made in a sticky,
group-writable directory, because the squashed owner is neither the caller
nor the directory's owner.  On FreeBSD it is 0770 plus an NFSv4 ACL.

It never moves data: a repository that already holds backups on the parent
filesystem is refused with the steps to move it.  The baseline (NFS server,
NFSv4, lock sharing, the ``V4:`` line, the account itself) is the operator's,
documented and audited -- never edited here.
"""

import os
import posixpath
from typing import Any, Callable, Dict, List, Optional, Tuple

# Unix-only: the agent also runs on Windows, where these modules do not
# exist and a storage host never runs (main.py imports this module there).
try:
    import grp
    import pwd
except ImportError:  # pragma: no cover - Windows
    grp = pwd = None  # type: ignore[assignment]

from src.i18n import _

from src.sysmanage_agent.backup import host_mount
from src.sysmanage_agent.backup.job_validation import mount_types

ACTION = "prepare"
ZFS = "zfs"
BTRFS = "btrfs"
PLAIN = "directory"
EXPORTS_D = "/etc/exports.d"
# Never the sticky bit: Linux NFS clients refuse files made in a sticky,
# group-writable directory (fs.protected_regular=2), after the server has
# made them, so a capture could never write a pack.
DIR_MODE = "0770"
# Linux: the repository's own entries (packs/, snapshots/, the marker) can
# be added to but never removed or renamed; restate protect makes finished
# packs and snapshots immutable.  chattr -a first: a flagged directory
# refuses the chown/chmod of a second prepare.
APPEND_ONLY_ON = ("chattr", "+a")
APPEND_ONLY_OFF = ("chattr", "-a")
# FreeBSD (ZFS, NFSv4 ACLs): the same rule as an ACL (as restate 2.1.0.2's
# protect does): the group may not delete what it does not own; a file's
# owner may delete its own.
APPEND_ONLY_ACL = ("group@:D::deny", "owner@:d:f:allow", "owner@:d:d:allow")


# ZFS's create and mount run in the host's mount namespace (host_mount).
HOST_NAMESPACE = host_mount.HOST_NAMESPACE
in_host_namespace = host_mount.in_host_namespace


def zfs_mounted(repository: str, mountinfo_text: Optional[str]) -> bool:
    """Is the repository a ZFS mount in the host's mount table?"""
    mounts = mount_types(mountinfo_text or "")
    return mounts.get(posixpath.normpath(repository)) == "zfs"


class PrepareRefused(Exception):
    """The repository cannot be prepared as it stands: ``code`` + why."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def exports_file(policy_id: str) -> str:
    """The Linux export file this policy owns."""
    return posixpath.join(EXPORTS_D, f"sysmanage-{policy_id}.exports")


def zfs_datasets(listing: str) -> Dict[str, str]:
    """``{mountpoint: dataset}`` from ``zfs list -H -o name,mountpoint``."""
    found = {}
    for line in listing.splitlines():
        fields = line.split("\t")
        if len(fields) == 2 and fields[1].startswith("/"):
            found[posixpath.normpath(fields[1])] = fields[0]
    return found


def _ids(account: str) -> Tuple[int, int]:
    try:
        return pwd.getpwnam(account).pw_uid, grp.getgrnam(account).gr_gid
    except KeyError as error:
        raise PrepareRefused(
            "no_account",
            _(
                "The backup service account %(account)s (user and group) does "
                "not exist on this storage host. Create it, then prepare again."
            )
            % {"account": account},
        ) from error


def sharenfs(address: str, account: str) -> str:
    """FreeBSD ``sharenfs``: this host only, every client mapped."""
    return f"-mapall={account}:{account} {address}"


def export_line(repository: str, address: str, uid: int, gid: int) -> str:
    """One Linux ``exports(5)`` line: this host only, all mapped."""
    return (
        f"{repository} {address}(rw,sync,no_subtree_check,all_squash,"
        f"anonuid={uid},anongid={gid})\n"
    )


def _empty(path: str, listdir: Callable) -> Optional[bool]:
    """True/False, or None when the directory does not exist."""
    try:
        return not listdir(path)
    except FileNotFoundError:
        return None
    except OSError as error:
        raise PrepareRefused(
            "unreadable",
            _(
                "The agent cannot read %(path)s, so it cannot tell whether it "
                "holds backups. Run the agent as root, or move the directory "
                "aside, then prepare again."
            )
            % {"path": path},
        ) from error


def _not_empty(repository: str, kind: str) -> PrepareRefused:
    if kind == ZFS:
        text = _(
            "%(path)s already holds files but is not its own ZFS dataset, and "
            "preparing never moves backups. Either 1) rename it (for example "
            "to %(path)s.old), prepare again, and copy its contents into the "
            "new dataset as root; or 2) remove it if those backups are no "
            "longer needed."
        )
    else:
        text = _(
            "%(path)s already holds files but is not its own btrfs subvolume, "
            "and preparing never moves backups. Either 1) rename it (for "
            "example to %(path)s.old), prepare again, and copy its contents "
            "into the new subvolume as root; or 2) remove it if those backups "
            "are no longer needed."
        )
    return PrepareRefused("not_empty", text % {"path": repository})


def plan(  # pylint: disable=too-many-arguments
    policy: Dict[str, Any],
    *,
    system: str,
    fstype: Optional[str],
    datasets: Dict[str, str],
    is_subvolume: Callable[[str], bool],
    listdir: Callable = os.listdir,
) -> Dict[str, Any]:
    """What to run: ``{"kind", "commands": [argv...], "export_file": (path,
    text) | None, "reload": bool, "protect": [argv...]}`` -- the filesystem
    and its export, then the ownership and append-only rule (after the new
    mount exists).  Raises ``PrepareRefused``."""
    repository = posixpath.normpath(policy["repository"])
    mount_point = posixpath.normpath(
        policy.get("mount_point") or posixpath.dirname(repository)
    )
    address = policy.get("client_address")
    if not address:
        raise PrepareRefused(
            "no_address",
            _(
                "The server does not know the backed-up host's IP address yet, "
                "so its export cannot be limited to it. Wait for that host to "
                "report its network details, then prepare again."
            ),
        )
    account = policy.get("service_account") or "restate"
    uid, gid = _ids(account)  # also proves the account exists
    protect = _protect_steps(system, account, repository)
    if system not in ("FreeBSD", "Linux"):
        raise PrepareRefused(
            "unsupported",
            _("Preparing storage is not supported on %(system)s.") % {"system": system},
        )
    if fstype == "zfs" or repository in datasets:
        steps = _zfs_steps(repository, mount_point, datasets, listdir)
    elif system == "FreeBSD":
        raise PrepareRefused(
            "zfs_required",
            _(
                "FreeBSD exports whole filesystems, so each host's repository "
                "needs its own ZFS dataset. Put the storage path on ZFS, then "
                "prepare again."
            ),
        )
    elif fstype == "btrfs":
        steps = _btrfs_steps(repository, listdir, is_subvolume)
    else:
        steps = _plain_steps(repository, listdir)
    if system == "FreeBSD":
        _freebsd_export(steps, address, account)
    else:
        # Linux: one /etc/exports.d file per policy, whatever the filesystem
        # (rewritten when the host's address changes), then exportfs -ra.
        dataset = steps.pop("dataset", None)
        if dataset:  # checked mounted host-wide before it is exported
            steps["zfs_dataset"], steps["repository"] = dataset, repository
        steps["export_file"] = (
            exports_file(policy["policy_id"]),
            export_line(repository, address, uid, gid),
        )
        steps["reload"] = True
    steps.pop("exists")
    steps["protect"] = protect
    return steps


def _protect_steps(system: str, account: str, repository: str) -> List[List[str]]:
    """Ownership and mode 0770, then the append-only rule: FreeBSD the NFSv4
    ACL, Linux the append-only flag."""
    if system == "FreeBSD":
        # chmod first: with aclmode=discard it resets the ACL, so a re-run
        # never stacks duplicate entries.
        return [["chown", f"root:{account}", repository],
                ["chmod", DIR_MODE, repository]] + [
            ["setfacl", "-a", "0", ace, repository] for ace in APPEND_ONLY_ACL
        ]  # fmt: skip
    return [
        [*APPEND_ONLY_OFF, repository],
        ["chown", f"root:{account}", repository],
        ["chmod", DIR_MODE, repository],
        [*APPEND_ONLY_ON, repository],
    ]


def _freebsd_export(steps: Dict[str, Any], address: str, account: str) -> None:
    """FreeBSD: the export is the dataset's sharenfs (ZFS writes it to
    /etc/zfs/exports and has mountd reread it)."""
    dataset = steps.pop("dataset")
    value = f"sharenfs={sharenfs(address, account)}"
    if steps["exists"]:
        steps["commands"].append([ZFS, "set", value, dataset])
    else:
        steps["commands"] = [[ZFS, "create", "-o", value, dataset]]
    steps["export_file"], steps["reload"] = None, False


def _zfs_steps(
    repository: str, mount_point: str, datasets: Dict[str, str], listdir: Callable
) -> Dict[str, Any]:
    if repository in datasets:  # already its own dataset: only re-export
        return {"kind": ZFS, "commands": [], "dataset": datasets[repository],
                "exists": True}  # fmt: skip
    parent = datasets.get(mount_point)
    if parent is None:
        raise PrepareRefused(
            "mount_point_not_dataset",
            _(
                "The storage path %(path)s is not where a ZFS dataset is "
                "mounted, so a child dataset would not land at the "
                "repository. Create a dataset mounted there (zfs create -o "
                "mountpoint=%(path)s POOL/NAME), then prepare again."
            )
            % {"path": mount_point},
        )
    if _empty(repository, listdir) is False:
        raise _not_empty(repository, ZFS)
    dataset = f"{parent}/{posixpath.basename(repository)}"
    return {"kind": ZFS, "commands": [[ZFS, "create", dataset]],
            "dataset": dataset, "exists": False}  # fmt: skip


def _btrfs_steps(
    repository: str, listdir: Callable, is_subvolume: Callable[[str], bool]
) -> Dict[str, Any]:
    empty = _empty(repository, listdir)
    if empty is None:
        return {"kind": BTRFS, "exists": False,
                "commands": [[BTRFS, "subvolume", "create", repository]]}  # fmt: skip
    if not is_subvolume(repository):
        if empty is False:
            raise _not_empty(repository, BTRFS)
        raise PrepareRefused(
            "not_subvolume",
            _(
                "%(path)s is an empty directory, not a btrfs subvolume. "
                "Remove it (rmdir as root), then prepare again."
            )
            % {"path": repository},
        )
    return {"kind": BTRFS, "commands": [], "exists": True}


def _plain_steps(repository: str, listdir: Callable) -> Dict[str, Any]:
    if _empty(repository, listdir) is None:
        return {"kind": PLAIN, "exists": False,
                "commands": [["mkdir", "-m", "700", repository]]}  # fmt: skip
    return {"kind": PLAIN, "commands": [], "exists": True}
