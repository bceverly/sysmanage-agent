# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""Validate a backup policy before anything is written (server ROADMAP 24.2).

A job file is run by restate AS ROOT, so whatever the server sends is treated
as hostile until proven otherwise: every action, key and value is checked
here, and nothing is written unless all of it passes.

The rules, in short:

* a ``host`` policy may capture, list snapshots and estimate -- never prune,
  check or copy: a host that can prune can delete its own history, so those
  run on the storage side (``storage`` role, the NAS's own agent);
* a host capture is always ``append_only``;
* the repository is ``<mount_point>/<repo_dir>``; the mount point sits under a
  backup root, and for a host it must currently be an NFS mount; the real
  path of the repository must stay inside it (no ``..``, no symlink escape);
* every path a job names is absolute and confined to an allow-listed root;
* booleans are booleans, counts are bounded integers, names match strict
  patterns, and an unknown key is an error.
"""

import posixpath
import re
import uuid
from typing import Any, Callable, Dict, List, Optional, Tuple

HOST_ACTIONS = ("capture", "snapshots", "estimate")
STORAGE_ACTIONS = ("prune", "check", "copy", "seal")
ROLES = {"host": HOST_ACTIONS, "storage": STORAGE_ACTIONS}

# Where repositories and their mounts may live.
BACKUP_ROOTS = ("/srv", "/mnt", "/media", "/var/backups")
RULES_ROOTS = ("/etc/restate", "/usr/share/restate")
TMP_ROOTS = ("/var/tmp",) + BACKUP_ROOTS  # nosec B108  # an allow-list, not a file
NFS_TYPES = ("nfs", "nfs4")

# The keys the SERVER may send for each action.  The agent fills command,
# repository, result, progress_file, report_group and encrypt_to itself.
SERVER_KEYS = {
    "capture": {
        "rules",
        "all",
        "baseline_content",
        "quiesce",
        "quiesce_with",
        "one_file_system",
        "tmpdir",
        "syslog",
        "append_only",
    },
    "snapshots": set(),
    "estimate": {"rules", "all", "baseline_content"},
    "prune": {"keep_last", "keep_daily", "keep_weekly", "keep_monthly", "whole_packs"},
    "check": {"read_all", "metadata_only"},
    "copy": {"copy_to", "snapshot"},
}

BOOLS = {
    "all",
    "baseline_content",
    "quiesce",
    "one_file_system",
    "syslog",
    "append_only",
    "whole_packs",
    "read_all",
    "metadata_only",
}
COUNTS = {"keep_last", "keep_daily", "keep_weekly", "keep_monthly"}
MAX_COUNT = 10000
MAX_LIST = 64

_NAME = re.compile(r"^[a-z0-9_-]{1,64}$")
_REPO_DIR = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,254}$")
_SNAPSHOT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9:._-]{0,127}$")
_DATASET = re.compile(r"^[A-Za-z0-9_.][A-Za-z0-9_./-]{0,254}$")
_KEY_BEGIN = "-----BEGIN PGP PUBLIC KEY BLOCK-----"
MAX_KEY_BYTES = 65536


class PolicyError(ValueError):
    """The policy is refused; the message says why (sent to the server)."""


def check_uuid(value: Any, what: str) -> str:
    try:
        return str(uuid.UUID(str(value)))
    except (TypeError, ValueError, AttributeError) as error:
        raise PolicyError(f"{what} is not a uuid") from error


def _under(path: str, roots) -> bool:
    return any(path == root or path.startswith(root + "/") for root in roots)


def confined_path(value: Any, roots, what: str) -> str:
    """An absolute, normalized path inside one of ``roots``."""
    if not isinstance(value, str) or not value.startswith("/"):
        raise PolicyError(f"{what} must be an absolute path")
    if "\x00" in value or "\n" in value or ".." in value.split("/"):
        raise PolicyError(f"{what} is not a plain path")
    normal = posixpath.normpath(value)
    if not _under(normal, roots):
        raise PolicyError(f"{what} is outside the allowed roots")
    return normal


def _bool(key: str, value: Any) -> bool:
    if not isinstance(value, bool):
        raise PolicyError(f"{key} must be true or false")
    return value


def _count(key: str, value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise PolicyError(f"{key} must be an integer")
    if not 0 <= value <= MAX_COUNT:
        raise PolicyError(f"{key} is out of range")
    return value


def _list(key: str, value: Any) -> List[Any]:
    if not isinstance(value, list) or len(value) > MAX_LIST:
        raise PolicyError(f"{key} must be a list of at most {MAX_LIST}")
    return value


def _string_value(key: str, value: Any) -> Any:
    if key == "rules":
        return [confined_path(v, RULES_ROOTS, key) for v in _list(key, value)]
    if key == "quiesce_with":
        names = _list(key, value)
        if not all(isinstance(n, str) and _NAME.match(n) for n in names):
            raise PolicyError("quiesce_with names must match [a-z0-9_-]+")
        return names
    if key == "tmpdir":
        return confined_path(value, TMP_ROOTS, key)
    if key == "copy_to":
        return confined_path(value, BACKUP_ROOTS, key)
    if key == "snapshot":
        return check_snapshot(value)
    raise PolicyError(f"unknown key {key}")


def check_value(key: str, value: Any) -> Any:
    if key in BOOLS:
        return _bool(key, value)
    if key in COUNTS:
        return _count(key, value)
    return _string_value(key, value)


def check_snapshot(value: Any) -> str:
    if not isinstance(value, str) or not _SNAPSHOT.match(value):
        raise PolicyError("snapshot name is not valid")
    return value


def check_job(role: str, action: str, job: Any) -> Dict[str, Any]:
    """One action's server-sent keys, validated (agent keys not yet added)."""
    if action == "seal":
        return check_seal(job)
    if not isinstance(job, dict):
        raise PolicyError(f"{action} job must be an object")
    allowed = SERVER_KEYS[action]
    unknown = sorted(set(job) - allowed)
    if unknown:
        raise PolicyError(f"{action} job has keys it may not set: {', '.join(unknown)}")
    checked = {key: check_value(key, value) for key, value in job.items()}
    if action == "capture" and role == "host":
        if checked.get("append_only") is False:
            raise PolicyError("a host capture is always append-only")
        checked["append_only"] = True
    return checked


_SEAL_KEYS = {
    "none": set(),
    "zfs_snapshot": {"dataset"},
    "btrfs_snapshot": {"subvolume", "snapshot_dir"},
}
_SEAL_PATH = re.compile(r"^/[A-Za-z0-9_./-]*$")


def _seal_path(value: Any, what: str) -> str:
    """An absolute, normalized btrfs path a root command may be given."""
    if (
        not isinstance(value, str)
        or not _SEAL_PATH.match(value)
        or posixpath.normpath(value) != value
        or value == "/"
        or any(part.startswith("-") or part == ".." for part in value.split("/"))
    ):
        raise PolicyError(f"seal {what} must be an absolute, normalized path")
    return value


def check_seal(job: Any) -> Dict[str, Any]:
    """The storage-side seal: a ZFS snapshot of the dataset, a read-only btrfs
    snapshot of the subvolume, or nothing."""
    if not isinstance(job, dict) or job.get("mode") not in _SEAL_KEYS:
        raise PolicyError("seal mode must be zfs_snapshot, btrfs_snapshot or none")
    mode = job["mode"]
    if set(job) != {"mode"} | _SEAL_KEYS[mode]:
        raise PolicyError(
            f"seal job for {mode} must have exactly {sorted(_SEAL_KEYS[mode])}"
        )
    if mode == "none":
        return {"mode": "none"}
    if mode == "zfs_snapshot":
        dataset = job["dataset"]
        if (
            not isinstance(dataset, str)
            or not _DATASET.match(dataset)
            or ".." in dataset.split("/")
        ):
            raise PolicyError("seal dataset is not a valid ZFS dataset name")
        return {"mode": mode, "dataset": dataset}
    subvolume = _seal_path(job["subvolume"], "subvolume")
    snapshot_dir = _seal_path(job["snapshot_dir"], "snapshot_dir")
    if snapshot_dir == subvolume or snapshot_dir.startswith(subvolume + "/"):
        # A snapshot inside the tree it snapshots would nest into the next one.
        raise PolicyError("seal snapshot_dir must be outside the subvolume")
    return {"mode": mode, "subvolume": subvolume, "snapshot_dir": snapshot_dir}


def check_key(text: Any) -> Optional[str]:
    """An armored OpenPGP public key, or None when none was sent."""
    if text is None:
        return None
    if not isinstance(text, str) or len(text.encode("utf-8")) > MAX_KEY_BYTES:
        raise PolicyError("encrypt_key must be an armored public key")
    stripped = text.strip()
    if not stripped.startswith(_KEY_BEGIN) or "PRIVATE KEY" in stripped:
        raise PolicyError("encrypt_key must be an armored PUBLIC key")
    return stripped + "\n"


# ---------------------------------------------------------------------------
# the target: mount point and repository
# ---------------------------------------------------------------------------


def _unescape(field: str) -> str:
    """mountinfo octal escapes (``\\040`` is a space)."""
    return re.sub(r"\\([0-7]{3})", lambda m: chr(int(m.group(1), 8)), field)


def mount_types(mountinfo_text: str) -> Dict[str, str]:
    """``{mount point: filesystem type}`` from /proc/self/mountinfo."""
    found = {}
    for line in mountinfo_text.splitlines():
        before, sep, after = line.partition(" - ")
        fields = before.split()
        if not sep or len(fields) < 5 or not after.split():
            continue
        found[_unescape(fields[4])] = after.split()[0]
    return found


def check_target(
    role: str,
    target: Any,
    *,
    mountinfo: Callable[[], str],
    realpath: Callable[[str], str] = posixpath.realpath,
    isdir: Callable[[str], bool] = posixpath.isdir,
) -> Tuple[str, str]:
    """``(mount_point, repository)`` for the target, both real paths."""
    if not isinstance(target, dict):
        raise PolicyError("target must be an object")
    mount_point = confined_path(target.get("mount_point"), BACKUP_ROOTS, "mount_point")
    repo_dir = target.get("repo_dir")
    if not isinstance(repo_dir, str) or not _REPO_DIR.match(repo_dir):
        raise PolicyError("repo_dir must be a single directory name")
    if role == "host":
        fstype = mount_types(mountinfo()).get(mount_point)
        if fstype not in NFS_TYPES:
            raise PolicyError("mount_point is not an NFS mount on this host")
    elif not isdir(mount_point):
        raise PolicyError("mount_point is not a directory on this host")
    real_mount = realpath(mount_point)
    repository = posixpath.join(mount_point, repo_dir)
    if (
        not _under(realpath(repository), (real_mount,))
        or realpath(repository) == real_mount
    ):
        raise PolicyError("repository escapes the mount point")
    return real_mount, posixpath.join(real_mount, repo_dir)


def check_policy(params: Any, *, mountinfo: Callable[[], str], **fs) -> Dict[str, Any]:
    """The whole ``backup_configure`` request, validated and normalized."""
    if not isinstance(params, dict):
        raise PolicyError("parameters must be an object")
    policy_id = check_uuid(params.get("policy_id"), "policy_id")
    role = params.get("role")
    if role not in ROLES:
        raise PolicyError("role must be host or storage")
    jobs = params.get("jobs")
    if not isinstance(jobs, dict) or not jobs:
        raise PolicyError("jobs must name at least one action")
    refused = sorted(set(jobs) - set(ROLES[role]))
    if refused:
        raise PolicyError(f"a {role} policy may not run: {', '.join(refused)}")
    mount_point, repository = check_target(
        role, params.get("target"), mountinfo=mountinfo, **fs
    )
    return {
        "policy_id": policy_id,
        "role": role,
        "mount_point": mount_point,
        "repository": repository,
        "jobs": {action: check_job(role, action, job) for action, job in jobs.items()},
        "encrypt_key": check_key(params.get("encrypt_key")),
    }
