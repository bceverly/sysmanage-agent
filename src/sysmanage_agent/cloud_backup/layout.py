# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""Where iCloud Photos go, and the checks on what the server sent.

* The CLOUD ROOT is ``<storage path>/cloud-photos`` -- beside the hosts'
  repositories, never inside one.  The storage path must be the one this
  storage host already serves for a backup policy (its own policies file
  says so): the server cannot point the agent anywhere else.
* Each account has its own ``icloud-<8 hex>`` under it: a ZFS child dataset
  where the storage path is a ZFS dataset (the target's recursive seal then
  covers it), else a plain directory (a btrfs seal snapshots the storage
  subvolume, which a nested subvolume would escape).  Photos are laid out by
  date, originals with their Live Photo videos and XMP sidecars, file names
  kept as Apple has them.
* Each account's SESSION (icloudpd's cookies) is in the agent's own state
  directory, ``cloud_backup/sessions/<account dir>``, 0700 and the agent's
  account's alone -- never on the backup storage, and left out of the
  storage host's own backup.  Removed when the account is deleted.

Every name is checked here again, whatever the server checked.
"""

import json
import posixpath
import re
import uuid
from typing import Any, Callable, Dict, Optional

from src.sysmanage_agent.cloud_backup import tool

CLOUD_ROOT = "cloud-photos"
SESSIONS = "sessions"
ACTIONS = ("connect", "download", "reconcile", "libraries")
STORAGE_ROLES = ("storage", "self")
FOLDER_STRUCTURE = "{:%Y/%m/%d}"
MAX_UNTIL_FOUND = 10000

_DIR = re.compile(r"^icloud-[0-9a-f]{8}$")
_EMAIL = re.compile(r"^[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,190}\.[A-Za-z]{2,24}$")
_LIBRARY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_. -]{0,127}$")


class LayoutError(Exception):
    """The server sent something this agent will not act on."""


def run_id(parameters: Dict[str, Any]) -> str:
    try:
        return str(uuid.UUID(str(parameters.get("run_id"))))
    except ValueError as error:
        raise LayoutError("run_id is not a UUID") from error


def dir_name(value: Any) -> str:
    if not isinstance(value, str) or not _DIR.match(value):
        raise LayoutError("dir_name is not icloud-<8 hex>")
    return value


def apple_id(value: Any) -> str:
    if not isinstance(value, str) or not _EMAIL.match(value):
        raise LayoutError("apple_id is not an e-mail address")
    return value


def library(value: Any) -> str:
    if not isinstance(value, str) or not _LIBRARY.match(value):
        raise LayoutError("library is not an iCloud library name")
    return value


def until_found(value: Any) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise LayoutError("until_found is not a number")
    if not 1 <= value <= MAX_UNTIL_FOUND:
        raise LayoutError("until_found is out of range")
    return value


def served_storage_paths(
    state_dir: str, read_text: Callable[[str], Optional[str]]
) -> set:
    """The storage paths this host serves: the mount points of its
    storage-side (and own) backup policies."""
    text = read_text(posixpath.join(state_dir, "backup", "policies.json"))
    try:
        policies = json.loads(text) if text else {}
    except ValueError:
        return set()
    if not isinstance(policies, dict):
        return set()
    return {
        posixpath.normpath(p["mount_point"])
        for p in policies.values()
        if isinstance(p, dict)
        and p.get("role") in STORAGE_ROLES
        and isinstance(p.get("mount_point"), str)
        and p["mount_point"].startswith("/")
    }


def storage_path(
    value: Any, state_dir: str, read_text: Callable[[str], Optional[str]]
) -> str:
    if not isinstance(value, str) or not value.startswith("/") or ".." in value:
        raise LayoutError("storage_path is not an absolute path")
    path = posixpath.normpath(value)
    if path not in served_storage_paths(state_dir, read_text):
        raise LayoutError(
            "storage_path is not a storage path this host serves for a backup "
            "policy (configure the backup target first)"
        )
    return path


def cloud_root(storage: str) -> str:
    return posixpath.join(storage, CLOUD_ROOT)


def account_dir(storage: str, name: str) -> str:
    return posixpath.join(cloud_root(storage), dir_name(name))


def sessions_root(state_dir: str) -> str:
    return posixpath.join(tool.tool_dir(state_dir), SESSIONS)


def session_dir(state_dir: str, name: str) -> str:
    return posixpath.join(sessions_root(state_dir), dir_name(name))


def account_job(
    parameters: Dict[str, Any],
    state_dir: str,
    read_text: Callable[[str], Optional[str]],
) -> Dict[str, Any]:
    """An account job's parameters, every one checked."""
    action = parameters.get("action")
    if action not in ACTIONS:
        raise LayoutError("unknown cloud backup action")
    storage = storage_path(parameters.get("storage_path"), state_dir, read_text)
    name = dir_name(parameters.get("dir_name"))
    job = {
        "run_id": run_id(parameters),
        "action": action,
        "apple_id": apple_id(parameters.get("apple_id")),
        "library": library(parameters.get("library") or "PrimarySync"),
        "dir_name": name,
        "storage_path": storage,
        "directory": account_dir(storage, name),
        "session_dir": session_dir(state_dir, name),
        "until_found": None,
    }
    if action == "download":
        job["until_found"] = until_found(parameters.get("until_found"))
    return job


# Every icloudpd 1.32.3 option that deletes anything: --auto-delete removes
# local files whose photo is in iCloud's "Recently Deleted", and the other two
# delete photos from iCloud itself.  Cloud backup is one-way -- iCloud to the
# storage host, nothing ever deleted on either side -- so none of them is ever
# passed, whatever the server sends (an older server could send auto_delete).
# Check this list again whenever tool.VERSION changes.
NEVER = ("--auto-delete", "--delete-after-download", "--keep-icloud-recent-days")


def argv(executable: str, job: Dict[str, Any]) -> list:
    """The icloudpd command line.  Never a password: icloudpd asks for it
    (``--password-provider console``) and the runner answers on its stdin.
    Never the web UI (no listener), never a keyring, and never an option in
    ``NEVER``: nothing here deletes, in iCloud or on the storage."""
    line = [
        executable,
        "--password-provider", "console",
        "--mfa-provider", "console",
        "--no-progress-bar",
        "--log-level", "debug",
        "--username", job["apple_id"],
        "--cookie-directory", job["session_dir"],
    ]  # fmt: skip
    action = job["action"]
    if action == "connect":
        return line + ["--auth-only"]
    if action == "libraries":
        return line + ["--list-libraries"]
    line += [
        "--directory", job["directory"],
        "--library", job["library"],
        "--folder-structure", FOLDER_STRUCTURE,
        # The original always, and Photos' edited version beside it for a photo
        # that was edited (icloudpd writes it only then); without it a crop or
        # an adjustment made in Photos would not be in the backup.
        "--size", "original",
        "--size", "adjusted",
        "--xmp-sidecar",
        "--keep-unicode-in-filenames",
        "--live-photo-mov-filename-policy", "suffix",
    ]  # fmt: skip
    if action == "download" and job["until_found"]:
        line += ["--until-found", str(job["until_found"])]
    if any(option in line for option in NEVER):
        raise LayoutError("an icloudpd option that deletes was refused")
    return line
