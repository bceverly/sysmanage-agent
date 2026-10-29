# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""Can this host back up with restate?  (The "backup" capability probe.)

The answer has three outcomes, each a reason code the server understands:

* not Linux or FreeBSD          -> ``wrong_platform`` (Linux runs jobs
  through a systemd unit, FreeBSD -- a storage host -- under daemon(8); see
  ``job_runner``; restate's other BSD and macOS builds are not driven yet)
* no ``restate`` executable     -> ``missing_tool`` (install it)
* restate present but too old   -> ``tool_outdated`` (upgrade it): on Linux
  the ``restate-job@.service`` unit is missing; or ``restate features
  --json`` fails, or it reports a major version below 2 or no job keys
* Linux with no NFS client      -> ``missing_nfs_client`` (Equip installs
  it): the host could never mount its backup storage

ONE DELIBERATE EXCEPTION to the capability probes' "no subprocess" rule: the
version can only be learned by asking restate.  The answer is cached per
binary (path, size, mtime), so restate is asked once per installed version,
not on every registration -- an upgrade changes the mtime and is asked again.
"""

import os
import shutil
import subprocess  # nosec B404 -- fixed argv, no shell
import threading
from typing import Any, Callable, Dict, Optional, Tuple

from src.sysmanage_agent.backup import host_mount
from src.sysmanage_agent.backup import job_runner
from src.sysmanage_agent.backup import restate_contract as contract

REASON_MISSING_TOOL = "missing_tool"
REASON_WRONG_PLATFORM = "wrong_platform"
REASON_TOOL_OUTDATED = "tool_outdated"
REASON_MISSING_NFS_CLIENT = "missing_nfs_client"

PROBE_TIMEOUT_SECONDS = 10

_lock = threading.Lock()
_cache: Dict[Tuple[str, int, int], Optional[Dict[str, Any]]] = {}


def _ask(executable: str) -> Optional[Dict[str, Any]]:
    try:
        completed = subprocess.run(  # nosec B603 -- fixed argv
            [executable, "features", "--json"],
            capture_output=True,
            text=True,
            timeout=PROBE_TIMEOUT_SECONDS,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if completed.returncode != 0:
        return None
    return contract.parse_features(completed.stdout)


def features(executable: str, ask: Callable = _ask) -> Optional[Dict[str, Any]]:
    """restate's feature object, cached per installed binary."""
    try:
        stat = os.stat(executable)
    except OSError:
        return None
    key = (os.path.realpath(executable), stat.st_size, int(stat.st_mtime))
    with _lock:
        if key in _cache:
            return _cache[key]
    found = ask(executable)
    with _lock:
        _cache[key] = found
    return found


def forget() -> None:
    """Drop the cache (tests; and after this agent installs restate)."""
    with _lock:
        _cache.clear()


# Where restate installs when it is not on the service PATH: FreeBSD's rc
# PATH is /sbin:/bin:/usr/sbin:/usr/bin, and a port or ``gmake install``
# puts restate in /usr/local/sbin.
FALLBACK_PATHS = ("/usr/sbin/restate", "/usr/local/sbin/restate")


def locate(
    lookup: Callable = shutil.which, exists: Callable = os.path.exists
) -> Optional[str]:
    """restate's path: on the service PATH (systemd's default includes
    /usr/sbin, where the package installs it), else a fixed install
    location, else None."""
    found = lookup("restate")
    if found:
        return found
    return next((path for path in FALLBACK_PATHS if exists(path)), None)


def unavailable_reason(
    lookup: Callable = shutil.which,
    system: Optional[str] = None,
    ask: Callable = _ask,
    unit_exists: Callable = os.path.exists,
    exists: Callable = os.path.exists,
    nfs_exists: Callable = os.path.exists,
) -> Optional[str]:
    """Why this host cannot run backups, or None when it can."""
    runner = job_runner.runner_for(system)
    if runner is None:
        return REASON_WRONG_PLATFORM
    executable = locate(lookup, exists)
    if not executable:
        return REASON_MISSING_TOOL
    if runner == job_runner.SYSTEMD and not contract.unit_installed(unit_exists):
        return REASON_TOOL_OUTDATED
    if not contract.features_usable(features(executable, ask)):
        return REASON_TOOL_OUTDATED
    if runner == job_runner.SYSTEMD and host_mount.nfs_client_missing(
        "Linux", nfs_exists
    ):
        return REASON_MISSING_NFS_CLIENT
    return None
