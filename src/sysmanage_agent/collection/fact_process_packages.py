# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""The ``sysmanage_process_packages`` fact table: which package owns each
running process's executable.

WHY IT EXISTS. The Phase 21.2 S0 spike (2026-09-23) could express "a host has
critical CVEs" but not the rule that matters more: "a LISTENING service's own
package has a critical CVE". That needs pid -> executable -> owning package,
and no contract table carried the last hop (osquery has only
``rpm_package_files``, Linux-only and not a join anyone can make portably).

WHY PER PROCESS AND NOT PER FILE. A full file -> package table is hundreds of
thousands of rows on a desktop, collected every interval to answer a question
about a few hundred executables. The running processes ARE the question, so
the table is bounded by them.

EVERY ROW SAYS WHAT HAPPENED. ``state`` keeps the four answers apart, the way
``sysmanage_file_state`` does: ``owned``; ``unowned`` (no package claims it --
a binary built by hand, or an OS component outside any package manager);
``unreadable`` (the agent could not see the process's executable, typically
another user's process under an unprivileged agent); ``unresolved`` (the
executable is known but this host has no package manager we can ask). A rule
must never read "unreadable" as "unowned".
"""

import logging
import os
import platform
import posixpath
import shutil
import subprocess  # nosec B404
from typing import Dict, Iterable, Iterator, List, Optional, Tuple

logger = logging.getLogger(__name__)

OWNED = "owned"
UNOWNED = "unowned"
UNREADABLE = "unreadable"
UNRESOLVED = "unresolved"

# (package, version, package_manager)
Owner = Tuple[str, Optional[str], str]

_DPKG_INFO = "/var/lib/dpkg/info"
_DPKG_STATUS = "/var/lib/dpkg/status"
_BSD_PKG_DB = "/var/db/pkg"
# Where an OpenBSD / NetBSD package's +CONTENTS paths are rooted until a
# ``@cwd`` line says otherwise.
_BSD_DEFAULT_PREFIX = {"openbsd": "/usr/local", "netbsd": "/usr/pkg"}
_BREW_CELLARS = ("/opt/homebrew/Cellar/", "/usr/local/Cellar/")
_TIMEOUT = 10


def build_process_packages() -> List[Dict[str, object]]:
    """One row per running process that has an executable."""
    import psutil  # noqa: PLC0415

    procs: List[Tuple[int, Optional[str]]] = []
    for proc in psutil.process_iter(["pid"]):
        try:
            exe = proc.exe()
        except (psutil.AccessDenied, psutil.ZombieProcess):
            procs.append((proc.info["pid"], None))
            continue
        except psutil.NoSuchProcess:
            continue
        if exe:  # kernel threads have no executable; they are not rows
            procs.append((proc.info["pid"], exe))

    owners, manager = resolve_owners({p for _, p in procs if p})
    rows = []
    for pid, path in procs:
        if path is None:
            rows.append(_row(pid, None, None, UNREADABLE))
        elif manager is None:
            rows.append(_row(pid, path, None, UNRESOLVED))
        else:
            owner = owners.get(path)
            rows.append(_row(pid, path, owner, OWNED if owner else UNOWNED))
    return rows


def _row(pid, path, owner: Optional[Owner], state: str) -> Dict[str, object]:
    return {
        "pid": pid,
        "path": path,
        "package": owner[0] if owner else None,
        "version": owner[1] if owner else None,
        "package_manager": owner[2] if owner else None,
        "state": state,
    }


def resolve_owners(paths: Iterable[str]) -> Tuple[Dict[str, Owner], Optional[str]]:
    """({path: owner}, the manager consulted) -- manager None = none available."""
    paths = set(paths)
    system = platform.system().lower()
    if system == "linux":
        # A snap's executable lives under /snap/<name>/<revision>/, and no
        # dpkg or rpm database claims it -- ask the path, then the distro.
        snaps = _snap_owners(paths)
        rest = paths - set(snaps)
        if os.path.isdir(_DPKG_INFO):
            return {**_dpkg_owners(rest), **snaps}, "dpkg"
        if shutil.which("rpm"):
            return {**_rpm_owners(rest), **snaps}, "rpm"
        return (snaps, "snap") if snaps else ({}, None)
    if system == "freebsd" and shutil.which("pkg"):
        return _freebsd_owners(paths), "pkg"
    if system in _BSD_DEFAULT_PREFIX and os.path.isdir(_BSD_PKG_DB):
        return _bsd_contents_owners(paths, _BSD_DEFAULT_PREFIX[system]), "pkg_info"
    if system == "darwin":
        return _homebrew_owners(paths), "homebrew"
    return {}, None


def _snap_owners(paths: set) -> Dict[str, Owner]:
    """/snap/<name>/<revision>/... -- the path names the snap. ``version`` is
    left NULL: the path carries the REVISION, which is not the version string
    software inventory and CVE data use."""
    owners: Dict[str, Owner] = {}
    for path in paths:
        if path.startswith("/snap/"):
            parts = path[len("/snap/") :].split("/")
            if len(parts) >= 3 and parts[0]:
                owners[path] = (parts[0], None, "snap")
    return owners


def _usrmerge_variants(path: str) -> List[str]:
    """The spellings dpkg may have recorded for one executable.

    On a merged-/usr system /sbin is a symlink to /usr/sbin, so a process runs
    as /usr/sbin/sshd while an older package's .list still says /sbin/sshd
    (and the reverse).
    """
    variants = [path]
    if path.startswith("/usr/"):
        variants.append(path[4:])
    else:
        variants.append("/usr" + path)
    return variants


def _dpkg_owners(paths: set) -> Dict[str, Owner]:
    wanted = {v: p for p in paths for v in _usrmerge_variants(p)}
    found: Dict[str, str] = {}
    for name in os.listdir(_DPKG_INFO):
        if not name.endswith(".list"):
            continue
        package = name[: -len(".list")].split(":", 1)[0]  # drop ":amd64"
        try:
            with open(
                os.path.join(_DPKG_INFO, name), encoding="utf-8", errors="replace"
            ) as fh:
                for line in fh:
                    path = wanted.get(line.rstrip("\n"))
                    if path and path not in found:
                        found[path] = package
        except OSError:
            continue
    versions = _dpkg_versions(set(found.values()))
    return {path: (pkg, versions.get(pkg), "dpkg") for path, pkg in found.items()}


def _dpkg_versions(packages: set) -> Dict[str, str]:
    versions: Dict[str, str] = {}
    current = None
    try:
        with open(_DPKG_STATUS, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                if line.startswith("Package: "):
                    current = line[9:].strip()
                elif line.startswith("Version: ") and current in packages:
                    versions.setdefault(current, line[9:].strip())
    except OSError:
        pass
    return versions


def _run(cmd: List[str]) -> Optional[str]:
    try:
        result = subprocess.run(  # nosec B603
            cmd, capture_output=True, text=True, timeout=_TIMEOUT, check=False
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        logger.debug("%s failed: %s", cmd[0], exc)
        return None
    return result.stdout if result.returncode == 0 else None


def _rpm_owners(paths: set) -> Dict[str, Owner]:
    owners: Dict[str, Owner] = {}
    for path in paths:
        out = _run(["rpm", "-qf", "--qf", "%{NAME}\t%{VERSION}-%{RELEASE}\n", path])
        if out:  # a file shared by several packages: the first is reported
            name, _, version = out.splitlines()[0].partition("\t")
            owners[path] = (name, version or None, "rpm")
    return owners


def _freebsd_owners(paths: set) -> Dict[str, Owner]:
    owners: Dict[str, Owner] = {}
    for path in paths:
        out = _run(["pkg", "which", "-q", path])
        if out and out.strip():
            name, _, version = out.strip().rpartition("-")
            owners[path] = (name or out.strip(), version or None, "pkg")
    return owners


def _bsd_contents_owners(paths: set, prefix: str) -> Dict[str, Owner]:
    """OpenBSD / NetBSD: each package's +CONTENTS lists its files.

    A line that is not an ``@`` directive is a path relative to the current
    ``@cwd``, which starts at the platform's package prefix.
    """
    owners: Dict[str, Owner] = {}
    for entry in os.listdir(_BSD_PKG_DB):
        contents = os.path.join(_BSD_PKG_DB, entry, "+CONTENTS")
        name, _, version = entry.rpartition("-")
        owner = (name or entry, version or None, "pkg_info")
        try:
            with open(contents, encoding="utf-8", errors="replace") as fh:
                for full in _bsd_contents_paths(fh, prefix):
                    if full in paths and full not in owners:
                        owners[full] = owner
        except OSError:
            continue
    return owners


def _bsd_contents_paths(lines: Iterable[str], prefix: str) -> Iterator[str]:
    """Yield the absolute path of each file a +CONTENTS listing names."""
    cwd = prefix
    for line in lines:
        line = line.rstrip("\n")
        if line.startswith("@cwd "):
            cwd = line[5:].strip()
        elif line and not line.startswith("@"):
            # The package database's paths are POSIX on the host it
            # describes, whatever OS evaluates them.
            yield posixpath.join(cwd, line)


def _homebrew_owners(paths: set) -> Dict[str, Owner]:
    """A Homebrew executable lives at <cellar>/<formula>/<version>/...;
    anything else on macOS belongs to the OS, not to a package manager."""
    owners: Dict[str, Owner] = {}
    for path in paths:
        real = os.path.realpath(path)
        for cellar in _BREW_CELLARS:
            if real.startswith(cellar):
                parts = real[len(cellar) :].split("/")
                if len(parts) >= 2:
                    owners[path] = (parts[0], parts[1], "homebrew")
                break
    return owners
