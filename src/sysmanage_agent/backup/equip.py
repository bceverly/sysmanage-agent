# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""Equip this host for backups: install restate and the NFS client (Phase 24).

Where restate is packaged, by how this agent installs it:

* **Ubuntu 22.04, 24.04 and 26.04** -- restate's PPA, then ``apt-get install``
  of restate and the NFS client (``nfs-common``): a backed-up host mounts its
  storage over NFS, and without the client it never can (production,
  nextcloud, 2026-10-29).  Installing both again is harmless, so Equip also
  fixes a host whose restate is current but whose NFS client is missing.
* **Fedora** -- restate's COPR (``dnf copr enable bceverly/restate``, after
  the copr command itself), then ``dnf install`` of restate and ``nfs-utils``.
* **RHEL 9 and 10 and their rebuilds** (AlmaLinux, Rocky, CentOS Stream,
  Oracle Linux), **openSUSE Leap 16 / SLE 16 and Tumbleweed**, **Alpine 3.21
  to 3.24**, **FreeBSD, OpenBSD and NetBSD (amd64)** -- the package attached
  to restate's newest GitHub release for this system, release and processor,
  checked against the release's ``SHA256SUMS`` before it is installed with
  the NFS client (``backup/equip_release.py``).  The BSDs have the NFS client
  in the base system.
* **macOS** -- restate's Homebrew formula (``bceverly/tap/restate``), run as
  the user who owns Homebrew (it refuses root); where Homebrew is not
  installed, Equip is not offered.  The NFS client is in the base system.

Not offered: Debian and every other Linux (restate is built from source
there, by hand), and Windows (restate does not run there) -- reason
``wrong_platform``.

Everything that decides what runs is HERE: the server sends no URL, package
name or command, only "equip".  Downloads come only from restate's own
release page, file names are built from this host's release, and nothing is
installed unless its checksum matches the release's list.

Failures come back as reason codes the server translates: ``unsupported``,
``no_release`` (no package for this OS release), ``download_failed``,
``checksum_mismatch``, ``install_failed``.
"""

import asyncio
import os
import platform
from typing import Callable, Dict, List, NamedTuple, Optional, Tuple

# Unix-only: the agent also runs on Windows, where pwd does not exist.
try:
    import pwd
except ImportError:  # pragma: no cover - Windows
    pwd = None  # type: ignore[assignment]

from src.sysmanage_agent.backup import equip_release as release
from src.sysmanage_agent.backup import restate_probe

# Kept here for callers and tests that name them on this module.
RELEASES_URL = release.RELEASES_URL
EQUIP_DIR = release.EQUIP_DIR
parse_sums = release.parse_sums
version_from_url = release.version_from_url
freebsd_release = release.release_of
_fetch = release.fetch

PPA = "ppa:bceverly/restate"
COPR = "bceverly/restate"
FORMULA = "bceverly/tap/restate"
NFS_CLIENT_PACKAGE = "nfs-common"
UBUNTU_RELEASES = ("22.04", "24.04", "26.04")
EL_IDS = ("rhel", "almalinux", "rocky", "centos", "ol")
EL_RELEASES = ("9", "10")
SUSE_LEAP_IDS = ("opensuse-leap", "sles", "sled", "sle")
ALPINE_RELEASES = ("3.21", "3.22", "3.23", "3.24")
LINUX_ARCHES = {"x86_64": "x86_64", "amd64": "x86_64",
                "aarch64": "aarch64", "arm64": "aarch64"}  # fmt: skip
BSD_MACHINES = ("amd64", "x86_64")
HOMEBREW = ("/opt/homebrew/bin/brew", "/usr/local/bin/brew")
INSTALL_SECONDS = 600

UBUNTU, FEDORA, MACOS = "ubuntu", "fedora", "macos"


class Target(NamedTuple):
    """How this host is equipped: the kind, its release, its processor."""

    kind: str
    release: str
    arch: str


def _os_release(path: str = "/etc/os-release") -> Dict[str, str]:
    found: Dict[str, str] = {}
    try:
        with open(path, "r", encoding="utf-8") as handle:
            for line in handle:
                key, _, value = line.partition("=")
                found[key.strip()] = value.strip().strip("\"'")
    except OSError:
        pass
    return found


def _linux_target(info: Dict[str, str], machine: str) -> Optional[Target]:
    ident, version = info.get("ID", ""), info.get("VERSION_ID", "")
    arch = LINUX_ARCHES.get(machine, "")
    major = version.split(".")[0]
    if ident == "ubuntu" and version in UBUNTU_RELEASES:
        return Target(UBUNTU, version, arch)
    if not arch:
        return None
    if ident == "fedora":
        return Target(FEDORA, version, arch)
    if ident in EL_IDS and major in EL_RELEASES:
        return Target(release.EL, major, arch)
    if ident == "opensuse-tumbleweed":
        return Target(release.TUMBLEWEED, "", arch)
    if ident in SUSE_LEAP_IDS and major == "16":
        return Target(release.LEAP, "16.0", arch)
    if ident == "alpine" and release.release_of(version) in ALPINE_RELEASES:
        return Target(release.ALPINE, release.release_of(version) or "", arch)
    return None


def target(
    system: str,
    os_release: Optional[Dict[str, str]] = None,
    machine: Optional[str] = None,
    release_text: Optional[str] = None,
    exists: Callable = os.path.exists,
) -> Optional[Target]:
    """How this host is equipped, or None where it cannot be."""
    machine = machine or platform.machine()
    if system == "Linux":
        info = os_release if os_release is not None else _os_release()
        return _linux_target(info, machine)
    if system in ("FreeBSD", "OpenBSD", "NetBSD") and machine in BSD_MACHINES:
        found = release.release_of(release_text or platform.release()) or ""
        return Target(system.lower(), found, "amd64")
    if system == "Darwin" and any(exists(path) for path in HOMEBREW):
        return Target(MACOS, "", machine)
    return None


def unavailable_reason(
    _lookup: Optional[Callable] = None,
    system: Optional[str] = None,
    os_release: Optional[Dict[str, str]] = None,
    machine: Optional[str] = None,
    exists: Callable = os.path.exists,
) -> Optional[str]:
    """None where this agent can equip the host, else ``wrong_platform``
    (a capability reason: not applicable here, so not a "limited" agent)."""
    found = target(system or platform.system(), os_release, machine, exists=exists)
    return None if found else restate_probe.REASON_WRONG_PLATFORM


def ubuntu_steps() -> List[List[str]]:
    """The PPA (add-apt-repository refreshes the package lists), then restate
    and the NFS client."""
    return [
        ["add-apt-repository", "-y", PPA],
        ["apt-get", "install", "-y", "restate", NFS_CLIENT_PACKAGE],
    ]


def fedora_steps() -> List[List[str]]:
    """The copr command (dnf-plugins-core, or dnf5's plugins), restate's
    COPR, then restate and the NFS client."""
    return [
        ["dnf", "install", "-y", "dnf-command(copr)"],
        ["dnf", "-y", "copr", "enable", COPR],
        ["dnf", "install", "-y", "restate", "nfs-utils"],
    ]


def asset_name(version: str, release_name: str) -> str:
    """FreeBSD's package for this release (amd64)."""
    return f"restate-{version}-freebsd-{release_name}-amd64.pkg"


def _privileged(argv: List[str], system: Optional[str] = None) -> List[str]:
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        return list(argv)
    if (system or platform.system()) == "OpenBSD":
        return ["doas", "-n"] + list(argv)
    return ["sudo", "-n"] + list(argv)


async def _run(argv: List[str]) -> Tuple[int, str]:
    proc = await asyncio.create_subprocess_exec(
        *argv, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT, cwd="/"
    )
    try:
        out, _ = await asyncio.wait_for(proc.communicate(), INSTALL_SECONDS)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        return 124, f"{argv[0]} did not finish in {INSTALL_SECONDS} seconds"
    return proc.returncode or 0, out.decode("utf-8", "replace")


_failed = release.failed


async def _steps(run: Callable, steps: List[List[str]], installed: str):
    for argv in steps:
        code, out = await run(_privileged(argv))
        if code:
            return _failed("install_failed", out)
    return {"success": True, "installed": installed}


def homebrew_argv(
    exists: Callable = os.path.exists, stat: Callable = os.stat
) -> Optional[List[str]]:
    """``brew install`` of restate's formula as Homebrew's owner (brew
    refuses root), or None when that cannot be done."""
    brew = next((path for path in HOMEBREW if exists(path)), None)
    if brew is None:
        return None
    argv = [brew, "install", FORMULA]
    if not (hasattr(os, "geteuid") and os.geteuid() == 0):
        return argv  # the agent's own user, which must own Homebrew
    owner = pwd.getpwuid(stat(brew).st_uid).pw_name if pwd else ""
    if not owner or owner == "root":
        return None
    return ["sudo", "-u", owner, "-H"] + argv


async def _equip_macos(run: Callable, exists: Callable, stat: Callable):
    argv = homebrew_argv(exists, stat)
    if argv is None:
        return _failed("unsupported", "Homebrew is not installed, or is root's")
    code, out = await run(argv)
    if code:
        return _failed("install_failed", out)
    return {"success": True, "installed": "homebrew"}


async def equip(  # pylint: disable=too-many-arguments
    state_dir: str,
    run: Callable = _run,
    fetch: Callable = release.fetch,
    system: Optional[str] = None,
    release_text: Optional[str] = None,
    exists: Callable = os.path.exists,
    stat: Callable = os.stat,
) -> Dict[str, object]:
    """Install restate (and the NFS client) on this host; ``{"success": True,
    "installed"}`` or a failure with its reason code and the tool's last
    output."""
    system = system or platform.system()
    found = target(system, release_text=release_text, exists=exists)
    if found is None:
        return _failed("unsupported")
    if found.kind == UBUNTU:
        return await _steps(run, ubuntu_steps(), "ppa")
    if found.kind == FEDORA:
        return await _steps(run, fedora_steps(), "copr")
    if found.kind == MACOS:
        return await _equip_macos(run, exists, stat)
    return await release.install(
        found.kind, found.release, found.arch, state_dir, run, fetch,
        lambda argv: _privileged(argv, system),
    )  # fmt: skip
