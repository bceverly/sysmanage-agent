# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""Equip this host for backups: install restate (ROADMAP Phase 24).

Where restate is packaged for a host the agent can back up:

* **Ubuntu 22.04, 24.04 and 26.04** -- restate's PPA, then ``apt-get install``.
* **FreeBSD (amd64)** -- the binary package attached to restate's newest
  GitHub release for this FreeBSD release, checked against the release's
  ``SHA256SUMS`` before ``pkg add``.  A FreeBSD host is a storage host only.

Everything that decides what runs is HERE: the server sends no URL, package
name or command, only "equip".  The download address is restate's own
release page, the file name is built from this host's release, and nothing is
installed unless its checksum matches the release's list.  Elsewhere (other
Linux distributions, and the BSDs the agent does not yet run backups on)
restate is built from source, which an operator does by hand.

Failures come back as reason codes the server translates: ``unsupported``,
``no_release`` (no package for this OS release), ``download_failed``,
``checksum_mismatch``, ``install_failed``.
"""

import asyncio
import hashlib
import os
import platform
import posixpath
import re
import urllib.request
from typing import Callable, Dict, List, Optional, Tuple

from src.sysmanage_agent.backup import restate_probe

PPA = "ppa:bceverly/restate"
UBUNTU_RELEASES = ("22.04", "24.04", "26.04")
RELEASES_URL = "https://github.com/bceverly/restate/releases"
FREEBSD_MACHINES = ("amd64", "x86_64")
# The equip directory under the agent's state dir; sudoers lets pkg add only
# a restate package from exactly here (installer/freebsd/sysmanage-agent.sudoers).
EQUIP_DIR = "equip"
MAX_PACKAGE_BYTES = 64 * 1024 * 1024
MAX_SUMS_BYTES = 64 * 1024
DOWNLOAD_SECONDS = 120
INSTALL_SECONDS = 600

_VERSION = r"[0-9]+(?:\.[0-9]+){3}"
_TAG = re.compile(r"/releases/tag/v(" + _VERSION + r")$")
_RELEASE = re.compile(r"^([0-9]+\.[0-9]+)")


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


def unavailable_reason(
    _lookup: Optional[Callable] = None,
    system: Optional[str] = None,
    os_release: Optional[Dict[str, str]] = None,
    machine: Optional[str] = None,
) -> Optional[str]:
    """None where this agent can equip the host, else ``wrong_platform``
    (a capability reason: not applicable here, so not a "limited" agent)."""
    system = system or platform.system()
    if system == "Linux":
        info = os_release if os_release is not None else _os_release()
        if info.get("ID") == "ubuntu" and info.get("VERSION_ID") in UBUNTU_RELEASES:
            return None
    elif system == "FreeBSD" and (machine or platform.machine()) in FREEBSD_MACHINES:
        return None
    return restate_probe.REASON_WRONG_PLATFORM


def ubuntu_steps() -> List[List[str]]:
    """The PPA (add-apt-repository refreshes the package lists), then restate."""
    return [["add-apt-repository", "-y", PPA], ["apt-get", "install", "-y", "restate"]]


def freebsd_release(release_text: str) -> Optional[str]:
    """``14.4`` from ``14.4-RELEASE-p8``."""
    match = _RELEASE.match(release_text or "")
    return match.group(1) if match else None


def asset_name(version: str, release: str) -> str:
    return f"restate-{version}-freebsd-{release}-amd64.pkg"


def parse_sums(text: str) -> Dict[str, str]:
    """``{file name: sha256}`` from a release's ``SHA256SUMS``."""
    found = {}
    for line in text.splitlines():
        fields = line.split()
        if len(fields) == 2 and re.fullmatch(r"[0-9a-f]{64}", fields[0]):
            found[posixpath.basename(fields[1])] = fields[0]
    return found


def version_from_url(url: str) -> Optional[str]:
    """The release version from the URL ``/releases/latest`` redirected to."""
    match = _TAG.search(url or "")
    return match.group(1) if match else None


def _fetch(url: str, limit: int) -> Tuple[str, bytes]:
    """``(final URL, body)``; raises OSError past ``limit`` bytes."""
    # Only ever restate's own https release URLs, built in this module.
    request = urllib.request.Request(url, headers={"User-Agent": "sysmanage-agent"})
    opened = urllib.request.urlopen(request, timeout=DOWNLOAD_SECONDS)  # nosec B310
    with opened as answer:
        body = answer.read(limit + 1)
        if len(body) > limit:
            raise OSError(f"{url} is larger than {limit} bytes")
        return answer.geturl(), body


def _privileged(argv: List[str]) -> List[str]:
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        return list(argv)
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


def _failed(reason: str, detail: str = "") -> Dict[str, object]:
    return {"success": False, "reason": reason, "detail": detail[-800:]}


async def equip(
    state_dir: str,
    run: Callable = _run,
    fetch: Callable = _fetch,
    system: Optional[str] = None,
    release_text: Optional[str] = None,
) -> Dict[str, object]:
    """Install restate on this host; ``{"success": True, "installed"}`` or a
    failure with its reason code and the tool's last output."""
    system = system or platform.system()
    if unavailable_reason(system=system):
        return _failed("unsupported")
    if system == "Linux":
        for argv in ubuntu_steps():
            code, out = await run(_privileged(argv))
            if code:
                return _failed("install_failed", out)
        return {"success": True, "installed": "ppa"}
    return await _equip_freebsd(
        state_dir, run, fetch, release_text or platform.release()
    )


async def _equip_freebsd(
    state_dir: str, run: Callable, fetch: Callable, release_text: str
) -> Dict[str, object]:
    release = freebsd_release(release_text)
    loop = asyncio.get_running_loop()
    try:
        final, _ = await loop.run_in_executor(
            None, fetch, RELEASES_URL + "/latest", 1 << 20
        )
        version = version_from_url(final)
        if not version:
            return _failed("download_failed", f"no release version in {final}")
        base = f"{RELEASES_URL}/download/v{version}/"
        _, sums = await loop.run_in_executor(
            None, fetch, base + "SHA256SUMS", MAX_SUMS_BYTES
        )
        listed = parse_sums(sums.decode("utf-8", "replace"))
        name = asset_name(version, release or "")
        if not release or name not in listed:
            offered = sorted(n for n in listed if "-freebsd-" in n)
            return _failed("no_release", ", ".join(offered))
        _, package = await loop.run_in_executor(
            None, fetch, base + name, MAX_PACKAGE_BYTES
        )
    except OSError as error:
        return _failed("download_failed", str(error))
    if hashlib.sha256(package).hexdigest() != listed[name]:
        return _failed("checksum_mismatch", name)
    folder = posixpath.join(state_dir, EQUIP_DIR)
    path = posixpath.join(folder, name)
    os.makedirs(folder, mode=0o755, exist_ok=True)
    try:
        with open(path, "wb") as handle:
            handle.write(package)
        os.chmod(path, 0o644)
        code, out = await run(_privileged(["pkg", "add", "-f", path]))
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass
    if code:
        return _failed("install_failed", out)
    return {"success": True, "installed": version}
