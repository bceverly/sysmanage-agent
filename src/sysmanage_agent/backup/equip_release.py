# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""Equip from restate's own GitHub release (``backup/equip.py`` decides when).

Each restate release carries a package for every system it is built for --
FreeBSD, OpenBSD and NetBSD (amd64), Alpine 3.21 to 3.24, RHEL 9 and 10 and
their rebuilds, openSUSE Leap 16 and Tumbleweed (x86_64 and aarch64) -- and a
``SHA256SUMS`` listing them all.  The agent:

1. follows ``/releases/latest`` to learn the newest version;
2. reads that release's ``SHA256SUMS`` (bounded);
3. names this host's package(s) from the version, its release and its
   processor -- never from anything the server sent -- and stops with
   ``no_release`` (listing what the release has for this system) when it is
   not there;
4. downloads each (bounded) and installs nothing unless every checksum
   matches;
5. writes them into its own state directory's ``equip/`` folder, installs
   them with the system's own tool together with the NFS client where it is
   a package (Alpine's ``nfs-utils``, openSUSE's ``nfs-client``, EL's
   ``nfs-utils``; the BSDs have it in the base system), and removes them.

OpenBSD's ``pkg_add`` refuses a file whose name is not the package's own, so
the OpenBSD package is saved as ``restate-VERSION.tgz``.  These packages are
signed by no key the systems know (hence ``-D unsigned``, ``--allow-untrusted``
and ``--allow-unsigned-rpm``): the release's checksums vouch for them.
"""

import asyncio
import hashlib
import os
import posixpath
import re
import urllib.request
from typing import Callable, Dict, List, Optional, Tuple

RELEASES_URL = "https://github.com/bceverly/restate/releases"
EQUIP_DIR = "equip"
MAX_PACKAGE_BYTES = 64 * 1024 * 1024
MAX_SUMS_BYTES = 64 * 1024
DOWNLOAD_SECONDS = 120

# The kinds installed from the release (equip.py's ``Target.kind``).
FREEBSD, OPENBSD, NETBSD = "freebsd", "openbsd", "netbsd"
ALPINE, EL, LEAP, TUMBLEWEED = "alpine", "el", "leap", "tumbleweed"
KINDS = (FREEBSD, OPENBSD, NETBSD, ALPINE, EL, LEAP, TUMBLEWEED)

_VERSION = r"[0-9]+(?:\.[0-9]+){3}"
_TAG = re.compile(r"/releases/tag/v(" + _VERSION + r")$")
_RELEASE = re.compile(r"^([0-9]+\.[0-9]+)")


def release_of(text: str) -> Optional[str]:
    """``14.4`` from ``14.4-RELEASE-p8``, ``3.24`` from ``3.24.1``."""
    match = _RELEASE.match(text or "")
    return match.group(1) if match else None


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


def asset_names(
    kind: str, version: str, release: str, arch: str, listed: Dict[str, str]
) -> Optional[List[str]]:
    """This host's package file(s) in the release, or None when the release
    has none for it."""
    names = {
        FREEBSD: [f"restate-{version}-freebsd-{release}-{arch}.pkg"],
        OPENBSD: [f"restate-{version}-openbsd-{release}-{arch}.tgz"],
        NETBSD: [f"restate-{version}-netbsd-{release}-{arch}.tgz"],
        ALPINE: [f"restate-{version}-r0-alpine{release}-{arch}.apk",
                 f"restate-doc-{version}-r0-alpine{release}-{arch}.apk"],  # fmt: skip
        EL: [f"restate-{version}-1.el{release}.{arch}.rpm"],
        LEAP: [f"restate-{version}-1.opensuseleap{release}.{arch}.rpm"],
    }.get(kind)
    if kind == TUMBLEWEED:
        # Named for the snapshot it was built on: the newest one.
        pattern = re.compile(
            rf"restate-{re.escape(version)}-1\.opensusetumbleweed[0-9]+\.{re.escape(arch)}\.rpm"
        )
        found = sorted(name for name in listed if pattern.fullmatch(name))
        names = found[-1:]
    if not names or any(name not in listed for name in names):
        return None
    return names


def offered(kind: str, listed: Dict[str, str]) -> str:
    """What the release has for this kind of system (the no_release detail)."""
    marks = {
        FREEBSD: "-freebsd-", OPENBSD: "-openbsd-", NETBSD: "-netbsd-",
        ALPINE: "-alpine", EL: ".el", LEAP: ".opensuseleap",
        TUMBLEWEED: ".opensusetumbleweed",
    }  # fmt: skip
    return ", ".join(sorted(n for n in listed if marks.get(kind, "\0") in n))


def local_name(kind: str, version: str, name: str) -> str:
    """The file name the package is saved under (OpenBSD's own name)."""
    return f"restate-{version}.tgz" if kind == OPENBSD else name


def install_steps(kind: str, paths: List[str]) -> List[List[str]]:
    """The commands that install the saved package(s) and the NFS client."""
    if kind == FREEBSD:
        return [["pkg", "add", "-f", paths[0]]]
    if kind == OPENBSD:
        # doas matches the command as typed: the absolute path its rule names.
        return [["/usr/sbin/pkg_add", "-D", "unsigned", paths[0]]]
    if kind == NETBSD:
        return [["/usr/sbin/pkg_add", paths[0]]]
    if kind == ALPINE:
        return [["apk", "add", "nfs-utils"],
                ["apk", "add", "--allow-untrusted", *paths]]  # fmt: skip
    if kind == EL:
        return [["dnf", "install", "-y", *paths, "nfs-utils"]]
    return [["zypper", "--non-interactive", "install", "--allow-unsigned-rpm",
             *paths, "nfs-client"]]  # fmt: skip


def fetch(url: str, limit: int) -> Tuple[str, bytes]:
    """``(final URL, body)``; raises OSError past ``limit`` bytes."""
    # Only ever restate's own https release URLs, built in this module.
    request = urllib.request.Request(url, headers={"User-Agent": "sysmanage-agent"})
    opened = urllib.request.urlopen(request, timeout=DOWNLOAD_SECONDS)  # nosec B310
    with opened as answer:
        body = answer.read(limit + 1)
        if len(body) > limit:
            raise OSError(f"{url} is larger than {limit} bytes")
        return answer.geturl(), body


def failed(reason: str, detail: str = "") -> Dict[str, object]:
    return {"success": False, "reason": reason, "detail": detail[-800:]}


async def _download(
    get: Callable, kind: str, release: str, arch: str
) -> Tuple[Optional[str], Dict[str, bytes], Optional[Dict[str, object]]]:
    """``(version, {name: package}, None)``, or a failure as the third item."""
    loop = asyncio.get_running_loop()
    final, _ = await loop.run_in_executor(None, get, RELEASES_URL + "/latest", 1 << 20)
    version = version_from_url(final)
    if not version:
        return None, {}, failed("download_failed", f"no release version in {final}")
    base = f"{RELEASES_URL}/download/v{version}/"
    _, sums = await loop.run_in_executor(None, get, base + "SHA256SUMS", MAX_SUMS_BYTES)
    listed = parse_sums(sums.decode("utf-8", "replace"))
    names = asset_names(kind, version, release, arch, listed)
    if not names:
        return None, {}, failed("no_release", offered(kind, listed))
    packages = {}
    for name in names:
        _, package = await loop.run_in_executor(
            None, get, base + name, MAX_PACKAGE_BYTES
        )
        if hashlib.sha256(package).hexdigest() != listed[name]:
            return None, {}, failed("checksum_mismatch", name)
        packages[name] = package
    return version, packages, None


async def install(  # pylint: disable=too-many-arguments
    kind: str,
    release: str,
    arch: str,
    state_dir: str,
    run: Callable,
    get: Callable,
    privileged: Callable[[List[str]], List[str]],
) -> Dict[str, object]:
    """Download, check and install this host's release package(s)."""
    try:
        version, packages, failure = await _download(get, kind, release, arch)
    except OSError as error:
        return failed("download_failed", str(error))
    if failure:
        return failure
    folder = posixpath.join(state_dir, EQUIP_DIR)
    os.makedirs(folder, mode=0o755, exist_ok=True)
    paths = [posixpath.join(folder, local_name(kind, version or "", name))
             for name in packages]  # fmt: skip
    try:
        for path, package in zip(paths, packages.values()):
            with open(path, "wb") as handle:
                handle.write(package)
            os.chmod(path, 0o644)
        for argv in install_steps(kind, paths):
            code, out = await run(privileged(argv))
            if code:
                return failed("install_failed", out)
    finally:
        for path in paths:
            try:
                os.unlink(path)
            except OSError:
                pass
    return {"success": True, "installed": version}
