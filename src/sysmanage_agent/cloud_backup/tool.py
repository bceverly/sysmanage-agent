# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""The pinned icloudpd (MIT, github.com/icloud-photos-downloader).

The version and every checksum are pinned HERE: the server sends no URL,
version or file name, only "enable".  Upgrading is a new agent release that
changes the pin, followed by an operator pressing "Enable iCloud backup"
again -- never automatic.

* **Linux x86_64 and aarch64 (glibc)** -- the release's own executable for
  the processor, checked against its pinned SHA-256 before it is kept;
* **everywhere else this agent runs it** (FreeBSD, OpenBSD, NetBSD, Alpine,
  other Linux processors) -- a venv of its own, from the release's
  pure-Python wheel, checked against its pinned SHA-256 before ``pip``
  installs it.  The wheel pins its own dependencies exactly; ``pip`` takes
  them from PyPI.  It needs Python 3.10 to 3.13 on the host;
* **macOS and Windows** -- not offered (``wrong_platform``).

Both live in the agent's own state directory, owned by the agent's account:
installing needs no root.  Nothing here starts a network listener: the web
UI icloudpd can run is never asked for.
"""

import hashlib
import json
import os
import platform
import posixpath
import re
import shutil
import sys
import urllib.request
from typing import Any, Callable, Dict, List, Optional, Tuple

VERSION = "1.32.3"
RELEASE_URL = (
    "https://github.com/icloud-photos-downloader/icloud_photos_downloader"
    f"/releases/download/v{VERSION}/"
)
BINARIES = {
    "x86_64": (
        f"icloudpd-{VERSION}-linux-amd64",
        "cbe4de08f715a9b524795eccd75f33a97661cd27fa7f0282c58611d760fce093",
    ),
    "aarch64": (
        f"icloudpd-{VERSION}-linux-arm64",
        "b869453b8282f50c9e7e79d96d1a11f1f9d126e8017b395fa62fd04e1acd3031",
    ),
}
WHEEL = (
    f"icloudpd-{VERSION}-py3-none-any.whl",
    "47435bb6e221255d8db620b7e83b1a588b0794d7e41d32448ac9b6d141828357",
)
BINARY, VENV = "binary", "venv"
SUPPORTED_SYSTEMS = ("Linux", "FreeBSD", "OpenBSD", "NetBSD")
# icloudpd 1.32.3's own Requires-Python.
PYTHONS = ("python3.13", "python3.12", "python3.11", "python3.10")
MAX_DOWNLOAD = 128 * 1024 * 1024
DOWNLOAD_SECONDS = 300
PIP_SECONDS = 900
TOOL_DIR = "cloud_backup"
MARKER = "tool.json"

REASON_WRONG_PLATFORM = "wrong_platform"
REASON_MISSING_TOOL = "missing_tool"
_VERSION_LINE = re.compile(r"version:\s*([0-9][0-9A-Za-z.+-]*)")


class ToolError(Exception):
    """Installing failed; ``reason`` is a short code, the message the why."""

    def __init__(self, reason: str, message: str):
        super().__init__(message)
        self.reason = reason


def tool_dir(state_dir: str) -> str:
    return posixpath.join(state_dir, TOOL_DIR)


def _machine(machine: Optional[str] = None) -> str:
    value = (machine or platform.machine() or "").lower()
    return {"amd64": "x86_64", "arm64": "aarch64"}.get(value, value)


def _musl(exists: Callable[[str], bool] = os.path.exists) -> bool:
    return exists("/etc/alpine-release")


def method(
    system: Optional[str] = None,
    machine: Optional[str] = None,
    exists: Callable[[str], bool] = os.path.exists,
) -> Optional[str]:
    """``binary``, ``venv``, or None where icloudpd is not offered."""
    system = system or platform.system()
    if system not in SUPPORTED_SYSTEMS:
        return None
    if system == "Linux" and _machine(machine) in BINARIES and not _musl(exists):
        return BINARY
    return VENV


def enable_unavailable_reason(
    _lookup: Optional[Callable] = None, system: Optional[str] = None
) -> Optional[str]:
    """For the capability report: None where Enable can install it."""
    return None if method(system) else REASON_WRONG_PLATFORM


def installed(
    state_dir: str, read_text: Callable[[str], Optional[str]]
) -> Optional[Dict[str, Any]]:
    """What Enable installed (its marker), when its executable is there."""
    text = read_text(posixpath.join(tool_dir(state_dir), MARKER))
    try:
        found = json.loads(text) if text else None
    except ValueError:
        return None
    if not isinstance(found, dict):
        return None
    path = found.get("path")
    if not isinstance(path, str) or not os.access(path, os.X_OK):
        return None
    return found


def run_unavailable_reason(
    state_dir: str,
    read_text: Callable[[str], Optional[str]],
    system: Optional[str] = None,
) -> Optional[str]:
    """For the capability report: runs need Enable to have installed it."""
    if not method(system):
        return REASON_WRONG_PLATFORM
    return None if installed(state_dir, read_text) else REASON_MISSING_TOOL


def parse_version(text: str) -> Optional[str]:
    """``1.32.3`` from ``version:1.32.3, commit sha:...``."""
    match = _VERSION_LINE.search(text or "")
    return match.group(1).rstrip(",") if match else None


def fetch(name: str, limit: int = MAX_DOWNLOAD) -> bytes:
    """One file of the pinned release (bounded)."""
    url = RELEASE_URL + name
    request = urllib.request.Request(url, headers={"User-Agent": "sysmanage-agent"})
    # Only the pinned release's own https URLs, built in this module.
    # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected
    with urllib.request.urlopen(
        request, timeout=DOWNLOAD_SECONDS
    ) as answer:  # nosec B310
        body = answer.read(limit + 1)
    if len(body) > limit:
        raise ToolError("download_failed", f"{name} is larger than {limit} bytes")
    return body


def checked(body: bytes, name: str, digest: str) -> bytes:
    if hashlib.sha256(body).hexdigest() != digest:
        raise ToolError("checksum_mismatch", f"{name}: SHA-256 does not match the pin")
    return body


def _write(path: str, body: bytes, mode: int) -> None:
    handle = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    with os.fdopen(handle, "wb") as out:
        out.write(body)
    os.chmod(path, mode)


def find_python(which: Callable[[str], Optional[str]] = shutil.which) -> Optional[str]:
    """A Python icloudpd supports: this agent's own when it is one, else
    the newest on PATH."""
    if (3, 10) <= sys.version_info[:2] <= (3, 13):
        return sys.executable
    for name in PYTHONS:
        found = which(name)
        if found:
            return found
    return None


def venv_argvs(python: str, venv: str, wheel: str) -> List[List[str]]:
    pip = posixpath.join(venv, "bin", "pip")
    return [
        [python, "-m", "venv", "--clear", venv],
        [pip, "install", "--disable-pip-version-check", "--no-input", "--quiet", wheel],
    ]


def _marker(state_dir: str, found: Dict[str, Any]) -> None:
    path = posixpath.join(tool_dir(state_dir), MARKER)
    temporary = path + ".tmp"
    _write(temporary, json.dumps(found, sort_keys=True).encode("utf-8"), 0o600)
    os.replace(temporary, path)


def _remove_others(state_dir: str, keep: str) -> None:
    """Older installs (an upgrade) go once the new one works."""
    base = tool_dir(state_dir)
    for name in os.listdir(base):
        path = posixpath.join(base, name)
        if path == keep or not name.startswith(("icloudpd-", "venv-")):
            continue
        if os.path.isdir(path) and not os.path.islink(path):
            shutil.rmtree(path, ignore_errors=True)
        else:
            try:
                os.unlink(path)
            except OSError:
                pass


def install(
    state_dir: str,
    run: Callable[[List[str], int], Tuple[int, str]],
    get: Callable[[str], bytes] = fetch,
    system: Optional[str] = None,
    machine: Optional[str] = None,
    which: Callable[[str], Optional[str]] = shutil.which,
) -> Dict[str, Any]:
    """Install the pinned icloudpd (blocking; run it off the event loop).
    ``run(argv, timeout) -> (exit code, output)``.  Returns the marker:
    ``{"version", "method", "path"}``; raises ToolError."""
    how = method(system, machine)
    if how is None:
        raise ToolError(REASON_WRONG_PLATFORM, "icloudpd is not offered on this system")
    base = tool_dir(state_dir)
    os.makedirs(base, mode=0o700, exist_ok=True)
    os.chmod(base, 0o700)
    if how == BINARY:
        name, digest = BINARIES[_machine(machine)]
        path = posixpath.join(base, name)
        _write(path, checked(get(name), name, digest), 0o700)
    else:
        python = find_python(which)
        if python is None:
            raise ToolError(
                "no_python",
                "icloudpd needs Python 3.10 to 3.13 on this host; install one "
                "(for example: pkg install python311), then enable again",
            )
        name, digest = WHEEL
        wheel = posixpath.join(base, name)
        _write(wheel, checked(get(name), name, digest), 0o600)
        venv = posixpath.join(base, f"venv-{VERSION}")
        try:
            for argv in venv_argvs(python, venv, wheel):
                code, output = run(argv, PIP_SECONDS)
                if code != 0:
                    raise ToolError("install_failed", output[-2000:] or f"exit {code}")
        finally:
            os.unlink(wheel)
        path = posixpath.join(venv, "bin", "icloudpd")
    code, output = run([path, "--version"], 60)
    version = parse_version(output)
    if code != 0 or version != VERSION:
        raise ToolError(
            "tool_broken",
            f"icloudpd --version answered {code}: {output[-500:]}",
        )
    found = {"version": version, "method": how, "path": path}
    _marker(state_dir, found)
    _remove_others(state_dir, path if how == BINARY else posixpath.dirname(
        posixpath.dirname(path)))  # fmt: skip
    return found
