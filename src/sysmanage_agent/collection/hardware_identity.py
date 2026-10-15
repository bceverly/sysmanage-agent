# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""
The PHYSICAL MACHINE's identity: SMBIOS system UUID plus system and baseboard
serial numbers (Phase 23.2).

An asset tag belongs to the machine, not to the OS installed on it -- a laptop
that multi-boots Windows, Ubuntu and OpenBSD is three hosts on ONE machine, and
a reinstalled OS lands back on the same machine.  So every OS must report the
same identity for the same hardware.

Measured on real hardware, 2026-10-11 (Phase 23.2 S0):

* Linux reads ``/sys/class/dmi/id/*``, mode 0400 root; NetBSD's
  ``machdep.dmi.system-uuid`` is root-only too.  Unprivileged there, the
  identity is reported UNREADABLE -- never guessed, never left blank.
* Windows (CIM), FreeBSD (``kenv``, one variable per call), OpenBSD
  (``sysctl``) and macOS (``ioreg``) read it unprivileged.
* OpenBSD prints the UUID's first three fields UNswapped
  (``4ce15669-7a34-b211-...``); Windows, FreeBSD and Linux print the SMBIOS 2.6
  order (``6956e14c-347a-11b2-...``).  ``canonical_uuid`` converts, and
  ``match_key`` makes the two forms one key, so an OS whose convention we have
  not measured still cannot split a machine.
* Apple Silicon has no SMBIOS: ``IOPlatformUUID`` is Apple's own hardware UUID,
  stable across reinstalls, and is used as-is.

The identity is NEVER a credential (Phase 22.0): any local user can read most
of it and a VM can be given any value.  It groups hosts; it does not
authenticate them.
"""

from __future__ import annotations

import json
import logging
import os
import platform
import re
import shutil
import subprocess  # nosec B404 -- fixed argv, no shell
from typing import Callable, Dict, Optional, Tuple

logger = logging.getLogger(__name__)

# Per-source outcome, reported with the identity so the server can say WHY a
# host has none ("needs privileged mode" is not the same as "no SMBIOS").
RAN = "ran"
ABSENT = "absent"
UNPRIVILEGED = "unprivileged"
FAILED = "failed"
PLACEHOLDER = "placeholder"

FIELDS = ("system_uuid", "system_serial", "board_serial")

_TIMEOUT = 20
_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")

# Values firmware ships when the vendor never filled the field in.  Two
# machines reporting one of these are NOT the same machine.
_PLACEHOLDER_UUIDS = frozenset(
    {
        "00000000-0000-0000-0000-000000000000",
        "ffffffff-ffff-ffff-ffff-ffffffffffff",
        "03000200-0400-0500-0006-000700080009",
        "00020003-0004-0005-0006-000700080009",
    }
)
_PLACEHOLDER_SERIALS = frozenset(
    {
        "to be filled by o.e.m.",
        "to be filled by oem",
        "default string",
        "system serial number",
        "chassis serial number",
        "base board serial number",
        "not specified",
        "not applicable",
        "none",
        "n/a",
        "na",
        "0",
        "0123456789",
        "123456789",
        "serial",
        "oem",
    }
)


# --------------------------------------------------------------------------
# normalization
# --------------------------------------------------------------------------


def swap_uuid(uuid: str) -> str:
    """The same UUID with its first three fields byte-swapped."""
    first, second, third, rest = uuid[0:8], uuid[9:13], uuid[14:18], uuid[18:]

    def rev(hexstr: str) -> str:
        return "".join(hexstr[i : i + 2] for i in range(len(hexstr) - 2, -2, -2))

    return f"{rev(first)}-{rev(second)}-{rev(third)}{rest}"


def canonical_uuid(
    raw: Optional[str], unswapped: bool = False
) -> Tuple[Optional[str], str]:
    """``(uuid in SMBIOS 2.6 order, status)`` from an OS's raw reading."""
    text = (raw or "").strip().lower().strip("{}")
    if not text:
        return None, ABSENT
    if not _UUID.match(text):
        return None, FAILED
    if text in _PLACEHOLDER_UUIDS or len(set(text.replace("-", ""))) == 1:
        return None, PLACEHOLDER
    return (swap_uuid(text) if unswapped else text), RAN


def canonical_serial(raw: Optional[str]) -> Tuple[Optional[str], str]:
    """``(serial, status)``: trimmed; vendor placeholders are not serials."""
    text = " ".join((raw or "").split())
    if not text:
        return None, ABSENT
    folded = text.lower()
    if folded in _PLACEHOLDER_SERIALS or len(set(folded)) == 1:
        return None, PLACEHOLDER
    return text, RAN


def match_key(uuid: Optional[str]) -> Optional[str]:
    """Byte-order-insensitive key: a UUID and its swapped form are one key."""
    if not uuid:
        return None
    return min(uuid, swap_uuid(uuid))


# --------------------------------------------------------------------------
# readers: raw strings plus a status override per field
# --------------------------------------------------------------------------


def _tool(name: str) -> str:
    """Absolute path: a non-login NetBSD PATH omits /sbin and /usr/sbin."""
    found = shutil.which(name)
    if found:
        return found
    for directory in ("/sbin", "/usr/sbin", "/usr/bin", "/bin"):
        candidate = os.path.join(directory, name)
        if os.path.isfile(candidate):
            return candidate
    return name


def _run(argv) -> Tuple[Optional[str], str]:
    """``(stdout, status)`` for one command; EPERM reads as unprivileged."""
    try:
        result = subprocess.run(  # nosec B603 -- fixed argv, no shell
            argv,
            capture_output=True,
            text=True,
            timeout=_TIMEOUT,
            check=False,
            # No console flash when the agent runs as a Windows service.
            creationflags=(
                subprocess.CREATE_NO_WINDOW if platform.system() == "Windows" else 0
            ),
        )
    except FileNotFoundError:
        return None, ABSENT
    except (OSError, subprocess.SubprocessError) as exc:
        logger.debug("identity: %s failed: %s", argv[0], exc)
        return None, FAILED
    if result.returncode != 0:
        err = (result.stderr or "").lower()
        if "not permitted" in err or "permission denied" in err:
            return None, UNPRIVILEGED
        if (
            not err.strip()  # kenv -q on an unset variable: exit 1, silent
            or "invalid" in err
            or "unknown oid" in err
            or "no such" in err
            or "not available" in err
        ):
            return None, ABSENT
        return None, FAILED
    return result.stdout.strip(), RAN


def _read_file(path: str) -> Tuple[Optional[str], str]:
    try:
        with open(path, encoding="utf-8", errors="replace") as handle:
            return handle.read().strip(), RAN
    except FileNotFoundError:
        return None, ABSENT
    except PermissionError:
        return None, UNPRIVILEGED
    except OSError:
        return None, FAILED


def _linux() -> Dict[str, Tuple[Optional[str], str]]:
    base = "/sys/class/dmi/id/"
    return {
        "system_uuid": _read_file(base + "product_uuid"),
        "system_serial": _read_file(base + "product_serial"),
        "board_serial": _read_file(base + "board_serial"),
        "vendor": _read_file(base + "sys_vendor"),
        "model": _read_file(base + "product_name"),
    }


def _sysctl(key: str) -> Tuple[Optional[str], str]:
    return _run([_tool("sysctl"), "-n", key])


def _openbsd() -> Dict[str, Tuple[Optional[str], str]]:
    return {
        "system_uuid": _sysctl("hw.uuid"),
        "system_serial": _sysctl("hw.serialno"),
        "board_serial": (None, ABSENT),  # OpenBSD exposes no baseboard serial
        "vendor": _sysctl("hw.vendor"),
        "model": _sysctl("hw.product"),
    }


def _netbsd() -> Dict[str, Tuple[Optional[str], str]]:
    return {
        "system_uuid": _sysctl("machdep.dmi.system-uuid"),
        "system_serial": _sysctl("machdep.dmi.system-serial"),
        "board_serial": _sysctl("machdep.dmi.board-serial"),
        "vendor": _sysctl("machdep.dmi.system-vendor"),
        "model": _sysctl("machdep.dmi.system-product"),
    }


def _kenv(key: str) -> Tuple[Optional[str], str]:
    return _run([_tool("kenv"), "-q", key])


def _freebsd() -> Dict[str, Tuple[Optional[str], str]]:
    return {
        "system_uuid": _kenv("smbios.system.uuid"),
        "system_serial": _kenv("smbios.system.serial"),
        "board_serial": _kenv("smbios.planar.serial"),
        "vendor": _kenv("smbios.system.maker"),
        "model": _kenv("smbios.system.product"),
    }


_WINDOWS_SCRIPT = (
    "$p = Get-CimInstance Win32_ComputerSystemProduct; "
    "$b = Get-CimInstance Win32_BaseBoard; "
    "[pscustomobject]@{uuid=$p.UUID; serial=$p.IdentifyingNumber; "
    "board=$b.SerialNumber; vendor=$p.Vendor; model=$p.Name} "
    "| ConvertTo-Json -Compress"
)


def _windows() -> Dict[str, Tuple[Optional[str], str]]:
    out, status = _run(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", _WINDOWS_SCRIPT]
    )
    if status != RAN or not out:
        return {f: (None, status) for f in (*FIELDS, "vendor", "model")}
    try:
        data = json.loads(out)
    except ValueError:
        return {f: (None, FAILED) for f in (*FIELDS, "vendor", "model")}

    def field(name: str) -> Tuple[Optional[str], str]:
        value = data.get(name)
        return (str(value), RAN) if value not in (None, "") else (None, ABSENT)

    return {
        "system_uuid": field("uuid"),
        "system_serial": field("serial"),
        "board_serial": field("board"),
        "vendor": field("vendor"),
        "model": field("model"),
    }


_IOREG_KEY = re.compile(
    r'"(IOPlatformUUID|IOPlatformSerialNumber|manufacturer|model)"\s*=\s*<?"([^"]*)"'
)


def _macos() -> Dict[str, Tuple[Optional[str], str]]:
    out, status = _run([_tool("ioreg"), "-rd1", "-c", "IOPlatformExpertDevice"])
    if status != RAN or not out:
        return {f: (None, status) for f in (*FIELDS, "vendor", "model")}
    found = dict(_IOREG_KEY.findall(out))

    def field(name: str) -> Tuple[Optional[str], str]:
        return (found[name], RAN) if found.get(name) else (None, ABSENT)

    return {
        "system_uuid": field("IOPlatformUUID"),
        "system_serial": field("IOPlatformSerialNumber"),
        "board_serial": (None, ABSENT),
        "vendor": (
            field("manufacturer") if found.get("manufacturer") else ("Apple Inc.", RAN)
        ),
        "model": field("model"),
    }


_READERS: Dict[str, Callable[[], Dict[str, Tuple[Optional[str], str]]]] = {
    "Linux": _linux,
    "Windows": _windows,
    "FreeBSD": _freebsd,
    "OpenBSD": _openbsd,
    "NetBSD": _netbsd,
    "Darwin": _macos,
}

# Operating systems whose UUID reading is NOT in SMBIOS 2.6 byte order.
_UNSWAPPED = frozenset({"OpenBSD"})


# --------------------------------------------------------------------------
# the report
# --------------------------------------------------------------------------


def collect_identity(system: Optional[str] = None) -> Dict[str, object]:
    """This machine's identity, normalized, with a status for every source."""
    system = system or platform.system()
    reader = _READERS.get(system)
    if reader is None:
        return {
            **dict.fromkeys(FIELDS),
            "vendor": None,
            "model": None,
            "match_key": None,
            "status": dict.fromkeys(FIELDS, ABSENT),
        }
    raw = reader()
    uuid, uuid_status = (
        canonical_uuid(raw["system_uuid"][0], unswapped=system in _UNSWAPPED)
        if raw["system_uuid"][1] == RAN
        else (None, raw["system_uuid"][1])
    )
    report: Dict[str, object] = {"system_uuid": uuid}
    status = {"system_uuid": uuid_status}
    for name in ("system_serial", "board_serial"):
        value, src = raw[name]
        serial, serial_status = canonical_serial(value) if src == RAN else (None, src)
        report[name] = serial
        status[name] = serial_status
    for name in ("vendor", "model"):
        value, src = raw.get(name, (None, ABSENT))
        report[name] = " ".join(value.split()) if src == RAN and value else None
    report["match_key"] = match_key(uuid)
    report["status"] = status
    return report
