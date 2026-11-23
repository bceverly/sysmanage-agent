# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""Compliance evidence on Windows (2026-11-23): what the CIS Windows 11 and
Windows Server 2022 benchmarks read.

THREE SECTIONS, each a flat ``{setting: value}`` map with lower-case keys
-----------------------------------------------------------------------
``win_registry``         ``hklm\\<key>\\<value>`` -> the value: every value
                         under ``HKLM\\SOFTWARE\\Policies`` (where Group
                         Policy writes) plus the keys in ``REGISTRY_KEYS``.
                         REG_DWORD/QWORD are ints, REG_MULTI_SZ is joined
                         with spaces, REG_BINARY is hex.
``win_security_policy``  secedit's ``[System Access]`` export (password and
                         lockout policy, guest account) -> its value.
``win_audit_policy``     audit subcategory -> its inclusion setting
                         ("Success and Failure", "No Auditing"...), from
                         ``auditpol /get /category:* /r``.

A section that could not be read is None and its rules score "not
collected", never "fail".  The agent service runs as LocalSystem, which
secedit and auditpol both need.

LIMITATION: auditpol names subcategories in the system's display language,
and the rules use the English names; on a non-English Windows the audit
rules read "not set".
"""

from __future__ import annotations

import csv
import io
import logging
import os
import subprocess  # nosec B404 -- fixed argv, no shell
import tempfile
from typing import Any, Dict, Optional, Tuple

logger = logging.getLogger(__name__)

RAN = "ran"
FAILED = "failed"
_TIMEOUT = 60
_POLICY_ROOT = "SOFTWARE\\Policies"
_MAX_VALUES = 20000

# The keys the rules read outside the Policies tree (each key's own values,
# not its subkeys), lower-case as the rules spell them.
REGISTRY_KEYS = (
    "software\\microsoft\\cryptography\\wintrust\\config",
    "software\\microsoft\\wcmsvc\\wifinetworkmanager\\config",
    "software\\microsoft\\windows nt\\currentversion\\winlogon",
    "software\\microsoft\\windows\\currentversion\\policies\\credui",
    "software\\microsoft\\windows\\currentversion\\policies\\explorer",
    "software\\microsoft\\windows\\currentversion\\policies\\laps",
    "software\\microsoft\\windows\\currentversion\\policies\\system",
    "software\\microsoft\\windows\\currentversion\\policies\\system\\audit",
    "software\\microsoft\\windows\\currentversion\\policies\\system\\credssp\\parameters",
    "software\\microsoft\\windows\\currentversion\\policies\\system\\kerberos\\parameters",
    "software\\microsoft\\windows\\currentversion\\policies\\system\\sam",
    "system\\currentcontrolset\\control\\lsa",
    "system\\currentcontrolset\\control\\lsa\\msv1_0",
    "system\\currentcontrolset\\control\\lsa\\pku2u",
    "system\\currentcontrolset\\control\\print",
    "system\\currentcontrolset\\control\\print\\providers\\lanman print services\\servers",
    "system\\currentcontrolset\\control\\productoptions",
    "system\\currentcontrolset\\control\\sam",
    "system\\currentcontrolset\\control\\securepipeservers\\winreg\\allowedexactpaths",
    "system\\currentcontrolset\\control\\securepipeservers\\winreg\\allowedpaths",
    "system\\currentcontrolset\\control\\securityproviders\\wdigest",
    "system\\currentcontrolset\\control\\session manager",
    "system\\currentcontrolset\\control\\session manager\\kernel",
    "system\\currentcontrolset\\policies\\earlylaunch",
    "system\\currentcontrolset\\services\\browser",
    "system\\currentcontrolset\\services\\eventlog\\security",
    "system\\currentcontrolset\\services\\ftpsvc",
    "system\\currentcontrolset\\services\\icssvc",
    "system\\currentcontrolset\\services\\iisadmin",
    "system\\currentcontrolset\\services\\irmon",
    "system\\currentcontrolset\\services\\lanmanserver\\parameters",
    "system\\currentcontrolset\\services\\lanmanworkstation\\parameters",
    "system\\currentcontrolset\\services\\ldap",
    "system\\currentcontrolset\\services\\lxssmanager",
    "system\\currentcontrolset\\services\\mrxsmb10",
    "system\\currentcontrolset\\services\\netbt\\parameters",
    "system\\currentcontrolset\\services\\netlogon\\parameters",
    "system\\currentcontrolset\\services\\ntds\\parameters",
    "system\\currentcontrolset\\services\\remoteaccess",
    "system\\currentcontrolset\\services\\rpclocator",
    "system\\currentcontrolset\\services\\sacsvr",
    "system\\currentcontrolset\\services\\simptcp",
    "system\\currentcontrolset\\services\\spooler",
    "system\\currentcontrolset\\services\\ssdpsrv",
    "system\\currentcontrolset\\services\\sshd",
    "system\\currentcontrolset\\services\\tcpip6\\parameters",
    "system\\currentcontrolset\\services\\tcpip\\parameters",
    "system\\currentcontrolset\\services\\upnphost",
    "system\\currentcontrolset\\services\\w3svc",
    "system\\currentcontrolset\\services\\wmpnetworksvc",
    "system\\currentcontrolset\\services\\wmsvc",
    "system\\currentcontrolset\\services\\xblauthmanager",
    "system\\currentcontrolset\\services\\xblgamesave",
    "system\\currentcontrolset\\services\\xboxgipsvc",
    "system\\currentcontrolset\\services\\xboxnetapisvc",
)

Section = Tuple[Optional[Any], str]


def registry_value(data: Any, kind: int) -> Any:
    """A registry value as the rules compare it."""
    import winreg  # pylint: disable=import-outside-toplevel,import-error

    if kind == winreg.REG_MULTI_SZ:
        return " ".join(str(item) for item in (data or []))
    if kind == winreg.REG_BINARY:
        return bytes(data or b"").hex()
    return data


def _read_key(winreg, path: str, found: Dict[str, Any], recurse: bool) -> None:
    access = winreg.KEY_READ | getattr(winreg, "KEY_WOW64_64KEY", 0)
    try:
        handle = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path, 0, access)
    except OSError:
        return  # not on this host: the rule decides what "missing" means
    with handle:
        index = 0
        while len(found) < _MAX_VALUES:
            try:
                name, data, kind = winreg.EnumValue(handle, index)
            except OSError:
                break
            found[f"hklm\\{path}\\{name}".lower()] = registry_value(data, kind)
            index += 1
        if not recurse:
            return
        index = 0
        while len(found) < _MAX_VALUES:
            try:
                child = winreg.EnumKey(handle, index)
            except OSError:
                break
            _read_key(winreg, path + "\\" + child, found, True)
            index += 1


def win_registry() -> Section:
    import winreg  # pylint: disable=import-outside-toplevel,import-error

    found: Dict[str, Any] = {}
    _read_key(winreg, _POLICY_ROOT, found, True)
    for path in REGISTRY_KEYS:
        _read_key(winreg, path, found, False)
    return found, RAN


def parse_secedit(text: str) -> Dict[str, Any]:
    """secedit's ``[System Access]`` section: ``Key = value`` -> value
    (ints where they are numbers, quotes dropped)."""
    found: Dict[str, Any] = {}
    in_section = False
    for raw in text.splitlines():
        line = raw.strip().lstrip("﻿")
        if line.startswith("["):
            in_section = line.lower() == "[system access]"
            continue
        if not in_section or "=" not in line:
            continue
        key, value = (part.strip() for part in line.split("=", 1))
        value = value.strip('"')
        try:
            found[key.lower()] = int(value)
        except ValueError:
            found[key.lower()] = value
    return found


def _run(argv) -> subprocess.CompletedProcess:
    return subprocess.run(  # nosec B603 -- fixed argv
        argv, capture_output=True, timeout=_TIMEOUT, check=False
    )


def win_security_policy() -> Section:
    handle, path = tempfile.mkstemp(suffix=".inf")
    os.close(handle)
    try:
        proc = _run(
            ["secedit", "/export", "/cfg", path, "/areas", "SECURITYPOLICY", "/quiet"]
        )
        if proc.returncode != 0:
            return None, FAILED
        with open(path, "rb") as fh:
            raw = fh.read()
        text = (
            raw.decode("utf-16")
            if raw[:2] in (b"\xff\xfe", b"\xfe\xff")
            else raw.decode("utf-8", "replace")
        )
        found = parse_secedit(text)
        return (found, RAN) if found else (None, FAILED)
    finally:
        try:
            os.remove(path)
        except OSError:
            pass


def parse_auditpol(text: str) -> Dict[str, str]:
    """``auditpol /r`` CSV: subcategory (lower-case) -> inclusion setting."""
    found: Dict[str, str] = {}
    for row in csv.DictReader(io.StringIO(text.lstrip("﻿"))):
        name = (row.get("Subcategory") or "").strip()
        if name:
            found[name.lower()] = (row.get("Inclusion Setting") or "").strip()
    return found


def win_audit_policy() -> Section:
    proc = _run(["auditpol", "/get", "/category:*", "/r"])
    if proc.returncode != 0:
        return None, FAILED
    found = parse_auditpol(proc.stdout.decode("utf-8", "replace"))
    return (found, RAN) if found else (None, FAILED)


SECTIONS = {
    "win_registry": win_registry,
    "win_security_policy": win_security_policy,
    "win_audit_policy": win_audit_policy,
}
