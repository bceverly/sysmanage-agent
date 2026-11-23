# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""Windows compliance evidence (2026-11-23): secedit, auditpol and the
registry, in the shapes the CIS Windows rules read."""

import subprocess
import sys
import types
from unittest.mock import patch

from src.sysmanage_agent.collection import compliance_evidence as ce
from src.sysmanage_agent.collection import compliance_evidence_windows as win

SECEDIT = (
    "[Unicode]\r\nUnicode=yes\r\n[System Access]\r\nMinimumPasswordAge = 0\r\n"
    "MaximumPasswordAge = 42\r\nMinimumPasswordLength = 14\r\nPasswordComplexity = 1\r\n"
    'LockoutBadCount = 0\r\nNewAdministratorName = "Administrator"\r\n'
    "EnableGuestAccount = 0\r\n[Event Audit]\r\nAuditSystemEvents = 0\r\n"
)
AUDITPOL = (
    "Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,"
    "Exclusion Setting\r\n"
    "WIN11,System,Security State Change,{0CCE9210-69AE-11D9-BED3-505054503030},Success,\r\n"
    "WIN11,System,Logon,{0CCE9215-69AE-11D9-BED3-505054503030},Success and Failure,\r\n"
    "WIN11,System,File Share,{0CCE9224-69AE-11D9-BED3-505054503030},No Auditing,\r\n"
)


def test_secedit_system_access_only_with_numbers_as_ints():
    found = win.parse_secedit("﻿" + SECEDIT)
    assert found["minimumpasswordlength"] == 14 and found["lockoutbadcount"] == 0
    assert found["newadministratorname"] == "Administrator"
    assert "auditsystemevents" not in found


def test_secedit_export_is_read_as_utf16(tmp_path):
    def fake_run(argv, **_kw):
        with open(argv[3], "wb") as fh:
            fh.write(SECEDIT.encode("utf-16"))
        return subprocess.CompletedProcess(argv, 0, b"", b"")

    with patch.object(win.subprocess, "run", side_effect=fake_run):
        found, status = win.win_security_policy()
    assert status == win.RAN and found["passwordcomplexity"] == 1


def test_a_failed_export_is_not_collected():
    done = subprocess.CompletedProcess([], 5, b"", b"Access is denied")
    with patch.object(win.subprocess, "run", return_value=done):
        assert win.win_security_policy() == (None, win.FAILED)


def test_auditpol_subcategories_by_name():
    done = subprocess.CompletedProcess([], 0, AUDITPOL.encode(), b"")
    with patch.object(win.subprocess, "run", return_value=done):
        found, status = win.win_audit_policy()
    assert status == win.RAN
    assert found == {"security state change": "Success", "logon": "Success and Failure",
                     "file share": "No Auditing"}  # fmt: skip


class _Key:
    def __init__(self, values, children):
        self.values, self.children = values, children

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False


def _fake_winreg(tree):
    mod = types.SimpleNamespace(
        HKEY_LOCAL_MACHINE="HKLM", KEY_READ=1, KEY_WOW64_64KEY=2, REG_SZ=1,
        REG_DWORD=4, REG_MULTI_SZ=7, REG_BINARY=3)  # fmt: skip

    def open_key(_root, path, _res, _access):
        if path.lower() not in tree:
            raise OSError("missing")
        return _Key(*tree[path.lower()])

    def enum_value(key, i):
        if i >= len(key.values):
            raise OSError
        return key.values[i]

    def enum_key(key, i):
        if i >= len(key.children):
            raise OSError
        return key.children[i]

    mod.OpenKey, mod.EnumValue, mod.EnumKey = open_key, enum_value, enum_key
    return mod


def test_registry_reads_the_policies_tree_and_the_named_keys():
    tree = {
        "software\\policies": ([], ["Microsoft"]),
        "software\\policies\\microsoft": ([], ["WindowsFirewall"]),
        "software\\policies\\microsoft\\windowsfirewall": ([("EnableFirewall", 1, 4)], []),
        "system\\currentcontrolset\\control\\lsa": ([("LmCompatibilityLevel", 5, 4)], []),
        "system\\currentcontrolset\\control\\productoptions": ([("ProductType", "WinNT", 1)], []),
        "system\\currentcontrolset\\control\\securepipeservers\\winreg\\allowedexactpaths": (
            [("Machine", ["System\\A", "System\\B"], 7)], []),
    }  # fmt: skip
    with patch.dict(sys.modules, {"winreg": _fake_winreg(tree)}):
        found, status = win.win_registry()
    assert status == win.RAN
    assert (
        found["hklm\\software\\policies\\microsoft\\windowsfirewall\\enablefirewall"]
        == 1
    )
    assert (
        found["hklm\\system\\currentcontrolset\\control\\lsa\\lmcompatibilitylevel"]
        == 5
    )
    assert (
        found["hklm\\system\\currentcontrolset\\control\\productoptions\\producttype"]
        == "WinNT"
    )
    assert found["hklm\\system\\currentcontrolset\\control\\securepipeservers\\winreg"
                 "\\allowedexactpaths\\machine"] == "System\\A System\\B"  # fmt: skip


def test_windows_reports_its_own_sections():
    collectors = {name: (lambda: ({}, win.RAN)) for name in win.SECTIONS}
    with patch.object(win, "SECTIONS", collectors):
        report = ce.collect_compliance_evidence("Windows")
    assert report["platform"] == "Windows"
    assert set(report["sections"]) == {
        "win_registry",
        "win_security_policy",
        "win_audit_policy",
    }
