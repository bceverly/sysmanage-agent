# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""Machine identity across all six OS families (Phase 23.2 S1).

The raw outputs below were RECORDED on real hardware on 2026-10-11 and then
SCRAMBLED: every hex digit and serial character was replaced, keeping the
structure that matters (field widths, the OpenBSD byte order, Lenovo's
``11b2`` marker).  Real serial numbers do not belong in a public repository.
"""

import json
import subprocess
from unittest.mock import mock_open, patch

import pytest

from src.sysmanage_agent.collection import hardware_identity as hid

# One scrambled machine as each OS reports it.  The SAME laptop reads
# 1a2b3c4d-5e6f-11b2-... on Linux/Windows/FreeBSD and 4d3c2b1a-6f5e-b211-...
# on OpenBSD, which prints the first three fields unswapped.
CANONICAL = "1a2b3c4d-5e6f-11b2-a85c-0f1e2d3c4b5a"
OPENBSD_RAW = "4d3c2b1a-6f5e-b211-a85c-0f1e2d3c4b5a"


def _proc(stdout="", returncode=0, stderr=""):
    return subprocess.CompletedProcess([], returncode, stdout=stdout, stderr=stderr)


# --------------------------------------------------------------------------
# normalization
# --------------------------------------------------------------------------


def test_openbsd_byte_order_is_converted_to_the_smbios_order():
    assert hid.swap_uuid(OPENBSD_RAW) == CANONICAL
    assert hid.canonical_uuid(OPENBSD_RAW, unswapped=True) == (CANONICAL, hid.RAN)


def test_the_match_key_is_the_same_for_both_byte_orders():
    assert hid.match_key(CANONICAL) == hid.match_key(OPENBSD_RAW)
    assert hid.match_key(None) is None


@pytest.mark.parametrize(
    "raw",
    [
        "00000000-0000-0000-0000-000000000000",
        "FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF",
        "03000200-0400-0500-0006-000700080009",
    ],
)
def test_placeholder_uuids_are_not_identities(raw):
    assert hid.canonical_uuid(raw) == (None, hid.PLACEHOLDER)


@pytest.mark.parametrize(
    "raw", ["To Be Filled By O.E.M.", "Default string", "0", "XXXXXXXX", " "]
)
def test_placeholder_or_empty_serials_are_not_serials(raw):
    value, status = hid.canonical_serial(raw)
    assert value is None and status in (hid.PLACEHOLDER, hid.ABSENT)


def test_a_malformed_uuid_is_a_failure_not_an_identity():
    assert hid.canonical_uuid("not-a-uuid") == (None, hid.FAILED)


def test_windows_braces_and_case_are_normalized():
    assert hid.canonical_uuid("{1A2B3C4D-5E6F-11B2-A85C-0F1E2D3C4B5A}") == (
        CANONICAL,
        hid.RAN,
    )


# --------------------------------------------------------------------------
# per-OS readers, from (scrambled) recorded outputs
# --------------------------------------------------------------------------


def test_linux_privileged():
    files = {
        "/sys/class/dmi/id/product_uuid": CANONICAL + "\n",
        "/sys/class/dmi/id/product_serial": "PF9ZQ7X1\n",
        "/sys/class/dmi/id/board_serial": "L8KM31N00QP\n",
        "/sys/class/dmi/id/sys_vendor": "LENOVO\n",
        "/sys/class/dmi/id/product_name": "21QG002HUS\n",
    }
    with patch(
        "builtins.open", side_effect=lambda p, **k: mock_open(read_data=files[p])()
    ):
        report = hid.collect_identity("Linux")
    assert report["system_uuid"] == CANONICAL
    assert report["system_serial"] == "PF9ZQ7X1"
    assert report["status"] == {f: hid.RAN for f in hid.FIELDS}


def test_linux_unprivileged_reports_unreadable_not_blank():
    def opener(path, **_kw):
        if path.endswith(("product_uuid", "product_serial", "board_serial")):
            raise PermissionError(path)
        return mock_open(read_data="LENOVO\n")()

    # No sudo on this host: the root-only files stay unreadable.  (With sudo,
    # see test_hardware_identity_sudo.py.)
    with patch("builtins.open", side_effect=opener), patch.object(
        hid.shutil, "which", return_value=None
    ):
        report = hid.collect_identity("Linux")
    assert report["system_uuid"] is None and report["match_key"] is None
    assert report["status"] == {f: hid.UNPRIVILEGED for f in hid.FIELDS}
    assert report["vendor"] == "LENOVO"


def test_openbsd():
    outputs = {
        "hw.uuid": OPENBSD_RAW,
        "hw.serialno": "PF9ZQ7X1",
        "hw.vendor": "LENOVO",
        "hw.product": "20L6S0U300",
    }
    with patch.object(
        hid.subprocess, "run", side_effect=lambda argv, **k: _proc(outputs[argv[-1]])
    ):
        report = hid.collect_identity("OpenBSD")
    assert report["system_uuid"] == CANONICAL
    assert report["status"]["board_serial"] == hid.ABSENT


def test_netbsd_unprivileged_and_absent_serials():
    def run(argv, **_kw):
        key = argv[-1]
        if key == "machdep.dmi.system-uuid":
            return _proc(
                returncode=1,
                stderr="sysctl: machdep.dmi.system-uuid: Operation not permitted",
            )
        if key.endswith("serial"):
            return _proc(
                returncode=1, stderr=f"sysctl: third level name '{key}' is invalid"
            )
        return _proc("QEMU")

    with patch.object(hid.subprocess, "run", side_effect=run):
        report = hid.collect_identity("NetBSD")
    assert report["status"] == {
        "system_uuid": hid.UNPRIVILEGED,
        "system_serial": hid.ABSENT,
        "board_serial": hid.ABSENT,
    }


def test_freebsd_kenv_one_variable_per_call():
    outputs = {
        "smbios.system.uuid": CANONICAL,
        "smbios.system.serial": "PC9QX2LM",
        "smbios.planar.serial": "L1ZX83K00TT",
        "smbios.system.maker": "LENOVO",
        "smbios.system.product": "20KES1J10E",
    }
    with patch.object(
        hid.subprocess, "run", side_effect=lambda argv, **k: _proc(outputs[argv[-1]])
    ):
        report = hid.collect_identity("FreeBSD")
    assert report["system_uuid"] == CANONICAL
    assert report["board_serial"] == "L1ZX83K00TT"


def test_freebsd_unset_variable_is_absent():
    with patch.object(hid.subprocess, "run", return_value=_proc(returncode=1)):
        report = hid.collect_identity("FreeBSD")
    assert report["status"]["system_uuid"] == hid.ABSENT


def test_windows():
    out = json.dumps(
        {
            "uuid": CANONICAL.upper(),
            "serial": "PW9XQZ11",
            "board": "W8CQ17A02ZX",
            "vendor": "LENOVO",
            "model": "21BYS03Y00",
        }
    )
    with patch.object(hid.subprocess, "run", return_value=_proc(out)):
        report = hid.collect_identity("Windows")
    assert report["system_uuid"] == CANONICAL
    assert report["board_serial"] == "W8CQ17A02ZX"


def test_macos_apple_silicon():
    out = (
        '      "IOPlatformSerialNumber" = "C09QX7184Z2K"\n'
        '      "model" = <"MacBookAir10,1">\n'
        '      "IOPlatformUUID" = "A1B2C3D4-E5F6-57D6-A84B-0A1B2C3D4E5F"\n'
    )
    with patch.object(hid.subprocess, "run", return_value=_proc(out)):
        report = hid.collect_identity("Darwin")
    assert report["system_uuid"] == "a1b2c3d4-e5f6-57d6-a84b-0a1b2c3d4e5f"
    assert report["model"] == "MacBookAir10,1"
    assert report["vendor"] == "Apple Inc."


def test_a_missing_tool_is_absent_and_an_unknown_os_has_no_identity():
    with patch.object(hid.subprocess, "run", side_effect=FileNotFoundError):
        assert hid.collect_identity("FreeBSD")["status"]["system_uuid"] == hid.ABSENT
    assert hid.collect_identity("Plan9")["match_key"] is None


def test_the_t480_multi_boot_case_lands_on_one_key():
    # The same laptop booted into Windows, Ubuntu and OpenBSD: three hosts,
    # one machine.
    keys = {
        hid.match_key(hid.canonical_uuid(CANONICAL.upper())[0]),  # Windows
        hid.match_key(hid.canonical_uuid(CANONICAL)[0]),  # Linux
        hid.match_key(hid.canonical_uuid(OPENBSD_RAW, unswapped=True)[0]),  # OpenBSD
        hid.match_key(hid.canonical_uuid(OPENBSD_RAW)[0]),  # an OS we did not model
    }
    assert len(keys) == 1
