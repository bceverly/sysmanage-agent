# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""Linux machine identity on an unprivileged (packaged) agent.

/sys/class/dmi/id/{product_uuid,product_serial,board_serial} are mode 0400
root, so every packaged agent showed "No machine identified" (production,
2026-10-17).  The three files are read through ``sudo -n cat`` with exact
paths on the allowlist; a refused sudo says so precisely."""

import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest

from src.sysmanage_agent.collection import hardware_identity as hi

MOD = "src.sysmanage_agent.collection.hardware_identity"
UUID = "aefddc6d-e186-3d17-aa70-0123456789ab"
REFUSAL = "sudo: a password is required\n"


def _denied_files(path):
    """Every root-only DMI file refuses; vendor/model read fine."""
    name = path.rsplit("/", 1)[-1]
    if name in hi._ROOT_ONLY_DMI:  # pylint: disable=protected-access
        return None, hi.UNPRIVILEGED
    return {"sys_vendor": "LENOVO", "product_name": "ThinkPad"}.get(name), hi.RAN


def _sudo(values):
    calls = []

    def fake_run(argv, **_kw):
        calls.append(argv)
        name = argv[-1].rsplit("/", 1)[-1]
        if values == "refused":
            return subprocess.CompletedProcess(argv, 1, "", REFUSAL)
        return subprocess.CompletedProcess(argv, 0, values[name] + "\n", "")

    return calls, fake_run


@pytest.fixture
def unprivileged():
    with patch(f"{MOD}._read_file", side_effect=_denied_files), patch(
        f"{MOD}._tool", side_effect=lambda name: f"/usr/bin/{name}"
    ), patch(f"{MOD}.shutil.which", return_value="/usr/bin/sudo"):
        yield


def test_unprivileged_reads_the_three_files_through_sudo_cat(unprivileged):
    calls, fake = _sudo(
        {"product_uuid": UUID, "product_serial": "PF9ZQ7X1", "board_serial": "L1HF"}
    )
    with patch(f"{MOD}.subprocess.run", side_effect=fake):
        report = hi.collect_identity("Linux")
    assert sorted(calls) == sorted(
        ["sudo", "-n", "/usr/bin/cat", f"/sys/class/dmi/id/{name}"]
        for name in ("product_uuid", "product_serial", "board_serial")
    )
    assert report["system_uuid"] == UUID
    assert report["system_serial"] == "PF9ZQ7X1"
    assert report["status"]["system_uuid"] == hi.RAN
    assert report["vendor"] == "LENOVO"  # readable files never go through sudo


def test_a_refused_sudo_is_needs_sudo_rule_not_unprivileged(unprivileged):
    _calls, fake = _sudo("refused")
    with patch(f"{MOD}.subprocess.run", side_effect=fake):
        report = hi.collect_identity("Linux")
    assert report["system_uuid"] is None
    assert set(report["status"].values()) == {hi.NEEDS_SUDO_RULE}


def test_no_sudo_at_all_stays_unprivileged():
    with patch(f"{MOD}._read_file", side_effect=_denied_files), patch(
        f"{MOD}._tool", side_effect=lambda name: f"/usr/bin/{name}"
    ), patch(f"{MOD}.shutil.which", return_value=None), patch(
        f"{MOD}.subprocess.run", side_effect=AssertionError("must not run")
    ):
        report = hi.collect_identity("Linux")
    assert set(report["status"].values()) == {hi.UNPRIVILEGED}


def test_root_reads_the_files_directly():
    with patch(
        f"{MOD}._read_file",
        side_effect=lambda path: (
            UUID if path.endswith("product_uuid") else "X1",
            hi.RAN,
        ),
    ), patch(f"{MOD}.subprocess.run", side_effect=AssertionError("no sudo as root")):
        report = hi.collect_identity("Linux")
    assert report["system_uuid"] == UUID


def test_the_status_code_fits_the_servers_16_character_cap():
    # backend/services/machine_identity.py keeps str(v)[:16].
    assert len(hi.NEEDS_SUDO_RULE) <= 16


@pytest.mark.parametrize("distro", ["ubuntu", "centos", "opensuse"])
def test_every_linux_sudoers_allows_exactly_the_three_files(distro):
    text = Path(f"installer/{distro}/sysmanage-agent.sudoers").read_text(
        encoding="utf-8"
    )
    assert "SYSMANAGE_DMI_READ" in text
    for name in ("product_uuid", "product_serial", "board_serial"):
        assert f"/usr/bin/cat /sys/class/dmi/id/{name}" in text
    assert "/sys/class/dmi/id/*" not in text  # no wildcard reads
