# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""An unprivileged agent's ``pro status`` cannot reach the Livepatch daemon
and reports livepatch as ``warning``; the UI then showed Livepatch disabled
on hosts where it was working (beast and nas, 2026-10-16).  Status queries
now go through ``sudo -n`` (allowlisted), falling back to the plain call."""

import json
import subprocess
from unittest.mock import patch

from src.sysmanage_agent.collection.os_info_collection import OSInfoCollector

MOD = "src.sysmanage_agent.collection.os_info_collection"
ARGV = ["pro", "status", "--all", "--format", "json"]


def _done(argv, rc=0, out="{}"):
    return subprocess.CompletedProcess(argv, rc, out, "")


def test_unprivileged_queries_go_through_sudo():
    calls = []

    def fake_run(argv, **_kw):
        calls.append(argv)
        return _done(argv, out='{"ok": true}')

    with patch(f"{MOD}.os.geteuid", return_value=1001, create=True), patch(
        f"{MOD}.shutil.which", return_value="/usr/bin/sudo"
    ), patch(f"{MOD}.subprocess.run", side_effect=fake_run):
        result = OSInfoCollector()._run_as_root_if_allowed(ARGV)
    assert calls == [["sudo", "-n"] + ARGV]
    assert result.stdout == '{"ok": true}'


def test_a_refused_sudo_falls_back_to_the_plain_call():
    calls = []

    def fake_run(argv, **_kw):
        calls.append(argv)
        return _done(argv, rc=1, out="") if argv[0] == "sudo" else _done(argv)

    with patch(f"{MOD}.os.geteuid", return_value=1001, create=True), patch(
        f"{MOD}.shutil.which", return_value="/usr/bin/sudo"
    ), patch(f"{MOD}.subprocess.run", side_effect=fake_run):
        OSInfoCollector()._run_as_root_if_allowed(ARGV)
    assert calls == [["sudo", "-n"] + ARGV, ARGV]


def test_root_needs_no_sudo():
    with patch(f"{MOD}.os.geteuid", return_value=0, create=True), patch(
        f"{MOD}.subprocess.run", side_effect=lambda argv, **_kw: _done(argv)
    ) as run:
        OSInfoCollector()._run_as_root_if_allowed(ARGV)
    assert run.call_args.args[0] == ARGV


def test_warning_means_enabled_and_keeps_the_raw_value():
    service = OSInfoCollector()._parse_single_ubuntu_pro_service(
        {
            "name": "livepatch",
            "available": "yes",
            "entitled": "yes",
            "status": "warning",
        },
        0,
        1,
    )
    assert service["status"] == "enabled"
    assert service["raw_status"] == "warning"


def test_the_recorded_beast_answer_as_root_reads_enabled():
    """beast's own ``sudo pro status`` answer for livepatch, 2026-10-16."""
    payload = json.dumps(
        {
            "attached": True,
            "services": [
                {
                    "name": "livepatch",
                    "available": "yes",
                    "entitled": "yes",
                    "status": "enabled",
                },
                {
                    "name": "esm-apps",
                    "available": "yes",
                    "entitled": "yes",
                    "status": "enabled",
                },
            ],
        }
    )
    info = {"services": []}
    collector = OSInfoCollector()
    with patch.object(collector, "_get_livepatch_info", return_value=None):
        collector._parse_ubuntu_pro_output(payload, info)
    assert {s["name"]: s["status"] for s in info["services"]} == {
        "livepatch": "enabled",
        "esm-apps": "enabled",
    }
