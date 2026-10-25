# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""Browsing a snapshot (restate ``list``) and what changed since one
(``status`` as a job), restate 2.1.0.4+: the jobs, their validation, and the
feature gates."""

import sys

import pytest

from src.sysmanage_agent.backup import job_builder as b
from src.sysmanage_agent.backup import job_validation as v
from src.sysmanage_agent.backup import restate_contract as contract

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="Unix-only feature")
PID = "3f2a0000-0000-4000-8000-0000000000c1"
REPO = "/mnt/backups/t14-1"
KW = {
    "repository": REPO,
    "state_dir": "/var/lib/sysmanage-agent",
    "group": "sysmanage-agent",
}


def test_a_listing_names_the_snapshot_and_one_directory():
    job = b.build_list_job({"policy_id": PID, "snapshot": "20261023T161149Z",
                            "path": "/etc/nginx/"}, **KW)  # fmt: skip
    assert job["command"] == "list"
    assert job["snapshot"] == f"{REPO}::20261023T161149Z"
    assert job["path"] == "/etc/nginx"
    assert job["result"].endswith(f"{PID}.list.result.json")
    assert b.build_list_job({"policy_id": PID, "snapshot": "s1"}, **KW)["path"] == "/"


@pytest.mark.parametrize(
    "path", ["etc", "/etc/../root", "/etc/\nx", 7, "/" + "a" * 5000]
)
def test_a_bad_listing_path_is_refused(path):
    with pytest.raises(v.PolicyError):
        b.build_list_job({"policy_id": PID, "snapshot": "s1", "path": path}, **KW)


def test_a_listing_needs_a_valid_snapshot():
    with pytest.raises(v.PolicyError):
        b.build_list_job({"policy_id": PID, "snapshot": "../x"}, **KW)


def test_status_defaults_to_the_newest_snapshot():
    newest = b.build_status_job({"policy_id": PID}, **KW)
    assert newest == {**newest, "command": "status", "repository": REPO, "root": "/"}
    assert "snapshot" not in newest
    named = b.build_status_job({"policy_id": PID, "snapshot": "s1"}, **KW)
    assert named["snapshot"] == f"{REPO}::s1" and "repository" not in named


def test_status_never_carries_classification_keys():
    """restate 2.2.0.2 classifies by the capture's recorded rules; a `rules`
    key would replace them (and 2.2.0.1 refused it with exit 2)."""
    job = b.build_status_job({"policy_id": PID}, **KW)
    assert not {"rules", "all", "one_file_system"} & set(job)


def test_abilities_come_only_from_what_restate_lists():
    assert contract.host_abilities({"commands": ["status", "capture"]}) == []
    new = {"job_commands": ["capture", "status", "list"],
           "result_members": ["capture.cache", "diff.changes", "list"]}  # fmt: skip
    assert contract.host_abilities(new) == ["list", "status", "cache"]
    assert contract.host_abilities(None) == []
