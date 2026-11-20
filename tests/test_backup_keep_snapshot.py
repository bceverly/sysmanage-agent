# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""Legal hold (27.2; restate 3.4.0.0, ``keep_snapshot``).

A prune on the storage host keeps the held snapshots whatever its keep-*
rules say.  The storage side reports whether its restate has it, and a
restate without it is refused the key -- never given a prune that would
drop a held snapshot.
"""

import pytest

from src.sysmanage_agent.backup import job_validation as v
from src.sysmanage_agent.backup import restate_contract as contract

OLD = {"version": "3.3.0.2", "job_keys": ["repository", "keep_last"]}
NEW = dict(OLD, version="3.4.0.0", job_keys=OLD["job_keys"] + ["keep_snapshot"])


def test_a_storage_prune_may_keep_named_snapshots():
    job = v.check_job(
        "storage", "prune",
        {"keep_last": 7, "keep_snapshot": ["20261101T010000Z", "20261102T010000Z"]},
    )  # fmt: skip
    assert job["keep_snapshot"] == ["20261101T010000Z", "20261102T010000Z"]


@pytest.mark.parametrize("bad", ["20261101T010000Z", [""], ["../x"], ["a b"], [5],
                                 ["x"] * (v.MAX_LIST + 1)])  # fmt: skip
def test_held_names_are_a_list_of_snapshot_names(bad):
    with pytest.raises(ValueError):
        v.check_job("storage", "prune", {"keep_last": 7, "keep_snapshot": bad})


def test_the_storage_side_reports_keep_snapshot_only_when_restate_has_it():
    assert "keep_snapshot" in contract.storage_abilities(NEW)
    assert "keep_snapshot" in contract.storage_abilities({"keep_snapshot": True})
    assert "keep_snapshot" not in contract.storage_abilities(OLD)


def test_an_old_restate_is_refused_the_key():
    assert contract.unsupported_keys(OLD, ["keep_last", "keep_snapshot"]) == [
        "keep_snapshot"
    ]
    assert not contract.unsupported_keys(NEW, ["keep_last", "keep_snapshot"])


def test_each_held_snapshot_is_its_own_line():
    text = contract.render_job({"command": "prune", "repository": "/r", "keep_last": 7,
                                "keep_snapshot": ["S1", "S2"]})  # fmt: skip
    assert "keep_snapshot = S1\nkeep_snapshot = S2" in text
