# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""Yearly retention (restate 2.2.0.12, ``keep_yearly``).

The prune that honors it runs on the storage host, so the storage side
reports whether its restate has it; a restate without it is refused the
key (``tool_outdated``) rather than given a prune that ignores it.
"""

import pytest

from src.sysmanage_agent.backup import job_validation as v
from src.sysmanage_agent.backup import restate_contract as contract

OLD = {"version": "2.2.0.11", "job_keys": ["repository", "keep_last", "keep_monthly"]}
NEW = dict(OLD, version="2.2.0.12", job_keys=OLD["job_keys"] + ["keep_yearly"])


def test_a_storage_prune_may_keep_yearly_snapshots():
    job = v.check_job("storage", "prune", {"keep_last": 7, "keep_yearly": 5})
    assert job["keep_yearly"] == 5


@pytest.mark.parametrize("bad", [-1, "5; rm", 10001, True])
def test_keep_yearly_is_a_bounded_count(bad):
    with pytest.raises(ValueError):
        v.check_job("storage", "prune", {"keep_last": 7, "keep_yearly": bad})


def test_the_storage_side_reports_keep_yearly_only_when_restate_has_it():
    assert contract.storage_abilities(NEW) == ["keep_yearly"]
    assert not contract.storage_abilities(OLD)
    assert not contract.storage_abilities(None)


def test_an_old_restate_is_refused_the_key_not_given_a_weaker_prune():
    assert contract.unsupported_keys(OLD, ["keep_last", "keep_yearly"]) == [
        "keep_yearly"
    ]
    assert not contract.unsupported_keys(NEW, ["keep_last", "keep_yearly"])


def test_keep_yearly_renders_as_a_number():
    assert "keep_yearly = 5" in contract.render_job(
        {"command": "prune", "repository": "/r", "keep_yearly": 5}
    )
