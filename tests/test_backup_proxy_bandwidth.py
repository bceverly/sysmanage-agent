# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""restate-proxy bandwidth by the hour (server ROADMAP 25.5 limits, 25.7).

The server's rules reach the grant file only when this host's restate-proxy
reads ``bandwidth`` (its restate lists it in ``grant_keys``): an older proxy
refuses a grant with a key it does not know, which would stop every backup
through it.  The rules are checked again here as the proxy checks them."""

# pylint: disable=protected-access,redefined-outer-name,unused-import

import pytest

from src.sysmanage_agent.backup import proxy_access as access
from src.sysmanage_agent.backup import restate_contract as contract
from src.sysmanage_agent.backup.job_validation import PolicyError
from src.sysmanage_agent.operations.backup_operations import BackupOperations
from tests.backup_ops_support import agent, ops  # noqa: F401
from tests.test_backup_proxy import (  # noqa: F401
    HASH,
    HOST,
    REMOTE,
    _storage,
    remote,
)

LIMITS = {**REMOTE, "grant_keys": ["repository", "operations", "token_sha256",
                                   "expires", "label", "max_sessions", "bandwidth"]}  # fmt: skip
RULES = ["08-18 2MiB/s", "22-06 512KiB/s", "20MiB/s"]


def _grant(**extra):
    return {"client": HOST, "token_sha256": [HASH], "operations": ["append", "read"],
            **extra}  # fmt: skip


@pytest.fixture
def limited(remote, monkeypatch):
    monkeypatch.setattr(BackupOperations, "_features", staticmethod(lambda: LIMITS))
    return remote


def test_rules_are_checked_as_the_proxy_checks_them():
    assert access.check_bandwidth(RULES) == RULES
    assert access.check_bandwidth(["00-24 unlimited"]) == ["00-24 unlimited"]
    for bad in (
        [],
        ["2 MiB/s"],
        ["32KiB/s"],
        ["8-18 2MiB/s"],
        ["24-06 1MiB/s"],
        ["08-08 1MiB/s"],
        ["08-18 2MiB/s", "17-19 1MiB/s"],
        ["22-06 2MiB/s", "05-07 1MiB/s"],
        ["1MiB/s", "2MiB/s"],
        ["1MiB/s; rm -rf /"],
        ["1MiB/s\nrepository = /"],
        ["1MiB/s"] * 26,
        "1MiB/s",
    ):
        with pytest.raises(PolicyError):
            access.check_bandwidth(bad)


def test_a_grant_may_carry_rules_and_nothing_else_new():
    checked = access.check_storage_proxy(
        {"target_id": "9a000000-0000-4000-8000-0000000000d1", "enabled": True,
         "grants": [_grant(bandwidth=RULES)], "clients": [HOST]}  # fmt: skip
    )
    assert checked["grants"][0]["bandwidth"] == RULES
    with pytest.raises(PolicyError):
        access.check_storage_proxy(
            {"target_id": "9a000000-0000-4000-8000-0000000000d1", "enabled": True,
             "grants": [_grant(quota="1G")], "clients": [HOST]}  # fmt: skip
        )


def test_the_proxy_reads_limits_only_once_restate_says_so():
    assert access.limits_supported(LIMITS) is True
    assert access.limits_supported(REMOTE) is False
    assert access.limits_supported({"grant_keys": ["repository"]}) is False
    assert access.limits_supported(None) is False
    assert "proxy_bandwidth" in contract.storage_abilities(LIMITS)
    assert "proxy_bandwidth" not in contract.storage_abilities(REMOTE)


def test_rendered_rules_follow_the_tokens():
    text = access.render_grant("/srv/r/h-1", _grant(bandwidth=RULES), "t", limits=True)
    assert text.splitlines()[4:8] == [f"token_sha256 = {HASH}",
                                      "bandwidth = 08-18 2MiB/s",
                                      "bandwidth = 22-06 512KiB/s",
                                      "bandwidth = 20MiB/s"]  # fmt: skip
    assert "bandwidth" not in access.render_grant(
        "/srv/r/h-1", _grant(bandwidth=RULES), "t", limits=False
    )


@pytest.mark.asyncio
async def test_the_storage_host_writes_the_rules_when_its_proxy_reads_them(limited):
    await limited.backup_configure(_storage(grants=[_grant(bandwidth=RULES)]))
    text, _mode = limited.installed[access.grant_path(HOST)]
    assert "bandwidth = 08-18 2MiB/s\n" in text and "bandwidth = 20MiB/s\n" in text


@pytest.mark.asyncio
async def test_an_older_proxy_gets_the_grant_without_them(remote):
    await remote.backup_configure(_storage(grants=[_grant(bandwidth=RULES)]))
    text, _mode = remote.installed[access.grant_path(HOST)]
    assert "bandwidth" not in text and f"token_sha256 = {HASH}\n" in text
