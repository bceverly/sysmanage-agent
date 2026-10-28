# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""A storage host re-sends its audit outside any job -- at start, daily and on
Request Host Data -- so a fixed check reaches the server (production,
2026-10-27: an "NFSv4 is not served" error two days stale)."""

import asyncio

from src.sysmanage_agent.backup import storage_reaudit

POLICIES = {
    "p-storage": {"role": "storage", "repository": "/srv/backups/restate/h-1"},
    "p-host": {"role": "host", "repository": "/mnt/backups/h-1"},
    "p-broken": {"role": "storage", "repository": "/srv/backups/restate/h-2"},
    "junk": "not a policy",
}


def _audit(policy):
    if policy["repository"].endswith("h-2"):
        return None  # the audit could not run
    return [{"code": "nfs_v4", "level": "ok", "params": {}}]


def test_only_storage_policies_with_an_audit_are_sent():
    sent = []

    async def send(message_type, data):
        sent.append((message_type, data))

    count = asyncio.run(storage_reaudit.send_all(POLICIES, _audit, send))
    assert count == 1
    assert sent == [
        (
            "backup_storage_audit",
            {
                "policy_id": "p-storage",
                "storage_audit": [{"code": "nfs_v4", "level": "ok", "params": {}}],
            },
        )
    ]


def test_the_restate_version_travels_for_every_policy():
    """A host whose runs never reached restate (production 2026-10-28) kept
    an old version on the server; the daily message now carries it, alone
    for a host policy and beside the audit for a storage policy."""
    sent = []

    async def send(message_type, data):
        sent.append(data)

    count = asyncio.run(
        storage_reaudit.send_all(POLICIES, _audit, send, version="2.2.0.12")
    )
    assert count == 3
    by_policy = {d["policy_id"]: d for d in sent}
    assert by_policy["p-host"] == {"policy_id": "p-host", "restate_version": "2.2.0.12"}
    assert by_policy["p-storage"]["restate_version"] == "2.2.0.12"
    assert "storage_audit" in by_policy["p-storage"]
    # an audit that could not run still reports the version
    assert by_policy["p-broken"] == {
        "policy_id": "p-broken",
        "restate_version": "2.2.0.12",
    }


def test_a_failing_reaudit_is_logged_and_scheduled_again(monkeypatch):
    calls, scheduled = [], []

    async def reaudit():
        calls.append(1)
        raise RuntimeError("storage host busy")

    monkeypatch.setattr(storage_reaudit, "schedule",
                        lambda fn, delay=0: scheduled.append(delay))  # fmt: skip
    run = storage_reaudit._run_then_reschedule  # pylint: disable=protected-access
    asyncio.run(run(reaudit))
    assert calls == [1]
    assert scheduled == [
        storage_reaudit.INTERVAL_SECONDS
    ]  # tomorrow, despite the failure


def test_schedule_sets_a_timer_not_a_task():
    fired = []

    async def main():
        async def reaudit():
            fired.append(1)
            return 0

        storage_reaudit.schedule(reaudit, delay=0)
        await asyncio.sleep(0.05)  # the timer fires, the re-audit runs
        others = [t for t in asyncio.all_tasks()
                  if t is not asyncio.current_task() and not t.done()]  # fmt: skip
        assert not others  # nothing left running to wait for

    asyncio.run(main())
    assert fired == [1]


def test_schedule_outside_an_event_loop_does_nothing():
    storage_reaudit.schedule(lambda: None)  # no running loop: no error, no timer
