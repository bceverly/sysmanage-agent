# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""Re-send a storage host's audit outside any job (ROADMAP 24.1 / 24.5).

The server's picture of a storage host's set-up -- NFSv4, the exports, the
append-only layout -- only refreshed when it sent the backup configuration or
a storage-side job ended.  A check fixed since (a new agent, or a repair made
by hand on the NAS) kept showing the old finding for as long as neither
happened: production, 2026-10-27, an "NFSv4 is not served" error two days
stale while every capture failed before reaching the storage host.

So a storage host also sends a fresh audit when the agent starts, once a day,
and when an operator clicks Request Host Data.

The same message carries the restate version, for host policies too (version
only): the server records which restate a host runs only from finished jobs,
so a host whose runs were all refused before restate started (an old agent's
``mount_failed``, production 2026-10-28) kept showing -- and writing job files
for -- the restate it had days before.  A changed version makes the server
re-send the job files.
"""

import asyncio
import logging
from typing import Any, Awaitable, Callable, Dict, List, Optional, Set

MESSAGE_TYPE = "backup_storage_audit"
INTERVAL_SECONDS = 24 * 3600
# The first one waits for the connection the agent is still making.
FIRST_DELAY_SECONDS = 60

logger = logging.getLogger(__name__)

Audit = Callable[[Dict[str, Any]], Optional[List[Dict[str, Any]]]]
Send = Callable[[str, Dict[str, Any]], Awaitable[None]]


async def send_all(
    policies: Dict[str, Any], audit: Audit, send: Send, version: Optional[str] = None
) -> int:
    """Audit every storage policy's repository and send each result, with the
    restate ``version`` when known; a host policy sends the version alone.
    How many were sent.  The audit runs commands, so it runs off the event
    loop."""
    loop = asyncio.get_running_loop()
    sent = 0
    for policy_id, policy in sorted(policies.items()):
        if not isinstance(policy, dict):
            continue
        payload: Dict[str, Any] = {"policy_id": policy_id}
        if version:
            payload["restate_version"] = version
        if policy.get("role") == "storage":
            found = await loop.run_in_executor(None, audit, policy)
            if found is None and not version:
                continue  # the audit could not run; _audit logged why
            if found is not None:
                payload["storage_audit"] = found
        elif policy.get("role") != "host" or not version:
            continue
        await send(MESSAGE_TYPE, payload)
        sent += 1
    return sent


# A strong reference to each running re-audit (an unreferenced task can be
# garbage-collected mid-run).
_running: Set["asyncio.Task[None]"] = set()


def schedule(
    reaudit: Callable[[], Awaitable[int]], delay: float = FIRST_DELAY_SECONDS
) -> None:
    """Run ``reaudit()`` after ``delay`` seconds, then every day.

    A timer rather than a sleeping task: nothing waits on a pending timer, so
    an agent shutting down -- or a test draining its tasks -- is never held
    up by a re-audit due tomorrow.  Outside a running event loop it does
    nothing."""
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        return
    loop.call_later(delay, _fire, reaudit)


def _fire(reaudit: Callable[[], Awaitable[int]]) -> None:
    task = asyncio.ensure_future(_run_then_reschedule(reaudit))
    _running.add(task)
    task.add_done_callback(_running.discard)


async def _run_then_reschedule(reaudit: Callable[[], Awaitable[int]]) -> None:
    try:
        await reaudit()
    except Exception as error:  # pylint: disable=broad-except
        logger.warning("The daily storage re-audit failed: %s", error)
    finally:
        schedule(reaudit, INTERVAL_SECONDS)
