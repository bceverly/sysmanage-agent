# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""Send what CHANGED in the package catalog, not the catalog.

WHY
---
The available-packages catalog is ~89k entries (~11 MB) and is re-scanned every
collection cycle, but almost nothing in it changes between cycles.  Sending it
whole was 83% of everything this agent transmitted.

The fingerprint handshake already removes the case where NOTHING changed.  This
module handles the rest: when a handful of packages appear, disappear or change
version, send those instead of all 89,000.

THE SAFETY RULE
---------------
A delta is only meaningful relative to a known base.  The agent may send one
ONLY when its snapshot of what it last delivered has the same fingerprint the
server reports holding.  If they disagree -- a lost message, a restored
database, a server that pruned rows, a host that was re-registered -- the base
is unknown and a delta would silently corrupt the server's view.  In that case
the agent sends the full catalog, which is always correct.

That is why ``build_delta_plan`` returns a MODE rather than just a diff: the
decision "delta or full" is the interesting part, and it is made from evidence
(fingerprints) rather than optimism.

WHEN A DELTA IS NOT WORTH IT
----------------------------
Two cases fall back to a full send even when a delta would be valid:

  * the diff is a large fraction of the catalog -- transmitting 40k puts plus
    40k takes is more expensive than 89k entries sent once, and it leaves the
    server doing two passes instead of one; and
  * the snapshot is old.  A periodic full send re-synchronises both sides
    cheaply and bounds how long any undetected drift can persist.  Deltas
    compound: an error in one is carried by every delta after it, until a full
    send clears it.
"""

from datetime import datetime, timedelta, timezone
from typing import Dict, Optional, Tuple

# Above this share of the catalog, a full send is cheaper than the diff.
MAX_DELTA_FRACTION = 0.30

# However well deltas are going, re-synchronise this often.  Bounds how long a
# missed change can persist, and costs one full send a week.
FULL_RECONCILE_AFTER_DAYS = 7

MODE_FULL = "full"
MODE_DELTA = "delta"

REASON_NO_SNAPSHOT = "no_snapshot"
REASON_FINGERPRINT_MISMATCH = "server_holds_a_different_catalog"
REASON_TOO_LARGE = "delta_too_large"
REASON_SNAPSHOT_STALE = "periodic_full_reconcile"
REASON_UNCHANGED = "unchanged"
REASON_CHANGED = "changed"


def _index(package_managers: Dict[str, list]) -> Dict[Tuple[str, str], str]:
    """{(manager, name): version} — the identity the server stores."""
    out = {}
    for manager, packages in (package_managers or {}).items():
        for pkg in packages or []:
            name = (pkg.get("name") or "").strip()
            if not name:
                continue
            out[(manager, name)] = (pkg.get("version") or "").strip()
    return out


def _descriptions(package_managers: Dict[str, list]) -> Dict[Tuple[str, str], str]:
    out = {}
    for manager, packages in (package_managers or {}).items():
        for pkg in packages or []:
            name = (pkg.get("name") or "").strip()
            if name:
                out[(manager, name)] = pkg.get("description") or ""
    return out


def compute_delta(current: Dict[str, list], snapshot: Dict[Tuple[str, str], str]):
    """(puts, takes) between a scan and the snapshot the server holds.

    A version change is a PUT, not a take-then-put: the server replaces the row
    for that (host, manager, name), so one message does the whole job.
    """
    now = _index(current)
    descriptions = _descriptions(current)

    puts, takes = [], []
    for key, version in now.items():
        if snapshot.get(key) != version:
            manager, name = key
            puts.append(
                {
                    "package_manager": manager,
                    "name": name,
                    "version": version,
                    "description": descriptions.get(key, ""),
                }
            )
    for key in snapshot:
        if key not in now:
            manager, name = key
            takes.append({"package_manager": manager, "name": name})

    return puts, takes


def build_delta_plan(
    current: Dict[str, list],
    snapshot: Dict[Tuple[str, str], str],
    snapshot_fingerprint: Optional[str],
    server_fingerprint: Optional[str],
    snapshot_sent_at=None,
    now=None,
) -> dict:
    """Decide how to bring the server up to date, and say why.

    Args:
        current: the freshly scanned catalog, ``{manager: [{name, version, ...}]}``.
        snapshot: what we last delivered, ``{(manager, name): version}``.
        snapshot_fingerprint: fingerprint of that snapshot.
        server_fingerprint: what the SERVER says it holds (from the command).
        snapshot_sent_at: when the snapshot was delivered (for the periodic
            full re-sync).
        now: injectable clock for tests.

    Returns:
        ``{"mode": "full"|"delta", "reason": str, "puts": [...], "takes": [...]}``.
        ``mode == "full"`` means send everything; the puts/takes are still
        reported so callers can log what changed.
    """
    now = now or datetime.now(timezone.utc)
    puts, takes = compute_delta(current, snapshot)
    plan = {"puts": puts, "takes": takes}

    # No base at all: nothing to diff against.
    if not snapshot or not snapshot_fingerprint:
        return {**plan, "mode": MODE_FULL, "reason": REASON_NO_SNAPSHOT}

    # The server does not hold what we think it holds.  Do NOT diff against a
    # base the other side does not have -- that is how a delta protocol
    # silently desynchronises.
    if not server_fingerprint or server_fingerprint != snapshot_fingerprint:
        return {**plan, "mode": MODE_FULL, "reason": REASON_FINGERPRINT_MISMATCH}

    # Periodic re-synchronisation, so drift cannot accumulate indefinitely.
    if snapshot_sent_at is not None:
        sent_at = snapshot_sent_at
        if sent_at.tzinfo is None:
            sent_at = sent_at.replace(tzinfo=timezone.utc)
        if now - sent_at > timedelta(days=FULL_RECONCILE_AFTER_DAYS):
            return {**plan, "mode": MODE_FULL, "reason": REASON_SNAPSHOT_STALE}

    if not puts and not takes:
        return {**plan, "mode": MODE_DELTA, "reason": REASON_UNCHANGED}

    total = max(len(_index(current)), 1)
    if (len(puts) + len(takes)) / total > MAX_DELTA_FRACTION:
        return {**plan, "mode": MODE_FULL, "reason": REASON_TOO_LARGE}

    return {**plan, "mode": MODE_DELTA, "reason": REASON_CHANGED}
