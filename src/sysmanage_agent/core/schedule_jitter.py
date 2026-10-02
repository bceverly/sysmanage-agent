# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""Timers that do not march in step (server Phase 22.1).

Every agent timer used to be anchored to its connect and never randomized, so
anything that made a fleet reconnect together -- a server restart, a site's
power coming back, a mass upgrade -- put every agent's collection, heartbeat
and update check in phase for good.  The server's scale harness measured the
result: traffic arriving in bursts several times the average.  Each interval
now varies a little every time it is used, so a fleet that starts together
drifts apart within a few cycles, and the first collection after a connect
waits a random moment instead of firing with everyone else's.
"""

import random

# Spread of an ordinary interval: +/-20% (heartbeats use less).
SPREAD = 0.2
# The first collection after a connect waits up to this long.
CONNECT_SPLAY_SECONDS = 60.0


def jittered(seconds: float, spread: float = SPREAD) -> float:
    """``seconds`` varied by up to +/-``spread`` (a fraction)."""
    return seconds * random.uniform(
        1.0 - spread, 1.0 + spread
    )  # nosec B311 - spreading load, not security


def connect_splay(limit: float = CONNECT_SPLAY_SECONDS) -> float:
    """How long to wait before the first collection after a connect."""
    return random.uniform(0.0, limit)  # nosec B311 - spreading load, not security
