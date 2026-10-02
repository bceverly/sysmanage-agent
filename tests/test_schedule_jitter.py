# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""Timers that do not march in step (server Phase 22.1)."""

from src.sysmanage_agent.core import schedule_jitter as sj


def test_jitter_stays_within_its_spread_and_actually_varies():
    values = [sj.jittered(300) for _ in range(500)]
    assert min(values) >= 300 * (1 - sj.SPREAD)
    assert max(values) <= 300 * (1 + sj.SPREAD)
    assert len({round(v, 3) for v in values}) > 100


def test_a_narrower_spread_for_heartbeats():
    values = [sj.jittered(30, 0.1) for _ in range(200)]
    assert 27 <= min(values) and max(values) <= 33


def test_connect_splay_is_bounded():
    values = [sj.connect_splay() for _ in range(200)]
    assert min(values) >= 0 and max(values) <= sj.CONNECT_SPLAY_SECONDS
