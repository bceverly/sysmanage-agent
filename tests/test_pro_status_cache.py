# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""The Ubuntu Pro / Livepatch status cache: `pro status --all` ran every ~10
seconds because get_system_info() reads the OS info (beast, 2026-10-19)."""

import subprocess
from unittest.mock import Mock, patch

from src.sysmanage_agent.collection import pro_status_cache as cache
from src.sysmanage_agent.collection.os_info_collection import OSInfoCollector

ARGV = ["pro", "status", "--all", "--format", "json"]


def _answer(code=0, out='{"attached": false, "services": []}'):
    return subprocess.CompletedProcess(ARGV, code, stdout=out, stderr="")


def test_a_status_answer_is_reused_within_the_ttl():
    run = Mock(return_value=_answer())
    cache.cached_run(ARGV, run)
    cache.cached_run(ARGV, run)
    assert run.call_count == 1


def test_it_asks_again_once_the_ttl_passes():
    run = Mock(return_value=_answer())
    with patch.object(cache.time, "monotonic", side_effect=[0.0, 0.0, 301.0, 301.0]):
        cache.cached_run(ARGV, run)
        cache.cached_run(ARGV, run)
    assert run.call_count == 2


def test_a_failed_answer_is_kept_for_the_failure_ttl():
    # nas, 2026-10-27: an uncached failure was asked again on every message
    run = Mock(side_effect=[_answer(code=1, out=""), _answer()])
    with patch.object(
        cache.time, "monotonic", side_effect=[0.0, 0.0, 10.0, 301.0, 301.0]
    ):
        assert cache.cached_run(ARGV, run).returncode == 1
        assert cache.cached_run(ARGV, run).returncode == 1  # kept, not asked
        assert cache.cached_run(ARGV, run).returncode == 0  # the period ended
    assert run.call_count == 2


def test_a_timeout_comes_back_as_a_kept_failure_not_an_exception():
    run = Mock(side_effect=subprocess.TimeoutExpired(ARGV, 60))
    first = cache.cached_run(ARGV, run)
    second = cache.cached_run(ARGV, run)
    assert first.returncode == cache.TIMED_OUT and second is first
    assert run.call_count == 1


def test_a_missing_pro_command_is_a_kept_failure():
    run = Mock(side_effect=FileNotFoundError("pro"))
    assert cache.cached_run(ARGV, run).returncode == cache.NOT_FOUND
    cache.cached_run(ARGV, run)
    assert run.call_count == 1


def test_invalidate_forgets_after_a_pro_change():
    run = Mock(return_value=_answer())
    cache.cached_run(ARGV, run)
    cache.invalidate()
    cache.cached_run(ARGV, run)
    assert run.call_count == 2


def test_repeated_os_info_reads_run_pro_status_once():
    collector = OSInfoCollector()
    with patch.object(
        collector, "_run_as_root_if_allowed", return_value=_answer()
    ) as run:
        for _ in range(5):
            collector._get_ubuntu_pro_info()  # pylint: disable=protected-access
    assert run.call_count == 1
