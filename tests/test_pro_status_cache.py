# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""The Ubuntu Pro / Livepatch status cache: `pro status --all` ran every ~10
seconds because get_system_info() reads the OS info (beast, 2026-10-19)."""

import subprocess
import threading
import time
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


class _Clock:
    """A settable monotonic clock."""

    def __init__(self):
        self.now = 0.0

    def __call__(self):
        return self.now


def test_once_the_ttl_passes_the_old_answer_serves_while_a_thread_asks_again():
    clock = _Clock()
    run = Mock(side_effect=[_answer(out="old"), _answer(out="new")])
    with patch.object(cache.time, "monotonic", clock):
        assert cache.cached_run(ARGV, run).stdout == "old"
        clock.now = 301.0
        assert cache.cached_run(ARGV, run).stdout == "old"  # no waiting
        cache.wait_for_refreshes()
        assert cache.cached_run(ARGV, run).stdout == "new"
    assert run.call_count == 2


def test_a_slow_pro_never_holds_up_a_caller_once_it_has_answered():
    """ubiquiti, 2026-11-01: `sudo pro status` took 37 s from the agent, on
    the event loop, every five minutes, and the server dropped the websocket."""
    clock = _Clock()
    release = threading.Event()

    def slow(_argv):
        release.wait(5)
        return _answer(out="new")

    with patch.object(cache.time, "monotonic", clock):
        cache.cached_run(ARGV, Mock(return_value=_answer(out="old")))
        clock.now = 301.0
        started = time.monotonic()
        assert cache.cached_run(ARGV, slow).stdout == "old"
        assert time.monotonic() - started < 1.0
        assert cache.cached_run(ARGV, slow).stdout == "old"  # one refresh only
        release.set()
        cache.wait_for_refreshes()
        assert cache.cached_run(ARGV, slow).stdout == "new"


def test_a_failed_answer_is_kept_for_the_failure_ttl():
    # nas, 2026-10-27: an uncached failure was asked again on every message
    clock = _Clock()
    run = Mock(side_effect=[_answer(code=1, out=""), _answer()])
    with patch.object(cache.time, "monotonic", clock):
        assert cache.cached_run(ARGV, run).returncode == 1
        clock.now = 10.0
        assert cache.cached_run(ARGV, run).returncode == 1  # kept, not asked
        clock.now = 301.0
        cache.cached_run(ARGV, run)  # the period ended: asked in the background
        cache.wait_for_refreshes()
        assert cache.cached_run(ARGV, run).returncode == 0
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
