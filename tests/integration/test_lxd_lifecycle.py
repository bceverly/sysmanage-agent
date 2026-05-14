"""
End-to-end integration test for LXD container lifecycle.

Drives ``GenericDeployment.apply_deployment_plan`` through a full
launch -> stop -> start -> restart -> delete sequence against a real
LXD daemon.  Verifies observable state via ``lxc list`` between
phases.

Why this lives in the agent test suite rather than the Pro+ engine:
the Pro+ ``container_engine`` ships *plan-builder* tests that lock
down the shape of the plans (argv, timeout, description envelope).
This integration test closes the loop — it confirms that an
apply_deployment_plan invocation actually drives a container through
its states on a host where LXD is installed.  The plans the engine
emits and the plans this test builds are byte-equivalent (same
``commands`` list shape, same ``lxc <action> <name>`` argv), so when
this test passes we know the engine -> agent path works end-to-end
for LXD.

Auto-skip: every test checks for ``lxc`` on PATH + an active LXD
daemon.  On hosts without LXD (every macOS / Windows runner, every
BSD runner, Linux runners without LXD installed) the entire module
is skipped at collection time so the suite still reports "passed
only" rather than "skipped".

The legacy agent class ``LxdOperations`` that the original ROADMAP
Phase 4 line 938 test drove was removed during the Phase 2 migration
to the Pro+ ``container_engine``.  This rewrite tests the same
*observable* lifecycle but routes through ``apply_deployment_plan``
— the current runtime path.
"""

# pylint: disable=missing-function-docstring,redefined-outer-name,protected-access

from __future__ import annotations

import asyncio
import os
import shutil
import subprocess
import time
import uuid
from typing import Iterator
from unittest.mock import AsyncMock, Mock

import pytest

from src.sysmanage_agent.operations.generic_deployment import GenericDeployment

# ---------------------------------------------------------------------------
# Auto-skip preflight
# ---------------------------------------------------------------------------


def _lxd_available() -> bool:
    """Return True iff ``lxc`` is on PATH AND the LXD daemon responds."""
    if shutil.which("lxc") is None:
        return False
    try:
        # ``lxc list --format csv`` is the cheapest call that hits the
        # daemon; succeeds if the socket is reachable, fails otherwise.
        result = subprocess.run(
            ["lxc", "list", "--format", "csv"],
            capture_output=True,
            timeout=10,
            check=False,
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, OSError):
        return False


pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        not _lxd_available(),
        reason="LXD daemon not available — install lxd and run `lxc list` once before running this suite",
    ),
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _list_states() -> dict[str, str]:
    """Return ``{container_name: state}`` for all LXD containers.

    Parses ``lxc list --format csv`` output.  ``state`` is the column
    LXD reports ("RUNNING", "STOPPED", etc.).
    """
    result = subprocess.run(
        ["lxc", "list", "--format", "csv", "--columns", "ns"],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    if result.returncode != 0:
        return {}
    out: dict[str, str] = {}
    for line in result.stdout.strip().splitlines():
        if not line:
            continue
        parts = line.split(",", 1)
        if len(parts) == 2:
            out[parts[0].strip()] = parts[1].strip().upper()
    return out


def _wait_for_state(name: str, expected: str, timeout_s: float = 30.0) -> str:
    """Poll ``lxc list`` until container ``name`` reaches ``expected``
    state, or ``timeout_s`` elapses.  Returns the last observed state."""
    deadline = time.monotonic() + timeout_s
    last_state = "UNKNOWN"
    while time.monotonic() < deadline:
        states = _list_states()
        last_state = states.get(name, "MISSING")
        if last_state == expected:
            return last_state
        time.sleep(0.5)
    return last_state


def _build_lxd_plan(action: str, container_name: str) -> dict:
    """Mirror the engine's ``build_lxd_lifecycle_plan`` /
    ``build_lxd_delete_plan`` output shape exactly.

    Keeping this inline in the test (vs. importing the engine) means
    the agent test suite has no Pro+ dependency — the test ships in
    OSS agents and runs on every LXD-equipped host without needing
    the Pro+ binary installed.  If the engine's plan shape ever
    drifts from this template the engine-side plan-builder tests
    will catch it; this end-to-end test would then need a matching
    update.
    """
    if action == "delete":
        return {
            "engine": "container_engine",
            "hypervisor": "lxd",
            "action": "delete",
            "container_name": container_name,
            "commands": [
                {
                    "argv": ["lxc", "delete", container_name, "--force"],
                    "timeout": 120,
                    "ignore_errors": False,
                    "description": f"lxc delete --force {container_name}",
                },
            ],
        }
    timeout = 120 if action == "restart" else 60
    return {
        "engine": "container_engine",
        "hypervisor": "lxd",
        "action": action,
        "container_name": container_name,
        "commands": [
            {
                "argv": ["lxc", action, container_name],
                "timeout": timeout,
                "ignore_errors": False,
                "description": f"lxc {action} {container_name}",
            },
        ],
    }


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def deployment() -> GenericDeployment:
    """A ``GenericDeployment`` wired to a minimal mock agent.

    ``apply_deployment_plan`` only reaches into ``self.agent`` for the
    ``install_package`` / ``uninstall_packages`` / ``message_processor``
    hooks — none of those fire for plans that contain only ``commands``,
    which is the only shape this test exercises.  So a bare Mock is
    enough.
    """
    mock_agent = Mock()
    mock_agent.install_package = AsyncMock(return_value={"success": True})
    mock_agent.uninstall_packages = AsyncMock(return_value={"success": True})
    mock_agent.message_processor = Mock()
    mock_agent.message_processor._handle_service_control = AsyncMock(
        return_value={"success": True}
    )
    return GenericDeployment(mock_agent)


@pytest.fixture
def alpine_container() -> Iterator[str]:
    """Launch a fresh Alpine container for the test, tear it down after.

    Container name is randomised so concurrent test runs don't
    collide on a shared LXD daemon.  The image is pinned to
    ``images:alpine/3.20`` for reproducibility — bump deliberately
    if the upstream image drops.
    """
    name = f"sysmanage-test-{uuid.uuid4().hex[:8]}"
    launch = subprocess.run(
        ["lxc", "launch", "images:alpine/3.20", name],
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
    )
    if launch.returncode != 0:
        pytest.skip(
            f"lxc launch failed (image fetch / network / quota?): "
            f"stderr={launch.stderr.strip()!r}"
        )

    # New containers start in RUNNING; wait for that to be visible
    # through ``lxc list`` before yielding so tests don't race the
    # daemon's bookkeeping.
    if _wait_for_state(name, "RUNNING", timeout_s=60.0) != "RUNNING":
        subprocess.run(
            ["lxc", "delete", name, "--force"], capture_output=True, check=False
        )
        pytest.fail(f"freshly-launched {name} never reached RUNNING")

    try:
        yield name
    finally:
        # Best-effort cleanup — even if the test killed/deleted the
        # container, ``--force`` is idempotent against missing.
        subprocess.run(
            ["lxc", "delete", name, "--force"], capture_output=True, check=False
        )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def _run(deployment: GenericDeployment, plan: dict) -> dict:
    """Synchronous wrapper for the async apply_deployment_plan handler.

    ``asyncio.get_event_loop()`` no longer auto-creates a loop in
    Python 3.14 (it raises ``RuntimeError`` when there is no running
    or current loop), so we always spin a fresh loop, run the
    coroutine to completion, and tear it down.  This works
    identically on 3.9–3.14 and keeps the test synchronous so the
    polling helpers like ``_wait_for_state`` can sit alongside it
    without an ``@pytest.mark.asyncio`` wrapper.
    """
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(deployment.apply_deployment_plan({"plan": plan}))
    finally:
        loop.close()


class TestLxdLifecycle:
    """End-to-end coverage of lxc start/stop/restart/delete via
    ``apply_deployment_plan``."""

    def test_stop_transitions_running_to_stopped(self, deployment, alpine_container):
        result = _run(deployment, _build_lxd_plan("stop", alpine_container))
        assert result["success"] is True, result
        # Stopping is synchronous in LXD, but the daemon may take a
        # beat to update its state cache.  Poll up to 30s.
        assert _wait_for_state(alpine_container, "STOPPED") == "STOPPED"

    def test_start_transitions_stopped_to_running(self, deployment, alpine_container):
        # Stop first so we have a known starting state.
        subprocess.run(
            ["lxc", "stop", alpine_container], capture_output=True, check=True
        )
        assert _wait_for_state(alpine_container, "STOPPED") == "STOPPED"

        result = _run(deployment, _build_lxd_plan("start", alpine_container))
        assert result["success"] is True, result
        assert _wait_for_state(alpine_container, "RUNNING") == "RUNNING"

    def test_restart_keeps_state_running(self, deployment, alpine_container):
        result = _run(deployment, _build_lxd_plan("restart", alpine_container))
        assert result["success"] is True, result
        # After restart the container should be back to RUNNING.
        assert _wait_for_state(alpine_container, "RUNNING", timeout_s=60.0) == "RUNNING"

    def test_delete_removes_container_from_listing(self, deployment, alpine_container):
        assert alpine_container in _list_states()
        result = _run(deployment, _build_lxd_plan("delete", alpine_container))
        assert result["success"] is True, result
        # ``lxc delete --force`` stops + deletes in one call.
        assert alpine_container not in _list_states()

    def test_full_cycle_stop_start_restart_delete(self, deployment, alpine_container):
        """One combined run through every lifecycle action.

        Mirrors the original Phase 4 test's "drive through every state"
        intent so regression coverage matches what was documented.
        """
        # stop
        result = _run(deployment, _build_lxd_plan("stop", alpine_container))
        assert result["success"] is True, result
        assert _wait_for_state(alpine_container, "STOPPED") == "STOPPED"

        # start
        result = _run(deployment, _build_lxd_plan("start", alpine_container))
        assert result["success"] is True, result
        assert _wait_for_state(alpine_container, "RUNNING") == "RUNNING"

        # restart
        result = _run(deployment, _build_lxd_plan("restart", alpine_container))
        assert result["success"] is True, result
        assert _wait_for_state(alpine_container, "RUNNING", timeout_s=60.0) == "RUNNING"

        # delete
        result = _run(deployment, _build_lxd_plan("delete", alpine_container))
        assert result["success"] is True, result
        assert alpine_container not in _list_states()

    def test_stop_when_already_stopped_reports_failure(
        self, deployment, alpine_container
    ):
        """Idempotency contract: lxc returns non-zero when asked to
        stop an already-stopped container, and the plan-builder uses
        ``ignore_errors=False`` for lifecycle calls.  Server-side
        callers are expected to verify state before dispatch — this
        test locks in that the agent surfaces the failure rather than
        masking it."""
        subprocess.run(
            ["lxc", "stop", alpine_container], capture_output=True, check=True
        )
        assert _wait_for_state(alpine_container, "STOPPED") == "STOPPED"

        result = _run(deployment, _build_lxd_plan("stop", alpine_container))
        # Re-stopping a stopped container should yield a non-zero
        # return code, which propagates as plan failure.
        assert result["success"] is False, result
        assert result["failed_step"] == "commands"

    def test_start_with_unsafe_name_never_reaches_lxc(self, deployment):
        """The engine's plan-builder rejects shell-meta in container
        names before any command runs; mirror that here so a future
        regression that bypasses validation doesn't sneak a shell
        injection through apply_deployment_plan."""
        # Hand-roll a plan with a tainted name (skipping the safe-name
        # validation the engine would normally apply).  The plan
        # *itself* is well-formed — the test asserts that even when
        # the agent runs such a plan, lxc exits non-zero on the bad
        # name and no shell expansion happens.
        plan = {
            "engine": "container_engine",
            "hypervisor": "lxd",
            "action": "start",
            "container_name": "bogus; rm -rf /tmp/sysmanage-rce-canary",
            "commands": [
                {
                    "argv": [
                        "lxc",
                        "start",
                        "bogus; rm -rf /tmp/sysmanage-rce-canary",
                    ],
                    "timeout": 30,
                    "ignore_errors": True,  # we expect failure; just verify no RCE
                    "description": "lxc start <bogus name>",
                },
            ],
        }
        # Drop a canary so we can prove no shell expansion happened.
        canary = "/tmp/sysmanage-rce-canary"  # NOSONAR S5443
        with open(canary, "w", encoding="utf-8") as canary_fh:
            canary_fh.write("intact")
        try:
            _run(deployment, plan)
            # Canary must still exist — if shell expansion had run,
            # `rm -rf` would have deleted it.
            assert os.path.exists(
                canary
            ), "RCE canary was removed; lxc args reached the shell"
        finally:
            try:
                os.unlink(canary)
            except OSError:
                pass
