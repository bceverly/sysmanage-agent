"""
LXD container lifecycle integration test.

Phase 4 ROADMAP item that was carried into the pre-Phase-8 hardening
push:  drive ``LxdOperations`` through stop → start → restart → delete
against a real LXD daemon, not mocks.  The unit tests in
``tests/test_lxd_operations.py`` already cover the mock-driven path;
this test catches things mocks can't:

  - ``lxc`` CLI argv drift (e.g., a flag rename in a future LXD release).
  - Real timing — does ``stop`` actually wait for the container to be
    stopped before returning?
  - Permission-related failures invisible to mocked tests.
  - State observability via ``lxc list``.

The test:

  1. ``setUp`` — create a real, throwaway Alpine container via the
     ``lxc launch`` CLI.  Alpine is the smallest practical image (~3 MB
     compressed) so CI setup stays fast.
  2. Assert it's running via ``lxc list`` (sanity check).
  3. Drive ``LxdOperations.stop_child_host`` → assert state is STOPPED.
  4. Drive ``LxdOperations.start_child_host`` → assert state is RUNNING.
  5. Drive ``LxdOperations.restart_child_host`` → assert state is RUNNING.
  6. Drive ``LxdOperations.delete_child_host`` → assert it's gone from
     ``lxc list``.
  7. ``tearDown`` — best-effort ``lxc delete --force`` if the test
     panicked midway, so retries don't get cluttered.

Skipped automatically if:
  - Not on Linux (``lxc`` only available on Linux).
  - LXD daemon not available / not initialized (``lxc list`` fails).

Tagged ``@pytest.mark.integration`` so the existing CI workflow filter
picks it up.  ``integration-tests.yml`` already installs LXD on the
Ubuntu runner (see lines 102-105), so this test runs out of the box on
that job.
"""

# pylint: disable=missing-class-docstring,missing-function-docstring,protected-access,redefined-outer-name

import asyncio
import logging
import platform
import shutil
import subprocess  # nosec B404 — orchestrating local CLI tools
import uuid
from unittest.mock import MagicMock

import pytest

from src.sysmanage_agent.operations.child_host_lxd import LxdOperations


# A throwaway-container name with a UUID suffix so concurrent test
# invocations on the same runner don't collide.
def _container_name() -> str:
    return f"sysmanage-it-{uuid.uuid4().hex[:8]}"


def _lxd_available() -> bool:
    """True iff the ``lxc`` binary is on PATH AND the daemon answers.

    Skip messaging is intentionally generic — CI bills this as a
    documented "LXD-required" test, so missing infra is a skip, not a
    fail."""
    if platform.system() != "Linux":
        return False
    if shutil.which("lxc") is None:
        return False
    # ``lxc list`` is the cheapest "is the daemon up?" probe.  Don't
    # use --format=json yet — older LXC builds don't support it; we
    # only care about exit code here.
    try:
        return_code = subprocess.run(  # nosec B603,B607 — fixed argv, no user input
            ["lxc", "list"], capture_output=True, timeout=10, check=False
        ).returncode
    except (subprocess.TimeoutExpired, OSError):
        return False
    return return_code == 0


def _lxc_state(container: str) -> str:
    """Return the container's state per ``lxc list`` (RUNNING / STOPPED /
    empty if absent).  Uppercased to match LXC's own canonical form."""
    try:
        out = subprocess.run(  # nosec B603,B607
            ["lxc", "list", container, "--format=csv", "--columns=ns"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        ).stdout.strip()
    except (subprocess.TimeoutExpired, OSError):
        return ""
    if not out:
        return ""
    # Format: "<name>,<state>"
    parts = out.split(",", 1)
    return parts[1].strip().upper() if len(parts) == 2 else ""


def _lxc_run(args: list, timeout: int = 60) -> int:
    """Run an ``lxc`` command, return its exit code (no output check)."""
    try:
        return subprocess.run(  # nosec B603,B607
            ["lxc", *args], timeout=timeout, capture_output=True, check=False
        ).returncode
    except (subprocess.TimeoutExpired, OSError):
        return 124  # timeout-ish


@pytest.fixture
def lxd_container():
    """Create a throwaway Alpine container; tear down on exit.

    The ``yield`` value is the container name.  ``lxc launch`` is
    synchronous — it waits for the container to be RUNNING before
    returning — so the body of the test can assert state without an
    arbitrary sleep."""
    if not _lxd_available():
        pytest.skip("LXD daemon not available on this host")

    name = _container_name()
    # alpine/edge is ~3 MB compressed; smallest practical image.  If
    # the runner doesn't have it cached, the launch can take 10–30 s
    # the first time — that's CI-network bound, not a test bug.
    return_code = _lxc_run(
        ["launch", "images:alpine/edge", name, "--ephemeral=false"],
        timeout=180,
    )
    if return_code != 0:
        pytest.skip(
            f"`lxc launch` failed with rc={return_code} (no network? image "
            f"cache miss? runner missing LXD remote?).  Skipping."
        )
    try:
        yield name
    finally:
        _lxc_run(["delete", name, "--force"], timeout=60)


@pytest.fixture
def lxd_ops():
    """LxdOperations needs (agent, logger, virtualization_checks).
    None of the lifecycle methods (start/stop/restart/delete) actually
    touch agent or virtualization_checks — they just call ``lxc`` via
    ``run_command_async`` — so MagicMocks suffice."""
    return LxdOperations(
        agent_instance=MagicMock(),
        logger=logging.getLogger("test_lxd_lifecycle"),
        virtualization_checks=MagicMock(),
    )


def _run(coro):
    """Run an async coroutine in a fresh event loop."""
    return asyncio.run(coro)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.mark.integration
@pytest.mark.skipif(
    not _lxd_available(), reason="LXD daemon not available on this host"
)
class TestLxdLifecycle:
    """Drive LxdOperations through the full RUNNING ↔ STOPPED cycle
    against a real container."""

    def test_stop_running_container(self, lxd_ops, lxd_container):
        """Container starts RUNNING (lxc launch is synchronous);
        stop_child_host must transition it to STOPPED."""
        assert _lxc_state(lxd_container) == "RUNNING", (
            "fixture invariant violated — `lxc launch` should leave the "
            "container RUNNING"
        )
        result = _run(lxd_ops.stop_child_host({"child_name": lxd_container}))
        assert result["success"] is True, f"stop returned: {result}"
        assert result["child_name"] == lxd_container
        assert result["child_type"] == "lxd"
        assert _lxc_state(lxd_container) == "STOPPED"

    def test_start_stopped_container(self, lxd_ops, lxd_container):
        """Stop → start cycle:  observable state must be RUNNING after
        start completes (the stop must have been synchronous, otherwise
        start could race)."""
        _run(lxd_ops.stop_child_host({"child_name": lxd_container}))
        assert _lxc_state(lxd_container) == "STOPPED"
        result = _run(lxd_ops.start_child_host({"child_name": lxd_container}))
        assert result["success"] is True, f"start returned: {result}"
        assert _lxc_state(lxd_container) == "RUNNING"

    def test_restart_running_container(self, lxd_ops, lxd_container):
        """Restart should leave the container RUNNING (regardless of
        the implementation: ``lxc restart`` vs ``stop && start``)."""
        result = _run(lxd_ops.restart_child_host({"child_name": lxd_container}))
        assert result["success"] is True, f"restart returned: {result}"
        assert _lxc_state(lxd_container) == "RUNNING"

    def test_delete_container(self, lxd_ops, lxd_container):
        """Delete must remove the container from `lxc list` even when
        it's RUNNING (LxdOperations passes ``--force``)."""
        assert _lxc_state(lxd_container) == "RUNNING"
        result = _run(lxd_ops.delete_child_host({"child_name": lxd_container}))
        assert result["success"] is True, f"delete returned: {result}"
        assert _lxc_state(lxd_container) == "", (
            "container is still listed by `lxc list` after delete returned "
            "success — delete didn't actually remove it"
        )

    def test_full_lifecycle_in_one_go(self, lxd_ops, lxd_container):
        """End-to-end:  stop → start → restart → delete in sequence on
        the same container.  Catches state-machine bugs that only show
        up across multiple transitions (e.g., a stop that leaves the
        container in a half-state where the next start fails)."""
        for operation, expected_state in [
            (lxd_ops.stop_child_host, "STOPPED"),
            (lxd_ops.start_child_host, "RUNNING"),
            (lxd_ops.restart_child_host, "RUNNING"),
        ]:
            result = _run(operation({"child_name": lxd_container}))
            assert result["success"] is True, f"{operation.__name__} returned: {result}"
            assert _lxc_state(lxd_container) == expected_state, (
                f"after {operation.__name__}: expected {expected_state}, "
                f"got {_lxc_state(lxd_container)!r}"
            )
        # Final delete (also covered by fixture teardown, but doing it
        # in-test verifies the result-shape contract).
        result = _run(lxd_ops.delete_child_host({"child_name": lxd_container}))
        assert result["success"] is True


@pytest.mark.integration
@pytest.mark.skipif(
    not _lxd_available(), reason="LXD daemon not available on this host"
)
class TestLxdLifecycleErrorPaths:
    """Negative paths that don't need a real container."""

    def test_stop_missing_container_returns_error_not_exception(self, lxd_ops):
        """Operating on a nonexistent container must return a structured
        error dict, NOT raise.  If it raises, the agent's command
        dispatcher will treat it as a fatal connection failure."""
        ghost = _container_name()  # never created
        result = _run(lxd_ops.stop_child_host({"child_name": ghost}))
        assert result["success"] is False
        assert "error" in result

    def test_missing_child_name_param_returns_error(self, lxd_ops):
        """Empty parameter dict must return success=False with the
        canonical "name required" error.  Catches the case where a
        future refactor accidentally tries to ``lxc stop``"""
        result = _run(lxd_ops.stop_child_host({}))
        assert result["success"] is False
        assert "error" in result
