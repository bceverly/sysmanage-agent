"""
Integration tests for the agent's tempdir-resolution behaviour.

We recently refactored ``script_operations._build_plan`` (and its
server-side sibling ``script_plan_builder``) to construct the script
path with ``tempfile.gettempdir()`` rather than hardcoding ``/tmp``.
These tests exercise the resolved path on a real host so we catch any
regression where the path can't actually be written to.
"""

# pylint: disable=missing-function-docstring,missing-class-docstring
# pylint: disable=invalid-name,protected-access  # long test names; deliberately exercise _build_plan

import os
import sys
import tempfile

import pytest

from src.sysmanage_agent.operations.script_operations import ScriptOperations


@pytest.mark.integration
def test_tempdir_exists_and_is_writable():
    """Whatever tempfile.gettempdir() returns must be a real, writable dir."""
    tmp = tempfile.gettempdir()
    assert os.path.isdir(tmp), f"gettempdir() returned {tmp!r} but it's not a dir"
    # Write a sentinel file and clean up.  This is the actual path the
    # agent's deploy_files handler will use, so a write failure here is
    # a real bug, not a test-environment quirk.
    sentinel_fd, sentinel_path = tempfile.mkstemp(prefix="sysmanage_int_", dir=tmp)
    try:
        os.close(sentinel_fd)
        assert os.path.exists(sentinel_path)
    finally:
        os.unlink(sentinel_path)


@pytest.mark.integration
@pytest.mark.skipif(sys.platform == "win32", reason="POSIX-shell branch")
def test_build_plan_posix_path_is_under_tempdir():
    """ScriptOperations._build_plan() POSIX branch should use gettempdir()."""
    plan = ScriptOperations._build_plan(
        "echo hello", "bash", 30
    )  # pylint: disable=protected-access
    script_path = plan["files"][0]["path"]
    assert script_path.startswith(
        tempfile.gettempdir() + os.sep
    ) or script_path.startswith(tempfile.gettempdir() + "/"), (
        f"script_path={script_path!r} is not under gettempdir()="
        f"{tempfile.gettempdir()!r} — refactor regressed?"
    )
    assert script_path.endswith(".sh"), f"unexpected script suffix in {script_path!r}"


@pytest.mark.integration
def test_build_plan_unique_paths_per_call():
    """Each _build_plan() call uses a fresh uuid4().hex — paths must differ."""
    shell = "powershell" if sys.platform == "win32" else "bash"
    plan_a = ScriptOperations._build_plan(
        "echo a", shell, 30
    )  # pylint: disable=protected-access
    plan_b = ScriptOperations._build_plan(
        "echo b", shell, 30
    )  # pylint: disable=protected-access
    assert plan_a["files"][0]["path"] != plan_b["files"][0]["path"], (
        "Two consecutive _build_plan() calls produced the same script path — "
        "uuid4().hex collision or the path is not being randomised."
    )
