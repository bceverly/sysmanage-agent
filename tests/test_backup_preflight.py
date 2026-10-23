# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""Capture pre-flight (24.1): the repository must take a new file, lock it,
and have room -- against a real directory, plus each refusal."""

import os
import sys
from types import SimpleNamespace

import pytest

from src.sysmanage_agent.backup import host_mount

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="Unix-only feature")
RID = "7b1c0000-0000-4000-8000-0000000000aa"


def test_a_healthy_repository_passes_and_leaves_nothing_behind(tmp_path):
    assert host_mount.preflight(str(tmp_path), RID) is None
    assert os.listdir(tmp_path) == []


def test_a_repository_that_takes_no_files_is_refused(tmp_path):
    tmp_path.chmod(0o500)
    try:
        if os.access(tmp_path, os.W_OK):
            pytest.skip("running as root: permissions do not apply")
        reason = host_mount.preflight(str(tmp_path), RID)
    finally:
        tmp_path.chmod(0o700)
    assert reason and "cannot take new files" in reason


def test_a_full_repository_is_refused(tmp_path, monkeypatch):
    full = SimpleNamespace(f_bavail=10, f_frsize=4096, f_blocks=1_000_000)
    monkeypatch.setattr(host_mount.os, "statvfs", lambda path: full)
    reason = host_mount.preflight(str(tmp_path), RID)
    assert reason and "nearly full" in reason
    assert os.listdir(tmp_path) == []


def test_broken_locking_is_refused(tmp_path, monkeypatch):
    import fcntl  # pylint: disable=import-outside-toplevel

    def no_locks(handle, op):
        raise OSError(37, "No locks available")

    monkeypatch.setattr(fcntl, "lockf", no_locks)
    reason = host_mount.preflight(str(tmp_path), RID)
    assert reason and "Locking does not work" in reason
    assert os.listdir(tmp_path) == []
