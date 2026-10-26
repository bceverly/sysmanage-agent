# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""Capture pre-flight (24.1): the repository must take new files, its lock
must work, and it must have room -- against a real directory, plus each
refusal.  It never makes a file: the repository's top is append-only on the
storage host, so nothing made there could be removed again."""

import errno
import os
import sys
from types import SimpleNamespace

import pytest

from src.sysmanage_agent.backup import host_mount

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="Unix-only feature")


def _repository(tmp_path):
    (tmp_path / "lock").write_text("")
    return str(tmp_path)


def test_a_healthy_repository_passes_and_gains_nothing(tmp_path):
    where = _repository(tmp_path)
    assert host_mount.preflight(where) is None
    assert os.listdir(where) == ["lock"]


def test_a_repository_before_its_first_capture_passes_and_stays_empty(tmp_path):
    # capture --create refuses a directory with anything in it
    assert host_mount.preflight(str(tmp_path)) is None
    assert os.listdir(tmp_path) == []


def test_a_repository_that_takes_no_files_is_refused(tmp_path):
    tmp_path.chmod(0o500)
    try:
        if os.access(tmp_path, os.W_OK):
            pytest.skip("running as root: permissions do not apply")
        reason = host_mount.preflight(str(tmp_path))
    finally:
        tmp_path.chmod(0o700)
    assert reason and "cannot take new files" in reason


def test_a_lock_file_it_cannot_open_is_refused(tmp_path):
    where = _repository(tmp_path)
    (tmp_path / "lock").chmod(0o400)
    try:
        if os.access(tmp_path / "lock", os.W_OK):
            pytest.skip("running as root: permissions do not apply")
        reason = host_mount.preflight(where)
    finally:
        (tmp_path / "lock").chmod(0o600)
    assert reason and "cannot take new files" in reason


def test_a_full_repository_is_refused(tmp_path, monkeypatch):
    full = SimpleNamespace(f_bavail=10, f_frsize=4096, f_blocks=1_000_000)
    monkeypatch.setattr(host_mount.os, "statvfs", lambda path: full)
    reason = host_mount.preflight(_repository(tmp_path))
    assert reason and "nearly full" in reason


def test_broken_locking_is_refused(tmp_path, monkeypatch):
    import fcntl  # pylint: disable=import-outside-toplevel

    def no_locks(handle, op):
        raise OSError(errno.ENOLCK, "No locks available")

    monkeypatch.setattr(fcntl, "lockf", no_locks)
    reason = host_mount.preflight(_repository(tmp_path))
    assert reason and "Locking does not work" in reason


@pytest.mark.parametrize("held", [errno.EAGAIN, errno.EACCES, errno.EIO])
def test_a_lock_held_elsewhere_still_passes(tmp_path, monkeypatch, held):
    # a storage-side prune holds it: locking works, restate waits or says busy
    import fcntl  # pylint: disable=import-outside-toplevel

    def busy(handle, op):
        raise OSError(held, os.strerror(held))

    monkeypatch.setattr(fcntl, "lockf", busy)
    assert host_mount.preflight(_repository(tmp_path)) is None


def test_a_symlinked_lock_is_not_followed(tmp_path):
    target = tmp_path / "elsewhere"
    target.write_text("")
    (tmp_path / "lock").symlink_to(target)
    reason = host_mount.preflight(str(tmp_path))
    assert reason and "cannot take new files" in reason
