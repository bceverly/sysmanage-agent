# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""Tests for ``sysmanage_agent.collection.fact_file_state`` — Phase 21.1 S7.

The property under test is the one the whole phase exists for: a watched path
that we did not measure must never be indistinguishable from one we measured
and found unchanged. osquery's own ``file`` table fails this — it returns no
row for a missing file, no row for an unreadable one, and no row for a path
nobody asked about — which is why this table exists instead of reusing it.
"""

import os
import sys

import pytest

from src.sysmanage_agent.collection import fact_file_state as ffs
from src.sysmanage_agent.collection import fact_native as fn
from src.sysmanage_agent.core import fact_schema as fs

# ``os.geteuid`` is POSIX-only, and a ``skipif`` CONDITION is evaluated when
# the decorator is APPLIED -- at import time -- so stacking it beneath a
# ``sys.platform == "win32"`` guard does not help: the Windows leg died during
# collection, before a single test in this module ran. The repo idiom is
# ``hasattr``; this file was the one place that did not follow it.
_IS_ROOT = os.geteuid() == 0 if hasattr(os, "geteuid") else False


def _try_symlink(src, dst) -> bool:
    """Create a symlink where the platform allows one; report whether it did.

    Windows needs SeCreateSymbolicLinkPrivilege (or Developer Mode), so an
    unconditional ``os.symlink`` in a fixture fails every test that uses it --
    including the twelve here that never touch a link.
    """
    try:
        os.symlink(str(src), str(dst))
        return True
    except (OSError, NotImplementedError, AttributeError):
        return False


def _require_symlink(path) -> None:
    if not os.path.islink(str(path)):
        pytest.skip("creating a symlink is not permitted on this platform")


@pytest.fixture
def tree(tmp_path):
    """A directory exercising every state the table can report."""
    (tmp_path / "config").write_text("PermitRootLogin yes\n", encoding="utf-8")
    (tmp_path / "adir").mkdir()
    _try_symlink(tmp_path / "config", tmp_path / "link_ok")
    _try_symlink(tmp_path / "nope", tmp_path / "link_dangling")
    return tmp_path


class TestStatesAreDistinguishable:
    def test_present_file_is_hashed(self, tree):
        row = ffs.file_state(str(tree / "config"))
        assert row["state"] == ffs.STATE_PRESENT
        assert row["type"] == ffs.TYPE_REGULAR
        assert len(row["sha256"]) == 64

    def test_missing_file_is_absent_not_empty(self, tree):
        """The defect this guards: a tool that returns no row for a missing
        file makes a DELETED config indistinguishable from an unwatched one,
        so deleting it is silently not drift."""
        row = ffs.file_state(str(tree / "nope"))
        assert row["state"] == ffs.STATE_ABSENT
        assert row["sha256"] is None
        # Every column is still present, so a consumer reading row["sha256"]
        # gets None rather than a KeyError.
        assert set(row) == set(fs.columns("sysmanage_file_state"))

    def test_directory_is_not_a_file(self, tree):
        row = ffs.file_state(str(tree / "adir"))
        assert row["state"] == ffs.STATE_NOT_A_FILE
        assert row["type"] == ffs.TYPE_DIRECTORY
        assert row["sha256"] is None
        # Metadata still reported: a config path that became a directory is
        # drift worth seeing, and mode/owner are how you see it.
        assert row["mode"] is not None

    @pytest.mark.skipif(
        sys.platform == "win32", reason="POSIX mode bits do not gate reads here"
    )
    @pytest.mark.skipif(_IS_ROOT, reason="root can read anything")
    def test_unreadable_is_not_unchanged(self, tree):
        """THE DANGEROUS ONE. An agent that loses permission on a watched file
        must not keep reporting it as stable. Unreadable is a FIXABLE gap and
        has to stay distinct from both 'absent' and 'present'."""
        secret = tree / "secret"
        secret.write_text("x\n", encoding="utf-8")
        secret.chmod(0o000)
        row = ffs.file_state(str(secret))
        assert row["state"] == ffs.STATE_UNREADABLE
        assert row["sha256"] is None

    def test_too_large_is_its_own_state(self, tree, monkeypatch):
        """A NULL sha256 alone cannot say whether we could not hash the file
        or chose not to. Those send an operator to different places."""
        monkeypatch.setattr(ffs, "MAX_HASH_BYTES", 4)
        row = ffs.file_state(str(tree / "config"))
        assert row["state"] == ffs.STATE_TOO_LARGE
        assert row["sha256"] is None
        assert row["size"] > 4


class TestSymlinks:
    def test_symlink_is_reported_as_one_and_still_hashed(self, tree):
        """A config file swapped for a symlink is exactly the drift worth
        catching, so the link is reported -- but the CONTENT at the end of it
        is what gets hashed, which is what an operator means by 'unchanged'."""
        _require_symlink(tree / "link_ok")
        row = ffs.file_state(str(tree / "link_ok"))
        assert row["type"] == ffs.TYPE_SYMLINK
        assert row["target"] == str(tree / "config")
        assert row["sha256"] == ffs.file_state(str(tree / "config"))["sha256"]

    def test_dangling_symlink_is_absent_but_keeps_its_target(self, tree):
        """'Deleted' and 'points at nothing' are different repairs."""
        _require_symlink(tree / "link_dangling")
        row = ffs.file_state(str(tree / "link_dangling"))
        assert row["state"] == ffs.STATE_ABSENT
        assert row["type"] == ffs.TYPE_SYMLINK
        assert row["target"] == str(tree / "nope")


class TestWindowsExtendedLengthTargets:
    """``os.readlink`` on Windows returns "\\\\?\\C:\\..." for an ABSOLUTE target.

    Caught by the Windows CI leg, and it is a product bug rather than a test
    one: that prefix is a Win32 API artifact, it is absent when the link was
    created with a RELATIVE target, and ``path`` in the same row arrives from
    the server's watch list without it. Left in, two hosts holding identical
    configuration differ only by how their link happened to be created, and
    the differ calls it drift -- the exact false positive this table exists to
    prevent.

    These run on every platform, not just Windows, because the normalizer is
    pure string work and the Windows leg is the slowest place to learn it
    broke.
    """

    @pytest.mark.parametrize(
        ("given", "expected"),
        [
            (r"\\?\C:\Users\me\config.ini", r"C:\Users\me\config.ini"),
            (r"\\?\UNC\server\share\f.ini", r"\\server\share\f.ini"),
            (r"C:\plain\path", r"C:\plain\path"),
            (r"\\server\share\plain", r"\\server\share\plain"),
            ("/etc/ssh/sshd_config", "/etc/ssh/sshd_config"),
            ("../relative/target", "../relative/target"),
            ("", ""),
        ],
    )
    def test_only_the_extended_prefix_is_rewritten(self, given, expected):
        assert ffs._normalize_link_target(given) == expected

    def test_a_genuine_unc_target_is_not_mistaken_for_an_extended_one(self):
        """``\\\\server\\share`` and ``\\\\?\\UNC\\server\\share`` name the same
        place, and only the second carries the prefix. Rewriting the first
        would corrupt a real path."""
        unc = r"\\fileserver\configs\sshd_config"
        assert ffs._normalize_link_target(unc) == unc


class TestContentNeverLeavesTheHost:
    def test_there_is_no_content_column(self):
        """The security property that lets an operator watch /etc/shadow. If a
        content column is ever added, this test is the place to argue for it."""
        cols = fs.columns("sysmanage_file_state")
        for forbidden in ("content", "contents", "data", "body", "text"):
            assert forbidden not in cols

    def test_a_row_carries_no_file_bytes(self, tree):
        (tree / "secretish").write_text("SUPERSECRET\n", encoding="utf-8")
        row = ffs.file_state(str(tree / "secretish"))
        assert "SUPERSECRET" not in repr(row)


class TestWatchList:
    def test_one_row_per_declared_path(self, tree):
        paths = [str(tree / "config"), str(tree / "nope"), str(tree / "adir")]
        rows = ffs.build_file_state(paths)
        assert [r["path"] for r in rows] == paths

    def test_duplicates_collapse_so_two_hosts_compare_row_for_row(self, tree):
        p = str(tree / "config")
        assert len(ffs.build_file_state([p, p, p])) == 1

    def test_empty_watch_list_is_zero_rows_not_an_error(self):
        """No watch list assigned is a legitimate state. It is the CONSUMER's
        job to refuse to call two empty watch lists 'identical'."""
        assert ffs.build_file_state([]) == []
        assert ffs.build_file_state(None) == []


class TestContractWiring:
    def test_table_is_in_the_contract(self):
        assert "sysmanage_file_state" in fs.FACT_TABLES

    def test_contract_version_was_bumped_for_it(self):
        """Adding a table changes the table SET, which is exactly what the
        version exists to signal."""
        assert fs.FACT_CONTRACT_VERSION >= 2

    def test_collect_routes_the_watch_list_through(self, tree):
        fn.register_native_provider()
        out = fn.collect(
            ["sysmanage_file_state"],
            {"sysmanage_file_state": {"paths": [str(tree / "config")]}},
        )
        assert out["sysmanage_file_state"][0]["state"] == ffs.STATE_PRESENT

    def test_collect_without_params_yields_no_rows(self, tree):
        """An unparameterized call must not raise, and must not invent rows."""
        fn.register_native_provider()
        assert fn.collect(["sysmanage_file_state"])["sysmanage_file_state"] == []

    def test_table_is_advertised_as_served(self):
        fn.register_native_provider()
        coverage = fs.build_fact_coverage(fn.platform_name())
        assert "sysmanage_file_state" in (coverage.get("served") or {})
