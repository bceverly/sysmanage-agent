# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""The storage host's append-only audit (24.1 / 24.5): baseline, exports,
filesystem and layout, each from fake readings -- nothing touches the host."""

# pylint: disable=protected-access

import os
import stat
import sys
from types import SimpleNamespace

import pytest

from src.sysmanage_agent.backup import storage_audit as a

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="Unix-only feature")
REPO = "/srv/backups/restate/t14-1"


def _codes(found):
    return {f["code"]: f["level"] for f in found}


@pytest.fixture
def account(monkeypatch):
    monkeypatch.setattr(a.pwd, "getpwnam", lambda n: SimpleNamespace(pw_uid=1002))
    monkeypatch.setattr(a.grp, "getgrnam", lambda n: SimpleNamespace(gr_gid=1003))


def test_a_good_freebsd_baseline(account):
    values = {("sysrc", "-n", "nfs_server_enable"): "YES",
              ("sysrc", "-n", "nfsv4_server_enable"): "YES",
              ("pgrep", "-x", "nfsd"): "123",
              ("sysctl", "-n", "vfs.nfsd.server_min_nfsvers"): "4",
              ("sysctl", "-n", "vfs.nfsd.enable_locallocks"): "1"}  # fmt: skip
    found = a.baseline("FreeBSD", "restate", run=lambda argv: values.get(tuple(argv)),
                       read=lambda p: "V4: /srv/backups -sec=sys\n")  # fmt: skip
    assert set(_codes(found).values()) == {"ok"}


def test_freebsd_without_local_locks_or_v4_root_is_an_error(account):
    values = {("sysrc", "-n", "nfs_server_enable"): "YES",
              ("sysrc", "-n", "nfsv4_server_enable"): "YES",
              ("pgrep", "-x", "nfsd"): "1",
              ("sysctl", "-n", "vfs.nfsd.server_min_nfsvers"): "2",
              ("sysctl", "-n", "vfs.nfsd.enable_locallocks"): "0"}  # fmt: skip
    found = _codes(a.baseline("FreeBSD", "restate",
                              run=lambda argv: values.get(tuple(argv)), read=lambda p: ""))  # fmt: skip
    assert found["nfs_local_locks"] == "error" and found["nfs_v4_root"] == "error"
    assert found["nfs_v4_only"] == "warning"


def test_linux_baseline_reads_the_kernels_versions(account):
    found = _codes(a.baseline(
        "Linux", "restate", run=lambda argv: "active" if argv[-1] == "nfs-server" else None,
        read=lambda p: "-2 +3 +4 +4.1 +4.2" if p.endswith("versions") else "",
    ))  # fmt: skip
    assert found["nfs_server"] == "ok" and found["nfs_v4"] == "ok"
    assert found["nfs_v4_only"] == "warning"  # v3 still served


def test_a_missing_service_account_is_an_error(monkeypatch):
    def missing(_name):
        raise KeyError(_name)

    monkeypatch.setattr(a.pwd, "getpwnam", missing)
    assert _codes(a.baseline("Plan9", "restate"))["service_account"] == "error"


def _exports(text):
    return lambda p: text if p in ("/etc/exports",) else ""


def test_a_shared_parent_export_is_an_error(account):
    text = "V4: /srv/backups\n/srv/backups/restate -alldirs -mapall=restate -sec=sys 192.168.4.196\n"
    found = _codes(a.export_findings("FreeBSD", REPO, "192.168.4.196", "restate",
                                     read=_exports(text)))  # fmt: skip
    assert found["export_shared"] == "error" and found["export_own"] == "warning"


def test_its_own_restricted_mapped_export_is_ok(account):
    text = f"{REPO} -mapall=restate:restate -sec=sys 192.168.4.196\n"
    found = _codes(a.export_findings("FreeBSD", REPO, "192.168.4.196", "restate",
                                     read=_exports(text)))  # fmt: skip
    assert found == {
        "export_own": "ok",
        "export_restricted": "ok",
        "export_mapping": "ok",
    }


def test_an_export_open_to_others_or_an_implicit_group_warns(account):
    text = f"{REPO} -mapall=restate -sec=sys 192.168.4.196 192.168.4.50\n"
    found = _codes(a.export_findings("FreeBSD", REPO, "192.168.4.196", "restate",
                                     read=_exports(text)))  # fmt: skip
    assert found["export_restricted"] == "warning"
    assert found["export_mapping"] == "warning"  # -mapall without :group


def test_linux_exports_need_all_squash_to_the_account(account):
    good = f"{REPO}\t192.168.4.196(rw,sync,all_squash,anonuid=1002,anongid=1003)\n"
    bad = f"{REPO}\t192.168.4.196(rw,sync,root_squash)\n"
    for text, level in ((good, "ok"), (bad, "error")):
        found = _codes(a.export_findings(
            "Linux", REPO, "192.168.4.196", "restate",
            read=lambda p, t=text: t if p == "/var/lib/nfs/etab" else "",
        ))  # fmt: skip
        assert found["export_mapping"] == level


def test_layout_needs_sticky_root_directories_and_root_owned_packs(
    account, tmp_path, monkeypatch
):
    repo = tmp_path / "r"
    (repo / "packs").mkdir(parents=True)
    (repo / "snapshots").mkdir()
    (repo / "packs" / "p1.tar.gz").write_text("x")
    (repo / "packs" / ".p2.tar.gz.tmp").write_text("x")  # unfinished: ignored
    real = os.lstat

    def as_protected(path):
        st = real(path)
        if os.path.isdir(path):
            return SimpleNamespace(st_uid=0, st_gid=1003, st_mode=stat.S_IFDIR | 0o1770)
        return SimpleNamespace(st_uid=0, st_gid=1003, st_mode=stat.S_IFREG | 0o440,
                               st_size=st.st_size)  # fmt: skip

    assert _codes(a.layout_findings(str(repo), "restate", lstat=as_protected)) == {
        "append_only_layout": "ok"
    }
    found = a.layout_findings(str(repo), "restate")  # really owned by the test user
    assert found[0]["level"] == "warning"
    assert found[0]["params"]["unprotected_files"] == 1


def test_a_parent_export_does_not_reach_a_repository_on_its_own_filesystem(account):
    text = f"/srv/backups -alldirs -mapall=restate:restate 192.168.4.0/24\n{REPO} -mapall=restate:restate 192.168.4.196\n"
    found = _codes(a.export_findings("FreeBSD", REPO, "192.168.4.196", "restate",
                                     read=_exports(text), own_fs=True))  # fmt: skip
    assert "export_shared" not in found and found["export_own"] == "ok"


def test_linux_crossmnt_still_reaches_a_child_filesystem(account):
    text = f"/srv/backups\t192.168.4.0/24(rw,crossmnt)\n{REPO}\t192.168.4.196(rw,all_squash,anonuid=1002,anongid=1003)\n"
    found = _codes(a.export_findings(
        "Linux", REPO, "192.168.4.196", "restate", own_fs=True,
        read=lambda p, t=text: t if p == "/var/lib/nfs/etab" else "",
    ))  # fmt: skip
    assert found["export_shared"] == "error"


def test_the_client_path_is_relative_to_the_nfsv4_root():
    text = "V4: /srv/backups -sec=sys\n/srv/backups/restate -alldirs 192.168.4.196\n"
    read = _exports(text)
    assert a.client_path("FreeBSD", REPO, read) == "/restate/t14-1"
    assert a.client_path("FreeBSD", "/elsewhere/r", read) is None
    assert a.client_path("FreeBSD", REPO, lambda p: "") is None  # no V4: line
    etab = f"/srv\t*(ro,fsid=0)\n{REPO}\t192.168.4.196(rw)\n"

    def linux(path):
        return etab if path == "/var/lib/nfs/etab" else ""

    assert a.client_path("Linux", REPO, linux) == "/backups/restate/t14-1"
    assert a.client_path("Linux", REPO, lambda p: "") == REPO
