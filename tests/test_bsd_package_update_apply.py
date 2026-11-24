# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""OpenBSD package updates (``pkg_add -u``) and NetBSD pkgin updates applied
(2026-11-23: OpenBSD's packages were never checked -- the detector looked for
a ``pkg`` command OpenBSD does not have -- and pkgin updates were detected
but never applied)."""

from types import SimpleNamespace
from unittest.mock import patch

from src.sysmanage_agent.collection import update_apply_batch
from src.sysmanage_agent.collection import update_detection_openbsd_pkg as obsd
from src.sysmanage_agent.collection.update_detection_bsd import BSDUpdateDetector

# t480 (OpenBSD 8.0), ``pkg_add -u -n``, 2026-11-23.
DRY_RUN = """quirks-7.103->7.110: ok
.libs-tb-browser-14.5.6+tb-browser-15.0.26->tb-browser-16.0.1: ok
tb-noscript-13.6.36.1984->13.6.38.1984: ok
tor-browser-15.0.26->16.0.1: ok
vim-9.2.1125p0-perl-python3-ruby->9.2.1373-perl-python3-ruby: ok
Couldn't find updates for eog-50.3 glib2-networking-2.80.1p0
"""


def test_the_dry_run_names_each_upgrade_with_its_flavor():
    found = obsd.parse_pkg_add_dry_run(DRY_RUN)
    assert [(u["package_name"], u["current_version"], u["available_version"])
            for u in found] == [
        ("quirks", "7.103", "7.110"),
        # joined to a left-over .libs set: once skipped, a real update
        ("tb-browser", "15.0.26", "16.0.1"),
        ("tb-noscript", "13.6.36.1984", "13.6.38.1984"),
        ("tor-browser", "15.0.26", "16.0.1"),
        ("vim--perl-python3-ruby", "9.2.1125p0", "9.2.1373"),
    ]  # fmt: skip
    assert found[-1]["installed_name"] == "vim-9.2.1125p0-perl-python3-ruby"
    assert all(u["package_manager"] == "pkg_add" for u in found)


def _capture():
    calls = []

    def run(argv, **_kw):
        calls.append(argv)
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    return calls, run


def test_openbsd_upgrades_by_installed_name_through_doas():
    calls, run = _capture()
    results = {}
    detector = BSDUpdateDetector()
    with patch.object(obsd.os, "geteuid", return_value=1000, create=True), \
            patch.object(update_apply_batch.subprocess, "run", side_effect=run):  # fmt: skip
        detector._apply_pkg_add_updates(  # pylint: disable=protected-access
            [{"package_name": "vim--perl-python3-ruby"},
             {"package_name": "quirks", "installed_name": "quirks-7.103"}], results)  # fmt: skip
    assert calls == [["doas", "-n", "/usr/sbin/pkg_add", "-I", "-u",
                      "vim--perl-python3-ruby", "quirks-7.103"]]  # fmt: skip
    assert len(results["updated_packages"]) == 2


def test_netbsd_installs_the_new_versions_with_pkgin():
    calls, run = _capture()
    results = {}
    detector = BSDUpdateDetector()
    with patch.object(detector, "_collect_pkgin_update_command",
                      return_value=["sudo", "-n", "pkgin", "update"]), \
            patch.object(update_apply_batch.subprocess, "run", side_effect=run):  # fmt: skip
        detector._apply_pkgin_updates(  # pylint: disable=protected-access
            [{"package_name": "curl"}, {"package_name": "git"}], results
        )
    assert calls == [["sudo", "-n", "pkgin", "-y", "install", "curl", "git"]]


def test_the_bsd_dispatcher_routes_pkgin_and_pkg_add():
    detector = BSDUpdateDetector()
    for manager, method in (("pkgin", "_apply_pkgin_updates"),
                            ("pkg_add", "_apply_pkg_add_updates")):  # fmt: skip
        with patch.object(BSDUpdateDetector, method) as handler:
            detector._process_bsd_manager_updates(  # pylint: disable=protected-access
                manager,
                [{"package_name": "x"}],
                {"updated_packages": [], "failed_packages": []},
            )
        assert handler.called, manager


def test_netbsd_sudoers_lets_a_packaged_agent_run_pkgin_with_options():
    with open("installer/netbsd/sysmanage_agent.sudoers", encoding="utf-8") as handle:
        assert "NOPASSWD: /usr/pkg/bin/pkgin *\n" in handle.read()


def test_the_openbsd_check_never_waits_on_a_question():
    """t480, 2026-11-24: ``pkg_add -u -n`` with a terminal-less stdin sat ten
    minutes on a prompt; the check runs non-interactive with no stdin."""
    seen = {}

    def fake_run(argv, **kwargs):
        seen["argv"], seen["stdin"] = argv, kwargs.get("stdin")
        return SimpleNamespace(stdout="", returncode=0)

    detector = BSDUpdateDetector()
    detector.available_updates = []
    with patch.object(obsd.subprocess, "run", side_effect=fake_run):
        detector._detect_openbsd_pkg_updates()  # pylint: disable=protected-access
    assert seen["argv"][1:] == ["-I", "-u", "-n"]
    assert seen["stdin"] is obsd.subprocess.DEVNULL


T480_SHAPES = """\
ImageMagick-6.9.13.59:openjp2-2.5.4->2.5.4p0: ok
ImageMagick-6.9.13.55->6.9.13.59: ok
.libs-freerdp-2.11.8p0+freerdp-3.32.0->freerdp-3.32.2: ok
adwaita-icon-theme-50.0:.libs-harfbuzz-14.1.0+harfbuzz-14.5.0+harfbuzz-icu-14.5.0->harfbuzz+harfbuzz-icu-14.5.1: ok
libreoffice-26.8.0.3v0:postgresql-client+postgresql-server-18.6->18.7: ok
aisleriot-3.22.35:libjxl-0.12.0->0.13.0: ok
gnome-49p8:libjxl-0.12.0->0.13.0: ok
quirks-7.227->7.227: ok
vim-9.2.1125p0-perl-python3-ruby->9.2.1373-perl-python3-ruby: ok
"""


def test_every_shape_t480_printed_is_one_record_per_installed_package():
    """t480 (OpenBSD 8.0), 2026-11-24: lines joined with ``+`` to left-over
    ``.libs`` sets were skipped (freerdp, firefox, clamav never offered);
    ``PARENT:DEP`` lines became a bogus record for the parent."""
    found = {u["installed_name"]: u["available_version"]
             for u in obsd.parse_pkg_add_dry_run(T480_SHAPES)}  # fmt: skip
    assert found == {
        "openjp2-2.5.4": "2.5.4p0",
        "ImageMagick-6.9.13.55": "6.9.13.59",
        "freerdp-3.32.0": "3.32.2",
        "harfbuzz-14.5.0": "14.5.1",
        "harfbuzz-icu-14.5.0": "14.5.1",
        "postgresql-client-18.6": "18.7",
        "postgresql-server-18.6": "18.7",
        "libjxl-0.12.0": "0.13.0",  # named by two parents, offered once
        "vim-9.2.1125p0-perl-python3-ruby": "9.2.1373",
    }  # quirks: no change, no record
