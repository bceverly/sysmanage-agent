# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""Held packages are marked in the update scan (ROADMAP 26.1): apt-get -y
refuses a whole transaction that changes a held package, so the server must
know which ones to leave out."""

import subprocess
from unittest.mock import patch

from src.sysmanage_agent.collection import package_holds


def _completed(stdout, code=0):
    return subprocess.CompletedProcess(args=[], returncode=code, stdout=stdout)


def test_apt_holds():
    with patch(
        "subprocess.run",
        return_value=_completed("linux-image-generic\npostgresql-16\n"),
    ):
        assert package_holds.apt_held() == {"linux-image-generic", "postgresql-16"}


def test_pkg_locks_drop_the_version():
    out = "Currently locked packages:\nnginx-1.24.0_12,3\npy311-django42-4.2.16\n"
    with patch("subprocess.run", return_value=_completed(out)):
        assert package_holds.pkg_locked() == {"nginx", "py311-django42"}


def test_a_failing_tool_means_no_holds_not_a_failed_scan():
    with patch("subprocess.run", side_effect=FileNotFoundError("apt-mark")):
        assert package_holds.apt_held() == set()
    with patch("subprocess.run", return_value=_completed("", code=1)):
        assert package_holds.pkg_locked() == set()


def test_mark():
    updates = [{"package_name": "postgresql-16"}, {"package_name": "curl"}]
    package_holds.mark(updates, {"postgresql-16"})
    assert [u["held"] for u in updates] == [True, False]
