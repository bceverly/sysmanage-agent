# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""A detector must not mutate the host it describes (FreeBSD).

``_detect_freebsd_version_upgrades`` used to run
``freebsd-update upgrade -r RELEASE`` — inside a detection path.

``freebsd-update upgrade`` is not a query: it fetches an entire operating
system release into /var/db/freebsd-update and stages it for install. It is
also interactive, and ``-r RELEASE`` is a literal placeholder rather than a
version, so on FreeBSD 14.4 it sat until the 30-second timeout on every
collection cycle and logged an exception. It only avoided mutating the host
because it was malformed enough to fail.

These tests pin the two properties that matter: detection runs no mutating
command, and the pkg check uses the REMOTE catalogue.
"""

from unittest.mock import patch

from src.sysmanage_agent.collection.update_detection_bsd import BSDUpdateDetector

# Anything here would change the machine rather than describe it.
MUTATING = {
    ("freebsd-update", "upgrade"),
    ("freebsd-update", "install"),
    ("freebsd-update", "fetch"),
    ("pkg", "upgrade"),
    ("pkg", "install"),
    ("pkg", "delete"),
}


def _argv_pairs(calls):
    pairs = set()
    for call in calls:
        argv = call.args[0] if call.args else call.kwargs.get("args")
        if isinstance(argv, (list, tuple)) and len(argv) >= 2:
            pairs.add((str(argv[0]), str(argv[1])))
    return pairs


def test_version_upgrade_detection_runs_nothing_mutating():
    detector = BSDUpdateDetector()
    with patch(
        "src.sysmanage_agent.collection.update_detection_bsd.subprocess.run"
    ) as run:
        detector._detect_freebsd_version_upgrades()  # pylint: disable=protected-access
    assert _argv_pairs(run.call_args_list).isdisjoint(MUTATING)


def test_version_upgrade_detection_claims_nothing_without_evidence():
    """It used to decide on ``"upgrade" in stdout``, which matches usage text
    and most error messages — a release upgrade reported on no evidence."""
    detector = BSDUpdateDetector()
    detector.available_updates = []
    with patch("src.sysmanage_agent.collection.update_detection_bsd.subprocess.run"):
        detector._detect_freebsd_version_upgrades()  # pylint: disable=protected-access
    assert detector.available_updates == []


def test_the_pkg_check_uses_the_remote_catalogue():
    """Without ``-R`` pkg compares against the ports INDEX and fetches it over
    the network: measured at over 400 seconds versus 6 with it, so the timeout
    fired every time and the host reported zero updates while 28 were due.
    The parser underneath matches "remote has", which only -R emits."""
    detector = BSDUpdateDetector()
    with patch(
        "src.sysmanage_agent.collection.update_detection_bsd.subprocess.run"
    ) as run:
        run.return_value.returncode = 0
        run.return_value.stdout = ""
        detector._detect_pkg_updates()  # pylint: disable=protected-access
    version_calls = [
        c.args[0]
        for c in run.call_args_list
        if c.args and c.args[0][:2] == ["pkg", "version"]
    ]
    assert version_calls, "the pkg version check did not run"
    assert "-vRl" in version_calls[0]


class TestPkginReportsOnlyRealUpgrades:
    """``pkgin list -u`` is not an upgrade list — pkgin has no such flag.

    It ignores ``-u`` and prints the plain installed-package list, byte for
    byte identical to ``pkgin list``. So every installed package was reported
    as having an update available. Measured on NetBSD 10.1 on 2026-09-21: 184
    "updates" on a host with 184 packages installed and 16 genuinely
    upgradable. The old parser's ``available_version: "available"`` placeholder
    was the tell — the command it read cannot say what you would move to.
    """

    DRY_RUN = (
        "calculating dependencies...done.\n"
        "\n"
        "31 packages to refresh:\n"
        "brotli-1.2.0\n"
        "gmake-4.4.1\n"
        "\n"
        "16 packages to upgrade:\n"
        "chromium-149.0.7827.155nb1\n"
        "gcc12-libs-12.5.0nb4\n"
        "openssl-3.6.3\n"
        "\n"
        "3 packages to install:\n"
        "libfoo-1.0\n"
        "\n"
        "0 to remove, 31 to refresh, 16 to upgrade, 3 to install\n"
    )

    def _parse(self):
        detector = BSDUpdateDetector()
        return detector._parse_pkgin_upgrade_output(  # pylint: disable=protected-access
            self.DRY_RUN
        )

    def test_only_the_upgrade_section_is_read(self):
        """A refresh is a rebuild at the SAME version and an install is a new
        dependency; counting either overstates what an operator must do."""
        names = [u["package_name"] for u in self._parse()]
        assert names == ["chromium", "gcc12-libs", "openssl"]
        assert "brotli" not in names and "libfoo" not in names

    def test_the_target_version_is_real_not_a_placeholder(self):
        by_name = {u["package_name"]: u for u in self._parse()}
        assert by_name["openssl"]["available_version"] == "3.6.3"

    def test_a_hyphenated_package_name_splits_at_the_version(self):
        """pkgsrc names contain hyphens: 'gcc12-libs-12.5.0nb4' is the package
        gcc12-libs at 12.5.0nb4, not gcc12 at 'libs-12.5.0nb4'."""
        by_name = {u["package_name"]: u for u in self._parse()}
        assert by_name["gcc12-libs"]["available_version"] == "12.5.0nb4"

    def test_nothing_to_upgrade_yields_nothing(self):
        detector = BSDUpdateDetector()
        out = detector._parse_pkgin_upgrade_output(  # pylint: disable=protected-access
            "calculating dependencies...done.\n\n0 to remove, 0 to upgrade\n"
        )
        assert out == []

    def test_escalation_lives_in_one_place(self):
        detector = BSDUpdateDetector()
        with patch("os.geteuid", return_value=0):
            assert detector._pkgin_privileged(  # pylint: disable=protected-access
                ["-n", "upgrade"]
            ) == ["pkgin", "-n", "upgrade"]
