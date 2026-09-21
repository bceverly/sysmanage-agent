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
