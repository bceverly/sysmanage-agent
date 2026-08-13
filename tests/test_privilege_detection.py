# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""``is_privileged`` decides whether the server believes a host can act.

That flag gates patching, service restarts and reboot-for-reprovision, so a
false POSITIVE is the expensive direction: the server dispatches work that
cannot possibly succeed, and the failure surfaces minutes later somewhere in a
log rather than as "this host is not privileged".

Two defects produced exactly that, and both are pinned here.

1. The probe ran ``sudo -n systemctl is-active sysmanage-agent`` and accepted
   any exit code except 255.  ``sudo -n`` exits 1 when it DENIES the request,
   and ``systemctl is-active`` exits 3 for an inactive unit -- so "denied" and
   "worked, unit inactive" were indistinguishable and both read as privileged.

2. The shipped sudoers granted systemctl only as ``/bin/systemctl``.  sudoers
   matches the LITERAL path, and on merged-/usr distros ``/bin`` is a symlink to
   ``usr/bin``, so the rule never authorised the ``/usr/bin/systemctl`` the
   agent actually invokes via PATH.
"""

import re
import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest

from src.sysmanage_agent.core.agent_privileges import _test_sudo_access

REPO = Path(__file__).resolve().parents[1]

# Merged-/usr distributions: /bin is a symlink to usr/bin, so a /bin-only rule
# authorises nothing.  Alpine and the BSDs have a real /bin and are excluded.
MERGED_USR_SUDOERS = [
    REPO / "installer" / "ubuntu" / "sysmanage-agent.sudoers",
    REPO / "installer" / "centos" / "sysmanage-agent.sudoers",
    REPO / "installer" / "opensuse" / "sysmanage-agent.sudoers",
]


def _completed(returncode):
    return subprocess.CompletedProcess(
        args=[], returncode=returncode, stdout="", stderr=""
    )


def test_sudo_denied_is_reported_as_unprivileged():
    """``sudo -n`` exits 1 when it refuses.  The old code called that privileged."""
    with patch("subprocess.run", return_value=_completed(1)):
        assert _test_sudo_access() is False


def test_sudo_working_is_reported_as_privileged():
    with patch("subprocess.run", return_value=_completed(0)):
        assert _test_sudo_access() is True


@pytest.mark.parametrize("code", [1, 2, 3, 4, 126, 127, 255])
def test_every_nonzero_exit_is_unprivileged(code):
    """The probe runs ``true``, which cannot fail on its own.

    So a non-zero status is a statement about sudo and nothing else -- there is
    no longer a class of exit codes meaning "sudo worked but the command
    didn't".
    """
    with patch("subprocess.run", return_value=_completed(code)):
        assert _test_sudo_access() is False


def test_the_probe_command_cannot_fail_on_its_own():
    """Pin the choice of ``true``.

    Any probe whose command can exit non-zero for its own reasons reintroduces
    the ambiguity: systemctl exits 3 for an inactive unit, 4 for an unknown one.
    """
    with patch("subprocess.run", return_value=_completed(0)) as run:
        _test_sudo_access()
    argv = run.call_args[0][0]
    assert argv[:2] == ["sudo", "-n"]
    assert argv[2] == "true", f"probe command must not be able to fail: {argv}"


def test_an_exception_is_unprivileged():
    """No sudo binary at all, or a timeout: assume not privileged."""
    with patch("subprocess.run", side_effect=FileNotFoundError):
        assert _test_sudo_access() is False


@pytest.mark.parametrize("path", MERGED_USR_SUDOERS, ids=lambda p: p.parent.name)
def test_systemctl_is_granted_at_its_real_merged_usr_path(path):
    """Every systemctl rule must list /usr/bin/systemctl.

    The agent resolves systemctl through PATH, which on these distros is
    /usr/bin/systemctl.  A rule naming only /bin/systemctl matches nothing.
    """
    offenders = [
        line
        for line in path.read_text().splitlines()
        if "NOPASSWD:" in line
        and re.search(r"[ ,]/bin/systemctl", line)
        and "/usr/bin/systemctl" not in line
    ]
    assert not offenders, "systemctl granted only at /bin: " + "; ".join(offenders)


@pytest.mark.parametrize("path", MERGED_USR_SUDOERS, ids=lambda p: p.parent.name)
def test_sudoers_still_parses(path):
    """A malformed sudoers drop-in locks the agent out of sudo entirely."""
    result = subprocess.run(
        ["visudo", "-c", "-f", str(path)], capture_output=True, text=True, check=False
    )
    if result.returncode != 0 and "command not found" in (result.stderr or ""):
        pytest.skip("visudo unavailable")
    assert result.returncode == 0, result.stdout + result.stderr
