# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""Guards on the Windows installer authoring.

Every assertion here corresponds to a defect that was observed on a real
Windows Server 2022 boot, because that is the only place any of them showed up.
Unit tests could not have caught them and did not: the MSI built, installed,
and reported success through all of it.

The rule these encode: an MSI custom action may DETECT a prerequisite, never
install one.  The Python and VC++ installers are Windows Installer packages,
the parent MSI holds the ``_MSIExecute`` mutex for as long as its custom
actions run, and a nested install is refused with 1618.  That is structural,
not a race.
"""

import re
import shutil
import subprocess  # nosec B404 - runs local build tooling only
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
WINDOWS = REPO / "installer" / "windows"
MSI_WXS = WINDOWS / "sysmanage-agent.wxs"
BUNDLE_WXS = WINDOWS / "sysmanage-agent-bundle.wxs"

WIX_NS = {"w": "http://wixtoolset.org/schemas/v4/wxs"}


def _text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# The MSI must not try to install prerequisites in-transaction
# ---------------------------------------------------------------------------


def test_check_python_custom_action_defers_to_a_task():
    """The bug: this ran without -DeferToTask and tried a nested install.

    Result on a clean host was 1618 for both the VC++ redistributable and
    Python, no interpreter, no venv, no service -- and msiexec still exited 0,
    so Add/Remove Programs showed the agent installed while nothing would ever
    enrol.
    """
    root = ET.parse(MSI_WXS).getroot()
    actions = [
        a
        for a in root.iter(f"{{{WIX_NS['w']}}}CustomAction")
        if a.get("Id") == "CheckPython"
    ]
    assert len(actions) == 1, "expected exactly one CheckPython custom action"
    command = actions[0].get("ExeCommand", "")
    assert "check-python.ps1" in command
    assert "-DeferToTask" in command, (
        "CheckPython must pass -DeferToTask so the script only DETECTS "
        "prerequisites inside the MSI transaction; installing one there is "
        "refused with 1618"
    )


def test_check_python_still_installs_when_run_standalone():
    """-DeferToTask must be opt-in, not the default.

    The Pro+ provisioning first-boot script (virtualization_engine's
    windows_unattend.pxi) invokes this script with NO arguments and relies on
    it actually installing Python.  Making detect-only the default would break
    that path silently.
    """
    body = _text(WINDOWS / "check-python.ps1")
    assert "[switch]$DeferToTask" in body
    assert "if ($DeferToTask)" in body, "the deferral must be conditional"


@pytest.mark.parametrize("script", ["bootstrap-task.ps1", "bootstrap-state.ps1"])
def test_bootstrap_scripts_are_packaged(script):
    """A payload absent from the MSI is a bootstrap that never runs."""
    root = ET.parse(MSI_WXS).getroot()
    sources = {f.get("Source") for f in root.iter(f"{{{WIX_NS['w']}}}File")}
    assert script in sources, f"{script} is not packaged by the MSI"
    assert (WINDOWS / script).is_file()


# ---------------------------------------------------------------------------
# The deferred bootstrap must wait on the right signal
# ---------------------------------------------------------------------------


def test_bootstrap_waits_on_the_installer_mutex_not_on_msiexec_processes():
    """Measured regression, 2026-08-13.

    The first implementation waited for ``Get-Process msiexec`` to return
    nothing.  msiexec's SERVICE process deliberately stays resident for about
    ten minutes after an install completes, so the wait never ended promptly:
    the install finished at 14:32:22 and an msiexec process was still present
    300 seconds later, with the mutex long since released.  The bootstrap sat
    idle until its ten-minute timeout expired -- the service appeared, but only
    after ten minutes of looking broken.

    ``Global\\_MSIExecute`` is the mutex that actually returns 1618, so it is
    the only thing worth waiting on.
    """
    body = _text(WINDOWS / "bootstrap-task.ps1")
    assert "Global\\_MSIExecute" in body, "must query the Windows Installer mutex"
    assert not re.search(r"Get-Process\s+(-Name\s+)?['\"]?msiexec", body), (
        "waiting on msiexec PROCESSES is the regression this test exists for; "
        "the service process outlives the transaction by ~10 minutes"
    )


def test_bootstrap_never_exits_non_zero():
    """A non-zero return from a Return=\"check\" custom action rolls the whole
    MSI back -- files removed, no ARP entry -- which is the winget-pkgs
    PR #375773 burn.  Bad news belongs in the state key, not the exit code.
    """
    body = _text(WINDOWS / "bootstrap-task.ps1")
    assert "exit 0" in body
    assert not re.search(r"^\s*exit\s+[1-9]", body, re.M)


# ---------------------------------------------------------------------------
# The bundle
# ---------------------------------------------------------------------------


def test_bundle_chains_prerequisites_before_the_agent():
    """Order is the entire point of the bundle.

    Burn installs each chain entry in its own transaction, so Python must come
    BEFORE the MSI; afterwards would leave the MSI's detect pass finding
    nothing and deferring to a task it did not need.
    """
    root = ET.parse(BUNDLE_WXS).getroot()
    chain = root.find(f".//{{{WIX_NS['w']}}}Chain")
    assert chain is not None, "bundle has no Chain"
    ids = [child.get("Id") for child in chain]
    assert ids == [
        "VcRedist",
        "Python",
        "SysManageAgentMsi",
    ], f"unexpected chain order {ids}; prerequisites must precede the agent MSI"


def test_bundle_embeds_its_prerequisites():
    """Compressed payloads are what make the bundle work air-gapped.

    A bundle that downloads Python mid-install is useless in exactly the
    estates that most need one self-contained installer -- and "no route to
    python.org" is the most common cause of the original failure.
    """
    root = ET.parse(BUNDLE_WXS).getroot()
    chain = root.find(f".//{{{WIX_NS['w']}}}Chain")
    for child in chain:
        assert (
            child.get("Compressed") == "yes"
        ), f"{child.get('Id')} must be embedded, not downloaded at install time"


def test_bundle_leaves_python_behind_on_uninstall():
    """Removing the agent must not break unrelated software.

    Other things on the box may have started depending on the interpreter we
    installed.  A stray Python is a far smaller sin than a broken application.
    """
    root = ET.parse(BUNDLE_WXS).getroot()
    chain = root.find(f".//{{{WIX_NS['w']}}}Chain")
    for child in chain:
        if child.get("Id") in {"VcRedist", "Python"}:
            assert (
                child.get("Permanent") == "yes"
            ), f"{child.get('Id')} must be Permanent so uninstall leaves it"


def test_bundle_does_not_reinstall_an_existing_python():
    """The agent's floor is 3.9, so any 3.9+ must satisfy the prerequisite.

    Detecting only the version we ship would put a second interpreter on a
    machine that already had a working one, and then the two would argue about
    PATH.
    """
    body = _text(BUNDLE_WXS)
    for minor in (9, 10, 11, 12, 13):
        assert f"HavePython3{minor}" in body, f"no search for Python 3.{minor}"


# ---------------------------------------------------------------------------
# Icon
# ---------------------------------------------------------------------------


def test_icon_is_committed_and_referenced():
    """Windows CI has no SVG rasteriser, so the .ico must be in the tree."""
    assert (WINDOWS / "sysmanage-agent.ico").is_file()
    assert (WINDOWS / "sysmanage-agent-icon.svg").is_file()
    assert "sysmanage-agent.ico" in _text(BUNDLE_WXS)
    assert "ARPPRODUCTICON" in _text(MSI_WXS)


def test_icon_matches_its_svg_source():
    """A committed binary that has drifted from its source is a mystery blob."""
    if not shutil.which("magick"):
        pytest.skip("ImageMagick not installed; cannot re-render the icon")
    script = REPO / "scripts" / "build_windows_icon.py"
    result = subprocess.run(  # nosec B603 - fixed local script, no user input
        ["python3", str(script), "--check"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr


# ---------------------------------------------------------------------------
# PowerShell syntax, checked by PowerShell
# ---------------------------------------------------------------------------


def test_installer_powershell_parses():
    """Ask the consumer, not a regex.

    pwsh exists on the Windows CI leg and on any developer box with PowerShell
    installed; elsewhere this skips rather than pretending to have checked.
    """
    pwsh = shutil.which("pwsh") or shutil.which("powershell")
    if not pwsh:
        pytest.skip("PowerShell not installed; cannot parse-check the scripts")

    scripts = sorted(WINDOWS.glob("*.ps1"))
    assert scripts, "no installer PowerShell scripts found"

    # The paths are embedded in the script rather than passed as arguments:
    # with -Command, trailing arguments are appended to the command TEXT rather
    # than bound to $args, so a path like /home/... parses as a division.
    quoted = ",".join("'" + str(s).replace("'", "''") + "'" for s in scripts)
    checker = (
        f"$bad=0; foreach ($f in @({quoted})) {{ $t=$null; $e=$null; "
        "[void][System.Management.Automation.Language.Parser]::ParseFile("
        "$f,[ref]$t,[ref]$e); "
        'if ($e -and $e.Count -gt 0) { $bad++; Write-Output "FAIL $f"; '
        "foreach ($x in $e) { Write-Output $x.Message } } }; exit $bad"
    )
    result = subprocess.run(  # nosec B603 - fixed argv, paths from the repo
        [pwsh, "-NoProfile", "-Command", checker],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
