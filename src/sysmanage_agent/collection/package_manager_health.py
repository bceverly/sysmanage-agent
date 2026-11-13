# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""Is this host's package manager able to install anything, and if not, fix it
(server: the hosts grid's "Package manager needs repair", 2026-11-13).

Production, 2026-11-13: an update that stopped the agent mid-upgrade left
dpkg interrupted on eight hosts, and from then on every update sent to them
failed with "dpkg was interrupted, you must manually run 'sudo dpkg
--configure -a'" -- while the hosts looked healthy.  So each update scan
also says whether the package manager needs repairing, and why:

* dpkg (Debian, Ubuntu): an interrupted run (``/var/lib/dpkg/updates`` holds
  files) or packages ``dpkg --audit`` reports half-installed or unconfigured.
  Repair: ``dpkg --configure -a``, then ``apt-get install -f``.
* dnf (Fedora, EL): ``dnf check`` reports broken dependencies or duplicates.
  Reported, not repaired: which package to keep is the operator's call.
* pkg (FreeBSD): ``pkg check -d`` reports missing dependencies.
  Repair: ``pkg check -d -y`` installs them.

Every check runs unprivileged and reads only; only the repair uses sudo,
through rules the sudoers grants for exactly those commands.  Elsewhere
(macOS, Windows, the other BSDs, Alpine, openSUSE) nothing is checked and
nothing is reported as wrong.
"""

import os
import platform
import shutil
import subprocess  # nosec B404
from typing import Any, Callable, Dict, List, Optional, Tuple

DPKG_UPDATES = "/var/lib/dpkg/updates"
CHECK_SECONDS = 120
REPAIR_SECONDS = 1800

Run = Callable[[List[str], int], Tuple[int, str]]


def _run(argv: List[str], timeout: int) -> Tuple[int, str]:
    try:
        done = subprocess.run(  # nosec B603
            argv, capture_output=True, text=True, timeout=timeout, check=False
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        return 127, str(error)
    return done.returncode, (done.stdout or "") + (done.stderr or "")


def _first_line(text: str) -> str:
    for line in text.splitlines():
        if line.strip():
            return line.strip()[:240]
    return ""


def _manager(
    which: Callable = shutil.which, system: Optional[str] = None
) -> Optional[str]:
    system = system or platform.system()
    if system == "FreeBSD" and (which("pkg") or os.path.exists("/usr/sbin/pkg")):
        return "pkg"
    if system != "Linux":
        return None
    if which("dpkg"):
        return "dpkg"
    if which("dnf"):
        return "dnf"
    return None


def check(
    run: Run = _run,
    which: Callable = shutil.which,
    listdir: Callable = os.listdir,
    system: Optional[str] = None,
) -> Dict[str, Any]:
    """``{"manager", "needs_repair", "reason", "repairable"}``; ``manager``
    None where nothing is checked."""
    manager = _manager(which, system)
    found: Dict[str, Any] = {
        "manager": manager,
        "needs_repair": False,
        "reason": None,
        "repairable": manager in ("dpkg", "pkg"),
    }
    if manager == "dpkg":
        try:
            interrupted = bool(listdir(DPKG_UPDATES))
        except OSError:
            interrupted = False
        if interrupted:
            found.update(needs_repair=True, reason="dpkg was interrupted")
            return found
        code, out = run(["dpkg", "--audit"], CHECK_SECONDS)
        if code == 0 and out.strip():
            found.update(needs_repair=True, reason=_first_line(out))
    elif manager == "dnf":
        code, out = run(["dnf", "-q", "check"], CHECK_SECONDS)
        if code != 0 and out.strip():
            found.update(needs_repair=True, reason=_first_line(out))
    elif manager == "pkg":
        code, out = run(["pkg", "check", "-d", "-n"], CHECK_SECONDS)
        if code != 0 or "missing" in out.lower():
            if out.strip():
                found.update(needs_repair=True, reason=_first_line(out))
    return found


def _sudo(argv: List[str]) -> List[str]:
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        return argv
    return ["sudo", "-n"] + argv


def repair_steps(manager: Optional[str]) -> Optional[List[List[str]]]:
    """What fixes it, or None where this agent does not repair it."""
    if manager == "dpkg":
        return [
            ["dpkg", "--configure", "-a"],
            ["apt-get", "install", "-f", "-y"],
        ]
    if manager == "pkg":
        return [["pkg", "check", "-d", "-y"]]
    return None


def repair(run: Run = _run, **probe) -> Dict[str, Any]:
    """Repair the package manager, then check it again.  ``{"success",
    "health", "output"}``; ``reason`` ``not_repairable`` where there is no
    safe automatic repair (dnf) or nothing to check here."""
    before = check(run=run, **probe)
    steps = repair_steps(before["manager"])
    if steps is None:
        return {
            "success": False,
            "reason": "not_repairable",
            "health": before,
            "output": "",
        }
    steps_log = []
    for argv in steps:
        code, out = run(_sudo(argv), REPAIR_SECONDS)
        steps_log.append(f"$ {' '.join(argv)}\n{out.strip()}")
        if code != 0:
            return {
                "success": False,
                "reason": "repair_failed",
                "health": check(run=run, **probe),
                "output": "\n".join(steps_log)[-2000:],
            }
    after = check(run=run, **probe)
    return {
        "success": not after["needs_repair"],
        "reason": None if not after["needs_repair"] else "still_broken",
        "health": after,
        "output": "\n".join(steps_log)[-2000:],
    }


def unavailable_reason(
    _lookup: Optional[Callable] = None, system: Optional[str] = None
) -> Optional[str]:
    """Where there is a package manager this agent checks: Linux (dpkg,
    dnf) and FreeBSD (pkg)."""
    if (system or platform.system()) in ("Linux", "FreeBSD"):
        return None
    return "wrong_platform"
