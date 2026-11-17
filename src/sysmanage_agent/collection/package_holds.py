# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""Packages the administrator has held back on purpose (ROADMAP 26.1).

``apt list --upgradable`` and ``pkg version`` still list a held package as
having an update.  Sent to the server unmarked, it was offered for update
like any other -- and ``apt-get -y`` refuses a whole transaction that would
change a held package, so one hold failed every package beside it.  Each
update scan now marks its holds; the server leaves them out of automatic
updates and never overrides them.

dnf's versionlock needs nothing here: a locked version never appears in
``dnf check-update`` at all.  zypper's locks (``zypper addlock``) can be
patterns (``kernel*``), so they match as globs.

Read-only and unprivileged; any failure is "no holds known", never a failed
scan.
"""

import fnmatch
import logging
import subprocess  # nosec B404

logger = logging.getLogger(__name__)


def _run(command):
    try:
        result = subprocess.run(  # nosec B603, B607
            command, capture_output=True, text=True, timeout=30, check=False
        )
    except Exception as error:  # pylint: disable=broad-exception-caught
        logger.debug("%s: %s", command[0], error)
        return ""
    return result.stdout if result.returncode == 0 else ""


def apt_held() -> set:
    """``apt-mark showhold``: one package name per line."""
    return {line.strip() for line in _run(["apt-mark", "showhold"]).splitlines()
            if line.strip()}  # fmt: skip


def pkg_locked() -> set:
    """FreeBSD ``pkg lock -l``: "Currently locked packages:" then
    ``name-version`` lines."""
    names = set()
    for line in _run(["pkg", "lock", "-l"]).splitlines():
        line = line.strip()
        if not line or line.endswith(":") or "-" not in line:
            continue
        names.add(line.rsplit("-", 1)[0])
    return names


def zypper_locked() -> set:
    """``zypper locks``: a table whose columns vary by version (``# | Name |
    Matches | Type | Repository``, or without Matches); the Name column of
    every package lock.  Names may be patterns."""
    names, header = set(), None
    for line in _run(["zypper", "--non-interactive", "locks"]).splitlines():
        cells = [c.strip() for c in line.split("|")]
        if len(cells) < 2:
            continue
        if header is None:
            if "Name" in cells:
                header = cells
            continue
        if set(line.strip()) <= set("-+"):
            continue
        row = dict(zip(header, cells))
        if row.get("Name") and row.get("Type", "package") in ("package", ""):
            names.add(row["Name"])
    return names


def is_held(name, held: set) -> bool:
    """``name`` is held: named outright, or matched by a pattern lock."""
    if not name:
        return False
    if name in held:
        return True
    return any(fnmatch.fnmatchcase(name, p) for p in held if any(c in p for c in "*?["))


def mark(updates, held: set) -> None:
    """Set ``held`` on each update whose package is held."""
    for update in updates:
        update["held"] = is_held(update.get("package_name"), held)
