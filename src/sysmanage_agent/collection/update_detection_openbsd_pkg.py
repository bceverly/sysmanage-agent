# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""OpenBSD third-party package updates: ``pkg_add -u`` (2026-11-23).

OpenBSD has no ``pkg`` command; the BSD detector looked for one, so an
OpenBSD host's packages were never checked for updates at all -- only base
(syspatch) and release (sysupgrade).  Detection is ``pkg_add -u -n``, a dry
run that needs no root and prints one line per upgrade::

    vim-9.2.1125p0-perl-python3-ruby->9.2.1373-perl-python3-ruby: ok

It compares every installed package against the mirror, so it is slow: nine
minutes on t480 (OpenBSD 8.0, a few hundred packages, over Wi-Fi).  Applying
is ``pkg_add -I -u`` with the installed names, flavor and all, through doas
(the agent's rule permits ``pkg_add``).
"""

import logging
import os
import subprocess  # nosec B404
from typing import Dict, List, Optional, Tuple

from src.i18n import _

from .update_apply_batch import run_batch

logger = logging.getLogger(__name__)

PKG_ADD = "/usr/sbin/pkg_add"
DETECT_SECONDS = 1800


def split_name(installed: str) -> Optional[Dict[str, str]]:
    """``{stem, version, flavor}`` of an OpenBSD package name, or None."""
    # stem-version[-flavor]: the version is the first dash-part (after the
    # first) that starts with a digit.
    parts = (installed or "").split("-")
    for index in range(1, len(parts)):
        if parts[index][:1].isdigit():
            stem = "-".join(parts[:index])
            if not stem:
                return None
            return {"stem": stem, "version": parts[index],
                    "flavor": "-".join(parts[index + 1:])}  # fmt: skip
    return None


def _upgrade_line(line: str) -> Optional[Tuple[str, str]]:
    """``old->new: ok`` -> (old, new), or None."""
    if not line.endswith(": ok"):
        return None
    old, sep, new = line[: -len(": ok")].partition("->")
    if not sep or not old or not new or any(c.isspace() for c in old + new):
        return None
    return old, new


def parse_pkg_add_dry_run(output: str) -> List[Dict]:
    """The upgrades ``pkg_add -u -n`` reports, as update records."""
    updates = []
    for line in (output or "").splitlines():
        pair = _upgrade_line(line.strip())
        if pair is None or pair[0].startswith((".libs", "partial-")):
            continue
        installed, new = pair
        old = split_name(installed)
        if old is None:
            continue
        if old["flavor"] and new.endswith("-" + old["flavor"]):
            new = new[: -len(old["flavor"]) - 1]
        name = old["stem"] + (f"--{old['flavor']}" if old["flavor"] else "")
        updates.append({
            "package_name": name,
            "installed_name": installed,
            # Kept by the server and sent back on apply: the exact package.
            "bundle_id": installed,
            "current_version": old["version"],
            "available_version": new,
            "package_manager": "pkg_add",
            "is_security_update": False,
            "is_system_update": False,
        })  # fmt: skip
    return updates


def _privileged(argv: List[str]) -> List[str]:
    return list(argv) if os.geteuid() == 0 else ["doas", "-n"] + list(argv)


class OpenBSDPackageUpdateMixin:
    """pkg_add update detection and application for OpenBSD."""

    def _detect_openbsd_pkg_updates(self):
        try:
            result = subprocess.run(  # nosec B603
                [PKG_ADD, "-u", "-n"], capture_output=True, text=True,
                timeout=DETECT_SECONDS, check=False,
            )  # fmt: skip
            found = parse_pkg_add_dry_run(result.stdout)
            self.available_updates.extend(found)
            if found:
                logger.info("Found %d OpenBSD package updates", len(found))
        except Exception as error:  # pylint: disable=broad-exception-caught
            logger.exception(
                _("Failed to detect OpenBSD package updates: %s"), str(error)
            )

    def _apply_pkg_add_updates(self, packages: List[Dict], results: Dict):
        names = [p.get("bundle_id") or p.get("installed_name") or p["package_name"]
                 for p in packages]  # fmt: skip
        run_batch(
            "pkg_add", [_privileged([PKG_ADD, "-I", "-u", *names])], packages, results
        )
