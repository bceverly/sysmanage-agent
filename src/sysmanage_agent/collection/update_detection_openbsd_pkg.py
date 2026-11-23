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
import re
import subprocess  # nosec B404
from typing import Dict, List, Optional

from src.i18n import _

from .update_apply_batch import run_batch

logger = logging.getLogger(__name__)

PKG_ADD = "/usr/sbin/pkg_add"
DETECT_SECONDS = 1800
_UPGRADE = re.compile(r"^(\S+?)->(\S+): ok$")
# stem-version[-flavor]: the version is the first dash-part starting with a digit.
_NAME = re.compile(r"^(.+?)-(\d[^-]*)(?:-(.+))?$")


def split_name(installed: str) -> Optional[Dict[str, str]]:
    """``{stem, version, flavor}`` of an OpenBSD package name, or None."""
    match = _NAME.match(installed or "")
    if not match:
        return None
    return {"stem": match.group(1), "version": match.group(2),
            "flavor": match.group(3) or ""}  # fmt: skip


def parse_pkg_add_dry_run(output: str) -> List[Dict]:
    """The upgrades ``pkg_add -u -n`` reports, as update records."""
    updates = []
    for line in (output or "").splitlines():
        match = _UPGRADE.match(line.strip())
        if not match or match.group(1).startswith((".libs", "partial-")):
            continue
        old = split_name(match.group(1))
        if old is None:
            continue
        new = match.group(2)
        if old["flavor"] and new.endswith("-" + old["flavor"]):
            new = new[: -len(old["flavor"]) - 1]
        name = old["stem"] + (f"--{old['flavor']}" if old["flavor"] else "")
        updates.append({
            "package_name": name,
            "installed_name": match.group(1),
            # Kept by the server and sent back on apply: the exact package.
            "bundle_id": match.group(1),
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
