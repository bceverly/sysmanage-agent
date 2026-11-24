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


def _installed_parts(old: str) -> List[Dict[str, str]]:
    """The installed packages on the left of an upgrade line.

    t480's real output (2026-11-24) has four shapes besides the plain one:
    ``PARENT:DEP-1->2`` (a dependency, shown under what needs it);
    ``.libs-freerdp-2.11.8p0+freerdp-3.32.0`` (left-over library sets
    joined to the real package -- every such line was skipped, so freerdp,
    firefox and clamav were never offered); ``harfbuzz-14.5.0+harfbuzz-icu-
    14.5.0`` (two upgraded together); and ``postgresql-client+postgresql-
    contrib+postgresql-server-18.6`` (several names sharing the version
    written on the last)."""
    old = old.rsplit(":", 1)[-1]
    names = [n for n in old.split("+") if n and not n.startswith((".libs", "partial-"))]
    parsed = [split_name(n) for n in names]
    last = next((p for p in reversed(parsed) if p is not None), None)
    if last is None:
        return []
    out = []
    for name, part in zip(names, parsed):
        if part is None:  # a bare name sharing the last one's version
            part = {"stem": name, "version": last["version"], "flavor": last["flavor"]}
        installed = "-".join(
            x for x in (part["stem"], part["version"], part["flavor"]) if x
        )
        out.append({**part, "installed": installed})
    return out


def _new_version(new: str, flavor: str) -> str:
    """The version on the right of an upgrade line: a bare version
    (``2.5.4p0``, ``9.2.1373-perl-python3-ruby``) or full names
    (``freerdp-3.32.2``, ``harfbuzz+harfbuzz-icu-14.5.1``)."""
    last = new.split("+")[-1]
    named = split_name(last)
    if named is not None:
        last = "-".join(x for x in (named["version"], named["flavor"]) if x)
    if flavor and last.endswith("-" + flavor):
        last = last[: -len(flavor) - 1]
    return last


def parse_pkg_add_dry_run(output: str) -> List[Dict]:
    """The upgrades ``pkg_add -u -n`` reports, as update records -- one per
    installed package, however many lines name it."""
    updates: Dict[str, Dict] = {}
    for line in (output or "").splitlines():
        pair = _upgrade_line(line.strip())
        if pair is None:
            continue
        for old in _installed_parts(pair[0]):
            new = _new_version(pair[1], old["flavor"])
            if not new or new == old["version"] or old["installed"] in updates:
                continue  # quirks-7.227->7.227: nothing to do
            name = old["stem"] + (f"--{old['flavor']}" if old["flavor"] else "")
            updates[old["installed"]] = {
                "package_name": name,
                "installed_name": old["installed"],
                # Kept by the server and sent back on apply: the exact package.
                "bundle_id": old["installed"],
                "current_version": old["version"],
                "available_version": new,
                "package_manager": "pkg_add",
                "is_security_update": False,
                "is_system_update": False,
            }  # fmt: skip
    return list(updates.values())


def _privileged(argv: List[str]) -> List[str]:
    return list(argv) if os.geteuid() == 0 else ["doas", "-n"] + list(argv)


class OpenBSDPackageUpdateMixin:
    """pkg_add update detection and application for OpenBSD."""

    def _detect_openbsd_pkg_updates(self):
        try:
            # -I and no stdin: without them pkg_add can stop at a question
            # with no one to answer it, and the check hangs until its
            # timeout (t480, 2026-11-24: ten minutes over ssh).
            result = subprocess.run(  # nosec B603
                [PKG_ADD, "-I", "-u", "-n"], capture_output=True, text=True,
                stdin=subprocess.DEVNULL, timeout=DETECT_SECONDS, check=False,
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
