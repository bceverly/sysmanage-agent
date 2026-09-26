# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""pkgin (NetBSD / pkgsrc) update detection.

Split out of ``update_detection_bsd.py`` when that module reached the
repository's 1000-line ceiling. A mixin rather than a separate collector so
``BSDUpdateDetector`` keeps one public surface -- the BSDs share an
``apply_updates`` path and splitting the class would have meant splitting that
too.

THE DEFECT THIS CARRIES THE SCARS OF
------------------------------------
Detection used to run ``pkgin list -u``. pkgin has no ``-u`` flag for
``list``; it ignores it and prints the plain installed-package list, so EVERY
installed package was reported as having an update available. Measured on
NetBSD 10.1 on 2026-09-21: 184 "updates" on a host with 184 packages and 16
genuinely upgradable. Nothing failed -- the numbers were simply wrong, and
wrong in the direction that makes a fleet look neglected.
"""

import logging
import os
import re
import subprocess

from src.i18n import _

logger = logging.getLogger(__name__)


class PkginUpdateMixin:
    """pkgin update detection for NetBSD and pkgsrc hosts."""

    def _parse_pkgin_upgrade_output(self, output):
        """The packages in the "to upgrade" section, as update dicts.

        The dry run prints several sections -- refresh, upgrade, install --
        each introduced by "N packages to <verb>:" and terminated by a blank
        line. Only "upgrade" means an installed package moving to a new
        version; a refresh is a rebuild at the SAME version, and an install is
        a new dependency. Reading the whole output would report all three as
        updates.
        """
        updates = []
        in_section = False
        for line in (output or "").splitlines():
            if self._PKGIN_UPGRADE_SECTION.match(line.strip()):
                in_section = True
                continue
            if not in_section:
                continue
            stripped = line.strip()
            # A blank line, or the next section header, ends this one.
            if not stripped or self._PKGIN_SECTION.match(stripped):
                break
            parsed = self._parse_pkgin_update_line(stripped)
            if parsed:
                updates.append(parsed)
        return updates

    def _pkgin_privileged(self, args):
        """``pkgin`` plus ``args``, escalated when this process is not root.

        Derived from ``_collect_pkgin_update_command`` so the escalation
        decision (root / doas / sudo) lives in ONE place; that method returns
        ``[...prefix, "pkgin", "update"]``, so dropping the final two elements
        leaves exactly the prefix.
        """
        prefix = self._collect_pkgin_update_command()[:-2]
        return prefix + ["pkgin"] + list(args)

    def _collect_pkgin_update_command(self):
        """Determine the correct pkgin update command based on privilege level.

        Returns:
            list: The command to run for pkgin update.
        """
        is_root = os.geteuid() == 0

        if is_root:
            return ["pkgin", "update"]
        if self._command_exists("doas"):
            return ["doas", "pkgin", "update"]
        if self._command_exists("sudo"):
            return ["sudo", "-n", "pkgin", "update"]
        return ["pkgin", "update"]

    def _process_pkgin_update_repo(self):
        """Run pkgin update to refresh the package repository.

        Logs warnings on failure but does not raise, allowing stale data checks.
        """
        update_cmd = self._collect_pkgin_update_command()

        update_result = subprocess.run(  # nosec B603, B607
            update_cmd, capture_output=True, text=True, timeout=60, check=False
        )

        if update_result.returncode != 0:
            logger.warning(
                _("pkgin update failed (code %d): %s"),
                update_result.returncode,
                (
                    update_result.stderr.strip()
                    if update_result.stderr
                    else "No error message"
                ),
            )
        else:
            logger.debug("pkgin update completed successfully")

    @staticmethod
    def _split_pkgsrc_name_version(token):
        """Split ``name-version`` as pkgsrc spells it, or None.

        The version starts at the LAST hyphen that is followed by a digit, so
        "gcc12-libs-12.5.0nb4" splits into "gcc12-libs" and "12.5.0nb4" rather
        than at the first hyphen. The name must be non-empty and the version
        may not contain whitespace. This is a linear scan rather than the
        equivalent ``^(.+)-(\\d[^\\s]*)$`` regex, which backtracks
        quadratically on a long token with many hyphens.
        """
        if token.endswith("\n"):
            # Mirror the regex's "$", which also matches before one final
            # newline.
            token = token[:-1]
        if "\n" in token:
            return None
        # The version may not contain whitespace, so it has to start after
        # the last whitespace character; find that once, up front.
        floor = 0
        for index in range(len(token) - 1, -1, -1):
            if token[index].isspace():
                floor = index
                break
        end = len(token)
        while True:
            hyphen = token.rfind("-", 0, end)
            if hyphen < max(floor, 1):
                return None
            if token[hyphen + 1 : hyphen + 2].isdecimal():
                return token[:hyphen], token[hyphen + 1 :]
            end = hyphen

    # "16 packages to upgrade:" -- the only section that describes an UPDATE to
    # something already installed. "refresh" is a rebuild at the same version
    # and "install" is a new dependency; counting either as an available
    # update would overstate what an operator has to do.
    _PKGIN_UPGRADE_SECTION = re.compile(r"^\d+ packages to upgrade:\s*$")
    _PKGIN_SECTION = re.compile(r"^\d+ packages to \w+:\s*$")

    def _parse_pkgin_update_line(self, line):
        """Split one ``name-version`` token from pkgin's upgrade list."""
        token = (line or "").strip()
        if not token or token.startswith("pkg_summary"):
            return None
        split = self._split_pkgsrc_name_version(token)
        if not split:
            return None
        return {
            "package_name": split[0],
            "current_version": None,
            "available_version": split[1],
            "package_manager": "pkgin",
            "is_security_update": False,
            "is_system_update": False,
        }

    def _pkgin_installed_versions(self):
        """{package name: installed version} from ``pkgin list``."""
        try:
            result = subprocess.run(  # nosec B603, B607
                ["pkgin", "list"],
                capture_output=True,
                text=True,
                timeout=60,
                check=False,
            )
        except (OSError, subprocess.SubprocessError):
            return {}
        if result.returncode != 0:
            return {}

        installed = {}
        for line in result.stdout.splitlines():
            token = line.split()[0] if line.split() else ""
            split = self._split_pkgsrc_name_version(token)
            if split:
                installed[split[0]] = split[1]
        return installed

    def _detect_pkgin_updates(self):
        """Detect updates from NetBSD pkgin."""
        logger.debug("=== PKGIN DETECTION START ===")
        try:
            logger.debug("Detecting pkgin updates")

            self._process_pkgin_update_repo()

            # ``pkgin -n upgrade``, NOT ``pkgin list -u``.
            #
            # pkgin has no ``-u`` flag for ``list`` and silently ignores it, so
            # ``pkgin list -u`` returns the plain installed-package list --
            # byte for byte identical to ``pkgin list``. Every installed
            # package was therefore reported as having an update available.
            # Measured on NetBSD 10.1 on 2026-09-21: 184 "updates" reported on
            # a host with 184 packages installed and 16 genuinely upgradable.
            #
            # The old parser even filled ``available_version`` with the
            # literal string "available", which was the tell: the command it
            # read cannot say what version you would move TO.
            result = subprocess.run(  # nosec B603, B607
                self._pkgin_privileged(["-n", "upgrade"]),
                capture_output=True,
                text=True,
                timeout=180,
                check=False,
            )

            if result.returncode != 0:
                logger.warning(
                    _("pkgin -n upgrade failed (code %d): %s"),
                    result.returncode,
                    result.stderr.strip() if result.stderr else "No error message",
                )
                return

            installed = self._pkgin_installed_versions()
            update_count = 0
            for update in self._parse_pkgin_upgrade_output(result.stdout):
                update["current_version"] = installed.get(update["package_name"])
                self.available_updates.append(update)
                update_count += 1

            if update_count > 0:
                logger.info("Found %d pkgin updates", update_count)

            logger.debug("=== PKGIN DETECTION END ===")
        except Exception as error:
            logger.exception(_("Failed to detect pkgin updates: %s"), str(error))
