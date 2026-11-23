# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""Applying updates on macOS (2026-11-23).

The macOS detector had no ``apply_updates`` at all, so EVERY update applied
to a Mac -- Homebrew included -- failed inside the agent with an
AttributeError.  This adds it, and the managers it routes to:

* ``homebrew`` and ``macos-upgrade`` -- the existing appliers;
* ``mac_app_store`` -- what ``softwareupdate --list`` reports (Safari, macOS
  point releases, Command Line Tools): ``softwareupdate --install <label>``,
  the label carried in ``bundle_id`` (and looked up again by title when an
  older agent's report has none);
* ``macports`` -- ``port -N upgrade <ports>``;
* ``mas`` -- App Store apps through the ``mas`` command-line tool:
  ``mas outdated`` to detect, ``mas upgrade <app id>`` to apply.
"""

import logging
import os
import re
import subprocess  # nosec B404
from typing import Dict, List, Optional

from src.i18n import _

from .update_apply_batch import run_batch

logger = logging.getLogger(__name__)

# "497799835 Xcode (15.0 -> 15.1)"
_MAS_LINE = re.compile(r"^(\d+)\s+(.+?)\s+\((\S+)\s+->\s+(\S+)\)\s*$")


def parse_mas_outdated(output: str) -> List[Dict]:
    """App Store updates from ``mas outdated``."""
    updates = []
    for line in (output or "").splitlines():
        match = _MAS_LINE.match(line.strip())
        if match:
            updates.append({
                "package_name": match.group(2),
                "bundle_id": match.group(1),
                "current_version": match.group(3),
                "available_version": match.group(4),
                "package_manager": "mas",
                "is_security_update": False,
                "is_system_update": False,
            })  # fmt: skip
    return updates


def _as_root(argv: List[str]) -> List[str]:
    return list(argv) if os.geteuid() == 0 else ["sudo", "-n"] + list(argv)


class MacOSApplyMixin:
    """``apply_updates`` for the macOS detector."""

    def _detect_mas_updates(self):
        try:
            result = subprocess.run(  # nosec B603, B607
                ["mas", "outdated"], capture_output=True, text=True, timeout=120,
                check=False,
            )  # fmt: skip
            if result.returncode == 0:
                self.available_updates.extend(parse_mas_outdated(result.stdout))
        except Exception as error:  # pylint: disable=broad-exception-caught
            logger.exception(_("Failed to detect App Store updates: %s"), str(error))

    def _softwareupdate_labels(self) -> Dict[str, str]:
        """{title: label} from a fresh ``softwareupdate --list``."""
        labels: Dict[str, str] = {}
        try:
            out = subprocess.run(  # nosec B603, B607
                ["softwareupdate", "--list"], capture_output=True, text=True,
                timeout=120, check=False,
            ).stdout  # fmt: skip
        except (OSError, subprocess.SubprocessError):
            return labels
        label: Optional[str] = None
        for line in out.splitlines():
            found = re.match(r"\s*\*\s+Label:\s+(.+)", line)
            if found:
                label = found.group(1).strip()
                continue
            title = re.match(r"\s*Title:\s+([^,]+)", line)
            if title and label:
                labels[title.group(1).strip()] = label
                label = None
        return labels

    def _apply_softwareupdate_updates(self, packages: List[Dict], results: Dict):
        known = None
        for package in packages:
            label = package.get("bundle_id") or package.get("label")
            if not label:
                known = known if known is not None else self._softwareupdate_labels()
                label = known.get(package["package_name"])
            if not label:
                results["failed_packages"].append({
                    "package_name": package["package_name"],
                    "package_manager": "mac_app_store",
                    "error": _("Software Update no longer lists this update."),
                })  # fmt: skip
                continue
            run_batch("mac_app_store",
                      [_as_root(["softwareupdate", "--install", label, "--agree-to-license"])],
                      [package], results, timeout=3600)  # fmt: skip

    def _apply_macports_updates(self, packages: List[Dict], results: Dict):
        names = [p["package_name"] for p in packages]
        run_batch("macports", [_as_root(["port", "-N", "upgrade", *names])],
                  packages, results)  # fmt: skip

    def _apply_mas_updates(self, packages: List[Dict], results: Dict):
        ids = [p.get("bundle_id") or p["package_name"] for p in packages]
        run_batch("mas", [["mas", "upgrade", *ids]], packages, results, timeout=3600)

    def apply_updates(
        self,
        package_names: List[str] = None,  # pylint: disable=unused-argument
        package_managers: List[str] = None,  # pylint: disable=unused-argument
        packages: List[Dict] = None,
    ) -> Dict:
        """Apply the requested updates, grouped by package manager."""
        results: Dict = {"updated_packages": [], "failed_packages": [],
                         "requires_reboot": False, "timestamp": ""}  # fmt: skip
        by_manager: Dict[str, List[Dict]] = {}
        for pkg in packages or []:
            if "package_name" not in pkg and "name" in pkg:
                pkg = {**pkg, "package_name": pkg["name"]}
            by_manager.setdefault(pkg.get("package_manager", "unknown"), []).append(pkg)
        dispatch = {
            "homebrew": self._apply_homebrew_updates,
            "macos-upgrade": self._apply_macos_upgrade_updates,
            "mac_app_store": self._apply_softwareupdate_updates,
            "macports": self._apply_macports_updates,
            "mas": self._apply_mas_updates,
        }
        for manager, pkg_list in by_manager.items():
            handler = dispatch.get(manager)
            if handler is None:
                for pkg in pkg_list:
                    results["failed_packages"].append({
                        "package_name": pkg.get("package_name"),
                        "package_manager": manager,
                        "error": f"Unsupported package manager: {manager}",
                    })  # fmt: skip
                continue
            try:
                handler(pkg_list, results)
            except Exception as error:  # pylint: disable=broad-exception-caught
                logger.exception(
                    _("Failed to apply %s updates: %s"), manager, str(error)
                )
                for pkg in pkg_list:
                    results["failed_packages"].append({
                        "package_name": pkg.get("package_name"),
                        "package_manager": manager, "error": str(error),
                    })  # fmt: skip
        if any(p.get("package_manager") in ("mac_app_store", "macos-upgrade")
               and p.get("requires_restart") for p in packages or []):  # fmt: skip
            results["requires_reboot"] = True
        return results
