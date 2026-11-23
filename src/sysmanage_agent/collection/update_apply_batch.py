# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""Apply one batch of updates with a package manager's own commands, shared
by the Linux and BSD detectors (zypper, pacman, apk, pkgin, pkg_add)."""

import logging
import subprocess  # nosec B404
from typing import Dict, List, Optional

from src.i18n import _

logger = logging.getLogger(__name__)


def run_batch(manager: str, steps: List[List[str]], packages: List[Dict],
              results: Dict, timeout: int = 1800, note: Optional[str] = None) -> None:  # fmt: skip
    """Run ``steps`` in order, stopping at the first that fails, and record
    every package of the batch as updated or failed by that."""
    ok, error = True, ""
    try:
        for argv in steps:
            result = subprocess.run(  # nosec B603
                argv, capture_output=True, text=True, timeout=timeout, check=False
            )
            if result.returncode != 0:
                ok, error = False, (result.stderr or result.stdout)[-2000:]
                break
    except subprocess.TimeoutExpired:
        ok, error = False, f"{manager} did not finish in {timeout} seconds"
    except Exception as exc:  # pylint: disable=broad-exception-caught
        logger.exception(_("Failed to apply %s updates: %s"), manager, str(exc))
        ok, error = False, str(exc)
    for package in packages:
        if ok:
            entry = {
                "package_name": package["package_name"],
                "old_version": package.get("current_version"),
                "new_version": package.get("available_version"),
                "package_manager": manager,
            }
            if note:
                entry["note"] = note
            results.setdefault("updated_packages", []).append(entry)
        else:
            results.setdefault("failed_packages", []).append(
                {"package_name": package["package_name"],
                 "package_manager": manager, "error": error}
            )  # fmt: skip
