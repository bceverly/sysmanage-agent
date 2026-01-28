#!/usr/bin/env python3
"""
Update Detection Module for SysManage Agent

This module provides comprehensive update detection across multiple platforms:

OS-Level System Updates:
- Linux: System/kernel updates via distribution-specific mechanisms
- macOS: System updates via Software Update (softwareupdate)
- Windows: Windows Updates via PowerShell/WU API (all updates from Windows Update)
- OpenBSD: System patches via syspatch

Package Manager Updates:
- Linux: apt, snap, flatpak, yum/dnf, pacman, zypper
- macOS: Mac App Store, Homebrew, MacPorts
- Windows: Microsoft Store, winget, Chocolatey
- BSD: pkg, ports

Detects available updates for both system components and installed packages,
providing detailed metadata including current version, available version,
security status, and update size.
"""

import logging
import os
import platform
import re
import subprocess  # nosec B404
import urllib.request
from typing import Any, Dict, List

# Platform-specific imports
try:
    import pwd  # Unix/macOS only  # pylint: disable=unused-import  # pwd used in other platform modules
except ImportError:
    pwd = None  # Windows

from src.i18n import _

logger = logging.getLogger(__name__)

from .update_detection_base import (  # pylint: disable=wrong-import-position
    UpdateDetectorBase,
)

logger = logging.getLogger(__name__)


class BSDUpdateDetector(UpdateDetectorBase):
    """BSD-specific update detection methods."""

    def _detect_pkg_updates(self):
        """Detect updates from FreeBSD/OpenBSD pkg."""
        try:
            logger.debug(_("Detecting pkg updates"))

            # Update the package repository
            subprocess.run(  # nosec B603, B607
                ["pkg", "update", "-q"], capture_output=True, timeout=60, check=False
            )

            result = subprocess.run(  # nosec B603, B607
                ["pkg", "version", "-vl", "<"],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )

            if result.returncode == 0 and result.stdout.strip():
                for line in result.stdout.strip().split("\n"):
                    # Parse format: package-version < needs updating (remote has version)
                    match = re.match(  # NOSONAR - regex operates on trusted internal data
                        r"^([^-]+(?:-\D[^-]*)*)-([^\s]+)\s+<\s+.*remote has ([^\)]+)",
                        line,
                    )
                    if match:
                        update = {
                            "package_name": match.group(1),
                            "current_version": match.group(2),
                            "available_version": match.group(3),
                            "package_manager": "pkg",
                            "is_security_update": False,
                            "is_system_update": False,
                        }
                        self.available_updates.append(update)

        except Exception as error:
            logger.error(_("Failed to detect pkg updates: %s"), str(error))

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
            return ["sudo", "-n", "pkgin", "update"]  # -n = non-interactive
        return ["pkgin", "update"]  # Try anyway

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
            logger.debug(_("pkgin update completed successfully"))

    def _parse_pkgin_update_line(self, line):
        """Parse a single line of pkgin list -u output into an update dict.

        Args:
            line: A single output line from pkgin list -u.

        Returns:
            dict or None: An update dict if the line was parsed, None otherwise.
        """
        if not line.strip() or line.startswith("pkg_summary"):
            return None

        match = re.match(  # NOSONAR - regex operates on trusted internal data
            r"^(\w[\w+.-]*)-(\d[^\s]*)\s+",
            line,
        )
        if match:
            return {
                "package_name": match.group(1),
                "current_version": match.group(2),
                "available_version": "available",  # pkgin list -u doesn't show target version
                "package_manager": "pkgin",
                "is_security_update": False,
                "is_system_update": False,
            }
        return None

    def _detect_pkgin_updates(self):
        """Detect updates from NetBSD pkgin."""
        logger.debug("=== PKGIN DETECTION START ===")
        try:
            logger.debug(_("Detecting pkgin updates"))

            self._process_pkgin_update_repo()

            result = subprocess.run(  # nosec B603, B607
                ["pkgin", "list", "-u"],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )

            if result.returncode != 0:
                logger.warning(
                    _("pkgin list -u failed (code %d): %s"),
                    result.returncode,
                    result.stderr.strip() if result.stderr else "No error message",
                )
                return

            if result.stdout.strip():
                update_count = 0
                for line in result.stdout.strip().split("\n"):
                    update = self._parse_pkgin_update_line(line)
                    if update:
                        self.available_updates.append(update)
                        update_count += 1

                if update_count > 0:
                    logger.info(_("Found %d pkgin updates"), update_count)

            logger.debug("=== PKGIN DETECTION END ===")
        except Exception as error:
            logger.error(_("Failed to detect pkgin updates: %s"), str(error))

    # Helper methods

    def _apply_pkg_updates(self, packages: List[Dict], results: Dict):
        """Apply pkg updates (FreeBSD/OpenBSD)."""
        package_names = [p["package_name"] for p in packages]

        try:
            result = subprocess.run(  # nosec B603, B607
                ["pkg", "upgrade", "-y"] + package_names,
                capture_output=True,
                text=True,
                timeout=300,
                check=False,
            )

            if result.returncode == 0:
                for package in packages:
                    results["updated_packages"].append(
                        {
                            "package_name": package["package_name"],
                            "old_version": package.get("current_version"),
                            "new_version": package["available_version"],
                            "package_manager": "pkg",
                        }
                    )
            else:
                for package in packages:
                    results["failed_packages"].append(
                        {
                            "package_name": package["package_name"],
                            "package_manager": "pkg",
                            "error": result.stderr,
                        }
                    )

        except Exception as error:
            logger.error(_("Failed to apply pkg updates: %s"), str(error))
            for package in packages:
                results["failed_packages"].append(
                    {
                        "package_name": package["package_name"],
                        "package_manager": "pkg",
                        "error": str(error),
                    }
                )

    def _apply_openbsd_upgrade_updates(self, packages: List[Dict], results: Dict):
        """Apply OpenBSD version upgrades using sysupgrade."""
        for package in packages:
            package_name = package.get("package_name")
            logger.info(_("Applying OpenBSD upgrade: %s"), package_name)

            try:
                # Run sysupgrade
                upgrade_cmd = ["sysupgrade"]
                logger.info(
                    _("Running OpenBSD sysupgrade command: %s"), " ".join(upgrade_cmd)
                )

                result = subprocess.run(  # nosec B603, B607
                    upgrade_cmd,
                    capture_output=True,
                    text=True,
                    timeout=1800,  # 30 minutes timeout
                    check=False,
                )

                if result.returncode == 0:
                    logger.info(
                        _("Successfully applied OpenBSD upgrade: %s"), package_name
                    )
                    results["updated_packages"].append(
                        {
                            "package_name": package_name,
                            "old_version": package.get("current_version"),
                            "new_version": package.get("available_version"),
                            "package_manager": "openbsd-upgrade",
                        }
                    )
                    results["requires_reboot"] = True
                else:
                    error_msg = (
                        result.stderr.strip()
                        if result.stderr
                        else _("OpenBSD upgrade failed")
                    )
                    results["failed_packages"].append(
                        {
                            "package_name": package_name,
                            "package_manager": "openbsd-upgrade",
                            "error": error_msg,
                        }
                    )

            except subprocess.TimeoutExpired:
                results["failed_packages"].append(
                    {
                        "package_name": package_name,
                        "package_manager": "openbsd-upgrade",
                        "error": _("OpenBSD upgrade timed out after 30 minutes"),
                    }
                )
            except Exception as error:
                results["failed_packages"].append(
                    {
                        "package_name": package_name,
                        "package_manager": "openbsd-upgrade",
                        "error": str(error),
                    }
                )

    def _apply_freebsd_upgrade_updates(self, packages: List[Dict], results: Dict):
        """Apply FreeBSD version upgrades using freebsd-update."""
        for package in packages:
            package_name = package.get("package_name")
            logger.info(_("Applying FreeBSD upgrade: %s"), package_name)

            try:
                # Run freebsd-update upgrade and install
                upgrade_cmd = ["freebsd-update", "upgrade", "-r", "RELEASE"]
                logger.info(
                    _("Running FreeBSD upgrade command: %s"), " ".join(upgrade_cmd)
                )

                result = subprocess.run(  # nosec B603, B607
                    upgrade_cmd,
                    capture_output=True,
                    text=True,
                    timeout=1800,  # 30 minutes for upgrade
                    check=False,
                )

                if result.returncode == 0:
                    # Install the upgrade
                    install_cmd = ["freebsd-update", "install"]
                    install_result = subprocess.run(  # nosec B603, B607
                        install_cmd,
                        capture_output=True,
                        text=True,
                        timeout=1800,  # 30 minutes for install
                        check=False,
                    )

                    if install_result.returncode == 0:
                        logger.info(
                            _("Successfully applied FreeBSD upgrade: %s"), package_name
                        )
                        results["updated_packages"].append(
                            {
                                "package_name": package_name,
                                "old_version": package.get("current_version"),
                                "new_version": package.get("available_version"),
                                "package_manager": "freebsd-upgrade",
                            }
                        )
                        results["requires_reboot"] = True
                    else:
                        error_msg = (
                            install_result.stderr.strip()
                            if install_result.stderr
                            else _("FreeBSD upgrade install failed")
                        )
                        results["failed_packages"].append(
                            {
                                "package_name": package_name,
                                "package_manager": "freebsd-upgrade",
                                "error": error_msg,
                            }
                        )
                else:
                    error_msg = (
                        result.stderr.strip()
                        if result.stderr
                        else _("FreeBSD upgrade failed")
                    )
                    results["failed_packages"].append(
                        {
                            "package_name": package_name,
                            "package_manager": "freebsd-upgrade",
                            "error": error_msg,
                        }
                    )

            except subprocess.TimeoutExpired:
                results["failed_packages"].append(
                    {
                        "package_name": package_name,
                        "package_manager": "freebsd-upgrade",
                        "error": _("FreeBSD upgrade timed out"),
                    }
                )
            except Exception as error:
                results["failed_packages"].append(
                    {
                        "package_name": package_name,
                        "package_manager": "freebsd-upgrade",
                        "error": str(error),
                    }
                )

    # OS-Level System Update Detection Methods

    def _detect_openbsd_system_updates(self):
        """Detect OpenBSD system updates using syspatch."""
        try:
            logger.debug(_("Detecting OpenBSD system updates"))

            # Check available syspatches
            result = subprocess.run(  # nosec B603, B607
                ["syspatch", "-c"],  # -c for check only
                capture_output=True,
                text=True,
                check=False,
                timeout=60,
            )

            if result.returncode == 0:
                patches = [
                    p.strip() for p in result.stdout.strip().split("\n") if p.strip()
                ]

                if patches:
                    # Combine all patches into a single update since syspatch
                    # applies all patches at once (cumulative, all-or-nothing)
                    patch_count = len(patches)
                    patch_list = ", ".join(patches)

                    self.available_updates.append(
                        {
                            "package_name": f"OpenBSD System Patches ({patch_count} patches)",
                            "current_version": "not installed",
                            "available_version": patch_list,
                            "package_manager": "syspatch",
                            "is_security_update": True,  # All syspatches are security updates
                            "is_system_update": True,  # All syspatches are also system updates
                            "requires_reboot": True,  # Most syspatches require reboot
                            "update_size_bytes": None,  # Size not available from syspatch -c
                            "source": "OpenBSD base system",
                            "repository": "syspatch",
                        }
                    )

                    logger.debug(
                        _(
                            "Found %d OpenBSD system patches (combined into single update)"
                        ),
                        patch_count,
                    )

            elif result.returncode == 1:
                # syspatch returns 1 when no patches are available
                logger.debug(_("No OpenBSD system patches available"))
            else:
                logger.warning(
                    _("syspatch command failed with exit code %d"), result.returncode
                )
                if result.stderr:
                    logger.warning(_("syspatch stderr: %s"), result.stderr)

        except subprocess.TimeoutExpired:
            logger.warning(_("OpenBSD system update detection timed out"))
        except FileNotFoundError:
            logger.debug(_("syspatch not available on this system"))
        except Exception as error:
            logger.error(_("Failed to detect OpenBSD system updates: %s"), str(error))

    def _detect_openbsd_version_upgrades(self):
        """Detect OpenBSD version upgrades by checking openbsd.org."""
        logger.info(_("=== Starting OpenBSD version upgrade detection ==="))
        try:
            # Get current version
            logger.debug(_("Getting current OpenBSD version with uname -r"))
            version_result = subprocess.run(  # nosec B603, B607
                ["uname", "-r"],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            if version_result.returncode != 0:
                logger.warning(_("Failed to get current OpenBSD version"))
                return

            current_version = version_result.stdout.strip()
            logger.info(_("Current OpenBSD version: %s"), current_version)

            # Fetch the OpenBSD homepage to find the current release
            try:
                logger.debug(
                    _("Fetching https://www.openbsd.org/ to check for updates")
                )
                # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected
                with urllib.request.urlopen(
                    "https://www.openbsd.org/", timeout=10
                ) as response:  # nosec B310 - hardcoded HTTPS URL to openbsd.org
                    html_content = response.read().decode("utf-8")

                logger.debug(_("Successfully fetched OpenBSD website, parsing version"))
                # Look for the current release version on the page
                # The page typically contains text like "OpenBSD 7.8" or similar
                match = re.search(r"OpenBSD\s+(\d+\.\d+)", html_content)
                if match:
                    latest_version = match.group(1)
                    logger.info(
                        _("Latest OpenBSD version from website: %s"), latest_version
                    )

                    # Compare versions
                    if latest_version != current_version:
                        logger.info(
                            _("OpenBSD upgrade available: %s -> %s"),
                            current_version,
                            latest_version,
                        )
                        self.available_updates.append(
                            {
                                "package_name": "OpenBSD Release Upgrade",
                                "current_version": current_version,
                                "available_version": latest_version,
                                "package_manager": "openbsd-upgrade",
                                "is_security_update": True,  # Always security for OS upgrades
                                "is_system_update": True,
                                "update_size": 500000000,  # ~500MB estimate
                                "repository": "openbsd-release",
                                "requires_reboot": True,
                            }
                        )
                        logger.info(
                            _("Added OpenBSD upgrade to available_updates list")
                        )
                    else:
                        logger.info(_("OpenBSD is up to date: %s"), current_version)
                else:
                    logger.warning(_("Could not parse OpenBSD version from website"))

            except Exception as fetch_error:
                logger.warning(
                    _("Failed to check OpenBSD website for updates: %s"),
                    str(fetch_error),
                )

        except Exception as error:
            logger.error(_("Failed to detect OpenBSD version upgrades: %s"), str(error))

        logger.info(_("=== Finished OpenBSD version upgrade detection ==="))

    def _detect_freebsd_version_upgrades(self):
        """Detect FreeBSD version upgrades using freebsd-update."""
        try:
            # Check for available upgrades
            result = subprocess.run(  # nosec B603, B607
                ["freebsd-update", "upgrade", "-r", "RELEASE"],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )

            if (
                "upgrade" in result.stdout.lower()
                or "available" in result.stdout.lower()
            ):
                # Get current version
                version_result = subprocess.run(  # nosec B603, B607
                    ["uname", "-r"],
                    capture_output=True,
                    text=True,
                    timeout=10,
                    check=False,
                )
                current_version = (
                    version_result.stdout.strip()
                    if version_result.returncode == 0
                    else "Unknown"
                )

                self.available_updates.append(
                    {
                        "package_name": "freebsd-release",
                        "current_version": current_version,
                        "available_version": "Next Release",
                        "package_manager": "freebsd-upgrade",
                        "is_security_update": True,  # Always security for OS upgrades
                        "is_system_update": True,
                        "update_size": 800000000,  # ~800MB estimate
                        "repository": "freebsd-release",
                        "requires_reboot": True,
                    }
                )

        except Exception as error:
            logger.error(_("Failed to detect FreeBSD version upgrades: %s"), str(error))

    def detect_updates(self):
        """Detect all updates from BSD sources."""
        logger.info(_("=== BSD detect_updates called ==="))

        # BSD system updates
        logger.info(_("Calling _detect_openbsd_system_updates"))
        self._detect_openbsd_system_updates()

        # BSD version upgrades
        logger.info(_("Calling _detect_openbsd_version_upgrades"))
        self._detect_openbsd_version_upgrades()

        # FreeBSD-specific detection
        if platform.system() == "FreeBSD":
            logger.info(_("Calling _detect_freebsd_version_upgrades"))
            self._detect_freebsd_version_upgrades()

        # Package managers
        logger.info(_("Detecting package managers"))
        managers = self._detect_package_managers()
        if "pkg" in managers:
            self._detect_pkg_updates()
        if "pkgin" in managers:
            self._detect_pkgin_updates()

        logger.info(
            _("=== BSD detect_updates finished, total updates: %d ==="),
            len(self.available_updates),
        )

    def _install_with_pkg(self, package_name: str) -> Dict[str, Any]:
        """Install package using pkg package manager (BSD systems)."""
        try:
            # OpenBSD uses pkg_add, FreeBSD uses pkg
            if platform.system() == "OpenBSD":
                # Check if running as root
                if os.geteuid() == 0:
                    cmd = ["pkg_add", package_name]
                else:
                    cmd = ["doas", "pkg_add", package_name]
            else:
                # FreeBSD
                if os.geteuid() == 0:
                    cmd = ["pkg", "install", "-y", package_name]
                else:
                    cmd = ["sudo", "pkg", "install", "-y", package_name]

            result = subprocess.run(  # nosec B603, B607
                cmd,
                capture_output=True,
                text=True,
                timeout=300,
                check=True,
            )

            return {"success": True, "version": "unknown", "output": result.stdout}

        except subprocess.CalledProcessError as error:
            return {
                "success": False,
                "error": f"Failed to install {package_name}: {error.stderr or error.stdout}",
            }

    def _install_with_pkgin(self, package_name: str) -> Dict[str, Any]:
        """Install package using pkgin package manager (NetBSD)."""
        try:
            # Check if running as root
            if os.geteuid() == 0:
                cmd = ["pkgin", "-y", "install", package_name]
            else:
                cmd = ["sudo", "pkgin", "-y", "install", package_name]

            result = subprocess.run(  # nosec B603, B607
                cmd,
                capture_output=True,
                text=True,
                timeout=300,
                check=True,
            )

            return {"success": True, "version": "unknown", "output": result.stdout}

        except subprocess.CalledProcessError as error:
            return {
                "success": False,
                "error": f"Failed to install {package_name}: {error.stderr or error.stdout}",
            }
        except subprocess.TimeoutExpired:
            return {
                "success": False,
                "error": f"Installation of {package_name} timed out after 300 seconds",
            }

    def _apply_syspatch_updates(self, packages: List[Dict], results: Dict):
        """Apply OpenBSD syspatch updates."""
        logger.info(_("Applying OpenBSD syspatch updates"))

        try:
            # syspatch applies all available patches when run without arguments
            # We can't selectively apply individual patches
            result = subprocess.run(  # nosec B603, B607
                ["syspatch"],
                capture_output=True,
                text=True,
                timeout=600,  # 10 minutes timeout
                check=False,
            )

            if result.returncode == 0:
                logger.info(_("Successfully applied syspatch updates"))
                # Mark all requested patches as updated
                for package in packages:
                    results["updated_packages"].append(
                        {
                            "package_name": package["package_name"],
                            "old_version": package.get("current_version"),
                            "new_version": package.get("available_version"),
                            "package_manager": "syspatch",
                        }
                    )
                results["requires_reboot"] = True
            else:
                error_msg = (
                    result.stderr.strip()
                    if result.stderr
                    else _("syspatch command failed")
                )
                logger.error(_("Failed to apply syspatch updates: %s"), error_msg)
                for package in packages:
                    results["failed_packages"].append(
                        {
                            "package_name": package["package_name"],
                            "package_manager": "syspatch",
                            "error": error_msg,
                        }
                    )

        except subprocess.TimeoutExpired:
            logger.error(_("syspatch command timed out"))
            for package in packages:
                results["failed_packages"].append(
                    {
                        "package_name": package["package_name"],
                        "package_manager": "syspatch",
                        "error": _("syspatch timed out after 10 minutes"),
                    }
                )
        except Exception as error:
            logger.error(_("Failed to apply syspatch updates: %s"), str(error))
            for package in packages:
                results["failed_packages"].append(
                    {
                        "package_name": package["package_name"],
                        "package_manager": "syspatch",
                        "error": str(error),
                    }
                )

    def _collect_packages_to_update(
        self,
        package_names: List[str] = None,
        package_managers: List[str] = None,
        packages: List[Dict] = None,
    ) -> List[Dict]:
        """Normalize package input from old or new calling conventions.

        Args:
            package_names: (deprecated) List of package names to update.
            package_managers: (deprecated) List of package managers for each package.
            packages: List of package dicts with 'name' and 'package_manager'.

        Returns:
            List of normalized package dicts, or empty list if no input provided.
        """
        if packages:
            logger.info(
                _("Applying updates for %d packages: %s"),
                len(packages),
                ", ".join([pkg.get("name", "unknown") for pkg in packages]),
            )
            return packages

        if package_names:
            logger.info(
                _("Applying updates for %d packages: %s"),
                len(package_names),
                ", ".join(package_names),
            )
            packages_to_update = []
            for i, package_name in enumerate(package_names):
                pkg_manager = (
                    package_managers[i]
                    if package_managers and i < len(package_managers)
                    else "unknown"
                )
                packages_to_update.append(
                    {
                        "name": package_name,
                        "package_manager": pkg_manager,
                    }
                )
            return packages_to_update

        return []

    def _collect_packages_by_manager(
        self, packages_to_update: List[Dict]
    ) -> Dict[str, List[Dict]]:
        """Group packages by their package manager and merge with available update info.

        Args:
            packages_to_update: List of normalized package dicts.

        Returns:
            Dict mapping package manager names to lists of enriched package dicts.
        """
        packages_by_manager: Dict[str, List[Dict]] = {}
        for pkg in packages_to_update:
            pkg_manager = pkg.get("package_manager", "unknown")
            if pkg_manager not in packages_by_manager:
                packages_by_manager[pkg_manager] = []

            package_info = pkg.copy()
            package_name = pkg.get("name")

            for update in self.available_updates:
                if (
                    update.get("package_name") == package_name
                    and update.get("package_manager") == pkg_manager
                ):
                    for key, value in update.items():
                        if key not in package_info:
                            package_info[key] = value
                    break

            if "package_name" not in package_info and "name" in package_info:
                package_info["package_name"] = package_info["name"]

            packages_by_manager[pkg_manager].append(package_info)

        return packages_by_manager

    def _process_bsd_manager_updates(
        self, pkg_manager: str, pkg_list: List[Dict], results: Dict
    ):
        """Dispatch update application to the correct BSD package manager handler.

        Args:
            pkg_manager: The name of the package manager.
            pkg_list: List of packages to update via this manager.
            results: The results dict to populate with outcomes.
        """
        if pkg_manager == "pkg":
            self._apply_pkg_updates(pkg_list, results)
        elif pkg_manager == "syspatch":
            self._apply_syspatch_updates(pkg_list, results)
        elif pkg_manager == "openbsd-upgrade":
            self._apply_openbsd_upgrade_updates(pkg_list, results)
        elif pkg_manager == "freebsd-upgrade":
            self._apply_freebsd_upgrade_updates(pkg_list, results)
        else:
            logger.warning(_("Unsupported package manager: %s"), pkg_manager)
            for package in pkg_list:
                results["failed_packages"].append(
                    {
                        "package_name": package["package_name"],
                        "package_manager": pkg_manager,
                        "error": f"Unsupported package manager: {pkg_manager}",
                    }
                )

    def apply_updates(
        self,
        package_names: List[str] = None,
        package_managers: List[str] = None,
        packages: List[Dict] = None,
    ) -> Dict[str, Any]:
        """
        Apply updates for specified packages.

        Args:
            package_names: (deprecated) List of package names to update
            package_managers: (deprecated) List of package managers corresponding to each package
            packages: List of package dicts with 'name', 'package_manager', and optional 'bundle_id'

        Returns:
            Dict containing update results with updated and failed packages
        """
        results = {
            "updated_packages": [],
            "failed_packages": [],
            "requires_reboot": False,
            "timestamp": "",
        }

        try:
            packages_to_update = self._collect_packages_to_update(
                package_names, package_managers, packages
            )
            if not packages_to_update:
                return results

            packages_by_manager = self._collect_packages_by_manager(packages_to_update)

            for pkg_manager, pkg_list in packages_by_manager.items():
                logger.info(
                    _("Applying %d updates using %s"), len(pkg_list), pkg_manager
                )
                self._process_bsd_manager_updates(pkg_manager, pkg_list, results)

            logger.info(
                _("Update process completed: %d updated, %d failed"),
                len(results["updated_packages"]),
                len(results["failed_packages"]),
            )

            return results

        except Exception as error:
            logger.error(_("Failed to apply updates: %s"), str(error))
            results["failed_packages"].append(
                {
                    "package_name": "all",
                    "package_manager": "unknown",
                    "error": str(error),
                }
            )
            return results
