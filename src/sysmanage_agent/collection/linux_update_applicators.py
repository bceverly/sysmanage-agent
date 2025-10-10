#!/usr/bin/env python3
"""
Linux Update Application Helper Module

This module contains methods for applying updates on Linux systems
across different package managers.
"""

import logging
import subprocess  # nosec B404
from typing import Dict, List

from src.i18n import _

logger = logging.getLogger(__name__)


class LinuxUpdateApplicator:
    """Helper class for applying Linux updates across different package managers."""

    @staticmethod
    def apply_apt_updates(packages: List[Dict], results: Dict):
        """Apply APT updates."""
        try:
            package_names = [pkg["package_name"] for pkg in packages]

            result = subprocess.run(  # nosec B603, B607
                [
                    "apt-get",
                    "install",
                    "--only-upgrade",
                    "-y",
                    *package_names,
                ],
                capture_output=True,
                text=True,
                timeout=600,
                check=False,
            )

            if result.returncode == 0:
                for package in packages:
                    results.setdefault("updated_packages", []).append(
                        {
                            "package_name": package["package_name"],
                            "old_version": package.get("current_version"),
                            "new_version": package["available_version"],
                            "package_manager": "apt",
                        }
                    )
            else:
                for package in packages:
                    results.setdefault("failed_packages", []).append(
                        {
                            "package_name": package["package_name"],
                            "package_manager": "apt",
                            "error": result.stderr,
                        }
                    )

        except Exception as error:
            logger.error(_("Failed to apply APT updates: %s"), str(error))
            for package in packages:
                results.setdefault("failed_packages", []).append(
                    {
                        "package_name": package["package_name"],
                        "package_manager": "apt",
                        "error": str(error),
                    }
                )

    @staticmethod
    def apply_snap_updates(packages: List[Dict], results: Dict):
        """Apply Snap updates."""
        for package in packages:
            try:
                result = subprocess.run(  # nosec B603, B607
                    ["snap", "refresh", package["package_name"]],
                    capture_output=True,
                    text=True,
                    timeout=300,
                    check=False,
                )

                if result.returncode == 0:
                    results.setdefault("updated_packages", []).append(
                        {
                            "package_name": package["package_name"],
                            "old_version": package.get("current_version"),
                            "new_version": package["available_version"],
                            "package_manager": "snap",
                        }
                    )
                else:
                    results.setdefault("failed_packages", []).append(
                        {
                            "package_name": package["package_name"],
                            "package_manager": "snap",
                            "error": result.stderr,
                        }
                    )

            except Exception as error:
                results.setdefault("failed_packages", []).append(
                    {
                        "package_name": package["package_name"],
                        "package_manager": "snap",
                        "error": str(error),
                    }
                )

    @staticmethod
    def apply_flatpak_updates(packages: List[Dict], results: Dict):
        """Apply Flatpak updates."""
        for package in packages:
            try:
                bundle_id = package.get("bundle_id", package["package_name"])
                result = subprocess.run(  # nosec B603, B607
                    ["flatpak", "update", "-y", bundle_id],
                    capture_output=True,
                    text=True,
                    timeout=300,
                    check=False,
                )

                if result.returncode == 0:
                    results.setdefault("updated_packages", []).append(
                        {
                            "package_name": package["package_name"],
                            "old_version": package.get("current_version"),
                            "new_version": package["available_version"],
                            "package_manager": "flatpak",
                        }
                    )
                else:
                    results.setdefault("failed_packages", []).append(
                        {
                            "package_name": package["package_name"],
                            "package_manager": "flatpak",
                            "error": result.stderr,
                        }
                    )

            except Exception as error:
                results.setdefault("failed_packages", []).append(
                    {
                        "package_name": package["package_name"],
                        "package_manager": "flatpak",
                        "error": str(error),
                    }
                )

    @staticmethod
    def apply_dnf_updates(packages: List[Dict], results: Dict):
        """Apply DNF/YUM updates."""
        try:
            package_names = [pkg["package_name"] for pkg in packages]

            result = subprocess.run(  # nosec B603, B607
                ["dnf", "upgrade", "-y", *package_names],
                capture_output=True,
                text=True,
                timeout=600,
                check=False,
            )

            if result.returncode == 0:
                for package in packages:
                    results.setdefault("updated_packages", []).append(
                        {
                            "package_name": package["package_name"],
                            "old_version": package.get("current_version"),
                            "new_version": package["available_version"],
                            "package_manager": "dnf",
                        }
                    )
            else:
                for package in packages:
                    results.setdefault("failed_packages", []).append(
                        {
                            "package_name": package["package_name"],
                            "package_manager": "dnf",
                            "error": result.stderr,
                        }
                    )

        except Exception as error:
            logger.error(_("Failed to apply DNF updates: %s"), str(error))
            for package in packages:
                results.setdefault("failed_packages", []).append(
                    {
                        "package_name": package["package_name"],
                        "package_manager": "dnf",
                        "error": str(error),
                    }
                )

    @staticmethod
    def apply_fwupd_updates(packages: List[Dict], results: Dict):
        """Apply firmware updates via fwupd."""
        for package in packages:
            device_id = package.get("device_id", "")
            package_name = package["package_name"]

            if not device_id:
                logger.error(
                    _("No device ID found for firmware package: %s"), package_name
                )
                results.setdefault("failed_packages", []).append(
                    {
                        "package_name": package_name,
                        "package_manager": "fwupd",
                        "error": _("No device ID available for firmware update"),
                    }
                )
                continue

            try:
                logger.info(_("Applying firmware update for device: %s"), device_id)

                result = subprocess.run(  # nosec B603, B607
                    ["fwupdmgr", "update", device_id, "--assume-yes"],
                    capture_output=True,
                    text=True,
                    timeout=600,
                    check=False,
                )

                if result.returncode == 0:
                    logger.info(
                        _("Successfully updated firmware for: %s"), package_name
                    )
                    results.setdefault("updated_packages", []).append(
                        {
                            "package_name": package_name,
                            "old_version": package.get("current_version"),
                            "new_version": package["available_version"],
                            "package_manager": "fwupd",
                            "device_id": device_id,
                            "requires_reboot": True,
                        }
                    )
                else:
                    error_msg = (
                        result.stderr.strip()
                        if result.stderr
                        else _("Firmware update failed")
                    )
                    logger.error(
                        _("Failed to update firmware for %s: %s"),
                        package_name,
                        error_msg,
                    )
                    results.setdefault("failed_packages", []).append(
                        {
                            "package_name": package_name,
                            "package_manager": "fwupd",
                            "error": error_msg,
                        }
                    )

            except Exception as error:
                logger.error(
                    _("Exception during firmware update for %s: %s"),
                    package_name,
                    str(error),
                )
                results.setdefault("failed_packages", []).append(
                    {
                        "package_name": package_name,
                        "package_manager": "fwupd",
                        "error": str(error),
                    }
                )

    @staticmethod
    def apply_ubuntu_release_updates(packages: List[Dict], results: Dict):
        """Apply Ubuntu release upgrades."""
        try:
            for package in packages:
                logger.info(
                    _("Applying Ubuntu release upgrade to: %s"),
                    package.get("available_version"),
                )

                result = subprocess.run(  # nosec B603, B607
                    ["do-release-upgrade", "-f", "DistUpgradeViewNonInteractive"],
                    capture_output=True,
                    text=True,
                    timeout=3600,
                    check=False,
                )

                if result.returncode == 0:
                    results.setdefault("successful_updates", []).append(
                        "Ubuntu Release Upgrade"
                    )
                else:
                    results.setdefault("failed_updates", []).append(
                        "Ubuntu Release Upgrade"
                    )
                    results.setdefault("errors", []).append(
                        f"Ubuntu release upgrade failed: {result.stderr}"
                    )

        except Exception as error:
            logger.error(_("Failed to apply Ubuntu release upgrade: %s"), str(error))
            results.setdefault("errors", []).append(
                f"Ubuntu release upgrade error: {str(error)}"
            )

    @staticmethod
    def apply_fedora_release_updates(packages: List[Dict], results: Dict):
        """Apply Fedora release upgrades."""
        try:
            for package in packages:
                target_version = package.get("available_version", "").replace(
                    "Fedora ", ""
                )
                logger.info(_("Applying Fedora release upgrade to: %s"), target_version)

                result = subprocess.run(  # nosec B603, B607
                    [
                        "dnf",
                        "system-upgrade",
                        "download",
                        f"--releasever={target_version}",
                        "-y",
                    ],
                    capture_output=True,
                    text=True,
                    timeout=1800,
                    check=False,
                )

                if result.returncode == 0:
                    # Start the upgrade (requires reboot)
                    subprocess.run(  # nosec B603, B607
                        ["dnf", "system-upgrade", "reboot"],
                        capture_output=True,
                        text=True,
                        timeout=60,
                        check=False,
                    )
                    results.setdefault("successful_updates", []).append(
                        "Fedora Release Upgrade"
                    )
                else:
                    results.setdefault("failed_updates", []).append(
                        "Fedora Release Upgrade"
                    )
                    results.setdefault("errors", []).append(
                        f"Fedora release upgrade failed: {result.stderr}"
                    )

        except Exception as error:
            logger.error(_("Failed to apply Fedora release upgrade: %s"), str(error))
            results.setdefault("errors", []).append(
                f"Fedora release upgrade error: {str(error)}"
            )

    @staticmethod
    def apply_opensuse_release_updates(packages: List[Dict], results: Dict):
        """Apply openSUSE release upgrades."""
        try:
            for package in packages:
                logger.info(
                    _("Applying openSUSE release upgrade to: %s"),
                    package.get("available_version"),
                )

                result = subprocess.run(  # nosec B603, B607
                    ["zypper", "dup", "-y", "--no-recommends"],
                    capture_output=True,
                    text=True,
                    timeout=1800,
                    check=False,
                )

                if result.returncode == 0:
                    results.setdefault("successful_updates", []).append(
                        "openSUSE Release Upgrade"
                    )
                else:
                    results.setdefault("failed_updates", []).append(
                        "openSUSE Release Upgrade"
                    )
                    results.setdefault("errors", []).append(
                        f"openSUSE release upgrade failed: {result.stderr}"
                    )

        except Exception as error:
            logger.error(_("Failed to apply openSUSE release upgrade: %s"), str(error))
            results.setdefault("errors", []).append(
                f"openSUSE release upgrade error: {str(error)}"
            )
