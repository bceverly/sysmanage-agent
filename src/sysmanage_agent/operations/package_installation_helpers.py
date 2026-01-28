"""
Helper functions for package installation operations.

This module contains helper logic extracted from the install_packages()
function to reduce complexity.
"""

import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from src.database.base import get_database_manager
from src.database.models import InstallationRequestTracking
from src.i18n import _
from src.sysmanage_agent.collection.update_detection import UpdateDetector

logger = logging.getLogger(__name__)


def create_installation_tracking_record(  # pylint: disable=invalid-name
    request_id: str, requested_by: str, packages: List[Dict[str, Any]]
) -> Tuple[bool, Optional[str]]:
    """
    Create a tracking record in the database for an installation request.

    Args:
        request_id: The unique ID for this installation request
        requested_by: The user who requested the installation
        packages: List of packages to install

    Returns:
        Tuple of (success: bool, error_message: Optional[str])
    """
    try:
        db_manager = get_database_manager()
        with db_manager.get_session() as session:
            tracking_record = InstallationRequestTracking(
                request_id=request_id,
                requested_by=requested_by,
                status="in_progress",
                packages_json=json.dumps(packages),
                received_at=datetime.now(timezone.utc),
                started_at=datetime.now(timezone.utc),
            )
            session.add(tracking_record)
            session.commit()
        return True, None
    except Exception as error:
        error_msg = _("Failed to store installation request: %s") % str(error)
        logger.error(error_msg)
        return False, error_msg


def update_installation_tracking_record(  # pylint: disable=invalid-name
    request_id: str, overall_success: bool, installation_log_text: str
) -> None:
    """
    Update the tracking record with completion status.

    Args:
        request_id: The unique ID for this installation request
        overall_success: Whether all packages installed successfully
        installation_log_text: The complete installation log
    """
    try:
        db_manager = get_database_manager()
        with db_manager.get_session() as session:
            tracking_record = (
                session.query(InstallationRequestTracking)
                .filter_by(request_id=request_id)
                .first()
            )
            if tracking_record:
                tracking_record.status = "completed" if overall_success else "failed"
                tracking_record.completed_at = datetime.now(timezone.utc)
                tracking_record.result_log = installation_log_text
                tracking_record.success = "true" if overall_success else "false"
                session.commit()
    except Exception as error:
        logger.error(_("Failed to update installation tracking record: %s"), error)


def validate_packages(
    packages: List[Dict[str, Any]], logger_instance: logging.Logger
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """
    Validate package list and extract valid packages.

    Args:
        packages: List of package dictionaries to validate
        logger_instance: Logger instance for logging warnings

    Returns:
        Tuple of (valid_packages: List, failed_packages: List)
    """
    valid_packages = []
    failed_packages = []

    for package in packages:
        package_name = package.get("package_name")
        if not package_name:
            logger_instance.warning(_("Skipping package with no name"))
            failed_packages.append({"package": package, "error": "No package name"})
            continue
        valid_packages.append(package)

    return valid_packages, failed_packages


def group_packages_by_manager(
    valid_packages: List[Dict[str, Any]],
) -> Dict[str, List[Dict[str, Any]]]:
    """
    Group packages by their package manager.

    Args:
        valid_packages: List of valid package dictionaries

    Returns:
        Dictionary mapping package manager name to list of packages
    """
    package_groups = {}
    for package in valid_packages:
        package_manager = package.get("package_manager", "auto")
        if package_manager == "auto":
            # Auto-detect package manager (assume apt for now)
            package_manager = "apt"

        if package_manager not in package_groups:
            package_groups[package_manager] = []
        package_groups[package_manager].append(package)

    return package_groups


async def install_apt_packages(  # pylint: disable=unused-argument
    pkg_list: List[Dict[str, Any]],
    install_method: Any,
    _logger_instance: logging.Logger,
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], List[str]]:
    """
    Install packages using apt package manager.

    Args:
        pkg_list: List of packages to install
        install_method: The _install_packages_with_apt method reference
        logger_instance: Logger instance

    Returns:
        Tuple of (success_packages, failed_packages, installation_log)
    """
    success_packages = []
    failed_packages = []
    installation_log = []

    result = await install_method([pkg["package_name"] for pkg in pkg_list])

    if result.get("success", False):
        # All packages succeeded
        for package in pkg_list:
            package_name = package["package_name"]
            success_packages.append(
                {
                    "package_name": package_name,
                    "installed_version": result.get("versions", {}).get(
                        package_name, "unknown"
                    ),
                    "result": result,
                }
            )
            installation_log.append(f"✓ {package_name} installed successfully")
    else:
        # All packages failed
        error_msg = result.get("error", "Unknown error")
        for package in pkg_list:
            package_name = package["package_name"]
            failed_packages.append(
                {
                    "package_name": package_name,
                    "error": error_msg,
                    "result": result,
                }
            )
            installation_log.append(f"✗ {package_name} failed: {error_msg}")

    return success_packages, failed_packages, installation_log


def install_non_apt_packages(
    pkg_list: List[Dict[str, Any]],
    pkg_manager: str,
    logger_instance: logging.Logger,
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], List[str]]:
    """
    Install packages using non-apt package managers.

    Args:
        pkg_list: List of packages to install
        pkg_manager: Package manager name
        logger_instance: Logger instance

    Returns:
        Tuple of (success_packages, failed_packages, installation_log)
    """
    success_packages = []
    failed_packages = []
    installation_log = []

    for package in pkg_list:
        package_name = package.get("package_name")
        try:
            installation_log.append(f"Installing {package_name}...")
            logger_instance.info(_("Installing package: %s"), package_name)

            update_detector = UpdateDetector()
            result = update_detector.install_package(package_name, pkg_manager)

            if result.get("success", False):
                success_packages.append(
                    {
                        "package_name": package_name,
                        "installed_version": result.get("installed_version"),
                        "result": result,
                    }
                )
                installation_log.append(f"✓ {package_name} installed successfully")
            else:
                error_msg = result.get("error", "Unknown error")
                failed_packages.append(
                    {
                        "package_name": package_name,
                        "error": error_msg,
                        "result": result,
                    }
                )
                installation_log.append(f"✗ {package_name} failed: {error_msg}")

        except Exception as error:
            error_msg = str(error)
            logger_instance.error(
                _("Failed to install package %s: %s"), package_name, error
            )
            failed_packages.append({"package_name": package_name, "error": error_msg})
            installation_log.append(f"✗ {package_name} failed: {error_msg}")

    return success_packages, failed_packages, installation_log
