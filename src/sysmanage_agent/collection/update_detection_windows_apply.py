#!/usr/bin/env python3
"""
Windows Update Application Module for SysManage Agent

This module handles applying updates on Windows systems:
- winget updates
- Chocolatey updates
- Windows system updates
- Windows version upgrades
"""

from __future__ import annotations

import logging
import platform
import subprocess  # nosec B404
import time
from typing import Any, Dict, List

from src.i18n import _

logger = logging.getLogger(__name__)

WINDOWS_UPDATE_LABEL = "Windows Update"


class WindowsUpdateApplierMixin:
    """Mixin class for applying Windows updates."""

    def _detect_winget_process_timeout(self, process, package, timeout, results):
        """Poll a winget upgrade subprocess, handling timeout and progress logging.

        Args:
            process: The Popen subprocess running winget upgrade.
            package: The package dict being updated.
            timeout: Maximum seconds to wait before killing the process.
            results: The results dict to populate on timeout.

        Returns:
            tuple: (returncode, stdout_output, stderr_output). returncode is None on timeout.
        """
        start_time = time.time()
        last_log_time = start_time

        while True:
            returncode = process.poll()
            if returncode is not None:
                stdout_output, stderr_output = process.communicate()
                return returncode, stdout_output, stderr_output

            elapsed = time.time() - start_time
            if elapsed > timeout:
                process.kill()
                stdout_output, stderr_output = process.communicate()

                error_msg = (
                    f"Update timed out after {timeout} seconds. "
                    f"Partial output: {(stdout_output or stderr_output or 'none')[-500:]}"
                )
                logger.error(
                    _(
                        "Package '%s' update timed out after %d seconds. Partial output: %s"
                    ),
                    package["package_name"],
                    timeout,
                    (stdout_output or stderr_output or "none")[-500:],
                )
                results["failed_packages"].append(
                    {
                        "package_name": package["package_name"],
                        "package_manager": "winget",
                        "error": error_msg,
                    }
                )
                return None, stdout_output, stderr_output

            if time.time() - last_log_time > 30:
                logger.info(
                    _("Update still running for '%s' (%d seconds elapsed)"),
                    package["package_name"],
                    int(elapsed),
                )
                last_log_time = time.time()

            time.sleep(0.5)

    def _process_winget_result(
        self, returncode, stdout_output, stderr_output, package, results
    ):
        """Process the result of a completed winget upgrade command.

        Args:
            returncode: The process return code (non-None).
            stdout_output: Captured stdout from the process.
            stderr_output: Captured stderr from the process.
            package: The package dict being updated.
            results: The results dict to populate with outcomes.
        """
        logger.debug(
            _("Winget command result: returncode=%d, stdout='%s', stderr='%s'"),
            returncode,
            (stdout_output or "")[:500],
            (stderr_output or "")[:500],
        )

        if returncode == 0:
            logger.info(
                _("Successfully updated package '%s'"),
                package["package_name"],
            )
            results["updated_packages"].append(
                {
                    "package_name": package["package_name"],
                    "old_version": package.get("current_version"),
                    "new_version": package.get("available_version"),
                    "package_manager": "winget",
                }
            )
        else:
            error_msg = (
                (stderr_output or "").strip()
                or (stdout_output or "").strip()
                or f"Command failed with exit code {returncode}"
            )
            logger.warning(
                _("Failed to update package '%s': %s"),
                package["package_name"],
                error_msg[:500],
            )
            results["failed_packages"].append(
                {
                    "package_name": package["package_name"],
                    "package_manager": "winget",
                    "error": error_msg[:1000],
                }
            )

    def _apply_winget_updates(self, packages: List[Dict], results: Dict):
        """Apply winget updates."""
        for package in packages:
            try:
                package_id = package.get("bundle_id", package["package_name"])
                logger.info(
                    _("Applying winget update for package '%s' (ID: %s)"),
                    package["package_name"],
                    package_id,
                )

                # pylint: disable=consider-using-with
                process = subprocess.Popen(  # nosec B603, B607
                    [
                        "winget",
                        "upgrade",
                        "--id",
                        package_id,
                        "--silent",
                        "--accept-package-agreements",
                        "--accept-source-agreements",
                    ],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )

                timeout = 1200  # 20 minutes for large packages
                returncode, stdout_output, stderr_output = (
                    self._detect_winget_process_timeout(
                        process, package, timeout, results
                    )
                )

                if returncode is not None:
                    self._process_winget_result(
                        returncode, stdout_output, stderr_output, package, results
                    )

            except Exception as error:
                logger.error(
                    _("Exception updating package '%s': %s"),
                    package["package_name"],
                    str(error),
                )
                results["failed_packages"].append(
                    {
                        "package_name": package["package_name"],
                        "package_manager": "winget",
                        "error": str(error),
                    }
                )

    def _apply_chocolatey_updates(self, packages: List[Dict], results: Dict):
        """Apply Chocolatey updates."""
        for package in packages:
            try:
                package_name = package["package_name"]
                logger.info(
                    _("Applying Chocolatey update for package '%s'"), package_name
                )

                result = subprocess.run(  # nosec B603, B607
                    ["choco", "upgrade", package_name, "-y"],
                    capture_output=True,
                    text=True,
                    timeout=300,
                    check=False,
                )

                logger.debug(
                    _(
                        "Chocolatey command result: returncode=%d, stdout='%s', stderr='%s'"
                    ),
                    result.returncode,
                    result.stdout.strip(),
                    result.stderr.strip(),
                )

                if result.returncode == 0:
                    logger.info(_("Successfully updated package '%s'"), package_name)
                    results["updated_packages"].append(
                        {
                            "package_name": package_name,
                            "old_version": package.get("current_version"),
                            "new_version": package.get("available_version"),
                            "package_manager": "chocolatey",
                        }
                    )
                else:
                    error_msg = (
                        result.stderr.strip()
                        or result.stdout.strip()
                        or f"Command failed with exit code {result.returncode}"
                    )
                    logger.warning(
                        _("Failed to update package '%s': %s"),
                        package_name,
                        error_msg,
                    )
                    results["failed_packages"].append(
                        {
                            "package_name": package_name,
                            "package_manager": "chocolatey",
                            "error": error_msg,
                        }
                    )

            except Exception as error:
                logger.error(
                    _("Exception updating package '%s': %s"),
                    package["package_name"],
                    str(error),
                )
                results["failed_packages"].append(
                    {
                        "package_name": package["package_name"],
                        "package_manager": "chocolatey",
                        "error": str(error),
                    }
                )

    def _collect_windows_update_powershell_cmd(self, update_id, package_name):
        """Build the PowerShell command string for installing a Windows Update.

        Uses PSWindowsUpdate module if available, otherwise falls back to COM objects.

        Args:
            update_id: The UpdateID to install by, or None to search by title.
            package_name: The title of the update (used when update_id is None).

        Returns:
            str: The PowerShell script string.
        """
        if update_id:
            search_field = "Identity.UpdateID"
            search_value = update_id
            ps_module_flag = f'-KBArticleID "{update_id}"'
            not_found_msg = f"Update not found with UpdateID '{update_id}'"
        else:
            search_field = "Title"
            search_value = package_name
            ps_module_flag = f'-Title "{package_name}"'
            not_found_msg = f"Update not found with title '{package_name}'"

        return f"""
                    try {{
                        if (Get-Module -ListAvailable -Name PSWindowsUpdate) {{
                            Import-Module PSWindowsUpdate -ErrorAction SilentlyContinue
                            Install-WindowsUpdate {ps_module_flag} -AcceptAll -IgnoreReboot
                        }} else {{
                            # Fallback to COM object
                            $session = New-Object -ComObject Microsoft.Update.Session
                            $searcher = $session.CreateUpdateSearcher()
                            $searchResult = $searcher.Search("IsInstalled=0")
                            $updatesToInstall = New-Object -ComObject Microsoft.Update.UpdateColl
                            $found = $false
                            foreach($update in $searchResult.Updates) {{
                                if($update.{search_field} -eq "{search_value}") {{
                                    $updatesToInstall.Add($update) | Out-Null
                                    $found = $true
                                    break
                                }}
                            }}
                            if($found) {{
                                # Download the update first
                                $downloader = $session.CreateUpdateDownloader()
                                $downloader.Updates = $updatesToInstall
                                $downloadResult = $downloader.Download()

                                if($downloadResult.ResultCode -ne 2) {{
                                    $dlUpdateResult = $downloadResult.GetUpdateResult(0)
                                    $dlHresult = $dlUpdateResult.HResult
                                    Write-Output "FAILED: Download failed - ResultCode=$($downloadResult.ResultCode), HResult=0x$($dlHresult.ToString('X8'))"
                                }} else {{
                                    # Now install the downloaded update
                                    $installer = $session.CreateUpdateInstaller()
                                    $installer.Updates = $updatesToInstall
                                    $installationResult = $installer.Install()
                                    if($installationResult.ResultCode -eq 2) {{
                                        Write-Output "SUCCESS"
                                    }} else {{
                                        # Get detailed error information
                                        $updateResult = $installationResult.GetUpdateResult(0)
                                        $hresult = $updateResult.HResult
                                        $resultCode = $installationResult.ResultCode
                                        Write-Output "FAILED: ResultCode=$resultCode, HResult=0x$($hresult.ToString('X8'))"
                                    }}
                                }}
                            }} else {{
                                Write-Output "ERROR: {not_found_msg}"
                            }}
                        }}
                    }} catch {{
                        Write-Output "ERROR: $($_.Exception.Message)"
                    }}
                    """

    def _process_windows_update_result(self, result, package_name, package, results):
        """Evaluate the result of a Windows Update PowerShell command.

        Args:
            result: The subprocess.CompletedProcess from the PowerShell command.
            package_name: The display name of the update.
            package: The full package dict.
            results: The results dict to populate with outcomes.
        """
        output = result.stdout.strip()
        logger.debug(
            _("Windows Update command result: returncode=%d, output='%s'"),
            result.returncode,
            output,
        )

        is_success = (
            result.returncode == 0
            and ("SUCCESS" in output or "ResultCode=2" in output)
            and "ERROR:" not in output
            and "FAILED:" not in output
        )

        if is_success:
            logger.info(_("Successfully installed Windows Update: %s"), package_name)
            results["updated_packages"].append(
                {
                    "package_name": package_name,
                    "old_version": package.get("current_version"),
                    "new_version": package.get("available_version"),
                    "package_manager": WINDOWS_UPDATE_LABEL,
                }
            )
            results["requires_reboot"] = True
        else:
            if "ERROR:" in output or "FAILED:" in output:
                error_msg = output
            elif result.stderr:
                error_msg = result.stderr.strip()
            else:
                error_msg = _("Windows Update installation failed")
            logger.warning(
                _("Failed to install Windows Update '%s': %s"),
                package_name,
                error_msg,
            )
            results["failed_packages"].append(
                {
                    "package_name": package_name,
                    "package_manager": WINDOWS_UPDATE_LABEL,
                    "error": error_msg,
                }
            )

    def _apply_windows_system_updates(self, packages: List[Dict], results: Dict):
        """Apply Windows system updates using PowerShell."""
        for package in packages:
            try:
                package_name = package.get("package_name")
                update_id = package.get("update_id") or package.get("bundle_id")

                logger.info(
                    _("Applying Windows Update: %s (UpdateID: %s)"),
                    package_name,
                    update_id if update_id else "searching by title",
                )

                powershell_cmd = self._collect_windows_update_powershell_cmd(
                    update_id, package_name
                )

                update_cmd = ["powershell", "-NoProfile", "-Command", powershell_cmd]
                logger.info(_("Running Windows Update installation command"))

                result = subprocess.run(  # nosec B603, B607
                    update_cmd,
                    capture_output=True,
                    text=True,
                    timeout=1800,
                    check=False,
                    creationflags=(
                        subprocess.CREATE_NO_WINDOW
                        if platform.system() == "Windows"
                        else 0
                    ),
                )

                self._process_windows_update_result(
                    result, package_name, package, results
                )

            except subprocess.TimeoutExpired:
                logger.error(
                    _("Windows Update '%s' timed out after 30 minutes"), package_name
                )
                results["failed_packages"].append(
                    {
                        "package_name": package_name,
                        "package_manager": WINDOWS_UPDATE_LABEL,
                        "error": _("Installation timed out after 30 minutes"),
                    }
                )
            except Exception as error:
                logger.error(
                    _("Exception installing Windows Update '%s': %s"),
                    package_name,
                    str(error),
                )
                results["failed_packages"].append(
                    {
                        "package_name": package_name,
                        "package_manager": WINDOWS_UPDATE_LABEL,
                        "error": str(error),
                    }
                )

    def _apply_windows_upgrade_updates(self, packages: List[Dict], results: Dict):
        """Apply Windows version upgrades using PowerShell."""
        for package in packages:
            package_name = package.get("package_name")
            available_version = package.get("available_version")
            logger.info(_("Applying Windows upgrade: %s"), available_version)

            try:
                # PowerShell command to install Windows feature updates
                powershell_cmd = f"""
                Install-WindowsUpdate -Title "{available_version}" -AcceptAll -AutoReboot
                """

                upgrade_cmd = ["powershell", "-Command", powershell_cmd]
                logger.info(_("Running Windows upgrade command"))

                result = subprocess.run(  # nosec B603, B607
                    upgrade_cmd,
                    capture_output=True,
                    text=True,
                    timeout=7200,  # 2 hours timeout for Windows upgrades
                    check=False,
                )

                if result.returncode == 0:
                    logger.info(
                        _("Successfully applied Windows upgrade: %s"), available_version
                    )
                    results["updated_packages"].append(
                        {
                            "package_name": package_name,
                            "old_version": package.get("current_version"),
                            "new_version": available_version,
                            "package_manager": "windows-upgrade",
                        }
                    )
                    results["requires_reboot"] = True
                else:
                    error_msg = (
                        result.stderr.strip()
                        if result.stderr
                        else _("Windows upgrade failed")
                    )
                    results["failed_packages"].append(
                        {
                            "package_name": package_name,
                            "package_manager": "windows-upgrade",
                            "error": error_msg,
                        }
                    )

            except subprocess.TimeoutExpired:
                results["failed_packages"].append(
                    {
                        "package_name": package_name,
                        "package_manager": "windows-upgrade",
                        "error": _("Windows upgrade timed out after 2 hours"),
                    }
                )
            except Exception as error:
                results["failed_packages"].append(
                    {
                        "package_name": package_name,
                        "package_manager": "windows-upgrade",
                        "error": str(error),
                    }
                )

    def _collect_windows_packages_to_update(
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

    def _find_windows_matching_update(
        self, package_name: str, pkg_manager: str
    ) -> Dict | None:
        """Find a matching update from available_updates.

        Args:
            package_name: Name of the package to find.
            pkg_manager: Package manager to match.

        Returns:
            The matching update dict, or None if not found.
        """
        for update in self.available_updates:
            if (
                update.get("package_name") == package_name
                and update.get("package_manager") == pkg_manager
            ):
                return update
        return None

    def _enrich_windows_package_info(self, pkg: Dict) -> Dict:
        """Enrich a package dict with available update info.

        Args:
            pkg: Package dict with name and package_manager.

        Returns:
            Enriched package dict with merged update info.
        """
        package_info = pkg.copy()
        package_name = pkg.get("name")
        pkg_manager = pkg.get("package_manager", "unknown")

        matching_update = self._find_windows_matching_update(package_name, pkg_manager)
        if matching_update:
            for key, value in matching_update.items():
                if key not in package_info:
                    package_info[key] = value

        if "package_name" not in package_info and "name" in package_info:
            package_info["package_name"] = package_info["name"]

        return package_info

    def _collect_windows_packages_by_manager(
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

            package_info = self._enrich_windows_package_info(pkg)
            packages_by_manager[pkg_manager].append(package_info)

        return packages_by_manager

    def _process_windows_manager_updates(
        self, pkg_manager: str, pkg_list: List[Dict], results: Dict
    ):
        """Dispatch update application to the correct Windows package manager handler.

        Args:
            pkg_manager: The name of the package manager.
            pkg_list: List of packages to update via this manager.
            results: The results dict to populate with outcomes.
        """
        if pkg_manager == "winget":
            self._apply_winget_updates(pkg_list, results)
        elif pkg_manager == "chocolatey":
            self._apply_chocolatey_updates(pkg_list, results)
        elif pkg_manager == WINDOWS_UPDATE_LABEL:
            self._apply_windows_system_updates(pkg_list, results)
        elif pkg_manager == "windows-upgrade":
            self._apply_windows_upgrade_updates(pkg_list, results)
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
            packages_to_update = self._collect_windows_packages_to_update(
                package_names, package_managers, packages
            )
            if not packages_to_update:
                return results

            packages_by_manager = self._collect_windows_packages_by_manager(
                packages_to_update
            )

            for pkg_manager, pkg_list in packages_by_manager.items():
                logger.info(
                    _("Applying %d updates using %s"), len(pkg_list), pkg_manager
                )
                self._process_windows_manager_updates(pkg_manager, pkg_list, results)

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
