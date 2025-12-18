#!/usr/bin/env python3
"""
Windows Update Application Module for SysManage Agent

This module handles applying updates on Windows systems:
- winget updates
- Chocolatey updates
- Windows system updates
- Windows version upgrades
"""

import logging
import platform
import subprocess  # nosec B404
import time
from typing import Any, Dict, List

from src.i18n import _

logger = logging.getLogger(__name__)


class WindowsUpdateApplierMixin:
    """Mixin class for applying Windows updates."""

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

                # Use Popen for better timeout control and progress logging
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

                # Monitor progress with longer timeout
                timeout = 1200  # 20 minutes for large packages like PostgreSQL
                start_time = time.time()
                last_log_time = start_time

                # Poll process with periodic progress logging
                while True:
                    # Check if process has finished
                    returncode = process.poll()
                    if returncode is not None:
                        # Process finished, collect output
                        stdout_output, stderr_output = process.communicate()
                        break

                    # Check for timeout
                    elapsed = time.time() - start_time
                    if elapsed > timeout:
                        # Timeout - kill process and get partial output
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
                        break

                    # Log progress every 30 seconds
                    if time.time() - last_log_time > 30:
                        logger.info(
                            _("Update still running for '%s' (%d seconds elapsed)"),
                            package["package_name"],
                            int(elapsed),
                        )
                        last_log_time = time.time()

                    # Sleep briefly before next check
                    time.sleep(0.5)

                # If we didn't timeout, process the result
                if returncode is not None:
                    logger.debug(
                        _(
                            "Winget command result: returncode=%d, stdout='%s', stderr='%s'"
                        ),
                        returncode,
                        (stdout_output or "")[:500],  # Limit log output
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
                            error_msg[:500],  # Limit error message length
                        )
                        results["failed_packages"].append(
                            {
                                "package_name": package["package_name"],
                                "package_manager": "winget",
                                "error": error_msg[:1000],  # Limit stored error
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

    def _apply_windows_system_updates(self, packages: List[Dict], results: Dict):
        """Apply Windows system updates using PowerShell."""
        for package in packages:
            try:
                package_name = package.get("package_name")
                # Try update_id first, then bundle_id as fallback (server sends update_id as bundle_id)
                update_id = package.get("update_id") or package.get("bundle_id")

                logger.info(
                    _("Applying Windows Update: %s (UpdateID: %s)"),
                    package_name,
                    update_id if update_id else "searching by title",
                )

                # PowerShell command to install Windows Update by UpdateID or Title
                if update_id:
                    # Install by UpdateID (more reliable)
                    powershell_cmd = f"""
                    try {{
                        if (Get-Module -ListAvailable -Name PSWindowsUpdate) {{
                            Import-Module PSWindowsUpdate -ErrorAction SilentlyContinue
                            Install-WindowsUpdate -KBArticleID "{update_id}" -AcceptAll -IgnoreReboot
                        }} else {{
                            # Fallback to COM object
                            $session = New-Object -ComObject Microsoft.Update.Session
                            $searcher = $session.CreateUpdateSearcher()
                            # Search for all pending updates, then filter by UpdateID
                            $searchResult = $searcher.Search("IsInstalled=0")
                            $updatesToInstall = New-Object -ComObject Microsoft.Update.UpdateColl
                            $found = $false
                            foreach($update in $searchResult.Updates) {{
                                if($update.Identity.UpdateID -eq "{update_id}") {{
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
                                Write-Output "ERROR: Update not found with UpdateID '{update_id}'"
                            }}
                        }}
                    }} catch {{
                        Write-Output "ERROR: $($_.Exception.Message)"
                    }}
                    """
                else:
                    # Install by Title
                    powershell_cmd = f"""
                    try {{
                        if (Get-Module -ListAvailable -Name PSWindowsUpdate) {{
                            Import-Module PSWindowsUpdate -ErrorAction SilentlyContinue
                            Install-WindowsUpdate -Title "{package_name}" -AcceptAll -IgnoreReboot
                        }} else {{
                            # Fallback to COM object - search by title
                            $session = New-Object -ComObject Microsoft.Update.Session
                            $searcher = $session.CreateUpdateSearcher()
                            $searchResult = $searcher.Search("IsInstalled=0")
                            $updatesToInstall = New-Object -ComObject Microsoft.Update.UpdateColl
                            $found = $false
                            foreach($update in $searchResult.Updates) {{
                                if($update.Title -eq "{package_name}") {{
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
                                Write-Output "ERROR: Update not found with title '{package_name}'"
                            }}
                        }}
                    }} catch {{
                        Write-Output "ERROR: $($_.Exception.Message)"
                    }}
                    """

                update_cmd = ["powershell", "-NoProfile", "-Command", powershell_cmd]
                logger.info(_("Running Windows Update installation command"))

                result = subprocess.run(  # nosec B603, B607
                    update_cmd,
                    capture_output=True,
                    text=True,
                    timeout=1800,  # 30 minutes timeout for Windows Updates
                    check=False,
                    creationflags=(
                        subprocess.CREATE_NO_WINDOW
                        if platform.system() == "Windows"
                        else 0
                    ),
                )

                output = result.stdout.strip()
                logger.debug(
                    _("Windows Update command result: returncode=%d, output='%s'"),
                    result.returncode,
                    output,
                )

                # Check for actual success (SUCCESS output or ResultCode=2)
                # ResultCode=2 means orcSucceeded, ResultCode=4 means orcFailed
                if (
                    result.returncode == 0
                    and ("SUCCESS" in output or "ResultCode=2" in output)
                    and "ERROR:" not in output
                    and "FAILED:" not in output
                ):
                    logger.info(
                        _("Successfully installed Windows Update: %s"), package_name
                    )
                    results["updated_packages"].append(
                        {
                            "package_name": package_name,
                            "old_version": package.get("current_version"),
                            "new_version": package.get("available_version"),
                            "package_manager": "Windows Update",
                        }
                    )
                    results["requires_reboot"] = True
                else:
                    error_msg = (
                        output
                        if ("ERROR:" in output or "FAILED:" in output)
                        else (
                            result.stderr.strip()
                            if result.stderr
                            else _("Windows Update installation failed")
                        )
                    )
                    logger.warning(
                        _("Failed to install Windows Update '%s': %s"),
                        package_name,
                        error_msg,
                    )
                    results["failed_packages"].append(
                        {
                            "package_name": package_name,
                            "package_manager": "Windows Update",
                            "error": error_msg,
                        }
                    )

            except subprocess.TimeoutExpired:
                logger.error(
                    _("Windows Update '%s' timed out after 30 minutes"), package_name
                )
                results["failed_packages"].append(
                    {
                        "package_name": package_name,
                        "package_manager": "Windows Update",
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
                        "package_manager": "Windows Update",
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

    def apply_updates(  # pylint: disable=too-many-nested-blocks
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
        # Initialize results dictionary
        results = {
            "updated_packages": [],
            "failed_packages": [],
            "requires_reboot": False,
            "timestamp": "",
        }

        try:
            # Support both old and new calling conventions
            if packages:
                # New format: direct package objects
                logger.info(
                    _("Applying updates for %d packages: %s"),
                    len(packages),
                    ", ".join([pkg.get("name", "unknown") for pkg in packages]),
                )
                packages_to_update = packages
            elif package_names:
                # Old format: separate lists
                logger.info(
                    _("Applying updates for %d packages: %s"),
                    len(package_names),
                    ", ".join(package_names),
                )
                # Convert to package objects
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
            else:
                return {
                    "updated_packages": [],
                    "failed_packages": [],
                    "requires_reboot": False,
                    "timestamp": "",
                }

            # Group packages by package manager
            packages_by_manager = {}
            for pkg in packages_to_update:
                pkg_manager = pkg.get("package_manager", "unknown")
                if pkg_manager not in packages_by_manager:
                    packages_by_manager[pkg_manager] = []

                # Find package info from available updates and merge with provided info
                package_info = (
                    pkg.copy()
                )  # Start with provided info (includes bundle_id if present)
                package_name = pkg.get("name")

                for update in self.available_updates:
                    if (
                        update.get("package_name") == package_name
                        and update.get("package_manager") == pkg_manager
                    ):
                        # Merge with available update info, but don't overwrite bundle_id if already present
                        for key, value in update.items():
                            if key not in package_info:
                                package_info[key] = value
                        break

                # Ensure package_name field exists for compatibility
                if "package_name" not in package_info and "name" in package_info:
                    package_info["package_name"] = package_info["name"]

                packages_by_manager[pkg_manager].append(package_info)

            # Apply updates for each package manager
            for pkg_manager, pkg_list in packages_by_manager.items():
                logger.info(
                    _("Applying %d updates using %s"), len(pkg_list), pkg_manager
                )

                if pkg_manager == "winget":
                    self._apply_winget_updates(pkg_list, results)
                elif pkg_manager == "chocolatey":
                    self._apply_chocolatey_updates(pkg_list, results)
                elif pkg_manager == "Windows Update":
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

            # Log summary
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
