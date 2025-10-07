"""
Package collection module for SysManage Agent.

This module handles the collection of available packages from various package managers
and stores them in the local SQLite database for later transmission to the server.
"""

import glob
import json
import logging
import os
import platform
import subprocess  # nosec B404
import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from typing import Dict, List

# Platform-specific imports
try:
    import pwd  # Unix/macOS only
except ImportError:
    pwd = None  # Windows

from src.database.base import get_database_manager
from src.database.models import AvailablePackage
from src.i18n import _

logger = logging.getLogger(__name__)


class PackageCollector:
    """Collects available packages from various package managers."""

    def __init__(self):
        """Initialize the package collector."""
        self.db_manager = get_database_manager()

    def collect_all_available_packages(self) -> bool:
        """
        Collect available packages from all supported package managers.

        Returns:
            bool: True if collection was successful, False otherwise
        """
        logger.info(_("Starting collection of available packages"))

        collected_count = 0

        # Detect platform and collect from appropriate package managers
        system = platform.system().lower()

        try:
            if system == "linux":
                collected_count += self._collect_linux_packages()
            elif system == "darwin":
                collected_count += self._collect_macos_packages()
            elif system == "windows":
                collected_count += self._collect_windows_packages()
            elif system in ["freebsd", "openbsd", "netbsd"]:
                collected_count += self._collect_bsd_packages()
            else:
                logger.warning(_("Unsupported operating system: %s"), system)
                return False

            logger.info(
                _("Package collection completed. Collected %d packages"),
                collected_count,
            )
            return True

        except Exception as e:
            logger.error(_("Failed to collect available packages: %s"), e)
            return False

    def _collect_linux_packages(self) -> int:
        """Collect packages from Linux package managers."""
        total_collected = 0

        # Try different package managers
        managers = [
            ("apt", self._collect_apt_packages),
            ("yum", self._collect_yum_packages),
            ("dnf", self._collect_dnf_packages),
            ("zypper", self._collect_zypper_packages),
            ("pacman", self._collect_pacman_packages),
            ("snap", self._collect_snap_packages),
            ("flatpak", self._collect_flatpak_packages),
        ]

        for manager_name, collector_func in managers:
            if self._is_package_manager_available(manager_name):
                try:
                    count = collector_func()
                    total_collected += count
                    logger.info(_("Collected %d packages from %s"), count, manager_name)
                except Exception as e:
                    logger.error(
                        _("Failed to collect packages from %s: %s"), manager_name, e
                    )

        return total_collected

    def _collect_macos_packages(self) -> int:
        """Collect packages from macOS package managers."""
        total_collected = 0

        # Try Homebrew
        if self._is_package_manager_available("brew"):
            try:
                count = self._collect_homebrew_packages()
                total_collected += count
                logger.info(_("Collected %d packages from Homebrew"), count)
            except Exception as e:
                logger.error(_("Failed to collect Homebrew packages: %s"), e)

        return total_collected

    def _collect_windows_packages(self) -> int:
        """Collect packages from Windows package managers."""
        total_collected = 0

        # Try different Windows package managers
        managers = [
            ("winget", self._collect_winget_packages),
            ("choco", self._collect_chocolatey_packages),
        ]

        for manager_name, collector_func in managers:
            if self._is_package_manager_available(manager_name):
                try:
                    count = collector_func()
                    total_collected += count
                    logger.info(_("Collected %d packages from %s"), count, manager_name)
                except Exception as e:
                    logger.error(
                        _("Failed to collect packages from %s: %s"), manager_name, e
                    )

        return total_collected

    def _collect_bsd_packages(self) -> int:
        """Collect packages from BSD package managers."""
        total_collected = 0
        system = platform.system().lower()

        # Try pkg (FreeBSD) or pkg_info (OpenBSD)
        if system == "openbsd":
            # OpenBSD uses pkg_info command
            if self._is_package_manager_available("pkg_info"):
                try:
                    count = self._collect_pkg_packages()
                    total_collected += count
                    logger.info(_("Collected %d packages from pkg_info"), count)
                except Exception as e:
                    logger.error(_("Failed to collect pkg_info packages: %s"), e)
        elif system == "freebsd":
            # FreeBSD uses pkg command
            if self._is_package_manager_available("pkg"):
                try:
                    count = self._collect_pkg_packages()
                    total_collected += count
                    logger.info(_("Collected %d packages from pkg"), count)
                except Exception as e:
                    logger.error(_("Failed to collect pkg packages: %s"), e)

        # Try pkgin (NetBSD)
        if self._is_package_manager_available("pkgin"):
            try:
                count = self._collect_pkgin_packages()
                total_collected += count
                logger.info(_("Collected %d packages from pkgin"), count)
            except Exception as e:
                logger.error(_("Failed to collect pkgin packages: %s"), e)

        return total_collected

    def _check_homebrew_available(self) -> bool:
        """Check if Homebrew is available."""
        homebrew_paths = [
            "/opt/homebrew/bin/brew",  # Apple Silicon (M1/M2)
            "/usr/local/bin/brew",  # Intel Macs
        ]
        for path in homebrew_paths:
            try:
                result = subprocess.run(  # nosec B603, B607
                    [path, "--version"],
                    capture_output=True,
                    timeout=10,
                    check=False,
                )
                if result.returncode == 0:
                    return True
            except Exception:  # nosec B112
                continue
        return False

    def _check_winget_available(self) -> bool:
        """Check if winget is available on Windows."""
        winget_paths = [
            os.path.expandvars(r"%LOCALAPPDATA%\Microsoft\WindowsApps\winget.exe"),
            r"C:\Program Files\WindowsApps\Microsoft.DesktopAppInstaller_*\winget.exe",
        ]
        for path in winget_paths:
            # Handle wildcards in path
            if "*" in path:
                matching_paths = glob.glob(path)
                if matching_paths:
                    path = matching_paths[0]
                else:
                    continue

            if os.path.exists(path):
                try:
                    result = subprocess.run(  # nosec B603, B607
                        [path, "--version"],
                        capture_output=True,
                        timeout=10,
                        check=False,
                    )
                    if result.returncode == 0:
                        return True
                except Exception:  # nosec B112
                    continue
        return False

    def _is_package_manager_available(self, manager: str) -> bool:
        """Check if a package manager is available on the system."""
        try:
            # For Homebrew on macOS, use dedicated checker
            if manager == "brew":
                return self._check_homebrew_available()

            # For winget on Windows, use dedicated checker
            if manager == "winget" and platform.system().lower() == "windows":
                return self._check_winget_available()

            # For other package managers, use which (Unix) or where (Windows)
            system = platform.system().lower()
            if system == "windows":
                # Windows uses 'where' command
                result = subprocess.run(  # nosec B603, B607
                    ["where", manager], capture_output=True, timeout=10, check=False
                )
            else:
                # Unix/Linux/BSD/macOS use 'which' command
                result = subprocess.run(  # nosec B603, B607
                    ["which", manager], capture_output=True, timeout=10, check=False
                )
            return result.returncode == 0
        except Exception:
            return False

    def _collect_apt_packages(self) -> int:
        """Collect packages from APT (Ubuntu/Debian)."""
        try:
            # Update package lists first
            subprocess.run(  # nosec B603, B607
                ["apt", "update"], capture_output=True, timeout=300, check=False
            )

            # Get all available packages with descriptions using apt-cache dumpavail
            result = subprocess.run(  # nosec B603, B607
                ["apt-cache", "dumpavail"],
                capture_output=True,
                text=True,
                timeout=600,  # Increased timeout for larger output
                check=False,
            )

            if result.returncode != 0:
                logger.error(_("Failed to get APT package information"))
                return 0

            packages = self._parse_apt_dumpavail_output(result.stdout)
            return self._store_packages("apt", packages)

        except Exception as e:
            logger.error(_("Error collecting APT packages: %s"), e)
            return 0

    def _collect_yum_packages(self) -> int:
        """Collect packages from YUM (CentOS/RHEL 7)."""
        try:
            result = subprocess.run(  # nosec B603, B607
                ["yum", "list", "available"],
                capture_output=True,
                text=True,
                timeout=300,
                check=False,
            )

            if result.returncode != 0:
                logger.error(_("Failed to get YUM package list"))
                return 0

            packages = self._parse_yum_output(result.stdout)
            return self._store_packages("yum", packages)

        except Exception as e:
            logger.error(_("Error collecting YUM packages: %s"), e)
            return 0

    def _collect_dnf_packages(self) -> int:
        """Collect packages from DNF (Fedora/RHEL 8+)."""
        try:
            result = subprocess.run(  # nosec B603, B607
                ["dnf", "list", "available"],
                capture_output=True,
                text=True,
                timeout=300,
                check=False,
            )

            if result.returncode != 0:
                logger.error(_("Failed to get DNF package list"))
                return 0

            packages = self._parse_yum_output(
                result.stdout
            )  # DNF uses similar format to YUM
            return self._store_packages("dnf", packages)

        except Exception as e:
            logger.error(_("Error collecting DNF packages: %s"), e)
            return 0

    def _collect_zypper_packages(self) -> int:
        """Collect packages from Zypper (openSUSE/SLES)."""
        try:
            result = subprocess.run(  # nosec B603, B607
                ["zypper", "search", "-t", "package", "-s"],
                capture_output=True,
                text=True,
                timeout=300,
                check=False,
            )

            if result.returncode != 0:
                logger.error(_("Failed to get Zypper package list"))
                return 0

            packages = self._parse_zypper_output(result.stdout)
            return self._store_packages("zypper", packages)

        except Exception as e:
            logger.error(_("Error collecting Zypper packages: %s"), e)
            return 0

    def _collect_pacman_packages(self) -> int:
        """Collect packages from Pacman (Arch Linux)."""
        try:
            result = subprocess.run(  # nosec B603, B607
                ["pacman", "-Ss"],
                capture_output=True,
                text=True,
                timeout=300,
                check=False,
            )

            if result.returncode != 0:
                logger.error(_("Failed to get Pacman package list"))
                return 0

            packages = self._parse_pacman_output(result.stdout)
            return self._store_packages("pacman", packages)

        except Exception as e:
            logger.error(_("Error collecting Pacman packages: %s"), e)
            return 0

    def _collect_snap_packages(self) -> int:
        """Collect packages from Snap."""
        try:
            # Use % to get all available snaps with descriptions
            result = subprocess.run(  # nosec B603, B607
                ["snap", "find", "%"],
                capture_output=True,
                text=True,
                timeout=300,
                check=False,
            )

            if result.returncode != 0:
                logger.error(_("Failed to get Snap package list"))
                return 0

            packages = self._parse_snap_output(result.stdout)
            return self._store_packages("snap", packages)

        except Exception as e:
            logger.error(_("Error collecting Snap packages: %s"), e)
            return 0

    def _collect_flatpak_packages(self) -> int:
        """Collect packages from Flatpak."""
        try:
            result = subprocess.run(  # nosec B603, B607
                ["flatpak", "remote-ls"],
                capture_output=True,
                text=True,
                timeout=300,
                check=False,
            )

            if result.returncode != 0:
                logger.error(_("Failed to get Flatpak package list"))
                return 0

            packages = self._parse_flatpak_output(result.stdout)
            return self._store_packages("flatpak", packages)

        except Exception as e:
            logger.error(_("Error collecting Flatpak packages: %s"), e)
            return 0

    def _collect_homebrew_packages(self) -> int:
        """Collect packages from Homebrew (macOS)."""
        try:
            # Find the correct brew path
            brew_cmd = self._get_brew_command()
            if not brew_cmd:
                logger.error(_("Homebrew command not found"))
                return 0

            total_packages = 0

            # Collect formulae (packages)
            # Split brew_cmd in case it contains sudo -u
            brew_args = brew_cmd.split() + ["list", "--formulae", "--versions"]
            formulae_result = subprocess.run(  # nosec B603, B607
                brew_args,
                capture_output=True,
                text=True,
                timeout=300,
                check=False,
            )

            if formulae_result.returncode == 0:
                formulae_packages = self._parse_homebrew_list_output(
                    formulae_result.stdout, "formula"
                )
                formulae_count = self._store_packages("homebrew", formulae_packages)
                total_packages += formulae_count
                logger.info(_("Collected %d Homebrew formulae"), formulae_count)

            # Collect casks (applications)
            # Split brew_cmd in case it contains sudo -u
            brew_args = brew_cmd.split() + ["list", "--casks", "--versions"]
            casks_result = subprocess.run(  # nosec B603, B607
                brew_args,
                capture_output=True,
                text=True,
                timeout=300,
                check=False,
            )

            if casks_result.returncode == 0:
                casks_packages = self._parse_homebrew_list_output(
                    casks_result.stdout, "cask"
                )
                casks_count = self._store_packages("homebrew-cask", casks_packages)
                total_packages += casks_count
                logger.info(_("Collected %d Homebrew casks"), casks_count)

            return total_packages

        except Exception as e:
            logger.error(_("Error collecting Homebrew packages: %s"), e)
            return 0

    def _get_homebrew_owner(self) -> str:
        """Get the owner of the Homebrew installation."""

        homebrew_paths = [
            "/opt/homebrew/bin/brew",  # Apple Silicon (M1/M2)
            "/usr/local/bin/brew",  # Intel Macs
        ]

        for path in homebrew_paths:
            try:
                if os.path.exists(path):
                    file_stat = os.stat(path)
                    owner_uid = file_stat.st_uid
                    if pwd is not None:
                        owner_info = pwd.getpwuid(owner_uid)
                        return owner_info.pw_name
                    # On Windows, return empty string since Homebrew doesn't exist
                    return ""
            except Exception:  # nosec B112 - Continue trying other homebrew paths
                continue
        return ""

    def _get_brew_command(self) -> str:
        """Get the correct brew command path, with sudo -u support when running privileged."""
        homebrew_paths = [
            "/opt/homebrew/bin/brew",  # Apple Silicon (M1/M2)
            "/usr/local/bin/brew",  # Intel Macs
            "brew",  # If in PATH
        ]

        for path in homebrew_paths:
            try:
                # Test if brew works directly first
                result = subprocess.run(  # nosec B603, B607
                    [path, "--version"], capture_output=True, timeout=10, check=False
                )
                if result.returncode == 0:
                    # Check if running as root and Homebrew owner is different
                    if os.geteuid() == 0:  # Running as root
                        homebrew_owner = self._get_homebrew_owner()
                        if homebrew_owner and homebrew_owner != "root":
                            # Return sudo command to run as homebrew owner
                            return f"sudo -u {homebrew_owner} {path}"

                    # Normal case
                    return path
            except Exception:  # nosec B112 - Continue trying other homebrew paths
                continue
        return ""

    def _get_winget_command(self) -> str:
        """Get the correct winget command path."""
        winget_paths = [
            os.path.expandvars(r"%LOCALAPPDATA%\Microsoft\WindowsApps\winget.exe"),
            r"C:\Program Files\WindowsApps\Microsoft.DesktopAppInstaller_*\winget.exe",
        ]

        # Also check common user profile locations
        users_dir = r"C:\Users"
        if os.path.exists(users_dir):
            for user_dir in os.listdir(users_dir):
                user_winget = os.path.join(
                    users_dir,
                    user_dir,
                    r"AppData\Local\Microsoft\WindowsApps\winget.exe",
                )
                winget_paths.append(user_winget)

        # Add PATH fallback
        winget_paths.append("winget")

        for path in winget_paths:
            # Handle wildcards in path
            if "*" in path:
                matching_paths = glob.glob(path)
                if matching_paths:
                    path = matching_paths[0]
                else:
                    continue

            if path == "winget":
                # Try using it from PATH
                try:
                    result = subprocess.run(  # nosec B603, B607
                        [path, "--version"],
                        capture_output=True,
                        timeout=10,
                        check=False,
                    )
                    if result.returncode == 0:
                        return path
                except Exception:  # nosec B112
                    continue
            elif os.path.exists(path):
                # Verify it works before returning
                try:
                    result = subprocess.run(  # nosec B603, B607
                        [path, "--version"],
                        capture_output=True,
                        timeout=10,
                        check=False,
                    )
                    if result.returncode == 0:
                        logger.info(_("Found winget at: %s"), path)
                        return path
                except Exception:  # nosec B112
                    continue

        logger.warning(_("winget not found in any common location"))
        return ""

    def _collect_winget_packages(self) -> int:
        """Collect packages from Windows Package Manager (winget) via REST API."""
        try:
            # Use winget.run REST API to get the full catalog
            # This works from SYSTEM context without needing winget installed
            logger.info(_("Fetching winget catalog via REST API"))

            # winget.run API endpoint for getting all packages
            api_url = "https://api.winget.run/v2/packages"

            packages = []
            page = 1

            while True:
                try:
                    # Add pagination parameters
                    url = f"{api_url}?page={page}&limit=100"

                    req = urllib.request.Request(url)  # nosec B310
                    req.add_header("User-Agent", "SysManage-Agent/1.0")

                    with urllib.request.urlopen(
                        req, timeout=30
                    ) as response:  # nosec B310
                        data = json.loads(response.read().decode("utf-8"))

                        # Check if we got packages
                        if not data or "Packages" not in data:
                            break

                        page_packages = data.get("Packages", [])
                        if not page_packages:
                            break

                        # Convert API response to our package format
                        for pkg in page_packages:
                            package_id = pkg.get("Id", "")
                            latest = pkg.get("Latest", {})
                            package_name = latest.get("Name", "")
                            latest_version = latest.get("PackageVersion", "unknown")

                            if package_id and package_name:
                                packages.append(
                                    {
                                        "name": package_name,
                                        "version": latest_version,
                                        "id": package_id,
                                    }
                                )

                        # Check if there are more pages
                        total = data.get("Total", 0)
                        if 0 < total <= len(packages):
                            break

                        page += 1

                except Exception as e:
                    logger.error(
                        _(
                            "Error fetching winget page %d (collected %d packages so far): %s"
                        ),
                        page,
                        len(packages),
                        str(e),
                    )
                    break

            if packages:
                logger.info(
                    _("Successfully collected %d packages from winget REST API"),
                    len(packages),
                )
                return self._store_packages("winget", packages)

            logger.warning(_("No packages collected from winget REST API"))
            return 0

        except Exception as e:
            logger.error(_("Error collecting winget packages via REST API: %s"), e)
            return 0

    def _collect_chocolatey_packages(self) -> int:
        """Collect packages from Chocolatey community repository API."""
        try:
            logger.info(_("Fetching Chocolatey catalog via community repository API"))

            # Chocolatey community repository API endpoint
            api_url = "https://community.chocolatey.org/api/v2/Packages()"

            packages = []
            skip = 0
            top = 100  # Fetch 100 packages at a time

            while True:
                try:
                    # OData pagination parameters
                    url = f"{api_url}?$skip={skip}&$top={top}&$orderby=Id"

                    req = urllib.request.Request(url)  # nosec B310
                    req.add_header("User-Agent", "SysManage-Agent/1.0")

                    with urllib.request.urlopen(
                        req, timeout=30
                    ) as response:  # nosec B310
                        # Parse XML response
                        data = response.read().decode("utf-8")
                        root = ET.fromstring(data)

                        # Define namespaces
                        ns = {
                            "atom": "http://www.w3.org/2005/Atom",
                            "d": "http://schemas.microsoft.com/ado/2007/08/dataservices",
                            "m": "http://schemas.microsoft.com/ado/2007/08/dataservices/metadata",
                        }

                        # Extract packages from feed
                        entries = root.findall("atom:entry", ns)
                        if not entries:
                            break

                        for entry in entries:
                            # Get package ID from title element
                            title_elem = entry.find("atom:title", ns)
                            if title_elem is None or not title_elem.text:
                                continue

                            # Get version from properties
                            props = entry.find("m:properties", ns)
                            if props is None:
                                continue

                            version_elem = props.find("d:Version", ns)
                            if version_elem is None or not version_elem.text:
                                continue

                            packages.append(
                                {
                                    "name": title_elem.text,
                                    "version": version_elem.text,
                                    "description": "",
                                }
                            )

                        # If we got no entries, we're done
                        if not entries:
                            break

                        skip += len(entries)

                except Exception as e:
                    logger.warning(_("Error fetching page at skip %d: %s"), skip, e)
                    break

            if packages:
                logger.info(
                    _(
                        "Successfully collected %d packages from Chocolatey community repository"
                    ),
                    len(packages),
                )
                return self._store_packages("chocolatey", packages)

            logger.warning(
                _("No packages collected from Chocolatey community repository")
            )
            return 0

        except Exception as e:
            logger.error(_("Error collecting Chocolatey packages via API: %s"), e)
            return 0

    def _collect_pkg_packages(self) -> int:
        """Collect packages from pkg (FreeBSD/OpenBSD)."""
        try:
            # Detect which BSD variant we're on
            system = platform.system().lower()

            if system == "openbsd":
                # OpenBSD uses pkg_info -Q to search all available packages
                result = subprocess.run(  # nosec B603, B607
                    ["pkg_info", "-Q", ""],
                    capture_output=True,
                    text=True,
                    timeout=300,
                    check=False,
                )

                if result.returncode != 0:
                    logger.error(_("Failed to get OpenBSD package list"))
                    return 0

                packages = self._parse_openbsd_pkg_info_output(result.stdout)
                return self._store_packages("pkg_add", packages)

            # FreeBSD uses pkg rquery
            result = subprocess.run(  # nosec B603, B607
                ["pkg", "rquery", "--all", "%n-%v %c"],
                capture_output=True,
                text=True,
                timeout=300,
                check=False,
            )

            if result.returncode != 0:
                logger.error(_("Failed to get pkg package list"))
                return 0

            packages = self._parse_pkg_rquery_output(result.stdout)
            return self._store_packages("pkg", packages)

        except Exception as e:
            logger.error(_("Error collecting pkg packages: %s"), e)
            return 0

    def _collect_pkgin_packages(self) -> int:
        """Collect packages from pkgin (NetBSD)."""
        try:
            # Use pkgin avail to get all available packages from remote repositories
            result = subprocess.run(  # nosec B603, B607
                ["pkgin", "avail"],
                capture_output=True,
                text=True,
                timeout=300,
                check=False,
            )

            if result.returncode != 0:
                logger.error(_("Failed to get pkgin package list"))
                return 0

            packages = self._parse_pkgin_output(result.stdout)
            return self._store_packages("pkgin", packages)

        except Exception as e:
            logger.error(_("Error collecting pkgin packages: %s"), e)
            return 0

    def _parse_apt_output(self, output: str) -> List[Dict[str, str]]:
        """Parse APT package list output."""
        packages = []
        for line in output.splitlines():
            if (
                line.startswith("WARNING")
                or line.startswith("Listing")
                or not line.strip()
            ):
                continue

            # APT format: "package/repository version architecture"
            parts = line.split()
            if len(parts) >= 3:
                name_repo = parts[0].split("/")[
                    0
                ]  # Extract package name without repository
                version = parts[1]
                _architecture = parts[2]  # Architecture info, not currently used

                # For now, description is empty - could be enhanced later with apt-cache show
                description = ""

                packages.append(
                    {"name": name_repo, "version": version, "description": description}
                )

        return packages

    def _parse_apt_dumpavail_output(self, output: str) -> List[Dict[str, str]]:
        """Parse apt-cache dumpavail output to extract package info with descriptions."""
        # pylint: disable=too-many-nested-blocks
        packages = []
        current_package = {}

        # Split output into lines and process each package block
        lines = output.splitlines()
        i = 0

        while i < len(lines):
            line = lines[i].strip()

            # Skip empty lines at the start
            if not line:
                i += 1
                continue

            # Start of a new package block
            current_package = {}

            # Process all fields in this package block
            while i < len(lines) and lines[i].strip():
                line = lines[i].strip()

                if ":" in line:
                    field, value = line.split(":", 1)
                    field = field.strip().lower()
                    value = value.strip()

                    if field == "package":
                        current_package["name"] = value
                    elif field == "version":
                        current_package["version"] = value
                    elif field == "description":
                        # Description might span multiple lines
                        description_lines = [value]
                        i += 1

                        # Collect continuation lines (start with space)
                        while i < len(lines) and lines[i].startswith(" "):
                            desc_line = lines[i][1:]  # Remove leading space
                            if desc_line.strip():  # Skip empty description lines
                                description_lines.append(desc_line.strip())
                            i += 1

                        # Join description lines and clean up
                        current_package["description"] = " ".join(
                            description_lines
                        ).strip()
                        continue  # i already incremented in the while loop

                i += 1

            # Add package if we have minimum required fields
            if current_package.get("name") and current_package.get("version"):
                # Ensure description exists (empty string if missing)
                if "description" not in current_package:
                    current_package["description"] = ""

                packages.append(current_package)

            # Skip empty line after package block
            i += 1

        return packages

    def _parse_yum_output(self, output: str) -> List[Dict[str, str]]:
        """Parse YUM/DNF package list output."""
        packages = []
        parsing_packages = False

        for line in output.splitlines():
            if "Available Packages" in line:
                parsing_packages = True
                continue

            if not parsing_packages or not line.strip():
                continue

            # YUM format: "package.arch version repo"
            parts = line.split()
            if len(parts) >= 2:
                name_arch = parts[0].split(".")[0]
                version = parts[1]

                packages.append(
                    {"name": name_arch, "version": version, "description": ""}
                )

        return packages

    def _parse_zypper_output(self, output: str) -> List[Dict[str, str]]:
        """Parse Zypper package list output."""
        packages = []
        for line in output.splitlines():
            if line.startswith("i") or line.startswith("v") or not line.strip():
                continue

            # Zypper format varies, try to extract name and version
            parts = line.split("|")
            if len(parts) >= 3:
                name = parts[1].strip()
                version = parts[2].strip()

                packages.append({"name": name, "version": version, "description": ""})

        return packages

    def _parse_pacman_output(self, output: str) -> List[Dict[str, str]]:
        """Parse Pacman package list output."""
        packages = []
        current_package: Dict[str, str] = {}

        for line in output.splitlines():
            if line.startswith("    "):
                # Description line
                if current_package:
                    current_package["description"] = line.strip()
            else:
                # Package line: "repo/package version"
                if current_package:
                    packages.append(current_package)

                parts = line.split()
                if len(parts) >= 2:
                    name = parts[0].split("/")[-1]
                    version = parts[1]

                    current_package = {
                        "name": name,
                        "version": version,
                        "description": "",
                    }

        if current_package:
            packages.append(current_package)

        return packages

    def _parse_snap_output(self, output: str) -> List[Dict[str, str]]:
        """Parse Snap package list output from 'snap find %'."""
        packages = []
        lines = output.splitlines()

        # Skip header line and empty lines
        for line in lines:
            if line.startswith("Name") or not line.strip():
                continue

            # Parse fixed-width columns based on 'snap find %' format
            # Name (25 chars), Version (28 chars), Publisher (21 chars), Notes (8 chars), Summary (rest)
            try:
                if len(line) < 30:  # Skip lines that are too short
                    continue

                # Extract name (first column, trim whitespace)
                name = line[:25].strip()
                if not name:
                    continue

                # Extract version (second column, starts around position 25)
                version_start = 25
                version_line = line[version_start:]
                version_match = version_line.split()[0] if version_line.split() else ""

                # Find summary - it's the last column after publisher and notes
                # Split the line and take everything after position 3 (name, version, publisher, notes)
                parts = line.split()
                if len(parts) >= 5:
                    # Summary is everything from the 5th element onwards
                    summary = " ".join(parts[4:])
                else:
                    summary = ""

                if name and version_match:
                    packages.append(
                        {"name": name, "version": version_match, "description": summary}
                    )

            except Exception:  # nosec B112
                # If parsing fails for a line, skip it and continue processing
                # This is safe because we're parsing text output that may have malformed lines
                continue

        return packages

    def _parse_flatpak_output(self, output: str) -> List[Dict[str, str]]:
        """Parse Flatpak package list output."""
        packages = []
        for line in output.splitlines():
            if not line.strip():
                continue

            # Flatpak format: "Name Description Application ID Version Branch Origin"
            parts = line.split("\t")
            if len(parts) >= 4:
                name = parts[0]
                description = parts[1]
                version = parts[3]

                packages.append(
                    {"name": name, "version": version, "description": description}
                )

        return packages

    def _parse_homebrew_list_output(
        self, output: str, package_type: str
    ) -> List[Dict[str, str]]:
        """Parse Homebrew list --versions output."""
        packages = []
        for line in output.splitlines():
            if not line.strip():
                continue

            # Format: "package_name version1 version2 ..."
            # We take the first version listed (usually the currently installed one)
            parts = line.split()
            if len(parts) >= 2:
                name = parts[0]
                version = parts[1]  # First version listed

                # Add package type info to description for clarity
                description = f"Homebrew {package_type}"

                packages.append(
                    {"name": name, "version": version, "description": description}
                )
            elif len(parts) == 1:
                # Some packages might not have versions listed
                name = parts[0]
                packages.append(
                    {
                        "name": name,
                        "version": "unknown",
                        "description": f"Homebrew {package_type}",
                    }
                )

        return packages

    def _parse_homebrew_output(self, output: str) -> List[Dict[str, str]]:
        """Parse Homebrew package list output (legacy method - kept for compatibility)."""
        packages = []
        for line in output.splitlines():
            if not line.strip():
                continue

            # For now, just get package names - version requires individual queries
            name = line.strip()
            if name:
                packages.append({"name": name, "version": "latest", "description": ""})

        return packages

    def _parse_winget_output(self, output: str) -> List[Dict[str, str]]:
        """Parse winget package list output."""
        packages = []
        for line in output.splitlines():
            if line.startswith("Name") or not line.strip():
                continue

            # winget format varies, try to extract basic info
            parts = line.split()
            if len(parts) >= 2:
                name = parts[0]
                version = parts[-1] if len(parts) > 1 else "latest"

                packages.append({"name": name, "version": version, "description": ""})

        return packages

    def _parse_chocolatey_output(self, output: str) -> List[Dict[str, str]]:
        """Parse Chocolatey package list output."""
        packages = []
        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue

            # Skip header/footer lines
            if any(
                skip in line.lower()
                for skip in [
                    "chocolatey",
                    "packages found",
                    "validating",
                    "loading",
                    "page",
                    "http",
                    "features?",
                    "did you",
                ]
            ):
                continue

            # Chocolatey format: "name version"
            parts = line.split()
            if len(parts) >= 2:
                name = parts[0]
                version = parts[1]

                # Validate package name (should not contain common HTML/text words)
                if name.lower() in ["the", "did", "you", "page", "this"]:
                    continue

                packages.append({"name": name, "version": version, "description": ""})

        return packages

    def _parse_pkg_output(self, output: str) -> List[Dict[str, str]]:
        """Parse pkg package list output."""
        packages = []
        for line in output.splitlines():
            if not line.strip():
                continue

            # pkg format: "name-version comment"
            parts = line.split(" ", 1)
            if len(parts) >= 1:
                name_version = parts[0]
                description = parts[1] if len(parts) > 1 else ""

                # Try to separate name and version
                if "-" in name_version:
                    last_dash = name_version.rfind("-")
                    name = name_version[:last_dash]
                    version = name_version[last_dash + 1 :]
                else:
                    name = name_version
                    version = "unknown"

                packages.append(
                    {"name": name, "version": version, "description": description}
                )

        return packages

    def _parse_pkg_rquery_output(self, output: str) -> List[Dict[str, str]]:
        """Parse pkg rquery --all output."""
        packages = []
        for line in output.splitlines():
            if not line.strip():
                continue

            # pkg rquery format: "name-version comment"
            parts = line.split(" ", 1)
            if len(parts) >= 1:
                name_version = parts[0]
                description = parts[1] if len(parts) > 1 else ""

                # Try to separate name and version
                if "-" in name_version:
                    last_dash = name_version.rfind("-")
                    name = name_version[:last_dash]
                    version = name_version[last_dash + 1 :]
                else:
                    name = name_version
                    version = "unknown"

                packages.append(
                    {"name": name, "version": version, "description": description}
                )

        return packages

    def _parse_pkgin_output(self, output: str) -> List[Dict[str, str]]:
        """Parse pkgin avail output."""
        packages = []
        for line in output.splitlines():
            if not line.strip() or line.startswith("pkg_summary"):
                continue

            # pkgin avail format: "package-version;comment"
            # Sometimes may be just "package-version" without comment
            if ";" in line:
                parts = line.split(";", 1)
                name_version = parts[0].strip()
                description = parts[1].strip()
            else:
                name_version = line.strip()
                description = ""

            # Try to separate name and version
            if "-" in name_version:
                # Find the last dash that separates name from version
                last_dash = name_version.rfind("-")
                name = name_version[:last_dash]
                version = name_version[last_dash + 1 :]
            else:
                name = name_version
                version = "unknown"

            packages.append(
                {"name": name, "version": version, "description": description}
            )

        return packages

    def _parse_openbsd_pkg_info_output(self, output: str) -> List[Dict[str, str]]:
        """Parse OpenBSD pkg_info -Q output."""
        packages = []
        for line in output.splitlines():
            if not line.strip():
                continue

            # pkg_info -Q format: "package-name-version"
            name_version = line.strip()

            # Try to separate name and version
            # OpenBSD package format: name-version where version starts with a digit
            if "-" in name_version:
                # Find the last dash followed by a digit (version number)
                parts = name_version.rsplit("-", 1)
                if len(parts) == 2 and parts[1] and parts[1][0].isdigit():
                    name = parts[0]
                    version = parts[1]
                else:
                    # If no digit after last dash, it's probably part of the name
                    name = name_version
                    version = "unknown"
            else:
                name = name_version
                version = "unknown"

            packages.append({"name": name, "version": version, "description": ""})

        return packages

    def _store_packages(self, manager: str, packages: List[Dict[str, str]]) -> int:
        """Store packages in the local database."""
        if not packages:
            return 0

        collection_date = datetime.now(timezone.utc)
        stored_count = 0

        try:
            with self.db_manager.get_session() as session:
                # Delete existing packages for this manager
                session.query(AvailablePackage).filter(
                    AvailablePackage.package_manager == manager
                ).delete()

                # Insert new packages
                for package in packages:
                    db_package = AvailablePackage(
                        package_manager=manager,
                        package_name=package["name"],
                        package_version=package["version"],
                        package_description=package.get("description", ""),
                        collection_date=collection_date,
                        created_at=collection_date,
                    )
                    session.add(db_package)
                    stored_count += 1

                session.commit()

        except Exception as e:
            logger.error(_("Failed to store packages for %s: %s"), manager, e)
            return 0

        return stored_count

    def get_packages_for_manager(self, manager: str) -> List[AvailablePackage]:
        """Get all packages for a specific package manager."""
        try:
            with self.db_manager.get_session() as session:
                packages = (
                    session.query(AvailablePackage)
                    .filter(AvailablePackage.package_manager == manager)
                    .all()
                )

                # Detach from session
                return [
                    AvailablePackage(
                        id=pkg.id,
                        package_manager=pkg.package_manager,
                        package_name=pkg.package_name,
                        package_version=pkg.package_version,
                        package_description=pkg.package_description,
                        collection_date=pkg.collection_date,
                        created_at=pkg.created_at,
                    )
                    for pkg in packages
                ]

        except Exception as e:
            logger.error(_("Failed to get packages for %s: %s"), manager, e)
            return []

    def get_all_packages(self) -> List[AvailablePackage]:
        """Get all available packages from the database."""
        try:
            with self.db_manager.get_session() as session:
                packages = session.query(AvailablePackage).all()

                # Detach from session
                return [
                    AvailablePackage(
                        id=pkg.id,
                        package_manager=pkg.package_manager,
                        package_name=pkg.package_name,
                        package_version=pkg.package_version,
                        package_description=pkg.package_description,
                        collection_date=pkg.collection_date,
                        created_at=pkg.created_at,
                    )
                    for pkg in packages
                ]

        except Exception as e:
            logger.error(_("Failed to get all packages: %s"), e)
            return []

    def get_package_managers(self) -> List[str]:
        """Get list of package managers that have packages stored."""
        try:
            with self.db_manager.get_session() as session:
                managers = (
                    session.query(AvailablePackage.package_manager).distinct().all()
                )
                return [manager[0] for manager in managers]

        except Exception as e:
            logger.error(_("Failed to get package managers: %s"), e)
            return []

    def get_packages_for_transmission(self) -> Dict[str, any]:
        """Get all packages organized by package manager for transmission to server.

        Note: This method only returns package data. The OS name and version
        should be determined by the caller using the registration system's
        get_system_info() to ensure consistency with host registration.
        """
        try:
            with self.db_manager.get_session() as session:
                packages = session.query(AvailablePackage).all()

                # Organize packages by manager
                packages_by_manager = {}
                for package in packages:
                    manager = package.package_manager
                    if manager not in packages_by_manager:
                        packages_by_manager[manager] = []

                    packages_by_manager[manager].append(
                        {
                            "name": package.package_name,
                            "version": package.package_version,
                            "description": package.package_description or "",
                        }
                    )

                # Return only package manager data
                # OS info should be added by caller from registration system
                return {
                    "package_managers": packages_by_manager,
                }

        except Exception as e:
            logger.error(_("Failed to get packages for transmission: %s"), e)
            return {}
