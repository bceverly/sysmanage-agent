"""
OS information collection module for SysManage Agent.
Handles platform-specific OS version and architecture information gathering.
"""

import json
import logging
import platform
import subprocess  # nosec B404
import time
from typing import Any, Dict, Optional

from src.i18n import _

# Constant for zoneinfo path used in timezone extraction
ZONEINFO_PATH_SEGMENT = "/zoneinfo/"


class OSInfoCollector:
    """Collects operating system information across different platforms."""

    def __init__(self):
        self.logger = logging.getLogger(__name__)

        # macOS version name mapping (Darwin kernel to macOS marketing names)
        self.macos_version_names = {
            "24": "Sequoia",
            "23": "Sonoma",
            "22": "Ventura",
            "21": "Monterey",
            "20": "Big Sur",
            "19": "Catalina",
            "18": "Mojave",
            "17": "High Sierra",
            "16": "Sierra",
            "15": "El Capitan",
            "14": "Yosemite",
            "13": "Mavericks",
            "12": "Mountain Lion",
            "11": "Lion",
        }

    def _get_macos_friendly_name(self, darwin_version: str) -> str:
        """Convert Darwin kernel version to friendly macOS name."""
        try:
            # Darwin version format is typically "24.6.0"
            major_version = darwin_version.split(".")[0]

            if major_version in self.macos_version_names:
                # Get the actual macOS version from system
                mac_ver = platform.mac_ver()
                if mac_ver[0]:
                    # Extract major.minor from macOS version (e.g., "15.6" from "15.6.0")
                    mac_version_parts = mac_ver[0].split(".")
                    if len(mac_version_parts) >= 2:
                        mac_version = f"{mac_version_parts[0]}.{mac_version_parts[1]}"
                        return (
                            f"{self.macos_version_names[major_version]} {mac_version}"
                        )
                    return f"{self.macos_version_names[major_version]} {mac_ver[0]}"

            # Fallback to original version if we can't map it
            return darwin_version

        except (IndexError, ValueError):
            return darwin_version

    def _get_linux_distribution_info(self) -> tuple:
        """Get Linux distribution name and version."""
        try:
            # Try to get Linux distribution info if available
            if hasattr(platform, "freedesktop_os_release"):
                os_release = platform.freedesktop_os_release()
                distro_name = os_release.get("NAME", "")
                distro_version = os_release.get("VERSION_ID", "")

                # Clean up distribution name (remove "Linux" suffix if present)
                if distro_name.endswith(" Linux"):
                    distro_name = distro_name[:-6]

                if distro_name and distro_version:
                    return (distro_name, distro_version)

        except (AttributeError, OSError):
            pass

        # Fallback to kernel version
        return ("Linux", platform.release())

    def _get_ubuntu_pro_info(self) -> Dict[str, Any]:
        """Get Ubuntu Pro subscription and service status information."""
        ubuntu_pro_info = {
            "available": False,
            "attached": False,
            "services": [],
            "account_name": "",
            "contract_name": "",
            "expires": None,
            "version": "",
            "tech_support_level": "n/a",
        }

        try:
            result = subprocess.run(
                ["pro", "status", "--all", "--format", "json"],  # nosec B603, B607
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )

            if result.returncode == 0 and result.stdout:
                self._parse_ubuntu_pro_output(result.stdout, ubuntu_pro_info)

        except subprocess.TimeoutExpired:
            self.logger.warning(_("Ubuntu Pro status check timed out"))
        except FileNotFoundError:
            # pro command not available - this is normal on non-Ubuntu systems
            self.logger.debug(_("Ubuntu Pro not available on this system"))
        except Exception as error:
            self.logger.warning(_("Failed to get Ubuntu Pro status: %s"), str(error))

        return ubuntu_pro_info

    def _parse_ubuntu_pro_output(
        self, stdout: str, ubuntu_pro_info: Dict[str, Any]
    ) -> None:
        """Parse the JSON output from Ubuntu Pro status command."""
        try:
            pro_data = json.loads(stdout)

            ubuntu_pro_info["available"] = True
            ubuntu_pro_info["attached"] = pro_data.get("attached", False)
            ubuntu_pro_info["version"] = pro_data.get("version", "")
            ubuntu_pro_info["expires"] = pro_data.get("expires")

            self._parse_ubuntu_pro_account_info(pro_data, ubuntu_pro_info)

            service_list = self._parse_ubuntu_pro_services(pro_data.get("services", []))
            ubuntu_pro_info["services"] = service_list

            self.logger.debug(
                _("Ubuntu Pro status collected: attached=%s, services=%d"),
                ubuntu_pro_info["attached"],
                len(service_list),
            )

        except json.JSONDecodeError as error:
            self.logger.warning(
                _("Failed to parse Ubuntu Pro JSON output: %s"), str(error)
            )
        except Exception as error:
            self.logger.warning(_("Error processing Ubuntu Pro data: %s"), str(error))

    def _parse_ubuntu_pro_account_info(
        self, pro_data: Dict, ubuntu_pro_info: Dict[str, Any]
    ) -> None:
        """Parse account and contract information from Ubuntu Pro data."""
        account = pro_data.get("account", {})
        if account:
            ubuntu_pro_info["account_name"] = account.get("name", "")

        contract = pro_data.get("contract", {})
        if contract:
            ubuntu_pro_info["contract_name"] = contract.get("name", "")
            ubuntu_pro_info["tech_support_level"] = contract.get(
                "tech_support_level", "n/a"
            )

    def _parse_ubuntu_pro_services(self, services: list) -> list:
        """Parse Ubuntu Pro services list into normalized service records."""
        service_list = []

        self.logger.debug("Processing %d services from pro status", len(services))

        for i, service in enumerate(services):
            service_info = self._parse_single_ubuntu_pro_service(
                service, i, len(services)
            )
            service_list.append(service_info)

        self.logger.debug("Final service list contains %d services", len(service_list))

        return service_list

    def _parse_single_ubuntu_pro_service(
        self, service: Dict, index: int, total: int
    ) -> Dict[str, Any]:
        """Parse a single Ubuntu Pro service into a normalized record."""
        service_name = service.get("name", "")
        raw_status = service.get("status", "disabled")
        available = service.get("available", "no") == "yes"
        entitled = service.get("entitled", "no") == "yes"

        self.logger.debug(
            "Service %d/%d: %s - raw_status=%s, available=%s, entitled=%s",
            index + 1,
            total,
            service_name,
            raw_status,
            available,
            entitled,
        )

        # Determine the normalized status
        if not available:
            status = "n/a"
        elif raw_status in ["enabled", "active"]:
            status = "enabled"
        else:
            status = "disabled"

        self.logger.debug("Added service: %s with status=%s", service_name, status)

        return {
            "name": service_name,
            "description": service.get("description", ""),
            "available": available,
            "status": status,
            "entitled": entitled,
            "raw_status": raw_status,  # Keep original for debugging
        }

    def _extract_timezone_from_zoneinfo_path(self, path: str) -> Optional[str]:
        """Extract timezone name from a zoneinfo path.

        Args:
            path: Path like /usr/share/zoneinfo/America/New_York

        Returns:
            Timezone name or None if not found
        """
        if ZONEINFO_PATH_SEGMENT in path:
            return path.split(ZONEINFO_PATH_SEGMENT)[-1]
        return None

    def _run_timezone_command(
        self, cmd: list, timeout: int = 5
    ) -> Optional[subprocess.CompletedProcess]:
        """Run a command to get timezone info, handling errors.

        Returns:
            CompletedProcess if successful, None otherwise
        """
        try:
            result = subprocess.run(  # nosec B603, B607
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
            if result.returncode == 0 and result.stdout.strip():
                return result
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
        return None

    def _get_timezone_linux_bsd(self) -> Optional[str]:
        """Get timezone on Linux/BSD systems."""
        # Try /etc/timezone (Debian/Ubuntu)
        result = self._run_timezone_command(["cat", "/etc/timezone"])
        if result:
            return result.stdout.strip()

        # Try /etc/localtime symlink (RHEL/CentOS/Fedora/FreeBSD)
        result = self._run_timezone_command(["readlink", "-f", "/etc/localtime"])
        if result:
            timezone_name = self._extract_timezone_from_zoneinfo_path(
                result.stdout.strip()
            )
            if timezone_name:
                return timezone_name

        # Try timedatectl (systemd)
        result = self._run_timezone_command(
            ["timedatectl", "show", "--property=Timezone", "--value"]
        )
        if result:
            return result.stdout.strip()

        return None

    def _get_timezone_darwin(self) -> Optional[str]:
        """Get timezone on macOS."""
        # Try systemsetup
        result = self._run_timezone_command(
            ["sudo", "-n", "systemsetup", "-gettimezone"]
        )
        if result:
            output = result.stdout.strip()
            if ":" in output:
                return output.split(":", 1)[1].strip()

        # Fallback: read /etc/localtime symlink
        result = self._run_timezone_command(["readlink", "/etc/localtime"])
        if result:
            return self._extract_timezone_from_zoneinfo_path(result.stdout.strip())

        return None

    def _get_timezone_windows(self) -> Optional[str]:
        """Get timezone on Windows."""
        result = self._run_timezone_command(
            ["powershell", "-Command", "(Get-TimeZone).Id"], timeout=10
        )
        if result:
            return result.stdout.strip()
        return None

    def _get_timezone_fallback(self) -> str:
        """Get timezone using Python's time module as fallback."""
        if time.daylight:
            return time.tzname[1]  # Daylight saving time name
        return time.tzname[0]  # Standard time name

    def _get_timezone(self) -> str:
        """Get the system timezone.

        Returns the timezone name (e.g., 'America/New_York', 'UTC', 'EST')
        """
        try:
            system = platform.system()

            # Try platform-specific methods
            timezone_result = None
            if system in ("Linux", "FreeBSD", "OpenBSD", "NetBSD"):
                timezone_result = self._get_timezone_linux_bsd()
            elif system == "Darwin":
                timezone_result = self._get_timezone_darwin()
            elif system == "Windows":
                timezone_result = self._get_timezone_windows()

            if timezone_result:
                return timezone_result

            # Fallback to Python's time module
            return self._get_timezone_fallback()

        except Exception as error:
            self.logger.warning(_("Failed to get timezone: %s"), error)
            return time.tzname[0] if time.tzname[0] else "Unknown"

    def get_os_version_info(self) -> Dict[str, Any]:
        """Get comprehensive OS version information as separate data."""
        # Get CPU architecture (x86_64, arm64, aarch64, riscv64, etc.)
        machine_arch = platform.machine()

        # Get the base system info
        system_name = platform.system()
        system_release = platform.release()

        # Get platform-specific friendly names, versions, and extra info
        friendly_platform, friendly_release, os_info = self._collect_platform_info(
            system_name, system_release
        )

        return {
            "platform": friendly_platform,
            "platform_release": friendly_release,
            "platform_version": platform.version(),
            "architecture": platform.architecture()[0],
            "processor": platform.processor(),
            "machine_architecture": machine_arch,  # CPU architecture
            "timezone": self._get_timezone(),
            "python_version": platform.python_version(),
            "os_info": os_info,
        }

    def _collect_platform_info(self, system_name: str, system_release: str) -> tuple:
        """Collect platform-specific friendly name, release, and OS info.

        Returns:
            Tuple of (friendly_platform, friendly_release, os_info dict)
        """
        if system_name == "Darwin":
            return self._collect_darwin_info(system_release)
        if system_name == "Linux":
            return self._collect_linux_info(system_release)
        if system_name == "Windows":
            return self._collect_windows_info(system_release)
        if system_name == "FreeBSD":
            return self._collect_freebsd_info(system_release)
        if system_name == "OpenBSD":
            return (system_name, system_release, {"openbsd_version": system_release})
        if system_name == "NetBSD":
            return (system_name, system_release, {"netbsd_version": system_release})
        return (system_name, system_release, {})

    def _collect_darwin_info(self, system_release: str) -> tuple:
        """Collect macOS-specific platform information."""
        friendly_release = self._get_macos_friendly_name(system_release)
        mac_ver = platform.mac_ver()
        os_info = {"mac_version": mac_ver[0] if mac_ver[0] else ""}
        return ("macOS", friendly_release, os_info)

    def _collect_linux_info(self, system_release: str) -> tuple:
        """Collect Linux-specific platform information."""
        distro_name, distro_version = self._get_linux_distribution_info()

        if distro_name != "Linux":
            friendly_release = f"{distro_name} {distro_version}"
        else:
            friendly_release = system_release

        os_info = self._collect_linux_os_info()
        return ("Linux", friendly_release, os_info)

    def _collect_linux_os_info(self) -> Dict[str, Any]:
        """Collect Linux distribution details and Ubuntu Pro info if applicable."""
        os_info = {}
        try:
            if hasattr(platform, "freedesktop_os_release"):
                os_release = platform.freedesktop_os_release()
                os_info["distribution"] = os_release.get("NAME", "")
                os_info["distribution_version"] = os_release.get("VERSION_ID", "")
                os_info["distribution_codename"] = os_release.get(
                    "VERSION_CODENAME", ""
                )

                distribution = os_info.get("distribution", "")
                if "ubuntu" in distribution.lower():
                    os_info["ubuntu_pro"] = self._get_ubuntu_pro_info()

        except (AttributeError, OSError):
            pass

        return os_info

    def _collect_windows_info(self, system_release: str) -> tuple:
        """Collect Windows-specific platform information."""
        win_ver = platform.win32_ver()
        os_info = {
            "windows_version": win_ver[0] if win_ver[0] else "",
            "windows_service_pack": win_ver[1] if win_ver[1] else "",
        }
        return ("Windows", system_release, os_info)

    def _collect_freebsd_info(self, system_release: str) -> tuple:
        """Collect FreeBSD-specific platform information."""
        os_info = {"freebsd_version": system_release}

        try:
            result = subprocess.run(
                ["freebsd-version", "-u"],  # nosec B603, B607
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            if result.returncode == 0 and result.stdout.strip():
                os_info["freebsd_userland_version"] = result.stdout.strip()
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

        return ("FreeBSD", system_release, os_info)
