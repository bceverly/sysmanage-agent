"""
OS information collection module for SysManage Agent.
Handles platform-specific OS version and architecture information gathering.
"""

import json
import logging
import platform
import subprocess  # nosec B404
from typing import Any, Dict

from src.i18n import _


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
            # Check if Ubuntu Pro (pro command) is available
            # Use --all to get all services including N/A ones
            result = subprocess.run(
                ["pro", "status", "--all", "--format", "json"],  # nosec B603, B607
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )

            if result.returncode == 0 and result.stdout:
                try:
                    pro_data = json.loads(result.stdout)

                    ubuntu_pro_info["available"] = True
                    ubuntu_pro_info["attached"] = pro_data.get("attached", False)
                    ubuntu_pro_info["version"] = pro_data.get("version", "")
                    ubuntu_pro_info["expires"] = pro_data.get("expires")

                    # Account information
                    account = pro_data.get("account", {})
                    if account:
                        ubuntu_pro_info["account_name"] = account.get("name", "")

                    # Contract information
                    contract = pro_data.get("contract", {})
                    if contract:
                        ubuntu_pro_info["contract_name"] = contract.get("name", "")
                        ubuntu_pro_info["tech_support_level"] = contract.get(
                            "tech_support_level", "n/a"
                        )

                    # Services information
                    services = pro_data.get("services", [])
                    service_list = []

                    self.logger.debug(
                        "Processing %d services from pro status", len(services)
                    )

                    for i, service in enumerate(services):
                        service_name = service.get("name", "")

                        # Map the pro status values to our standardized status
                        raw_status = service.get("status", "disabled")
                        available = service.get("available", "no") == "yes"
                        entitled = service.get("entitled", "no") == "yes"

                        self.logger.debug(
                            "Service %d/%d: %s - raw_status=%s, available=%s, entitled=%s",
                            i + 1,
                            len(services),
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

                        service_info = {
                            "name": service_name,
                            "description": service.get("description", ""),
                            "available": available,
                            "status": status,
                            "entitled": entitled,
                            "raw_status": raw_status,  # Keep original for debugging
                        }
                        service_list.append(service_info)

                        self.logger.debug(
                            "Added service: %s with status=%s", service_name, status
                        )

                    ubuntu_pro_info["services"] = service_list
                    self.logger.debug(
                        "Final service list contains %d services", len(service_list)
                    )

                    self.logger.debug(
                        _("Ubuntu Pro status collected: attached=%s, services=%d"),
                        ubuntu_pro_info["attached"],
                        len(service_list),
                    )

                except json.JSONDecodeError as e:
                    self.logger.warning(
                        _("Failed to parse Ubuntu Pro JSON output: %s"), str(e)
                    )
                except Exception as e:
                    self.logger.warning(
                        _("Error processing Ubuntu Pro data: %s"), str(e)
                    )

        except subprocess.TimeoutExpired:
            self.logger.warning(_("Ubuntu Pro status check timed out"))
        except FileNotFoundError:
            # pro command not available - this is normal on non-Ubuntu systems
            self.logger.debug(_("Ubuntu Pro not available on this system"))
        except Exception as e:
            self.logger.warning(_("Failed to get Ubuntu Pro status: %s"), str(e))

        return ubuntu_pro_info

    def get_os_version_info(self) -> Dict[str, Any]:
        """Get comprehensive OS version information as separate data."""
        # Get CPU architecture (x86_64, arm64, aarch64, riscv64, etc.)
        machine_arch = platform.machine()

        # Get the base system info
        system_name = platform.system()
        system_release = platform.release()

        # Get detailed OS information
        os_info = {}

        # Handle platform-specific friendly names and versions
        if system_name == "Darwin":
            # Change "Darwin" to "macOS" and get friendly version name
            friendly_platform = "macOS"
            friendly_release = self._get_macos_friendly_name(system_release)

            mac_ver = platform.mac_ver()
            os_info["mac_version"] = mac_ver[0] if mac_ver[0] else ""

        elif system_name == "Linux":
            # For Linux, get distribution info
            distro_name, distro_version = self._get_linux_distribution_info()
            friendly_platform = "Linux"

            # If we got distribution info, use it for the release field
            if distro_name != "Linux":
                friendly_release = f"{distro_name} {distro_version}"
            else:
                friendly_release = system_release  # Fallback to kernel version

            # Store distribution info in os_info for backward compatibility
            try:
                if hasattr(platform, "freedesktop_os_release"):
                    os_release = platform.freedesktop_os_release()
                    os_info["distribution"] = os_release.get("NAME", "")
                    os_info["distribution_version"] = os_release.get("VERSION_ID", "")
                    os_info["distribution_codename"] = os_release.get(
                        "VERSION_CODENAME", ""
                    )

                    # Add Ubuntu Pro information for Ubuntu systems
                    distribution = os_info.get("distribution", "")
                    if "ubuntu" in distribution.lower():
                        os_info["ubuntu_pro"] = self._get_ubuntu_pro_info()

            except (AttributeError, OSError):
                pass

        elif system_name == "Windows":
            # Keep Windows as-is for now
            friendly_platform = system_name
            friendly_release = system_release

            win_ver = platform.win32_ver()
            os_info["windows_version"] = win_ver[0] if win_ver[0] else ""
            os_info["windows_service_pack"] = win_ver[1] if win_ver[1] else ""

        else:
            # Default behavior for other platforms
            friendly_platform = system_name
            friendly_release = system_release

        return {
            "platform": friendly_platform,
            "platform_release": friendly_release,
            "platform_version": platform.version(),
            "architecture": platform.architecture()[0],
            "processor": platform.processor(),
            "machine_architecture": machine_arch,  # CPU architecture
            "python_version": platform.python_version(),
            "os_info": os_info,
        }
