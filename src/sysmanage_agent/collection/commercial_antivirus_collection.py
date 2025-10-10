"""
Commercial antivirus detection module for SysManage Agent.
Handles detection of commercial antivirus software (e.g., Microsoft Defender, McAfee, Symantec).
"""

import json
import logging
import platform
import subprocess  # nosec B404
from datetime import datetime
from typing import Dict, Optional

from src.i18n import _


class CommercialAntivirusCollector:
    """Collects commercial antivirus software information across different platforms."""

    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.system = platform.system()

    def collect_commercial_antivirus_status(self) -> Dict[str, Optional[str]]:
        """
        Collect commercial antivirus status information for the current system.

        Returns:
            dict: Dictionary containing commercial antivirus status fields or None if not detected
        """
        self.logger.info(_("Starting commercial antivirus detection"))

        try:
            if self.system == "Windows":
                return self._detect_windows_commercial_antivirus()
            if self.system == "Darwin":  # macOS
                return self._detect_macos_commercial_antivirus()
            # For other systems, return None to indicate no commercial AV
            self.logger.info(
                _("Commercial antivirus detection not applicable for %s"),
                self.system,
            )
            return None

        except Exception as error:
            self.logger.error(
                _("Error detecting commercial antivirus: %s"), error, exc_info=True
            )
            return None

    def _detect_windows_commercial_antivirus(self) -> Optional[Dict]:
        """
        Detect Microsoft Defender on Windows systems using PowerShell.

        Returns:
            dict with commercial antivirus information or None if not detected
        """
        try:
            # Check if Windows Defender service exists and is running
            service_check_cmd = [
                "powershell.exe",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "Get-Service -Name 'WinDefend' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Status",
            ]

            service_result = subprocess.run(
                service_check_cmd,
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )  # nosec B603

            # If service doesn't exist or isn't running, no Microsoft Defender
            if service_result.returncode != 0 or "Running" not in service_result.stdout:
                self.logger.info(
                    _("Microsoft Defender service not detected or not running")
                )
                return None

            # Get detailed status from Get-MpComputerStatus
            status_cmd = [
                "powershell.exe",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "Get-MpComputerStatus | ConvertTo-Json -Compress",
            ]

            status_result = subprocess.run(
                status_cmd, capture_output=True, text=True, timeout=30, check=False
            )  # nosec B603

            if status_result.returncode != 0:
                self.logger.error(
                    _("Failed to get Microsoft Defender status: %s"),
                    status_result.stderr,
                )
                return None

            # Parse the JSON output
            status_data = json.loads(status_result.stdout)

            # Get product version
            version_cmd = [
                "powershell.exe",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "(Get-MpComputerStatus).AMProductVersion",
            ]

            version_result = subprocess.run(
                version_cmd, capture_output=True, text=True, timeout=10, check=False
            )  # nosec B603

            product_version = (
                version_result.stdout.strip()
                if version_result.returncode == 0
                else None
            )

            # Extract and format the data
            antivirus_info = {
                "product_name": "Microsoft Defender",
                "product_version": product_version,
                "service_enabled": status_data.get("AMServiceEnabled"),
                "antispyware_enabled": status_data.get("AntispywareEnabled"),
                "antivirus_enabled": status_data.get("AntivirusEnabled"),
                "realtime_protection_enabled": status_data.get(
                    "RealTimeProtectionEnabled"
                ),
                "full_scan_age": status_data.get("FullScanAge"),
                "quick_scan_age": status_data.get("QuickScanAge"),
                "full_scan_end_time": self._parse_ps_datetime(
                    status_data.get("FullScanEndTime")
                ),
                "quick_scan_end_time": self._parse_ps_datetime(
                    status_data.get("QuickScanEndTime")
                ),
                "signature_last_updated": self._parse_ps_datetime(
                    status_data.get("AntivirusSignatureLastUpdated")
                ),
                "signature_version": status_data.get("AntivirusSignatureVersion"),
                "tamper_protection_enabled": status_data.get("IsTamperProtected"),
            }

            self.logger.info(
                _("Detected Microsoft Defender (version: %s, enabled: %s)"),
                product_version,
                antivirus_info["antivirus_enabled"],
            )

            return antivirus_info

        except json.JSONDecodeError as error:
            self.logger.error(
                _("Failed to parse Microsoft Defender status JSON: %s"), error
            )
            return None
        except subprocess.TimeoutExpired:
            self.logger.error(_("Timeout while querying Microsoft Defender status"))
            return None
        except Exception as error:
            self.logger.error(
                _("Error detecting Microsoft Defender: %s"), error, exc_info=True
            )
            return None

    def _parse_ps_datetime(self, ps_datetime_str: Optional[str]) -> Optional[str]:
        """
        Parse PowerShell datetime string and convert to ISO format UTC.

        Args:
            ps_datetime_str: PowerShell datetime string

        Returns:
            ISO format datetime string in UTC or None
        """
        if not ps_datetime_str:
            return None

        try:
            # PowerShell datetime format: "MM/DD/YYYY HH:MM:SS AM/PM"
            # Try to parse various PowerShell date formats
            for fmt in [
                "%m/%d/%Y %I:%M:%S %p",  # 12-hour format
                "%m/%d/%Y %H:%M:%S",  # 24-hour format
                "%Y-%m-%d %H:%M:%S",  # ISO-like format
                "%Y-%m-%dT%H:%M:%S",  # ISO format without timezone
                "%Y-%m-%dT%H:%M:%S.%f",  # ISO format with microseconds
            ]:
                try:
                    parsed_dt = datetime.strptime(ps_datetime_str.strip(), fmt)
                    # Assume local time, convert to UTC (naive)
                    return parsed_dt.isoformat()
                except ValueError:
                    continue

            # If none of the formats worked, log and return None
            self.logger.warning(
                _("Could not parse datetime string: %s"), ps_datetime_str
            )
            return None

        except Exception as error:
            self.logger.error(
                _("Error parsing datetime %s: %s"), ps_datetime_str, error
            )
            return None

    def _detect_macos_commercial_antivirus(self) -> Optional[Dict]:
        """
        Detect Microsoft Defender on macOS systems using mdatp CLI.

        Returns:
            dict with commercial antivirus information or None if not detected
        """
        try:
            # Check if mdatp command exists
            which_result = subprocess.run(
                ["which", "mdatp"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )  # nosec B603

            if which_result.returncode != 0:
                self.logger.info(_("Microsoft Defender CLI (mdatp) not found on macOS"))
                return None

            # Get health status from mdatp
            health_cmd = ["mdatp", "health"]

            health_result = subprocess.run(
                health_cmd, capture_output=True, text=True, timeout=10, check=False
            )  # nosec B603

            if health_result.returncode != 0:
                self.logger.error(
                    _("Failed to get Microsoft Defender health status: %s"),
                    health_result.stderr,
                )
                return None

            # Parse the health output (key-value pairs)
            health_data = {}
            for line in health_result.stdout.split("\n"):
                line = line.strip()
                if ":" in line:
                    key, value = line.split(":", 1)
                    key = key.strip()
                    value = value.strip()

                    # Convert boolean strings to actual booleans
                    if value.lower() == "true":
                        value = True
                    elif value.lower() == "false":
                        value = False

                    health_data[key] = value

            # Get version information
            version_cmd = ["mdatp", "version"]
            version_result = subprocess.run(
                version_cmd, capture_output=True, text=True, timeout=5, check=False
            )  # nosec B603

            product_version = None
            if version_result.returncode == 0:
                # Parse version output (usually "app_version: X.Y.Z")
                for line in version_result.stdout.split("\n"):
                    if "app_version" in line.lower():
                        parts = line.split(":", 1)
                        if len(parts) == 2:
                            product_version = parts[1].strip()
                            break

            # Get definitions status
            definitions_cmd = ["mdatp", "definitions", "list"]
            definitions_result = subprocess.run(
                definitions_cmd, capture_output=True, text=True, timeout=5, check=False
            )  # nosec B603

            signature_version = None
            signature_last_updated = None
            if definitions_result.returncode == 0:
                for line in definitions_result.stdout.split("\n"):
                    if "version" in line.lower():
                        parts = line.split(":", 1)
                        if len(parts) == 2:
                            signature_version = parts[1].strip()
                    elif "last_updated" in line.lower() or "updated" in line.lower():
                        parts = line.split(":", 1)
                        if len(parts) == 2:
                            # Try to parse the datetime
                            date_str = parts[1].strip()
                            signature_last_updated = self._parse_macos_datetime(
                                date_str
                            )

            # Extract relevant fields from health data
            realtime_protection = health_data.get("real_time_protection_enabled")
            if realtime_protection is None:
                realtime_protection = health_data.get("realTimeProtectionEnabled")

            healthy = health_data.get("healthy")
            licensed = health_data.get("licensed")

            # Build the antivirus info dict
            antivirus_info = {
                "product_name": "Microsoft Defender for Endpoint",
                "product_version": product_version,
                "service_enabled": healthy,  # If healthy, service is enabled
                "antispyware_enabled": realtime_protection,  # Defender covers both
                "antivirus_enabled": realtime_protection,
                "realtime_protection_enabled": realtime_protection,
                "full_scan_age": None,  # macOS mdatp doesn't expose scan ages easily
                "quick_scan_age": None,
                "full_scan_end_time": None,
                "quick_scan_end_time": None,
                "signature_last_updated": signature_last_updated,
                "signature_version": signature_version,
                "tamper_protection_enabled": None,  # Not directly exposed in mdatp health
            }

            self.logger.info(
                _(
                    "Detected Microsoft Defender for Endpoint on macOS (version: %s, enabled: %s, licensed: %s)"
                ),
                product_version,
                realtime_protection,
                licensed,
            )

            return antivirus_info

        except subprocess.TimeoutExpired:
            self.logger.error(
                _("Timeout while querying Microsoft Defender status on macOS")
            )
            return None
        except Exception as error:
            self.logger.error(
                _("Error detecting Microsoft Defender on macOS: %s"),
                error,
                exc_info=True,
            )
            return None

    def _parse_macos_datetime(self, datetime_str: Optional[str]) -> Optional[str]:
        """
        Parse macOS datetime string and convert to ISO format.

        Args:
            datetime_str: macOS datetime string

        Returns:
            ISO format datetime string or None
        """
        if not datetime_str:
            return None

        try:
            # Try various common macOS date formats
            for fmt in [
                "%Y-%m-%d %H:%M:%S",  # Standard format
                "%Y-%m-%dT%H:%M:%S",  # ISO format
                "%Y-%m-%dT%H:%M:%S.%f",  # ISO with microseconds
                "%a %b %d %H:%M:%S %Y",  # ctime format
                "%Y-%m-%d %H:%M:%S %z",  # With timezone
            ]:
                try:
                    parsed_dt = datetime.strptime(datetime_str.strip(), fmt)
                    return parsed_dt.isoformat()
                except ValueError:
                    continue

            # If parsing failed, try to return as-is if it looks like ISO
            if "T" in datetime_str or "-" in datetime_str:
                return datetime_str.strip()

            self.logger.warning(
                _("Could not parse macOS datetime string: %s"), datetime_str
            )
            return None

        except Exception as error:
            self.logger.error(
                _("Error parsing macOS datetime %s: %s"), datetime_str, error
            )
            return None
