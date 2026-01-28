"""
WSL (Windows Subsystem for Linux) listing methods.

Extracted from child_host_listing.py to reduce module size.
"""

import re
import subprocess  # nosec B404 # Required for system command execution
from typing import Any, Dict, List, Optional

# Windows registry access for WSL GUID retrieval
try:
    import winreg
except ImportError:
    winreg = None  # type: ignore[misc, assignment]


class WSLListing:
    """Methods to list and manage WSL instances."""

    def __init__(self, logger):
        """Initialize with logger."""
        self.logger = logger

    def list_wsl_instances(self) -> List[Dict[str, Any]]:
        """
        List all WSL instances on Windows.

        Returns:
            List of WSL instance information dicts
        """
        instances = []

        try:
            # Get list of WSL distributions using wsl -l -v
            result = subprocess.run(  # nosec B603 B607
                ["wsl", "-l", "-v"],
                capture_output=True,
                timeout=30,
                check=False,
                creationflags=(
                    subprocess.CREATE_NO_WINDOW
                    if hasattr(subprocess, "CREATE_NO_WINDOW")
                    else 0
                ),
            )

            if result.returncode != 0:
                self.logger.warning("WSL list command failed: %s", result.stderr)
                return instances

            output = self._decode_wsl_output(result.stdout)

            # Check for "no distributions" message
            if "no installed distributions" in output.lower():
                self.logger.info("No WSL distributions installed")
                return instances

            # Parse output lines (skip header)
            lines = output.strip().split("\n")
            if len(lines) < 2:
                return instances

            instances = self._parse_wsl_output_lines(lines[1:])

            self.logger.info("Found %d WSL instances", len(instances))

        except subprocess.TimeoutExpired:
            self.logger.warning("WSL list command timed out")
        except FileNotFoundError:
            self.logger.debug("WSL command not found")
        except Exception as error:
            self.logger.error("Error listing WSL instances: %s", error)

        return instances

    def _decode_wsl_output(self, stdout: bytes) -> str:
        """Decode WSL command output, trying multiple encodings."""
        # Parse the output - WSL outputs UTF-16 with BOM on Windows
        try:
            output = stdout.decode("utf-16-le").strip()
        except UnicodeDecodeError:
            try:
                output = stdout.decode("utf-8").strip()
            except UnicodeDecodeError:
                output = stdout.decode("latin-1").strip()

        # Remove null characters that Windows sometimes adds
        return output.replace("\x00", "")

    def _parse_wsl_output_lines(self, lines: List[str]) -> List[Dict[str, Any]]:
        """Parse WSL output lines into instance dicts."""
        instances = []
        for line in lines:
            line = line.strip()
            if not line:
                continue

            instance = self._parse_single_wsl_line(line)
            if instance:
                instances.append(instance)

        return instances

    def _parse_single_wsl_line(self, line: str) -> Optional[Dict[str, Any]]:
        """Parse a single WSL output line into an instance dict."""
        # Parse line: "* Ubuntu    Running  2" or "  Debian   Stopped  2"
        # The asterisk indicates the default distribution
        is_default = line.startswith("*")
        if is_default:
            line = line[1:].strip()

        # Split by whitespace
        parts = line.split()
        if len(parts) < 2:
            return None

        name = parts[0]
        status = parts[1].lower() if len(parts) > 1 else "unknown"
        version = parts[2] if len(parts) > 2 else "2"

        mapped_status = self._map_wsl_status(status)

        # Get hostname from inside the WSL instance if it's running
        hostname = None
        if mapped_status == "running":
            hostname = self._get_wsl_hostname(name)

        # Get unique GUID for this WSL instance from registry
        wsl_guid = self._get_wsl_guid(name)

        return {
            "child_type": "wsl",
            "child_name": name,
            "status": mapped_status,
            "is_default": is_default,
            "wsl_version": version,
            "distribution": self._parse_wsl_distribution(name),
            "hostname": hostname,
            "wsl_guid": wsl_guid,
        }

    def _map_wsl_status(self, status: str) -> str:
        """Map WSL status string to our status values."""
        if status == "running":
            return "running"
        if status == "stopped":
            return "stopped"
        return status

    def _get_wsl_guid(self, distribution_name: str) -> Optional[str]:
        """
        Get the unique GUID for a WSL distribution from the Windows registry.

        WSL assigns a unique GUID to each distribution instance. This GUID changes
        when a distribution is deleted and recreated, even with the same name.
        This allows us to distinguish between different instances with the same name.

        Args:
            distribution_name: WSL distribution name (e.g., "Ubuntu-24.04")

        Returns:
            GUID string (e.g., "0283592d-be56-40d4-b935-3dc18c3aa007") or None
        """
        if winreg is None:
            return None

        try:
            lxss_key_path = r"Software\Microsoft\Windows\CurrentVersion\Lxss"
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, lxss_key_path) as lxss_key:
                # Enumerate all subkeys (each is a GUID)
                index = 0
                while True:
                    try:
                        guid = winreg.EnumKey(lxss_key, index)
                        # Open the subkey to get the DistributionName
                        with winreg.OpenKey(lxss_key, guid) as dist_key:
                            try:
                                dist_name, _ = winreg.QueryValueEx(
                                    dist_key, "DistributionName"
                                )
                                if dist_name == distribution_name:
                                    # Remove curly braces if present
                                    return guid.strip("{}")
                            except FileNotFoundError:
                                pass  # DistributionName not found in this key
                        index += 1
                    except OSError:
                        break  # No more subkeys
        except FileNotFoundError:
            self.logger.debug("WSL registry key not found")
        except Exception as error:
            self.logger.debug(
                "Error reading WSL GUID for %s: %s", distribution_name, error
            )

        return None

    def _get_wsl_hostname(self, distribution: str) -> Optional[str]:
        """
        Get the FQDN hostname from inside a running WSL instance.

        Tries multiple methods in order:
        1. Read hostname from /etc/wsl.conf [network] section (most reliable for our setup)
        2. Read from /etc/hostname file (requires FQDN with '.')
        3. Run hostname -f command
        4. Fall back to hostname command
        5. Fall back to /etc/hostname (any hostname)

        Args:
            distribution: WSL distribution name

        Returns:
            FQDN hostname string or None if unable to retrieve
        """
        try:
            # Try methods in order of preference
            hostname = self._try_wsl_conf_hostname(distribution)
            if hostname:
                return hostname

            hostname = self._try_etc_hostname_fqdn(distribution)
            if hostname:
                return hostname

            hostname = self._try_hostname_fqdn_command(distribution)
            if hostname:
                return hostname

            hostname = self._try_hostname_command(distribution)
            if hostname:
                return hostname

            hostname = self._try_etc_hostname_any(distribution)
            if hostname:
                return hostname

        except Exception as error:
            self.logger.debug("Error getting hostname for %s: %s", distribution, error)

        return None

    def _get_wsl_creationflags(self) -> int:
        """Get creationflags for WSL subprocess calls."""
        return (
            subprocess.CREATE_NO_WINDOW
            if hasattr(subprocess, "CREATE_NO_WINDOW")
            else 0
        )

    def _try_wsl_conf_hostname(self, distribution: str) -> Optional[str]:
        """Try reading hostname from /etc/wsl.conf."""
        result = subprocess.run(  # nosec B603 B607
            [
                "wsl",
                "-d",
                distribution,
                "--",
                "sh",
                "-c",
                "grep -E '^hostname=' /etc/wsl.conf 2>/dev/null | cut -d= -f2",
            ],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
            creationflags=self._get_wsl_creationflags(),
        )
        if result.returncode == 0:
            hostname = result.stdout.strip()
            if hostname and hostname != "localhost" and "." in hostname:
                return hostname
        return None

    def _try_etc_hostname_fqdn(self, distribution: str) -> Optional[str]:
        """Try reading FQDN from /etc/hostname."""
        result = subprocess.run(  # nosec B603 B607
            ["wsl", "-d", distribution, "--", "cat", "/etc/hostname"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
            creationflags=self._get_wsl_creationflags(),
        )
        if result.returncode == 0:
            hostname = result.stdout.strip()
            if hostname and hostname != "localhost" and "." in hostname:
                return hostname
        return None

    def _try_hostname_fqdn_command(self, distribution: str) -> Optional[str]:
        """Try getting FQDN using hostname -f command."""
        result = subprocess.run(  # nosec B603 B607
            ["wsl", "-d", distribution, "--", "hostname", "-f"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
            creationflags=self._get_wsl_creationflags(),
        )
        if result.returncode == 0:
            hostname = result.stdout.strip()
            if hostname and hostname != "localhost":
                return hostname
        return None

    def _try_hostname_command(self, distribution: str) -> Optional[str]:
        """Try getting hostname using hostname command."""
        result = subprocess.run(  # nosec B603 B607
            ["wsl", "-d", distribution, "--", "hostname"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
            creationflags=self._get_wsl_creationflags(),
        )
        if result.returncode == 0:
            hostname = result.stdout.strip()
            if hostname:
                return hostname
        return None

    def _try_etc_hostname_any(self, distribution: str) -> Optional[str]:
        """Try reading any hostname from /etc/hostname (fallback)."""
        result = subprocess.run(  # nosec B603 B607
            ["wsl", "-d", distribution, "--", "cat", "/etc/hostname"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
            creationflags=self._get_wsl_creationflags(),
        )
        if result.returncode == 0:
            hostname = result.stdout.strip()
            if hostname:
                return hostname
        return None

    def _parse_wsl_distribution(self, name: str) -> Dict[str, Optional[str]]:
        """
        Parse distribution info from WSL instance name.

        Args:
            name: WSL distribution name (e.g., "Ubuntu-24.04")

        Returns:
            Dict with distribution_name and distribution_version
        """
        # Common WSL distribution name patterns
        distribution_patterns = {
            "Ubuntu": ("Ubuntu", None),
            "Ubuntu-24.04": ("Ubuntu", "24.04"),
            "Ubuntu-22.04": ("Ubuntu", "22.04"),
            "Ubuntu-20.04": ("Ubuntu", "20.04"),
            "Ubuntu-18.04": ("Ubuntu", "18.04"),
            "Debian": ("Debian", None),
            "kali-linux": ("Kali Linux", None),
            "openSUSE-Tumbleweed": ("openSUSE", "Tumbleweed"),
            "openSUSE-Leap-15": ("openSUSE", "15"),
            "SLES-15": ("SLES", "15"),
            "Fedora": ("Fedora", None),
            "AlmaLinux-9": ("AlmaLinux", "9"),
            "RockyLinux-9": ("Rocky Linux", "9"),
        }

        # Try exact match first
        if name in distribution_patterns:
            dist_name, dist_version = distribution_patterns[name]
            return {
                "distribution_name": dist_name,
                "distribution_version": dist_version,
            }

        # Try partial match
        name_lower = name.lower()
        for pattern, (dist_name, dist_version) in distribution_patterns.items():
            if pattern.lower() in name_lower:
                # Try to extract version from name if not in pattern
                if dist_version is None:
                    # Look for version pattern like -XX.XX or -X
                    version_match = re.search(r"-(\d+\.?\d*)", name)
                    if version_match:
                        dist_version = version_match.group(1)
                return {
                    "distribution_name": dist_name,
                    "distribution_version": dist_version,
                }

        # Unknown distribution
        return {
            "distribution_name": name,
            "distribution_version": None,
        }
