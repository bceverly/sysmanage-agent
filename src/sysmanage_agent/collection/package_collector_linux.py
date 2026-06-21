"""
Linux package collection module for SysManage Agent.

This module handles the collection of available packages from Linux package managers.
"""

import io
import logging
import subprocess  # nosec B404
from typing import Any, Dict, Iterable, Iterator, List, Optional

from src.i18n import _
from src.sysmanage_agent.collection.package_collector_base import BasePackageCollector

logger = logging.getLogger(__name__)


class LinuxPackageCollector(BasePackageCollector):
    """Collects available packages from Linux package managers."""

    def collect_packages(self) -> int:
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

        # On RHEL/Fedora 8+ ``yum`` is just a symlink to ``dnf`` and
        # ``yum list available`` returns the same set of packages as
        # ``dnf list available``.  Running both costs ~90s of subprocess
        # blocking on a fresh OL9 host (1.5 min × 2) for zero new data
        # and starves the asyncio heartbeat long enough for the server
        # to kill the WebSocket with a 1011 keepalive timeout.  Skip
        # ``yum`` whenever ``dnf`` is also present.
        if self._is_package_manager_available("dnf"):
            managers = [(n, f) for (n, f) in managers if n != "yum"]
            logger.info(
                _(
                    "Skipping yum collection on host with dnf available "
                    "(yum is a dnf wrapper on RHEL/Fedora 8+)"
                )
            )

        for manager_name, collector_func in managers:
            if self._is_package_manager_available(manager_name):
                try:
                    count = collector_func()
                    total_collected += count
                    logger.info(_("Collected %d packages from %s"), count, manager_name)
                except Exception as error:
                    logger.exception(
                        _("Failed to collect packages from %s: %s"), manager_name, error
                    )

        return total_collected

    def _collect_apt_packages(self) -> int:
        """Collect packages from APT (Ubuntu/Debian).

        ``apt-cache dumpavail`` is the ENTIRE available-package universe with
        descriptions — hundreds of MB of text on Ubuntu (universe/multiverse).
        We STREAM it: parse the subprocess output stanza-by-stanza and store in
        batches, so peak memory stays flat instead of holding the whole dump +
        parsed list + ORM objects at once (which OOM-killed the agent on small
        hosts).
        """
        try:
            # Update package lists first
            subprocess.run(  # nosec B603, B607
                ["apt", "update"], capture_output=True, timeout=300, check=False
            )

            with subprocess.Popen(  # nosec B603, B607
                ["apt-cache", "dumpavail"],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
            ) as proc:
                # The generator pulls lines lazily from proc.stdout, so the
                # dump is never fully buffered in the agent.
                count = self._store_packages_streaming(
                    "apt", self._iter_apt_dumpavail(proc.stdout)
                )
                try:
                    proc.wait(timeout=600)
                except subprocess.TimeoutExpired:
                    proc.kill()
                if proc.returncode not in (0, None):
                    logger.error(_("Failed to get APT package information"))

            return count

        except Exception as error:  # pylint: disable=broad-exception-caught
            logger.exception(_("Error collecting APT packages: %s"), error)
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

        except Exception as error:
            logger.exception(_("Error collecting YUM packages: %s"), error)
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

        except Exception as error:
            logger.exception(_("Error collecting DNF packages: %s"), error)
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

        except Exception as error:
            logger.exception(_("Error collecting Zypper packages: %s"), error)
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

        except Exception as error:
            logger.exception(_("Error collecting Pacman packages: %s"), error)
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

        except Exception as error:
            logger.exception(_("Error collecting Snap packages: %s"), error)
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

        except Exception as error:
            logger.exception(_("Error collecting Flatpak packages: %s"), error)
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

    def _iter_apt_dumpavail(
        self, line_stream: Iterable[str]
    ) -> Iterator[Dict[str, str]]:
        """Yield ``{name, version, description}`` dicts from an apt-cache
        dumpavail line stream, one stanza at a time.

        Accepts any iterable of lines — a live ``Popen.stdout`` or an in-memory
        ``io.StringIO`` — so the multi-hundred-MB dump never has to live in
        memory all at once.  Description fields span continuation lines that
        start with a space; they're joined with spaces (matching the previous
        list-based parser).
        """
        stanza: Dict[str, Any] = {}

        for raw in line_stream:
            line = raw.rstrip("\n")
            if not line.strip():
                # Stanza boundary — emit the package we just finished.
                record = self._dumpavail_record(stanza)
                if record is not None:
                    yield record
                stanza = {}
                continue
            self._dumpavail_consume_line(line, stanza)

        # Final stanza (dumpavail may not end with a blank line).
        record = self._dumpavail_record(stanza)
        if record is not None:
            yield record

    @staticmethod
    def _dumpavail_record(stanza: Dict[str, Any]) -> Optional[Dict[str, str]]:
        """Build a package dict from an accumulated stanza, or None if it lacks
        a name/version (a partial or non-package stanza)."""
        name = stanza.get("name")
        version = stanza.get("version")
        if name and version:
            return {
                "name": name,
                "version": version,
                "description": " ".join(stanza.get("description_parts", [])).strip(),
            }
        return None

    @staticmethod
    def _dumpavail_consume_line(line: str, stanza: Dict[str, Any]) -> None:
        """Fold one non-blank dumpavail line into the in-progress stanza dict
        (a continuation of a Description, or a ``Field: value`` line)."""
        if stanza.get("in_description") and line[:1] in (" ", "\t"):
            cont = line.strip()
            if cont:
                stanza.setdefault("description_parts", []).append(cont)
            return
        if ":" not in line:
            return
        field, value = line.split(":", 1)
        field = field.strip().lower()
        value = value.strip()
        stanza["in_description"] = False
        if field == "package":
            stanza["name"] = value
        elif field == "version":
            stanza["version"] = value
        elif field == "description":
            stanza["description_parts"] = [value]
            stanza["in_description"] = True

    def _parse_apt_dumpavail_output(self, output: str) -> List[Dict[str, str]]:
        """Parse a full apt-cache dumpavail string into package dicts.

        Thin wrapper over the streaming :meth:`_iter_apt_dumpavail` — kept for
        callers/tests that already hold the whole output as a string.
        """
        return list(self._iter_apt_dumpavail(io.StringIO(output)))

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
                current_package = self._parse_pacman_package_line(line)

        if current_package:
            packages.append(current_package)

        return packages

    def _parse_pacman_package_line(self, line: str) -> Dict[str, str]:
        """Parse a single pacman package header line.

        Expects format: 'repo/package version [installed]'.
        Returns a package dict with name, version, and empty description,
        or an empty dict if the line cannot be parsed.
        """
        parts = line.split()
        if len(parts) >= 2:
            name = parts[0].split("/")[-1]
            version = parts[1]
            return {"name": name, "version": version, "description": ""}
        return {}

    def _parse_snap_output(self, output: str) -> List[Dict[str, str]]:
        """Parse Snap package list output from 'snap find %'."""
        packages = []

        for line in output.splitlines():
            if line.startswith("Name") or not line.strip():
                continue

            parsed = self._parse_snap_line(line)
            if parsed is not None:
                packages.append(parsed)

        return packages

    def _parse_snap_line(self, line: str) -> Optional[Dict[str, str]]:
        """Parse a single line from 'snap find %' output into a package dict.

        Expects fixed-width columns: Name (25 chars), Version, Publisher, Notes, Summary.
        Returns a package dict with name, version, and description, or None if
        the line cannot be parsed.
        """
        try:
            if len(line) < 30:
                return None

            # Extract name (first column, trim whitespace)
            name = line[:25].strip()
            if not name:
                return None

            # Extract version (second column, starts around position 25)
            version_line = line[25:]
            version_match = version_line.split()[0] if version_line.split() else ""

            # Find summary - it's the last column after publisher and notes
            parts = line.split()
            summary = " ".join(parts[4:]) if len(parts) >= 5 else ""

            if name and version_match:
                return {"name": name, "version": version_match, "description": summary}

            return None

        except Exception:  # nosec B112
            # If parsing fails for a line, skip it and continue processing
            # This is safe because we're parsing text output that may have malformed lines
            return None

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
