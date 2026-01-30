"""
Windows package collection module for SysManage Agent.

This module handles the collection of available packages from Windows package managers.
"""

import json
import logging
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET  # nosec B405 # Parsing trusted Chocolatey API XML
from typing import Dict, List, Optional

from src.i18n import _
from src.sysmanage_agent.collection.package_collector_base import BasePackageCollector

logger = logging.getLogger(__name__)


def _validate_https_url(url: str) -> str:
    """
    Validate that a URL uses HTTPS scheme and return it.

    This prevents file:// and other dangerous URL schemes.
    Raises ValueError if URL is not HTTPS.
    """
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != "https":
        raise ValueError(f"Only HTTPS URLs are allowed, got: {parsed.scheme}")
    return url


class WindowsPackageCollector(BasePackageCollector):
    """Collects available packages from Windows package managers."""

    def collect_packages(self) -> int:
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
                except Exception as error:
                    logger.error(
                        _("Failed to collect packages from %s: %s"), manager_name, error
                    )

        return total_collected

    def _collect_winget_packages(self) -> int:
        """Collect packages from Windows Package Manager (winget) via REST API."""
        try:
            logger.info(_("Fetching winget catalog via REST API"))

            api_url = "https://api.winget.run/v2/packages"
            packages = self._collect_winget_pages(api_url)

            if packages:
                logger.info(
                    _("Successfully collected %d packages from winget REST API"),
                    len(packages),
                )
                return self._store_packages("winget", packages)

            logger.warning(_("No packages collected from winget REST API"))
            return 0

        except Exception as error:
            logger.error(_("Error collecting winget packages via REST API: %s"), error)
            return 0

    def _collect_winget_pages(self, api_url: str) -> List[Dict[str, str]]:
        """Collect all pages of winget packages from the REST API.

        Iterates through paginated API responses until all packages are fetched
        or an error occurs.
        """
        packages = []
        page = 1

        while True:
            try:
                url = f"{api_url}?page={page}&limit=100"
                data = self._collect_winget_api_page(url)

                if not data or "Packages" not in data:
                    break

                page_packages = data.get("Packages", [])
                if not page_packages:
                    break

                packages.extend(self._parse_winget_api_packages(page_packages))

                # Check if there are more pages
                total = data.get("Total", 0)
                if 0 < total <= len(packages):
                    break

                page += 1

            except Exception as error:
                logger.error(
                    _(
                        "Error fetching winget page %d (collected %d packages so far): %s"
                    ),
                    page,
                    len(packages),
                    str(error),
                )
                break

        return packages

    def _collect_winget_api_page(self, url: str) -> dict:
        """Fetch a single page of winget packages from the REST API.

        Validates the URL scheme, makes the HTTP request, and returns the
        parsed JSON response.
        """
        validated_url = _validate_https_url(url)
        req = urllib.request.Request(validated_url)  # nosec B310
        req.add_header("User-Agent", "SysManage-Agent/1.0")

        # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected
        with urllib.request.urlopen(req, timeout=30) as response:  # nosec B310
            return json.loads(response.read().decode("utf-8"))

    def _parse_winget_api_packages(
        self, page_packages: List[dict]
    ) -> List[Dict[str, str]]:
        """Parse a list of package entries from the winget API response.

        Extracts the package ID, name, and version from each entry in the
        API response format.
        """
        packages = []
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
        return packages

    def _collect_chocolatey_packages(self) -> int:
        """Collect packages from Chocolatey community repository API."""
        try:
            logger.info(_("Fetching Chocolatey catalog via community repository API"))

            api_url = "https://community.chocolatey.org/api/v2/Packages()"
            packages = self._collect_chocolatey_pages(api_url)

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

        except Exception as error:
            logger.error(_("Error collecting Chocolatey packages via API: %s"), error)
            return 0

    def _collect_chocolatey_pages(self, api_url: str) -> List[Dict[str, str]]:
        """Collect all pages of Chocolatey packages from the OData API.

        Iterates through paginated OData responses until all packages are
        fetched or an error occurs.
        """
        packages = []
        skip = 0
        top = 100

        while True:
            try:
                url = f"{api_url}?$skip={skip}&$top={top}&$orderby=Id"
                xml_data = self._collect_chocolatey_api_page(url)

                entries = self._parse_chocolatey_xml_entries(xml_data)
                if not entries:
                    break

                packages.extend(entries)
                skip += len(entries)

            except Exception as error:
                logger.warning(_("Error fetching page at skip %d: %s"), skip, error)
                break

        return packages

    def _collect_chocolatey_api_page(self, url: str) -> str:
        """Fetch a single page of Chocolatey packages from the OData API.

        Validates the URL scheme, makes the HTTP request, and returns the
        raw XML response as a string.
        """
        validated_url = _validate_https_url(url)
        req = urllib.request.Request(validated_url)  # nosec B310
        req.add_header("User-Agent", "SysManage-Agent/1.0")

        # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected
        with urllib.request.urlopen(req, timeout=30) as response:  # nosec B310
            return response.read().decode("utf-8")

    def _parse_chocolatey_xml_entries(self, xml_data: str) -> List[Dict[str, str]]:
        """Parse Chocolatey OData XML response into a list of package dicts.

        Extracts package name and version from the Atom feed entries using
        the OData namespace conventions.
        """
        root = ET.fromstring(xml_data)  # nosec B314 # Trusted Chocolatey API XML

        namespace = {
            "atom": "http://www.w3.org/2005/Atom",  # NOSONAR - XML namespace URI, not network connection
            "d": "http://schemas.microsoft.com/ado/2007/08/dataservices",  # NOSONAR - XML namespace URI
            "m": "http://schemas.microsoft.com/ado/2007/08/dataservices/metadata",  # NOSONAR - XML namespace URI
        }

        entries = root.findall("atom:entry", namespace)
        if not entries:
            return []

        packages = []
        for entry in entries:
            parsed = self._parse_chocolatey_entry(entry, namespace)
            if parsed is not None:
                packages.append(parsed)

        return packages

    def _parse_chocolatey_entry(
        self, entry: ET.Element, namespace: dict
    ) -> Optional[Dict[str, str]]:
        """Parse a single Atom entry element into a package dict.

        Extracts the package title and version from the entry's XML elements.
        Returns a package dict, or None if required fields are missing.
        """
        title_elem = entry.find("atom:title", namespace)
        if title_elem is None or not title_elem.text:
            return None

        props = entry.find("m:properties", namespace)
        if props is None:
            return None

        version_elem = props.find("d:Version", namespace)
        if version_elem is None or not version_elem.text:
            return None

        return {
            "name": title_elem.text,
            "version": version_elem.text,
            "description": "",
        }

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

            if self._detect_chocolatey_noise_line(line):
                continue

            parsed = self._parse_chocolatey_package_line(line)
            if parsed is not None:
                packages.append(parsed)

        return packages

    def _detect_chocolatey_noise_line(self, line: str) -> bool:
        """Detect whether a line is a Chocolatey header, footer, or noise line.

        Returns True if the line should be skipped (contains known non-package text).
        """
        skip_keywords = [
            "chocolatey",
            "packages found",
            "validating",
            "loading",
            "page",
            "http",
            "features?",
            "did you",
        ]
        return any(skip in line.lower() for skip in skip_keywords)

    def _parse_chocolatey_package_line(self, line: str) -> Optional[Dict[str, str]]:
        """Parse a single Chocolatey package line in 'name version' format.

        Validates that the package name is not a common English word that
        would indicate a non-package line. Returns a package dict, or None
        if the line is not a valid package entry.
        """
        invalid_names = {"the", "did", "you", "page", "this"}
        parts = line.split()
        if len(parts) >= 2:
            name = parts[0]
            version = parts[1]

            if name.lower() in invalid_names:
                return None

            return {"name": name, "version": version, "description": ""}

        return None
