"""
Windows package collection module for SysManage Agent.

This module handles the collection of available packages from Windows package managers.
"""

import json
import logging
import urllib.request
import xml.etree.ElementTree as ET  # nosec B405 # Parsing trusted Chocolatey API XML
from typing import Dict, List

from src.i18n import _
from src.sysmanage_agent.collection.package_collector_base import BasePackageCollector

logger = logging.getLogger(__name__)


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

                    # Validate URL scheme for security
                    if not url.startswith("https://"):
                        raise ValueError("Only HTTPS URLs are allowed")

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

                    # Validate URL scheme for security
                    if not url.startswith("https://"):
                        raise ValueError("Only HTTPS URLs are allowed")

                    req = urllib.request.Request(url)  # nosec B310
                    req.add_header("User-Agent", "SysManage-Agent/1.0")

                    with urllib.request.urlopen(
                        req, timeout=30
                    ) as response:  # nosec B310
                        # Parse XML response
                        data = response.read().decode("utf-8")
                        root = ET.fromstring(
                            data
                        )  # nosec B314 # Trusted Chocolatey API XML

                        # Define namespaces
                        namespace = {
                            "atom": "http://www.w3.org/2005/Atom",
                            "d": "http://schemas.microsoft.com/ado/2007/08/dataservices",
                            "m": "http://schemas.microsoft.com/ado/2007/08/dataservices/metadata",
                        }

                        # Extract packages from feed
                        entries = root.findall("atom:entry", namespace)
                        if not entries:
                            break

                        for entry in entries:
                            # Get package ID from title element
                            title_elem = entry.find("atom:title", namespace)
                            if title_elem is None or not title_elem.text:
                                continue

                            # Get version from properties
                            props = entry.find("m:properties", namespace)
                            if props is None:
                                continue

                            version_elem = props.find("d:Version", namespace)
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

                except Exception as error:
                    logger.warning(_("Error fetching page at skip %d: %s"), skip, error)
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

        except Exception as error:
            logger.error(_("Error collecting Chocolatey packages via API: %s"), error)
            return 0

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
