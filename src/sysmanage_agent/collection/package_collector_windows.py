# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""
Windows package collection module for SysManage Agent.

This module handles the collection of available packages from Windows package managers.
"""

import json
import logging
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, Dict, List, Optional

import defusedxml.ElementTree as DET  # secure parser for fromstring()

from src.database.models import AvailablePackage
from src.i18n import _
from src.sysmanage_agent.collection.package_collector_base import BasePackageCollector
from src.sysmanage_agent.core.schedule_jitter import jittered

if TYPE_CHECKING:
    # Type-only import -- only mypy / pyright evaluates this block;
    # the runtime interpreter skips it entirely (TYPE_CHECKING is
    # always False at runtime).  Bandit's B405 rule does a textual
    # match on the import statement without flow analysis, so the
    # ``# nosec B405`` annotation documents that no actual XML parse
    # ever uses this import -- the runtime parser is defusedxml
    # (``DET.fromstring`` above).
    import xml.etree.ElementTree as ET  # nosec B405  # noqa: N811  # nosemgrep: python.lang.security.use-defused-xml.use-defused-xml

logger = logging.getLogger(__name__)

# Phase 22.1: every Windows agent pages through the PUBLIC winget and
# Chocolatey catalogs -- about 360 + 100 requests (winget answers 12 packages a
# page whatever the limit asks for).  Behind one NAT a site's agents are one
# client to those services, so the fetch is paced, honors a rate limit, and a
# catalog fetched within PUBLIC_CATALOG_MAX_AGE is reused (the server asks
# for the catalog again on its own schedule; the catalog does not change by
# the hour).  A fetch that does not finish is a failure: the previous catalog
# is kept, never replaced by part of one.
PUBLIC_CATALOG_MAX_AGE = timedelta(hours=24)
PAGE_DELAY_SECONDS = 0.5  # pause between pages, +/-40%
PAGE_DELAY_SPREAD = 0.4
RATE_LIMIT_STATUSES = (429, 503)
MAX_ATTEMPTS = 4  # per page, rate-limit waits included
MAX_RETRY_WAIT_SECONDS = 300
MAX_PAGES = 2000  # a runaway pager (no Total, never an empty page) stops here


class CatalogIncomplete(Exception):
    """A public catalog could not be fetched in full."""


def _retry_after_seconds(error: urllib.error.HTTPError, attempt: int) -> float:
    """How long to wait after a rate-limit answer: the server's Retry-After
    (seconds) when it gives one, else a jittered backoff; never more than
    MAX_RETRY_WAIT_SECONDS."""
    header = error.headers.get("Retry-After") if error.headers else None
    try:
        wait = float(header) if header is not None else None
    except ValueError:
        wait = None  # an HTTP date: back off instead
    if wait is None:
        wait = jittered(15 * (2**attempt), 0.25)
    return max(1.0, min(wait, MAX_RETRY_WAIT_SECONDS))


def _fetch_public(url: str) -> bytes:
    """GET one page of a public catalog: HTTPS only, retried after a rate
    limit (429/503) or a dropped connection; raises CatalogIncomplete when
    the page cannot be had."""
    validated_url = _validate_https_url(url)
    for attempt in range(MAX_ATTEMPTS):
        req = urllib.request.Request(validated_url)  # nosec B310
        req.add_header("User-Agent", "SysManage-Agent/1.0")
        try:
            # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected
            with urllib.request.urlopen(req, timeout=30) as response:  # nosec B310
                return response.read()
        except urllib.error.HTTPError as error:
            error.close()  # it holds the response; release it before waiting
            if error.code not in RATE_LIMIT_STATUSES or attempt == MAX_ATTEMPTS - 1:
                raise CatalogIncomplete(f"HTTP {error.code} for {url}") from error
            wait = _retry_after_seconds(error, attempt)
            logger.warning(
                "Catalog server answered HTTP %d; waiting %.0f s before retrying",
                error.code,
                wait,
            )
            time.sleep(wait)
        except (urllib.error.URLError, OSError) as error:
            if attempt == MAX_ATTEMPTS - 1:
                raise CatalogIncomplete(f"{error} for {url}") from error
            time.sleep(5 * (attempt + 1))
    raise CatalogIncomplete(f"no answer for {url}")  # pragma: no cover


def _pause_between_pages() -> None:
    time.sleep(jittered(PAGE_DELAY_SECONDS, PAGE_DELAY_SPREAD))


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
                    logger.info("Collected %d packages from %s", count, manager_name)
                except Exception as error:
                    logger.exception(
                        _("Failed to collect packages from %s: %s"), manager_name, error
                    )

        return total_collected

    def _catalog_age(self, manager: str) -> Optional[timedelta]:
        """How old the stored catalog for ``manager`` is; None if there is
        none (or it cannot be read -- then it is fetched)."""
        try:
            with self.db_manager.get_session() as session:
                newest = (
                    session.query(AvailablePackage.collection_date)
                    .filter(AvailablePackage.package_manager == manager)
                    .order_by(AvailablePackage.collection_date.desc())
                    .first()
                )
        except Exception as error:  # pylint: disable=broad-exception-caught
            logger.warning("Could not read the stored %s catalog: %s", manager, error)
            return None
        if not newest or newest[0] is None:
            return None
        collected = newest[0]
        if collected.tzinfo is None:
            collected = collected.replace(tzinfo=timezone.utc)
        return datetime.now(timezone.utc) - collected

    def _collect_public_catalog(
        self, manager: str, fetch, error_message: str, empty_message: str
    ) -> int:
        """Fetch and store one public catalog -- unless a fresh one is
        stored, or the fetch does not finish (then the stored one is kept).
        ``error_message`` (one ``%s``) and ``empty_message`` are translated."""
        age = self._catalog_age(manager)
        if age is not None and age < PUBLIC_CATALOG_MAX_AGE:
            kept = len(self.get_packages_for_manager(manager))
            logger.info(
                "%s catalog fetched %.1f hours ago; reusing its %d packages",
                manager,
                age.total_seconds() / 3600,
                kept,
            )
            return kept
        try:
            packages = fetch()
        except CatalogIncomplete as error:
            logger.warning(error_message, error)
            logger.info("Keeping the previous %s catalog", manager)
            return 0
        if not packages:
            logger.warning(empty_message)
            return 0
        logger.info("Collected %d packages from the %s catalog", len(packages), manager)
        return self._store_packages(manager, packages)

    def _collect_winget_packages(self) -> int:
        """Collect packages from Windows Package Manager (winget) via REST API."""
        return self._collect_public_catalog(
            "winget",
            lambda: self._collect_winget_pages("https://api.winget.run/v2/packages"),
            _("Error collecting winget packages via REST API: %s"),
            _("No packages collected from winget REST API"),
        )

    def _collect_winget_pages(self, api_url: str) -> List[Dict[str, str]]:
        """Every page of the winget catalog, paced; raises CatalogIncomplete
        if any page cannot be fetched or read."""
        packages: List[Dict[str, str]] = []
        for page in range(1, MAX_PAGES + 1):
            if page > 1:
                _pause_between_pages()
            data = self._collect_winget_api_page(f"{api_url}?page={page}&limit=100")
            page_packages = data.get("Packages") if isinstance(data, dict) else None
            if not page_packages:
                return packages
            packages.extend(self._parse_winget_api_packages(page_packages))
            total = data.get("Total", 0)
            if 0 < total <= len(packages):
                return packages
        raise CatalogIncomplete(f"winget catalog longer than {MAX_PAGES} pages")

    def _collect_winget_api_page(self, url: str) -> dict:
        """One page of the winget REST API, parsed."""
        try:
            return json.loads(_fetch_public(url).decode("utf-8"))
        except ValueError as error:
            raise CatalogIncomplete(f"unreadable winget page: {error}") from error

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
        """Collect packages from the Chocolatey community repository API."""
        return self._collect_public_catalog(
            "chocolatey",
            lambda: self._collect_chocolatey_pages(
                "https://community.chocolatey.org/api/v2/Packages()"
            ),
            _("Error collecting Chocolatey packages via API: %s"),
            _("No packages collected from Chocolatey community repository"),
        )

    def _collect_chocolatey_pages(self, api_url: str) -> List[Dict[str, str]]:
        """Every page of the Chocolatey OData feed, paced; raises
        CatalogIncomplete if any page cannot be fetched or read."""
        packages: List[Dict[str, str]] = []
        top = 100
        for page in range(MAX_PAGES):
            if page:
                _pause_between_pages()
            url = f"{api_url}?$skip={len(packages)}&$top={top}&$orderby=Id"
            try:
                entries = self._parse_chocolatey_xml_entries(
                    self._collect_chocolatey_api_page(url)
                )
            except DET.ParseError as error:
                raise CatalogIncomplete(
                    f"unreadable Chocolatey page: {error}"
                ) from error
            if not entries:
                return packages
            packages.extend(entries)
        raise CatalogIncomplete(f"Chocolatey catalog longer than {MAX_PAGES} pages")

    def _collect_chocolatey_api_page(self, url: str) -> str:
        """One page of the Chocolatey OData API, as XML text."""
        return _fetch_public(url).decode("utf-8")

    def _parse_chocolatey_xml_entries(self, xml_data: str) -> List[Dict[str, str]]:
        """Parse Chocolatey OData XML response into a list of package dicts.

        Extracts package name and version from the Atom feed entries using
        the OData namespace conventions.
        """
        # Phase 11 hardening -- parse via defusedxml so XXE / billion-laughs
        # in a hijacked Chocolatey response can't escalate.  ``ET`` is
        # only kept around for the ``ET.Element`` type annotation below.
        root = DET.fromstring(xml_data)

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
        self, entry: "ET.Element", namespace: dict
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
