#!/usr/bin/env python3
# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""
Linux Software Inventory Collection Module

Handles software inventory collection for Linux systems supporting multiple
package managers: apt/dpkg, snap, flatpak, yum, dnf, pacman, zypper, portage, apk.
"""

import logging
import subprocess  # nosec B404
from typing import List

from src.i18n import _
from src.sysmanage_agent.collection.software_inventory_base import (
    SoftwareInventoryCollectorBase,
)

logger = logging.getLogger(__name__)

# Container runtimes print "<none>" for a dangling/untagged repository, tag,
# or digest (e.g. `podman images` on a locally-built or pruned image).
_OCI_NONE = "<none>"


APK_INSTALLED_DB = "/lib/apk/db/installed"


def rpm_source_name(source_rpm: str):
    """``openssl`` from ``openssl-3.0.7-27.el9.src.rpm``; None for none."""
    text = (source_rpm or "").strip()
    if not text or text == "(none)" or not text.endswith(".rpm"):
        return None
    parts = text.rsplit("-", 2)
    return parts[0] if len(parts) == 3 else None


def rpm_sources() -> dict:
    """{package: source package} from rpm's database (``rpm -qa``)."""
    try:
        result = subprocess.run(  # nosec B603, B607
            ["rpm", "-qa", "--queryformat", "%{NAME}\t%{SOURCERPM}\n"],
            capture_output=True, text=True, timeout=60, check=False,
        )  # fmt: skip
    except (OSError, subprocess.SubprocessError):
        return {}
    found = {}
    for line in result.stdout.splitlines() if result.returncode == 0 else []:
        name, _tab, source_rpm = line.partition("\t")
        source = rpm_source_name(source_rpm)
        if name and source:
            found[name] = source
    return found


def apk_origins(path: str = APK_INSTALLED_DB) -> dict:
    """{package: origin} from apk's installed database (``P:`` and ``o:``)."""
    found, name = {}, None
    try:
        with open(path, encoding="utf-8", errors="replace") as handle:
            for line in handle:
                if line.startswith("P:"):
                    name = line[2:].strip()
                elif line.startswith("o:") and name:
                    found[name] = line[2:].strip()
                elif not line.strip():
                    name = None
    except OSError:
        return {}
    return found


class LinuxSoftwareInventoryCollector(SoftwareInventoryCollectorBase):
    """Collects software inventory from Linux package managers."""

    def __init__(self):  # pylint: disable=useless-parent-delegation
        super().__init__()

    def detect_package_managers(self) -> List[str]:
        """Detect available Linux package managers."""
        if self._package_managers is not None:
            return self._package_managers

        managers = []
        manager_executables = {
            "apt": ["apt", "apt-get", "dpkg"],
            "snap": ["snap"],
            "flatpak": ["flatpak"],
            "yum": ["yum"],
            "dnf": ["dnf"],
            "pacman": ["pacman"],
            "zypper": ["zypper"],
            "portage": ["emerge"],
            "apk": ["apk"],
            # Phase 17.2: OCI/container images (any of these runtimes present).
            "oci": ["podman", "docker", "nerdctl"],
        }

        for manager, executables in manager_executables.items():
            for executable in executables:
                if self._command_exists(executable):
                    managers.append(manager)
                    break

        self._package_managers = managers
        logger.debug("Detected package managers: %s", ", ".join(managers))
        return managers

    # Mapping of package manager name to its collection method name
    _MANAGER_COLLECTORS = {
        "apt": "_collect_apt_packages",
        "snap": "_collect_snap_packages",
        "flatpak": "_collect_flatpak_packages",
        "yum": "_collect_yum_packages",
        "dnf": "_collect_dnf_packages",
        "pacman": "_collect_pacman_packages",
        "zypper": "_collect_zypper_packages",
        "portage": "_collect_portage_packages",
        "apk": "_collect_apk_packages",
        "oci": "_collect_oci_images",
    }

    def collect_packages(self):
        """Collect packages from all detected Linux package managers."""
        managers = self.detect_package_managers()

        for manager in managers:
            collector_name = self._MANAGER_COLLECTORS.get(manager)
            if collector_name:
                getattr(self, collector_name)()

    def _parse_apt_package_line(self, parts):
        """Parse a single dpkg-query output line into a package dict.

        Args:
            parts: Tab-separated fields from dpkg-query output
                   (package, version, architecture, description, [installed-size]).

        Returns:
            A package dict, or None if the line cannot be parsed.
        """
        if len(parts) < 4:
            return None

        package = {
            "package_name": parts[0],
            "version": parts[1],
            "architecture": parts[2],
            "description": parts[3],
            "package_manager": "apt",
            "source": "debian_repository",
            "is_system_package": self._is_system_package_linux(parts[0]),
            "is_user_installed": True,
        }

        # Convert size from KB to bytes if available
        if len(parts) >= 5 and parts[4].isdigit():
            package["size_bytes"] = int(parts[4]) * 1024
        if len(parts) >= 6 and parts[5].strip():
            package["source_package"] = parts[5].strip()

        return package

    def _collect_apt_packages(self):
        """Collect packages from apt/dpkg (Debian/Ubuntu)."""
        try:
            logger.debug("Collecting apt packages")

            # Use dpkg-query for detailed package information
            result = subprocess.run(
                [
                    "dpkg-query",
                    "-W",
                    # One line per package: ${Description} is the FULL
                    # multi-line text, which pushed every later field onto the
                    # next line; ${binary:Summary} is its first line.  The
                    # source package is what Debian's advisories name.
                    "--showformat=${Package}\t${Version}\t${Architecture}\t${binary:Summary}\t${Installed-Size}\t${source:Package}\n",
                ],  # nosec B603, B607
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )

            if result.returncode == 0:
                for line in result.stdout.strip().split("\n"):
                    if line:
                        parts = line.split("\t")
                        package = self._parse_apt_package_line(parts)
                        if package:
                            self.collected_packages.append(package)

        except Exception as error:
            logger.exception(_("Failed to collect apt packages: %s"), str(error))

    def _parse_snap_package_line(self, parts):
        """Parse a single snap list output line into a package dict.

        ``snap list`` columns are: Name Version Rev Tracking Publisher Notes.
        Channel-aware detection (ROADMAP 17.1) captures the tracking channel and
        revision as structured fields (not just folded into ``source``), plus a
        best-effort confinement read from the Notes column.

        Args:
            parts: Whitespace-separated fields from snap list output
                   (name, version, rev, [tracking], [publisher], [notes]).

        Returns:
            A package dict, or None if the line cannot be parsed.
        """
        if len(parts) < 3:
            return None

        package = {
            "package_name": parts[0],
            "version": parts[1],
            "package_manager": "snap",
            "source": "snap_store",
            "revision": parts[2],
            "is_system_package": False,
            "is_user_installed": True,
        }

        # The Tracking column IS the snap's channel -- keep it structured (and,
        # for backward compatibility, still reflect it in ``source``).
        if len(parts) >= 4:
            package["channel"] = parts[3]
            package["source"] = f"snap_store/{parts[3]}"

        # Confinement (best-effort): ``snap list`` does not expose confinement
        # directly, but the Notes column flags classic/devmode snaps.  Strict
        # snaps show "-" (no note), which is ambiguous with other notes, so only
        # classic/devmode are reported with confidence.
        if len(parts) >= 6:
            notes = parts[5]
            if "classic" in notes:
                package["confinement"] = "classic"
            elif "devmode" in notes:
                package["confinement"] = "devmode"

        return package

    def _collect_snap_packages(self):
        """Collect packages from Snap."""
        try:
            logger.debug("Collecting snap packages")

            result = subprocess.run(
                ["snap", "list", "--unicode=never"],  # nosec B603, B607
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )

            if result.returncode == 0:
                lines = result.stdout.strip().split("\n")[1:]  # Skip header
                for line in lines:
                    parts = line.split()
                    package = self._parse_snap_package_line(parts)
                    if package:
                        self.collected_packages.append(package)

        except Exception as error:
            logger.exception(_("Failed to collect snap packages: %s"), str(error))

    def _parse_oci_image_line(self, parts, runtime):
        """Parse one ``<runtime> images`` row into a package dict.

        Columns (from the ``--digests --format`` template below) are:
        Repository, Tag, Digest, ID.  Container images are reported through the
        software-inventory pipeline as ``package_manager="oci"`` -- name =
        repository, version = tag, and the registry manifest **digest** (the
        immutable pin) reuses the ``revision`` field (Phase 17.2 / 17.1 column).

        Returns a package dict, or None for the dangling/untagged noise rows.
        """
        if len(parts) < 2:
            return None
        repository = parts[0].strip()
        if not repository or repository == _OCI_NONE:
            return None
        tag = parts[1].strip() if len(parts) > 1 else ""
        digest = parts[2].strip() if len(parts) > 2 else ""
        image_id = parts[3].strip() if len(parts) > 3 else ""

        package = {
            "package_name": repository,
            "version": tag if tag and tag != _OCI_NONE else "latest",
            "package_manager": "oci",
            "source": runtime,
            "is_system_package": False,
            "is_user_installed": True,
        }
        # The registry manifest digest is the reproducible pin; fall back to the
        # local image ID when the digest is absent (e.g. locally-built images).
        if digest and digest != _OCI_NONE:
            package["revision"] = digest
        elif image_id and image_id != _OCI_NONE:
            package["revision"] = image_id
        return package

    def _collect_oci_images(self):
        """Collect container images from the local OCI runtime (podman/docker/
        nerdctl).  All three share the same ``images --digests --format``
        template."""
        runtime = None
        for candidate in ("podman", "docker", "nerdctl"):
            if self._command_exists(candidate):
                runtime = candidate
                break
        if runtime is None:
            return
        try:
            logger.debug("Collecting %s container images", runtime)
            result = subprocess.run(
                [
                    runtime,
                    "images",
                    "--digests",
                    "--format",
                    "{{.Repository}}\t{{.Tag}}\t{{.Digest}}\t{{.ID}}",
                ],  # nosec B603, B607
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
            if result.returncode == 0:
                for line in result.stdout.strip().split("\n"):
                    if line:
                        package = self._parse_oci_image_line(line.split("\t"), runtime)
                        if package:
                            self.collected_packages.append(package)
        except Exception as error:
            logger.exception(_("Failed to collect container images: %s"), str(error))

    def _parse_flatpak_package_line(self, parts):
        """Parse a single flatpak list output line into a package dict.

        Args:
            parts: Tab-separated fields from flatpak list output
                   (name, application, [version], [size], [origin]).

        Returns:
            A package dict, or None if the line cannot be parsed.
        """
        if len(parts) < 2:
            return None

        package = {
            "package_name": parts[0] if parts[0] else parts[1],
            "bundle_id": parts[1],
            "version": parts[2] if len(parts) > 2 else None,
            "package_manager": "flatpak",
            "source": "flathub",
            "is_system_package": False,
            "is_user_installed": True,
        }

        # Add size if available
        if len(parts) > 3 and parts[3]:
            package["size_bytes"] = self._parse_size_string(parts[3])

        # Add origin if available
        if len(parts) > 4 and parts[4]:
            package["source"] = parts[4]

        return package

    def _collect_flatpak_packages(self):
        """Collect packages from Flatpak."""
        try:
            logger.debug("Collecting flatpak packages")

            result = subprocess.run(
                [
                    "flatpak",
                    "list",
                    "--app",
                    "--columns=name,application,version,size,origin",
                ],  # nosec B603, B607
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )

            if result.returncode == 0:
                lines = result.stdout.strip().split("\n")[1:]  # Skip header
                for line in lines:
                    parts = line.split("\t")
                    package = self._parse_flatpak_package_line(parts)
                    if package:
                        self.collected_packages.append(package)

        except Exception as error:
            logger.exception(_("Failed to collect flatpak packages: %s"), str(error))

    def _collect_yum_packages(self):
        """Collect packages from YUM (Red Hat/CentOS)."""
        # Implementation would use 'yum list installed' or 'rpm -qa'
        logger.debug("YUM package collection not implemented")

    def _parse_dnf_package_line(self, parts):
        """Parse a single DNF installed package line into a package dict.

        Args:
            parts: Whitespace-separated fields from dnf list output
                   (name.arch, version, repo).

        Returns:
            A package dict, or None if the line cannot be parsed.
        """
        if len(parts) < 3:
            return None

        package_name = parts[0].split(".")[0]  # Remove arch
        version = parts[1]
        repo = parts[2]

        return {
            "package_name": package_name,
            "version": version,
            "package_manager": "dnf",
            "source": repo,
            "is_system_package": self._is_system_package_linux(package_name),
            "is_user_installed": True,
        }

    def _dnf_installed(self, output: str, sources) -> list:
        """The packages under dnf's "Installed packages" header, each with
        the source package Fedora's advisories name."""
        packages = []
        in_packages = False
        for line in output.strip().split("\n"):
            # dnf4 prints "Installed Packages", dnf5 (Fedora 41+)
            # "Installed packages": a Fedora 42 host reported no packages at
            # all (2026-11-23).
            if line.strip().lower() == "installed packages":
                in_packages = True
                continue
            if not (in_packages and line.strip()):
                continue
            package = self._parse_dnf_package_line(line.split())
            if package:
                source = sources.get(package["package_name"])
                if source:
                    package["source_package"] = source
                packages.append(package)
        return packages

    def _collect_dnf_packages(self):
        """Collect packages from DNF (Fedora)."""
        try:
            logger.debug("Collecting DNF packages")

            result = subprocess.run(
                # ``--installed``: dnf5 reads ``installed`` as a package NAME
                # ("No matching packages to list"); dnf4 takes both forms.
                ["dnf", "list", "--installed"],  # nosec B603, B607
                capture_output=True,
                text=True,
                timeout=60,
                check=False,
            )

            if result.returncode == 0:
                self.collected_packages.extend(
                    self._dnf_installed(result.stdout, rpm_sources())
                )

        except Exception as error:
            logger.exception(_("Failed to collect DNF packages: %s"), str(error))

    def _parse_pacman_package_line(self, parts):
        """Parse a single pacman -Q output line into a package dict.

        Args:
            parts: Whitespace-separated fields from pacman output (name, version).

        Returns:
            A package dict, or None if the line cannot be parsed.
        """
        if len(parts) < 2:
            return None

        return {
            "package_name": parts[0],
            "version": parts[1],
            "package_manager": "pacman",
            "source": "arch_repository",
            "is_system_package": self._is_system_package_linux(parts[0]),
            "is_user_installed": True,
        }

    def _collect_pacman_packages(self):
        """Collect packages from Pacman (Arch Linux)."""
        try:
            logger.debug("Collecting Pacman packages")

            result = subprocess.run(
                ["pacman", "-Q"],  # nosec B603, B607
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )

            if result.returncode == 0:
                for line in result.stdout.strip().split("\n"):
                    if line:
                        parts = line.split()
                        package = self._parse_pacman_package_line(parts)
                        if package:
                            self.collected_packages.append(package)

        except Exception as error:
            logger.exception(_("Failed to collect Pacman packages: %s"), str(error))

    def _parse_zypper_package_line(self, parts):
        """Parse a single rpm query output line into a package dict for Zypper.

        Args:
            parts: Tab-separated fields from rpm query output
                   (name, version-release, arch, summary, [size]).

        Returns:
            A package dict, or None if the line cannot be parsed.
        """
        if len(parts) < 4:
            return None

        package = {
            "package_name": parts[0],
            "version": parts[1],
            "architecture": parts[2],
            "description": parts[3],
            "package_manager": "zypper",
            "source": "opensuse_repository",
            "is_system_package": self._is_system_package_linux(parts[0]),
            "is_user_installed": True,
        }

        # Add size if available
        if len(parts) >= 5 and parts[4].isdigit():
            package["size_bytes"] = int(parts[4])
        source = rpm_source_name(parts[5]) if len(parts) >= 6 else None
        if source:
            package["source_package"] = source

        return package

    def _collect_zypper_packages(self):
        """Collect packages from Zypper (openSUSE)."""
        try:
            logger.debug("Collecting Zypper packages")

            # Use rpm -qa for comprehensive package listing
            result = subprocess.run(
                [
                    "rpm",
                    "-qa",
                    "--queryformat",
                    "%{NAME}\t%{VERSION}-%{RELEASE}\t%{ARCH}\t%{SUMMARY}\t%{SIZE}\t%{SOURCERPM}\n",
                ],  # nosec B603, B607
                capture_output=True,
                text=True,
                timeout=60,
                check=False,
            )

            if result.returncode != 0:
                return

            for line in result.stdout.strip().split("\n"):
                if not line:
                    continue

                parts = line.split("\t")
                package = self._parse_zypper_package_line(parts)
                if package:
                    self.collected_packages.append(package)

            zypper_count = len(
                [
                    p
                    for p in self.collected_packages
                    if p.get("package_manager") == "zypper"
                ]
            )
            logger.debug("Successfully collected %d Zypper packages", zypper_count)

        except Exception as error:
            logger.exception(_("Failed to collect Zypper packages: %s"), str(error))

    def _collect_portage_packages(self):
        """Collect packages from Portage (Gentoo)."""
        # Implementation would use 'equery list "*"'
        logger.debug("Portage package collection not implemented")

    def _parse_apk_name_version(self, line):
        """Parse an APK package line into (name, version) tuple.

        APK format is 'package-name-version' where the version starts with a digit.
        For example:
          - 'busybox-1.36.1-r0' -> ('busybox', '1.36.1-r0')
          - 'py3-foo-1.0-r0'    -> ('py3-foo', '1.0-r0')

        Args:
            line: A single line from 'apk info -v' output.

        Returns:
            A (package_name, version) tuple. Version may be None if not parseable.
        """
        parts = line.rsplit("-", 2)
        if len(parts) < 2:
            return (line, None)

        # Handle packages like "py3-foo-1.0-r0" correctly
        if len(parts) == 3 and parts[1][0].isdigit():
            return (parts[0], f"{parts[1]}-{parts[2]}")

        if parts[-1][0].isdigit():
            return ("-".join(parts[:-1]), parts[-1])

        return (line, None)

    def _collect_apk_packages(self):
        """Collect packages from APK (Alpine Linux)."""
        try:
            logger.debug("Collecting APK packages")

            # Use 'apk info -v' to get package names with versions
            result = subprocess.run(
                ["apk", "info", "-v"],  # nosec B603, B607
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )

            if result.returncode != 0:
                return

            origins = apk_origins()
            for line in result.stdout.strip().split("\n"):
                if not line:
                    continue

                package_name, version = self._parse_apk_name_version(line)

                package = {
                    "package_name": package_name,
                    "version": version,
                    "package_manager": "apk",
                    "source": "alpine_repository",
                    # The origin is what Alpine's secdb names.
                    **(
                        {"source_package": origins[package_name]}
                        if origins.get(package_name)
                        else {}
                    ),
                    "is_system_package": self._is_system_package_linux(package_name),
                    "is_user_installed": True,
                }

                self.collected_packages.append(package)

            apk_count = len(
                [
                    p
                    for p in self.collected_packages
                    if p.get("package_manager") == "apk"
                ]
            )
            logger.debug("Successfully collected %d APK packages", apk_count)

        except Exception as error:
            logger.exception(_("Failed to collect APK packages: %s"), str(error))

    def _is_system_package_linux(self, package_name: str) -> bool:
        """Determine if a Linux package is a system package."""
        system_prefixes = [
            "lib",
            "python3",
            "linux-",
            "systemd",
            "base-",
            "core",
            "essential",
            "kernel",
            "firmware",
            "driver",
        ]
        return any(package_name.startswith(prefix) for prefix in system_prefixes)
