"""
OpenBSD package builder for VMM child hosts.

Handles building sysmanage-agent packages from port files.
"""

import logging
import os
import re
import shutil
import subprocess  # nosec B404 # Required for system commands
from pathlib import Path
from typing import Any, Dict

from src.i18n import _

# Module-level constants for duplicate strings
_PBUILD_USER_GROUP = "_pbuild:_pbuild"
_NO_OUTPUT = "(no output)"


class PackageBuilder:
    """Builds OpenBSD packages for sysmanage-agent."""

    def __init__(self, logger: logging.Logger):
        """Initialize package builder."""
        self.logger = logger

    def build_agent_package(self, port_dir: Path, agent_version: str) -> Dict[str, Any]:
        """Build sysmanage-agent package from port."""
        try:
            self.logger.info(_("ENTERED build_agent_package, port_dir: %s"), port_dir)
            # Copy port to /usr/ports/mystuff/sysutils/sysmanage-agent
            ports_dir = Path("/usr/ports/mystuff/sysutils/sysmanage-agent")

            # Remove old port directory if exists
            if ports_dir.exists():
                self.logger.info(_("Removing old port directory: %s"), ports_dir)
                shutil.rmtree(ports_dir)

            # Create directory and copy files
            self.logger.info(_("Creating ports directory: %s"), ports_dir.parent)
            ports_dir.parent.mkdir(parents=True, exist_ok=True)

            self.logger.info(_("Copying port from %s to %s"), port_dir, ports_dir)
            shutil.copytree(port_dir, ports_dir)

            # Update Makefile GH_TAGNAME to match the agent version we're building
            self.logger.info(_("Updating Makefile GH_TAGNAME to agent version"))
            makefile_path = ports_dir / "Makefile"
            if makefile_path.exists():
                with open(makefile_path, "r", encoding="utf-8") as makefile:
                    makefile_content = makefile.read()

                # Replace GH_TAGNAME line with correct version
                makefile_content = re.sub(
                    r"^GH_TAGNAME\s*=.*$",
                    f"GH_TAGNAME = {agent_version}",
                    makefile_content,
                    flags=re.MULTILINE,
                )

                # Fix yaml filename references (sysmanage-agent.yaml -> sysmanage-agent-system.yaml)
                makefile_content = makefile_content.replace(
                    "sysmanage-agent.yaml", "sysmanage-agent-system.yaml"
                )

                with open(makefile_path, "w", encoding="utf-8") as makefile:
                    makefile.write(makefile_content)

                self.logger.info(_("Updated GH_TAGNAME to: %s"), agent_version)
                self.logger.info(_("Fixed yaml filename references in Makefile"))

            # Fix yaml filename references in PLIST
            self.logger.info(_("Fixing yaml filename references in PLIST"))
            plist_path = ports_dir / "pkg" / "PLIST"
            if plist_path.exists():
                with open(plist_path, "r", encoding="utf-8") as plist_file:
                    plist_content = plist_file.read()

                plist_content = plist_content.replace(
                    "sysmanage-agent.yaml", "sysmanage-agent-system.yaml"
                )

                with open(plist_path, "w", encoding="utf-8") as plist_file:
                    plist_file.write(plist_content)

                self.logger.info(_("Fixed yaml filename references in PLIST"))

            # Set ownership of port directory for _pbuild user
            self.logger.info(_("Setting port directory ownership to _pbuild"))
            subprocess.run(  # nosec B603 B607
                ["chown", "-R", _PBUILD_USER_GROUP, str(ports_dir)],
                check=True,
                capture_output=True,
                timeout=30,
            )

            # Fix distinfo file version mismatch
            self.logger.info(_("Patching distinfo file for correct version"))
            distinfo_path = ports_dir / "distinfo"
            if distinfo_path.exists():
                # Create stub distinfo with correct version to trigger makesum
                self.logger.info(
                    _("Creating stub distinfo for version: %s"), agent_version
                )
                stub_distinfo = f"""SHA256 ({agent_version}.tar.gz) = 0000000000000000000000000000000000000000000000000000000000000000
SIZE ({agent_version}.tar.gz) = 0
"""
                with open(distinfo_path, "w", encoding="utf-8") as distinfo_file:
                    distinfo_file.write(stub_distinfo)
                self.logger.info(
                    _("Created stub distinfo for %s, makesum will regenerate it"),
                    agent_version,
                )

            # Set up build environment
            self._setup_build_environment(ports_dir)

            # Clean previous builds
            self._clean_previous_builds()

            # Build the package
            return self._build_package(ports_dir)

        except subprocess.TimeoutExpired as error:
            self.logger.error(_("Build timeout: %s"), error)
            return {
                "success": False,
                "package_path": None,
                "error": f"Build timeout: {error}",
            }
        except subprocess.CalledProcessError as error:
            self.logger.error(_("Build failed with CalledProcessError: %s"), error)
            self.logger.error(_("stderr: %s"), error.stderr)
            return {
                "success": False,
                "package_path": None,
                "error": f"Build failed: {error.stderr.decode() if error.stderr else str(error)}",
            }
        except Exception as error:  # pylint: disable=broad-except
            self.logger.error(_("Unexpected build error: %s"), error, exc_info=True)
            return {
                "success": False,
                "package_path": None,
                "error": f"Build error: {error}",
            }

    def _setup_build_environment(self, ports_dir: Path) -> None:
        """Set up build directories and permissions."""
        self.logger.info(_("Setting up build directories for _pbuild user"))

        # Create and set ownership of /usr/obj/ports for build artifacts
        obj_ports = Path("/usr/obj/ports")
        obj_ports.mkdir(parents=True, exist_ok=True)

        # Allow _pbuild to traverse /usr/obj
        subprocess.run(  # nosec B603 B607
            ["chmod", "o+x", "/usr/obj"],
            check=True,
            capture_output=True,
            timeout=30,
        )

        subprocess.run(  # nosec B603 B607
            ["chown", "-R", _PBUILD_USER_GROUP, str(obj_ports)],
            check=True,
            capture_output=True,
            timeout=30,
        )

        # Create package directories (required by OpenBSD ports system)
        self.logger.info(_("Setting up package directories"))
        for pkg_dir in [
            "/usr/packages/amd64/all",
            "/usr/packages/amd64/tmp",
            "/usr/packages/amd64/ftp",
        ]:
            Path(pkg_dir).mkdir(parents=True, exist_ok=True)

        subprocess.run(  # nosec B603 B607
            ["chown", "-R", _PBUILD_USER_GROUP, "/usr/packages"],
            check=True,
            capture_output=True,
            timeout=30,
        )

        # Create plist directory
        plist_dir = Path("/usr/ports/plist/amd64/history")
        plist_dir.mkdir(parents=True, exist_ok=True)

        subprocess.run(  # nosec B603 B607
            ["chown", "-R", _PBUILD_USER_GROUP, "/usr/ports/plist"],
            check=True,
            capture_output=True,
            timeout=30,
        )

        # Set ownership of port directory
        subprocess.run(  # nosec B603 B607
            ["chown", "-R", _PBUILD_USER_GROUP, str(ports_dir)],
            check=True,
            capture_output=True,
            timeout=30,
        )

    def _clean_previous_builds(self) -> None:
        """Clean cached PLIST files and old builds."""
        # Clean cached PLIST files to prevent "change in plist" validation errors
        self.logger.info(_("Removing cached PLIST files"))
        subprocess.run(  # nosec B603 B607
            ["sh", "-c", "rm -f /usr/ports/plist/amd64/sysmanage-agent-*"],
            capture_output=True,
            timeout=10,
            check=False,
        )

        # Remove old work directories
        self.logger.info(_("Removing old work directories"))
        subprocess.run(  # nosec B603 B607
            ["sh", "-c", "rm -rf /usr/obj/ports/sysmanage-agent-*"],
            capture_output=True,
            timeout=10,
            check=False,
        )

        # Remove old packages
        self.logger.info(_("Removing old packages"))
        subprocess.run(  # nosec B603 B607
            ["sh", "-c", "rm -f /usr/packages/*/all/sysmanage-agent-*.tgz"],
            capture_output=True,
            timeout=10,
            check=False,
        )

    def _build_package(self, ports_dir: Path) -> Dict[str, Any]:
        """Run make commands to build the package."""
        # Build package as _pbuild user (ports won't build as root)
        self.logger.info(_("Running make clean as _pbuild"))
        result = subprocess.run(  # nosec B603 B607
            ["su", "-m", "_pbuild", "-c", "make clean"],
            cwd=ports_dir,
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
        self.logger.info(
            _("make clean output: %s"),
            result.stdout if result.stdout else _NO_OUTPUT,
        )
        if result.stderr:
            self.logger.warning(_("make clean stderr: %s"), result.stderr)

        self.logger.info(_("Running make makesum as _pbuild"))
        result = subprocess.run(  # nosec B603 B607
            ["su", "-m", "_pbuild", "-c", "make makesum"],
            cwd=ports_dir,
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
        self.logger.info(
            _("make makesum output: %s"),
            result.stdout if result.stdout else _NO_OUTPUT,
        )
        if result.stderr:
            self.logger.warning(_("make makesum stderr: %s"), result.stderr)

        # Try to fetch distfiles first
        self.logger.info(_("Running make fetch as _pbuild"))
        result = subprocess.run(  # nosec B603 B607
            ["su", "-m", "_pbuild", "-c", "make fetch"],
            cwd=ports_dir,
            capture_output=True,
            text=True,
            timeout=300,
            check=False,
        )
        self.logger.info(
            _("make fetch output: %s"),
            result.stdout if result.stdout else _NO_OUTPUT,
        )
        self.logger.info(_("make fetch return code: %d"), result.returncode)
        if result.stderr:
            self.logger.warning(_("make fetch stderr: %s"), result.stderr)

        # Now try to build and package
        self.logger.info(_("Running make package as _pbuild"))
        result = subprocess.run(  # nosec B603 B607
            ["su", "-m", "_pbuild", "-c", "make package"],
            cwd=ports_dir,
            capture_output=True,
            text=True,
            timeout=600,
            check=False,
        )
        self.logger.info(
            _("make package output: %s"),
            result.stdout if result.stdout else _NO_OUTPUT,
        )
        self.logger.info(_("make package return code: %d"), result.returncode)
        if result.stderr:
            self.logger.warning(_("make package stderr: %s"), result.stderr)
        if result.returncode != 0:
            self.logger.error(
                _("make package failed with return code: %d"), result.returncode
            )
            return {
                "success": False,
                "package_path": None,
                "error": f"make package failed: {result.stderr}",
            }

        self.logger.info(_("Package build completed, searching for package file"))

        # Get package repository location from Makefile
        self.logger.info(_("Querying Makefile for package repository location"))
        result = subprocess.run(  # nosec B603 B607
            ["su", "-m", "_pbuild", "-c", "make show=PACKAGE_REPOSITORY"],
            cwd=ports_dir,
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        pkg_repo = result.stdout.strip()
        self.logger.info(_("Package repository: %s"), pkg_repo)

        # Find built package (newest by timestamp)
        pkg_pattern = f"{pkg_repo}/*/all/sysmanage-agent-*.tgz"
        self.logger.info(_("Searching for package with pattern: %s"), pkg_pattern)
        result = subprocess.run(  # nosec B603 B607
            ["sh", "-c", f"ls -t {pkg_pattern} 2>/dev/null | head -1"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )

        pkg_path = result.stdout.strip()
        self.logger.info(
            _("Package search result: %s"), pkg_path if pkg_path else "NOT FOUND"
        )
        if not pkg_path or not os.path.exists(pkg_path):
            self.logger.error(_("Built package not found at pattern: %s"), pkg_pattern)
            return {
                "success": False,
                "package_path": None,
                "error": _("Built package not found"),
            }

        self.logger.info(_("Package built successfully: %s"), pkg_path)
        return {
            "success": True,
            "package_path": pkg_path,
            "error": None,
        }
