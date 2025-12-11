"""
OpenBSD bsd.rd embedding module for VMM autoinstall.

This module handles embedding site.tgz into bsd.rd for automated
installation via PXE boot.
"""

import logging
import os
import shutil
import subprocess  # nosec B404 # Required for system commands
import tempfile
import urllib.request
from pathlib import Path
from typing import Any, Dict

from src.i18n import _


class BsdRdEmbedder:
    """Handles embedding site.tgz into OpenBSD bsd.rd kernel."""

    # OpenBSD mirror base URL
    OPENBSD_MIRROR = "https://cdn.openbsd.org/pub/OpenBSD"

    def __init__(self, logger: logging.Logger):
        """
        Initialize bsd.rd embedder.

        Args:
            logger: Logger instance
        """
        self.logger = logger

    def embed_site_in_bsdrd(
        self,
        openbsd_version: str,
        site_tgz_path: str,
    ) -> Dict[str, Any]:
        """
        Embed site.tgz into bsd.rd for autoinstall.

        This creates a modified bsd.rd with the site tarball embedded
        in the ramdisk, allowing fully offline installation.

        Args:
            openbsd_version: OpenBSD version (e.g., "7.7")
            site_tgz_path: Path to site.tgz file

        Returns:
            Dict containing:
                - success: bool
                - bsdrd_path: str if successful (path to modified bsd.rd)
                - error: str if failed
        """
        try:
            self.logger.info(
                _("Embedding site.tgz into bsd.rd for OpenBSD %s"),
                openbsd_version,
            )

            # Create working directory
            with tempfile.TemporaryDirectory(prefix="bsdrd-embed-") as work_dir:
                work_path = Path(work_dir)

                # Step 1: Download original bsd.rd
                self.logger.info(_("Downloading bsd.rd"))
                download_result = self._download_bsdrd(openbsd_version, work_path)
                if not download_result["success"]:
                    return download_result
                bsdrd_orig = download_result["bsdrd_path"]

                # Step 2: Extract ramdisk from bsd.rd
                self.logger.info(_("Extracting ramdisk from bsd.rd"))
                extract_result = self._extract_ramdisk(bsdrd_orig, work_path)
                if not extract_result["success"]:
                    return extract_result
                ramdisk_path = extract_result["ramdisk_path"]

                # Step 3: Mount ramdisk and add site.tgz
                self.logger.info(_("Adding site.tgz to ramdisk"))
                embed_result = self._embed_site_tarball(
                    ramdisk_path, site_tgz_path, openbsd_version
                )
                if not embed_result["success"]:
                    return embed_result

                # Step 4: Repack ramdisk into bsd.rd
                self.logger.info(_("Repacking bsd.rd with modified ramdisk"))
                repack_result = self._repack_bsdrd(
                    bsdrd_orig, ramdisk_path, openbsd_version
                )
                if not repack_result["success"]:
                    return repack_result

                self.logger.info(
                    _("Successfully created modified bsd.rd: %s"),
                    repack_result["bsdrd_path"],
                )

                return repack_result

        except Exception as error:  # pylint: disable=broad-except
            self.logger.error(
                _("Failed to embed site.tgz in bsd.rd: %s"),
                error,
                exc_info=True,
            )
            return {
                "success": False,
                "bsdrd_path": None,
                "error": str(error),
            }

    def _download_bsdrd(self, openbsd_version: str, work_path: Path) -> Dict[str, Any]:
        """Download original bsd.rd from OpenBSD mirror."""
        try:
            url = f"{self.OPENBSD_MIRROR}/{openbsd_version}/" f"amd64/bsd.rd"
            dest_path = work_path / "bsd.rd.orig"

            self.logger.debug(_("Downloading from %s"), url)

            with urllib.request.urlopen(url, timeout=300) as response:  # nosec B310
                with open(dest_path, "wb") as file:
                    shutil.copyfileobj(response, file)

            if not dest_path.exists() or dest_path.stat().st_size < 1000000:
                return {
                    "success": False,
                    "bsdrd_path": None,
                    "error": _("Downloaded bsd.rd appears invalid"),
                }

            return {
                "success": True,
                "bsdrd_path": str(dest_path),
                "error": None,
            }

        except Exception as error:  # pylint: disable=broad-except
            return {
                "success": False,
                "bsdrd_path": None,
                "error": f"Download failed: {error}",
            }

    def _extract_ramdisk(self, bsdrd_path: str, work_path: Path) -> Dict[str, Any]:
        """Extract ramdisk from bsd.rd using rdsetroot."""
        try:
            ramdisk_path = work_path / "ramdisk.img"

            # Use rdsetroot to extract the ramdisk
            result = subprocess.run(  # nosec B603 B607
                [
                    "doas",
                    "rdsetroot",
                    "-x",
                    str(ramdisk_path),
                    bsdrd_path,
                ],
                capture_output=True,
                text=True,
                timeout=60,
                check=False,
            )

            if result.returncode != 0:
                return {
                    "success": False,
                    "ramdisk_path": None,
                    "error": f"rdsetroot extraction failed: {result.stderr}",
                }

            if not ramdisk_path.exists():
                return {
                    "success": False,
                    "ramdisk_path": None,
                    "error": _("Ramdisk extraction produced no output"),
                }

            return {
                "success": True,
                "ramdisk_path": str(ramdisk_path),
                "error": None,
            }

        except subprocess.TimeoutExpired as error:
            return {
                "success": False,
                "ramdisk_path": None,
                "error": f"rdsetroot timeout: {error}",
            }
        except Exception as error:  # pylint: disable=broad-except
            return {
                "success": False,
                "ramdisk_path": None,
                "error": f"Extraction failed: {error}",
            }

    def _embed_site_tarball(
        self, ramdisk_path: str, site_tgz_path: str, openbsd_version: str
    ) -> Dict[str, Any]:
        """Embed site.tgz into ramdisk using vnconfig."""
        vnd_device = None
        mount_point = None

        try:
            # Configure vnode device
            result = subprocess.run(  # nosec B603 B607
                ["doas", "vnconfig", "vnd0", ramdisk_path],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )

            if result.returncode != 0:
                return {
                    "success": False,
                    "error": f"vnconfig failed: {result.stderr}",
                }

            vnd_device = "vnd0"

            # Create mount point
            mount_point = tempfile.mkdtemp(prefix="ramdisk-mount-")

            # Mount the ramdisk
            result = subprocess.run(  # nosec B603 B607
                ["doas", "mount", "/dev/vnd0a", mount_point],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )

            if result.returncode != 0:
                return {
                    "success": False,
                    "error": f"mount failed: {result.stderr}",
                }

            # Copy site.tgz to ramdisk (version-specific filename)
            site_filename = f"site{openbsd_version.replace('.', '')}.tgz"
            dest_site = os.path.join(mount_point, site_filename)

            subprocess.run(  # nosec B603 B607
                ["doas", "cp", site_tgz_path, dest_site],
                check=True,
                capture_output=True,
                timeout=30,
            )

            # Verify copy
            if not os.path.exists(dest_site):
                return {
                    "success": False,
                    "error": _("Failed to copy site.tgz to ramdisk"),
                }

            self.logger.debug(_("Embedded %s into ramdisk"), site_filename)

            return {"success": True, "error": None}

        except subprocess.TimeoutExpired as error:
            return {"success": False, "error": f"Timeout: {error}"}
        except Exception as error:  # pylint: disable=broad-except
            return {"success": False, "error": f"Embed failed: {error}"}
        finally:
            # Cleanup: unmount and unconfigure vnode
            if mount_point:
                subprocess.run(  # nosec B603 B607
                    ["doas", "umount", mount_point],
                    capture_output=True,
                    timeout=30,
                    check=False,
                )
                try:
                    os.rmdir(mount_point)
                except OSError:
                    pass

            if vnd_device:
                subprocess.run(  # nosec B603 B607
                    ["doas", "vnconfig", "-u", vnd_device],
                    capture_output=True,
                    timeout=30,
                    check=False,
                )

    def _repack_bsdrd(
        self, orig_bsdrd: str, ramdisk_path: str, openbsd_version: str
    ) -> Dict[str, Any]:
        """Repack bsd.rd with modified ramdisk using rdsetroot."""
        try:
            # Create output directory
            output_dir = Path("/var/vmm/pxeboot")
            output_dir.mkdir(parents=True, exist_ok=True)

            # Create versioned bsd.rd filename
            output_path = output_dir / f"bsd.rd.{openbsd_version}"

            # Copy original bsd.rd
            shutil.copy2(orig_bsdrd, output_path)

            # Use rdsetroot to insert modified ramdisk
            result = subprocess.run(  # nosec B603 B607
                ["doas", "rdsetroot", str(output_path), ramdisk_path],
                capture_output=True,
                text=True,
                timeout=60,
                check=False,
            )

            if result.returncode != 0:
                return {
                    "success": False,
                    "bsdrd_path": None,
                    "error": f"rdsetroot insertion failed: {result.stderr}",
                }

            # Verify output file
            if not output_path.exists():
                return {
                    "success": False,
                    "bsdrd_path": None,
                    "error": _("Repacked bsd.rd not found"),
                }

            # Also create unversioned symlink for TFTP
            symlink_path = output_dir / "bsd.rd"
            if symlink_path.exists() or symlink_path.is_symlink():
                symlink_path.unlink()
            symlink_path.symlink_to(output_path.name)

            return {
                "success": True,
                "bsdrd_path": str(output_path),
                "error": None,
            }

        except subprocess.TimeoutExpired as error:
            return {
                "success": False,
                "bsdrd_path": None,
                "error": f"Repack timeout: {error}",
            }
        except Exception as error:  # pylint: disable=broad-except
            return {
                "success": False,
                "bsdrd_path": None,
                "error": f"Repack failed: {error}",
            }
