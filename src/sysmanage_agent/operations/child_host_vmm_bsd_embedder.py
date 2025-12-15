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
                    self.logger.error(
                        _("Ramdisk extraction failed: %s"), extract_result["error"]
                    )
                    return extract_result
                ramdisk_path = extract_result["ramdisk_path"]

                # Step 3: Mount ramdisk and add site.tgz
                self.logger.info(_("Adding site.tgz to ramdisk"))
                embed_result = self._embed_site_tarball(
                    ramdisk_path, site_tgz_path, openbsd_version
                )
                if not embed_result["success"]:
                    self.logger.error(
                        _("Failed to embed site.tgz: %s"), embed_result["error"]
                    )
                    return embed_result

                # Step 4: Repack ramdisk into bsd.rd
                self.logger.info(_("Repacking bsd.rd with modified ramdisk"))
                repack_result = self._repack_bsdrd(
                    bsdrd_orig, ramdisk_path, openbsd_version
                )
                if not repack_result["success"]:
                    self.logger.error(
                        _("Failed to repack bsd.rd: %s"), repack_result["error"]
                    )
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
            compressed_path = work_path / "bsd.rd.gz"
            dest_path = work_path / "bsd.rd.orig"

            self.logger.debug(_("Downloading from %s"), url)

            # Download the gzipped bsd.rd
            # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected
            with urllib.request.urlopen(url, timeout=300) as response:  # nosec B310
                with open(compressed_path, "wb") as file:
                    shutil.copyfileobj(response, file)

            if not compressed_path.exists() or compressed_path.stat().st_size < 1000000:
                return {
                    "success": False,
                    "bsdrd_path": None,
                    "error": _("Downloaded bsd.rd appears invalid"),
                }

            # Decompress the downloaded bsd.rd
            result = subprocess.run(  # nosec B603 B607
                ["gunzip", "-c", str(compressed_path)],
                capture_output=True,
                timeout=30,
                check=False,
            )

            if result.returncode != 0:
                return {
                    "success": False,
                    "bsdrd_path": None,
                    "error": f"gunzip failed: {result.stderr.decode()}",
                }

            # Write decompressed content to dest_path
            with open(dest_path, "wb") as file:
                file.write(result.stdout)

            if not dest_path.exists() or dest_path.stat().st_size < 1000000:
                return {
                    "success": False,
                    "bsdrd_path": None,
                    "error": _("Decompressed bsd.rd appears invalid"),
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

            # Use rdsetroot to extract the ramdisk (uncompressed FFS filesystem)
            # Syntax: rdsetroot -x kernel [output_file]
            result = subprocess.run(  # nosec B603 B607
                [
                    "rdsetroot",
                    "-x",
                    bsdrd_path,
                    str(ramdisk_path),
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
        """Embed site.tgz into ramdisk by creating a larger custom ramdisk."""
        vnd0_device = None
        vnd1_device = None
        old_mount = None
        new_mount = None
        new_ramdisk_path = None

        try:
            # Get site.tgz size to determine new ramdisk size
            site_size = os.path.getsize(site_tgz_path)
            # Create ramdisk with 200MB to have plenty of room (site.tgz + original contents + overhead)
            new_ramdisk_size_mb = 200
            new_ramdisk_path = f"{ramdisk_path}.large"

            self.logger.info(
                _("Creating larger ramdisk (%dMB) to fit site.tgz (%d bytes)"),
                new_ramdisk_size_mb,
                site_size,
            )

            # Create a new larger ramdisk filesystem
            # Using dd to create a 200MB file, then newfs to format it
            result = subprocess.run(  # nosec B603 B607
                [
                    "dd",
                    "if=/dev/zero",
                    f"of={new_ramdisk_path}",
                    "bs=1m",
                    f"count={new_ramdisk_size_mb}",
                ],
                capture_output=True,
                text=True,
                timeout=60,
                check=False,
            )

            if result.returncode != 0:
                return {
                    "success": False,
                    "error": f"dd failed: {result.stderr}",
                }

            # Format the new ramdisk as FFS
            result = subprocess.run(  # nosec B603 B607
                ["newfs", "-m", "0", "-o", "space", new_ramdisk_path],
                capture_output=True,
                text=True,
                timeout=60,
                check=False,
            )

            if result.returncode != 0:
                return {
                    "success": False,
                    "error": f"newfs failed: {result.stderr}",
                }

            # Mount original ramdisk
            result = subprocess.run(  # nosec B603 B607
                ["vnconfig", "vnd0", ramdisk_path],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )

            if result.returncode != 0:
                return {
                    "success": False,
                    "error": f"vnconfig vnd0 failed: {result.stderr}",
                }

            vnd0_device = "vnd0"
            old_mount = tempfile.mkdtemp(prefix="ramdisk-old-")

            result = subprocess.run(  # nosec B603 B607
                ["mount", "-r", "/dev/vnd0a", old_mount],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )

            if result.returncode != 0:
                return {
                    "success": False,
                    "error": f"mount old ramdisk failed: {result.stderr}",
                }

            # Mount new ramdisk
            result = subprocess.run(  # nosec B603 B607
                ["vnconfig", "vnd1", new_ramdisk_path],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )

            if result.returncode != 0:
                return {
                    "success": False,
                    "error": f"vnconfig vnd1 failed: {result.stderr}",
                }

            vnd1_device = "vnd1"
            new_mount = tempfile.mkdtemp(prefix="ramdisk-new-")

            result = subprocess.run(  # nosec B603 B607
                ["mount", "/dev/vnd1a", new_mount],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )

            if result.returncode != 0:
                return {
                    "success": False,
                    "error": f"mount new ramdisk failed: {result.stderr}",
                }

            # Copy all contents from old ramdisk to new
            self.logger.info(_("Copying original ramdisk contents to larger ramdisk"))
            result = subprocess.run(  # nosec B603 B607
                ["sh", "-c", f"cd {old_mount} && pax -rw -pe . {new_mount}/"],
                capture_output=True,
                text=True,
                timeout=120,
                check=False,
            )

            if result.returncode != 0:
                return {
                    "success": False,
                    "error": f"pax copy failed: {result.stderr}",
                }

            # Copy site.tgz to new ramdisk
            site_filename = f"site{openbsd_version.replace('.', '')}.tgz"
            dest_site = os.path.join(new_mount, site_filename)

            self.logger.info(_("Copying site.tgz to new ramdisk"))
            result = subprocess.run(  # nosec B603 B607
                ["cp", site_tgz_path, dest_site],
                capture_output=True,
                text=True,
                timeout=120,
                check=False,
            )

            if result.returncode != 0:
                return {
                    "success": False,
                    "error": f"cp site.tgz failed: {result.stderr}",
                }

            # Verify copy
            if not os.path.exists(dest_site):
                return {
                    "success": False,
                    "error": _("Failed to copy site.tgz to ramdisk"),
                }

            self.logger.info(_("Successfully embedded %s into ramdisk"), site_filename)

            return {
                "success": True,
                "error": None,
                "ramdisk_path": new_ramdisk_path,
            }

        except subprocess.TimeoutExpired as error:
            return {"success": False, "error": f"Timeout: {error}"}
        except Exception as error:  # pylint: disable=broad-except
            return {"success": False, "error": f"Embed failed: {error}"}
        finally:
            # Cleanup: unmount and unconfigure vnodes
            if old_mount:
                subprocess.run(  # nosec B603 B607
                    ["umount", old_mount],
                    capture_output=True,
                    timeout=30,
                    check=False,
                )
                try:
                    os.rmdir(old_mount)
                except OSError:
                    pass

            if new_mount:
                subprocess.run(  # nosec B603 B607
                    ["umount", new_mount],
                    capture_output=True,
                    timeout=30,
                    check=False,
                )
                try:
                    os.rmdir(new_mount)
                except OSError:
                    pass

            if vnd0_device:
                subprocess.run(  # nosec B603 B607
                    ["vnconfig", "-u", vnd0_device],
                    capture_output=True,
                    timeout=30,
                    check=False,
                )

            if vnd1_device:
                subprocess.run(  # nosec B603 B607
                    ["vnconfig", "-u", vnd1_device],
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
                ["rdsetroot", str(output_path), ramdisk_path],
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
