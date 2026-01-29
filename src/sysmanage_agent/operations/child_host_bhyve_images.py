"""
bhyve VM image handling for FreeBSD hosts.

This module contains helper functions for managing bhyve VM images:
- Cloud image downloading and caching
- Image format detection and conversion (qcow2 to raw)
- Disk image creation and resizing
"""

import hashlib
import os
import shutil
import subprocess  # nosec B404 # needed for sync disk/network operations
from typing import Any, Dict

from src.i18n import _

# Default paths for bhyve images
BHYVE_IMAGES_DIR = "/vm/images"


class BhyveImageHelper:
    """Helper class for bhyve VM image operations."""

    def __init__(self, logger):
        """
        Initialize the image helper.

        Args:
            logger: Logger instance
        """
        self.logger = logger

    def _is_qcow2_image(self, path: str) -> bool:
        """
        Check if a disk image is in qcow2 format.

        Args:
            path: Path to the image file

        Returns:
            True if qcow2 format, False otherwise
        """
        try:
            # Check file magic bytes - qcow2 starts with "QFI\xfb"
            with open(path, "rb") as img_file:
                magic = img_file.read(4)
                return magic == b"QFI\xfb"
        except Exception:
            return False

    def _convert_qcow2_to_raw(self, qcow2_path: str, raw_path: str) -> Dict[str, Any]:
        """
        Convert a qcow2 image to raw format for bhyve.

        bhyve requires raw disk images - it does not support qcow2 natively.

        Args:
            qcow2_path: Path to the qcow2 image
            raw_path: Destination path for raw image

        Returns:
            Dict with success status
        """
        try:
            self.logger.info(
                _("Converting qcow2 image to raw format for bhyve compatibility")
            )

            # Use qemu-img to convert (from qemu-utils package)
            result = subprocess.run(  # nosec B603 B607
                [
                    "qemu-img",
                    "convert",
                    "-f",
                    "qcow2",
                    "-O",
                    "raw",
                    qcow2_path,
                    raw_path,
                ],
                capture_output=True,
                text=True,
                timeout=1800,  # 30 minutes for large images
                check=False,
            )

            if result.returncode != 0:
                return {
                    "success": False,
                    "error": _("Failed to convert qcow2 to raw: %s") % result.stderr,
                }

            self.logger.info(_("Converted image to raw format: %s"), raw_path)
            return {"success": True, "path": raw_path}

        except FileNotFoundError:
            return {
                "success": False,
                "error": _(
                    "qemu-img not found. Install qemu-utils: pkg install qemu-utils"
                ),
            }
        except subprocess.TimeoutExpired:
            return {"success": False, "error": _("Image conversion timed out")}
        except Exception as error:
            return {"success": False, "error": str(error)}

    def _get_cache_paths(self, url: str) -> Dict[str, str]:
        """
        Get cache paths for a cloud image URL.

        Args:
            url: URL of the cloud image

        Returns:
            Dict with download_dir, cached_path, raw_cached_path, decompressed_path, is_xz
        """
        download_dir = os.path.join(BHYVE_IMAGES_DIR, ".downloads")
        url_hash = hashlib.md5(url.encode(), usedforsecurity=False).hexdigest()[:8]
        filename = os.path.basename(url.split("?")[0])
        cached_path = os.path.join(download_dir, f"{url_hash}_{filename}")
        raw_cached_path = cached_path + ".raw"

        is_xz = filename.endswith(".xz")
        decompressed_path = cached_path[:-3] if is_xz else cached_path

        return {
            "download_dir": download_dir,
            "cached_path": cached_path,
            "raw_cached_path": raw_cached_path,
            "decompressed_path": decompressed_path,
            "is_xz": is_xz,
        }

    def _download_image_file(self, url: str, cached_path: str) -> Dict[str, Any]:
        """
        Download image file using fetch or curl.

        Args:
            url: URL to download from
            cached_path: Path to save the file

        Returns:
            Dict with success status
        """
        result = subprocess.run(  # nosec B603 B607
            ["fetch", "-o", cached_path, url],
            capture_output=True,
            text=True,
            timeout=1800,
            check=False,
        )

        if result.returncode == 0:
            return {"success": True}

        # Try curl as fallback
        result = subprocess.run(  # nosec B603 B607
            ["curl", "-L", "-o", cached_path, url],
            capture_output=True,
            text=True,
            timeout=1800,
            check=False,
        )

        if result.returncode != 0:
            return {
                "success": False,
                "error": _("Failed to download image: %s") % result.stderr,
            }

        return {"success": True}

    def _decompress_xz_archive(self, cached_path: str) -> Dict[str, Any]:
        """
        Decompress an xz archive.

        Args:
            cached_path: Path to the .xz file

        Returns:
            Dict with success status
        """
        self.logger.info(_("Decompressing xz archive"))
        result = subprocess.run(  # nosec B603 B607
            ["xz", "-dk", cached_path],
            capture_output=True,
            text=True,
            timeout=600,
            check=False,
        )

        if result.returncode != 0:
            return {
                "success": False,
                "error": _("Failed to decompress: %s") % result.stderr,
            }

        return {"success": True}

    def _prepare_final_image(
        self, decompressed_path: str, raw_cached_path: str, dest_path: str
    ) -> Dict[str, Any]:
        """
        Prepare final image by converting if needed and copying to destination.

        Args:
            decompressed_path: Path to the decompressed source image
            raw_cached_path: Path for caching converted raw image
            dest_path: Final destination path

        Returns:
            Dict with success status
        """
        if self._is_qcow2_image(decompressed_path):
            self.logger.info(_("Detected qcow2 format, converting to raw for bhyve"))
            convert_result = self._convert_qcow2_to_raw(
                decompressed_path, raw_cached_path
            )
            if not convert_result.get("success"):
                return convert_result
            shutil.copy2(raw_cached_path, dest_path)
        else:
            shutil.copy2(decompressed_path, dest_path)

        return {"success": True}

    def download_cloud_image(
        self, url: str, dest_path: str, disk_size_gb: int = 20
    ) -> Dict[str, Any]:
        """
        Download a cloud image and convert to raw format if needed.

        bhyve requires raw disk images. Cloud images are often in qcow2 format,
        so this function detects and converts them automatically.

        Args:
            url: URL of the cloud image
            dest_path: Destination path for the image
            disk_size_gb: Target disk size in GB (for resizing after conversion)

        Returns:
            Dict with success status and path
        """
        try:
            self.logger.info(_("Downloading cloud image from: %s"), url)

            paths = self._get_cache_paths(url)
            os.makedirs(paths["download_dir"], mode=0o755, exist_ok=True)

            # Check if we have a cached raw conversion
            if os.path.exists(paths["raw_cached_path"]):
                self.logger.info(
                    _("Using cached raw cloud image: %s"), paths["raw_cached_path"]
                )
                shutil.copy2(paths["raw_cached_path"], dest_path)
                self._resize_disk_image(dest_path, disk_size_gb)
                return {"success": True, "path": dest_path}

            # Download if not cached
            if not os.path.exists(paths["decompressed_path"]):
                download_result = self._download_image_file(url, paths["cached_path"])
                if not download_result.get("success"):
                    return download_result

                self.logger.info(
                    _("Cloud image downloaded to: %s"), paths["cached_path"]
                )

                if paths["is_xz"]:
                    decompress_result = self._decompress_xz_archive(
                        paths["cached_path"]
                    )
                    if not decompress_result.get("success"):
                        return decompress_result
            else:
                self.logger.info(
                    _("Using cached cloud image: %s"), paths["decompressed_path"]
                )

            # Convert and copy to destination
            prepare_result = self._prepare_final_image(
                paths["decompressed_path"], paths["raw_cached_path"], dest_path
            )
            if not prepare_result.get("success"):
                return prepare_result

            self._resize_disk_image(dest_path, disk_size_gb)
            return {"success": True, "path": dest_path}

        except subprocess.TimeoutExpired:
            return {"success": False, "error": _("Download timed out")}
        except Exception as error:
            return {"success": False, "error": str(error)}

    def _resize_disk_image(self, path: str, size_gb: int) -> None:
        """
        Resize a raw disk image to the specified size.

        Args:
            path: Path to the raw disk image
            size_gb: Target size in GB
        """
        try:
            size_bytes = size_gb * 1024 * 1024 * 1024
            current_size = os.path.getsize(path)

            if current_size < size_bytes:
                self.logger.info(_("Resizing disk image to %dGB"), size_gb)
                result = subprocess.run(  # nosec B603 B607
                    ["truncate", "-s", str(size_bytes), path],
                    capture_output=True,
                    text=True,
                    timeout=60,
                    check=False,
                )
                if result.returncode != 0:
                    self.logger.warning(_("Failed to resize disk: %s"), result.stderr)
        except Exception as error:
            self.logger.warning(_("Error resizing disk: %s"), error)

    def create_disk_image(
        self, path: str, size_gb: int, use_zvol: bool = False, zvol_parent: str = ""
    ) -> Dict[str, Any]:
        """
        Create a disk image for the VM.

        Args:
            path: Path to create the disk (file path or zvol name)
            size_gb: Size in GB
            use_zvol: Use ZFS zvol instead of file
            zvol_parent: Parent ZFS dataset for zvol

        Returns:
            Dict with success status and disk path
        """
        try:
            if use_zvol and zvol_parent:
                # Create ZFS zvol
                zvol_name = f"{zvol_parent}/{os.path.basename(path)}"
                self.logger.info(_("Creating ZFS zvol: %s (%dG)"), zvol_name, size_gb)
                result = subprocess.run(  # nosec B603 B607
                    ["zfs", "create", "-V", f"{size_gb}G", zvol_name],
                    capture_output=True,
                    text=True,
                    timeout=120,
                    check=False,
                )
                if result.returncode != 0:
                    return {
                        "success": False,
                        "error": _("Failed to create zvol: %s") % result.stderr,
                    }
                return {"success": True, "path": f"/dev/zvol/{zvol_name}"}

            # Create file-based disk using truncate
            self.logger.info(_("Creating disk image: %s (%dG)"), path, size_gb)
            size_bytes = size_gb * 1024 * 1024 * 1024
            result = subprocess.run(  # nosec B603 B607
                ["truncate", "-s", str(size_bytes), path],
                capture_output=True,
                text=True,
                timeout=120,
                check=False,
            )
            if result.returncode != 0:
                return {
                    "success": False,
                    "error": _("Failed to create disk: %s") % result.stderr,
                }
            return {"success": True, "path": path}

        except Exception as error:
            return {"success": False, "error": str(error)}
