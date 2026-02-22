"""
Comprehensive unit tests for src.sysmanage_agent.operations.child_host_bhyve_images module.
Tests bhyve VM image handling for FreeBSD hosts.
"""

# pylint: disable=protected-access,redefined-outer-name

import subprocess
from unittest.mock import Mock, patch

import pytest

from src.sysmanage_agent.operations.child_host_bhyve_images import (
    BHYVE_IMAGES_DIR,
    BhyveImageHelper,
)


@pytest.fixture
def mock_logger():
    """Create a mock logger instance."""
    return Mock()


@pytest.fixture
def image_helper(mock_logger):
    """Create a BhyveImageHelper for testing."""
    return BhyveImageHelper(mock_logger)


class TestBhyveImageHelperInit:
    """Test cases for BhyveImageHelper initialization."""

    def test_init_sets_logger(self, mock_logger):
        """Test that __init__ sets the logger."""
        helper = BhyveImageHelper(mock_logger)
        assert helper.logger == mock_logger

    def test_bhyve_images_dir_constant(self):
        """Test that BHYVE_IMAGES_DIR is set correctly."""
        assert BHYVE_IMAGES_DIR == "/vm/images"


class TestIsQcow2Image:
    """Test cases for _is_qcow2_image method."""

    def test_is_qcow2_image_true(self, image_helper, tmp_path):
        """Test detecting qcow2 image by magic bytes."""
        qcow2_file = tmp_path / "test.qcow2"
        # QFI\xfb is the qcow2 magic header
        qcow2_file.write_bytes(b"QFI\xfb" + b"\x00" * 100)

        result = image_helper._is_qcow2_image(str(qcow2_file))

        assert result is True

    def test_is_qcow2_image_false_raw(self, image_helper, tmp_path):
        """Test detecting non-qcow2 (raw) image."""
        raw_file = tmp_path / "test.raw"
        # Raw images don't have qcow2 magic
        raw_file.write_bytes(b"\x00" * 100)

        result = image_helper._is_qcow2_image(str(raw_file))

        assert result is False

    def test_is_qcow2_image_false_other_format(self, image_helper, tmp_path):
        """Test detecting non-qcow2 image with different magic."""
        vdi_file = tmp_path / "test.vdi"
        # VDI has different magic
        vdi_file.write_bytes(b"<<< ")

        result = image_helper._is_qcow2_image(str(vdi_file))

        assert result is False

    def test_is_qcow2_image_file_not_found(self, image_helper):
        """Test handling non-existent file."""
        result = image_helper._is_qcow2_image("/nonexistent/path/image.qcow2")

        assert result is False

    def test_is_qcow2_image_permission_error(self, image_helper):
        """Test handling permission error when reading file."""
        with patch("builtins.open", side_effect=PermissionError("Access denied")):
            result = image_helper._is_qcow2_image("/some/protected/file")

        assert result is False

    def test_is_qcow2_image_empty_file(self, image_helper, tmp_path):
        """Test detecting qcow2 with empty file."""
        empty_file = tmp_path / "empty.img"
        empty_file.write_bytes(b"")

        result = image_helper._is_qcow2_image(str(empty_file))

        assert result is False

    def test_is_qcow2_image_partial_magic(self, image_helper, tmp_path):
        """Test file with partial qcow2 magic (less than 4 bytes)."""
        partial_file = tmp_path / "partial.img"
        partial_file.write_bytes(b"QFI")  # Missing the \xfb

        result = image_helper._is_qcow2_image(str(partial_file))

        assert result is False


class TestConvertQcow2ToRaw:
    """Test cases for _convert_qcow2_to_raw method."""

    def test_convert_qcow2_to_raw_success(self, image_helper):
        """Test successful qcow2 to raw conversion."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = ""
        mock_result.stderr = ""

        with patch("subprocess.run", return_value=mock_result) as mock_run:
            result = image_helper._convert_qcow2_to_raw(
                "/path/to/image.qcow2", "/path/to/image.raw"
            )

        assert result["success"] is True
        assert result["path"] == "/path/to/image.raw"
        mock_run.assert_called_once_with(
            [
                "qemu-img",
                "convert",
                "-f",
                "qcow2",
                "-O",
                "raw",
                "/path/to/image.qcow2",
                "/path/to/image.raw",
            ],
            capture_output=True,
            text=True,
            timeout=1800,
            check=False,
        )

    def test_convert_qcow2_to_raw_failure(self, image_helper):
        """Test failed qcow2 to raw conversion."""
        mock_result = Mock()
        mock_result.returncode = 1
        mock_result.stderr = "conversion error"

        with patch("subprocess.run", return_value=mock_result):
            result = image_helper._convert_qcow2_to_raw(
                "/path/to/image.qcow2", "/path/to/image.raw"
            )

        assert result["success"] is False
        assert "conversion error" in result["error"]

    def test_convert_qcow2_to_raw_qemu_not_found(self, image_helper):
        """Test conversion when qemu-img is not installed."""
        with patch("subprocess.run", side_effect=FileNotFoundError()):
            result = image_helper._convert_qcow2_to_raw(
                "/path/to/image.qcow2", "/path/to/image.raw"
            )

        assert result["success"] is False
        assert "qemu-img not found" in result["error"]
        assert "pkg install qemu-utils" in result["error"]

    def test_convert_qcow2_to_raw_timeout(self, image_helper):
        """Test conversion timeout."""
        with patch(
            "subprocess.run", side_effect=subprocess.TimeoutExpired("cmd", 1800)
        ):
            result = image_helper._convert_qcow2_to_raw(
                "/path/to/image.qcow2", "/path/to/image.raw"
            )

        assert result["success"] is False
        assert "timed out" in result["error"].lower()

    def test_convert_qcow2_to_raw_generic_exception(self, image_helper):
        """Test conversion with generic exception."""
        with patch("subprocess.run", side_effect=Exception("Unexpected error")):
            result = image_helper._convert_qcow2_to_raw(
                "/path/to/image.qcow2", "/path/to/image.raw"
            )

        assert result["success"] is False
        assert "Unexpected error" in result["error"]

    def test_convert_qcow2_to_raw_logs_info(self, image_helper, mock_logger):
        """Test that conversion logs info messages."""
        mock_result = Mock()
        mock_result.returncode = 0

        with patch("subprocess.run", return_value=mock_result):
            image_helper._convert_qcow2_to_raw(
                "/path/to/image.qcow2", "/path/to/image.raw"
            )

        # Should log at least one info message
        assert mock_logger.info.called


class TestGetCachePaths:
    """Test cases for _get_cache_paths method."""

    def test_get_cache_paths_basic_url(self, image_helper):
        """Test cache paths for basic URL."""
        url = "https://example.com/images/freebsd.qcow2"

        result = image_helper._get_cache_paths(url)

        assert result["download_dir"] == "/vm/images/.downloads"
        assert result["cached_path"].startswith("/vm/images/.downloads/")
        assert result["cached_path"].endswith("_freebsd.qcow2")
        assert result["raw_cached_path"].endswith("_freebsd.qcow2.raw")
        assert result["is_xz"] is False
        # Decompressed path should equal cached path for non-xz
        assert result["decompressed_path"] == result["cached_path"]

    def test_get_cache_paths_xz_url(self, image_helper):
        """Test cache paths for xz compressed URL."""
        url = "https://example.com/images/freebsd.qcow2.xz"

        result = image_helper._get_cache_paths(url)

        assert result["is_xz"] is True
        assert result["cached_path"].endswith(".qcow2.xz")
        # Decompressed path should have .xz removed
        assert result["decompressed_path"].endswith(".qcow2")
        assert not result["decompressed_path"].endswith(".xz")

    def test_get_cache_paths_url_with_query_params(self, image_helper):
        """Test cache paths for URL with query parameters."""
        url = "https://example.com/images/freebsd.qcow2?token=abc123&version=1"

        result = image_helper._get_cache_paths(url)

        # Should strip query parameters from filename
        assert "?" not in result["cached_path"]
        assert "token" not in result["cached_path"]
        assert "_freebsd.qcow2" in result["cached_path"]

    def test_get_cache_paths_different_urls_different_hashes(self, image_helper):
        """Test that different URLs produce different cache paths."""
        url1 = "https://example.com/images/freebsd-14.qcow2"
        url2 = "https://example.com/images/freebsd-15.qcow2"

        result1 = image_helper._get_cache_paths(url1)
        result2 = image_helper._get_cache_paths(url2)

        # Should have different hashes
        assert result1["cached_path"] != result2["cached_path"]

    def test_get_cache_paths_same_url_same_hash(self, image_helper):
        """Test that same URL produces same cache path."""
        url = "https://example.com/images/freebsd.qcow2"

        result1 = image_helper._get_cache_paths(url)
        result2 = image_helper._get_cache_paths(url)

        assert result1["cached_path"] == result2["cached_path"]


class TestDownloadImageFile:
    """Test cases for _download_image_file method."""

    def test_download_with_fetch_success(self, image_helper):
        """Test successful download with fetch."""
        mock_result = Mock()
        mock_result.returncode = 0

        with patch("subprocess.run", return_value=mock_result) as mock_run:
            result = image_helper._download_image_file(
                "https://example.com/image.qcow2", "/tmp/image.qcow2"
            )

        assert result["success"] is True
        mock_run.assert_called_once_with(
            ["fetch", "-o", "/tmp/image.qcow2", "https://example.com/image.qcow2"],
            capture_output=True,
            text=True,
            timeout=1800,
            check=False,
        )

    def test_download_fallback_to_curl(self, image_helper):
        """Test fallback to curl when fetch fails."""
        fetch_result = Mock()
        fetch_result.returncode = 1

        curl_result = Mock()
        curl_result.returncode = 0

        with patch(
            "subprocess.run", side_effect=[fetch_result, curl_result]
        ) as mock_run:
            result = image_helper._download_image_file(
                "https://example.com/image.qcow2", "/tmp/image.qcow2"
            )

        assert result["success"] is True
        assert mock_run.call_count == 2
        # Second call should be curl
        second_call_args = mock_run.call_args_list[1][0][0]
        assert second_call_args[0] == "curl"
        assert "-L" in second_call_args

    def test_download_both_fail(self, image_helper):
        """Test when both fetch and curl fail."""
        fetch_result = Mock()
        fetch_result.returncode = 1
        fetch_result.stderr = "fetch failed"

        curl_result = Mock()
        curl_result.returncode = 1
        curl_result.stderr = "curl error: connection refused"

        with patch("subprocess.run", side_effect=[fetch_result, curl_result]):
            result = image_helper._download_image_file(
                "https://example.com/image.qcow2", "/tmp/image.qcow2"
            )

        assert result["success"] is False
        assert "curl error" in result["error"]


class TestDecompressXzArchive:
    """Test cases for _decompress_xz_archive method."""

    def test_decompress_xz_success(self, image_helper):
        """Test successful xz decompression."""
        mock_result = Mock()
        mock_result.returncode = 0

        with patch("subprocess.run", return_value=mock_result) as mock_run:
            result = image_helper._decompress_xz_archive("/tmp/image.qcow2.xz")

        assert result["success"] is True
        mock_run.assert_called_once_with(
            ["xz", "-dk", "/tmp/image.qcow2.xz"],
            capture_output=True,
            text=True,
            timeout=600,
            check=False,
        )

    def test_decompress_xz_failure(self, image_helper):
        """Test xz decompression failure."""
        mock_result = Mock()
        mock_result.returncode = 1
        mock_result.stderr = "xz: /tmp/image.qcow2.xz: File format not recognized"

        with patch("subprocess.run", return_value=mock_result):
            result = image_helper._decompress_xz_archive("/tmp/image.qcow2.xz")

        assert result["success"] is False
        assert "File format not recognized" in result["error"]

    def test_decompress_xz_logs_info(self, image_helper, mock_logger):
        """Test that decompression logs info message."""
        mock_result = Mock()
        mock_result.returncode = 0

        with patch("subprocess.run", return_value=mock_result):
            image_helper._decompress_xz_archive("/tmp/image.qcow2.xz")

        mock_logger.info.assert_called()


class TestPrepareFinalImage:
    """Test cases for _prepare_final_image method."""

    def test_prepare_final_image_qcow2_success(self, image_helper, tmp_path):
        """Test preparing qcow2 image (conversion required)."""
        source = tmp_path / "source.qcow2"
        source.write_bytes(b"QFI\xfb" + b"\x00" * 100)  # qcow2 magic

        raw_cache = tmp_path / "cache.raw"
        dest = tmp_path / "dest.raw"

        convert_result = {"success": True, "path": str(raw_cache)}

        with patch.object(
            image_helper, "_convert_qcow2_to_raw", return_value=convert_result
        ):
            with patch("shutil.copy2") as mock_copy:
                result = image_helper._prepare_final_image(
                    str(source), str(raw_cache), str(dest)
                )

        assert result["success"] is True
        # Should copy from raw_cache to dest
        mock_copy.assert_called_once_with(str(raw_cache), str(dest))

    def test_prepare_final_image_raw_success(self, image_helper, tmp_path):
        """Test preparing raw image (no conversion needed)."""
        source = tmp_path / "source.raw"
        source.write_bytes(b"\x00" * 100)  # Not qcow2

        raw_cache = tmp_path / "cache.raw"
        dest = tmp_path / "dest.raw"

        with patch("shutil.copy2") as mock_copy:
            result = image_helper._prepare_final_image(
                str(source), str(raw_cache), str(dest)
            )

        assert result["success"] is True
        # Should copy directly from source to dest
        mock_copy.assert_called_once_with(str(source), str(dest))

    def test_prepare_final_image_conversion_fails(self, image_helper, tmp_path):
        """Test preparing image when conversion fails."""
        source = tmp_path / "source.qcow2"
        source.write_bytes(b"QFI\xfb" + b"\x00" * 100)  # qcow2 magic

        raw_cache = tmp_path / "cache.raw"
        dest = tmp_path / "dest.raw"

        convert_result = {"success": False, "error": "Conversion failed"}

        with patch.object(
            image_helper, "_convert_qcow2_to_raw", return_value=convert_result
        ):
            result = image_helper._prepare_final_image(
                str(source), str(raw_cache), str(dest)
            )

        assert result["success"] is False
        assert "Conversion failed" in result["error"]


class TestDownloadCloudImage:
    """Test cases for download_cloud_image method."""

    def test_download_cloud_image_cached_raw(self, image_helper, tmp_path):
        """Test using cached raw image."""
        url = "https://example.com/freebsd.qcow2"
        dest = str(tmp_path / "vm.raw")

        # Create a mock cached raw file
        cached_raw = tmp_path / ".downloads" / "abc12345_freebsd.qcow2.raw"
        cached_raw.parent.mkdir(parents=True, exist_ok=True)
        cached_raw.write_bytes(b"\x00" * 100)

        def mock_get_cache_paths(_url):
            return {
                "download_dir": str(tmp_path / ".downloads"),
                "cached_path": str(tmp_path / ".downloads" / "abc12345_freebsd.qcow2"),
                "raw_cached_path": str(cached_raw),
                "decompressed_path": str(
                    tmp_path / ".downloads" / "abc12345_freebsd.qcow2"
                ),
                "is_xz": False,
            }

        with patch.object(image_helper, "_get_cache_paths", mock_get_cache_paths):
            with patch("os.path.exists", return_value=True):
                with patch("shutil.copy2") as mock_copy:
                    with patch.object(
                        image_helper, "_resize_disk_image"
                    ) as mock_resize:
                        result = image_helper.download_cloud_image(url, dest, 30)

        assert result["success"] is True
        assert result["path"] == dest
        mock_copy.assert_called_once()
        mock_resize.assert_called_once_with(dest, 30)

    def test_download_cloud_image_fresh_download(self, image_helper, tmp_path):
        """Test fresh download when no cache exists."""
        url = "https://example.com/freebsd.qcow2"
        dest = str(tmp_path / "vm.raw")

        def mock_get_cache_paths(_url):
            return {
                "download_dir": str(tmp_path / ".downloads"),
                "cached_path": str(tmp_path / ".downloads" / "abc_freebsd.qcow2"),
                "raw_cached_path": str(
                    tmp_path / ".downloads" / "abc_freebsd.qcow2.raw"
                ),
                "decompressed_path": str(tmp_path / ".downloads" / "abc_freebsd.qcow2"),
                "is_xz": False,
            }

        with patch.object(image_helper, "_get_cache_paths", mock_get_cache_paths):
            with patch("os.makedirs") as mock_makedirs:
                with patch("os.path.exists", return_value=False):
                    with patch.object(
                        image_helper,
                        "_download_image_file",
                        return_value={"success": True},
                    ) as mock_download:
                        with patch.object(
                            image_helper,
                            "_prepare_final_image",
                            return_value={"success": True},
                        ):
                            with patch.object(image_helper, "_resize_disk_image"):
                                result = image_helper.download_cloud_image(url, dest)

        assert result["success"] is True
        mock_makedirs.assert_called_once()
        mock_download.assert_called_once()

    def test_download_cloud_image_xz_decompression(self, image_helper, tmp_path):
        """Test downloading and decompressing xz archive."""
        url = "https://example.com/freebsd.qcow2.xz"
        dest = str(tmp_path / "vm.raw")

        def mock_get_cache_paths(_url):
            return {
                "download_dir": str(tmp_path / ".downloads"),
                "cached_path": str(tmp_path / ".downloads" / "abc_freebsd.qcow2.xz"),
                "raw_cached_path": str(
                    tmp_path / ".downloads" / "abc_freebsd.qcow2.xz.raw"
                ),
                "decompressed_path": str(tmp_path / ".downloads" / "abc_freebsd.qcow2"),
                "is_xz": True,
            }

        with patch.object(image_helper, "_get_cache_paths", mock_get_cache_paths):
            with patch("os.makedirs"):
                with patch("os.path.exists", return_value=False):
                    with patch.object(
                        image_helper,
                        "_download_image_file",
                        return_value={"success": True},
                    ):
                        with patch.object(
                            image_helper,
                            "_decompress_xz_archive",
                            return_value={"success": True},
                        ) as mock_decompress:
                            with patch.object(
                                image_helper,
                                "_prepare_final_image",
                                return_value={"success": True},
                            ):
                                with patch.object(image_helper, "_resize_disk_image"):
                                    result = image_helper.download_cloud_image(
                                        url, dest
                                    )

        assert result["success"] is True
        mock_decompress.assert_called_once()

    def test_download_cloud_image_download_fails(self, image_helper, tmp_path):
        """Test handling download failure."""
        url = "https://example.com/freebsd.qcow2"
        dest = str(tmp_path / "vm.raw")

        def mock_get_cache_paths(_url):
            return {
                "download_dir": str(tmp_path / ".downloads"),
                "cached_path": str(tmp_path / ".downloads" / "abc_freebsd.qcow2"),
                "raw_cached_path": str(
                    tmp_path / ".downloads" / "abc_freebsd.qcow2.raw"
                ),
                "decompressed_path": str(tmp_path / ".downloads" / "abc_freebsd.qcow2"),
                "is_xz": False,
            }

        with patch.object(image_helper, "_get_cache_paths", mock_get_cache_paths):
            with patch("os.makedirs"):
                with patch("os.path.exists", return_value=False):
                    with patch.object(
                        image_helper,
                        "_download_image_file",
                        return_value={"success": False, "error": "Network error"},
                    ):
                        result = image_helper.download_cloud_image(url, dest)

        assert result["success"] is False
        assert "Network error" in result["error"]

    def test_download_cloud_image_decompression_fails(self, image_helper, tmp_path):
        """Test handling decompression failure."""
        url = "https://example.com/freebsd.qcow2.xz"
        dest = str(tmp_path / "vm.raw")

        def mock_get_cache_paths(_url):
            return {
                "download_dir": str(tmp_path / ".downloads"),
                "cached_path": str(tmp_path / ".downloads" / "abc_freebsd.qcow2.xz"),
                "raw_cached_path": str(
                    tmp_path / ".downloads" / "abc_freebsd.qcow2.xz.raw"
                ),
                "decompressed_path": str(tmp_path / ".downloads" / "abc_freebsd.qcow2"),
                "is_xz": True,
            }

        with patch.object(image_helper, "_get_cache_paths", mock_get_cache_paths):
            with patch("os.makedirs"):
                with patch("os.path.exists", return_value=False):
                    with patch.object(
                        image_helper,
                        "_download_image_file",
                        return_value={"success": True},
                    ):
                        with patch.object(
                            image_helper,
                            "_decompress_xz_archive",
                            return_value={"success": False, "error": "Corrupt archive"},
                        ):
                            result = image_helper.download_cloud_image(url, dest)

        assert result["success"] is False
        assert "Corrupt archive" in result["error"]

    def test_download_cloud_image_preparation_fails(self, image_helper, tmp_path):
        """Test handling image preparation failure."""
        url = "https://example.com/freebsd.qcow2"
        dest = str(tmp_path / "vm.raw")

        def mock_get_cache_paths(_url):
            return {
                "download_dir": str(tmp_path / ".downloads"),
                "cached_path": str(tmp_path / ".downloads" / "abc_freebsd.qcow2"),
                "raw_cached_path": str(
                    tmp_path / ".downloads" / "abc_freebsd.qcow2.raw"
                ),
                "decompressed_path": str(tmp_path / ".downloads" / "abc_freebsd.qcow2"),
                "is_xz": False,
            }

        with patch.object(image_helper, "_get_cache_paths", mock_get_cache_paths):
            with patch("os.makedirs"):
                with patch("os.path.exists", return_value=False):
                    with patch.object(
                        image_helper,
                        "_download_image_file",
                        return_value={"success": True},
                    ):
                        with patch.object(
                            image_helper,
                            "_prepare_final_image",
                            return_value={"success": False, "error": "Copy failed"},
                        ):
                            result = image_helper.download_cloud_image(url, dest)

        assert result["success"] is False
        assert "Copy failed" in result["error"]

    def test_download_cloud_image_timeout(self, image_helper, tmp_path):
        """Test handling download timeout."""
        url = "https://example.com/freebsd.qcow2"
        dest = str(tmp_path / "vm.raw")

        def mock_get_cache_paths(_url):
            return {
                "download_dir": str(tmp_path / ".downloads"),
                "cached_path": str(tmp_path / ".downloads" / "abc_freebsd.qcow2"),
                "raw_cached_path": str(
                    tmp_path / ".downloads" / "abc_freebsd.qcow2.raw"
                ),
                "decompressed_path": str(tmp_path / ".downloads" / "abc_freebsd.qcow2"),
                "is_xz": False,
            }

        with patch.object(image_helper, "_get_cache_paths", mock_get_cache_paths):
            with patch("os.makedirs"):
                with patch("os.path.exists", return_value=False):
                    with patch.object(
                        image_helper,
                        "_download_image_file",
                        side_effect=subprocess.TimeoutExpired("cmd", 1800),
                    ):
                        result = image_helper.download_cloud_image(url, dest)

        assert result["success"] is False
        assert "timed out" in result["error"].lower()

    def test_download_cloud_image_generic_exception(self, image_helper, tmp_path):
        """Test handling generic exception."""
        url = "https://example.com/freebsd.qcow2"
        dest = str(tmp_path / "vm.raw")

        with patch.object(
            image_helper, "_get_cache_paths", side_effect=Exception("Unexpected error")
        ):
            result = image_helper.download_cloud_image(url, dest)

        assert result["success"] is False
        assert "Unexpected error" in result["error"]

    def test_download_cloud_image_uses_cached_decompressed(
        self, image_helper, tmp_path
    ):
        """Test using cached decompressed image (not raw)."""
        url = "https://example.com/freebsd.qcow2"
        dest = str(tmp_path / "vm.raw")

        # Simulate: decompressed exists but raw_cached does not
        def mock_exists(path):
            if "raw" in path:
                return False  # raw_cached_path doesn't exist
            if ".downloads" in path:
                return True  # decompressed_path exists
            return False

        def mock_get_cache_paths(_url):
            return {
                "download_dir": str(tmp_path / ".downloads"),
                "cached_path": str(tmp_path / ".downloads" / "abc_freebsd.qcow2"),
                "raw_cached_path": str(
                    tmp_path / ".downloads" / "abc_freebsd.qcow2.raw"
                ),
                "decompressed_path": str(tmp_path / ".downloads" / "abc_freebsd.qcow2"),
                "is_xz": False,
            }

        with patch.object(image_helper, "_get_cache_paths", mock_get_cache_paths):
            with patch("os.makedirs"):
                with patch("os.path.exists", side_effect=mock_exists):
                    with patch.object(
                        image_helper,
                        "_prepare_final_image",
                        return_value={"success": True},
                    ) as mock_prepare:
                        with patch.object(image_helper, "_resize_disk_image"):
                            result = image_helper.download_cloud_image(url, dest)

        assert result["success"] is True
        # Should call prepare without download
        mock_prepare.assert_called_once()

    def test_download_cloud_image_logs_info(self, image_helper, mock_logger, tmp_path):
        """Test that download logs info messages."""
        url = "https://example.com/freebsd.qcow2"
        dest = str(tmp_path / "vm.raw")

        def mock_get_cache_paths(_url):
            return {
                "download_dir": str(tmp_path / ".downloads"),
                "cached_path": str(tmp_path / ".downloads" / "abc_freebsd.qcow2"),
                "raw_cached_path": str(
                    tmp_path / ".downloads" / "abc_freebsd.qcow2.raw"
                ),
                "decompressed_path": str(tmp_path / ".downloads" / "abc_freebsd.qcow2"),
                "is_xz": False,
            }

        with patch.object(image_helper, "_get_cache_paths", mock_get_cache_paths):
            with patch("os.makedirs"):
                with patch("os.path.exists", return_value=False):
                    with patch.object(
                        image_helper,
                        "_download_image_file",
                        return_value={"success": True},
                    ):
                        with patch.object(
                            image_helper,
                            "_prepare_final_image",
                            return_value={"success": True},
                        ):
                            with patch.object(image_helper, "_resize_disk_image"):
                                image_helper.download_cloud_image(url, dest)

        mock_logger.info.assert_called()


class TestResizeDiskImage:
    """Test cases for _resize_disk_image method."""

    def test_resize_disk_image_success(self, image_helper, tmp_path):
        """Test successful disk resize."""
        disk_file = tmp_path / "vm.raw"
        disk_file.write_bytes(b"\x00" * 1024)  # 1KB file

        mock_result = Mock()
        mock_result.returncode = 0

        with patch("subprocess.run", return_value=mock_result) as mock_run:
            with patch("os.path.getsize", return_value=1024):
                image_helper._resize_disk_image(str(disk_file), 20)

        # Should call truncate to resize to 20GB
        expected_size = 20 * 1024 * 1024 * 1024
        mock_run.assert_called_once_with(
            ["truncate", "-s", str(expected_size), str(disk_file)],
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )

    def test_resize_disk_image_already_large_enough(self, image_helper, tmp_path):
        """Test skipping resize when image is already large enough."""
        disk_file = tmp_path / "vm.raw"

        # Size is already 20GB
        current_size = 20 * 1024 * 1024 * 1024

        with patch("os.path.getsize", return_value=current_size):
            with patch("subprocess.run") as mock_run:
                image_helper._resize_disk_image(str(disk_file), 20)

        # Should not call truncate
        mock_run.assert_not_called()

    def test_resize_disk_image_larger_than_target(self, image_helper, tmp_path):
        """Test skipping resize when image is larger than target."""
        disk_file = tmp_path / "vm.raw"

        # Size is 30GB, target is 20GB
        current_size = 30 * 1024 * 1024 * 1024

        with patch("os.path.getsize", return_value=current_size):
            with patch("subprocess.run") as mock_run:
                image_helper._resize_disk_image(str(disk_file), 20)

        # Should not call truncate (don't shrink)
        mock_run.assert_not_called()

    def test_resize_disk_image_truncate_fails(
        self, image_helper, mock_logger, tmp_path
    ):
        """Test handling truncate failure."""
        disk_file = tmp_path / "vm.raw"

        mock_result = Mock()
        mock_result.returncode = 1
        mock_result.stderr = "truncate: cannot extend 'vm.raw': Permission denied"

        with patch("os.path.getsize", return_value=1024):
            with patch("subprocess.run", return_value=mock_result):
                # Should not raise, just log warning
                image_helper._resize_disk_image(str(disk_file), 20)

        mock_logger.warning.assert_called()

    def test_resize_disk_image_exception(self, image_helper, mock_logger, tmp_path):
        """Test handling exception during resize."""
        disk_file = tmp_path / "vm.raw"

        with patch("os.path.getsize", side_effect=Exception("Disk error")):
            # Should not raise, just log warning
            image_helper._resize_disk_image(str(disk_file), 20)

        mock_logger.warning.assert_called()


class TestCreateDiskImage:
    """Test cases for create_disk_image method."""

    def test_create_file_disk_success(self, image_helper):
        """Test successful file-based disk creation."""
        mock_result = Mock()
        mock_result.returncode = 0

        with patch("subprocess.run", return_value=mock_result) as mock_run:
            result = image_helper.create_disk_image("/vm/disk.raw", 50)

        assert result["success"] is True
        assert result["path"] == "/vm/disk.raw"

        expected_size = 50 * 1024 * 1024 * 1024
        mock_run.assert_called_once_with(
            ["truncate", "-s", str(expected_size), "/vm/disk.raw"],
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )

    def test_create_file_disk_failure(self, image_helper):
        """Test file-based disk creation failure."""
        mock_result = Mock()
        mock_result.returncode = 1
        mock_result.stderr = "No space left on device"

        with patch("subprocess.run", return_value=mock_result):
            result = image_helper.create_disk_image("/vm/disk.raw", 50)

        assert result["success"] is False
        assert "No space left on device" in result["error"]

    def test_create_zvol_disk_success(self, image_helper):
        """Test successful ZFS zvol creation."""
        mock_result = Mock()
        mock_result.returncode = 0

        with patch("subprocess.run", return_value=mock_result) as mock_run:
            result = image_helper.create_disk_image(
                "/vm/disk", 50, use_zvol=True, zvol_parent="zpool/vms"
            )

        assert result["success"] is True
        assert result["path"] == "/dev/zvol/zpool/vms/disk"

        mock_run.assert_called_once_with(
            ["zfs", "create", "-V", "50G", "zpool/vms/disk"],
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )

    def test_create_zvol_disk_failure(self, image_helper):
        """Test ZFS zvol creation failure."""
        mock_result = Mock()
        mock_result.returncode = 1
        mock_result.stderr = "dataset already exists"

        with patch("subprocess.run", return_value=mock_result):
            result = image_helper.create_disk_image(
                "/vm/disk", 50, use_zvol=True, zvol_parent="zpool/vms"
            )

        assert result["success"] is False
        assert "dataset already exists" in result["error"]

    def test_create_disk_use_zvol_without_parent(self, image_helper):
        """Test zvol creation without parent falls back to file-based."""
        mock_result = Mock()
        mock_result.returncode = 0

        with patch("subprocess.run", return_value=mock_result) as mock_run:
            # use_zvol=True but zvol_parent=""
            result = image_helper.create_disk_image(
                "/vm/disk.raw", 50, use_zvol=True, zvol_parent=""
            )

        assert result["success"] is True
        # Should use truncate for file-based disk
        call_args = mock_run.call_args[0][0]
        assert call_args[0] == "truncate"

    def test_create_disk_exception(self, image_helper):
        """Test handling exception during disk creation."""
        with patch("subprocess.run", side_effect=Exception("ZFS error")):
            result = image_helper.create_disk_image("/vm/disk.raw", 50)

        assert result["success"] is False
        assert "ZFS error" in result["error"]

    def test_create_disk_logs_info(self, image_helper, mock_logger):
        """Test that disk creation logs info messages."""
        mock_result = Mock()
        mock_result.returncode = 0

        with patch("subprocess.run", return_value=mock_result):
            image_helper.create_disk_image("/vm/disk.raw", 50)

        mock_logger.info.assert_called()

    def test_create_zvol_logs_info(self, image_helper, mock_logger):
        """Test that zvol creation logs info messages."""
        mock_result = Mock()
        mock_result.returncode = 0

        with patch("subprocess.run", return_value=mock_result):
            image_helper.create_disk_image(
                "/vm/disk", 50, use_zvol=True, zvol_parent="zpool/vms"
            )

        mock_logger.info.assert_called()


class TestBhyveImageHelperEdgeCases:
    """Edge case tests for BhyveImageHelper."""

    def test_is_qcow2_with_io_error(self, image_helper):
        """Test _is_qcow2_image with IOError."""
        with patch("builtins.open", side_effect=IOError("I/O error")):
            result = image_helper._is_qcow2_image("/some/path")

        assert result is False

    def test_convert_with_empty_stderr(self, image_helper):
        """Test conversion with empty stderr on failure."""
        mock_result = Mock()
        mock_result.returncode = 1
        mock_result.stderr = ""

        with patch("subprocess.run", return_value=mock_result):
            result = image_helper._convert_qcow2_to_raw("/path/src", "/path/dst")

        assert result["success"] is False

    def test_get_cache_paths_url_with_fragment(self, image_helper):
        """Test cache paths for URL with fragment identifier."""
        url = "https://example.com/freebsd.qcow2#section"

        result = image_helper._get_cache_paths(url)

        # Filename extraction should handle fragments
        assert (
            result["cached_path"].endswith("_freebsd.qcow2#section")
            or "#" not in result["cached_path"]
        )

    def test_create_disk_with_zero_size(self, image_helper):
        """Test creating disk with zero size."""
        mock_result = Mock()
        mock_result.returncode = 0

        with patch("subprocess.run", return_value=mock_result) as mock_run:
            result = image_helper.create_disk_image("/vm/disk.raw", 0)

        assert result["success"] is True
        # Should call truncate with 0 bytes
        call_args = mock_run.call_args[0][0]
        assert call_args[2] == "0"

    def test_resize_with_zero_target(self, image_helper):
        """Test resize with zero target size."""
        with patch("os.path.getsize", return_value=1024):
            with patch("subprocess.run") as mock_run:
                image_helper._resize_disk_image("/vm/disk.raw", 0)

        # Should not resize since current (1024) > target (0)
        mock_run.assert_not_called()

    def test_download_handles_special_characters_in_url(self, image_helper, tmp_path):
        """Test downloading URL with special characters."""
        url = "https://example.com/images/freebsd%20image.qcow2"
        dest = str(tmp_path / "vm.raw")

        def mock_get_cache_paths(_url):
            return {
                "download_dir": str(tmp_path / ".downloads"),
                "cached_path": str(
                    tmp_path / ".downloads" / "abc_freebsd%20image.qcow2"
                ),
                "raw_cached_path": str(
                    tmp_path / ".downloads" / "abc_freebsd%20image.qcow2.raw"
                ),
                "decompressed_path": str(
                    tmp_path / ".downloads" / "abc_freebsd%20image.qcow2"
                ),
                "is_xz": False,
            }

        with patch.object(image_helper, "_get_cache_paths", mock_get_cache_paths):
            with patch("os.makedirs"):
                with patch("os.path.exists", return_value=False):
                    with patch.object(
                        image_helper,
                        "_download_image_file",
                        return_value={"success": True},
                    ):
                        with patch.object(
                            image_helper,
                            "_prepare_final_image",
                            return_value={"success": True},
                        ):
                            with patch.object(image_helper, "_resize_disk_image"):
                                result = image_helper.download_cloud_image(url, dest)

        assert result["success"] is True


class TestBhyveImageHelperIntegration:
    """Integration-style tests for BhyveImageHelper."""

    def test_full_download_workflow_qcow2(self, mock_logger, tmp_path):
        """Test complete download workflow for qcow2 image."""
        helper = BhyveImageHelper(mock_logger)
        url = "https://example.com/freebsd.qcow2"
        dest = str(tmp_path / "vm.raw")

        # Create mock qcow2 file in cache
        download_dir = tmp_path / ".downloads"
        download_dir.mkdir(parents=True, exist_ok=True)

        with patch.object(
            helper,
            "_get_cache_paths",
            return_value={
                "download_dir": str(download_dir),
                "cached_path": str(download_dir / "abc_freebsd.qcow2"),
                "raw_cached_path": str(download_dir / "abc_freebsd.qcow2.raw"),
                "decompressed_path": str(download_dir / "abc_freebsd.qcow2"),
                "is_xz": False,
            },
        ):
            with patch("os.makedirs"):
                with patch("os.path.exists", return_value=False):
                    with patch.object(
                        helper, "_download_image_file", return_value={"success": True}
                    ):
                        with patch.object(helper, "_is_qcow2_image", return_value=True):
                            with patch.object(
                                helper,
                                "_convert_qcow2_to_raw",
                                return_value={
                                    "success": True,
                                    "path": str(download_dir / "abc_freebsd.qcow2.raw"),
                                },
                            ):
                                with patch("shutil.copy2"):
                                    with patch("os.path.getsize", return_value=1024):
                                        with patch(
                                            "subprocess.run",
                                            return_value=Mock(returncode=0),
                                        ):
                                            result = helper.download_cloud_image(
                                                url, dest, 20
                                            )

        assert result["success"] is True
        assert result["path"] == dest

    def test_full_download_workflow_raw(self, mock_logger, tmp_path):
        """Test complete download workflow for raw image."""
        helper = BhyveImageHelper(mock_logger)
        url = "https://example.com/freebsd.raw"
        dest = str(tmp_path / "vm.raw")

        download_dir = tmp_path / ".downloads"
        download_dir.mkdir(parents=True, exist_ok=True)

        with patch.object(
            helper,
            "_get_cache_paths",
            return_value={
                "download_dir": str(download_dir),
                "cached_path": str(download_dir / "abc_freebsd.raw"),
                "raw_cached_path": str(download_dir / "abc_freebsd.raw.raw"),
                "decompressed_path": str(download_dir / "abc_freebsd.raw"),
                "is_xz": False,
            },
        ):
            with patch("os.makedirs"):
                with patch("os.path.exists", return_value=False):
                    with patch.object(
                        helper, "_download_image_file", return_value={"success": True}
                    ):
                        with patch.object(
                            helper, "_is_qcow2_image", return_value=False
                        ):
                            with patch("shutil.copy2"):
                                with patch("os.path.getsize", return_value=1024):
                                    with patch(
                                        "subprocess.run",
                                        return_value=Mock(returncode=0),
                                    ):
                                        result = helper.download_cloud_image(
                                            url, dest, 20
                                        )

        assert result["success"] is True
        assert result["path"] == dest
