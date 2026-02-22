"""
Comprehensive unit tests for KVM/libvirt VM creation operations.

Tests cover:
- VM existence checking
- Disk image creation
- Cloud image downloading and caching
- XZ decompression
- Domain XML generation
- VM definition and startup
- IP address detection and extraction
- SSH availability checking
- VM disk preparation
- VM provisioning
- FreeBSD bootstrap
- Full VM creation workflow
- VM listing
- Error handling and edge cases
"""

# pylint: disable=redefined-outer-name,protected-access,too-many-public-methods

import logging
import os
import subprocess
from unittest.mock import AsyncMock, Mock, patch

import pytest

from src.sysmanage_agent.operations.child_host_kvm_creation import (
    KvmCreation,
    KVM_IMAGES_DIR,
)
from src.sysmanage_agent.operations.child_host_kvm_types import KvmVmConfig


@pytest.fixture
def logger():
    """Create a logger for testing."""
    return logging.getLogger("test_kvm_creation")


@pytest.fixture
def kvm_creation(logger):
    """Create a KvmCreation instance for testing."""
    return KvmCreation(logger)


@pytest.fixture
def sample_vm_config():
    """Create a sample VM configuration for testing."""
    return KvmVmConfig(
        distribution="ubuntu:22.04",
        vm_name="test-vm",
        hostname="test.example.com",
        username="admin",
        password_hash="$6$rounds=5000$saltsalt$hashhashhashhash",
        server_url="https://server.example.com",
        agent_install_commands=["apt update", "apt install -y sysmanage-agent"],
    )


@pytest.fixture
def freebsd_vm_config():
    """Create a FreeBSD VM configuration for testing."""
    return KvmVmConfig(
        distribution="freebsd:14.0",
        vm_name="freebsd-test-vm",
        hostname="freebsd.example.com",
        username="admin",
        password_hash="$6$rounds=5000$saltsalt$hashhashhashhash",
        server_url="https://server.example.com",
        agent_install_commands=["pkg install -y sysmanage-agent"],
        cloud_image_url="https://example.com/freebsd.qcow2.xz",
    )


class TestKvmCreationInit:
    """Tests for KvmCreation initialization."""

    def test_init_sets_logger(self, kvm_creation, logger):
        """Test that __init__ sets logger."""
        assert kvm_creation.logger == logger

    def test_init_creates_cloudinit(self, kvm_creation):
        """Test that __init__ creates cloud-init helper."""
        assert kvm_creation._cloudinit is not None

    def test_init_creates_freebsd(self, kvm_creation):
        """Test that __init__ creates FreeBSD provisioner."""
        assert kvm_creation._freebsd is not None


class TestIsFreebsd:
    """Tests for _is_freebsd method."""

    def test_is_freebsd_true(self, kvm_creation, freebsd_vm_config):
        """Test _is_freebsd returns True for FreeBSD config."""
        with patch.object(kvm_creation._freebsd, "is_freebsd", return_value=True):
            result = kvm_creation._is_freebsd(freebsd_vm_config)
        assert result is True

    def test_is_freebsd_false(self, kvm_creation, sample_vm_config):
        """Test _is_freebsd returns False for non-FreeBSD config."""
        with patch.object(kvm_creation._freebsd, "is_freebsd", return_value=False):
            result = kvm_creation._is_freebsd(sample_vm_config)
        assert result is False


class TestVmExists:
    """Tests for _vm_exists method."""

    def test_vm_exists_true(self, kvm_creation):
        """Test _vm_exists returns True when VM exists."""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = Mock(returncode=0)
            result = kvm_creation._vm_exists("existing-vm")
        assert result is True
        mock_run.assert_called_once()

    def test_vm_exists_false(self, kvm_creation):
        """Test _vm_exists returns False when VM doesn't exist."""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = Mock(returncode=1)
            result = kvm_creation._vm_exists("nonexistent-vm")
        assert result is False

    def test_vm_exists_exception(self, kvm_creation):
        """Test _vm_exists handles exceptions gracefully."""
        with patch("subprocess.run", side_effect=Exception("Connection error")):
            result = kvm_creation._vm_exists("test-vm")
        assert result is False

    def test_vm_exists_timeout(self, kvm_creation):
        """Test _vm_exists handles timeout gracefully."""
        with patch(
            "subprocess.run", side_effect=subprocess.TimeoutExpired("virsh", 30)
        ):
            result = kvm_creation._vm_exists("test-vm")
        assert result is False


class TestCreateDiskImage:
    """Tests for _create_disk_image method."""

    def test_create_disk_image_success(self, kvm_creation):
        """Test creating disk image successfully."""
        with patch("os.makedirs"):
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = Mock(returncode=0, stdout="", stderr="")
                result = kvm_creation._create_disk_image(
                    "/var/lib/libvirt/images/test.qcow2", "20G"
                )
        assert result["success"] is True
        assert result["path"] == "/var/lib/libvirt/images/test.qcow2"

    def test_create_disk_image_with_raw_format(self, kvm_creation):
        """Test creating disk image with raw format."""
        with patch("os.makedirs"):
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = Mock(returncode=0, stdout="", stderr="")
                result = kvm_creation._create_disk_image(
                    "/var/lib/libvirt/images/test.raw", "50G", "raw"
                )
        assert result["success"] is True
        mock_run.assert_called_once()
        call_args = mock_run.call_args[0][0]
        assert "raw" in call_args

    def test_create_disk_image_failure(self, kvm_creation):
        """Test creating disk image when qemu-img fails."""
        with patch("os.makedirs"):
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = Mock(
                    returncode=1, stdout="", stderr="qemu-img: Could not create"
                )
                result = kvm_creation._create_disk_image(
                    "/var/lib/libvirt/images/test.qcow2", "20G"
                )
        assert result["success"] is False
        assert "qemu-img" in result["error"]

    def test_create_disk_image_failure_stdout_fallback(self, kvm_creation):
        """Test error message fallback to stdout when stderr is empty."""
        with patch("os.makedirs"):
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = Mock(
                    returncode=1, stdout="Error in stdout", stderr=""
                )
                result = kvm_creation._create_disk_image(
                    "/var/lib/libvirt/images/test.qcow2", "20G"
                )
        assert result["success"] is False
        assert "stdout" in result["error"]

    def test_create_disk_image_timeout(self, kvm_creation):
        """Test creating disk image when it times out."""
        with patch("os.makedirs"):
            with patch(
                "subprocess.run",
                side_effect=subprocess.TimeoutExpired("qemu-img", 120),
            ):
                result = kvm_creation._create_disk_image(
                    "/var/lib/libvirt/images/test.qcow2", "20G"
                )
        assert result["success"] is False
        assert "timed out" in result["error"].lower()

    def test_create_disk_image_exception(self, kvm_creation):
        """Test creating disk image with general exception."""
        with patch("os.makedirs"):
            with patch("subprocess.run", side_effect=Exception("Unexpected error")):
                result = kvm_creation._create_disk_image(
                    "/var/lib/libvirt/images/test.qcow2", "20G"
                )
        assert result["success"] is False
        assert "Unexpected error" in result["error"]


class TestDecompressXz:
    """Tests for _decompress_xz method."""

    def test_decompress_xz_success(self, kvm_creation):
        """Test decompressing xz file successfully."""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = Mock(returncode=0, stdout="", stderr="")
            result = kvm_creation._decompress_xz(
                "/tmp/test.qcow2.xz", "/tmp/test.qcow2"
            )
        assert result["success"] is True
        assert result["path"] == "/tmp/test.qcow2"

    def test_decompress_xz_failure(self, kvm_creation):
        """Test decompressing xz file when it fails."""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = Mock(
                returncode=1, stdout="", stderr="xz: corrupted data"
            )
            result = kvm_creation._decompress_xz(
                "/tmp/test.qcow2.xz", "/tmp/test.qcow2"
            )
        assert result["success"] is False
        assert "corrupted" in result["error"]

    def test_decompress_xz_failure_no_stderr(self, kvm_creation):
        """Test decompressing xz file failure with empty stderr."""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = Mock(returncode=1, stdout="", stderr="")
            result = kvm_creation._decompress_xz(
                "/tmp/test.qcow2.xz", "/tmp/test.qcow2"
            )
        assert result["success"] is False

    def test_decompress_xz_timeout(self, kvm_creation):
        """Test decompressing xz file when it times out."""
        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired("xz", 600)):
            result = kvm_creation._decompress_xz(
                "/tmp/test.qcow2.xz", "/tmp/test.qcow2"
            )
        assert result["success"] is False
        assert "timed out" in result["error"].lower()

    def test_decompress_xz_exception(self, kvm_creation):
        """Test decompressing xz file with general exception."""
        with patch("subprocess.run", side_effect=Exception("IO error")):
            result = kvm_creation._decompress_xz(
                "/tmp/test.qcow2.xz", "/tmp/test.qcow2"
            )
        assert result["success"] is False
        assert "IO error" in result["error"]


class TestGetImageCachePaths:
    """Tests for _get_image_cache_paths method."""

    def test_get_image_cache_paths_non_xz(self, kvm_creation):
        """Test getting cache paths for non-compressed image."""
        url = "https://cloud-images.ubuntu.com/jammy/current/jammy-server-cloudimg-amd64.img"
        result = kvm_creation._get_image_cache_paths(url)

        assert result["download_dir"] == os.path.join(KVM_IMAGES_DIR, ".downloads")
        assert "jammy-server-cloudimg-amd64.img" in result["cached_path"]
        assert result["is_xz_compressed"] is False
        assert result["decompressed_path"] == result["cached_path"]

    def test_get_image_cache_paths_xz(self, kvm_creation):
        """Test getting cache paths for xz-compressed image."""
        url = "https://example.com/freebsd-14.0-RELEASE.qcow2.xz"
        result = kvm_creation._get_image_cache_paths(url)

        assert result["is_xz_compressed"] is True
        assert result["cached_path"].endswith(".xz")
        assert not result["decompressed_path"].endswith(".xz")
        assert result["cached_path"] != result["decompressed_path"]

    def test_get_image_cache_paths_with_query_string(self, kvm_creation):
        """Test getting cache paths for URL with query string."""
        url = "https://example.com/image.qcow2?auth=token123"
        result = kvm_creation._get_image_cache_paths(url)

        assert "image.qcow2" in result["cached_path"]
        assert "auth" not in result["cached_path"]


class TestDownloadImageToCache:
    """Tests for _download_image_to_cache method."""

    def test_download_image_to_cache_success(self, kvm_creation):
        """Test downloading image to cache successfully."""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = Mock(returncode=0, stdout="", stderr="")
            result = kvm_creation._download_image_to_cache(
                "https://example.com/image.qcow2", "/tmp/cached.qcow2"
            )
        assert result["success"] is True

    def test_download_image_to_cache_failure(self, kvm_creation):
        """Test downloading image to cache when curl fails."""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = Mock(
                returncode=1, stdout="", stderr="curl: connection refused"
            )
            result = kvm_creation._download_image_to_cache(
                "https://example.com/image.qcow2", "/tmp/cached.qcow2"
            )
        assert result["success"] is False
        assert "connection refused" in result["error"]

    def test_download_image_to_cache_failure_no_stderr(self, kvm_creation):
        """Test downloading image failure with empty stderr."""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = Mock(returncode=1, stdout="", stderr="")
            result = kvm_creation._download_image_to_cache(
                "https://example.com/image.qcow2", "/tmp/cached.qcow2"
            )
        assert result["success"] is False


class TestCreateQcow2WithBacking:
    """Tests for _create_qcow2_with_backing method."""

    def test_create_qcow2_with_backing_success_new_qemu(self, kvm_creation):
        """Test creating qcow2 with backing file using new qemu-img."""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = Mock(returncode=0, stdout="", stderr="")
            result = kvm_creation._create_qcow2_with_backing(
                "/tmp/backing.qcow2", "/var/lib/libvirt/images/vm.qcow2"
            )
        assert result["success"] is True
        # First call should use -F option
        first_call = mock_run.call_args_list[0][0][0]
        assert "-F" in first_call

    def test_create_qcow2_with_backing_fallback_old_qemu(self, kvm_creation):
        """Test creating qcow2 with backing file falling back to old qemu-img."""
        with patch("subprocess.run") as mock_run:
            # First call fails (new qemu-img), second succeeds (old qemu-img)
            mock_run.side_effect = [
                Mock(returncode=1, stdout="", stderr="unknown option -F"),
                Mock(returncode=0, stdout="", stderr=""),
            ]
            result = kvm_creation._create_qcow2_with_backing(
                "/tmp/backing.qcow2", "/var/lib/libvirt/images/vm.qcow2"
            )
        assert result["success"] is True
        assert mock_run.call_count == 2

    def test_create_qcow2_with_backing_fallback_copy(self, kvm_creation):
        """Test creating qcow2 with backing file falling back to direct copy."""
        with patch("subprocess.run") as mock_run:
            with patch("shutil.copy2") as mock_copy:
                # Both qemu-img calls fail
                mock_run.side_effect = [
                    Mock(returncode=1, stdout="", stderr="error"),
                    Mock(returncode=1, stdout="", stderr="error"),
                    Mock(returncode=0, stdout="", stderr=""),  # chown call
                ]
                result = kvm_creation._create_qcow2_with_backing(
                    "/tmp/backing.qcow2", "/var/lib/libvirt/images/vm.qcow2"
                )
        assert result["success"] is True
        mock_copy.assert_called_once()


class TestDownloadCloudImage:
    """Tests for _download_cloud_image method."""

    def test_download_cloud_image_cached_decompressed(self, kvm_creation):
        """Test using cached decompressed image."""
        with patch.object(kvm_creation, "_get_image_cache_paths") as mock_paths:
            mock_paths.return_value = {
                "download_dir": "/tmp/downloads",
                "cached_path": "/tmp/image.qcow2.xz",
                "decompressed_path": "/tmp/image.qcow2",
                "is_xz_compressed": True,
            }
            with patch("os.makedirs"):
                with patch("os.path.exists", return_value=True):
                    with patch.object(
                        kvm_creation, "_create_qcow2_with_backing"
                    ) as mock_create:
                        mock_create.return_value = {"success": True}
                        result = kvm_creation._download_cloud_image(
                            "https://example.com/image.qcow2.xz",
                            "/var/lib/libvirt/images/vm.qcow2",
                        )
        assert result["success"] is True

    def test_download_cloud_image_cached_non_compressed(self, kvm_creation):
        """Test using cached non-compressed image."""
        with patch.object(kvm_creation, "_get_image_cache_paths") as mock_paths:
            mock_paths.return_value = {
                "download_dir": "/tmp/downloads",
                "cached_path": "/tmp/image.qcow2",
                "decompressed_path": "/tmp/image.qcow2",
                "is_xz_compressed": False,
            }
            with patch("os.makedirs"):
                # For non-xz: first check is for cached_path existence (True = use cache)
                with patch("os.path.exists", return_value=True):
                    with patch.object(
                        kvm_creation, "_create_qcow2_with_backing"
                    ) as mock_create:
                        mock_create.return_value = {"success": True}
                        result = kvm_creation._download_cloud_image(
                            "https://example.com/image.qcow2",
                            "/var/lib/libvirt/images/vm.qcow2",
                        )
        assert result["success"] is True

    def test_download_cloud_image_fresh_download(self, kvm_creation):
        """Test downloading fresh image."""
        with patch.object(kvm_creation, "_get_image_cache_paths") as mock_paths:
            mock_paths.return_value = {
                "download_dir": "/tmp/downloads",
                "cached_path": "/tmp/image.qcow2",
                "decompressed_path": "/tmp/image.qcow2",
                "is_xz_compressed": False,
            }
            with patch("os.makedirs"):
                with patch("os.path.exists", return_value=False):
                    with patch.object(
                        kvm_creation, "_download_image_to_cache"
                    ) as mock_download:
                        mock_download.return_value = {"success": True}
                        with patch.object(
                            kvm_creation, "_create_qcow2_with_backing"
                        ) as mock_create:
                            mock_create.return_value = {"success": True}
                            result = kvm_creation._download_cloud_image(
                                "https://example.com/image.qcow2",
                                "/var/lib/libvirt/images/vm.qcow2",
                            )
        assert result["success"] is True
        mock_download.assert_called_once()

    def test_download_cloud_image_fresh_with_xz(self, kvm_creation):
        """Test downloading and decompressing xz image."""
        with patch.object(kvm_creation, "_get_image_cache_paths") as mock_paths:
            mock_paths.return_value = {
                "download_dir": "/tmp/downloads",
                "cached_path": "/tmp/image.qcow2.xz",
                "decompressed_path": "/tmp/image.qcow2",
                "is_xz_compressed": True,
            }
            with patch("os.makedirs"):
                with patch("os.path.exists", return_value=False):
                    with patch.object(
                        kvm_creation, "_download_image_to_cache"
                    ) as mock_download:
                        mock_download.return_value = {"success": True}
                        with patch.object(
                            kvm_creation, "_decompress_xz"
                        ) as mock_decompress:
                            mock_decompress.return_value = {"success": True}
                            with patch.object(
                                kvm_creation, "_create_qcow2_with_backing"
                            ) as mock_create:
                                mock_create.return_value = {"success": True}
                                result = kvm_creation._download_cloud_image(
                                    "https://example.com/image.qcow2.xz",
                                    "/var/lib/libvirt/images/vm.qcow2",
                                )
        assert result["success"] is True
        mock_decompress.assert_called_once()

    def test_download_cloud_image_download_failure(self, kvm_creation):
        """Test download failure."""
        with patch.object(kvm_creation, "_get_image_cache_paths") as mock_paths:
            mock_paths.return_value = {
                "download_dir": "/tmp/downloads",
                "cached_path": "/tmp/image.qcow2",
                "decompressed_path": "/tmp/image.qcow2",
                "is_xz_compressed": False,
            }
            with patch("os.makedirs"):
                with patch("os.path.exists", return_value=False):
                    with patch.object(
                        kvm_creation, "_download_image_to_cache"
                    ) as mock_download:
                        mock_download.return_value = {
                            "success": False,
                            "error": "Download failed",
                        }
                        result = kvm_creation._download_cloud_image(
                            "https://example.com/image.qcow2",
                            "/var/lib/libvirt/images/vm.qcow2",
                        )
        assert result["success"] is False

    def test_download_cloud_image_decompress_failure(self, kvm_creation):
        """Test decompression failure."""
        with patch.object(kvm_creation, "_get_image_cache_paths") as mock_paths:
            mock_paths.return_value = {
                "download_dir": "/tmp/downloads",
                "cached_path": "/tmp/image.qcow2.xz",
                "decompressed_path": "/tmp/image.qcow2",
                "is_xz_compressed": True,
            }
            with patch("os.makedirs"):
                with patch("os.path.exists", return_value=False):
                    with patch.object(
                        kvm_creation, "_download_image_to_cache"
                    ) as mock_download:
                        mock_download.return_value = {"success": True}
                        with patch.object(
                            kvm_creation, "_decompress_xz"
                        ) as mock_decompress:
                            mock_decompress.return_value = {
                                "success": False,
                                "error": "Decompress failed",
                            }
                            result = kvm_creation._download_cloud_image(
                                "https://example.com/image.qcow2.xz",
                                "/var/lib/libvirt/images/vm.qcow2",
                            )
        assert result["success"] is False

    def test_download_cloud_image_backing_failure(self, kvm_creation):
        """Test backing file creation failure."""
        with patch.object(kvm_creation, "_get_image_cache_paths") as mock_paths:
            mock_paths.return_value = {
                "download_dir": "/tmp/downloads",
                "cached_path": "/tmp/image.qcow2",
                "decompressed_path": "/tmp/image.qcow2",
                "is_xz_compressed": False,
            }
            with patch("os.makedirs"):
                # Cached file exists so we skip downloading and go straight to backing
                with patch("os.path.exists", return_value=True):
                    with patch.object(
                        kvm_creation, "_create_qcow2_with_backing"
                    ) as mock_create:
                        mock_create.return_value = {
                            "success": False,
                            "error": "Backing failed",
                        }
                        result = kvm_creation._download_cloud_image(
                            "https://example.com/image.qcow2",
                            "/var/lib/libvirt/images/vm.qcow2",
                        )
        assert result["success"] is False

    def test_download_cloud_image_timeout(self, kvm_creation):
        """Test download timeout."""
        with patch.object(kvm_creation, "_get_image_cache_paths") as mock_paths:
            mock_paths.return_value = {
                "download_dir": "/tmp/downloads",
                "cached_path": "/tmp/image.qcow2",
                "decompressed_path": "/tmp/image.qcow2",
                "is_xz_compressed": False,
            }
            with patch(
                "os.makedirs", side_effect=subprocess.TimeoutExpired("curl", 1800)
            ):
                result = kvm_creation._download_cloud_image(
                    "https://example.com/image.qcow2",
                    "/var/lib/libvirt/images/vm.qcow2",
                )
        assert result["success"] is False
        assert "timed out" in result["error"].lower()

    def test_download_cloud_image_exception(self, kvm_creation):
        """Test download with exception."""
        with patch.object(kvm_creation, "_get_image_cache_paths") as mock_paths:
            mock_paths.return_value = {
                "download_dir": "/tmp/downloads",
                "cached_path": "/tmp/image.qcow2",
                "decompressed_path": "/tmp/image.qcow2",
                "is_xz_compressed": False,
            }
            with patch("os.makedirs", side_effect=Exception("Permission denied")):
                result = kvm_creation._download_cloud_image(
                    "https://example.com/image.qcow2",
                    "/var/lib/libvirt/images/vm.qcow2",
                )
        assert result["success"] is False
        assert "Permission denied" in result["error"]


class TestResizeDisk:
    """Tests for _resize_disk method."""

    def test_resize_disk_success(self, kvm_creation):
        """Test resizing disk successfully."""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = Mock(returncode=0, stdout="", stderr="")
            result = kvm_creation._resize_disk(
                "/var/lib/libvirt/images/test.qcow2", "50G"
            )
        assert result["success"] is True

    def test_resize_disk_failure(self, kvm_creation):
        """Test resizing disk when it fails."""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = Mock(
                returncode=1, stdout="", stderr="Cannot resize"
            )
            result = kvm_creation._resize_disk(
                "/var/lib/libvirt/images/test.qcow2", "50G"
            )
        assert result["success"] is False
        assert "Cannot resize" in result["error"]

    def test_resize_disk_failure_no_stderr(self, kvm_creation):
        """Test resizing disk failure with empty stderr."""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = Mock(returncode=1, stdout="", stderr="")
            result = kvm_creation._resize_disk(
                "/var/lib/libvirt/images/test.qcow2", "50G"
            )
        assert result["success"] is False

    def test_resize_disk_exception(self, kvm_creation):
        """Test resizing disk with exception."""
        with patch("subprocess.run", side_effect=Exception("Disk error")):
            result = kvm_creation._resize_disk(
                "/var/lib/libvirt/images/test.qcow2", "50G"
            )
        assert result["success"] is False
        assert "Disk error" in result["error"]


class TestGenerateDomainXml:
    """Tests for _generate_domain_xml method."""

    def test_generate_domain_xml_basic(self, kvm_creation, sample_vm_config):
        """Test generating basic domain XML."""
        sample_vm_config.disk_path = "/var/lib/libvirt/images/test.qcow2"
        xml = kvm_creation._generate_domain_xml(sample_vm_config)

        assert "<name>test-vm</name>" in xml
        assert "<vcpu>2</vcpu>" in xml
        assert "virtio" in xml
        assert "/var/lib/libvirt/images/test.qcow2" in xml

    def test_generate_domain_xml_with_cloudinit(self, kvm_creation, sample_vm_config):
        """Test generating domain XML with cloud-init ISO."""
        sample_vm_config.disk_path = "/var/lib/libvirt/images/test.qcow2"
        sample_vm_config.cloud_init_iso_path = "/var/lib/libvirt/cloud-init/test-vm.iso"

        with patch("os.path.exists", return_value=True):
            xml = kvm_creation._generate_domain_xml(sample_vm_config)

        assert "cloud-init/test-vm.iso" in xml
        assert "cdrom" in xml

    def test_generate_domain_xml_no_cloudinit_file(
        self, kvm_creation, sample_vm_config
    ):
        """Test generating domain XML when cloud-init file doesn't exist."""
        sample_vm_config.disk_path = "/var/lib/libvirt/images/test.qcow2"
        sample_vm_config.cloud_init_iso_path = "/var/lib/libvirt/cloud-init/missing.iso"

        with patch("os.path.exists", return_value=False):
            xml = kvm_creation._generate_domain_xml(sample_vm_config)

        assert "missing.iso" not in xml
        assert "cdrom" not in xml

    def test_generate_domain_xml_custom_memory(self, kvm_creation):
        """Test generating domain XML with custom memory."""
        config = KvmVmConfig(
            distribution="ubuntu:22.04",
            vm_name="test-vm",
            hostname="test.example.com",
            username="admin",
            password_hash="$6$test",
            server_url="https://server.example.com",
            agent_install_commands=[],
            memory="8G",
            cpus=4,
        )
        config.disk_path = "/var/lib/libvirt/images/test.qcow2"
        xml = kvm_creation._generate_domain_xml(config)

        assert "<memory unit='MiB'>8192</memory>" in xml
        assert "<vcpu>4</vcpu>" in xml


class TestDefineAndStartVm:
    """Tests for _define_and_start_vm method."""

    def test_define_and_start_vm_success(self, kvm_creation, sample_vm_config):
        """Test defining and starting VM successfully."""
        sample_vm_config.disk_path = "/var/lib/libvirt/images/test.qcow2"

        with patch("tempfile.NamedTemporaryFile") as mock_temp:
            mock_temp.return_value.__enter__.return_value.name = "/tmp/test.xml"
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = Mock(returncode=0, stdout="", stderr="")
                with patch("os.unlink"):
                    result = kvm_creation._define_and_start_vm(sample_vm_config)

        assert result["success"] is True

    def test_define_and_start_vm_define_failure(self, kvm_creation, sample_vm_config):
        """Test defining VM when virsh define fails."""
        sample_vm_config.disk_path = "/var/lib/libvirt/images/test.qcow2"

        with patch("tempfile.NamedTemporaryFile") as mock_temp:
            mock_temp.return_value.__enter__.return_value.name = "/tmp/test.xml"
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = Mock(
                    returncode=1, stdout="", stderr="Failed to define"
                )
                with patch("os.unlink"):
                    result = kvm_creation._define_and_start_vm(sample_vm_config)

        assert result["success"] is False
        assert "Failed to define" in result["error"]

    def test_define_and_start_vm_start_failure(self, kvm_creation, sample_vm_config):
        """Test starting VM when virsh start fails."""
        sample_vm_config.disk_path = "/var/lib/libvirt/images/test.qcow2"

        with patch("tempfile.NamedTemporaryFile") as mock_temp:
            mock_temp.return_value.__enter__.return_value.name = "/tmp/test.xml"
            with patch("subprocess.run") as mock_run:
                mock_run.side_effect = [
                    Mock(returncode=0, stdout="", stderr=""),  # define
                    Mock(returncode=1, stdout="", stderr="Failed to start"),  # start
                ]
                with patch("os.unlink"):
                    result = kvm_creation._define_and_start_vm(sample_vm_config)

        assert result["success"] is False
        assert "Failed to start" in result["error"]

    def test_define_and_start_vm_timeout(self, kvm_creation, sample_vm_config):
        """Test defining and starting VM with timeout."""
        sample_vm_config.disk_path = "/var/lib/libvirt/images/test.qcow2"

        with patch("tempfile.NamedTemporaryFile") as mock_temp:
            mock_temp.return_value.__enter__.return_value.name = "/tmp/test.xml"
            with patch(
                "subprocess.run", side_effect=subprocess.TimeoutExpired("virsh", 60)
            ):
                with patch("os.unlink"):
                    result = kvm_creation._define_and_start_vm(sample_vm_config)

        assert result["success"] is False
        assert "timed out" in result["error"].lower()

    def test_define_and_start_vm_exception(self, kvm_creation, sample_vm_config):
        """Test defining and starting VM with exception."""
        sample_vm_config.disk_path = "/var/lib/libvirt/images/test.qcow2"

        with patch("tempfile.NamedTemporaryFile") as mock_temp:
            mock_temp.return_value.__enter__.return_value.name = "/tmp/test.xml"
            with patch("subprocess.run", side_effect=Exception("Unexpected")):
                with patch("os.unlink"):
                    result = kvm_creation._define_and_start_vm(sample_vm_config)

        assert result["success"] is False
        assert "Unexpected" in result["error"]

    def test_define_and_start_vm_cleanup_on_unlink_error(
        self, kvm_creation, sample_vm_config
    ):
        """Test that temp file cleanup errors are handled."""
        sample_vm_config.disk_path = "/var/lib/libvirt/images/test.qcow2"

        with patch("tempfile.NamedTemporaryFile") as mock_temp:
            mock_temp.return_value.__enter__.return_value.name = "/tmp/test.xml"
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = Mock(returncode=0, stdout="", stderr="")
                with patch("os.unlink", side_effect=OSError("Cannot delete")):
                    result = kvm_creation._define_and_start_vm(sample_vm_config)

        # Should still succeed despite cleanup error
        assert result["success"] is True


class TestExtractIpFromDomifaddr:
    """Tests for _extract_ip_from_domifaddr method."""

    def test_extract_ip_from_domifaddr_success(self, kvm_creation):
        """Test extracting IP from domifaddr output."""
        output = """
 Name       MAC address          Protocol     Address
-------------------------------------------------------------------------------
 vnet0      52:54:00:ab:cd:ef    ipv4         192.168.122.100/24
"""
        result = kvm_creation._extract_ip_from_domifaddr(output)
        assert result == "192.168.122.100"

    def test_extract_ip_from_domifaddr_multiple_interfaces(self, kvm_creation):
        """Test extracting IP when multiple interfaces exist."""
        output = """
 Name       MAC address          Protocol     Address
-------------------------------------------------------------------------------
 vnet0      52:54:00:ab:cd:ef    ipv4         192.168.122.100/24
 vnet1      52:54:00:12:34:56    ipv4         10.0.0.50/8
"""
        result = kvm_creation._extract_ip_from_domifaddr(output)
        assert result == "192.168.122.100"

    def test_extract_ip_from_domifaddr_no_ip(self, kvm_creation):
        """Test extracting IP when no IP available."""
        output = """
 Name       MAC address          Protocol     Address
-------------------------------------------------------------------------------
"""
        result = kvm_creation._extract_ip_from_domifaddr(output)
        assert result is None

    def test_extract_ip_from_domifaddr_localhost_ignored(self, kvm_creation):
        """Test that localhost IP is ignored."""
        output = """
 Name       MAC address          Protocol     Address
-------------------------------------------------------------------------------
 lo         00:00:00:00:00:00    ipv4         127.0.0.1/8
"""
        result = kvm_creation._extract_ip_from_domifaddr(output)
        assert result is None

    def test_extract_ip_from_domifaddr_empty(self, kvm_creation):
        """Test extracting IP from empty output."""
        result = kvm_creation._extract_ip_from_domifaddr("")
        assert result is None


class TestExtractIpFromDhcpLeases:
    """Tests for _extract_ip_from_dhcp_leases method."""

    def test_extract_ip_from_dhcp_leases_success(self, kvm_creation):
        """Test extracting IP from DHCP leases output."""
        output = """
 Expiry Time           MAC address         Protocol   IP address      Hostname        Client ID or DUID
-------------------------------------------------------------------------------------------------------------------
 2024-01-15 10:00:00   52:54:00:ab:cd:ef   ipv4       192.168.122.100/24   test-vm         ff:ab:cd:ef
"""
        result = kvm_creation._extract_ip_from_dhcp_leases(output, "test-vm")
        assert result == "192.168.122.100"

    def test_extract_ip_from_dhcp_leases_case_insensitive(self, kvm_creation):
        """Test extracting IP with case-insensitive matching."""
        output = """
 Expiry Time           MAC address         Protocol   IP address      Hostname        Client ID or DUID
-------------------------------------------------------------------------------------------------------------------
 2024-01-15 10:00:00   52:54:00:ab:cd:ef   ipv4       192.168.122.100/24   TEST-VM         ff:ab:cd:ef
"""
        result = kvm_creation._extract_ip_from_dhcp_leases(output, "test-vm")
        assert result == "192.168.122.100"

    def test_extract_ip_from_dhcp_leases_no_match(self, kvm_creation):
        """Test extracting IP when VM not in leases."""
        output = """
 Expiry Time           MAC address         Protocol   IP address      Hostname        Client ID or DUID
-------------------------------------------------------------------------------------------------------------------
 2024-01-15 10:00:00   52:54:00:ab:cd:ef   ipv4       192.168.122.100/24   other-vm        ff:ab:cd:ef
"""
        result = kvm_creation._extract_ip_from_dhcp_leases(output, "test-vm")
        assert result is None

    def test_extract_ip_from_dhcp_leases_empty(self, kvm_creation):
        """Test extracting IP from empty output."""
        result = kvm_creation._extract_ip_from_dhcp_leases("", "test-vm")
        assert result is None


class TestGetVmIpOnce:
    """Tests for _get_vm_ip_once method."""

    def test_get_vm_ip_once_from_domifaddr(self, kvm_creation):
        """Test getting IP from domifaddr."""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = Mock(
                returncode=0,
                stdout="vnet0 52:54:00:ab:cd:ef ipv4 192.168.122.100/24",
                stderr="",
            )
            with patch.object(
                kvm_creation,
                "_extract_ip_from_domifaddr",
                return_value="192.168.122.100",
            ):
                result = kvm_creation._get_vm_ip_once("test-vm")
        assert result == "192.168.122.100"

    def test_get_vm_ip_once_fallback_to_dhcp(self, kvm_creation):
        """Test falling back to DHCP leases when domifaddr fails."""
        with patch("subprocess.run") as mock_run:
            # First call (domifaddr) returns no IP, second (dhcp-leases) succeeds
            mock_run.side_effect = [
                Mock(returncode=0, stdout="", stderr=""),
                Mock(
                    returncode=0,
                    stdout="2024-01-15 52:54:00:ab:cd:ef ipv4 192.168.122.100/24 test-vm",
                    stderr="",
                ),
            ]
            with patch.object(
                kvm_creation, "_extract_ip_from_domifaddr", return_value=None
            ):
                with patch.object(
                    kvm_creation,
                    "_extract_ip_from_dhcp_leases",
                    return_value="192.168.122.100",
                ):
                    result = kvm_creation._get_vm_ip_once("test-vm")
        assert result == "192.168.122.100"

    def test_get_vm_ip_once_no_ip_found(self, kvm_creation):
        """Test when no IP is found."""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = Mock(returncode=0, stdout="", stderr="")
            with patch.object(
                kvm_creation, "_extract_ip_from_domifaddr", return_value=None
            ):
                with patch.object(
                    kvm_creation, "_extract_ip_from_dhcp_leases", return_value=None
                ):
                    result = kvm_creation._get_vm_ip_once("test-vm")
        assert result is None

    def test_get_vm_ip_once_domifaddr_exception(self, kvm_creation):
        """Test handling exception in domifaddr."""
        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = [
                Exception("Connection error"),  # domifaddr fails
                Mock(returncode=0, stdout="test-vm 192.168.122.100/24", stderr=""),
            ]
            with patch.object(
                kvm_creation,
                "_extract_ip_from_dhcp_leases",
                return_value="192.168.122.100",
            ):
                result = kvm_creation._get_vm_ip_once("test-vm")
        assert result == "192.168.122.100"

    def test_get_vm_ip_once_all_exceptions(self, kvm_creation):
        """Test when all methods raise exceptions."""
        with patch("subprocess.run", side_effect=Exception("Connection error")):
            result = kvm_creation._get_vm_ip_once("test-vm")
        assert result is None


class TestWaitForVmIpAsync:
    """Tests for _wait_for_vm_ip async method."""

    @pytest.mark.asyncio
    async def test_wait_for_vm_ip_found_immediately(self, kvm_creation):
        """Test waiting for VM IP when found immediately."""
        with patch.object(
            kvm_creation, "_get_vm_ip_once", return_value="192.168.122.100"
        ):
            result = await kvm_creation._wait_for_vm_ip("test-vm", timeout=10)
        assert result == "192.168.122.100"

    @pytest.mark.asyncio
    async def test_wait_for_vm_ip_found_after_retry(self, kvm_creation):
        """Test waiting for VM IP when found after retry."""
        call_count = 0

        def mock_get_ip(_vm_name):
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                return None
            return "192.168.122.100"

        with patch.object(kvm_creation, "_get_vm_ip_once", side_effect=mock_get_ip):
            result = await kvm_creation._wait_for_vm_ip(
                "test-vm", timeout=30, interval=0.1
            )
        assert result == "192.168.122.100"
        assert call_count == 3

    @pytest.mark.asyncio
    async def test_wait_for_vm_ip_timeout(self, kvm_creation):
        """Test waiting for VM IP with timeout."""
        with patch.object(kvm_creation, "_get_vm_ip_once", return_value=None):
            result = await kvm_creation._wait_for_vm_ip(
                "test-vm", timeout=0.2, interval=0.1
            )
        assert result is None


class TestWaitForSshAsync:
    """Tests for _wait_for_ssh async method."""

    @pytest.mark.asyncio
    async def test_wait_for_ssh_available(self, kvm_creation):
        """Test waiting for SSH when it's available."""
        with patch("socket.socket") as mock_socket:
            mock_sock = Mock()
            mock_sock.connect_ex.return_value = 0
            mock_socket.return_value = mock_sock
            result = await kvm_creation._wait_for_ssh("192.168.122.100", timeout=10)
        assert result is True

    @pytest.mark.asyncio
    async def test_wait_for_ssh_timeout(self, kvm_creation):
        """Test waiting for SSH with timeout."""
        with patch("socket.socket") as mock_socket:
            mock_sock = Mock()
            mock_sock.connect_ex.return_value = 111  # Connection refused
            mock_socket.return_value = mock_sock
            result = await kvm_creation._wait_for_ssh(
                "192.168.122.100", timeout=0.2, interval=0.1
            )
        assert result is False

    @pytest.mark.asyncio
    async def test_wait_for_ssh_available_after_retry(self, kvm_creation):
        """Test waiting for SSH when available after retry."""
        call_count = 0

        def mock_connect_ex(_addr):
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                return 111  # Connection refused
            return 0

        with patch("socket.socket") as mock_socket:
            mock_sock = Mock()
            mock_sock.connect_ex.side_effect = mock_connect_ex
            mock_socket.return_value = mock_sock
            result = await kvm_creation._wait_for_ssh(
                "192.168.122.100", timeout=30, interval=0.1
            )
        assert result is True

    @pytest.mark.asyncio
    async def test_wait_for_ssh_exception_handled(self, kvm_creation):
        """Test waiting for SSH with socket exception."""
        with patch("socket.socket") as mock_socket:
            mock_socket.return_value.connect_ex.side_effect = Exception("Network error")
            result = await kvm_creation._wait_for_ssh(
                "192.168.122.100", timeout=0.2, interval=0.1
            )
        assert result is False


class TestPrepareVmDisk:
    """Tests for _prepare_vm_disk method."""

    def test_prepare_vm_disk_with_cloud_image(self, kvm_creation, sample_vm_config):
        """Test preparing VM disk with cloud image."""
        sample_vm_config.cloud_image_url = "https://example.com/image.qcow2"

        with patch.object(kvm_creation, "_download_cloud_image") as mock_download:
            mock_download.return_value = {"success": True}
            with patch.object(kvm_creation, "_resize_disk") as mock_resize:
                mock_resize.return_value = {"success": True}
                result = kvm_creation._prepare_vm_disk(sample_vm_config)

        assert result["success"] is True
        mock_download.assert_called_once()
        mock_resize.assert_called_once()

    def test_prepare_vm_disk_with_cloud_image_resize_warning(
        self, kvm_creation, sample_vm_config
    ):
        """Test preparing VM disk when resize fails (warning only)."""
        sample_vm_config.cloud_image_url = "https://example.com/image.qcow2"

        with patch.object(kvm_creation, "_download_cloud_image") as mock_download:
            mock_download.return_value = {"success": True}
            with patch.object(kvm_creation, "_resize_disk") as mock_resize:
                mock_resize.return_value = {"success": False, "error": "Cannot resize"}
                result = kvm_creation._prepare_vm_disk(sample_vm_config)

        # Should still succeed even if resize fails
        assert result["success"] is True

    def test_prepare_vm_disk_download_failure(self, kvm_creation, sample_vm_config):
        """Test preparing VM disk when download fails."""
        sample_vm_config.cloud_image_url = "https://example.com/image.qcow2"

        with patch.object(kvm_creation, "_download_cloud_image") as mock_download:
            mock_download.return_value = {"success": False, "error": "Download failed"}
            result = kvm_creation._prepare_vm_disk(sample_vm_config)

        assert result["success"] is False

    def test_prepare_vm_disk_without_cloud_image(self, kvm_creation, sample_vm_config):
        """Test preparing VM disk without cloud image (create empty disk)."""
        sample_vm_config.cloud_image_url = ""

        with patch.object(kvm_creation, "_create_disk_image") as mock_create:
            mock_create.return_value = {"success": True}
            result = kvm_creation._prepare_vm_disk(sample_vm_config)

        assert result["success"] is True
        mock_create.assert_called_once()


class TestProvisionVm:
    """Tests for _provision_vm method."""

    def test_provision_vm_no_cloud_init(self, kvm_creation, sample_vm_config):
        """Test provisioning VM without cloud-init."""
        sample_vm_config.use_cloud_init = False
        result = kvm_creation._provision_vm(sample_vm_config)
        assert result["success"] is True

    def test_provision_vm_linux_cloud_init(self, kvm_creation, sample_vm_config):
        """Test provisioning Linux VM with cloud-init."""
        sample_vm_config.use_cloud_init = True

        with patch.object(kvm_creation, "_is_freebsd", return_value=False):
            with patch.object(
                kvm_creation._cloudinit, "create_cloud_init_iso"
            ) as mock_cloudinit:
                mock_cloudinit.return_value = {"success": True}
                result = kvm_creation._provision_vm(sample_vm_config)

        assert result["success"] is True
        mock_cloudinit.assert_called_once()

    def test_provision_vm_freebsd(self, kvm_creation, freebsd_vm_config):
        """Test provisioning FreeBSD VM."""
        freebsd_vm_config.use_cloud_init = True
        freebsd_vm_config.disk_path = "/var/lib/libvirt/images/freebsd.qcow2"

        with patch.object(kvm_creation, "_is_freebsd", return_value=True):
            with patch.object(kvm_creation._freebsd, "provision_image") as mock_freebsd:
                mock_freebsd.return_value = {
                    "success": True,
                    "config_disk_path": "/tmp/config.iso",
                }
                result = kvm_creation._provision_vm(freebsd_vm_config)

        assert result["success"] is True
        assert freebsd_vm_config.cloud_init_iso_path == "/tmp/config.iso"

    def test_provision_vm_freebsd_failure(self, kvm_creation, freebsd_vm_config):
        """Test provisioning FreeBSD VM when it fails."""
        freebsd_vm_config.use_cloud_init = True
        freebsd_vm_config.disk_path = "/var/lib/libvirt/images/freebsd.qcow2"

        with patch.object(kvm_creation, "_is_freebsd", return_value=True):
            with patch.object(kvm_creation._freebsd, "provision_image") as mock_freebsd:
                mock_freebsd.return_value = {
                    "success": False,
                    "error": "FreeBSD provision failed",
                }
                result = kvm_creation._provision_vm(freebsd_vm_config)

        assert result["success"] is False


class TestRunFreebsdBootstrap:
    """Tests for _run_freebsd_bootstrap method."""

    @pytest.mark.asyncio
    async def test_run_freebsd_bootstrap_not_freebsd(
        self, kvm_creation, sample_vm_config
    ):
        """Test bootstrap skipped for non-FreeBSD."""
        with patch.object(kvm_creation, "_is_freebsd", return_value=False):
            await kvm_creation._run_freebsd_bootstrap(
                sample_vm_config, "192.168.122.100"
            )
        # Should complete without calling anything else

    @pytest.mark.asyncio
    async def test_run_freebsd_bootstrap_no_ssh_key(
        self, kvm_creation, freebsd_vm_config
    ):
        """Test bootstrap skipped when no SSH key."""
        with patch.object(kvm_creation, "_is_freebsd", return_value=True):
            with patch.object(kvm_creation._freebsd, "has_ssh_key", return_value=False):
                await kvm_creation._run_freebsd_bootstrap(
                    freebsd_vm_config, "192.168.122.100"
                )
        # Should complete without calling bootstrap

    @pytest.mark.asyncio
    async def test_run_freebsd_bootstrap_success(self, kvm_creation, freebsd_vm_config):
        """Test FreeBSD bootstrap success."""
        with patch.object(kvm_creation, "_is_freebsd", return_value=True):
            with patch.object(kvm_creation._freebsd, "has_ssh_key", return_value=True):
                with patch.object(
                    kvm_creation._freebsd,
                    "run_bootstrap_via_ssh",
                    new_callable=AsyncMock,
                ) as mock_bootstrap:
                    mock_bootstrap.return_value = {"success": True}
                    with patch.object(kvm_creation._freebsd, "cleanup") as mock_cleanup:
                        await kvm_creation._run_freebsd_bootstrap(
                            freebsd_vm_config, "192.168.122.100"
                        )

        mock_bootstrap.assert_called_once_with("192.168.122.100")
        mock_cleanup.assert_called_once()

    @pytest.mark.asyncio
    async def test_run_freebsd_bootstrap_failure(self, kvm_creation, freebsd_vm_config):
        """Test FreeBSD bootstrap failure (logged but not fatal)."""
        with patch.object(kvm_creation, "_is_freebsd", return_value=True):
            with patch.object(kvm_creation._freebsd, "has_ssh_key", return_value=True):
                with patch.object(
                    kvm_creation._freebsd,
                    "run_bootstrap_via_ssh",
                    new_callable=AsyncMock,
                ) as mock_bootstrap:
                    mock_bootstrap.return_value = {
                        "success": False,
                        "error": "SSH failed",
                    }
                    with patch.object(kvm_creation._freebsd, "cleanup"):
                        # Should not raise, just log warning
                        await kvm_creation._run_freebsd_bootstrap(
                            freebsd_vm_config, "192.168.122.100"
                        )


class TestCleanupFailedVm:
    """Tests for _cleanup_failed_vm method."""

    @pytest.mark.asyncio
    async def test_cleanup_failed_vm_exists(self, kvm_creation):
        """Test cleanup when VM exists."""
        with patch.object(kvm_creation, "_vm_exists", return_value=True):
            with patch(
                "src.sysmanage_agent.operations.child_host_kvm_creation.run_command_async"
            ) as mock_cmd:
                mock_cmd.return_value = Mock(returncode=0)
                await kvm_creation._cleanup_failed_vm("test-vm")

        assert mock_cmd.call_count == 2  # destroy and undefine

    @pytest.mark.asyncio
    async def test_cleanup_failed_vm_not_exists(self, kvm_creation):
        """Test cleanup when VM doesn't exist."""
        with patch.object(kvm_creation, "_vm_exists", return_value=False):
            with patch(
                "src.sysmanage_agent.operations.child_host_kvm_creation.run_command_async"
            ) as mock_cmd:
                await kvm_creation._cleanup_failed_vm("test-vm")

        mock_cmd.assert_not_called()

    @pytest.mark.asyncio
    async def test_cleanup_failed_vm_exception(self, kvm_creation):
        """Test cleanup handles exceptions gracefully."""
        with patch.object(kvm_creation, "_vm_exists", return_value=True):
            with patch(
                "src.sysmanage_agent.operations.child_host_kvm_creation.run_command_async",
                side_effect=Exception("Cleanup error"),
            ):
                # Should not raise
                await kvm_creation._cleanup_failed_vm("test-vm")


class TestCreateVm:
    """Tests for create_vm method."""

    @pytest.mark.asyncio
    async def test_create_vm_already_exists(self, kvm_creation, sample_vm_config):
        """Test creating VM that already exists."""
        with patch.object(kvm_creation, "_vm_exists", return_value=True):
            result = await kvm_creation.create_vm(sample_vm_config)

        assert result["success"] is False
        assert "already exists" in result["error"]

    @pytest.mark.asyncio
    async def test_create_vm_disk_failure(self, kvm_creation, sample_vm_config):
        """Test creating VM when disk preparation fails."""
        with patch.object(kvm_creation, "_vm_exists", return_value=False):
            with patch.object(kvm_creation, "_prepare_vm_disk") as mock_disk:
                mock_disk.return_value = {"success": False, "error": "Disk failed"}
                result = await kvm_creation.create_vm(sample_vm_config)

        assert result["success"] is False
        assert "Disk failed" in result["error"]

    @pytest.mark.asyncio
    async def test_create_vm_provision_failure(self, kvm_creation, sample_vm_config):
        """Test creating VM when provisioning fails."""
        with patch.object(kvm_creation, "_vm_exists", return_value=False):
            with patch.object(kvm_creation, "_prepare_vm_disk") as mock_disk:
                mock_disk.return_value = {"success": True}
                with patch.object(kvm_creation, "_provision_vm") as mock_provision:
                    mock_provision.return_value = {
                        "success": False,
                        "error": "Provision failed",
                    }
                    result = await kvm_creation.create_vm(sample_vm_config)

        assert result["success"] is False

    @pytest.mark.asyncio
    async def test_create_vm_start_failure(self, kvm_creation, sample_vm_config):
        """Test creating VM when start fails."""
        with patch.object(kvm_creation, "_vm_exists", return_value=False):
            with patch.object(kvm_creation, "_prepare_vm_disk") as mock_disk:
                mock_disk.return_value = {"success": True}
                with patch.object(kvm_creation, "_provision_vm") as mock_provision:
                    mock_provision.return_value = {"success": True}
                    with patch.object(
                        kvm_creation, "_define_and_start_vm"
                    ) as mock_start:
                        mock_start.return_value = {
                            "success": False,
                            "error": "Start failed",
                        }
                        result = await kvm_creation.create_vm(sample_vm_config)

        assert result["success"] is False

    @pytest.mark.asyncio
    async def test_create_vm_no_ip(self, kvm_creation, sample_vm_config):
        """Test creating VM when no IP is obtained."""
        with patch.object(kvm_creation, "_vm_exists", return_value=False):
            with patch.object(kvm_creation, "_prepare_vm_disk") as mock_disk:
                mock_disk.return_value = {"success": True}
                with patch.object(kvm_creation, "_provision_vm") as mock_provision:
                    mock_provision.return_value = {"success": True}
                    with patch.object(
                        kvm_creation, "_define_and_start_vm"
                    ) as mock_start:
                        mock_start.return_value = {"success": True}
                        with patch.object(
                            kvm_creation, "_wait_for_vm_ip", new_callable=AsyncMock
                        ) as mock_wait_ip:
                            mock_wait_ip.return_value = None
                            result = await kvm_creation.create_vm(sample_vm_config)

        assert result["success"] is True
        assert result["ip_pending"] is True

    @pytest.mark.asyncio
    async def test_create_vm_no_ssh(self, kvm_creation, sample_vm_config):
        """Test creating VM when SSH is not available."""
        with patch.object(kvm_creation, "_vm_exists", return_value=False):
            with patch.object(kvm_creation, "_prepare_vm_disk") as mock_disk:
                mock_disk.return_value = {"success": True}
                with patch.object(kvm_creation, "_provision_vm") as mock_provision:
                    mock_provision.return_value = {"success": True}
                    with patch.object(
                        kvm_creation, "_define_and_start_vm"
                    ) as mock_start:
                        mock_start.return_value = {"success": True}
                        with patch.object(
                            kvm_creation, "_wait_for_vm_ip", new_callable=AsyncMock
                        ) as mock_wait_ip:
                            mock_wait_ip.return_value = "192.168.122.100"
                            with patch.object(
                                kvm_creation, "_wait_for_ssh", new_callable=AsyncMock
                            ) as mock_wait_ssh:
                                mock_wait_ssh.return_value = False
                                result = await kvm_creation.create_vm(sample_vm_config)

        assert result["success"] is True
        assert result["ssh_pending"] is True
        assert result["ip_address"] == "192.168.122.100"

    @pytest.mark.asyncio
    async def test_create_vm_success(self, kvm_creation, sample_vm_config):
        """Test creating VM successfully."""
        with patch.object(kvm_creation, "_vm_exists", return_value=False):
            with patch.object(kvm_creation, "_prepare_vm_disk") as mock_disk:
                mock_disk.return_value = {"success": True}
                with patch.object(kvm_creation, "_provision_vm") as mock_provision:
                    mock_provision.return_value = {"success": True}
                    with patch.object(
                        kvm_creation, "_define_and_start_vm"
                    ) as mock_start:
                        mock_start.return_value = {"success": True}
                        with patch.object(
                            kvm_creation, "_wait_for_vm_ip", new_callable=AsyncMock
                        ) as mock_wait_ip:
                            mock_wait_ip.return_value = "192.168.122.100"
                            with patch.object(
                                kvm_creation, "_wait_for_ssh", new_callable=AsyncMock
                            ) as mock_wait_ssh:
                                mock_wait_ssh.return_value = True
                                with patch.object(
                                    kvm_creation,
                                    "_run_freebsd_bootstrap",
                                    new_callable=AsyncMock,
                                ):
                                    result = await kvm_creation.create_vm(
                                        sample_vm_config
                                    )

        assert result["success"] is True
        assert result["vm_name"] == "test-vm"
        assert result["ip_address"] == "192.168.122.100"
        assert result["child_type"] == "kvm"

    @pytest.mark.asyncio
    async def test_create_vm_exception_with_cleanup(
        self, kvm_creation, sample_vm_config
    ):
        """Test creating VM with exception triggers cleanup."""
        with patch.object(kvm_creation, "_vm_exists", return_value=False):
            with patch.object(
                kvm_creation, "_prepare_vm_disk", side_effect=Exception("Unexpected")
            ):
                with patch.object(
                    kvm_creation, "_cleanup_failed_vm", new_callable=AsyncMock
                ) as mock_cleanup:
                    result = await kvm_creation.create_vm(sample_vm_config)

        assert result["success"] is False
        assert "Unexpected" in result["error"]
        mock_cleanup.assert_called_once_with("test-vm")


class TestListVms:
    """Tests for list_vms method."""

    def test_list_vms_success(self, kvm_creation):
        """Test listing VMs successfully."""
        virsh_output = """ Id   Name       State
-----------------------------
 1    test-vm1   running
 -    test-vm2   shut off
"""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = Mock(returncode=0, stdout=virsh_output, stderr="")
            with patch.object(kvm_creation, "_get_vm_info", return_value={}):
                result = kvm_creation.list_vms()

        assert result["success"] is True
        assert len(result["vms"]) == 2
        assert result["vms"][0]["name"] == "test-vm1"
        assert result["vms"][0]["state"] == "running"
        assert result["vms"][0]["id"] == "1"
        assert result["vms"][1]["name"] == "test-vm2"
        assert result["vms"][1]["state"] == "shut off"
        assert result["vms"][1]["id"] is None

    def test_list_vms_empty(self, kvm_creation):
        """Test listing VMs when none exist."""
        virsh_output = """ Id   Name       State
-----------------------------

"""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = Mock(returncode=0, stdout=virsh_output, stderr="")
            result = kvm_creation.list_vms()

        assert result["success"] is True
        assert len(result["vms"]) == 0

    def test_list_vms_failure(self, kvm_creation):
        """Test listing VMs when virsh fails."""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = Mock(
                returncode=1, stdout="", stderr="Failed to connect"
            )
            result = kvm_creation.list_vms()

        assert result["success"] is False
        assert "Failed to connect" in result["error"]

    def test_list_vms_failure_no_stderr(self, kvm_creation):
        """Test listing VMs failure with empty stderr."""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = Mock(returncode=1, stdout="", stderr="")
            result = kvm_creation.list_vms()

        assert result["success"] is False

    def test_list_vms_timeout(self, kvm_creation):
        """Test listing VMs with timeout."""
        with patch(
            "subprocess.run", side_effect=subprocess.TimeoutExpired("virsh", 30)
        ):
            result = kvm_creation.list_vms()

        assert result["success"] is False
        assert "timed out" in result["error"].lower()

    def test_list_vms_exception(self, kvm_creation):
        """Test listing VMs with exception."""
        with patch("subprocess.run", side_effect=Exception("Connection error")):
            result = kvm_creation.list_vms()

        assert result["success"] is False
        assert "Connection error" in result["error"]


class TestParseDominfoOutput:
    """Tests for _parse_dominfo_output method."""

    def test_parse_dominfo_output_full(self, kvm_creation):
        """Test parsing full dominfo output."""
        output = """Id:             1
Name:           test-vm
UUID:           12345678-1234-1234-1234-123456789abc
OS Type:        hvm
State:          running
CPU(s):         2
CPU time:       10.5s
Max memory:     4194304 KiB
Used memory:    2097152 KiB
Persistent:     yes
Autostart:      enable
"""
        result = kvm_creation._parse_dominfo_output(output)

        assert result["state"] == "running"
        assert result["cpu(s)"] == "2"
        assert result["max_memory"] == "4194304 KiB"
        assert result["used_memory"] == "2097152 KiB"
        assert result["autostart"] == "enable"

    def test_parse_dominfo_output_empty(self, kvm_creation):
        """Test parsing empty dominfo output."""
        result = kvm_creation._parse_dominfo_output("")
        assert result == {}

    def test_parse_dominfo_output_no_colon(self, kvm_creation):
        """Test parsing dominfo output without colons."""
        output = "No colon here\nStill no colon"
        result = kvm_creation._parse_dominfo_output(output)
        assert result == {}


class TestGetVmInfo:
    """Tests for _get_vm_info method."""

    def test_get_vm_info_success(self, kvm_creation):
        """Test getting VM info successfully."""
        dominfo_output = """State:          running
CPU(s):         2
Max memory:     4194304 KiB
"""
        domifaddr_output = """vnet0 52:54:00:ab:cd:ef ipv4 192.168.122.100/24"""

        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = [
                Mock(returncode=0, stdout=dominfo_output, stderr=""),
                Mock(returncode=0, stdout=domifaddr_output, stderr=""),
            ]
            with patch.object(
                kvm_creation,
                "_extract_ip_from_domifaddr",
                return_value="192.168.122.100",
            ):
                result = kvm_creation._get_vm_info("test-vm")

        assert result["state"] == "running"
        assert result["ip_address"] == "192.168.122.100"

    def test_get_vm_info_dominfo_failure(self, kvm_creation):
        """Test getting VM info when dominfo fails."""
        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = [
                Mock(returncode=1, stdout="", stderr="Not found"),
                Mock(returncode=0, stdout="", stderr=""),
            ]
            result = kvm_creation._get_vm_info("test-vm")

        assert "state" not in result

    def test_get_vm_info_no_ip(self, kvm_creation):
        """Test getting VM info when no IP available."""
        dominfo_output = """State:          running
"""
        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = [
                Mock(returncode=0, stdout=dominfo_output, stderr=""),
                Mock(returncode=0, stdout="", stderr=""),
            ]
            with patch.object(
                kvm_creation, "_extract_ip_from_domifaddr", return_value=None
            ):
                result = kvm_creation._get_vm_info("test-vm")

        assert "ip_address" not in result

    def test_get_vm_info_exception(self, kvm_creation):
        """Test getting VM info with exception."""
        with patch("subprocess.run", side_effect=Exception("Connection error")):
            result = kvm_creation._get_vm_info("test-vm")

        assert result == {}
