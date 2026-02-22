"""
Comprehensive unit tests for src.sysmanage_agent.operations.child_host_vmm_bsd_embedder module.
Tests OpenBSD bsd.rd embedding operations for VMM autoinstall.
"""

# pylint: disable=protected-access,attribute-defined-outside-init

import subprocess
from pathlib import Path
from unittest.mock import Mock, MagicMock, patch

from src.sysmanage_agent.operations.child_host_vmm_bsd_embedder import BsdRdEmbedder


class TestBsdRdEmbedderInit:
    """Test cases for BsdRdEmbedder initialization."""

    def test_init_with_logger(self):
        """Test BsdRdEmbedder initialization with logger."""
        mock_logger = Mock()
        embedder = BsdRdEmbedder(mock_logger)

        assert embedder.logger == mock_logger

    def test_openbsd_mirror_constant(self):
        """Test OpenBSD mirror URL is correct."""
        mock_logger = Mock()
        embedder = BsdRdEmbedder(mock_logger)

        assert embedder.OPENBSD_MIRROR == "https://cdn.openbsd.org/pub/OpenBSD"


class TestDownloadBsdrd:
    """Test cases for _download_bsdrd method."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_logger = Mock()
        self.embedder = BsdRdEmbedder(self.mock_logger)

    @patch(
        "src.sysmanage_agent.operations.child_host_vmm_bsd_embedder.shutil.copyfileobj"
    )
    @patch(
        "src.sysmanage_agent.operations.child_host_vmm_bsd_embedder.open", create=True
    )
    @patch(
        "src.sysmanage_agent.operations.child_host_vmm_bsd_embedder.urllib.request.urlopen"
    )
    @patch("src.sysmanage_agent.operations.child_host_vmm_bsd_embedder.subprocess.run")
    def test_download_bsdrd_success(
        self, mock_run, mock_urlopen, mock_open, _mock_copyfileobj
    ):
        """Test successful bsd.rd download and decompression."""
        # Mock the Path objects
        mock_work_path = MagicMock(spec=Path)
        mock_compressed = MagicMock()
        mock_dest = MagicMock()

        mock_work_path.__truediv__ = Mock(side_effect=[mock_compressed, mock_dest])

        # Mock compressed file exists and is large enough
        mock_compressed.exists.return_value = True
        mock_compressed_stat = Mock()
        mock_compressed_stat.st_size = 2000000
        mock_compressed.stat.return_value = mock_compressed_stat

        # Mock dest file exists and is large enough
        mock_dest.exists.return_value = True
        mock_dest_stat = Mock()
        mock_dest_stat.st_size = 2000000
        mock_dest.stat.return_value = mock_dest_stat
        mock_dest.__str__ = Mock(return_value="/work/bsd.rd.orig")

        # Mock urlopen
        mock_response = MagicMock()
        mock_response.__enter__ = Mock(return_value=mock_response)
        mock_response.__exit__ = Mock(return_value=False)
        mock_urlopen.return_value = mock_response

        # Mock gunzip success
        mock_run.return_value = Mock(
            returncode=0,
            stdout=b"x" * 2000000,
            stderr=b"",
        )

        # Mock file open for writing
        mock_file = MagicMock()
        mock_open.return_value.__enter__ = Mock(return_value=mock_file)
        mock_open.return_value.__exit__ = Mock(return_value=False)

        result = self.embedder._download_bsdrd("7.7", mock_work_path)

        assert result["success"] is True
        assert result["error"] is None

    @patch(
        "src.sysmanage_agent.operations.child_host_vmm_bsd_embedder.shutil.copyfileobj"
    )
    @patch(
        "src.sysmanage_agent.operations.child_host_vmm_bsd_embedder.open", create=True
    )
    @patch(
        "src.sysmanage_agent.operations.child_host_vmm_bsd_embedder.urllib.request.urlopen"
    )
    def test_download_bsdrd_download_too_small(
        self, mock_urlopen, mock_open, _mock_copyfileobj
    ):
        """Test download failure when file is too small."""
        mock_work_path = MagicMock(spec=Path)
        mock_compressed = MagicMock()
        mock_dest = MagicMock()

        mock_work_path.__truediv__ = Mock(side_effect=[mock_compressed, mock_dest])

        # Mock compressed file is too small
        mock_compressed.exists.return_value = True
        mock_compressed_stat = Mock()
        mock_compressed_stat.st_size = 100  # Too small
        mock_compressed.stat.return_value = mock_compressed_stat

        # Mock urlopen
        mock_response = MagicMock()
        mock_response.__enter__ = Mock(return_value=mock_response)
        mock_response.__exit__ = Mock(return_value=False)
        mock_urlopen.return_value = mock_response

        mock_file = MagicMock()
        mock_open.return_value.__enter__ = Mock(return_value=mock_file)
        mock_open.return_value.__exit__ = Mock(return_value=False)

        result = self.embedder._download_bsdrd("7.7", mock_work_path)

        assert result["success"] is False
        assert "invalid" in result["error"].lower()

    @patch(
        "src.sysmanage_agent.operations.child_host_vmm_bsd_embedder.shutil.copyfileobj"
    )
    @patch(
        "src.sysmanage_agent.operations.child_host_vmm_bsd_embedder.open", create=True
    )
    @patch(
        "src.sysmanage_agent.operations.child_host_vmm_bsd_embedder.urllib.request.urlopen"
    )
    @patch("src.sysmanage_agent.operations.child_host_vmm_bsd_embedder.subprocess.run")
    def test_download_bsdrd_gunzip_failure(
        self, mock_run, mock_urlopen, mock_open, _mock_copyfileobj
    ):
        """Test download failure when gunzip fails."""
        mock_work_path = MagicMock(spec=Path)
        mock_compressed = MagicMock()
        mock_dest = MagicMock()

        mock_work_path.__truediv__ = Mock(side_effect=[mock_compressed, mock_dest])

        # Mock compressed file exists and is large enough
        mock_compressed.exists.return_value = True
        mock_compressed_stat = Mock()
        mock_compressed_stat.st_size = 2000000
        mock_compressed.stat.return_value = mock_compressed_stat
        mock_compressed.__str__ = Mock(return_value="/work/bsd.rd.gz")

        # Mock urlopen
        mock_response = MagicMock()
        mock_response.__enter__ = Mock(return_value=mock_response)
        mock_response.__exit__ = Mock(return_value=False)
        mock_urlopen.return_value = mock_response

        mock_file = MagicMock()
        mock_open.return_value.__enter__ = Mock(return_value=mock_file)
        mock_open.return_value.__exit__ = Mock(return_value=False)

        # Mock gunzip failure
        mock_run.return_value = Mock(
            returncode=1, stdout=b"", stderr=b"gzip: invalid format"
        )

        result = self.embedder._download_bsdrd("7.7", mock_work_path)

        assert result["success"] is False
        assert "gunzip failed" in result["error"]

    @patch(
        "src.sysmanage_agent.operations.child_host_vmm_bsd_embedder.shutil.copyfileobj"
    )
    @patch(
        "src.sysmanage_agent.operations.child_host_vmm_bsd_embedder.open", create=True
    )
    @patch(
        "src.sysmanage_agent.operations.child_host_vmm_bsd_embedder.urllib.request.urlopen"
    )
    @patch("src.sysmanage_agent.operations.child_host_vmm_bsd_embedder.subprocess.run")
    def test_download_bsdrd_decompressed_too_small(
        self, mock_run, mock_urlopen, mock_open, _mock_copyfileobj
    ):
        """Test download failure when decompressed file is too small."""
        mock_work_path = MagicMock(spec=Path)
        mock_compressed = MagicMock()
        mock_dest = MagicMock()

        mock_work_path.__truediv__ = Mock(side_effect=[mock_compressed, mock_dest])

        # Mock compressed file exists and is large enough
        mock_compressed.exists.return_value = True
        mock_compressed_stat = Mock()
        mock_compressed_stat.st_size = 2000000
        mock_compressed.stat.return_value = mock_compressed_stat
        mock_compressed.__str__ = Mock(return_value="/work/bsd.rd.gz")

        # Mock dest file is too small after decompression
        mock_dest.exists.return_value = True
        mock_dest_stat = Mock()
        mock_dest_stat.st_size = 100  # Too small
        mock_dest.stat.return_value = mock_dest_stat

        # Mock urlopen
        mock_response = MagicMock()
        mock_response.__enter__ = Mock(return_value=mock_response)
        mock_response.__exit__ = Mock(return_value=False)
        mock_urlopen.return_value = mock_response

        mock_file = MagicMock()
        mock_open.return_value.__enter__ = Mock(return_value=mock_file)
        mock_open.return_value.__exit__ = Mock(return_value=False)

        # Mock gunzip success with small output
        mock_run.return_value = Mock(returncode=0, stdout=b"small", stderr=b"")

        result = self.embedder._download_bsdrd("7.7", mock_work_path)

        assert result["success"] is False
        assert "invalid" in result["error"].lower()

    @patch(
        "src.sysmanage_agent.operations.child_host_vmm_bsd_embedder.urllib.request.urlopen"
    )
    def test_download_bsdrd_network_error(self, mock_urlopen):
        """Test download failure due to network error."""
        mock_work_path = MagicMock(spec=Path)

        mock_urlopen.side_effect = Exception("Network unreachable")

        result = self.embedder._download_bsdrd("7.7", mock_work_path)

        assert result["success"] is False
        assert "Download failed" in result["error"]
        assert "Network unreachable" in result["error"]

    @patch(
        "src.sysmanage_agent.operations.child_host_vmm_bsd_embedder.urllib.request.urlopen"
    )
    def test_download_bsdrd_correct_url(self, mock_urlopen):
        """Test that correct URL is constructed."""
        mock_work_path = MagicMock(spec=Path)

        mock_urlopen.side_effect = Exception("Test")

        self.embedder._download_bsdrd("7.7", mock_work_path)

        expected_url = "https://cdn.openbsd.org/pub/OpenBSD/7.7/amd64/bsd.rd"
        mock_urlopen.assert_called_once()
        actual_url = mock_urlopen.call_args[0][0]
        assert actual_url == expected_url


class TestExtractRamdisk:
    """Test cases for _extract_ramdisk method."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_logger = Mock()
        self.embedder = BsdRdEmbedder(self.mock_logger)

    @patch("src.sysmanage_agent.operations.child_host_vmm_bsd_embedder.subprocess.run")
    def test_extract_ramdisk_success(self, mock_run):
        """Test successful ramdisk extraction."""
        mock_work_path = MagicMock(spec=Path)
        mock_ramdisk = MagicMock()

        mock_work_path.__truediv__ = Mock(return_value=mock_ramdisk)
        mock_ramdisk.exists.return_value = True
        mock_ramdisk.__str__ = Mock(return_value="/work/ramdisk.img")

        mock_run.return_value = Mock(returncode=0, stdout="", stderr="")

        result = self.embedder._extract_ramdisk("/path/to/bsd.rd", mock_work_path)

        assert result["success"] is True
        assert result["error"] is None

    @patch("src.sysmanage_agent.operations.child_host_vmm_bsd_embedder.subprocess.run")
    def test_extract_ramdisk_rdsetroot_failure(self, mock_run):
        """Test ramdisk extraction failure when rdsetroot fails."""
        mock_work_path = MagicMock(spec=Path)
        mock_ramdisk = MagicMock()

        mock_work_path.__truediv__ = Mock(return_value=mock_ramdisk)
        mock_ramdisk.__str__ = Mock(return_value="/work/ramdisk.img")

        mock_run.return_value = Mock(
            returncode=1, stdout="", stderr="rdsetroot: invalid kernel"
        )

        result = self.embedder._extract_ramdisk("/path/to/bsd.rd", mock_work_path)

        assert result["success"] is False
        assert "rdsetroot extraction failed" in result["error"]

    @patch("src.sysmanage_agent.operations.child_host_vmm_bsd_embedder.subprocess.run")
    def test_extract_ramdisk_no_output(self, mock_run):
        """Test ramdisk extraction failure when no output file is created."""
        mock_work_path = MagicMock(spec=Path)
        mock_ramdisk = MagicMock()

        mock_work_path.__truediv__ = Mock(return_value=mock_ramdisk)
        mock_ramdisk.exists.return_value = False  # File not created
        mock_ramdisk.__str__ = Mock(return_value="/work/ramdisk.img")

        # rdsetroot returns success but doesn't create output
        mock_run.return_value = Mock(returncode=0, stdout="", stderr="")

        result = self.embedder._extract_ramdisk("/path/to/bsd.rd", mock_work_path)

        assert result["success"] is False
        assert "no output" in result["error"].lower()

    @patch("src.sysmanage_agent.operations.child_host_vmm_bsd_embedder.subprocess.run")
    def test_extract_ramdisk_timeout(self, mock_run):
        """Test ramdisk extraction timeout."""
        mock_work_path = MagicMock(spec=Path)
        mock_ramdisk = MagicMock()

        mock_work_path.__truediv__ = Mock(return_value=mock_ramdisk)
        mock_ramdisk.__str__ = Mock(return_value="/work/ramdisk.img")

        mock_run.side_effect = subprocess.TimeoutExpired(cmd="rdsetroot", timeout=60)

        result = self.embedder._extract_ramdisk("/path/to/bsd.rd", mock_work_path)

        assert result["success"] is False
        assert "timeout" in result["error"].lower()

    @patch("src.sysmanage_agent.operations.child_host_vmm_bsd_embedder.subprocess.run")
    def test_extract_ramdisk_exception(self, mock_run):
        """Test ramdisk extraction with unexpected exception."""
        mock_work_path = MagicMock(spec=Path)
        mock_ramdisk = MagicMock()

        mock_work_path.__truediv__ = Mock(return_value=mock_ramdisk)
        mock_ramdisk.__str__ = Mock(return_value="/work/ramdisk.img")

        mock_run.side_effect = Exception("Unexpected error")

        result = self.embedder._extract_ramdisk("/path/to/bsd.rd", mock_work_path)

        assert result["success"] is False
        assert "Extraction failed" in result["error"]

    @patch("src.sysmanage_agent.operations.child_host_vmm_bsd_embedder.subprocess.run")
    def test_extract_ramdisk_command_args(self, mock_run):
        """Test that rdsetroot is called with correct arguments."""
        mock_work_path = MagicMock(spec=Path)
        mock_ramdisk = MagicMock()

        mock_work_path.__truediv__ = Mock(return_value=mock_ramdisk)
        mock_ramdisk.__str__ = Mock(return_value="/work/ramdisk.img")
        mock_ramdisk.exists.return_value = False

        mock_run.return_value = Mock(returncode=1, stdout="", stderr="")

        self.embedder._extract_ramdisk("/path/to/bsd.rd", mock_work_path)

        mock_run.assert_called_once_with(
            ["rdsetroot", "-x", "/path/to/bsd.rd", "/work/ramdisk.img"],
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )


class TestCreateLargerRamdisk:
    """Test cases for _create_larger_ramdisk method."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_logger = Mock()
        self.embedder = BsdRdEmbedder(self.mock_logger)

    @patch("src.sysmanage_agent.operations.child_host_vmm_bsd_embedder.os.path.getsize")
    @patch("src.sysmanage_agent.operations.child_host_vmm_bsd_embedder.subprocess.run")
    def test_create_larger_ramdisk_success(self, mock_run, mock_getsize):
        """Test successful larger ramdisk creation."""
        mock_getsize.return_value = 10 * 1024 * 1024  # 10MB site.tgz

        # Mock both dd and newfs success
        mock_run.return_value = Mock(returncode=0, stdout="", stderr="")

        result = self.embedder._create_larger_ramdisk(
            "/path/to/ramdisk", "/path/to/site.tgz"
        )

        assert result["success"] is True
        assert result["new_ramdisk_path"] == "/path/to/ramdisk.large"
        assert mock_run.call_count == 2  # dd and newfs

    @patch("src.sysmanage_agent.operations.child_host_vmm_bsd_embedder.os.path.getsize")
    @patch("src.sysmanage_agent.operations.child_host_vmm_bsd_embedder.subprocess.run")
    def test_create_larger_ramdisk_dd_failure(self, mock_run, mock_getsize):
        """Test larger ramdisk creation failure when dd fails."""
        mock_getsize.return_value = 10 * 1024 * 1024

        mock_run.return_value = Mock(returncode=1, stdout="", stderr="dd: error")

        result = self.embedder._create_larger_ramdisk(
            "/path/to/ramdisk", "/path/to/site.tgz"
        )

        assert result["success"] is False
        assert "dd failed" in result["error"]

    @patch("src.sysmanage_agent.operations.child_host_vmm_bsd_embedder.os.path.getsize")
    @patch("src.sysmanage_agent.operations.child_host_vmm_bsd_embedder.subprocess.run")
    def test_create_larger_ramdisk_newfs_failure(self, mock_run, mock_getsize):
        """Test larger ramdisk creation failure when newfs fails."""
        mock_getsize.return_value = 10 * 1024 * 1024

        # dd succeeds, newfs fails
        mock_run.side_effect = [
            Mock(returncode=0, stdout="", stderr=""),  # dd success
            Mock(returncode=1, stdout="", stderr="newfs: error"),  # newfs failure
        ]

        result = self.embedder._create_larger_ramdisk(
            "/path/to/ramdisk", "/path/to/site.tgz"
        )

        assert result["success"] is False
        assert "newfs failed" in result["error"]

    @patch("src.sysmanage_agent.operations.child_host_vmm_bsd_embedder.os.path.getsize")
    @patch("src.sysmanage_agent.operations.child_host_vmm_bsd_embedder.subprocess.run")
    def test_create_larger_ramdisk_dd_command_args(self, mock_run, mock_getsize):
        """Test that dd is called with correct arguments."""
        mock_getsize.return_value = 10 * 1024 * 1024
        mock_run.return_value = Mock(returncode=0, stdout="", stderr="")

        self.embedder._create_larger_ramdisk("/path/to/ramdisk", "/path/to/site.tgz")

        dd_call = mock_run.call_args_list[0]
        expected_args = [
            "dd",
            "if=/dev/zero",
            "of=/path/to/ramdisk.large",
            "bs=1m",
            "count=200",
        ]
        assert dd_call[0][0] == expected_args

    @patch("src.sysmanage_agent.operations.child_host_vmm_bsd_embedder.os.path.getsize")
    @patch("src.sysmanage_agent.operations.child_host_vmm_bsd_embedder.subprocess.run")
    def test_create_larger_ramdisk_newfs_command_args(self, mock_run, mock_getsize):
        """Test that newfs is called with correct arguments."""
        mock_getsize.return_value = 10 * 1024 * 1024
        mock_run.return_value = Mock(returncode=0, stdout="", stderr="")

        self.embedder._create_larger_ramdisk("/path/to/ramdisk", "/path/to/site.tgz")

        newfs_call = mock_run.call_args_list[1]
        expected_args = ["newfs", "-m", "0", "-o", "space", "/path/to/ramdisk.large"]
        assert newfs_call[0][0] == expected_args


class TestMountRamdisk:
    """Test cases for _mount_ramdisk method."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_logger = Mock()
        self.embedder = BsdRdEmbedder(self.mock_logger)

    @patch(
        "src.sysmanage_agent.operations.child_host_vmm_bsd_embedder.tempfile.mkdtemp"
    )
    @patch("src.sysmanage_agent.operations.child_host_vmm_bsd_embedder.subprocess.run")
    def test_mount_ramdisk_success(self, mock_run, mock_mkdtemp):
        """Test successful ramdisk mounting."""
        mock_mkdtemp.return_value = "/tmp/ramdisk-vnd0-abc123"
        mock_run.return_value = Mock(returncode=0, stdout="", stderr="")

        result = self.embedder._mount_ramdisk("/path/to/ramdisk", "vnd0")

        assert result["success"] is True
        assert result["mount_point"] == "/tmp/ramdisk-vnd0-abc123"
        assert mock_run.call_count == 2  # vnconfig and mount

    @patch("src.sysmanage_agent.operations.child_host_vmm_bsd_embedder.subprocess.run")
    def test_mount_ramdisk_vnconfig_failure(self, mock_run):
        """Test ramdisk mounting failure when vnconfig fails."""
        mock_run.return_value = Mock(
            returncode=1, stdout="", stderr="vnconfig: device busy"
        )

        result = self.embedder._mount_ramdisk("/path/to/ramdisk", "vnd0")

        assert result["success"] is False
        assert "vnconfig vnd0 failed" in result["error"]

    @patch(
        "src.sysmanage_agent.operations.child_host_vmm_bsd_embedder.tempfile.mkdtemp"
    )
    @patch("src.sysmanage_agent.operations.child_host_vmm_bsd_embedder.subprocess.run")
    def test_mount_ramdisk_mount_failure(self, mock_run, mock_mkdtemp):
        """Test ramdisk mounting failure when mount fails."""
        mock_mkdtemp.return_value = "/tmp/ramdisk-vnd0-abc123"
        # vnconfig succeeds, mount fails
        mock_run.side_effect = [
            Mock(returncode=0, stdout="", stderr=""),  # vnconfig
            Mock(returncode=1, stdout="", stderr="mount: permission denied"),  # mount
        ]

        result = self.embedder._mount_ramdisk("/path/to/ramdisk", "vnd0")

        assert result["success"] is False
        assert "mount vnd0 failed" in result["error"]

    @patch(
        "src.sysmanage_agent.operations.child_host_vmm_bsd_embedder.tempfile.mkdtemp"
    )
    @patch("src.sysmanage_agent.operations.child_host_vmm_bsd_embedder.subprocess.run")
    def test_mount_ramdisk_read_only(self, mock_run, mock_mkdtemp):
        """Test ramdisk mounting with read-only flag."""
        mock_mkdtemp.return_value = "/tmp/ramdisk-vnd0-abc123"
        mock_run.return_value = Mock(returncode=0, stdout="", stderr="")

        self.embedder._mount_ramdisk("/path/to/ramdisk", "vnd0", read_only=True)

        mount_call = mock_run.call_args_list[1]
        mount_args = mount_call[0][0]
        assert "-r" in mount_args

    @patch(
        "src.sysmanage_agent.operations.child_host_vmm_bsd_embedder.tempfile.mkdtemp"
    )
    @patch("src.sysmanage_agent.operations.child_host_vmm_bsd_embedder.subprocess.run")
    def test_mount_ramdisk_write_mode(self, mock_run, mock_mkdtemp):
        """Test ramdisk mounting without read-only flag."""
        mock_mkdtemp.return_value = "/tmp/ramdisk-vnd0-abc123"
        mock_run.return_value = Mock(returncode=0, stdout="", stderr="")

        self.embedder._mount_ramdisk("/path/to/ramdisk", "vnd0", read_only=False)

        mount_call = mock_run.call_args_list[1]
        mount_args = mount_call[0][0]
        assert "-r" not in mount_args

    @patch(
        "src.sysmanage_agent.operations.child_host_vmm_bsd_embedder.tempfile.mkdtemp"
    )
    @patch("src.sysmanage_agent.operations.child_host_vmm_bsd_embedder.subprocess.run")
    def test_mount_ramdisk_vnconfig_args(self, mock_run, mock_mkdtemp):
        """Test vnconfig command arguments."""
        mock_mkdtemp.return_value = "/tmp/ramdisk-vnd0-abc123"
        mock_run.return_value = Mock(returncode=0, stdout="", stderr="")

        self.embedder._mount_ramdisk("/path/to/ramdisk", "vnd0")

        vnconfig_call = mock_run.call_args_list[0]
        expected_args = ["vnconfig", "vnd0", "/path/to/ramdisk"]
        assert vnconfig_call[0][0] == expected_args


class TestCopyRamdiskContents:
    """Test cases for _copy_ramdisk_contents method."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_logger = Mock()
        self.embedder = BsdRdEmbedder(self.mock_logger)

    @patch("src.sysmanage_agent.operations.child_host_vmm_bsd_embedder.os.path.exists")
    @patch("src.sysmanage_agent.operations.child_host_vmm_bsd_embedder.subprocess.run")
    def test_copy_ramdisk_contents_success(self, mock_run, mock_exists):
        """Test successful ramdisk content copy."""
        mock_run.return_value = Mock(returncode=0, stdout="", stderr="")
        mock_exists.return_value = True

        result = self.embedder._copy_ramdisk_contents(
            "/old/mount", "/new/mount", "/path/to/site.tgz", "7.7"
        )

        assert result["success"] is True
        assert mock_run.call_count == 2  # pax and cp

    @patch("src.sysmanage_agent.operations.child_host_vmm_bsd_embedder.subprocess.run")
    def test_copy_ramdisk_contents_pax_failure(self, mock_run):
        """Test copy failure when pax fails."""
        mock_run.return_value = Mock(returncode=1, stdout="", stderr="pax: error")

        result = self.embedder._copy_ramdisk_contents(
            "/old/mount", "/new/mount", "/path/to/site.tgz", "7.7"
        )

        assert result["success"] is False
        assert "pax copy failed" in result["error"]

    @patch("src.sysmanage_agent.operations.child_host_vmm_bsd_embedder.subprocess.run")
    def test_copy_ramdisk_contents_cp_failure(self, mock_run):
        """Test copy failure when cp fails."""
        # pax succeeds, cp fails
        mock_run.side_effect = [
            Mock(returncode=0, stdout="", stderr=""),  # pax
            Mock(returncode=1, stdout="", stderr="cp: error"),  # cp
        ]

        result = self.embedder._copy_ramdisk_contents(
            "/old/mount", "/new/mount", "/path/to/site.tgz", "7.7"
        )

        assert result["success"] is False
        assert "cp site.tgz failed" in result["error"]

    @patch("src.sysmanage_agent.operations.child_host_vmm_bsd_embedder.os.path.exists")
    @patch("src.sysmanage_agent.operations.child_host_vmm_bsd_embedder.subprocess.run")
    def test_copy_ramdisk_contents_file_not_created(self, mock_run, mock_exists):
        """Test copy failure when site.tgz is not created."""
        mock_run.return_value = Mock(returncode=0, stdout="", stderr="")
        mock_exists.return_value = False  # File not created

        result = self.embedder._copy_ramdisk_contents(
            "/old/mount", "/new/mount", "/path/to/site.tgz", "7.7"
        )

        assert result["success"] is False
        assert "Failed to copy site.tgz" in result["error"]

    @patch("src.sysmanage_agent.operations.child_host_vmm_bsd_embedder.os.path.exists")
    @patch("src.sysmanage_agent.operations.child_host_vmm_bsd_embedder.subprocess.run")
    def test_copy_ramdisk_contents_version_formatting(self, mock_run, mock_exists):
        """Test that site filename is correctly formatted."""
        mock_run.return_value = Mock(returncode=0, stdout="", stderr="")
        mock_exists.return_value = True

        self.embedder._copy_ramdisk_contents(
            "/old/mount", "/new/mount", "/path/to/site.tgz", "7.7"
        )

        cp_call = mock_run.call_args_list[1]
        cp_args = cp_call[0][0]
        # site77.tgz (dots removed from version)
        assert cp_args[2] == "/new/mount/site77.tgz"

    @patch("src.sysmanage_agent.operations.child_host_vmm_bsd_embedder.os.path.exists")
    @patch("src.sysmanage_agent.operations.child_host_vmm_bsd_embedder.subprocess.run")
    def test_copy_ramdisk_contents_pax_command(self, mock_run, mock_exists):
        """Test pax command construction."""
        mock_run.return_value = Mock(returncode=0, stdout="", stderr="")
        mock_exists.return_value = True

        self.embedder._copy_ramdisk_contents(
            "/old/mount", "/new/mount", "/path/to/site.tgz", "7.7"
        )

        pax_call = mock_run.call_args_list[0]
        pax_args = pax_call[0][0]
        assert pax_args == ["sh", "-c", "cd /old/mount && pax -rw -pe . /new/mount/"]


class TestCleanupMounts:
    """Test cases for _cleanup_mounts method."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_logger = Mock()
        self.embedder = BsdRdEmbedder(self.mock_logger)

    @patch("src.sysmanage_agent.operations.child_host_vmm_bsd_embedder.os.rmdir")
    @patch("src.sysmanage_agent.operations.child_host_vmm_bsd_embedder.subprocess.run")
    def test_cleanup_mounts_all_cleanup(self, mock_run, mock_rmdir):
        """Test cleanup with all mount points and devices."""
        mock_run.return_value = Mock(returncode=0)

        self.embedder._cleanup_mounts("/old/mount", "/new/mount", "vnd0", "vnd1")

        # Should call umount twice and vnconfig -u twice
        assert mock_run.call_count == 4
        assert mock_rmdir.call_count == 2

    @patch("src.sysmanage_agent.operations.child_host_vmm_bsd_embedder.os.rmdir")
    @patch("src.sysmanage_agent.operations.child_host_vmm_bsd_embedder.subprocess.run")
    def test_cleanup_mounts_partial_cleanup(self, mock_run, mock_rmdir):
        """Test cleanup with only some parameters."""
        mock_run.return_value = Mock(returncode=0)

        self.embedder._cleanup_mounts("/old/mount", None, "vnd0", None)

        # Should call umount once and vnconfig -u once
        assert mock_run.call_count == 2
        assert mock_rmdir.call_count == 1

    @patch("src.sysmanage_agent.operations.child_host_vmm_bsd_embedder.os.rmdir")
    @patch("src.sysmanage_agent.operations.child_host_vmm_bsd_embedder.subprocess.run")
    def test_cleanup_mounts_no_cleanup(self, mock_run, mock_rmdir):
        """Test cleanup with no parameters."""
        self.embedder._cleanup_mounts(None, None, None, None)

        mock_run.assert_not_called()
        mock_rmdir.assert_not_called()

    @patch("src.sysmanage_agent.operations.child_host_vmm_bsd_embedder.os.rmdir")
    @patch("src.sysmanage_agent.operations.child_host_vmm_bsd_embedder.subprocess.run")
    def test_cleanup_mounts_rmdir_failure(self, mock_run, mock_rmdir):
        """Test cleanup continues when rmdir fails."""
        mock_run.return_value = Mock(returncode=0)
        mock_rmdir.side_effect = OSError("Directory not empty")

        # Should not raise exception
        self.embedder._cleanup_mounts("/old/mount", None, "vnd0", None)

        # cleanup should still complete
        mock_run.assert_called()

    @patch("src.sysmanage_agent.operations.child_host_vmm_bsd_embedder.os.rmdir")
    @patch("src.sysmanage_agent.operations.child_host_vmm_bsd_embedder.subprocess.run")
    def test_cleanup_mounts_new_mount_rmdir_failure(self, mock_run, mock_rmdir):
        """Test cleanup continues when rmdir fails for new_mount."""
        mock_run.return_value = Mock(returncode=0)
        # First call (old_mount) succeeds, second call (new_mount) fails
        mock_rmdir.side_effect = [None, OSError("Directory not empty")]

        # Should not raise exception
        self.embedder._cleanup_mounts("/old/mount", "/new/mount", "vnd0", "vnd1")

        # All cleanup calls should still be attempted
        assert mock_run.call_count == 4
        assert mock_rmdir.call_count == 2


class TestEmbedSiteTarball:
    """Test cases for _embed_site_tarball method."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_logger = Mock()
        self.embedder = BsdRdEmbedder(self.mock_logger)

    @patch.object(BsdRdEmbedder, "_cleanup_mounts")
    @patch.object(BsdRdEmbedder, "_copy_ramdisk_contents")
    @patch.object(BsdRdEmbedder, "_mount_ramdisk")
    @patch.object(BsdRdEmbedder, "_create_larger_ramdisk")
    def test_embed_site_tarball_success(
        self, mock_create, mock_mount, mock_copy, mock_cleanup
    ):
        """Test successful site.tgz embedding."""
        mock_create.return_value = {
            "success": True,
            "new_ramdisk_path": "/path/to/ramdisk.large",
        }
        mock_mount.side_effect = [
            {"success": True, "mount_point": "/old/mount"},
            {"success": True, "mount_point": "/new/mount"},
        ]
        mock_copy.return_value = {"success": True}

        result = self.embedder._embed_site_tarball(
            "/path/to/ramdisk", "/path/to/site.tgz", "7.7"
        )

        assert result["success"] is True
        assert result["ramdisk_path"] == "/path/to/ramdisk.large"
        mock_cleanup.assert_called_once()

    @patch.object(BsdRdEmbedder, "_cleanup_mounts")
    @patch.object(BsdRdEmbedder, "_create_larger_ramdisk")
    def test_embed_site_tarball_create_failure(self, mock_create, mock_cleanup):
        """Test embedding failure when creating larger ramdisk fails."""
        mock_create.return_value = {"success": False, "error": "dd failed"}

        result = self.embedder._embed_site_tarball(
            "/path/to/ramdisk", "/path/to/site.tgz", "7.7"
        )

        assert result["success"] is False
        assert "dd failed" in result["error"]
        mock_cleanup.assert_called_once()

    @patch.object(BsdRdEmbedder, "_cleanup_mounts")
    @patch.object(BsdRdEmbedder, "_mount_ramdisk")
    @patch.object(BsdRdEmbedder, "_create_larger_ramdisk")
    def test_embed_site_tarball_mount_old_failure(
        self, mock_create, mock_mount, mock_cleanup
    ):
        """Test embedding failure when mounting old ramdisk fails."""
        mock_create.return_value = {
            "success": True,
            "new_ramdisk_path": "/path/to/ramdisk.large",
        }
        mock_mount.return_value = {"success": False, "error": "mount failed"}

        result = self.embedder._embed_site_tarball(
            "/path/to/ramdisk", "/path/to/site.tgz", "7.7"
        )

        assert result["success"] is False
        assert "mount failed" in result["error"]
        mock_cleanup.assert_called_once()

    @patch.object(BsdRdEmbedder, "_cleanup_mounts")
    @patch.object(BsdRdEmbedder, "_mount_ramdisk")
    @patch.object(BsdRdEmbedder, "_create_larger_ramdisk")
    def test_embed_site_tarball_mount_new_failure(
        self, mock_create, mock_mount, mock_cleanup
    ):
        """Test embedding failure when mounting new ramdisk fails."""
        mock_create.return_value = {
            "success": True,
            "new_ramdisk_path": "/path/to/ramdisk.large",
        }
        mock_mount.side_effect = [
            {"success": True, "mount_point": "/old/mount"},
            {"success": False, "error": "mount failed"},
        ]

        result = self.embedder._embed_site_tarball(
            "/path/to/ramdisk", "/path/to/site.tgz", "7.7"
        )

        assert result["success"] is False
        assert "mount failed" in result["error"]
        mock_cleanup.assert_called_once()

    @patch.object(BsdRdEmbedder, "_cleanup_mounts")
    @patch.object(BsdRdEmbedder, "_copy_ramdisk_contents")
    @patch.object(BsdRdEmbedder, "_mount_ramdisk")
    @patch.object(BsdRdEmbedder, "_create_larger_ramdisk")
    def test_embed_site_tarball_copy_failure(
        self, mock_create, mock_mount, mock_copy, mock_cleanup
    ):
        """Test embedding failure when copy fails."""
        mock_create.return_value = {
            "success": True,
            "new_ramdisk_path": "/path/to/ramdisk.large",
        }
        mock_mount.side_effect = [
            {"success": True, "mount_point": "/old/mount"},
            {"success": True, "mount_point": "/new/mount"},
        ]
        mock_copy.return_value = {"success": False, "error": "pax failed"}

        result = self.embedder._embed_site_tarball(
            "/path/to/ramdisk", "/path/to/site.tgz", "7.7"
        )

        assert result["success"] is False
        assert "pax failed" in result["error"]
        mock_cleanup.assert_called_once()

    @patch.object(BsdRdEmbedder, "_cleanup_mounts")
    @patch.object(BsdRdEmbedder, "_create_larger_ramdisk")
    def test_embed_site_tarball_timeout_exception(self, mock_create, mock_cleanup):
        """Test embedding with timeout exception."""
        mock_create.side_effect = subprocess.TimeoutExpired(cmd="dd", timeout=60)

        result = self.embedder._embed_site_tarball(
            "/path/to/ramdisk", "/path/to/site.tgz", "7.7"
        )

        assert result["success"] is False
        assert "Timeout" in result["error"]
        mock_cleanup.assert_called_once()

    @patch.object(BsdRdEmbedder, "_cleanup_mounts")
    @patch.object(BsdRdEmbedder, "_create_larger_ramdisk")
    def test_embed_site_tarball_generic_exception(self, mock_create, mock_cleanup):
        """Test embedding with generic exception."""
        mock_create.side_effect = Exception("Unexpected error")

        result = self.embedder._embed_site_tarball(
            "/path/to/ramdisk", "/path/to/site.tgz", "7.7"
        )

        assert result["success"] is False
        assert "Embed failed" in result["error"]
        mock_cleanup.assert_called_once()


class TestRepackBsdrd:
    """Test cases for _repack_bsdrd method."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_logger = Mock()
        self.embedder = BsdRdEmbedder(self.mock_logger)

    @patch("src.sysmanage_agent.operations.child_host_vmm_bsd_embedder.shutil.copy2")
    @patch("src.sysmanage_agent.operations.child_host_vmm_bsd_embedder.subprocess.run")
    @patch("src.sysmanage_agent.operations.child_host_vmm_bsd_embedder.Path.mkdir")
    @patch("src.sysmanage_agent.operations.child_host_vmm_bsd_embedder.Path.exists")
    @patch("src.sysmanage_agent.operations.child_host_vmm_bsd_embedder.Path.is_symlink")
    @patch("src.sysmanage_agent.operations.child_host_vmm_bsd_embedder.Path.unlink")
    @patch("src.sysmanage_agent.operations.child_host_vmm_bsd_embedder.Path.symlink_to")
    def test_repack_bsdrd_success(
        self,
        _mock_symlink_to,
        _mock_unlink,
        mock_is_symlink,
        mock_exists,
        _mock_mkdir,
        mock_run,
        mock_copy2,
    ):
        """Test successful bsd.rd repacking."""
        mock_run.return_value = Mock(returncode=0, stdout="", stderr="")
        mock_exists.return_value = True
        mock_is_symlink.return_value = False

        result = self.embedder._repack_bsdrd("/orig/bsd.rd", "/path/to/ramdisk", "7.7")

        assert result["success"] is True
        assert "7.7" in result["bsdrd_path"]
        mock_copy2.assert_called_once()

    @patch("src.sysmanage_agent.operations.child_host_vmm_bsd_embedder.shutil.copy2")
    @patch("src.sysmanage_agent.operations.child_host_vmm_bsd_embedder.subprocess.run")
    @patch("src.sysmanage_agent.operations.child_host_vmm_bsd_embedder.Path.mkdir")
    def test_repack_bsdrd_rdsetroot_failure(self, _mock_mkdir, mock_run, _mock_copy2):
        """Test repacking failure when rdsetroot fails."""
        mock_run.return_value = Mock(returncode=1, stdout="", stderr="rdsetroot: error")

        result = self.embedder._repack_bsdrd("/orig/bsd.rd", "/path/to/ramdisk", "7.7")

        assert result["success"] is False
        assert "rdsetroot insertion failed" in result["error"]

    @patch("src.sysmanage_agent.operations.child_host_vmm_bsd_embedder.shutil.copy2")
    @patch("src.sysmanage_agent.operations.child_host_vmm_bsd_embedder.subprocess.run")
    @patch("src.sysmanage_agent.operations.child_host_vmm_bsd_embedder.Path.mkdir")
    @patch("src.sysmanage_agent.operations.child_host_vmm_bsd_embedder.Path.exists")
    def test_repack_bsdrd_output_not_found(
        self, mock_exists, _mock_mkdir, mock_run, _mock_copy2
    ):
        """Test repacking failure when output file not found."""
        mock_run.return_value = Mock(returncode=0, stdout="", stderr="")
        mock_exists.return_value = False

        result = self.embedder._repack_bsdrd("/orig/bsd.rd", "/path/to/ramdisk", "7.7")

        assert result["success"] is False
        assert "not found" in result["error"].lower()

    @patch("src.sysmanage_agent.operations.child_host_vmm_bsd_embedder.shutil.copy2")
    @patch("src.sysmanage_agent.operations.child_host_vmm_bsd_embedder.subprocess.run")
    @patch("src.sysmanage_agent.operations.child_host_vmm_bsd_embedder.Path.mkdir")
    def test_repack_bsdrd_timeout(self, _mock_mkdir, mock_run, _mock_copy2):
        """Test repacking with timeout."""
        mock_run.side_effect = subprocess.TimeoutExpired(cmd="rdsetroot", timeout=60)

        result = self.embedder._repack_bsdrd("/orig/bsd.rd", "/path/to/ramdisk", "7.7")

        assert result["success"] is False
        assert "timeout" in result["error"].lower()

    @patch("src.sysmanage_agent.operations.child_host_vmm_bsd_embedder.shutil.copy2")
    @patch("src.sysmanage_agent.operations.child_host_vmm_bsd_embedder.subprocess.run")
    @patch("src.sysmanage_agent.operations.child_host_vmm_bsd_embedder.Path.mkdir")
    def test_repack_bsdrd_exception(self, _mock_mkdir, mock_run, _mock_copy2):
        """Test repacking with unexpected exception."""
        mock_run.side_effect = Exception("Unexpected error")

        result = self.embedder._repack_bsdrd("/orig/bsd.rd", "/path/to/ramdisk", "7.7")

        assert result["success"] is False
        assert "Repack failed" in result["error"]

    @patch("src.sysmanage_agent.operations.child_host_vmm_bsd_embedder.shutil.copy2")
    @patch("src.sysmanage_agent.operations.child_host_vmm_bsd_embedder.subprocess.run")
    @patch("src.sysmanage_agent.operations.child_host_vmm_bsd_embedder.Path.mkdir")
    @patch("src.sysmanage_agent.operations.child_host_vmm_bsd_embedder.Path.exists")
    @patch("src.sysmanage_agent.operations.child_host_vmm_bsd_embedder.Path.is_symlink")
    @patch("src.sysmanage_agent.operations.child_host_vmm_bsd_embedder.Path.unlink")
    @patch("src.sysmanage_agent.operations.child_host_vmm_bsd_embedder.Path.symlink_to")
    def test_repack_bsdrd_replaces_existing_symlink(
        self,
        mock_symlink_to,
        mock_unlink,
        mock_is_symlink,
        mock_exists,
        _mock_mkdir,
        mock_run,
        _mock_copy2,
    ):
        """Test that existing symlink is replaced."""
        mock_run.return_value = Mock(returncode=0, stdout="", stderr="")
        mock_exists.return_value = True
        mock_is_symlink.return_value = True

        self.embedder._repack_bsdrd("/orig/bsd.rd", "/path/to/ramdisk", "7.7")

        mock_unlink.assert_called()
        mock_symlink_to.assert_called()


class TestEmbedSiteInBsdrd:
    """Test cases for embed_site_in_bsdrd method (main orchestration)."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_logger = Mock()
        self.embedder = BsdRdEmbedder(self.mock_logger)

    @patch(
        "src.sysmanage_agent.operations.child_host_vmm_bsd_embedder.tempfile.TemporaryDirectory"
    )
    @patch.object(BsdRdEmbedder, "_repack_bsdrd")
    @patch.object(BsdRdEmbedder, "_embed_site_tarball")
    @patch.object(BsdRdEmbedder, "_extract_ramdisk")
    @patch.object(BsdRdEmbedder, "_download_bsdrd")
    def test_embed_site_in_bsdrd_success(
        self, mock_download, mock_extract, mock_embed, mock_repack, mock_tempdir
    ):
        """Test successful full bsd.rd embedding."""
        # Mock the context manager
        mock_tempdir.return_value.__enter__ = Mock(return_value="/tmp/work")
        mock_tempdir.return_value.__exit__ = Mock(return_value=False)

        mock_download.return_value = {
            "success": True,
            "bsdrd_path": "/path/to/bsd.rd.orig",
        }
        mock_extract.return_value = {
            "success": True,
            "ramdisk_path": "/path/to/ramdisk.img",
        }
        mock_embed.return_value = {
            "success": True,
            "ramdisk_path": "/path/to/ramdisk.large",
        }
        mock_repack.return_value = {
            "success": True,
            "bsdrd_path": "/var/vmm/pxeboot/bsd.rd.7.7",
            "error": None,
        }

        result = self.embedder.embed_site_in_bsdrd("7.7", "/path/to/site.tgz")

        assert result["success"] is True
        assert result["bsdrd_path"] == "/var/vmm/pxeboot/bsd.rd.7.7"
        self.mock_logger.info.assert_called()

    @patch(
        "src.sysmanage_agent.operations.child_host_vmm_bsd_embedder.tempfile.TemporaryDirectory"
    )
    @patch.object(BsdRdEmbedder, "_download_bsdrd")
    def test_embed_site_in_bsdrd_download_failure(self, mock_download, mock_tempdir):
        """Test embedding failure when download fails."""
        mock_tempdir.return_value.__enter__ = Mock(return_value="/tmp/work")
        mock_tempdir.return_value.__exit__ = Mock(return_value=False)

        mock_download.return_value = {
            "success": False,
            "bsdrd_path": None,
            "error": "Network error",
        }

        result = self.embedder.embed_site_in_bsdrd("7.7", "/path/to/site.tgz")

        assert result["success"] is False
        assert "Network error" in result["error"]

    @patch(
        "src.sysmanage_agent.operations.child_host_vmm_bsd_embedder.tempfile.TemporaryDirectory"
    )
    @patch.object(BsdRdEmbedder, "_extract_ramdisk")
    @patch.object(BsdRdEmbedder, "_download_bsdrd")
    def test_embed_site_in_bsdrd_extract_failure(
        self, mock_download, mock_extract, mock_tempdir
    ):
        """Test embedding failure when extraction fails."""
        mock_tempdir.return_value.__enter__ = Mock(return_value="/tmp/work")
        mock_tempdir.return_value.__exit__ = Mock(return_value=False)

        mock_download.return_value = {
            "success": True,
            "bsdrd_path": "/path/to/bsd.rd.orig",
        }
        mock_extract.return_value = {
            "success": False,
            "ramdisk_path": None,
            "error": "rdsetroot failed",
        }

        result = self.embedder.embed_site_in_bsdrd("7.7", "/path/to/site.tgz")

        assert result["success"] is False
        self.mock_logger.error.assert_called()

    @patch(
        "src.sysmanage_agent.operations.child_host_vmm_bsd_embedder.tempfile.TemporaryDirectory"
    )
    @patch.object(BsdRdEmbedder, "_embed_site_tarball")
    @patch.object(BsdRdEmbedder, "_extract_ramdisk")
    @patch.object(BsdRdEmbedder, "_download_bsdrd")
    def test_embed_site_in_bsdrd_embed_failure(
        self, mock_download, mock_extract, mock_embed, mock_tempdir
    ):
        """Test embedding failure when embedding site.tgz fails."""
        mock_tempdir.return_value.__enter__ = Mock(return_value="/tmp/work")
        mock_tempdir.return_value.__exit__ = Mock(return_value=False)

        mock_download.return_value = {
            "success": True,
            "bsdrd_path": "/path/to/bsd.rd.orig",
        }
        mock_extract.return_value = {
            "success": True,
            "ramdisk_path": "/path/to/ramdisk.img",
        }
        mock_embed.return_value = {
            "success": False,
            "error": "mount failed",
        }

        result = self.embedder.embed_site_in_bsdrd("7.7", "/path/to/site.tgz")

        assert result["success"] is False
        self.mock_logger.error.assert_called()

    @patch(
        "src.sysmanage_agent.operations.child_host_vmm_bsd_embedder.tempfile.TemporaryDirectory"
    )
    @patch.object(BsdRdEmbedder, "_repack_bsdrd")
    @patch.object(BsdRdEmbedder, "_embed_site_tarball")
    @patch.object(BsdRdEmbedder, "_extract_ramdisk")
    @patch.object(BsdRdEmbedder, "_download_bsdrd")
    def test_embed_site_in_bsdrd_repack_failure(
        self, mock_download, mock_extract, mock_embed, mock_repack, mock_tempdir
    ):
        """Test embedding failure when repacking fails."""
        mock_tempdir.return_value.__enter__ = Mock(return_value="/tmp/work")
        mock_tempdir.return_value.__exit__ = Mock(return_value=False)

        mock_download.return_value = {
            "success": True,
            "bsdrd_path": "/path/to/bsd.rd.orig",
        }
        mock_extract.return_value = {
            "success": True,
            "ramdisk_path": "/path/to/ramdisk.img",
        }
        mock_embed.return_value = {
            "success": True,
            "ramdisk_path": "/path/to/ramdisk.large",
        }
        mock_repack.return_value = {
            "success": False,
            "bsdrd_path": None,
            "error": "rdsetroot failed",
        }

        result = self.embedder.embed_site_in_bsdrd("7.7", "/path/to/site.tgz")

        assert result["success"] is False
        self.mock_logger.error.assert_called()

    @patch(
        "src.sysmanage_agent.operations.child_host_vmm_bsd_embedder.tempfile.TemporaryDirectory"
    )
    @patch.object(BsdRdEmbedder, "_download_bsdrd")
    def test_embed_site_in_bsdrd_exception(self, mock_download, mock_tempdir):
        """Test embedding with unexpected exception."""
        mock_tempdir.return_value.__enter__ = Mock(return_value="/tmp/work")
        mock_tempdir.return_value.__exit__ = Mock(return_value=False)

        mock_download.side_effect = Exception("Unexpected error")

        result = self.embedder.embed_site_in_bsdrd("7.7", "/path/to/site.tgz")

        assert result["success"] is False
        assert "Unexpected error" in result["error"]
        self.mock_logger.error.assert_called()

    @patch(
        "src.sysmanage_agent.operations.child_host_vmm_bsd_embedder.tempfile.TemporaryDirectory"
    )
    @patch.object(BsdRdEmbedder, "_repack_bsdrd")
    @patch.object(BsdRdEmbedder, "_embed_site_tarball")
    @patch.object(BsdRdEmbedder, "_extract_ramdisk")
    @patch.object(BsdRdEmbedder, "_download_bsdrd")
    def test_embed_site_in_bsdrd_logging(
        self, mock_download, mock_extract, mock_embed, mock_repack, mock_tempdir
    ):
        """Test that proper logging occurs during embedding."""
        mock_tempdir.return_value.__enter__ = Mock(return_value="/tmp/work")
        mock_tempdir.return_value.__exit__ = Mock(return_value=False)

        mock_download.return_value = {
            "success": True,
            "bsdrd_path": "/path/to/bsd.rd.orig",
        }
        mock_extract.return_value = {
            "success": True,
            "ramdisk_path": "/path/to/ramdisk.img",
        }
        mock_embed.return_value = {
            "success": True,
            "ramdisk_path": "/path/to/ramdisk.large",
        }
        mock_repack.return_value = {
            "success": True,
            "bsdrd_path": "/var/vmm/pxeboot/bsd.rd.7.7",
            "error": None,
        }

        self.embedder.embed_site_in_bsdrd("7.7", "/path/to/site.tgz")

        # Verify logging calls for each step
        info_calls = [call[0][0] for call in self.mock_logger.info.call_args_list]
        assert any("Embedding site.tgz" in str(call) for call in info_calls)
        assert any("Downloading bsd.rd" in str(call) for call in info_calls)
        assert any("Extracting ramdisk" in str(call) for call in info_calls)
        assert any("Adding site.tgz" in str(call) for call in info_calls)
        assert any("Repacking bsd.rd" in str(call) for call in info_calls)
        assert any("Successfully created" in str(call) for call in info_calls)


class TestBsdRdEmbedderVersionFormatting:
    """Test cases for version string handling."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_logger = Mock()
        self.embedder = BsdRdEmbedder(self.mock_logger)

    @patch("src.sysmanage_agent.operations.child_host_vmm_bsd_embedder.os.path.exists")
    @patch("src.sysmanage_agent.operations.child_host_vmm_bsd_embedder.subprocess.run")
    def test_version_76_formatting(self, mock_run, mock_exists):
        """Test version 7.6 site filename formatting."""
        mock_run.return_value = Mock(returncode=0, stdout="", stderr="")
        mock_exists.return_value = True

        self.embedder._copy_ramdisk_contents("/old", "/new", "/path/to/site.tgz", "7.6")

        cp_call = mock_run.call_args_list[1]
        assert "site76.tgz" in cp_call[0][0][2]

    @patch("src.sysmanage_agent.operations.child_host_vmm_bsd_embedder.os.path.exists")
    @patch("src.sysmanage_agent.operations.child_host_vmm_bsd_embedder.subprocess.run")
    def test_version_80_formatting(self, mock_run, mock_exists):
        """Test version 8.0 site filename formatting."""
        mock_run.return_value = Mock(returncode=0, stdout="", stderr="")
        mock_exists.return_value = True

        self.embedder._copy_ramdisk_contents("/old", "/new", "/path/to/site.tgz", "8.0")

        cp_call = mock_run.call_args_list[1]
        assert "site80.tgz" in cp_call[0][0][2]


class TestBsdRdEmbedderEdgeCases:
    """Edge case tests for BsdRdEmbedder."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_logger = Mock()
        self.embedder = BsdRdEmbedder(self.mock_logger)

    @patch(
        "src.sysmanage_agent.operations.child_host_vmm_bsd_embedder.urllib.request.urlopen"
    )
    def test_download_with_different_versions(self, mock_urlopen):
        """Test URL construction for different versions."""
        mock_work_path = MagicMock(spec=Path)
        mock_urlopen.side_effect = Exception("Test")

        for version in ["7.5", "7.6", "7.7", "8.0"]:
            self.embedder._download_bsdrd(version, mock_work_path)

            expected_url = f"https://cdn.openbsd.org/pub/OpenBSD/{version}/amd64/bsd.rd"
            actual_url = mock_urlopen.call_args[0][0]
            assert actual_url == expected_url

    @patch("src.sysmanage_agent.operations.child_host_vmm_bsd_embedder.os.rmdir")
    @patch("src.sysmanage_agent.operations.child_host_vmm_bsd_embedder.subprocess.run")
    def test_cleanup_handles_umount_failure(self, mock_run, _mock_rmdir):
        """Test cleanup continues even when umount fails."""
        mock_run.return_value = Mock(returncode=1, stderr="device busy")

        # Should not raise exception
        self.embedder._cleanup_mounts("/mount1", "/mount2", "vnd0", "vnd1")

        # All cleanup calls should still be attempted
        assert mock_run.call_count == 4

    @patch(
        "src.sysmanage_agent.operations.child_host_vmm_bsd_embedder.tempfile.TemporaryDirectory"
    )
    @patch.object(BsdRdEmbedder, "_download_bsdrd")
    def test_embed_handles_tempdir_cleanup(self, mock_download, mock_tempdir):
        """Test that temporary directory is cleaned up even on failure."""
        mock_tempdir.return_value.__enter__ = Mock(return_value="/tmp/work")
        mock_tempdir.return_value.__exit__ = Mock(return_value=False)

        mock_download.return_value = {
            "success": False,
            "bsdrd_path": None,
            "error": "Failed",
        }

        # This should not leave any temporary directories
        result = self.embedder.embed_site_in_bsdrd("7.7", "/path/to/site.tgz")

        assert result["success"] is False
        # Verify __exit__ was called (cleanup)
        mock_tempdir.return_value.__exit__.assert_called()

    @patch("src.sysmanage_agent.operations.child_host_vmm_bsd_embedder.subprocess.run")
    def test_extract_ramdisk_command_timeout_value(self, mock_run):
        """Test that extract ramdisk uses correct timeout."""
        mock_work_path = MagicMock(spec=Path)
        mock_ramdisk = MagicMock()

        mock_work_path.__truediv__ = Mock(return_value=mock_ramdisk)
        mock_ramdisk.__str__ = Mock(return_value="/work/ramdisk.img")
        mock_ramdisk.exists.return_value = False

        mock_run.return_value = Mock(returncode=1, stdout="", stderr="")

        self.embedder._extract_ramdisk("/path/to/bsd.rd", mock_work_path)

        call_kwargs = mock_run.call_args[1]
        assert call_kwargs["timeout"] == 60

    @patch(
        "src.sysmanage_agent.operations.child_host_vmm_bsd_embedder.tempfile.mkdtemp"
    )
    @patch("src.sysmanage_agent.operations.child_host_vmm_bsd_embedder.subprocess.run")
    def test_mount_ramdisk_device_naming(self, mock_run, mock_mkdtemp):
        """Test mount point naming includes device name."""
        mock_mkdtemp.return_value = "/tmp/ramdisk-vnd1-xyz"
        mock_run.return_value = Mock(returncode=0, stdout="", stderr="")

        result = self.embedder._mount_ramdisk("/path/to/ramdisk", "vnd1")

        mock_mkdtemp.assert_called_with(prefix="ramdisk-vnd1-")
        assert result["mount_point"] == "/tmp/ramdisk-vnd1-xyz"
