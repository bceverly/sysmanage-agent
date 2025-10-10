"""
Unit tests for antivirus deployment modules.
Tests deployment operations for Linux, BSD, and Windows systems.
"""

# pylint: disable=protected-access,too-many-public-methods,attribute-defined-outside-init

from unittest.mock import AsyncMock, Mock, patch, mock_open

import pytest

from src.sysmanage_agent.operations.antivirus_deploy_bsd import AntivirusDeployerBSD
from src.sysmanage_agent.operations.antivirus_deploy_linux import (
    AntivirusDeployerLinux,
)
from src.sysmanage_agent.operations.antivirus_deploy_windows import (
    AntivirusDeployerWindows,
)


class TestAntivirusDeployerLinux:
    """Test cases for AntivirusDeployerLinux class."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_logger = Mock()
        self.deployer = AntivirusDeployerLinux(self.mock_logger)

    @pytest.mark.asyncio
    async def test_deploy_opensuse_success(self):
        """Test successful deployment on openSUSE."""
        mock_detector = Mock()
        mock_detector.install_package.return_value = {"success": True}

        mock_process = AsyncMock()
        mock_process.returncode = 0
        mock_process.communicate = AsyncMock(return_value=(b"", b""))

        with patch(
            "src.sysmanage_agent.operations.antivirus_deploy_linux.UpdateDetector",
            return_value=mock_detector,
        ):
            with patch("asyncio.create_subprocess_exec", return_value=mock_process):
                with patch("asyncio.sleep", return_value=None):
                    result = await self.deployer.deploy_opensuse("clamav")

                    assert result["success"] is True
                    assert "openSUSE" in result["result"]
                    assert mock_detector.install_package.call_count == 3

    @pytest.mark.asyncio
    async def test_deploy_opensuse_service_failure(self):
        """Test deployment on openSUSE with service failure."""
        mock_detector = Mock()
        mock_detector.install_package.return_value = {"success": True}

        mock_process = AsyncMock()
        mock_process.returncode = 1
        mock_process.communicate = AsyncMock(return_value=(b"", b"Service failed"))

        with patch(
            "src.sysmanage_agent.operations.antivirus_deploy_linux.UpdateDetector",
            return_value=mock_detector,
        ):
            with patch("asyncio.create_subprocess_exec", return_value=mock_process):
                result = await self.deployer.deploy_opensuse("clamav")

                # Still returns success even if service fails to start
                assert result["success"] is True

    @pytest.mark.asyncio
    async def test_deploy_redhat_success(self):
        """Test successful deployment on RHEL/CentOS."""
        mock_detector = Mock()
        mock_detector.install_package.return_value = {"success": True}

        mock_process = AsyncMock()
        mock_process.returncode = 0
        mock_process.communicate = AsyncMock(return_value=(b"", b""))

        config_content = "#Example\n#LocalSocket /run/clamd.scan/clamd.sock"

        with patch(
            "src.sysmanage_agent.operations.antivirus_deploy_linux.UpdateDetector",
            return_value=mock_detector,
        ):
            with patch("asyncio.create_subprocess_exec", return_value=mock_process):
                with patch("builtins.open", mock_open(read_data=config_content)):
                    with patch("asyncio.sleep", return_value=None):
                        result = await self.deployer.deploy_redhat("clamav")

                        assert result["success"] is True
                        assert "RHEL" in result["result"]

    @pytest.mark.asyncio
    async def test_deploy_redhat_freshclam_failure(self):
        """Test deployment on RHEL with freshclam failure."""
        mock_detector = Mock()
        mock_detector.install_package.return_value = {"success": True}

        # First process (freshclam) fails, rest succeed
        mock_process_fail = AsyncMock()
        mock_process_fail.returncode = 1
        mock_process_fail.communicate = AsyncMock(return_value=(b"", b"Update failed"))

        mock_process_success = AsyncMock()
        mock_process_success.returncode = 0
        mock_process_success.communicate = AsyncMock(return_value=(b"", b""))

        config_content = "#Example\n#LocalSocket /run/clamd.scan/clamd.sock"

        with patch(
            "src.sysmanage_agent.operations.antivirus_deploy_linux.UpdateDetector",
            return_value=mock_detector,
        ):
            with patch(
                "asyncio.create_subprocess_exec",
                side_effect=[mock_process_fail, mock_process_success],
            ):
                with patch("builtins.open", mock_open(read_data=config_content)):
                    with patch("asyncio.sleep", return_value=None):
                        result = await self.deployer.deploy_redhat("clamav")

                        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_deploy_debian_success_dict_result(self):
        """Test successful deployment on Debian with dict result."""
        mock_detector = Mock()
        mock_detector.install_package.return_value = {
            "success": True,
            "version": "1.0.0",
        }

        mock_process = AsyncMock()
        mock_process.returncode = 0
        mock_process.communicate = AsyncMock(return_value=(b"", b""))

        with patch(
            "src.sysmanage_agent.operations.antivirus_deploy_linux.UpdateDetector",
            return_value=mock_detector,
        ):
            with patch("asyncio.create_subprocess_exec", return_value=mock_process):
                with patch("asyncio.sleep", return_value=None):
                    result = await self.deployer.deploy_debian("clamav")

                    assert result["success"] is True
                    assert result["installed_version"] == "1.0.0"

    @pytest.mark.asyncio
    async def test_deploy_debian_success_string_result(self):
        """Test deployment on Debian with string result."""
        mock_detector = Mock()
        mock_detector.install_package.return_value = "Package installed successfully"

        mock_process = AsyncMock()
        mock_process.returncode = 0
        mock_process.communicate = AsyncMock(return_value=(b"", b""))

        with patch(
            "src.sysmanage_agent.operations.antivirus_deploy_linux.UpdateDetector",
            return_value=mock_detector,
        ):
            with patch("asyncio.create_subprocess_exec", return_value=mock_process):
                with patch("asyncio.sleep", return_value=None):
                    result = await self.deployer.deploy_debian("clamav")

                    assert result["success"] is True

    @pytest.mark.asyncio
    async def test_deploy_debian_failure_dict_result(self):
        """Test deployment on Debian with dict failure result."""
        mock_detector = Mock()
        mock_detector.install_package.return_value = {
            "success": False,
            "error": "Package not found",
        }

        with patch(
            "src.sysmanage_agent.operations.antivirus_deploy_linux.UpdateDetector",
            return_value=mock_detector,
        ):
            result = await self.deployer.deploy_debian("clamav")

            assert result["success"] is False
            assert result["error_message"] == "Package not found"

    @pytest.mark.asyncio
    async def test_deploy_debian_failure_string_result(self):
        """Test deployment on Debian with string error result."""
        mock_detector = Mock()
        mock_detector.install_package.return_value = "Error: Failed to install"

        with patch(
            "src.sysmanage_agent.operations.antivirus_deploy_linux.UpdateDetector",
            return_value=mock_detector,
        ):
            result = await self.deployer.deploy_debian("clamav")

            assert result["success"] is False
            assert "Error: Failed to install" in result["error_message"]

    @pytest.mark.asyncio
    async def test_deploy_debian_service_exception(self):
        """Test deployment on Debian with service exception."""
        mock_detector = Mock()
        mock_detector.install_package.return_value = {"success": True}

        with patch(
            "src.sysmanage_agent.operations.antivirus_deploy_linux.UpdateDetector",
            return_value=mock_detector,
        ):
            with patch(
                "asyncio.create_subprocess_exec",
                side_effect=Exception("Service error"),
            ):
                result = await self.deployer.deploy_debian("clamav")

                # Should still return success for package install
                assert result["success"] is True

    @pytest.mark.asyncio
    async def test_deploy_debian_non_clamav_package(self):
        """Test deployment on Debian with non-ClamAV package."""
        mock_detector = Mock()
        mock_detector.install_package.return_value = {"success": True}

        with patch(
            "src.sysmanage_agent.operations.antivirus_deploy_linux.UpdateDetector",
            return_value=mock_detector,
        ):
            result = await self.deployer.deploy_debian("other-av")

            # Should not try to enable service
            assert result["success"] is True


class TestAntivirusDeployerBSD:
    """Test cases for AntivirusDeployerBSD class."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_logger = Mock()
        self.deployer = AntivirusDeployerBSD(self.mock_logger)

    @pytest.mark.asyncio
    async def test_deploy_macos_success(self):
        """Test successful deployment on macOS."""
        mock_detector = Mock()
        mock_detector.install_package.return_value = {"success": True}

        mock_process = AsyncMock()
        mock_process.returncode = 0
        mock_process.communicate = AsyncMock(return_value=(b"", b""))

        with patch(
            "src.sysmanage_agent.operations.antivirus_deploy_bsd.UpdateDetector",
            return_value=mock_detector,
        ):
            with patch("os.path.exists", return_value=True):
                with patch("os.makedirs"):
                    with patch(
                        "asyncio.create_subprocess_exec", return_value=mock_process
                    ):
                        with patch("asyncio.sleep", return_value=None):
                            with patch(
                                "src.sysmanage_agent.operations.antivirus_deploy_bsd.os.geteuid",
                                return_value=1000,
                                create=True,
                            ):
                                result = await self.deployer.deploy_macos("clamav")

                                assert result["success"] is True
                                assert "macOS" in result["result"]

    @pytest.mark.asyncio
    async def test_deploy_macos_as_root(self):
        """Test deployment on macOS as root."""
        mock_detector = Mock()
        mock_detector.install_package.return_value = {"success": True}

        mock_process = AsyncMock()
        mock_process.returncode = 0
        mock_process.communicate = AsyncMock(return_value=(b"", b""))

        with patch(
            "src.sysmanage_agent.operations.antivirus_deploy_bsd.UpdateDetector",
            return_value=mock_detector,
        ):
            with patch("os.path.exists", return_value=True):
                with patch("os.makedirs"):
                    with patch(
                        "asyncio.create_subprocess_exec", return_value=mock_process
                    ):
                        with patch("asyncio.sleep", return_value=None):
                            with patch(
                                "src.sysmanage_agent.operations.antivirus_deploy_bsd.os.geteuid",
                                return_value=0,
                                create=True,
                            ):
                                with patch(
                                    "src.sysmanage_agent.operations.antivirus_deploy_bsd._get_brew_user",
                                    return_value="brewuser",
                                ):
                                    result = await self.deployer.deploy_macos("clamav")

                                    assert result["success"] is True

    @pytest.mark.asyncio
    async def test_deploy_macos_intel_architecture(self):
        """Test deployment on macOS Intel architecture."""
        mock_detector = Mock()
        mock_detector.install_package.return_value = {"success": True}

        mock_process = AsyncMock()
        mock_process.returncode = 0
        mock_process.communicate = AsyncMock(return_value=(b"", b""))

        def mock_exists(path):
            # Simulate Intel Mac (no /opt/homebrew)
            if path == "/opt/homebrew":
                return False
            if "/usr/local" in path:
                return True
            return False

        with patch(
            "src.sysmanage_agent.operations.antivirus_deploy_bsd.UpdateDetector",
            return_value=mock_detector,
        ):
            with patch("os.path.exists", side_effect=mock_exists):
                with patch("os.makedirs"):
                    with patch(
                        "asyncio.create_subprocess_exec", return_value=mock_process
                    ):
                        with patch("asyncio.sleep", return_value=None):
                            with patch(
                                "src.sysmanage_agent.operations.antivirus_deploy_bsd.os.geteuid",
                                return_value=1000,
                                create=True,
                            ):
                                result = await self.deployer.deploy_macos("clamav")

                                assert result["success"] is True

    @pytest.mark.asyncio
    async def test_deploy_netbsd_success(self):
        """Test successful deployment on NetBSD."""
        mock_detector = Mock()
        mock_detector.install_package.return_value = {"success": True}

        mock_process = AsyncMock()
        mock_process.returncode = 0
        mock_process.communicate = AsyncMock(return_value=(b"", b""))

        with patch(
            "src.sysmanage_agent.operations.antivirus_deploy_bsd.UpdateDetector",
            return_value=mock_detector,
        ):
            with patch("os.path.exists", return_value=True):
                with patch("asyncio.create_subprocess_exec", return_value=mock_process):
                    with patch("asyncio.sleep", return_value=None):
                        result = await self.deployer.deploy_netbsd("clamav")

                        assert result["success"] is True
                        assert "NetBSD" in result["result"]

    @pytest.mark.asyncio
    async def test_deploy_netbsd_database_timeout(self):
        """Test deployment on NetBSD with database download timeout."""
        mock_detector = Mock()
        mock_detector.install_package.return_value = {"success": True}

        mock_process = AsyncMock()
        mock_process.returncode = 0
        mock_process.communicate = AsyncMock(return_value=(b"", b""))

        with patch(
            "src.sysmanage_agent.operations.antivirus_deploy_bsd.UpdateDetector",
            return_value=mock_detector,
        ):
            with patch("os.path.exists", return_value=False):  # Database never appears
                with patch("asyncio.create_subprocess_exec", return_value=mock_process):
                    with patch("asyncio.sleep", return_value=None):
                        result = await self.deployer.deploy_netbsd("clamav")

                        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_deploy_freebsd_success(self):
        """Test successful deployment on FreeBSD."""
        mock_detector = Mock()
        mock_detector.install_package.return_value = {"success": True}

        mock_process = AsyncMock()
        mock_process.returncode = 0
        mock_process.communicate = AsyncMock(return_value=(b"", b""))

        with patch(
            "src.sysmanage_agent.operations.antivirus_deploy_bsd.UpdateDetector",
            return_value=mock_detector,
        ):
            with patch("os.path.exists", return_value=True):
                with patch("asyncio.create_subprocess_exec", return_value=mock_process):
                    with patch("asyncio.sleep", return_value=None):
                        result = await self.deployer.deploy_freebsd("clamav")

                        assert result["success"] is True
                        assert "FreeBSD" in result["result"]

    @pytest.mark.asyncio
    async def test_deploy_freebsd_database_ready(self):
        """Test deployment on FreeBSD with database ready quickly."""
        mock_detector = Mock()
        mock_detector.install_package.return_value = {"success": True}

        mock_process = AsyncMock()
        mock_process.returncode = 0
        mock_process.communicate = AsyncMock(return_value=(b"", b""))

        def mock_exists(path):
            if "main.cvd" in path:
                return True
            return False

        with patch(
            "src.sysmanage_agent.operations.antivirus_deploy_bsd.UpdateDetector",
            return_value=mock_detector,
        ):
            with patch("os.path.exists", side_effect=mock_exists):
                with patch("asyncio.create_subprocess_exec", return_value=mock_process):
                    with patch("asyncio.sleep", return_value=None):
                        result = await self.deployer.deploy_freebsd("clamav")

                        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_deploy_openbsd_success(self):
        """Test successful deployment on OpenBSD."""
        mock_detector = Mock()
        mock_detector.install_package.return_value = {"success": True}

        mock_process = AsyncMock()
        mock_process.returncode = 0
        mock_process.communicate = AsyncMock(return_value=(b"", b""))

        with patch(
            "src.sysmanage_agent.operations.antivirus_deploy_bsd.UpdateDetector",
            return_value=mock_detector,
        ):
            with patch("os.path.exists", return_value=True):
                with patch("asyncio.create_subprocess_exec", return_value=mock_process):
                    with patch("asyncio.sleep", return_value=None):
                        result = await self.deployer.deploy_openbsd("clamav")

                        assert result["success"] is True
                        assert "OpenBSD" in result["result"]

    @pytest.mark.asyncio
    async def test_deploy_openbsd_create_runtime_directory(self):
        """Test deployment on OpenBSD creating runtime directory."""
        mock_detector = Mock()
        mock_detector.install_package.return_value = {"success": True}

        mock_process = AsyncMock()
        mock_process.returncode = 0
        mock_process.communicate = AsyncMock(return_value=(b"", b""))

        def mock_exists(path):
            if path == "/var/run/clamav":
                return False  # Directory doesn't exist yet
            return True

        with patch(
            "src.sysmanage_agent.operations.antivirus_deploy_bsd.UpdateDetector",
            return_value=mock_detector,
        ):
            with patch("os.path.exists", side_effect=mock_exists):
                with patch("asyncio.create_subprocess_exec", return_value=mock_process):
                    with patch("asyncio.sleep", return_value=None):
                        result = await self.deployer.deploy_openbsd("clamav")

                        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_deploy_openbsd_database_main_cld(self):
        """Test deployment on OpenBSD with .cld database file."""
        mock_detector = Mock()
        mock_detector.install_package.return_value = {"success": True}

        mock_process = AsyncMock()
        mock_process.returncode = 0
        mock_process.communicate = AsyncMock(return_value=(b"", b""))

        def mock_exists(path):
            if "main.cld" in path:
                return True
            return False

        with patch(
            "src.sysmanage_agent.operations.antivirus_deploy_bsd.UpdateDetector",
            return_value=mock_detector,
        ):
            with patch("os.path.exists", side_effect=mock_exists):
                with patch("asyncio.create_subprocess_exec", return_value=mock_process):
                    with patch("asyncio.sleep", return_value=None):
                        result = await self.deployer.deploy_openbsd("clamav")

                        assert result["success"] is True


class TestAntivirusDeployerWindows:
    """Test cases for AntivirusDeployerWindows class."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_logger = Mock()
        self.deployer = AntivirusDeployerWindows(self.mock_logger)

    @pytest.mark.asyncio
    async def test_deploy_windows_success(self):
        """Test successful deployment on Windows."""
        mock_detector = Mock()
        mock_detector.install_package.return_value = {"success": True}

        mock_process = AsyncMock()
        mock_process.returncode = 0
        mock_process.communicate = AsyncMock(return_value=(b"", b""))

        with patch(
            "src.sysmanage_agent.operations.antivirus_deploy_windows.UpdateDetector",
            return_value=mock_detector,
        ):
            with patch("os.path.exists", return_value=True):
                with patch("asyncio.create_subprocess_exec", return_value=mock_process):
                    with patch("asyncio.sleep", return_value=None):
                        result = await self.deployer.deploy_windows("clamav")

                        assert result["success"] is True
                        assert "Windows" in result["result"]

    @pytest.mark.asyncio
    async def test_deploy_windows_install_failure(self):
        """Test deployment on Windows with installation failure."""
        mock_detector = Mock()
        mock_detector.install_package.return_value = {
            "success": False,
            "error": "Package not found",
        }

        with patch(
            "src.sysmanage_agent.operations.antivirus_deploy_windows.UpdateDetector",
            return_value=mock_detector,
        ):
            result = await self.deployer.deploy_windows("clamav")

            assert result["success"] is False
            assert "Package not found" in result["error"]

    @pytest.mark.asyncio
    async def test_deploy_windows_directory_not_found(self):
        """Test deployment on Windows when installation directory not found."""
        mock_detector = Mock()
        mock_detector.install_package.return_value = {"success": True}

        with patch(
            "src.sysmanage_agent.operations.antivirus_deploy_windows.UpdateDetector",
            return_value=mock_detector,
        ):
            with patch("os.path.exists", return_value=False):
                result = await self.deployer.deploy_windows("clamav")

                assert result["success"] is False
                assert "Installation directory not found" in result["error"]

    @pytest.mark.asyncio
    async def test_deploy_windows_freshclam_not_found(self):
        """Test deployment on Windows when freshclam.exe not found."""
        mock_detector = Mock()
        mock_detector.install_package.return_value = {"success": True}

        def mock_exists(path):
            if "ClamWin\\bin" in path:
                return True
            if "freshclam.exe" in path:
                return False
            return False

        with patch(
            "src.sysmanage_agent.operations.antivirus_deploy_windows.UpdateDetector",
            return_value=mock_detector,
        ):
            with patch("os.path.exists", side_effect=mock_exists):
                with patch("asyncio.sleep", return_value=None):
                    result = await self.deployer.deploy_windows("clamav")

                    # Still succeeds even if freshclam not found
                    assert result["success"] is True

    @pytest.mark.asyncio
    async def test_deploy_windows_freshclam_failure(self):
        """Test deployment on Windows with freshclam failure."""
        mock_detector = Mock()
        mock_detector.install_package.return_value = {"success": True}

        mock_process = AsyncMock()
        mock_process.returncode = 1
        mock_process.communicate = AsyncMock(return_value=(b"", b"Update failed"))

        with patch(
            "src.sysmanage_agent.operations.antivirus_deploy_windows.UpdateDetector",
            return_value=mock_detector,
        ):
            with patch("os.path.exists", return_value=True):
                with patch("asyncio.create_subprocess_exec", return_value=mock_process):
                    with patch("asyncio.sleep", return_value=None):
                        result = await self.deployer.deploy_windows("clamav")

                        # Still succeeds even if freshclam fails
                        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_deploy_windows_freshclam_exception(self):
        """Test deployment on Windows with freshclam exception."""
        mock_detector = Mock()
        mock_detector.install_package.return_value = {"success": True}

        with patch(
            "src.sysmanage_agent.operations.antivirus_deploy_windows.UpdateDetector",
            return_value=mock_detector,
        ):
            with patch("os.path.exists", return_value=True):
                with patch(
                    "asyncio.create_subprocess_exec",
                    side_effect=Exception("Process error"),
                ):
                    with patch("asyncio.sleep", return_value=None):
                        result = await self.deployer.deploy_windows("clamav")

                        # Still succeeds even if freshclam raises exception
                        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_deploy_windows_alternative_path(self):
        """Test deployment on Windows using alternative installation path."""
        mock_detector = Mock()
        mock_detector.install_package.return_value = {"success": True}

        mock_process = AsyncMock()
        mock_process.returncode = 0
        mock_process.communicate = AsyncMock(return_value=(b"", b""))

        def mock_exists(path):
            # First path doesn't exist, second one does
            if "Program Files\\ClamWin" in path:
                return False
            if "Program Files (x86)\\ClamWin" in path:
                return True
            if "freshclam.exe" in path and "(x86)" in path:
                return True
            return False

        with patch(
            "src.sysmanage_agent.operations.antivirus_deploy_windows.UpdateDetector",
            return_value=mock_detector,
        ):
            with patch("os.path.exists", side_effect=mock_exists):
                with patch("asyncio.create_subprocess_exec", return_value=mock_process):
                    with patch("asyncio.sleep", return_value=None):
                        result = await self.deployer.deploy_windows("clamav")

                        assert result["success"] is True
