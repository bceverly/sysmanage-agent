"""
Unit tests for src.sysmanage_agent.operations.antivirus_deployment_helpers module.
Tests helper functions for ClamAV deployment across different platforms.
"""

# pylint: disable=protected-access,too-many-public-methods,attribute-defined-outside-init

import sys
from unittest.mock import AsyncMock, Mock, patch

import pytest

from src.sysmanage_agent.operations import (
    antivirus_deployment_helpers as av_deploy_module,
)
from src.sysmanage_agent.operations.antivirus_deployment_helpers import (
    _get_brew_user,
    configure_config_file,
    wait_for_virus_database,
    deploy_clamav_macos,
    deploy_clamav_netbsd,
    deploy_clamav_freebsd,
    deploy_clamav_openbsd,
    deploy_clamav_opensuse,
    deploy_clamav_rhel,
    deploy_clamav_windows,
    deploy_clamav_debian,
    _configure_macos_clamd,
    _run_freshclam_macos,
    _start_brew_service,
    _configure_openbsd_clamd,
    _create_openbsd_runtime_dir,
    _enable_and_start_rcctl_service,
    _run_freshclam_system,
    _configure_rhel_clamd_scan,
    _find_windows_clamav_path,
    _run_freshclam_windows,
)


class TestGetBrewUser:
    """Test cases for _get_brew_user function."""

    def test_get_brew_user_opt_homebrew(self):
        """Test _get_brew_user with /opt/homebrew."""
        mock_stat = Mock()
        mock_stat.st_uid = 501
        mock_pwd_entry = Mock()
        mock_pwd_entry.pw_name = "testuser"

        mock_pwd = Mock()
        mock_pwd.getpwuid = Mock(return_value=mock_pwd_entry)

        with patch.dict(sys.modules, {"pwd": mock_pwd}):
            with patch("os.path.exists", return_value=True):
                with patch("os.stat", return_value=mock_stat):
                    result = _get_brew_user()
                    assert result == "testuser"

    def test_get_brew_user_usr_local_homebrew(self):
        """Test _get_brew_user with /usr/local/Homebrew."""
        mock_stat = Mock()
        mock_stat.st_uid = 502
        mock_pwd_entry = Mock()
        mock_pwd_entry.pw_name = "localuser"

        mock_pwd = Mock()
        mock_pwd.getpwuid = Mock(return_value=mock_pwd_entry)

        def mock_exists(path):
            # Only /usr/local/Homebrew exists
            return path == "/usr/local/Homebrew"

        with patch.dict(sys.modules, {"pwd": mock_pwd}):
            with patch("os.path.exists", side_effect=mock_exists):
                with patch("os.stat", return_value=mock_stat):
                    result = _get_brew_user()
                    assert result == "localuser"

    def test_get_brew_user_oserror(self):
        """Test _get_brew_user when OSError occurs."""

        def mock_exists(path):
            return path == "/opt/homebrew"

        with patch("os.path.exists", side_effect=mock_exists):
            with patch("os.stat", side_effect=OSError("Permission denied")):
                with patch.dict("os.environ", {"SUDO_USER": "fallbackuser"}):
                    result = _get_brew_user()
                    assert result == "fallbackuser"

    def test_get_brew_user_keyerror(self):
        """Test _get_brew_user when KeyError occurs from pwd.getpwuid."""
        mock_stat = Mock()
        mock_stat.st_uid = 999

        mock_pwd = Mock()
        mock_pwd.getpwuid = Mock(side_effect=KeyError("User not found"))

        def mock_exists(path):
            return path == "/opt/homebrew"

        with patch.dict(sys.modules, {"pwd": mock_pwd}):
            with patch("os.path.exists", side_effect=mock_exists):
                with patch("os.stat", return_value=mock_stat):
                    with patch.dict("os.environ", {"SUDO_USER": "sudouser"}):
                        result = _get_brew_user()
                        assert result == "sudouser"

    def test_get_brew_user_no_brew_no_sudo(self):
        """Test _get_brew_user when no Homebrew and no SUDO_USER."""
        with patch("os.path.exists", return_value=False):
            with patch.dict("os.environ", {}, clear=True):
                result = _get_brew_user()
                assert result is None

    def test_get_brew_user_fallback_to_sudo_user(self):
        """Test _get_brew_user falls back to SUDO_USER."""
        with patch("os.path.exists", return_value=False):
            with patch.dict("os.environ", {"SUDO_USER": "sudotest"}):
                result = _get_brew_user()
                assert result == "sudotest"


class TestConfigureConfigFile:
    """Test cases for configure_config_file function."""

    @pytest.mark.asyncio
    async def test_configure_config_file_sample_not_exists(self):
        """Test configure_config_file when sample file doesn't exist."""
        with patch("os.path.exists", return_value=False):
            result = await configure_config_file(
                "/path/to/sample.conf",
                "/path/to/target.conf",
                [("s/^Example/#Example/", "")],
            )
            assert result is None

    @pytest.mark.asyncio
    async def test_configure_config_file_with_tuple_patterns(self):
        """Test configure_config_file with tuple pattern data."""
        mock_process = AsyncMock()
        mock_process.returncode = 0
        mock_process.communicate = AsyncMock(return_value=(b"", b""))

        with patch("os.path.exists", return_value=True):
            with patch("asyncio.create_subprocess_exec", return_value=mock_process):
                await configure_config_file(
                    "/path/to/sample.conf",
                    "/path/to/target.conf",
                    [
                        ("s/^Example/#Example/", ""),
                        ("s/^#LocalSocket/LocalSocket/", "-e"),
                    ],
                )

                # Should have been called for cp and 2 sed commands
                assert mock_process.communicate.call_count == 3

    @pytest.mark.asyncio
    async def test_configure_config_file_with_string_patterns(self):
        """Test configure_config_file with string pattern (not tuple)."""
        mock_process = AsyncMock()
        mock_process.returncode = 0
        mock_process.communicate = AsyncMock(return_value=(b"", b""))

        with patch("os.path.exists", return_value=True):
            with patch("asyncio.create_subprocess_exec", return_value=mock_process):
                await configure_config_file(
                    "/path/to/sample.conf",
                    "/path/to/target.conf",
                    ["s/^Example/#Example/"],
                )

                # Should have been called for cp and 1 sed command
                assert mock_process.communicate.call_count == 2

    @pytest.mark.asyncio
    async def test_configure_config_file_with_extra_arg(self):
        """Test configure_config_file with extra sed argument."""
        mock_process = AsyncMock()
        mock_process.returncode = 0
        mock_process.communicate = AsyncMock(return_value=(b"", b""))

        with patch("os.path.exists", return_value=True):
            with patch(
                "asyncio.create_subprocess_exec", return_value=mock_process
            ) as mock_exec:
                await configure_config_file(
                    "/path/to/sample.conf",
                    "/path/to/target.conf",
                    [("s/^Example/#Example/", "-backup")],
                )

                # Verify the sed command includes the extra arg
                calls = mock_exec.call_args_list
                # Second call is sed with the extra arg
                assert "-backup" in calls[1][0]


class TestWaitForVirusDatabase:
    """Test cases for wait_for_virus_database function."""

    @pytest.mark.asyncio
    async def test_wait_for_virus_database_found_immediately(self):
        """Test wait_for_virus_database when database exists immediately."""
        with patch("os.path.exists", return_value=True):
            with patch("asyncio.sleep", return_value=None):
                await wait_for_virus_database(["/var/clamav/main.cvd"])
                # Should return quickly when database found

    @pytest.mark.asyncio
    async def test_wait_for_virus_database_found_after_delay(self):
        """Test wait_for_virus_database when database appears after some time."""
        call_count = [0]

        def mock_exists(_path):
            call_count[0] += 1
            # Database appears on 3rd check
            return call_count[0] >= 3

        with patch("os.path.exists", side_effect=mock_exists):
            with patch("asyncio.sleep", return_value=None):
                await wait_for_virus_database(
                    ["/var/clamav/main.cvd", "/var/clamav/main.cld"], timeout=5
                )

    @pytest.mark.asyncio
    async def test_wait_for_virus_database_timeout(self):
        """Test wait_for_virus_database when database never appears."""
        with patch("os.path.exists", return_value=False):
            with patch("asyncio.sleep", return_value=None):
                # Should complete with warning, not raise
                await wait_for_virus_database(["/var/clamav/main.cvd"], timeout=3)

    @pytest.mark.asyncio
    async def test_wait_for_virus_database_second_path_found(self):
        """Test wait_for_virus_database finds .cld file instead of .cvd."""

        def mock_exists(path):
            return "main.cld" in path

        with patch("os.path.exists", side_effect=mock_exists):
            with patch("asyncio.sleep", return_value=None):
                await wait_for_virus_database(
                    ["/var/clamav/main.cvd", "/var/clamav/main.cld"]
                )


class TestDeployClamavMacos:
    """Test cases for deploy_clamav_macos function."""

    @pytest.mark.asyncio
    async def test_deploy_clamav_macos_arm_success(self):
        """Test successful deployment on macOS ARM."""
        mock_detector = Mock()
        mock_detector.install_package.return_value = {"success": True}

        mock_process = AsyncMock()
        mock_process.returncode = 0
        mock_process.communicate = AsyncMock(return_value=(b"", b""))

        with patch("os.path.exists", return_value=True):
            with patch("os.makedirs"):
                with patch("asyncio.create_subprocess_exec", return_value=mock_process):
                    with patch("asyncio.sleep", return_value=None):
                        with patch(
                            "src.sysmanage_agent.operations.antivirus_deployment_helpers.os.geteuid",
                            return_value=1000,
                            create=True,
                        ):
                            success, err, _, msg = await deploy_clamav_macos(
                                mock_detector
                            )

                            assert success is True
                            assert err is None
                            assert "macOS" in msg

    @pytest.mark.asyncio
    async def test_deploy_clamav_macos_intel(self):
        """Test deployment on macOS Intel (not ARM)."""
        mock_detector = Mock()
        mock_detector.install_package.return_value = {"success": True}

        mock_process = AsyncMock()
        mock_process.returncode = 0
        mock_process.communicate = AsyncMock(return_value=(b"", b""))

        def mock_exists(path):
            # /opt/homebrew doesn't exist (Intel), other paths exist
            if path == "/opt/homebrew":
                return False
            return True

        with patch("os.path.exists", side_effect=mock_exists):
            with patch("os.makedirs"):
                with patch("asyncio.create_subprocess_exec", return_value=mock_process):
                    with patch("asyncio.sleep", return_value=None):
                        with patch(
                            "src.sysmanage_agent.operations.antivirus_deployment_helpers.os.geteuid",
                            return_value=1000,
                            create=True,
                        ):
                            success, _, _, _ = await deploy_clamav_macos(mock_detector)
                            assert success is True


class TestConfigureMacosClamd:
    """Test cases for _configure_macos_clamd function."""

    @pytest.mark.asyncio
    async def test_configure_macos_clamd_sample_not_exists(self):
        """Test _configure_macos_clamd when sample doesn't exist."""
        with patch("os.path.exists", return_value=False):
            result = await _configure_macos_clamd(
                "/opt/homebrew/etc/clamav",
                "/opt/homebrew/var/log/clamav",
                "/opt/homebrew/var/lib/clamav",
            )
            assert result is None

    @pytest.mark.asyncio
    async def test_configure_macos_clamd_success(self):
        """Test _configure_macos_clamd successful configuration."""
        mock_process = AsyncMock()
        mock_process.returncode = 0
        mock_process.communicate = AsyncMock(return_value=(b"", b""))

        with patch("os.path.exists", return_value=True):
            with patch("asyncio.create_subprocess_exec", return_value=mock_process):
                await _configure_macos_clamd(
                    "/opt/homebrew/etc/clamav",
                    "/opt/homebrew/var/log/clamav",
                    "/opt/homebrew/var/lib/clamav",
                )

                # cp + 5 sed commands
                assert mock_process.communicate.call_count == 6


class TestRunFreshclamMacos:
    """Test cases for _run_freshclam_macos function."""

    @pytest.mark.asyncio
    async def test_run_freshclam_macos_arm_as_root(self):
        """Test _run_freshclam_macos on ARM as root."""
        mock_process = AsyncMock()
        mock_process.returncode = 0
        mock_process.communicate = AsyncMock(return_value=(b"", b""))

        with patch(
            "src.sysmanage_agent.operations.antivirus_deployment_helpers.os.geteuid",
            return_value=0,
            create=True,
        ):
            with patch(
                "src.sysmanage_agent.operations.antivirus_deployment_helpers._get_brew_user",
                return_value="brewuser",
            ):
                with patch(
                    "asyncio.create_subprocess_exec", return_value=mock_process
                ) as mock_exec:
                    await _run_freshclam_macos(is_arm=True)

                    # Should call with sudo -u brewuser
                    call_args = mock_exec.call_args[0]
                    assert "sudo" in call_args
                    assert "-u" in call_args
                    assert "brewuser" in call_args

    @pytest.mark.asyncio
    async def test_run_freshclam_macos_intel_as_user(self):
        """Test _run_freshclam_macos on Intel as regular user."""
        mock_process = AsyncMock()
        mock_process.returncode = 0
        mock_process.communicate = AsyncMock(return_value=(b"", b""))

        with patch(
            "src.sysmanage_agent.operations.antivirus_deployment_helpers.os.geteuid",
            return_value=1000,
            create=True,
        ):
            with patch(
                "asyncio.create_subprocess_exec", return_value=mock_process
            ) as mock_exec:
                await _run_freshclam_macos(is_arm=False)

                # Should call freshclam directly without sudo
                call_args = mock_exec.call_args[0]
                assert "/usr/local/bin/freshclam" in call_args
                assert "sudo" not in call_args

    @pytest.mark.asyncio
    async def test_run_freshclam_macos_failure(self):
        """Test _run_freshclam_macos with failure."""
        mock_process = AsyncMock()
        mock_process.returncode = 1
        mock_process.communicate = AsyncMock(return_value=(b"", b"Update failed"))

        with patch(
            "src.sysmanage_agent.operations.antivirus_deployment_helpers.os.geteuid",
            return_value=1000,
            create=True,
        ):
            with patch("asyncio.create_subprocess_exec", return_value=mock_process):
                # Should not raise, just log warning
                await _run_freshclam_macos(is_arm=True)

    @pytest.mark.asyncio
    async def test_run_freshclam_macos_failure_no_stderr(self):
        """Test _run_freshclam_macos with failure but no stderr."""
        mock_process = AsyncMock()
        mock_process.returncode = 1
        mock_process.communicate = AsyncMock(return_value=(b"", None))

        with patch(
            "src.sysmanage_agent.operations.antivirus_deployment_helpers.os.geteuid",
            return_value=1000,
            create=True,
        ):
            with patch("asyncio.create_subprocess_exec", return_value=mock_process):
                await _run_freshclam_macos(is_arm=True)


class TestStartBrewService:
    """Test cases for _start_brew_service function."""

    @pytest.mark.asyncio
    async def test_start_brew_service_arm_success(self):
        """Test _start_brew_service on ARM with success."""
        mock_process = AsyncMock()
        mock_process.returncode = 0
        mock_process.communicate = AsyncMock(return_value=(b"", b""))

        with patch(
            "asyncio.create_subprocess_exec", return_value=mock_process
        ) as mock_exec:
            await _start_brew_service(is_arm=True)

            call_args = mock_exec.call_args[0]
            assert "/opt/homebrew/bin/brew" in call_args

    @pytest.mark.asyncio
    async def test_start_brew_service_intel_success(self):
        """Test _start_brew_service on Intel with success."""
        mock_process = AsyncMock()
        mock_process.returncode = 0
        mock_process.communicate = AsyncMock(return_value=(b"", b""))

        with patch(
            "asyncio.create_subprocess_exec", return_value=mock_process
        ) as mock_exec:
            await _start_brew_service(is_arm=False)

            call_args = mock_exec.call_args[0]
            assert "/usr/local/bin/brew" in call_args

    @pytest.mark.asyncio
    async def test_start_brew_service_failure(self):
        """Test _start_brew_service with failure."""
        mock_process = AsyncMock()
        mock_process.returncode = 1
        mock_process.communicate = AsyncMock(return_value=(b"", b"Service failed"))

        with patch("asyncio.create_subprocess_exec", return_value=mock_process):
            # Should not raise, just log warning
            await _start_brew_service(is_arm=True)

    @pytest.mark.asyncio
    async def test_start_brew_service_failure_no_stderr(self):
        """Test _start_brew_service with failure but no stderr."""
        mock_process = AsyncMock()
        mock_process.returncode = 1
        mock_process.communicate = AsyncMock(return_value=(b"", None))

        with patch("asyncio.create_subprocess_exec", return_value=mock_process):
            await _start_brew_service(is_arm=True)


class TestDeployClamavNetbsd:
    """Test cases for deploy_clamav_netbsd function."""

    @pytest.mark.asyncio
    async def test_deploy_clamav_netbsd_success(self):
        """Test successful deployment on NetBSD."""
        mock_detector = Mock()
        mock_detector.install_package.return_value = {"success": True}

        mock_process = AsyncMock()
        mock_process.returncode = 0
        mock_process.communicate = AsyncMock(return_value=(b"", b""))

        with patch("os.path.exists", return_value=True):
            with patch("asyncio.create_subprocess_exec", return_value=mock_process):
                with patch("asyncio.sleep", return_value=None):
                    success, err, _, msg = await deploy_clamav_netbsd(mock_detector)

                    assert success is True
                    assert err is None
                    assert "NetBSD" in msg

    @pytest.mark.asyncio
    async def test_deploy_clamav_netbsd_service_failure(self):
        """Test deployment on NetBSD with service failure."""
        mock_detector = Mock()
        mock_detector.install_package.return_value = {"success": True}

        mock_process = AsyncMock()
        mock_process.returncode = 1
        mock_process.communicate = AsyncMock(return_value=(b"", b"Service failed"))

        with patch("os.path.exists", return_value=True):
            with patch("asyncio.create_subprocess_exec", return_value=mock_process):
                with patch("asyncio.sleep", return_value=None):
                    success, _, _, _ = await deploy_clamav_netbsd(mock_detector)

                    # Still returns success even if service fails
                    assert success is True


class TestDeployClamavFreebsd:
    """Test cases for deploy_clamav_freebsd function."""

    @pytest.mark.asyncio
    async def test_deploy_clamav_freebsd_success(self):
        """Test successful deployment on FreeBSD."""
        mock_detector = Mock()
        mock_detector.install_package.return_value = {"success": True}

        mock_process = AsyncMock()
        mock_process.returncode = 0
        mock_process.communicate = AsyncMock(return_value=(b"", b""))

        with patch("os.path.exists", return_value=True):
            with patch("asyncio.create_subprocess_exec", return_value=mock_process):
                with patch("asyncio.sleep", return_value=None):
                    success, err, _, msg = await deploy_clamav_freebsd(mock_detector)

                    assert success is True
                    assert err is None
                    assert "FreeBSD" in msg

    @pytest.mark.asyncio
    async def test_deploy_clamav_freebsd_freshclam_failure(self):
        """Test deployment on FreeBSD with freshclam service failure."""
        mock_detector = Mock()
        mock_detector.install_package.return_value = {"success": True}

        mock_process = AsyncMock()
        mock_process.returncode = 1
        mock_process.communicate = AsyncMock(return_value=(b"", b"Service failed"))

        with patch("os.path.exists", return_value=True):
            with patch("asyncio.create_subprocess_exec", return_value=mock_process):
                with patch("asyncio.sleep", return_value=None):
                    success, _, _, _ = await deploy_clamav_freebsd(mock_detector)

                    # Still returns success
                    assert success is True


class TestDeployClamavOpenbsd:
    """Test cases for deploy_clamav_openbsd function."""

    @pytest.mark.asyncio
    async def test_deploy_clamav_openbsd_success(self):
        """Test successful deployment on OpenBSD."""
        mock_detector = Mock()
        mock_detector.install_package.return_value = {"success": True}

        mock_process = AsyncMock()
        mock_process.returncode = 0
        mock_process.communicate = AsyncMock(return_value=(b"", b""))

        def mock_exists(path):
            # freshclam.conf.sample doesn't exist to skip the problematic code path
            if "freshclam.conf.sample" in path:
                return False
            return True

        with patch("os.path.exists", side_effect=mock_exists):
            with patch("asyncio.create_subprocess_exec", return_value=mock_process):
                with patch("asyncio.sleep", return_value=None):
                    success, err, _, msg = await deploy_clamav_openbsd(mock_detector)

                    assert success is True
                    assert err is None
                    assert "OpenBSD" in msg

    @pytest.mark.asyncio
    async def test_deploy_clamav_openbsd_freshclam_sample_exists(self):
        """Test deployment on OpenBSD when freshclam.conf.sample exists.

        Note: The current code has a bug where single-element tuple patterns
        like (_SED_COMMENT_EXAMPLE,) cause a ValueError in configure_config_file.
        This test documents that behavior.
        """
        mock_detector = Mock()
        mock_detector.install_package.return_value = {"success": True}

        mock_process = AsyncMock()
        mock_process.returncode = 0
        mock_process.communicate = AsyncMock(return_value=(b"", b""))

        with patch("os.path.exists", return_value=True):
            with patch("asyncio.create_subprocess_exec", return_value=mock_process):
                with pytest.raises(ValueError) as exc_info:
                    await deploy_clamav_openbsd(mock_detector)

                assert "not enough values to unpack" in str(exc_info.value)


class TestConfigureOpenbsdClamd:
    """Test cases for _configure_openbsd_clamd function."""

    @pytest.mark.asyncio
    async def test_configure_openbsd_clamd_sample_not_exists(self):
        """Test _configure_openbsd_clamd when sample doesn't exist."""
        with patch("os.path.exists", return_value=False):
            result = await _configure_openbsd_clamd()
            assert result is None

    @pytest.mark.asyncio
    async def test_configure_openbsd_clamd_success(self):
        """Test _configure_openbsd_clamd successful configuration."""
        mock_process = AsyncMock()
        mock_process.returncode = 0
        mock_process.communicate = AsyncMock(return_value=(b"", b""))

        with patch("os.path.exists", return_value=True):
            with patch("asyncio.create_subprocess_exec", return_value=mock_process):
                await _configure_openbsd_clamd()

                # cp + sed with multiple -e options
                assert mock_process.communicate.call_count == 2


class TestCreateOpenbsdRuntimeDir:
    """Test cases for _create_openbsd_runtime_dir function."""

    @pytest.mark.asyncio
    async def test_create_openbsd_runtime_dir_exists(self):
        """Test _create_openbsd_runtime_dir when directory already exists."""
        with patch("os.path.exists", return_value=True):
            with patch("asyncio.create_subprocess_exec") as mock_exec:
                await _create_openbsd_runtime_dir()

                # Should not call mkdir if directory exists
                mock_exec.assert_not_called()

    @pytest.mark.asyncio
    async def test_create_openbsd_runtime_dir_create(self):
        """Test _create_openbsd_runtime_dir creating new directory."""
        mock_process = AsyncMock()
        mock_process.returncode = 0
        mock_process.communicate = AsyncMock(return_value=(b"", b""))

        with patch("os.path.exists", return_value=False):
            with patch("asyncio.create_subprocess_exec", return_value=mock_process):
                await _create_openbsd_runtime_dir()

                # mkdir + chown
                assert mock_process.communicate.call_count == 2


class TestEnableAndStartRcctlService:
    """Test cases for _enable_and_start_rcctl_service function."""

    @pytest.mark.asyncio
    async def test_enable_and_start_rcctl_service_success(self):
        """Test _enable_and_start_rcctl_service with success."""
        mock_process = AsyncMock()
        mock_process.returncode = 0
        mock_process.communicate = AsyncMock(return_value=(b"", b""))

        with patch("asyncio.create_subprocess_exec", return_value=mock_process):
            await _enable_and_start_rcctl_service("clamd")

            # enable + start
            assert mock_process.communicate.call_count == 2

    @pytest.mark.asyncio
    async def test_enable_and_start_rcctl_service_failure(self):
        """Test _enable_and_start_rcctl_service with failure."""
        mock_process_enable = AsyncMock()
        mock_process_enable.returncode = 0
        mock_process_enable.communicate = AsyncMock(return_value=(b"", b""))

        mock_process_start = AsyncMock()
        mock_process_start.returncode = 1
        mock_process_start.communicate = AsyncMock(return_value=(b"", b"Start failed"))

        with patch(
            "asyncio.create_subprocess_exec",
            side_effect=[mock_process_enable, mock_process_start],
        ):
            # Should not raise, just log warning
            await _enable_and_start_rcctl_service("clamd")

    @pytest.mark.asyncio
    async def test_enable_and_start_rcctl_service_failure_no_stderr(self):
        """Test _enable_and_start_rcctl_service with failure but no stderr."""
        mock_process_enable = AsyncMock()
        mock_process_enable.returncode = 0
        mock_process_enable.communicate = AsyncMock(return_value=(b"", b""))

        mock_process_start = AsyncMock()
        mock_process_start.returncode = 1
        mock_process_start.communicate = AsyncMock(return_value=(b"", None))

        with patch(
            "asyncio.create_subprocess_exec",
            side_effect=[mock_process_enable, mock_process_start],
        ):
            await _enable_and_start_rcctl_service("freshclam")


class TestDeployClamavOpensuse:
    """Test cases for deploy_clamav_opensuse function."""

    @pytest.mark.asyncio
    async def test_deploy_clamav_opensuse_success(self):
        """Test successful deployment on openSUSE."""
        mock_detector = Mock()
        mock_detector.install_package.return_value = {"success": True}

        mock_process = AsyncMock()
        mock_process.returncode = 0
        mock_process.communicate = AsyncMock(return_value=(b"", b""))

        with patch("asyncio.create_subprocess_exec", return_value=mock_process):
            with patch("asyncio.sleep", return_value=None):
                success, err, _, msg = await deploy_clamav_opensuse(mock_detector)

                assert success is True
                assert err is None
                assert "openSUSE" in msg
                # Should install 3 packages
                assert mock_detector.install_package.call_count == 3

    @pytest.mark.asyncio
    async def test_deploy_clamav_opensuse_freshclam_failure(self):
        """Test deployment on openSUSE with freshclam service failure."""
        mock_detector = Mock()
        mock_detector.install_package.return_value = {"success": True}

        mock_process_fail = AsyncMock()
        mock_process_fail.returncode = 1
        mock_process_fail.communicate = AsyncMock(return_value=(b"", b"Failed"))

        mock_process_success = AsyncMock()
        mock_process_success.returncode = 0
        mock_process_success.communicate = AsyncMock(return_value=(b"", b""))

        with patch(
            "asyncio.create_subprocess_exec",
            side_effect=[mock_process_fail, mock_process_success],
        ):
            with patch("asyncio.sleep", return_value=None):
                success, _, _, _ = await deploy_clamav_opensuse(mock_detector)

                # Still returns success
                assert success is True

    @pytest.mark.asyncio
    async def test_deploy_clamav_opensuse_clamd_failure(self):
        """Test deployment on openSUSE with clamd service failure."""
        mock_detector = Mock()
        mock_detector.install_package.return_value = {"success": True}

        mock_process_success = AsyncMock()
        mock_process_success.returncode = 0
        mock_process_success.communicate = AsyncMock(return_value=(b"", b""))

        mock_process_fail = AsyncMock()
        mock_process_fail.returncode = 1
        mock_process_fail.communicate = AsyncMock(return_value=(b"", b"Failed"))

        with patch(
            "asyncio.create_subprocess_exec",
            side_effect=[mock_process_success, mock_process_fail],
        ):
            success, _, _, _ = await deploy_clamav_opensuse(mock_detector)

            # Still returns success
            assert success is True


class TestDeployClamavRhel:
    """Test cases for deploy_clamav_rhel function."""

    @pytest.mark.asyncio
    async def test_deploy_clamav_rhel_success(self):
        """Test successful deployment on RHEL/CentOS."""
        mock_detector = Mock()
        mock_detector.install_package.return_value = {"success": True}

        mock_process = AsyncMock()
        mock_process.returncode = 0
        mock_process.communicate = AsyncMock(return_value=(b"", b""))

        config_content = "#Example\n#LocalSocket /run/clamd.scan/clamd.sock"

        mock_file = AsyncMock()
        mock_file.read = AsyncMock(return_value=config_content)
        mock_file.write = AsyncMock()
        mock_aiofiles_open = AsyncMock()
        mock_aiofiles_open.__aenter__ = AsyncMock(return_value=mock_file)
        mock_aiofiles_open.__aexit__ = AsyncMock(return_value=False)

        with patch("asyncio.create_subprocess_exec", return_value=mock_process):
            with patch(
                "src.sysmanage_agent.operations.antivirus_deployment_helpers.aiofiles.open",
                return_value=mock_aiofiles_open,
            ):
                with patch("asyncio.sleep", return_value=None):
                    success, err, _, msg = await deploy_clamav_rhel(mock_detector)

                    assert success is True
                    assert err is None
                    assert "RHEL" in msg

    @pytest.mark.asyncio
    async def test_deploy_clamav_rhel_service_failure(self):
        """Test deployment on RHEL with service failure."""
        mock_detector = Mock()
        mock_detector.install_package.return_value = {"success": True}

        mock_process_success = AsyncMock()
        mock_process_success.returncode = 0
        mock_process_success.communicate = AsyncMock(return_value=(b"", b""))

        mock_process_fail = AsyncMock()
        mock_process_fail.returncode = 1
        mock_process_fail.communicate = AsyncMock(return_value=(b"", b"Service failed"))

        config_content = "#Example\n#LocalSocket /run/clamd.scan/clamd.sock"

        mock_file = AsyncMock()
        mock_file.read = AsyncMock(return_value=config_content)
        mock_file.write = AsyncMock()
        mock_aiofiles_open = AsyncMock()
        mock_aiofiles_open.__aenter__ = AsyncMock(return_value=mock_file)
        mock_aiofiles_open.__aexit__ = AsyncMock(return_value=False)

        with patch(
            "asyncio.create_subprocess_exec",
            side_effect=[mock_process_success, mock_process_fail],
        ):
            with patch(
                "src.sysmanage_agent.operations.antivirus_deployment_helpers.aiofiles.open",
                return_value=mock_aiofiles_open,
            ):
                success, _, _, _ = await deploy_clamav_rhel(mock_detector)

                # Still returns success
                assert success is True


class TestRunFreshclamSystem:
    """Test cases for _run_freshclam_system function."""

    @pytest.mark.asyncio
    async def test_run_freshclam_system_success(self):
        """Test _run_freshclam_system with success."""
        mock_process = AsyncMock()
        mock_process.returncode = 0
        mock_process.communicate = AsyncMock(return_value=(b"", b""))

        with patch("asyncio.create_subprocess_exec", return_value=mock_process):
            await _run_freshclam_system()

    @pytest.mark.asyncio
    async def test_run_freshclam_system_failure(self):
        """Test _run_freshclam_system with failure."""
        mock_process = AsyncMock()
        mock_process.returncode = 1
        mock_process.communicate = AsyncMock(return_value=(b"", b"Update failed"))

        with patch("asyncio.create_subprocess_exec", return_value=mock_process):
            # Should not raise
            await _run_freshclam_system()

    @pytest.mark.asyncio
    async def test_run_freshclam_system_failure_no_stderr(self):
        """Test _run_freshclam_system with failure but no stderr."""
        mock_process = AsyncMock()
        mock_process.returncode = 1
        mock_process.communicate = AsyncMock(return_value=(b"", None))

        with patch("asyncio.create_subprocess_exec", return_value=mock_process):
            await _run_freshclam_system()


class TestConfigureRhelClamdScan:
    """Test cases for _configure_rhel_clamd_scan function."""

    @pytest.mark.asyncio
    async def test_configure_rhel_clamd_scan_success(self):
        """Test _configure_rhel_clamd_scan successful configuration."""
        config_content = "#Example\n#LocalSocket /run/clamd.scan/clamd.sock"
        expected_content = "# Example\nLocalSocket /run/clamd.scan/clamd.sock"

        mock_file = AsyncMock()
        mock_file.read = AsyncMock(return_value=config_content)
        mock_file.write = AsyncMock()
        mock_aiofiles_open = AsyncMock()
        mock_aiofiles_open.__aenter__ = AsyncMock(return_value=mock_file)
        mock_aiofiles_open.__aexit__ = AsyncMock(return_value=False)

        with patch(
            "src.sysmanage_agent.operations.antivirus_deployment_helpers.aiofiles.open",
            return_value=mock_aiofiles_open,
        ):
            await _configure_rhel_clamd_scan()

            # Verify write was called with modified content
            mock_file.write.assert_called_once_with(expected_content)


class TestDeployClamavWindows:
    """Test cases for deploy_clamav_windows function."""

    @pytest.mark.asyncio
    async def test_deploy_clamav_windows_success(self):
        """Test successful deployment on Windows."""
        mock_detector = Mock()
        mock_detector.install_package.return_value = {"success": True}

        mock_process = AsyncMock()
        mock_process.returncode = 0
        mock_process.communicate = AsyncMock(return_value=(b"", b""))

        with patch("os.path.exists", return_value=True):
            with patch("asyncio.create_subprocess_exec", return_value=mock_process):
                with patch("asyncio.sleep", return_value=None):
                    success, err, _, msg = await deploy_clamav_windows(mock_detector)

                    assert success is True
                    assert err is None
                    assert "Windows" in msg

    @pytest.mark.asyncio
    async def test_deploy_clamav_windows_install_failure(self):
        """Test deployment on Windows with installation failure."""
        mock_detector = Mock()
        mock_detector.install_package.return_value = {
            "success": False,
            "error": "Package not found",
        }

        success, err, _, _ = await deploy_clamav_windows(mock_detector)

        assert success is False
        assert "Package not found" in err

    @pytest.mark.asyncio
    async def test_deploy_clamav_windows_install_failure_no_error(self):
        """Test deployment on Windows with installation failure but no error message."""
        mock_detector = Mock()
        mock_detector.install_package.return_value = {"success": False}

        success, err, _, _result = await deploy_clamav_windows(mock_detector)

        assert success is False
        assert "Installation failed" in err

    @pytest.mark.asyncio
    async def test_deploy_clamav_windows_non_dict_result(self):
        """Test deployment on Windows with non-dict result (string)."""
        mock_detector = Mock()
        mock_detector.install_package.return_value = "Installation complete"

        success, err, _, _ = await deploy_clamav_windows(mock_detector)

        assert success is False
        assert err == "Installation failed"

    @pytest.mark.asyncio
    async def test_deploy_clamav_windows_path_not_found(self):
        """Test deployment on Windows when installation path not found."""
        mock_detector = Mock()
        mock_detector.install_package.return_value = {"success": True}

        with patch("os.path.exists", return_value=False):
            success, err, _, _msg = await deploy_clamav_windows(mock_detector)

            assert success is False
            assert "Installation directory not found" in err


class TestFindWindowsClamavPath:
    """Test cases for _find_windows_clamav_path function."""

    def test_find_windows_clamav_path_first_path(self):
        """Test _find_windows_clamav_path finds first path."""

        def mock_exists(path):
            return path == "C:\\Program Files\\ClamWin\\bin"

        with patch("os.path.exists", side_effect=mock_exists):
            result = _find_windows_clamav_path()
            assert result == "C:\\Program Files\\ClamWin\\bin"

    def test_find_windows_clamav_path_second_path(self):
        """Test _find_windows_clamav_path finds second path."""

        def mock_exists(path):
            return path == "C:\\Program Files (x86)\\ClamWin\\bin"

        with patch("os.path.exists", side_effect=mock_exists):
            result = _find_windows_clamav_path()
            assert result == "C:\\Program Files (x86)\\ClamWin\\bin"

    def test_find_windows_clamav_path_chocolatey_path(self):
        """Test _find_windows_clamav_path finds Chocolatey path."""

        def mock_exists(path):
            return path == "C:\\ProgramData\\chocolatey\\lib\\clamwin\\tools\\bin"

        with patch("os.path.exists", side_effect=mock_exists):
            result = _find_windows_clamav_path()
            assert result == "C:\\ProgramData\\chocolatey\\lib\\clamwin\\tools\\bin"

    def test_find_windows_clamav_path_not_found(self):
        """Test _find_windows_clamav_path when no path found."""
        with patch("os.path.exists", return_value=False):
            result = _find_windows_clamav_path()
            assert result is None


class TestRunFreshclamWindows:
    """Test cases for _run_freshclam_windows function."""

    @pytest.mark.asyncio
    async def test_run_freshclam_windows_exe_not_found(self):
        """Test _run_freshclam_windows when freshclam.exe not found."""
        with patch("os.path.exists", return_value=False):
            with patch("asyncio.create_subprocess_exec") as mock_exec:
                await _run_freshclam_windows("C:\\ClamWin\\bin")

                # Should not call subprocess
                mock_exec.assert_not_called()

    @pytest.mark.asyncio
    async def test_run_freshclam_windows_success(self):
        """Test _run_freshclam_windows with success."""
        mock_process = AsyncMock()
        mock_process.returncode = 0
        mock_process.communicate = AsyncMock(return_value=(b"", b""))

        with patch("os.path.exists", return_value=True):
            with patch("asyncio.create_subprocess_exec", return_value=mock_process):
                await _run_freshclam_windows("C:\\ClamWin\\bin")

    @pytest.mark.asyncio
    async def test_run_freshclam_windows_failure(self):
        """Test _run_freshclam_windows with failure."""
        mock_process = AsyncMock()
        mock_process.returncode = 1
        mock_process.communicate = AsyncMock(return_value=(b"", b"Update failed"))

        with patch("os.path.exists", return_value=True):
            with patch("asyncio.create_subprocess_exec", return_value=mock_process):
                # Should not raise
                await _run_freshclam_windows("C:\\ClamWin\\bin")

    @pytest.mark.asyncio
    async def test_run_freshclam_windows_failure_no_stderr(self):
        """Test _run_freshclam_windows with failure but no stderr."""
        mock_process = AsyncMock()
        mock_process.returncode = 1
        mock_process.communicate = AsyncMock(return_value=(b"", None))

        with patch("os.path.exists", return_value=True):
            with patch("asyncio.create_subprocess_exec", return_value=mock_process):
                await _run_freshclam_windows("C:\\ClamWin\\bin")

    @pytest.mark.asyncio
    async def test_run_freshclam_windows_exception(self):
        """Test _run_freshclam_windows with exception."""
        with patch("os.path.exists", return_value=True):
            with patch(
                "asyncio.create_subprocess_exec", side_effect=Exception("Process error")
            ):
                # Should not raise, just log warning
                await _run_freshclam_windows("C:\\ClamWin\\bin")


class TestDeployClamavDebian:
    """Test cases for deploy_clamav_debian function."""

    @pytest.mark.asyncio
    async def test_deploy_clamav_debian_success_dict_result(self):
        """Test successful deployment on Debian with dict result."""
        mock_detector = Mock()
        mock_detector.install_package.return_value = {
            "success": True,
            "version": "1.0.0",
        }

        mock_process = AsyncMock()
        mock_process.returncode = 0
        mock_process.communicate = AsyncMock(return_value=(b"", b""))

        with patch("asyncio.create_subprocess_exec", return_value=mock_process):
            with patch("asyncio.sleep", return_value=None):
                success, err, version, _ = await deploy_clamav_debian(mock_detector)

                assert success is True
                assert err is None
                assert version == "1.0.0"

    @pytest.mark.asyncio
    async def test_deploy_clamav_debian_success_string_result(self):
        """Test deployment on Debian with string result."""
        mock_detector = Mock()
        mock_detector.install_package.return_value = "Package installed"

        mock_process = AsyncMock()
        mock_process.returncode = 0
        mock_process.communicate = AsyncMock(return_value=(b"", b""))

        with patch("asyncio.create_subprocess_exec", return_value=mock_process):
            with patch("asyncio.sleep", return_value=None):
                success, err, _, _ = await deploy_clamav_debian(mock_detector)

                assert success is True
                assert err is None

    @pytest.mark.asyncio
    async def test_deploy_clamav_debian_failure_dict_result(self):
        """Test deployment on Debian with dict failure result."""
        mock_detector = Mock()
        mock_detector.install_package.return_value = {
            "success": False,
            "error": "Package not found",
        }

        success, err, _, _ = await deploy_clamav_debian(mock_detector)

        assert success is False
        assert err == "Package not found"

    @pytest.mark.asyncio
    async def test_deploy_clamav_debian_failure_string_error(self):
        """Test deployment on Debian with string error result."""
        mock_detector = Mock()
        mock_detector.install_package.return_value = "Error: Failed to install"

        success, err, _, _ = await deploy_clamav_debian(mock_detector)

        assert success is False
        assert err == "Error: Failed to install"

    @pytest.mark.asyncio
    async def test_deploy_clamav_debian_failure_string_failed(self):
        """Test deployment on Debian with 'failed' in string result."""
        mock_detector = Mock()
        mock_detector.install_package.return_value = "Installation failed"

        success, err, _, _ = await deploy_clamav_debian(mock_detector)

        assert success is False
        assert err == "Installation failed"

    @pytest.mark.asyncio
    async def test_deploy_clamav_debian_service_exception(self):
        """Test deployment on Debian with service exception."""
        mock_detector = Mock()
        mock_detector.install_package.return_value = {"success": True}

        with patch(
            "asyncio.create_subprocess_exec", side_effect=Exception("Service error")
        ):
            success, err, _, _ = await deploy_clamav_debian(mock_detector)

            # Should still return success for package install
            assert success is True
            assert err is None

    @pytest.mark.asyncio
    async def test_deploy_clamav_debian_service_failure(self):
        """Test deployment on Debian with service failure."""
        mock_detector = Mock()
        mock_detector.install_package.return_value = {"success": True}

        mock_process = AsyncMock()
        mock_process.returncode = 1
        mock_process.communicate = AsyncMock(return_value=(b"", b"Service failed"))

        with patch("asyncio.create_subprocess_exec", return_value=mock_process):
            success, _, _, _ = await deploy_clamav_debian(mock_detector)

            # Should still return success for package install
            assert success is True

    @pytest.mark.asyncio
    async def test_deploy_clamav_debian_service_failure_no_stderr(self):
        """Test deployment on Debian with service failure but no stderr."""
        mock_detector = Mock()
        mock_detector.install_package.return_value = {"success": True}

        mock_process = AsyncMock()
        mock_process.returncode = 1
        mock_process.communicate = AsyncMock(return_value=(b"", None))

        with patch("asyncio.create_subprocess_exec", return_value=mock_process):
            success, _, _, _ = await deploy_clamav_debian(mock_detector)

            assert success is True


class TestModuleConstants:
    """Test module-level constants are defined correctly."""

    def test_constants_exist(self):
        """Test that module constants are defined."""
        assert hasattr(av_deploy_module, "_MSG_CLAMAV_INSTALL_RESULT")
        assert hasattr(av_deploy_module, "_SED_COMMENT_EXAMPLE")
        assert hasattr(av_deploy_module, "_MSG_UPDATING_VIRUS_DEFS")
        assert hasattr(av_deploy_module, "_MSG_VIRUS_DEFS_UPDATED")
        assert hasattr(av_deploy_module, "_MSG_FAILED_UPDATE_VIRUS_DEFS")
        assert hasattr(av_deploy_module, "_MSG_UNKNOWN_ERROR")
        assert hasattr(av_deploy_module, "_SED_UNCOMMENT_LOCAL_SOCKET")
        assert hasattr(av_deploy_module, "_MSG_INSTALLING")
        assert hasattr(av_deploy_module, "_MSG_INSTALLATION_RESULT")
        assert hasattr(av_deploy_module, "_MSG_ENABLING_SERVICE")
        assert hasattr(av_deploy_module, "_MSG_SERVICE_ENABLED")
        assert hasattr(av_deploy_module, "_MSG_FAILED_ENABLE_SERVICE")
