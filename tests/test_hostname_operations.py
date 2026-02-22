"""
Unit tests for src.sysmanage_agent.operations.hostname_operations module.
Tests hostname change operations across different operating systems.
"""

# pylint: disable=protected-access,attribute-defined-outside-init

from unittest.mock import AsyncMock, Mock, patch

import pytest

from src.sysmanage_agent.core.async_utils import AsyncProcessResult
from src.sysmanage_agent.operations.hostname_operations import HostnameOperations


class HostnameWriteError(Exception):
    """Custom exception for hostname write errors in tests."""


class TestHostnameOperations:
    """Test cases for HostnameOperations class."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_agent = Mock()
        self.mock_agent.registration.get_system_info.return_value = {
            "hostname": "old-hostname"
        }
        self.mock_agent.create_message = Mock(return_value={"type": "hostname_changed"})
        self.mock_agent.send_message = AsyncMock()

        self.hostname_ops = HostnameOperations(self.mock_agent)

    def test_init(self):
        """Test HostnameOperations initialization."""
        assert self.hostname_ops.agent_instance == self.mock_agent
        assert self.hostname_ops.logger is not None

    # =========================================================================
    # Hostname Validation Tests
    # =========================================================================

    def test_validate_hostname_valid_simple(self):
        """Test hostname validation with simple valid hostname."""
        assert self.hostname_ops._validate_hostname("myhost") is True

    def test_validate_hostname_valid_with_numbers(self):
        """Test hostname validation with numbers."""
        assert self.hostname_ops._validate_hostname("myhost123") is True

    def test_validate_hostname_valid_with_hyphen(self):
        """Test hostname validation with hyphen."""
        assert self.hostname_ops._validate_hostname("my-host") is True

    def test_validate_hostname_valid_fqdn(self):
        """Test hostname validation with FQDN."""
        assert self.hostname_ops._validate_hostname("host.example.com") is True

    def test_validate_hostname_valid_subdomain(self):
        """Test hostname validation with subdomain."""
        assert self.hostname_ops._validate_hostname("server1.dc1.example.com") is True

    def test_validate_hostname_invalid_empty(self):
        """Test hostname validation with empty string."""
        assert self.hostname_ops._validate_hostname("") is False

    def test_validate_hostname_invalid_too_long(self):
        """Test hostname validation with hostname exceeding 253 characters."""
        long_hostname = "a" * 254
        assert self.hostname_ops._validate_hostname(long_hostname) is False

    def test_validate_hostname_invalid_starts_with_hyphen(self):
        """Test hostname validation with hostname starting with hyphen."""
        assert self.hostname_ops._validate_hostname("-myhost") is False

    def test_validate_hostname_invalid_ends_with_hyphen(self):
        """Test hostname validation with hostname ending with hyphen."""
        assert self.hostname_ops._validate_hostname("myhost-") is False

    def test_validate_hostname_invalid_special_chars(self):
        """Test hostname validation with special characters."""
        assert self.hostname_ops._validate_hostname("my_host") is False
        assert self.hostname_ops._validate_hostname("my@host") is False
        assert self.hostname_ops._validate_hostname("my host") is False

    def test_validate_hostname_invalid_consecutive_dots(self):
        """Test hostname validation with consecutive dots."""
        assert self.hostname_ops._validate_hostname("host..example.com") is False

    def test_validate_hostname_valid_max_label_length(self):
        """Test hostname validation with max label length (63 chars)."""
        hostname = "a" * 63
        assert self.hostname_ops._validate_hostname(hostname) is True

    def test_validate_hostname_invalid_label_too_long(self):
        """Test hostname validation with label exceeding 63 characters."""
        hostname = "a" * 64
        assert self.hostname_ops._validate_hostname(hostname) is False

    # =========================================================================
    # change_hostname Entry Point Tests
    # =========================================================================

    @pytest.mark.asyncio
    async def test_change_hostname_no_hostname_specified(self):
        """Test change_hostname with no hostname parameter."""
        parameters = {}
        result = await self.hostname_ops.change_hostname(parameters)

        assert result["success"] is False
        assert "No hostname specified" in result["error"]

    @pytest.mark.asyncio
    async def test_change_hostname_empty_hostname(self):
        """Test change_hostname with empty hostname."""
        parameters = {"new_hostname": ""}
        result = await self.hostname_ops.change_hostname(parameters)

        assert result["success"] is False
        assert "No hostname specified" in result["error"]

    @pytest.mark.asyncio
    async def test_change_hostname_whitespace_only(self):
        """Test change_hostname with whitespace-only hostname."""
        parameters = {"new_hostname": "   "}
        result = await self.hostname_ops.change_hostname(parameters)

        assert result["success"] is False
        assert "No hostname specified" in result["error"]

    @pytest.mark.asyncio
    async def test_change_hostname_invalid_format(self):
        """Test change_hostname with invalid hostname format."""
        parameters = {"new_hostname": "-invalid-hostname"}
        result = await self.hostname_ops.change_hostname(parameters)

        assert result["success"] is False
        assert "Invalid hostname format" in result["error"]

    @pytest.mark.asyncio
    async def test_change_hostname_unsupported_os(self):
        """Test change_hostname on unsupported operating system."""
        with patch("platform.system", return_value="UnknownOS"):
            parameters = {"new_hostname": "valid-hostname"}
            result = await self.hostname_ops.change_hostname(parameters)

            assert result["success"] is False
            assert "Unsupported operating system" in result["error"]
            assert "unknownos" in result["error"]

    @pytest.mark.asyncio
    async def test_change_hostname_exception(self):
        """Test change_hostname handles unexpected exceptions."""
        with patch("platform.system", side_effect=Exception("System error")):
            parameters = {"new_hostname": "valid-hostname"}
            result = await self.hostname_ops.change_hostname(parameters)

            assert result["success"] is False
            assert "System error" in result["error"]

    # =========================================================================
    # Linux Hostname Tests
    # =========================================================================

    @pytest.mark.asyncio
    async def test_change_linux_hostname_success_hostnamectl(self):
        """Test successful Linux hostname change with hostnamectl."""
        mock_result = AsyncProcessResult(returncode=0, stdout="", stderr="")

        with patch("platform.system", return_value="Linux"):
            with patch(
                "src.sysmanage_agent.operations.hostname_operations.run_command_async",
                new_callable=AsyncMock,
                return_value=mock_result,
            ):
                with patch.object(
                    self.hostname_ops, "_send_hostname_update", new_callable=AsyncMock
                ):
                    parameters = {"new_hostname": "new-linux-host"}
                    result = await self.hostname_ops.change_hostname(parameters)

                    assert result["success"] is True
                    assert "new-linux-host" in result["result"]

    @pytest.mark.asyncio
    async def test_change_linux_hostname_fallback_to_manual(self):
        """Test Linux hostname change falls back to manual method when hostnamectl fails."""
        hostnamectl_fail = AsyncProcessResult(
            returncode=1, stdout="", stderr="hostnamectl: command not found"
        )
        tee_success = AsyncProcessResult(returncode=0, stdout="", stderr="")
        hostname_success = AsyncProcessResult(returncode=0, stdout="", stderr="")

        call_count = 0

        async def mock_run_command(*_args, **_kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:  # hostnamectl
                return hostnamectl_fail
            if call_count == 2:  # tee
                return tee_success
            # hostname
            return hostname_success

        with patch("platform.system", return_value="Linux"):
            with patch(
                "src.sysmanage_agent.operations.hostname_operations.run_command_async",
                side_effect=mock_run_command,
            ):
                with patch.object(
                    self.hostname_ops, "_send_hostname_update", new_callable=AsyncMock
                ):
                    parameters = {"new_hostname": "new-linux-host"}
                    result = await self.hostname_ops.change_hostname(parameters)

                    assert result["success"] is True
                    assert "new-linux-host" in result["result"]

    @pytest.mark.asyncio
    async def test_change_linux_hostname_tee_failure(self):
        """Test Linux hostname change fails when tee command fails."""
        hostnamectl_fail = AsyncProcessResult(
            returncode=1, stdout="", stderr="hostnamectl failed"
        )
        tee_fail = AsyncProcessResult(
            returncode=1, stdout="", stderr="Permission denied"
        )

        call_count = 0

        async def mock_run_command(*_args, **_kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return hostnamectl_fail
            return tee_fail

        with patch("platform.system", return_value="Linux"):
            with patch(
                "src.sysmanage_agent.operations.hostname_operations.run_command_async",
                side_effect=mock_run_command,
            ):
                parameters = {"new_hostname": "new-linux-host"}
                result = await self.hostname_ops.change_hostname(parameters)

                assert result["success"] is False
                assert "Failed to update /etc/hostname" in result["error"]

    @pytest.mark.asyncio
    async def test_change_linux_hostname_tee_exception(self):
        """Test Linux hostname change handles tee exception."""
        hostnamectl_fail = AsyncProcessResult(
            returncode=1, stdout="", stderr="hostnamectl failed"
        )

        call_count = 0

        async def mock_run_command(*_args, **_kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return hostnamectl_fail
            raise HostnameWriteError("Write error")

        with patch("platform.system", return_value="Linux"):
            with patch(
                "src.sysmanage_agent.operations.hostname_operations.run_command_async",
                side_effect=mock_run_command,
            ):
                parameters = {"new_hostname": "new-linux-host"}
                result = await self.hostname_ops.change_hostname(parameters)

                assert result["success"] is False
                assert "Failed to update /etc/hostname" in result["error"]

    @pytest.mark.asyncio
    async def test_change_linux_hostname_hostname_command_failure(self):
        """Test Linux hostname change fails when hostname command fails."""
        hostnamectl_fail = AsyncProcessResult(
            returncode=1, stdout="", stderr="hostnamectl failed"
        )
        tee_success = AsyncProcessResult(returncode=0, stdout="", stderr="")
        hostname_fail = AsyncProcessResult(
            returncode=1, stdout="", stderr="hostname: command failed"
        )

        call_count = 0

        async def mock_run_command(*_args, **_kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return hostnamectl_fail
            if call_count == 2:
                return tee_success
            return hostname_fail

        with patch("platform.system", return_value="Linux"):
            with patch(
                "src.sysmanage_agent.operations.hostname_operations.run_command_async",
                side_effect=mock_run_command,
            ):
                parameters = {"new_hostname": "new-linux-host"}
                result = await self.hostname_ops.change_hostname(parameters)

                assert result["success"] is False
                assert "Failed to set runtime hostname" in result["error"]

    # =========================================================================
    # macOS Hostname Tests
    # =========================================================================

    @pytest.mark.asyncio
    async def test_change_macos_hostname_success(self):
        """Test successful macOS hostname change."""
        mock_result = AsyncProcessResult(returncode=0, stdout="", stderr="")

        with patch("platform.system", return_value="Darwin"):
            with patch(
                "src.sysmanage_agent.operations.hostname_operations.run_command_async",
                new_callable=AsyncMock,
                return_value=mock_result,
            ):
                with patch.object(
                    self.hostname_ops, "_send_hostname_update", new_callable=AsyncMock
                ):
                    parameters = {"new_hostname": "new-mac-host"}
                    result = await self.hostname_ops.change_hostname(parameters)

                    assert result["success"] is True
                    assert "new-mac-host" in result["result"]

    @pytest.mark.asyncio
    async def test_change_macos_hostname_computer_name_failure(self):
        """Test macOS hostname change fails when ComputerName cannot be set."""
        mock_fail = AsyncProcessResult(
            returncode=1, stdout="", stderr="Failed to set ComputerName"
        )

        with patch("platform.system", return_value="Darwin"):
            with patch(
                "src.sysmanage_agent.operations.hostname_operations.run_command_async",
                new_callable=AsyncMock,
                return_value=mock_fail,
            ):
                parameters = {"new_hostname": "new-mac-host"}
                result = await self.hostname_ops.change_hostname(parameters)

                assert result["success"] is False
                assert "Failed to set ComputerName" in result["error"]

    @pytest.mark.asyncio
    async def test_change_macos_hostname_local_hostname_failure(self):
        """Test macOS hostname change fails when LocalHostName cannot be set."""
        success = AsyncProcessResult(returncode=0, stdout="", stderr="")
        fail = AsyncProcessResult(
            returncode=1, stdout="", stderr="Failed to set LocalHostName"
        )

        call_count = 0

        async def mock_run_command(*_args, **_kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:  # ComputerName succeeds
                return success
            # LocalHostName fails
            return fail

        with patch("platform.system", return_value="Darwin"):
            with patch(
                "src.sysmanage_agent.operations.hostname_operations.run_command_async",
                side_effect=mock_run_command,
            ):
                parameters = {"new_hostname": "new-mac-host"}
                result = await self.hostname_ops.change_hostname(parameters)

                assert result["success"] is False
                assert "Failed to set LocalHostName" in result["error"]

    @pytest.mark.asyncio
    async def test_change_macos_hostname_hostname_failure(self):
        """Test macOS hostname change fails when HostName cannot be set."""
        success = AsyncProcessResult(returncode=0, stdout="", stderr="")
        fail = AsyncProcessResult(
            returncode=1, stdout="", stderr="Failed to set HostName"
        )

        call_count = 0

        async def mock_run_command(*_args, **_kwargs):
            nonlocal call_count
            call_count += 1
            if call_count <= 2:  # ComputerName and LocalHostName succeed
                return success
            # HostName fails
            return fail

        with patch("platform.system", return_value="Darwin"):
            with patch(
                "src.sysmanage_agent.operations.hostname_operations.run_command_async",
                side_effect=mock_run_command,
            ):
                parameters = {"new_hostname": "new-mac-host"}
                result = await self.hostname_ops.change_hostname(parameters)

                assert result["success"] is False
                assert "Failed to set HostName" in result["error"]

    @pytest.mark.asyncio
    async def test_change_macos_hostname_fqdn_extracts_short_name(self):
        """Test macOS hostname change correctly extracts short hostname from FQDN."""
        mock_result = AsyncProcessResult(returncode=0, stdout="", stderr="")
        called_commands = []

        async def capture_commands(cmd, **_kwargs):
            called_commands.append(cmd)
            return mock_result

        with patch("platform.system", return_value="Darwin"):
            with patch(
                "src.sysmanage_agent.operations.hostname_operations.run_command_async",
                side_effect=capture_commands,
            ):
                with patch.object(
                    self.hostname_ops, "_send_hostname_update", new_callable=AsyncMock
                ):
                    parameters = {"new_hostname": "myhost.example.com"}
                    result = await self.hostname_ops.change_hostname(parameters)

                    assert result["success"] is True
                    # LocalHostName should use short hostname (no dots)
                    assert any(
                        "myhost" in str(cmd) and "LocalHostName" in str(cmd)
                        for cmd in called_commands
                    )

    # =========================================================================
    # Windows Hostname Tests
    # =========================================================================

    @pytest.mark.asyncio
    async def test_change_windows_hostname_success(self):
        """Test successful Windows hostname change."""
        mock_result = AsyncProcessResult(returncode=0, stdout="", stderr="")

        with patch("platform.system", return_value="Windows"):
            with patch(
                "src.sysmanage_agent.operations.hostname_operations.run_command_async",
                new_callable=AsyncMock,
                return_value=mock_result,
            ):
                with patch.object(
                    self.hostname_ops, "_send_hostname_update", new_callable=AsyncMock
                ):
                    parameters = {"new_hostname": "new-windows-host"}
                    result = await self.hostname_ops.change_hostname(parameters)

                    assert result["success"] is True
                    assert "new-windows-host" in result["result"]
                    assert "reboot is required" in result["result"]

    @pytest.mark.asyncio
    async def test_change_windows_hostname_failure(self):
        """Test Windows hostname change failure."""
        mock_fail = AsyncProcessResult(
            returncode=1, stdout="", stderr="Rename-Computer failed"
        )

        with patch("platform.system", return_value="Windows"):
            with patch(
                "src.sysmanage_agent.operations.hostname_operations.run_command_async",
                new_callable=AsyncMock,
                return_value=mock_fail,
            ):
                parameters = {"new_hostname": "new-windows-host"}
                result = await self.hostname_ops.change_hostname(parameters)

                assert result["success"] is False
                assert "Failed to rename computer" in result["error"]

    # =========================================================================
    # FreeBSD Hostname Tests
    # =========================================================================

    @pytest.mark.asyncio
    async def test_change_freebsd_hostname_success_with_sysrc(self):
        """Test successful FreeBSD hostname change using sysrc."""
        mock_result = AsyncProcessResult(returncode=0, stdout="", stderr="")

        with patch("platform.system", return_value="FreeBSD"):
            with patch(
                "src.sysmanage_agent.operations.hostname_operations.run_command_async",
                new_callable=AsyncMock,
                return_value=mock_result,
            ):
                with patch.object(
                    self.hostname_ops, "_send_hostname_update", new_callable=AsyncMock
                ):
                    parameters = {"new_hostname": "new-freebsd-host"}
                    result = await self.hostname_ops.change_hostname(parameters)

                    assert result["success"] is True
                    assert "new-freebsd-host" in result["result"]

    @pytest.mark.asyncio
    async def test_change_freebsd_hostname_runtime_failure(self):
        """Test FreeBSD hostname change fails when runtime hostname cannot be set."""
        mock_fail = AsyncProcessResult(
            returncode=1, stdout="", stderr="hostname: permission denied"
        )

        with patch("platform.system", return_value="FreeBSD"):
            with patch(
                "src.sysmanage_agent.operations.hostname_operations.run_command_async",
                new_callable=AsyncMock,
                return_value=mock_fail,
            ):
                parameters = {"new_hostname": "new-freebsd-host"}
                result = await self.hostname_ops.change_hostname(parameters)

                assert result["success"] is False
                assert "Failed to set runtime hostname" in result["error"]

    @pytest.mark.asyncio
    async def test_change_freebsd_hostname_fallback_to_sed(self):
        """Test FreeBSD hostname change falls back to sed when sysrc fails."""
        hostname_success = AsyncProcessResult(returncode=0, stdout="", stderr="")
        sysrc_fail = AsyncProcessResult(
            returncode=1, stdout="", stderr="sysrc: command not found"
        )
        sed_success = AsyncProcessResult(returncode=0, stdout="", stderr="")

        call_count = 0

        async def mock_run_command(*_args, **_kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:  # hostname command
                return hostname_success
            if call_count == 2:  # sysrc fails
                return sysrc_fail
            # sed succeeds
            return sed_success

        with patch("platform.system", return_value="FreeBSD"):
            with patch(
                "src.sysmanage_agent.operations.hostname_operations.run_command_async",
                side_effect=mock_run_command,
            ):
                with patch.object(
                    self.hostname_ops, "_send_hostname_update", new_callable=AsyncMock
                ):
                    parameters = {"new_hostname": "new-freebsd-host"}
                    result = await self.hostname_ops.change_hostname(parameters)

                    assert result["success"] is True
                    assert "new-freebsd-host" in result["result"]

    @pytest.mark.asyncio
    async def test_change_freebsd_hostname_sed_failure(self):
        """Test FreeBSD hostname change fails when both sysrc and sed fail."""
        hostname_success = AsyncProcessResult(returncode=0, stdout="", stderr="")
        sysrc_fail = AsyncProcessResult(
            returncode=1, stdout="", stderr="sysrc: command not found"
        )
        sed_fail = AsyncProcessResult(
            returncode=1, stdout="", stderr="sed: failed to update"
        )

        call_count = 0

        async def mock_run_command(*_args, **_kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return hostname_success
            if call_count == 2:
                return sysrc_fail
            return sed_fail

        with patch("platform.system", return_value="FreeBSD"):
            with patch(
                "src.sysmanage_agent.operations.hostname_operations.run_command_async",
                side_effect=mock_run_command,
            ):
                parameters = {"new_hostname": "new-freebsd-host"}
                result = await self.hostname_ops.change_hostname(parameters)

                assert result["success"] is False
                assert "Failed to update /etc/rc.conf" in result["error"]

    # =========================================================================
    # OpenBSD/NetBSD Hostname Tests
    # =========================================================================

    @pytest.mark.asyncio
    async def test_change_openbsd_hostname_success(self):
        """Test successful OpenBSD hostname change."""
        mock_result = AsyncProcessResult(returncode=0, stdout="", stderr="")

        with patch("platform.system", return_value="OpenBSD"):
            with patch(
                "src.sysmanage_agent.operations.hostname_operations.run_command_async",
                new_callable=AsyncMock,
                return_value=mock_result,
            ):
                with patch.object(
                    self.hostname_ops, "_send_hostname_update", new_callable=AsyncMock
                ):
                    parameters = {"new_hostname": "new-openbsd-host"}
                    result = await self.hostname_ops.change_hostname(parameters)

                    assert result["success"] is True
                    assert "new-openbsd-host" in result["result"]

    @pytest.mark.asyncio
    async def test_change_netbsd_hostname_success(self):
        """Test successful NetBSD hostname change."""
        mock_result = AsyncProcessResult(returncode=0, stdout="", stderr="")

        with patch("platform.system", return_value="NetBSD"):
            with patch(
                "src.sysmanage_agent.operations.hostname_operations.run_command_async",
                new_callable=AsyncMock,
                return_value=mock_result,
            ):
                with patch.object(
                    self.hostname_ops, "_send_hostname_update", new_callable=AsyncMock
                ):
                    parameters = {"new_hostname": "new-netbsd-host"}
                    result = await self.hostname_ops.change_hostname(parameters)

                    assert result["success"] is True
                    assert "new-netbsd-host" in result["result"]

    @pytest.mark.asyncio
    async def test_change_bsd_hostname_runtime_failure(self):
        """Test BSD hostname change fails when runtime hostname cannot be set."""
        mock_fail = AsyncProcessResult(
            returncode=1, stdout="", stderr="hostname: permission denied"
        )

        with patch("platform.system", return_value="OpenBSD"):
            with patch(
                "src.sysmanage_agent.operations.hostname_operations.run_command_async",
                new_callable=AsyncMock,
                return_value=mock_fail,
            ):
                parameters = {"new_hostname": "new-bsd-host"}
                result = await self.hostname_ops.change_hostname(parameters)

                assert result["success"] is False
                assert "Failed to set runtime hostname" in result["error"]

    @pytest.mark.asyncio
    async def test_change_bsd_hostname_myname_failure(self):
        """Test BSD hostname change fails when /etc/myname cannot be updated."""
        hostname_success = AsyncProcessResult(returncode=0, stdout="", stderr="")
        tee_fail = AsyncProcessResult(
            returncode=1, stdout="", stderr="Permission denied"
        )

        call_count = 0

        async def mock_run_command(*_args, **_kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return hostname_success
            return tee_fail

        with patch("platform.system", return_value="OpenBSD"):
            with patch(
                "src.sysmanage_agent.operations.hostname_operations.run_command_async",
                side_effect=mock_run_command,
            ):
                parameters = {"new_hostname": "new-bsd-host"}
                result = await self.hostname_ops.change_hostname(parameters)

                assert result["success"] is False
                assert "Failed to update /etc/myname" in result["error"]

    @pytest.mark.asyncio
    async def test_change_bsd_hostname_myname_exception(self):
        """Test BSD hostname change handles /etc/myname write exception."""
        hostname_success = AsyncProcessResult(returncode=0, stdout="", stderr="")

        call_count = 0

        async def mock_run_command(*_args, **_kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return hostname_success
            raise HostnameWriteError("Write error")

        with patch("platform.system", return_value="OpenBSD"):
            with patch(
                "src.sysmanage_agent.operations.hostname_operations.run_command_async",
                side_effect=mock_run_command,
            ):
                parameters = {"new_hostname": "new-bsd-host"}
                result = await self.hostname_ops.change_hostname(parameters)

                assert result["success"] is False
                assert "Failed to update /etc/myname" in result["error"]

    # =========================================================================
    # Send Hostname Update Tests
    # =========================================================================

    @pytest.mark.asyncio
    async def test_send_hostname_update_success(self):
        """Test successful hostname update notification to server."""
        self.mock_agent.registration.get_system_info.return_value = {
            "hostname": "old-host"
        }
        self.mock_agent.create_message.return_value = {"type": "hostname_changed"}
        self.mock_agent.send_message = AsyncMock()

        await self.hostname_ops._send_hostname_update("new-host")

        self.mock_agent.registration.get_system_info.assert_called_once()
        self.mock_agent.create_message.assert_called_once_with(
            "hostname_changed",
            {
                "hostname": "old-host",
                "new_hostname": "new-host",
                "success": True,
            },
        )
        self.mock_agent.send_message.assert_called_once()

    @pytest.mark.asyncio
    async def test_send_hostname_update_uses_socket_fallback(self):
        """Test hostname update uses socket.gethostname() when system_info is None."""
        self.mock_agent.registration.get_system_info.return_value = {}
        self.mock_agent.create_message.return_value = {"type": "hostname_changed"}
        self.mock_agent.send_message = AsyncMock()

        with patch("socket.gethostname", return_value="socket-host"):
            await self.hostname_ops._send_hostname_update("new-host")

            self.mock_agent.create_message.assert_called_once()
            call_args = self.mock_agent.create_message.call_args
            assert call_args[0][1]["hostname"] == "socket-host"

    @pytest.mark.asyncio
    async def test_send_hostname_update_exception(self):
        """Test hostname update handles exceptions gracefully."""
        self.mock_agent.registration.get_system_info.side_effect = Exception(
            "Network error"
        )

        # Should not raise exception
        await self.hostname_ops._send_hostname_update("new-host")

    @pytest.mark.asyncio
    async def test_send_hostname_update_send_message_exception(self):
        """Test hostname update handles send_message exception gracefully."""
        self.mock_agent.registration.get_system_info.return_value = {
            "hostname": "old-host"
        }
        self.mock_agent.create_message.return_value = {"type": "hostname_changed"}
        self.mock_agent.send_message = AsyncMock(side_effect=Exception("Send failed"))

        # Should not raise exception
        await self.hostname_ops._send_hostname_update("new-host")

    # =========================================================================
    # Integration Tests (Full Flow)
    # =========================================================================

    @pytest.mark.asyncio
    async def test_change_hostname_full_flow_success_sends_update(self):
        """Test that successful hostname change sends update to server."""
        mock_result = AsyncProcessResult(returncode=0, stdout="", stderr="")

        with patch("platform.system", return_value="Linux"):
            with patch(
                "src.sysmanage_agent.operations.hostname_operations.run_command_async",
                new_callable=AsyncMock,
                return_value=mock_result,
            ):
                parameters = {"new_hostname": "new-host"}
                result = await self.hostname_ops.change_hostname(parameters)

                assert result["success"] is True
                self.mock_agent.send_message.assert_called_once()

    @pytest.mark.asyncio
    async def test_change_hostname_failure_does_not_send_update(self):
        """Test that failed hostname change does not send update to server."""
        mock_fail = AsyncProcessResult(
            returncode=1, stdout="", stderr="Permission denied"
        )

        with patch("platform.system", return_value="Linux"):
            with patch(
                "src.sysmanage_agent.operations.hostname_operations.run_command_async",
                new_callable=AsyncMock,
                return_value=mock_fail,
            ):
                parameters = {"new_hostname": "new-host"}
                result = await self.hostname_ops.change_hostname(parameters)

                assert result["success"] is False
                self.mock_agent.send_message.assert_not_called()

    @pytest.mark.asyncio
    async def test_change_hostname_strips_whitespace(self):
        """Test that hostname is properly stripped of whitespace."""
        mock_result = AsyncProcessResult(returncode=0, stdout="", stderr="")

        with patch("platform.system", return_value="Linux"):
            with patch(
                "src.sysmanage_agent.operations.hostname_operations.run_command_async",
                new_callable=AsyncMock,
                return_value=mock_result,
            ) as mock_run:
                with patch.object(
                    self.hostname_ops, "_send_hostname_update", new_callable=AsyncMock
                ):
                    parameters = {"new_hostname": "  trimmed-host  "}
                    result = await self.hostname_ops.change_hostname(parameters)

                    assert result["success"] is True
                    # Verify the command was called with trimmed hostname
                    call_args = mock_run.call_args
                    assert "trimmed-host" in str(call_args)
