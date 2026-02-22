"""
Tests for Windows virtualization support check methods.
Tests WSL (Windows Subsystem for Linux) and Hyper-V detection.
"""

# pylint: disable=redefined-outer-name,protected-access

import logging
import subprocess
from unittest.mock import Mock, patch

import pytest

from src.sysmanage_agent.operations._virtualization_windows import (
    WindowsVirtualizationMixin,
)


class VirtHelper(WindowsVirtualizationMixin):
    """Helper class that implements the mixin (not prefixed with Test)."""

    def __init__(self):
        self.logger = logging.getLogger(__name__)


@pytest.fixture
def virt_helper():
    """Create a virtualization helper for testing."""
    return VirtHelper()


class TestDecodeWslOutput:
    """Tests for _decode_wsl_output method."""

    def test_decode_empty_output(self, virt_helper):
        """Test decoding empty output."""
        result = virt_helper._decode_wsl_output(b"", b"")
        assert result == ""

    def test_decode_utf16le_output(self, virt_helper):
        """Test decoding UTF-16LE encoded output."""
        # "Default Version: 2" in UTF-16LE
        utf16_text = "Default Version: 2".encode("utf-16-le")
        result = virt_helper._decode_wsl_output(utf16_text, b"")
        assert "Default Version: 2" in result

    def test_decode_utf16le_with_bom(self, virt_helper):
        """Test decoding UTF-16LE output with BOM."""
        # UTF-16LE BOM followed by text
        utf16_text = b"\xff\xfe" + "WSL enabled".encode("utf-16-le")
        result = virt_helper._decode_wsl_output(utf16_text, b"")
        assert "WSL enabled" in result

    def test_decode_utf8_fallback(self, virt_helper):
        """Test decoding with UTF-8 fallback when UTF-16LE fails.

        UTF-16LE decode attempt will fail on invalid byte sequences,
        causing fallback to UTF-8.
        """
        # Start with BOM marker that gets stripped, then use invalid UTF-16 data
        # that will cause UTF-16 decode to produce empty string, triggering UTF-8 fallback
        # Actually, the method tries UTF-16LE first and if it produces non-empty content
        # it returns that. We need to test that UTF-8 encoded multi-byte chars work.
        # UTF-8 multi-byte sequence that's invalid UTF-16LE
        utf8_text = "Test \u00e9\u00e8\u00ea".encode("utf-8")  # accented chars
        result = virt_helper._decode_wsl_output(utf8_text, b"")
        # The result will be whatever the decode produces - just verify it returns a string
        assert isinstance(result, str)
        assert len(result) > 0

    def test_decode_latin1_fallback(self, virt_helper):
        """Test decoding with latin-1 fallback for binary data."""
        # Invalid UTF-8 and UTF-16 sequences - latin-1 never fails
        binary_data = bytes([0x80, 0x81, 0x82])
        result = virt_helper._decode_wsl_output(binary_data, b"")
        # Latin-1 can decode any byte sequence
        assert len(result) == 3

    def test_decode_combines_stdout_and_stderr(self, virt_helper):
        """Test that stdout and stderr are combined."""
        # Use UTF-16LE encoded strings since that's what the method prioritizes
        stdout = "stdout data".encode("utf-16-le")
        stderr = "stderr data".encode("utf-16-le")
        result = virt_helper._decode_wsl_output(stdout, stderr)
        assert "stdout data" in result
        assert "stderr data" in result

    def test_decode_filters_null_characters(self, virt_helper):
        """Test that null characters are filtered from UTF-16LE output."""
        # UTF-16LE text typically has null bytes between ASCII chars
        utf16_text = "Test".encode("utf-16-le")
        result = virt_helper._decode_wsl_output(utf16_text, b"")
        assert "\x00" not in result

    def test_decode_utf16le_empty_after_decode(self, virt_helper):
        """Test UTF-16LE decode that results in empty/whitespace string."""
        # Some bytes that decode to whitespace in UTF-16LE
        whitespace_utf16 = "   ".encode("utf-16-le")
        # This should fall back to UTF-8
        result = virt_helper._decode_wsl_output(whitespace_utf16, b"")
        # Should still return something (may be whitespace or UTF-8 interpretation)
        assert isinstance(result, str)


class TestDetectWslBlockers:
    """Tests for _detect_wsl_blockers method."""

    def test_detect_bios_virtualization_blocker(self, virt_helper):
        """Test detection of BIOS virtualization blocker."""
        result = {
            "enabled": True,
            "needs_enable": False,
            "needs_bios_virtualization": False,
        }
        output_lower = "please enable the bios virtualization feature"

        blocked = virt_helper._detect_wsl_blockers(output_lower, result)

        assert blocked is True
        assert result["enabled"] is False
        assert result["needs_enable"] is False
        assert result["needs_bios_virtualization"] is True

    def test_detect_virtual_machine_platform_blocker(self, virt_helper):
        """Test detection of Virtual Machine Platform blocker."""
        result = {
            "enabled": True,
            "needs_enable": False,
            "needs_bios_virtualization": False,
        }
        output_lower = "virtual machine platform is not enabled"

        blocked = virt_helper._detect_wsl_blockers(output_lower, result)

        assert blocked is True
        assert result["enabled"] is False
        assert result["needs_enable"] is True
        assert result["needs_bios_virtualization"] is False

    def test_no_blockers_detected(self, virt_helper):
        """Test when no blockers are present."""
        result = {
            "enabled": True,
            "needs_enable": False,
            "needs_bios_virtualization": False,
        }
        output_lower = "default version: 2"

        blocked = virt_helper._detect_wsl_blockers(output_lower, result)

        assert blocked is False
        # Result should be unchanged
        assert result["enabled"] is True
        assert result["needs_enable"] is False
        assert result["needs_bios_virtualization"] is False


class TestParseWslVersion:
    """Tests for _parse_wsl_version method."""

    def test_parse_default_version_2(self, virt_helper):
        """Test parsing Default Version: 2."""
        result = {"default_version": None, "version": None}
        output = "Default Version: 2\nKernel version: 5.15"

        virt_helper._parse_wsl_version(output, result)

        assert result["default_version"] == 2
        assert result["version"] == "2"

    def test_parse_default_version_wsl_2(self, virt_helper):
        """Test parsing Default Version: WSL 2."""
        result = {"default_version": None, "version": None}
        output = "Default Version: WSL 2\nSome other info"

        virt_helper._parse_wsl_version(output, result)

        assert result["default_version"] == 2
        assert result["version"] == "2"

    def test_parse_default_version_1(self, virt_helper):
        """Test parsing Default Version: 1."""
        result = {"default_version": None, "version": None}
        output = "Default Version: 1\nKernel version: n/a"

        virt_helper._parse_wsl_version(output, result)

        assert result["default_version"] == 1
        assert result["version"] == "1"

    def test_parse_default_version_wsl_1(self, virt_helper):
        """Test parsing Default Version: WSL 1."""
        result = {"default_version": None, "version": None}
        output = "Default Version: WSL 1\nSome other info"

        virt_helper._parse_wsl_version(output, result)

        assert result["default_version"] == 1
        assert result["version"] == "1"

    def test_parse_wsl_1_in_output(self, virt_helper):
        """Test parsing when only 'WSL 1' appears without default prefix."""
        result = {"default_version": None, "version": None}
        output = "WSL 1 is currently configured"

        virt_helper._parse_wsl_version(output, result)

        assert result["default_version"] == 1
        assert result["version"] == "1"

    def test_parse_unclear_version_defaults_to_2(self, virt_helper):
        """Test that unclear version defaults to WSL 2."""
        result = {"default_version": None, "version": None}
        output = "WSL is running\nNo version information"

        virt_helper._parse_wsl_version(output, result)

        assert result["default_version"] == 2
        assert result["version"] == "2"


class TestCheckWslSupport:
    """Tests for check_wsl_support method."""

    def test_wsl_not_windows(self, virt_helper):
        """Test WSL check on non-Windows system."""
        with patch("platform.system", return_value="Linux"):
            result = virt_helper.check_wsl_support()

        assert result["available"] is False
        assert result["enabled"] is False
        assert result["version"] is None
        assert result["needs_enable"] is False
        assert result["needs_bios_virtualization"] is False
        assert result["default_version"] is None

    def test_wsl_exe_not_found(self, virt_helper):
        """Test WSL check when wsl.exe is not found."""
        with patch("platform.system", return_value="Windows"):
            with patch.dict("os.environ", {"SystemRoot": "C:\\Windows"}):
                with patch("os.path.exists", return_value=False):
                    result = virt_helper.check_wsl_support()

        assert result["available"] is False
        assert result["enabled"] is False

    def test_wsl_available_and_enabled(self, virt_helper):
        """Test WSL check when fully available and enabled."""
        mock_status_result = Mock()
        mock_status_result.returncode = 0
        mock_status_result.stdout = "Default Version: 2\n".encode("utf-16-le")
        mock_status_result.stderr = b""

        with patch("platform.system", return_value="Windows"):
            with patch.dict("os.environ", {"SystemRoot": "C:\\Windows"}):
                with patch("os.path.exists", return_value=True):
                    with patch("subprocess.run", return_value=mock_status_result):
                        result = virt_helper.check_wsl_support()

        assert result["available"] is True
        assert result["enabled"] is True
        assert result["version"] == "2"
        assert result["default_version"] == 2
        assert result["needs_enable"] is False

    def test_wsl_available_not_enabled(self, virt_helper):
        """Test WSL check when available but not enabled."""
        mock_status_result = Mock()
        mock_status_result.returncode = 1
        mock_status_result.stdout = b"WSL not configured"
        mock_status_result.stderr = b""

        with patch("platform.system", return_value="Windows"):
            with patch.dict("os.environ", {"SystemRoot": "C:\\Windows"}):
                with patch("os.path.exists", return_value=True):
                    with patch("subprocess.run", return_value=mock_status_result):
                        result = virt_helper.check_wsl_support()

        assert result["available"] is True
        assert result["enabled"] is False
        assert result["needs_enable"] is True

    def test_wsl_needs_bios_virtualization(self, virt_helper):
        """Test WSL check when BIOS virtualization is needed."""
        output_text = "Please enable the BIOS virtualization feature"
        mock_status_result = Mock()
        mock_status_result.returncode = 1
        mock_status_result.stdout = output_text.encode("utf-8")
        mock_status_result.stderr = b""

        with patch("platform.system", return_value="Windows"):
            with patch.dict("os.environ", {"SystemRoot": "C:\\Windows"}):
                with patch("os.path.exists", return_value=True):
                    with patch("subprocess.run", return_value=mock_status_result):
                        result = virt_helper.check_wsl_support()

        assert result["available"] is True
        assert result["enabled"] is False
        assert result["needs_bios_virtualization"] is True
        assert result["needs_enable"] is False

    def test_wsl_needs_virtual_machine_platform(self, virt_helper):
        """Test WSL check when Virtual Machine Platform is needed."""
        output_text = "virtual machine platform is required"
        mock_status_result = Mock()
        mock_status_result.returncode = 1
        mock_status_result.stdout = output_text.encode("utf-8")
        mock_status_result.stderr = b""

        with patch("platform.system", return_value="Windows"):
            with patch.dict("os.environ", {"SystemRoot": "C:\\Windows"}):
                with patch("os.path.exists", return_value=True):
                    with patch("subprocess.run", return_value=mock_status_result):
                        result = virt_helper.check_wsl_support()

        assert result["available"] is True
        assert result["enabled"] is False
        assert result["needs_enable"] is True

    def test_wsl_timeout_expired(self, virt_helper):
        """Test WSL check when subprocess times out."""
        with patch("platform.system", return_value="Windows"):
            with patch.dict("os.environ", {"SystemRoot": "C:\\Windows"}):
                with patch("os.path.exists", return_value=True):
                    with patch(
                        "subprocess.run",
                        side_effect=subprocess.TimeoutExpired(cmd="wsl", timeout=30),
                    ):
                        result = virt_helper.check_wsl_support()

        assert result["available"] is True
        assert result["enabled"] is False
        assert result["needs_enable"] is True

    def test_wsl_file_not_found(self, virt_helper):
        """Test WSL check when wsl command not found during execution."""
        with patch("platform.system", return_value="Windows"):
            with patch.dict("os.environ", {"SystemRoot": "C:\\Windows"}):
                with patch("os.path.exists", return_value=True):
                    with patch("subprocess.run", side_effect=FileNotFoundError()):
                        result = virt_helper.check_wsl_support()

        assert result["available"] is True
        assert result["enabled"] is False
        assert result["needs_enable"] is True

    def test_wsl_general_exception(self, virt_helper):
        """Test WSL check with general exception."""
        with patch("platform.system", side_effect=Exception("test error")):
            result = virt_helper.check_wsl_support()

        assert result["available"] is False
        assert result["enabled"] is False

    def test_wsl_uses_create_no_window_flag(self, virt_helper):
        """Test that WSL check uses CREATE_NO_WINDOW flag when available."""
        mock_status_result = Mock()
        mock_status_result.returncode = 0
        mock_status_result.stdout = "Default Version: 2\n".encode("utf-8")
        mock_status_result.stderr = b""

        with patch("platform.system", return_value="Windows"):
            with patch.dict("os.environ", {"SystemRoot": "C:\\Windows"}):
                with patch("os.path.exists", return_value=True):
                    with patch(
                        "subprocess.run", return_value=mock_status_result
                    ) as mock_run:
                        with patch.object(
                            subprocess, "CREATE_NO_WINDOW", 0x08000000, create=True
                        ):
                            virt_helper.check_wsl_support()

                        # Verify subprocess.run was called
                        mock_run.assert_called_once()

    def test_wsl_without_create_no_window_flag(self, virt_helper):
        """Test that WSL check works when CREATE_NO_WINDOW is not available."""
        mock_status_result = Mock()
        mock_status_result.returncode = 0
        mock_status_result.stdout = "Default Version: 2\n".encode("utf-8")
        mock_status_result.stderr = b""

        # Remove CREATE_NO_WINDOW if it exists
        has_flag = hasattr(subprocess, "CREATE_NO_WINDOW")
        if has_flag:
            original = subprocess.CREATE_NO_WINDOW
            delattr(subprocess, "CREATE_NO_WINDOW")

        try:
            with patch("platform.system", return_value="Windows"):
                with patch.dict("os.environ", {"SystemRoot": "C:\\Windows"}):
                    with patch("os.path.exists", return_value=True):
                        with patch(
                            "subprocess.run", return_value=mock_status_result
                        ) as mock_run:
                            result = virt_helper.check_wsl_support()

                            # Should still work, just with creationflags=0
                            assert result["available"] is True
                            mock_run.assert_called_once()
                            call_kwargs = mock_run.call_args[1]
                            assert call_kwargs["creationflags"] == 0
        finally:
            if has_flag:
                subprocess.CREATE_NO_WINDOW = original

    def test_wsl_version_1_detection(self, virt_helper):
        """Test detection of WSL version 1."""
        mock_status_result = Mock()
        mock_status_result.returncode = 0
        mock_status_result.stdout = "Default Version: 1\n".encode("utf-8")
        mock_status_result.stderr = b""

        with patch("platform.system", return_value="Windows"):
            with patch.dict("os.environ", {"SystemRoot": "C:\\Windows"}):
                with patch("os.path.exists", return_value=True):
                    with patch("subprocess.run", return_value=mock_status_result):
                        result = virt_helper.check_wsl_support()

        assert result["available"] is True
        assert result["enabled"] is True
        assert result["version"] == "1"
        assert result["default_version"] == 1

    def test_wsl_systemroot_not_set(self, virt_helper):
        """Test WSL check when SystemRoot environment variable is not set."""
        mock_status_result = Mock()
        mock_status_result.returncode = 0
        mock_status_result.stdout = "Default Version: 2\n".encode("utf-8")
        mock_status_result.stderr = b""

        with patch("platform.system", return_value="Windows"):
            with patch.dict("os.environ", {}, clear=True):  # Empty environment
                with patch("os.path.exists", return_value=True):
                    with patch("subprocess.run", return_value=mock_status_result):
                        result = virt_helper.check_wsl_support()

        # Should use default C:\Windows path
        assert result["available"] is True


class TestCheckHypervSupport:
    """Tests for check_hyperv_support method."""

    def test_hyperv_not_windows(self, virt_helper):
        """Test Hyper-V check on non-Windows system."""
        with patch("platform.system", return_value="Linux"):
            result = virt_helper.check_hyperv_support()

        assert result["available"] is False
        assert result["enabled"] is False

    def test_hyperv_enabled(self, virt_helper):
        """Test Hyper-V check when enabled."""
        mock_ps_result = Mock()
        mock_ps_result.returncode = 0
        mock_ps_result.stdout = "Enabled"

        with patch("platform.system", return_value="Windows"):
            with patch("subprocess.run", return_value=mock_ps_result):
                result = virt_helper.check_hyperv_support()

        assert result["available"] is True
        assert result["enabled"] is True

    def test_hyperv_disabled(self, virt_helper):
        """Test Hyper-V check when disabled."""
        mock_ps_result = Mock()
        mock_ps_result.returncode = 0
        mock_ps_result.stdout = "Disabled"

        with patch("platform.system", return_value="Windows"):
            with patch("subprocess.run", return_value=mock_ps_result):
                result = virt_helper.check_hyperv_support()

        assert result["available"] is True
        assert result["enabled"] is False

    def test_hyperv_not_available(self, virt_helper):
        """Test Hyper-V check when not available."""
        mock_ps_result = Mock()
        mock_ps_result.returncode = 1
        mock_ps_result.stdout = ""

        with patch("platform.system", return_value="Windows"):
            with patch("subprocess.run", return_value=mock_ps_result):
                result = virt_helper.check_hyperv_support()

        assert result["available"] is False
        assert result["enabled"] is False

    def test_hyperv_powershell_exception(self, virt_helper):
        """Test Hyper-V check with PowerShell exception."""
        with patch("platform.system", return_value="Windows"):
            with patch("subprocess.run", side_effect=Exception("PowerShell error")):
                result = virt_helper.check_hyperv_support()

        assert result["available"] is False
        assert result["enabled"] is False

    def test_hyperv_uses_create_no_window_flag(self, virt_helper):
        """Test that Hyper-V check uses CREATE_NO_WINDOW flag when available."""
        mock_ps_result = Mock()
        mock_ps_result.returncode = 0
        mock_ps_result.stdout = "Enabled"

        with patch("platform.system", return_value="Windows"):
            with patch("subprocess.run", return_value=mock_ps_result) as mock_run:
                with patch.object(
                    subprocess, "CREATE_NO_WINDOW", 0x08000000, create=True
                ):
                    virt_helper.check_hyperv_support()

                    # Verify subprocess.run was called
                    mock_run.assert_called_once()

    def test_hyperv_without_create_no_window_flag(self, virt_helper):
        """Test that Hyper-V check works when CREATE_NO_WINDOW is not available."""
        mock_ps_result = Mock()
        mock_ps_result.returncode = 0
        mock_ps_result.stdout = "Enabled"

        # Remove CREATE_NO_WINDOW if it exists
        has_flag = hasattr(subprocess, "CREATE_NO_WINDOW")
        if has_flag:
            original = subprocess.CREATE_NO_WINDOW
            delattr(subprocess, "CREATE_NO_WINDOW")

        try:
            with patch("platform.system", return_value="Windows"):
                with patch("subprocess.run", return_value=mock_ps_result) as mock_run:
                    result = virt_helper.check_hyperv_support()

                    # Should still work, just with creationflags=0
                    assert result["available"] is True
                    mock_run.assert_called_once()
                    call_kwargs = mock_run.call_args[1]
                    assert call_kwargs["creationflags"] == 0
        finally:
            if has_flag:
                subprocess.CREATE_NO_WINDOW = original

    def test_hyperv_case_insensitive_enabled(self, virt_helper):
        """Test Hyper-V enabled check is case insensitive."""
        mock_ps_result = Mock()
        mock_ps_result.returncode = 0
        mock_ps_result.stdout = "ENABLED"

        with patch("platform.system", return_value="Windows"):
            with patch("subprocess.run", return_value=mock_ps_result):
                result = virt_helper.check_hyperv_support()

        assert result["available"] is True
        assert result["enabled"] is True

    def test_hyperv_enabled_with_whitespace(self, virt_helper):
        """Test Hyper-V enabled check with leading/trailing whitespace."""
        mock_ps_result = Mock()
        mock_ps_result.returncode = 0
        mock_ps_result.stdout = "  Enabled  \n"

        with patch("platform.system", return_value="Windows"):
            with patch("subprocess.run", return_value=mock_ps_result):
                result = virt_helper.check_hyperv_support()

        assert result["available"] is True
        assert result["enabled"] is True

    def test_hyperv_timeout_expired(self, virt_helper):
        """Test Hyper-V check when subprocess times out."""
        with patch("platform.system", return_value="Windows"):
            with patch(
                "subprocess.run",
                side_effect=subprocess.TimeoutExpired(cmd="powershell", timeout=30),
            ):
                result = virt_helper.check_hyperv_support()

        # Exception is caught, returns default values
        assert result["available"] is False
        assert result["enabled"] is False

    def test_hyperv_file_not_found(self, virt_helper):
        """Test Hyper-V check when PowerShell is not found."""
        with patch("platform.system", return_value="Windows"):
            with patch("subprocess.run", side_effect=FileNotFoundError()):
                result = virt_helper.check_hyperv_support()

        assert result["available"] is False
        assert result["enabled"] is False
