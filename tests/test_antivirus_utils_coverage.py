"""Tests for antivirus utilities module."""

# pylint: disable=import-outside-toplevel

import os
from unittest.mock import MagicMock, patch

from src.sysmanage_agent.operations.antivirus_utils import get_brew_user


class TestGetBrewUser:
    """Tests for get_brew_user function."""

    def test_get_brew_user_opt_homebrew_exists(self):
        """Test finding brew user from /opt/homebrew."""
        mock_stat = MagicMock()
        mock_stat.st_uid = 501

        mock_pwuid = MagicMock()
        mock_pwuid.pw_name = "brewuser"

        with patch("os.path.exists") as mock_exists:
            with patch("os.stat") as mock_os_stat:
                with patch.dict("sys.modules", {"pwd": MagicMock()}):
                    import pwd

                    with patch.object(pwd, "getpwuid", return_value=mock_pwuid):
                        mock_exists.side_effect = lambda p: p == "/opt/homebrew"
                        mock_os_stat.return_value = mock_stat

                        result = get_brew_user()
                        assert result == "brewuser"

    def test_get_brew_user_usr_local_homebrew_exists(self):
        """Test finding brew user from /usr/local/Homebrew."""
        mock_stat = MagicMock()
        mock_stat.st_uid = 502

        mock_pwuid = MagicMock()
        mock_pwuid.pw_name = "localbrewuser"

        with patch("os.path.exists") as mock_exists:
            with patch("os.stat") as mock_os_stat:
                with patch.dict("sys.modules", {"pwd": MagicMock()}):
                    import pwd

                    with patch.object(pwd, "getpwuid", return_value=mock_pwuid):
                        mock_exists.side_effect = lambda p: p == "/usr/local/Homebrew"
                        mock_os_stat.return_value = mock_stat

                        result = get_brew_user()
                        assert result == "localbrewuser"

    def test_get_brew_user_no_homebrew_with_sudo_user(self):
        """Test fallback to SUDO_USER when Homebrew not found."""
        with patch("os.path.exists", return_value=False):
            with patch.dict(os.environ, {"SUDO_USER": "sudouser"}):
                result = get_brew_user()
                assert result == "sudouser"

    def test_get_brew_user_no_homebrew_no_sudo_user(self):
        """Test returns None when no Homebrew and no SUDO_USER."""
        with patch("os.path.exists", return_value=False):
            with patch.dict(os.environ, {}, clear=True):
                # Remove SUDO_USER if it exists
                env = os.environ.copy()
                if "SUDO_USER" in env:
                    del env["SUDO_USER"]
                with patch.dict(os.environ, env, clear=True):
                    result = get_brew_user()
                    assert result is None

    def test_get_brew_user_os_error_continues(self):
        """Test that OSError during stat is handled gracefully."""
        with patch("os.path.exists", return_value=True):
            with patch("os.stat", side_effect=OSError("Permission denied")):
                with patch.dict(os.environ, {"SUDO_USER": "fallbackuser"}):
                    result = get_brew_user()
                    assert result == "fallbackuser"

    def test_get_brew_user_key_error_continues(self):
        """Test that KeyError from getpwuid is handled gracefully."""
        mock_stat = MagicMock()
        mock_stat.st_uid = 99999

        with patch("os.path.exists", return_value=True):
            with patch("os.stat", return_value=mock_stat):
                with patch.dict("sys.modules", {"pwd": MagicMock()}):
                    import pwd

                    with patch.object(
                        pwd, "getpwuid", side_effect=KeyError("User not found")
                    ):
                        with patch.dict(os.environ, {"SUDO_USER": "fallback"}):
                            result = get_brew_user()
                            assert result == "fallback"
