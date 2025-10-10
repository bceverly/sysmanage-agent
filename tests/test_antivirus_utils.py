"""
Unit tests for src.sysmanage_agent.operations.antivirus_utils module.
Tests utility functions for antivirus operations.
"""

# pylint: disable=protected-access

import os
import sys
from unittest.mock import Mock, patch

from src.sysmanage_agent.operations.antivirus_utils import get_brew_user


class TestGetBrewUser:
    """Test cases for get_brew_user function."""

    def test_get_brew_user_opt_homebrew_exists(self):
        """Test get_brew_user when /opt/homebrew exists."""
        mock_stat = Mock()
        mock_stat.st_uid = 501
        mock_pwd_entry = Mock()
        mock_pwd_entry.pw_name = "testuser"

        mock_pwd = Mock()
        mock_pwd.getpwuid = Mock(return_value=mock_pwd_entry)

        with patch.dict(sys.modules, {"pwd": mock_pwd}):
            with patch("os.path.exists") as mock_exists:
                with patch("os.stat", return_value=mock_stat):
                    # First call for /opt/homebrew should return True
                    mock_exists.side_effect = [True]

                    result = get_brew_user()

                    assert result == "testuser"
                    mock_exists.assert_called_with("/opt/homebrew")

    def test_get_brew_user_usr_local_homebrew_exists(self):
        """Test get_brew_user when /usr/local/Homebrew exists."""
        mock_stat = Mock()
        mock_stat.st_uid = 502
        mock_pwd_entry = Mock()
        mock_pwd_entry.pw_name = "localuser"

        mock_pwd = Mock()
        mock_pwd.getpwuid = Mock(return_value=mock_pwd_entry)

        with patch.dict(sys.modules, {"pwd": mock_pwd}):
            with patch("os.path.exists") as mock_exists:
                with patch("os.stat", return_value=mock_stat):
                    # First call fails, second succeeds
                    mock_exists.side_effect = [False, True]

                    result = get_brew_user()

                    assert result == "localuser"
                    assert mock_exists.call_count == 2

    def test_get_brew_user_os_error(self):
        """Test get_brew_user when os.stat raises OSError."""
        mock_pwd = Mock()

        with patch.dict(sys.modules, {"pwd": mock_pwd}):
            with patch("os.path.exists", return_value=True):
                with patch("os.stat", side_effect=OSError("Permission denied")):
                    with patch.dict(os.environ, {"SUDO_USER": "fallbackuser"}):
                        result = get_brew_user()

                        assert result == "fallbackuser"

    def test_get_brew_user_key_error(self):
        """Test get_brew_user when pwd.getpwuid raises KeyError."""
        mock_stat = Mock()
        mock_stat.st_uid = 999

        mock_pwd = Mock()
        mock_pwd.getpwuid = Mock(side_effect=KeyError("User not found"))

        with patch.dict(sys.modules, {"pwd": mock_pwd}):
            with patch("os.path.exists", return_value=True):
                with patch("os.stat", return_value=mock_stat):
                    with patch.dict(os.environ, {"SUDO_USER": "sudouser"}):
                        result = get_brew_user()

                        assert result == "sudouser"

    def test_get_brew_user_no_homebrew_no_sudo_user(self):
        """Test get_brew_user when no Homebrew and no SUDO_USER."""
        mock_pwd = Mock()

        with patch.dict(sys.modules, {"pwd": mock_pwd}):
            with patch("os.path.exists", return_value=False):
                with patch.dict(os.environ, {}, clear=True):
                    result = get_brew_user()

                    assert result is None

    def test_get_brew_user_no_homebrew_with_sudo_user(self):
        """Test get_brew_user when no Homebrew but SUDO_USER is set."""
        mock_pwd = Mock()

        with patch.dict(sys.modules, {"pwd": mock_pwd}):
            with patch("os.path.exists", return_value=False):
                with patch.dict(os.environ, {"SUDO_USER": "envuser"}):
                    result = get_brew_user()

                    assert result == "envuser"

    def test_get_brew_user_first_dir_fails_second_succeeds(self):
        """Test get_brew_user when first dir fails with exception, second succeeds."""
        mock_stat1 = Mock()
        mock_stat1.st_uid = 501
        mock_stat2 = Mock()
        mock_stat2.st_uid = 502

        mock_pwd_entry = Mock()
        mock_pwd_entry.pw_name = "seconduser"

        mock_pwd = Mock()
        mock_pwd.getpwuid = Mock(return_value=mock_pwd_entry)

        with patch.dict(sys.modules, {"pwd": mock_pwd}):
            with patch("os.path.exists") as mock_exists:
                # Both directories exist
                mock_exists.side_effect = [True, True]

                with patch("os.stat") as mock_stat:
                    # First call raises OSError, second succeeds
                    mock_stat.side_effect = [OSError("Error"), mock_stat2]

                    result = get_brew_user()

                    assert result == "seconduser"
                    assert mock_stat.call_count == 2
