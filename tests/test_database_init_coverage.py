"""
Tests for database/init.py to improve coverage.
Targets the 13 missing lines (80% -> 100%).
"""

import subprocess
from unittest.mock import Mock, patch

from src.database.init import run_alembic_migration


class TestDatabaseInitCoverage:
    """Test cases for database init coverage improvements."""

    @patch("subprocess.run")
    def test_run_alembic_migration_success_with_stdout(self, mock_run):
        """Test successful alembic migration with stdout output (line 89)."""
        # Mock successful command with stdout
        mock_run.return_value = Mock(
            returncode=0, stdout="Migration completed successfully", stderr=""
        )

        with patch("src.database.init.logger") as mock_logger:
            result = run_alembic_migration("upgrade", "head")

            assert result is True
            # Should log the stdout output (line 89)
            mock_logger.debug.assert_called_with(
                "Alembic output: %s", "Migration completed successfully"
            )

    @patch("subprocess.run")
    def test_run_alembic_migration_failure_with_stderr(self, mock_run):
        """Test failed alembic command with stderr output (lines 92-98)."""
        # Mock failed command with stderr
        mock_run.return_value = Mock(
            returncode=1,
            stdout="Some output",
            stderr="Migration failed: table already exists",
        )

        with patch("src.database.init.logger") as mock_logger:
            result = run_alembic_migration("upgrade", "head")

            assert result is False
            # Should log error message (line 92-94)
            mock_logger.error.assert_any_call(
                "Alembic %s failed with return code %d", "upgrade", 1
            )
            # Should log stderr (line 96)
            mock_logger.error.assert_any_call(
                "Alembic error: %s", "Migration failed: table already exists"
            )
            # Should log stdout (line 98)
            mock_logger.error.assert_any_call("Alembic output: %s", "Some output")

    @patch("subprocess.run")
    def test_run_alembic_migration_timeout(self, mock_run):
        """Test alembic migration timeout (lines 101-103)."""
        # Mock timeout exception
        mock_run.side_effect = subprocess.TimeoutExpired("alembic upgrade head", 60)

        with patch("src.database.init.logger") as mock_logger:
            result = run_alembic_migration("upgrade", "head")

            assert result is False
            # Should log timeout error (line 102)
            mock_logger.error.assert_called_with(
                "Alembic %s timed out after 60 seconds", "upgrade"
            )

    @patch("subprocess.run")
    def test_run_alembic_migration_general_exception(self, mock_run):
        """Test alembic migration with general exception (lines 104-106)."""
        # Mock general exception
        mock_run.side_effect = Exception("Database connection failed")

        with patch("src.database.init.logger") as mock_logger:
            result = run_alembic_migration("upgrade", "head")

            assert result is False
            # Should log general error (line 105)
            args, _ = mock_logger.error.call_args
            assert "Failed to run alembic" in args[0]
            assert "upgrade" in args[1]
