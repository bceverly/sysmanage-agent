"""
Additional comprehensive tests for database.init module.
Tests missing coverage areas to improve overall coverage.
"""

from unittest.mock import Mock, patch

from src.database.init import (
    get_database_path_from_config,
    initialize_database,
    run_alembic_migration,
    should_auto_migrate,
)


class TestDatabaseInitAdditional:
    """Additional test cases for database initialization functions."""

    def test_get_database_path_from_config_relative_path(self):
        """Test getting database path with relative path (line 33)."""
        mock_config = Mock()
        mock_config.get.return_value = {"path": "relative_agent.db"}

        with patch("os.path.isabs", return_value=False), patch(
            "os.path.join"
        ) as mock_join, patch("os.getcwd", return_value="/current/dir"):

            mock_join.return_value = "/current/dir/relative_agent.db"

            result = get_database_path_from_config(mock_config)

            mock_join.assert_called_with("/current/dir", "relative_agent.db")
            assert result == "/current/dir/relative_agent.db"

    def test_get_database_path_from_config_default_value(self):
        """Test getting database path with default value."""
        mock_config = Mock()
        mock_config.get.return_value = {}  # No 'path' key

        with patch("os.path.isabs", return_value=False), patch(
            "os.path.join"
        ) as mock_join, patch("os.getcwd", return_value="/current/dir"):

            mock_join.return_value = "/current/dir/agent.db"

            result = get_database_path_from_config(mock_config)

            mock_join.assert_called_with("/current/dir", "agent.db")
            assert result == "/current/dir/agent.db"

    def test_should_auto_migrate_exception(self):
        """Test should_auto_migrate with exception (lines 57-58)."""
        mock_config = Mock()
        mock_config.get.side_effect = Exception("Config access error")

        result = should_auto_migrate(mock_config)

        assert result is True  # Default to auto-migrate

    def test_should_auto_migrate_enabled(self):
        """Test should_auto_migrate when enabled."""
        mock_config = Mock()
        mock_config.get.return_value = {"auto_migrate": True}

        result = should_auto_migrate(mock_config)

        assert result is True

    def test_should_auto_migrate_disabled(self):
        """Test should_auto_migrate when disabled."""
        mock_config = Mock()
        mock_config.get.return_value = {"auto_migrate": False}

        result = should_auto_migrate(mock_config)

        assert result is False

    def test_should_auto_migrate_default(self):
        """Test should_auto_migrate with default value."""
        mock_config = Mock()
        mock_config.get.return_value = {}  # No 'auto_migrate' key

        result = should_auto_migrate(mock_config)

        assert result is True  # Default value

    @patch("src.database.init.run_alembic_migration")
    @patch("src.database.init.should_auto_migrate")
    @patch("src.database.init.get_database_manager")
    @patch("src.database.init.get_database_path_from_config")
    @patch("os.path.exists")
    def test_initialize_database_new_database(  # pylint: disable=too-many-positional-arguments
        self,
        mock_exists,
        mock_get_path,
        mock_get_manager,
        mock_auto_migrate,
        mock_alembic,
    ):
        """Test initialize_database with new database (line 132)."""
        mock_config = Mock()
        mock_get_path.return_value = "/path/to/agent.db"
        mock_exists.return_value = False  # Database doesn't exist
        mock_auto_migrate.return_value = True
        mock_alembic.return_value = True
        mock_get_manager.return_value = Mock()

        result = initialize_database(mock_config)

        assert result is True
        mock_exists.assert_called_with("/path/to/agent.db")

    @patch("src.database.init.run_alembic_migration")
    @patch("src.database.init.should_auto_migrate")
    @patch("src.database.init.get_database_manager")
    @patch("src.database.init.get_database_path_from_config")
    @patch("os.path.exists")
    def test_initialize_database_migration_failure(  # pylint: disable=too-many-positional-arguments
        self,
        mock_exists,
        mock_get_path,
        mock_get_manager,
        mock_auto_migrate,
        mock_alembic,
    ):
        """Test initialize_database when migration fails (lines 142-143)."""
        mock_config = Mock()
        mock_get_path.return_value = "/path/to/agent.db"
        mock_exists.return_value = True  # Database exists
        mock_auto_migrate.return_value = True
        mock_alembic.return_value = False  # Migration fails
        mock_get_manager.return_value = Mock()

        result = initialize_database(mock_config)

        assert result is False

    @patch("src.database.init.should_auto_migrate")
    @patch("src.database.init.get_database_manager")
    @patch("src.database.init.get_database_path_from_config")
    @patch("os.path.exists")
    def test_initialize_database_auto_migrate_disabled(
        self, mock_exists, mock_get_path, mock_get_manager, mock_auto_migrate
    ):
        """Test initialize_database with auto-migration disabled (lines 144-145)."""
        mock_config = Mock()
        mock_get_path.return_value = "/path/to/agent.db"
        mock_exists.return_value = True
        mock_auto_migrate.return_value = False  # Auto-migrate disabled
        mock_get_manager.return_value = Mock()

        result = initialize_database(mock_config)

        assert result is True

    @patch("src.database.init.get_database_path_from_config")
    def test_initialize_database_exception(self, mock_get_path):
        """Test initialize_database with exception (lines 151-153)."""
        mock_config = Mock()
        mock_get_path.side_effect = Exception("Database initialization error")

        result = initialize_database(mock_config)

        assert result is False

    def test_run_alembic_migration_custom_operation(self):
        """Test run_alembic_migration with custom operation and revision."""
        with patch("subprocess.run") as mock_run, patch(
            "src.database.init.os.path.dirname"
        ) as mock_dirname, patch("src.database.init.os.path.abspath") as mock_abspath:

            # Setup path mocking
            mock_abspath.return_value = "/path/to/src/database/init.py"

            # Provide enough dirname return values for all expected calls
            mock_dirname.side_effect = [
                "/path/to/src/database",  # First call from run_alembic_migration
                "/path/to/src",  # Second call from run_alembic_migration
                "/path/to",  # Third call from run_alembic_migration
                "/home/bceverly/dev/sysmanage-agent/src/i18n",  # From i18n module
                "/home/bceverly/dev/sysmanage-agent/src",  # Additional fallback
                "/home/bceverly/dev/sysmanage-agent",  # Additional fallback
                "/home/bceverly/dev",  # Additional fallback
                "/home/bceverly",  # Additional fallback
                "/home",  # Additional fallback
                "/",  # Root fallback
            ]

            # Setup subprocess mock for success
            mock_result = Mock()
            mock_result.returncode = 0
            mock_result.stdout = ""
            mock_result.stderr = ""
            mock_run.return_value = mock_result

            result = run_alembic_migration("downgrade", "base")

            assert result is True
            mock_run.assert_called_once_with(
                ["alembic", "downgrade", "base"],
                cwd="/path/to",
                capture_output=True,
                text=True,
                timeout=60,
                check=False,
            )

    @patch("src.database.init.run_alembic_migration")
    @patch("src.database.init.should_auto_migrate")
    @patch("src.database.init.get_database_manager")
    @patch("src.database.init.get_database_path_from_config")
    @patch("os.path.exists")
    def test_initialize_database_existing_database(  # pylint: disable=too-many-positional-arguments
        self,
        mock_exists,
        mock_get_path,
        mock_get_manager,
        mock_auto_migrate,
        mock_alembic,
    ):
        """Test initialize_database with existing database."""
        mock_config = Mock()
        mock_get_path.return_value = "/path/to/agent.db"
        mock_exists.return_value = True  # Database exists
        mock_auto_migrate.return_value = True
        mock_alembic.return_value = True
        mock_get_manager.return_value = Mock()

        result = initialize_database(mock_config)

        assert result is True
        mock_alembic.assert_called_once_with("upgrade", "head")
