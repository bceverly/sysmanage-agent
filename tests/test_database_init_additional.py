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

        with patch("src.database.init.os.getcwd", return_value="/current/dir"):
            result = get_database_path_from_config(mock_config)

            # Should join current directory with relative path
            assert result == "/current/dir/relative_agent.db"

    def test_get_database_path_from_config_default_value(self):
        """Test getting database path with default value."""
        mock_config = Mock()
        mock_config.get.return_value = {}  # No 'path' key

        with patch("src.database.init.os.path.isabs", return_value=False), patch(
            "src.database.init.os.path.join", side_effect=lambda *args: "/".join(args)
        ), patch("src.database.init.os.getcwd", return_value="/current/dir"), patch(
            "src.database.init.os.path.exists", return_value=False
        ):

            result = get_database_path_from_config(mock_config)

            # Should use os.path.join with current directory and default "agent.db"
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
        ) as mock_dirname, patch(
            "src.database.init.os.path.abspath"
        ) as mock_abspath, patch(
            "src.database.init.os.path.exists"
        ) as mock_exists, patch(
            "src.database.base.get_database_manager"
        ) as mock_db_mgr:

            # Setup path mocking
            mock_abspath.return_value = "/path/to/src/database/init.py"
            mock_exists.return_value = False  # No venv python, use system python3

            # Setup database manager mock
            mock_db = Mock()
            mock_db.database_path = "/test/db/path/agent.db"
            mock_db_mgr.return_value = mock_db

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
            # Verify the call was made with python3 -m alembic and env variable
            assert mock_run.call_count == 1
            call_args = mock_run.call_args
            assert call_args[1]["cwd"] == "/path/to"
            assert call_args[1]["capture_output"] is True
            assert call_args[1]["text"] is True
            assert call_args[1]["timeout"] == 60
            assert call_args[1]["check"] is False
            # Check that it used python3 -m alembic
            assert call_args[0][0] == ["python3", "-m", "alembic", "downgrade", "base"]
            # Check that env was passed
            assert "env" in call_args[1]
            assert "SYSMANAGE_DB_PATH" in call_args[1]["env"]

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
