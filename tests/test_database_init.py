"""
Unit tests for src.database.init module.
Tests database initialization functionality.
"""

from unittest.mock import Mock


from src.database.init import get_database_path_from_config, initialize_database


class TestDatabaseInit:
    """Test cases for database initialization functions."""

    def test_get_database_path_from_config_custom(self):
        """Test getting database path with custom value."""
        mock_config = Mock()
        mock_config.get.return_value = {"path": "/custom/path/agent.db"}

        result = get_database_path_from_config(mock_config)

        assert "/custom/path/agent.db" in result

    def test_get_database_path_from_config_exception(self):
        """Test getting database path with exception."""
        mock_config = Mock()
        mock_config.get.side_effect = Exception("Config error")

        result = get_database_path_from_config(mock_config)

        assert "agent.db" in result

    def test_initialize_database_simple(self):
        """Test database initialization simply."""
        mock_config = Mock()
        result = initialize_database(mock_config)
        # Just test that it doesn't crash
        assert result in [True, False]
