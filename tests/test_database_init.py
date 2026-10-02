# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""
Unit tests for src.database.init module.
Tests database initialization functionality.
"""

import os
from unittest.mock import Mock, patch

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


class TestSchemaCurrentCheck:
    """2026-09-30: an agent tree on a slow NFS share spent 107 s starting a
    second interpreter just for Alembic to report "already at head", and the
    60 s limit killed it -- the agent refused to start with nothing to do."""

    def _versions(self, tmp_path):
        versions = tmp_path / "versions"
        versions.mkdir()
        (versions / "a.py").write_text('revision: str = "aaa"\ndown_revision = None\n')
        (versions / "b.py").write_text(
            'revision: str = "bbb"\ndown_revision: Union[str, None] = "aaa"\n'
        )
        return str(versions)

    def _db(self, tmp_path, *revisions):
        import sqlite3  # pylint: disable=import-outside-toplevel

        path = str(tmp_path / "agent.db")
        conn = sqlite3.connect(path)
        conn.execute("CREATE TABLE alembic_version (version_num VARCHAR(32))")
        conn.executemany(
            "INSERT INTO alembic_version VALUES (?)", [(r,) for r in revisions]
        )
        conn.commit()
        conn.close()
        return path

    def test_heads_are_read_from_the_scripts(self, tmp_path):
        from src.database import init  # pylint: disable=import-outside-toplevel

        assert init._migration_heads(self._versions(tmp_path)) == {"bbb"}

    def test_only_a_database_at_every_head_skips_alembic(self, tmp_path):
        from src.database import init  # pylint: disable=import-outside-toplevel

        versions = self._versions(tmp_path)
        with patch.object(init, "_migration_heads", return_value={"bbb"}):
            assert init.database_is_current(self._db(tmp_path, "bbb"))
        assert init._migration_heads(versions) == {"bbb"}
        other = tmp_path / "old"
        other.mkdir()
        with patch.object(init, "_migration_heads", return_value={"bbb"}):
            assert not init.database_is_current(self._db(other, "aaa"))
            assert not init.database_is_current(str(tmp_path / "missing.db"))

    def test_an_unparseable_script_means_run_alembic(self, tmp_path):
        from src.database import init  # pylint: disable=import-outside-toplevel

        versions = tmp_path / "v"
        versions.mkdir()
        (versions / "x.py").write_text("# no revision here\n")
        assert init._migration_heads(str(versions)) is None

    def test_the_shipped_migrations_have_one_head(self):
        from src.database import init  # pylint: disable=import-outside-toplevel

        versions = os.path.join(os.path.dirname(init.__file__), "alembic", "versions")
        assert len(init._migration_heads(versions)) == 1
