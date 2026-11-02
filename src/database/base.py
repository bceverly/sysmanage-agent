# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""
Database base configuration for SysManage Agent.
"""

import logging
import os
from contextlib import contextmanager
from pathlib import Path
from typing import Optional

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, declarative_base, sessionmaker
from sqlalchemy.pool import NullPool, StaticPool

from src.i18n import _

# Create the base model class
Base = declarative_base()

# Logger
logger = logging.getLogger(__name__)


class DatabaseManager:
    """Manages SQLite database connection and sessions for the agent."""

    def __init__(self, database_path: str = None):
        """
        Initialize the database manager.

        Args:
            database_path: Path to SQLite database file. If None, uses default location.
        """
        if database_path is None:
            database_path = self._get_default_database_path()

        self.database_path = database_path
        self._ensure_database_directory()

        # Create engine with SQLite-specific settings
        # Note: isolation_level=None disables pysqlite's internal transaction
        # handling, preventing conflicts with SQLAlchemy's transaction management.
        # This fixes "cannot rollback - no transaction is active" errors when
        # using StaticPool with asyncio.to_thread() for multi-threaded access.
        self.engine = create_engine(
            f"sqlite:///{database_path}",
            echo=False,  # Set to True for SQL debugging
            poolclass=StaticPool,
            connect_args={
                "check_same_thread": False,  # Allow multiple threads
                "timeout": 30,  # Connection timeout in seconds
                "isolation_level": None,  # Disable pysqlite transaction handling
            },
        )

        self._bulk_engine = None  # bulk_session's own connection, made on use

        # Create session factory
        self.session_local = sessionmaker(
            autocommit=False, autoflush=False, bind=self.engine
        )

        logger.info("Database manager initialized with path: %s", database_path)

    def _get_default_database_path(self) -> str:
        """Get the default database path - defaults to current working directory."""
        # Default to current working directory as requested
        return os.path.join(os.getcwd(), "agent.db")

    def _ensure_database_directory(self):
        """Ensure the database directory exists."""
        directory = os.path.dirname(self.database_path)
        try:
            Path(directory).mkdir(parents=True, exist_ok=True)
        except OSError as error:
            logger.exception(
                _("Failed to create database directory %s: %s"), directory, error
            )
            raise

    def create_tables(self):
        """Create all tables defined by models."""
        try:
            Base.metadata.create_all(bind=self.engine)
            logger.info("Database tables created successfully")
        except Exception as error:
            logger.exception(_("Failed to create database tables: %s"), error)
            raise

    def get_session(self):
        """Get a database session."""
        return self.session_local()

    @contextmanager
    def bulk_session(self):
        """A session on a connection of its own, for one large write.

        Every other session shares ONE connection (StaticPool), so another
        thread's commit there ended a bulk write's transaction early and the
        rest of its rows were committed -- and synced -- one at a time: a
        package catalog took over an hour on ubiquiti's disk while the event
        loop waited on the same connection (production, 2026-11-02).  On its
        own connection the transaction is the writer's alone; the others wait
        for its single commit (``timeout``) instead.  The session is pinned to
        that one connection until the block ends, so its own commit cannot
        hand the connection back (and close it) mid-transaction."""
        if self._bulk_engine is None:
            self._bulk_engine = create_engine(
                f"sqlite:///{self.database_path}",
                echo=False,
                poolclass=NullPool,
                connect_args={"check_same_thread": False, "timeout": 30,
                              "isolation_level": None},
            )  # fmt: skip
        connection = self._bulk_engine.connect()
        session = Session(bind=connection, autoflush=False)
        try:
            yield session
        finally:
            session.close()
            connection.close()

    def close(self):
        """Close the database connection."""
        self.engine.dispose()
        if self._bulk_engine is not None:
            self._bulk_engine.dispose()
        logger.info("Database connection closed")


# Global database manager instance (module-level private variable)
_db_manager = None  # pylint: disable=invalid-name


def get_database_manager(database_path: str = None) -> DatabaseManager:
    """
    Get the global database manager instance.

    Args:
        database_path: Path to database file (only used on first call)

    Returns:
        DatabaseManager instance
    """
    global _db_manager  # pylint: disable=global-statement
    if _db_manager is None:
        _db_manager = DatabaseManager(database_path)
    return _db_manager


def current_database_path() -> Optional[str]:
    """The open database's path, or None before ``initialize_database`` --
    read-only: unlike ``get_database_manager`` it never creates one."""
    return _db_manager.database_path if _db_manager is not None else None


@contextmanager
def write_transaction(session):
    """One real SQLite transaction around a bulk write.

    The engine runs pysqlite with ``isolation_level=None``, so SQLAlchemy emits
    no BEGIN and every statement commits -- and syncs to disk -- on its own.
    Replacing a 121,420-row package catalog was therefore ~120 separate
    commits while the one shared connection (StaticPool) stayed busy; the
    event loop's small queue reads waited behind it for minutes and the server
    dropped the websocket for missed pings (production, ubiquiti, 2026-11-01).
    Inside this block the whole write is one transaction (one sync).

    Use it on ``DatabaseManager.bulk_session()``: on the shared connection
    another thread's commit ended the transaction early and the rest went back
    to a sync per statement -- NOT harmless on a slow disk (production,
    ubiquiti, 2026-11-02).  Keep the block short: stage the data first.
    """
    raw = session.connection().connection.driver_connection
    if not raw.in_transaction:
        raw.execute("BEGIN IMMEDIATE")
    try:
        yield
    except BaseException:
        if raw.in_transaction:
            raw.execute("ROLLBACK")
        raise
    if raw.in_transaction:
        raw.execute("COMMIT")


@contextmanager
def get_db_session():
    """
    Get a database session. Use this in a context manager.

    Example:
        with get_db_session() as session:
            # Use session here
            pass
    """
    db_manager = get_database_manager()
    session = db_manager.get_session()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
