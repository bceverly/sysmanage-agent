"""
Database base configuration for SysManage Agent.
"""

import os
import logging
from pathlib import Path
from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker
from sqlalchemy.pool import StaticPool

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
        self.engine = create_engine(
            f"sqlite:///{database_path}",
            echo=False,  # Set to True for SQL debugging
            poolclass=StaticPool,
            connect_args={
                "check_same_thread": False,  # Allow multiple threads
                "timeout": 30,  # Connection timeout in seconds
            },
        )

        # Create session factory
        self.SessionLocal = sessionmaker(
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
        except (OSError, PermissionError) as e:
            logger.error("Failed to create database directory %s: %s", directory, e)
            raise

    def create_tables(self):
        """Create all tables defined by models."""
        try:
            Base.metadata.create_all(bind=self.engine)
            logger.info("Database tables created successfully")
        except Exception as e:
            logger.error("Failed to create database tables: %s", e)
            raise

    def get_session(self):
        """Get a database session."""
        return self.SessionLocal()

    def close(self):
        """Close the database connection."""
        self.engine.dispose()
        logger.info("Database connection closed")


# Global database manager instance
_db_manager = None


def get_database_manager(database_path: str = None) -> DatabaseManager:
    """
    Get the global database manager instance.

    Args:
        database_path: Path to database file (only used on first call)

    Returns:
        DatabaseManager instance
    """
    global _db_manager
    if _db_manager is None:
        _db_manager = DatabaseManager(database_path)
    return _db_manager


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
