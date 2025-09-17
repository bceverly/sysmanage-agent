"""
Database initialization and migration management for SysManage Agent.
"""

import os
import subprocess  # nosec B404
import logging
from typing import Optional

from .base import get_database_manager
from src.i18n import _

logger = logging.getLogger(__name__)


def get_database_path_from_config(config_manager) -> str:
    """
    Get database path from configuration.

    Args:
        config_manager: ConfigManager instance

    Returns:
        Database path from config, or default "agent.db" in current directory
    """
    try:
        # Get database path from config, defaulting to "agent.db" in current directory
        db_config = config_manager.get("database", {})
        db_path = db_config.get("path", "agent.db")

        # If relative path, make it relative to current working directory
        if not os.path.isabs(db_path):
            db_path = os.path.join(os.getcwd(), db_path)

        return db_path

    except Exception as e:
        logger.warning(
            _("Failed to get database path from config: %s, using default"), e
        )
        return os.path.join(os.getcwd(), "agent.db")


def should_auto_migrate(config_manager) -> bool:
    """
    Check if auto-migration is enabled in configuration.

    Args:
        config_manager: ConfigManager instance

    Returns:
        True if auto-migration is enabled, False otherwise
    """
    try:
        db_config = config_manager.get("database", {})
        return db_config.get("auto_migrate", True)
    except Exception:
        return True  # Default to auto-migrate


def run_alembic_migration(operation: str = "upgrade", revision: str = "head") -> bool:
    """
    Run alembic migration commands.

    Args:
        operation: Alembic operation (upgrade, downgrade, etc.)
        revision: Target revision (head, etc.)

    Returns:
        True if successful, False otherwise
    """
    try:
        # Change to the agent directory to ensure alembic.ini is found
        agent_dir = os.path.dirname(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        )

        # Run alembic command using the virtual environment's alembic
        venv_alembic = os.path.join(agent_dir, ".venv", "bin", "alembic")
        if os.path.exists(venv_alembic):
            cmd = [venv_alembic, operation, revision]
        else:
            cmd = ["alembic", operation, revision]
        logger.info(_("Running alembic command: %s"), " ".join(cmd))

        result = subprocess.run(  # nosec B603, B607
            cmd, cwd=agent_dir, capture_output=True, text=True, timeout=60
        )

        if result.returncode == 0:
            logger.info(_("Alembic %s completed successfully"), operation)
            if result.stdout:
                logger.debug("Alembic output: %s", result.stdout)
            return True
        else:
            logger.error(
                _("Alembic %s failed with return code %d"), operation, result.returncode
            )
            if result.stderr:
                logger.error("Alembic error: %s", result.stderr)
            if result.stdout:
                logger.error("Alembic output: %s", result.stdout)
            return False

    except subprocess.TimeoutExpired:
        logger.error(_("Alembic %s timed out after 60 seconds"), operation)
        return False
    except Exception as e:
        logger.error(_("Failed to run alembic %s: %s"), operation, e)
        return False


def initialize_database(config_manager) -> bool:
    """
    Initialize the agent database with proper configuration and migrations.

    Args:
        config_manager: ConfigManager instance

    Returns:
        True if successful, False otherwise
    """
    try:
        # Get database path from configuration
        db_path = get_database_path_from_config(config_manager)
        logger.info(_("Initializing database at: %s"), db_path)

        # Initialize the global database manager with the correct path FIRST
        # This ensures all subsequent get_database_manager() calls use this path
        db_manager = get_database_manager(db_path)

        # Check if database exists
        db_exists = os.path.exists(db_path)

        if not db_exists:
            logger.info(_("Database does not exist, creating new database"))
        else:
            logger.info(_("Database exists, checking for migrations"))

        # Check if auto-migration is enabled
        if should_auto_migrate(config_manager):
            logger.info(_("Auto-migration is enabled"))

            # Run alembic upgrade to latest
            if not run_alembic_migration("upgrade", "head"):
                logger.error(_("Failed to run database migrations"))
                return False
        else:
            logger.info(_("Auto-migration is disabled, skipping migrations"))

        logger.info(_("Database initialized successfully"))

        return True

    except Exception as e:
        logger.error(_("Failed to initialize database: %s"), e)
        return False
