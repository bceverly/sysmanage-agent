"""
Database initialization and migration management for SysManage Agent.
"""

import logging
import os
import subprocess  # nosec B404
import sys

from src.i18n import _

from .base import get_database_manager

logger = logging.getLogger(__name__)


def get_database_path_from_config(config_manager) -> str:
    """
    Get database path from configuration with system-to-local fallback.

    Tries paths in order:
    1. Configured path from config file
    2. System path: /var/lib/sysmanage-agent/agent.db
    3. Local fallback: ./agent.db (in current directory)

    Args:
        config_manager: ConfigManager instance

    Returns:
        Database path, preferring system location if it exists
    """
    try:
        # Get database path from config
        db_config = config_manager.get("database", {})
        config_path = db_config.get("path", None)

        # If configured path is specified and absolute, use it
        # (database will be created if it doesn't exist)
        if config_path and os.path.isabs(config_path):
            logger.info(_("Using configured database path: %s"), config_path)
            return config_path

        # If configured path is relative, join with current directory
        if config_path:
            abs_path = os.path.join(os.getcwd(), config_path)
            logger.info(_("Using configured relative database path: %s"), abs_path)
            return abs_path

        # Try system path: /var/lib/sysmanage-agent/agent.db
        system_path = "/var/lib/sysmanage-agent/agent.db"
        if os.path.exists(system_path):
            logger.info(_("Using system database path: %s"), system_path)
            return system_path

        # If system directory exists but database doesn't, use system path
        # (database will be created there)
        system_dir = "/var/lib/sysmanage-agent"
        if os.path.exists(system_dir) and os.access(system_dir, os.W_OK):
            logger.info(
                _("System directory exists, using system database path: %s"),
                system_path,
            )
            return system_path

        # Fallback to local directory
        local_path = os.path.join(os.getcwd(), "agent.db")
        logger.info(_("Falling back to local database path: %s"), local_path)
        return local_path

    except Exception as error:
        logger.warning(
            _("Failed to get database path from config: %s, using local fallback"),
            error,
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

        # Get the database path from the global database manager
        # This will be used by alembic's env.py
        from .base import (  # pylint: disable=import-outside-toplevel
            get_database_manager as get_db_mgr,
        )

        db_mgr = get_db_mgr()
        db_path = db_mgr.database_path

        # Run alembic command using the currently running Python interpreter
        # This ensures we use the same Python that's running this code
        # (which will be the venv Python if run from a venv)
        # Special case: if running as Windows service (pythonservice.exe),
        # use the venv's python.exe instead
        python_exe = sys.executable
        if python_exe.endswith("pythonservice.exe"):
            # Running as Windows service - find the venv's python.exe
            venv_python = os.path.join(agent_dir, ".venv", "Scripts", "python.exe")
            if os.path.exists(venv_python):
                python_exe = venv_python
                logger.debug("Using venv Python for alembic: %s", python_exe)
            else:
                logger.warning("Venv Python not found, using system Python")
                # Fall back to system Python
                python_exe = sys.exec_prefix + "\\python.exe"

        cmd = [python_exe, "-m", "alembic", operation, revision]
        logger.info(_("Running alembic command: %s"), " ".join(cmd))

        # Set environment variable for alembic to find the database
        env = os.environ.copy()
        env["SYSMANAGE_DB_PATH"] = db_path

        result = subprocess.run(  # nosec B603, B607
            cmd,
            cwd=agent_dir,
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
            env=env,
        )

        if result.returncode == 0:
            logger.info(_("Alembic %s completed successfully"), operation)
            if result.stdout:
                logger.debug("Alembic output: %s", result.stdout)
            return True

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
    except Exception as error:
        logger.error(_("Failed to run alembic %s: %s"), operation, error)
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
        get_database_manager(db_path)  # Initialize global database manager

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

    except Exception as error:
        logger.error(_("Failed to initialize database: %s"), error)
        return False
