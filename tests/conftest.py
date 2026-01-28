"""
Pytest configuration and shared fixtures for SysManage agent tests.
Provides isolated test database and mocking infrastructure.
"""

import asyncio
import gc
import glob
import os
import sys
import tempfile
import uuid
from unittest.mock import AsyncMock, MagicMock, Mock, patch

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

# Mock the aiohttp module if not available
if "aiohttp" not in sys.modules:
    sys.modules["aiohttp"] = MagicMock()
    sys.modules["aiohttp.ClientSession"] = MagicMock()
    sys.modules["aiohttp.ClientError"] = Exception

# pylint: disable=wrong-import-position,wildcard-import,unused-wildcard-import
# Import after mocking to avoid import errors
from main import SysManageAgent
from src.database.base import Base, DatabaseManager
from src.database.models import *


@pytest.fixture(scope="function")
def test_db_path():
    """Create a unique test database path for each test."""
    test_db_fd, test_db_file = tempfile.mkstemp(
        suffix=f"_test_{uuid.uuid4().hex}.db", prefix="sysmanage_agent_"
    )
    os.close(test_db_fd)  # Close the file descriptor, we only need the path

    yield test_db_file

    # Clean up the temporary database file after test
    try:
        if os.path.exists(test_db_file):
            os.unlink(test_db_file)
    except OSError:
        pass


@pytest.fixture(scope="function")
def engine(test_db_path):  # pylint: disable=redefined-outer-name
    """Create test database engine with fresh schema for each test."""
    test_db_url = f"sqlite:///{test_db_path}"

    test_engine = create_engine(
        test_db_url,
        connect_args={"check_same_thread": False},
        echo=False,  # Set to True for SQL debugging
    )

    # Create all tables from models
    Base.metadata.create_all(bind=test_engine)

    yield test_engine

    # Clean up
    test_engine.dispose()


@pytest.fixture(scope="function")
def session(engine):  # pylint: disable=redefined-outer-name
    """Create a test database session with proper isolation."""
    testing_session_local = sessionmaker(autocommit=False, autoflush=False, bind=engine)

    session_instance = testing_session_local()

    try:
        yield session_instance
    finally:
        session_instance.close()


@pytest.fixture(scope="function")
def mock_db_manager(test_db_path):  # pylint: disable=redefined-outer-name
    """Mock database manager that uses test database."""
    with patch("src.database.base.get_database_manager") as mock_get_db_manager:
        # Create a real DatabaseManager instance with test database
        test_db_manager = DatabaseManager(test_db_path)
        test_db_manager.create_tables()

        mock_get_db_manager.return_value = test_db_manager

        yield test_db_manager

        # Clean up
        test_db_manager.close()


@pytest.fixture
def agent_config():
    """Create a test agent configuration."""
    # Create a temporary log file for this test
    with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as temp_log:
        temp_log_path = temp_log.name

    # Convert to forward slashes for YAML compatibility on Windows
    temp_log_path_str = temp_log_path.replace("\\", "/")

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".yaml", delete=False
    ) as config_file:
        config_file.write(f"""
server:
  hostname: "test.example.com"
  port: 8000
  use_https: false
  api_path: "/api"
client:
  registration_retry_interval: 1
  max_registration_retries: 1
logging:
  level: "INFO"
  file: "{temp_log_path_str}"
websocket:
  auto_reconnect: false
  reconnect_interval: 1
  ping_interval: 5
database:
  path: ":memory:"  # Use in-memory database for tests
""")
        temp_config_path = config_file.name

    yield temp_config_path

    # Clean up temporary files
    if os.path.exists(temp_config_path):
        try:
            os.unlink(temp_config_path)
        except PermissionError:
            pass  # File may be locked on Windows
    if os.path.exists(temp_log_path):
        try:
            os.unlink(temp_log_path)
        except PermissionError:
            pass  # File may be locked on Windows


@pytest.fixture
def agent(agent_config, mock_db_manager):  # pylint: disable=redefined-outer-name
    """Create a SysManage agent instance for testing with mocked database."""
    _ = mock_db_manager
    with patch("main.initialize_database", return_value=True):
        agent_instance = SysManageAgent(agent_config)
        yield agent_instance


@pytest.fixture
def mock_websocket():
    """Create a mock WebSocket connection."""
    mock_ws = Mock()
    mock_ws.send = AsyncMock()
    mock_ws.recv = AsyncMock()
    mock_ws.close = AsyncMock()
    return mock_ws


@pytest.fixture
def sample_system_info():
    """Sample system information data."""
    return {
        "hostname": "test.example.com",
        "platform": "Linux",
        "ipv4": "192.168.1.100",
        "ipv6": "2001:db8::1",
        "architecture": "x86_64",
        "memory_total_mb": 16384,
        "cpu_count": 8,
        "disk_total_gb": 512,
    }


@pytest.fixture
def sample_command_message():
    """Sample command message from server."""
    return {
        "message_type": "command",
        "message_id": "cmd-123",
        "timestamp": "2024-01-01T00:00:00.000000",
        "data": {
            "command_type": "execute_shell",
            "parameters": {"command": "echo hello"},
            "timeout": 300,
        },
    }


@pytest.fixture(scope="function")
def event_loop():
    """Create event loop for async tests."""
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


@pytest.fixture
def mock_subprocess():
    """Mock subprocess for command execution tests."""
    mock_process = Mock()
    mock_process.communicate = AsyncMock(return_value=(b"Hello World\n", b""))
    mock_process.returncode = 0
    return mock_process


@pytest.fixture
def mock_package_manager():
    """Mock package manager for testing package operations."""
    mock_pm = Mock()
    mock_pm.list_installed_packages = Mock(
        return_value=[
            {"name": "test-package", "version": "1.0.0", "description": "Test package"}
        ]
    )
    mock_pm.list_available_packages = Mock(
        return_value=[
            {
                "name": "available-package",
                "version": "2.0.0",
                "description": "Available package",
            }
        ]
    )
    mock_pm.update_package_lists = Mock(return_value=True)
    return mock_pm


@pytest.fixture
def mock_os_operations():
    """Mock OS operations for testing system operations."""
    with (
        patch("platform.system", return_value="Linux"),
        patch("platform.release", return_value="5.15.0"),
        patch("platform.machine", return_value="x86_64"),
        patch("platform.node", return_value="test-host"),
    ):
        yield


@pytest.fixture(autouse=True)
def cleanup_temp_files():
    """Automatically clean up any temporary files created during tests."""
    yield

    # Clean up any remaining temporary agent databases
    temp_files = glob.glob("/tmp/sysmanage_agent_test_*.db")
    for temp_file in temp_files:
        try:
            os.unlink(temp_file)
        except OSError:
            pass


# Test isolation helpers
def isolate_database_operations():
    """Context manager to isolate database operations in tests."""
    with patch("src.database.base.get_database_manager") as mock_get_db:
        # Create isolated in-memory database
        test_engine = create_engine(
            "sqlite:///:memory:", connect_args={"check_same_thread": False}
        )
        Base.metadata.create_all(bind=test_engine)

        mock_db_manager = Mock()  # pylint: disable=redefined-outer-name
        mock_db_manager.engine = test_engine
        mock_db_manager.SessionLocal = sessionmaker(bind=test_engine)
        mock_get_db.return_value = mock_db_manager

        yield mock_db_manager


# Legacy compatibility fixtures for existing tests
@pytest.fixture
def agent_legacy():
    """Legacy agent fixture for backward compatibility."""
    # Create a temporary log file for this test
    with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as temp_log:
        temp_log_path = temp_log.name

    # Convert to forward slashes for YAML compatibility on Windows
    temp_log_path_str = temp_log_path.replace("\\", "/")

    # Create a secure temporary file for testing
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".yaml", delete=False
    ) as legacy_config_file:
        legacy_config_file.write(f"""
server:
  hostname: "test.example.com"
  port: 8000
  use_https: false
  api_path: "/api"
client:
  registration_retry_interval: 1
  max_registration_retries: 1
logging:
  level: "INFO"
  file: "{temp_log_path_str}"
websocket:
  auto_reconnect: false
  reconnect_interval: 1
  ping_interval: 5
""")
        temp_config_path = legacy_config_file.name

    try:
        with patch("main.initialize_database", return_value=True):
            agent_instance = SysManageAgent(temp_config_path)
            yield agent_instance
    finally:
        # Clean up temporary files
        if os.path.exists(temp_config_path):
            os.unlink(temp_config_path)
        if os.path.exists(temp_log_path):
            os.unlink(temp_log_path)


# Pytest hooks for better test isolation
def pytest_runtest_setup(item):
    """Setup for each test run."""
    _ = item
    # Ensure no existing database connections interfere
    gc.collect()


def pytest_runtest_teardown(item, nextitem):
    """Teardown after each test run."""
    _ = item
    _ = nextitem
    # Clean up any remaining database connections
    gc.collect()
