"""
Comprehensive unit tests for src.sysmanage_agent.core.agent_utils module.
Tests focus on uncovered code paths to improve coverage beyond 51%.
"""

# pylint: disable=protected-access,attribute-defined-outside-init

import asyncio
import ssl
import subprocess
from unittest.mock import AsyncMock, MagicMock, Mock, patch

import pytest

from src.sysmanage_agent.core.agent_utils import (
    AuthenticationHelper,
    MessageProcessor,
    PackageCollectionScheduler,
    _check_sudoers_privileges,
    _parse_sudoers_content,
    _parse_sudoers_line,
    _read_sudoers_file,
    _test_sudo_access,
    is_running_privileged,
)


class TestPackageCollectionScheduler:
    """Test cases for PackageCollectionScheduler class."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_agent = Mock()
        self.mock_agent.running = True
        self.mock_agent.config.is_package_collection_enabled.return_value = True
        self.mock_agent.config.is_package_collection_at_startup_enabled.return_value = (
            False
        )
        self.mock_agent.config.get_package_collection_interval.return_value = 3600

        self.mock_logger = Mock()

        with patch(
            "src.sysmanage_agent.core.agent_utils.PackageCollector"
        ) as mock_collector_class:
            self.mock_collector = Mock()
            mock_collector_class.return_value = self.mock_collector
            self.scheduler = PackageCollectionScheduler(
                self.mock_agent, self.mock_logger
            )

    @pytest.mark.asyncio
    async def test_perform_package_collection_disabled(self):
        """Test package collection when disabled in config."""
        self.mock_agent.config.is_package_collection_enabled.return_value = False

        result = await self.scheduler.perform_package_collection()

        assert result is False
        self.mock_logger.debug.assert_called()

    @pytest.mark.asyncio
    async def test_perform_package_collection_success(self):
        """Test successful package collection."""
        self.mock_collector.collect_all_available_packages.return_value = True

        with patch("asyncio.get_event_loop") as mock_loop:
            mock_loop.return_value.run_in_executor = AsyncMock(return_value=True)

            result = await self.scheduler.perform_package_collection()

            assert result is True
            self.mock_logger.info.assert_called()

    @pytest.mark.asyncio
    async def test_perform_package_collection_partial_failure(self):
        """Test package collection with partial failure (returns False but no exception)."""
        with patch("asyncio.get_event_loop") as mock_loop:
            mock_loop.return_value.run_in_executor = AsyncMock(return_value=False)

            result = await self.scheduler.perform_package_collection()

            assert result is False
            self.mock_logger.warning.assert_called()

    @pytest.mark.asyncio
    async def test_perform_package_collection_exception(self):
        """Test package collection with exception."""
        with patch("asyncio.get_event_loop") as mock_loop:
            mock_loop.return_value.run_in_executor = AsyncMock(
                side_effect=Exception("Collection failed")
            )

            result = await self.scheduler.perform_package_collection()

            assert result is False
            self.mock_logger.error.assert_called()

    @pytest.mark.asyncio
    async def test_run_package_collection_loop_disabled(self):
        """Test package collection loop when disabled."""
        self.mock_agent.config.is_package_collection_enabled.return_value = False

        await self.scheduler.run_package_collection_loop()

        self.mock_logger.info.assert_called_with(
            "Package collection is disabled - scheduler will not run"
        )

    @pytest.mark.asyncio
    async def test_run_package_collection_loop_with_startup_collection(self):
        """Test package collection loop with startup collection enabled."""
        self.mock_agent.config.is_package_collection_at_startup_enabled.return_value = (
            True
        )
        call_count = 0

        async def mock_sleep(duration):
            _ = duration
            nonlocal call_count
            call_count += 1
            self.mock_agent.running = False

        with patch("asyncio.sleep", side_effect=mock_sleep):
            with patch("asyncio.get_event_loop") as mock_loop:
                mock_loop.return_value.time.return_value = 0
                mock_loop.return_value.run_in_executor = AsyncMock(return_value=True)

                with patch.object(
                    self.scheduler, "perform_package_collection"
                ) as mock_collect:
                    mock_collect.return_value = True

                    await self.scheduler.run_package_collection_loop()

                    # Should call at startup
                    assert mock_collect.call_count >= 1
                    self.mock_logger.info.assert_any_call(
                        "Running initial package collection at startup"
                    )

    @pytest.mark.asyncio
    async def test_run_package_collection_loop_cancelled(self):
        """Test package collection loop cancellation."""
        with patch("asyncio.sleep", side_effect=asyncio.CancelledError()):
            with patch("asyncio.get_event_loop") as mock_loop:
                mock_loop.return_value.time.return_value = 0

                with pytest.raises(asyncio.CancelledError):
                    await self.scheduler.run_package_collection_loop()

                self.mock_logger.debug.assert_called_with(
                    "Package collection scheduler cancelled"
                )

    @pytest.mark.asyncio
    async def test_run_package_collection_loop_exception_recovery(self):
        """Test package collection loop continues after exception."""
        call_count = 0

        async def mock_sleep(duration):
            _ = duration
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise RuntimeError("Random error")
            self.mock_agent.running = False

        with patch("asyncio.sleep", side_effect=mock_sleep):
            with patch("asyncio.get_event_loop") as mock_loop:
                mock_loop.return_value.time.return_value = 0

                await self.scheduler.run_package_collection_loop()

        assert call_count >= 2
        self.mock_logger.error.assert_called()

    @pytest.mark.asyncio
    async def test_run_package_collection_loop_interval_triggered(self):
        """Test package collection triggers when interval passes."""
        call_count = 0
        time_values = [0, 0, 4000]  # Start, check, past interval

        def time_side_effect():
            return time_values[min(call_count, len(time_values) - 1)]

        async def mock_sleep(duration):
            _ = duration
            nonlocal call_count
            call_count += 1
            if call_count >= 2:
                self.mock_agent.running = False

        with patch("asyncio.sleep", side_effect=mock_sleep):
            with patch("asyncio.get_event_loop") as mock_loop:
                mock_loop.return_value.time.side_effect = time_side_effect
                mock_loop.return_value.run_in_executor = AsyncMock(return_value=True)

                with patch.object(
                    self.scheduler, "perform_package_collection"
                ) as mock_collect:
                    mock_collect.return_value = True

                    await self.scheduler.run_package_collection_loop()

    @pytest.mark.asyncio
    async def test_run_package_collection_loop_interval_collection_executes(self):
        """Test that collection actually executes when interval is reached (covers lines 160-161)."""
        collection_calls = []
        time_call_count = [0]

        async def mock_perform_collection():
            collection_calls.append(1)
            return True

        def time_side_effect():
            time_call_count[0] += 1
            # First call: initialization (last_collection_time = 0)
            # Second call: in loop (current_time = 0, won't trigger)
            # Third call: in loop (current_time = 4000, will trigger - past 3600 interval)
            if time_call_count[0] <= 2:
                return 0
            return 4000

        sleep_call_count = [0]

        async def mock_sleep(duration):
            _ = duration
            sleep_call_count[0] += 1
            if sleep_call_count[0] >= 2:
                self.mock_agent.running = False

        self.scheduler.perform_package_collection = mock_perform_collection

        with patch("asyncio.sleep", side_effect=mock_sleep):
            with patch("asyncio.get_event_loop") as mock_loop:
                mock_loop.return_value.time.side_effect = time_side_effect

                await self.scheduler.run_package_collection_loop()

        # Verify collection was called when interval passed
        assert len(collection_calls) >= 1


class TestAuthenticationHelperGetAuthToken:
    """Test cases for AuthenticationHelper.get_auth_token method."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_agent = Mock()
        self.mock_agent.config.get_server_config.return_value = {
            "hostname": "test-server",
            "port": 8080,
            "use_https": False,
        }
        self.mock_agent.config.should_verify_ssl.return_value = True

        self.mock_logger = Mock()
        self.auth_helper = AuthenticationHelper(self.mock_agent, self.mock_logger)

    def _create_mock_session(self, mock_response):
        """Helper to create a properly mocked aiohttp ClientSession."""
        # Create the response context manager
        mock_response_ctx = MagicMock()
        mock_response_ctx.__aenter__ = AsyncMock(return_value=mock_response)
        mock_response_ctx.__aexit__ = AsyncMock(return_value=None)

        # Create the session with post method
        mock_session = MagicMock()
        mock_session.post = MagicMock(return_value=mock_response_ctx)

        # Create the session context manager
        mock_session_ctx = MagicMock()
        mock_session_ctx.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session_ctx.__aexit__ = AsyncMock(return_value=None)

        return mock_session_ctx

    @pytest.mark.asyncio
    async def test_get_auth_token_success_http(self):
        """Test successful auth token retrieval via HTTP."""
        mock_response = MagicMock()
        mock_response.status = 200
        mock_response.json = AsyncMock(return_value={"connection_token": "test-token"})

        mock_session_ctx = self._create_mock_session(mock_response)

        with patch("aiohttp.TCPConnector"):
            with patch("aiohttp.ClientSession", return_value=mock_session_ctx):
                with patch("socket.gethostname", return_value="test-host"):
                    result = await self.auth_helper.get_auth_token()

                    assert result == "test-token"

    @pytest.mark.asyncio
    async def test_get_auth_token_success_https_verified(self):
        """Test successful auth token retrieval via HTTPS with SSL verification."""
        self.mock_agent.config.get_server_config.return_value = {
            "hostname": "secure-server",
            "port": 8443,
            "use_https": True,
        }
        self.mock_agent.config.should_verify_ssl.return_value = True

        mock_response = MagicMock()
        mock_response.status = 200
        mock_response.json = AsyncMock(
            return_value={"connection_token": "secure-token"}
        )

        mock_session_ctx = self._create_mock_session(mock_response)

        with patch("aiohttp.TCPConnector"):
            with patch("aiohttp.ClientSession", return_value=mock_session_ctx):
                with patch("socket.gethostname", return_value="test-host"):
                    with patch("ssl.create_default_context") as mock_ssl_ctx:
                        mock_ctx = Mock()
                        mock_ssl_ctx.return_value = mock_ctx

                        result = await self.auth_helper.get_auth_token()

                        assert result == "secure-token"
                        mock_ssl_ctx.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_auth_token_success_https_no_verify(self):
        """Test auth token retrieval via HTTPS without SSL verification."""
        self.mock_agent.config.get_server_config.return_value = {
            "hostname": "secure-server",
            "port": 8443,
            "use_https": True,
        }
        self.mock_agent.config.should_verify_ssl.return_value = False

        mock_response = MagicMock()
        mock_response.status = 200
        mock_response.json = AsyncMock(
            return_value={"connection_token": "insecure-token"}
        )

        mock_session_ctx = self._create_mock_session(mock_response)

        with patch("aiohttp.TCPConnector"):
            with patch("aiohttp.ClientSession", return_value=mock_session_ctx):
                with patch("socket.gethostname", return_value="test-host"):
                    with patch("ssl.create_default_context") as mock_ssl_ctx:
                        mock_ctx = Mock()
                        mock_ssl_ctx.return_value = mock_ctx

                        result = await self.auth_helper.get_auth_token()

                        assert result == "insecure-token"
                        # Verify SSL was configured with no verification
                        assert mock_ctx.check_hostname is False
                        assert mock_ctx.verify_mode == ssl.CERT_NONE

    @pytest.mark.asyncio
    async def test_get_auth_token_failure(self):
        """Test auth token retrieval failure."""
        mock_response = MagicMock()
        mock_response.status = 401
        mock_response.text = AsyncMock(return_value="Unauthorized")

        mock_session_ctx = self._create_mock_session(mock_response)

        with patch("aiohttp.TCPConnector"):
            with patch("aiohttp.ClientSession", return_value=mock_session_ctx):
                with patch("socket.gethostname", return_value="test-host"):
                    with pytest.raises(ConnectionError) as exc_info:
                        await self.auth_helper.get_auth_token()

                    assert "401" in str(exc_info.value)
                    assert "Unauthorized" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_get_auth_token_empty_token(self):
        """Test auth token retrieval with empty token in response."""
        mock_response = MagicMock()
        mock_response.status = 200
        mock_response.json = AsyncMock(return_value={})  # No connection_token

        mock_session_ctx = self._create_mock_session(mock_response)

        with patch("aiohttp.TCPConnector"):
            with patch("aiohttp.ClientSession", return_value=mock_session_ctx):
                with patch("socket.gethostname", return_value="test-host"):
                    result = await self.auth_helper.get_auth_token()

                    assert result == ""


class TestMessageProcessorServiceControl:
    """Test cases for MessageProcessor service control methods."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_agent = Mock()
        self.mock_agent.collect_roles = AsyncMock()

        self.mock_logger = Mock()
        self.processor = MessageProcessor(self.mock_agent, self.mock_logger)

    @pytest.mark.asyncio
    async def test_handle_service_control_invalid_action(self):
        """Test service control with invalid action."""
        parameters = {"action": "invalid_action", "services": ["nginx"]}

        result = await self.processor._handle_service_control(parameters)

        assert result["success"] is False
        assert "Invalid or missing action" in result["error"]

    @pytest.mark.asyncio
    async def test_handle_service_control_missing_action(self):
        """Test service control with missing action."""
        parameters = {"services": ["nginx"]}

        result = await self.processor._handle_service_control(parameters)

        assert result["success"] is False
        assert "Invalid or missing action" in result["error"]

    @pytest.mark.asyncio
    async def test_handle_service_control_no_services(self):
        """Test service control with no services specified."""
        parameters = {"action": "start", "services": []}

        result = await self.processor._handle_service_control(parameters)

        assert result["success"] is False
        assert "No services specified" in result["error"]

    @pytest.mark.asyncio
    async def test_handle_service_control_not_privileged(self):
        """Test service control when not running privileged."""
        parameters = {"action": "start", "services": ["nginx"]}

        with patch(
            "src.sysmanage_agent.core.agent_utils.is_running_privileged",
            return_value=False,
        ):
            result = await self.processor._handle_service_control(parameters)

            assert result["success"] is False
            assert "requires privileged mode" in result["error"]

    @pytest.mark.asyncio
    async def test_handle_service_control_start_success(self):
        """Test successful service start."""
        parameters = {"action": "start", "services": ["nginx", "apache2"]}

        with patch(
            "src.sysmanage_agent.core.agent_utils.is_running_privileged",
            return_value=True,
        ):
            with patch.object(
                self.processor, "_process_service_control_action"
            ) as mock_process:
                mock_process.return_value = {"success": True, "message": "Started"}

                result = await self.processor._handle_service_control(parameters)

                assert result["success"] is True
                assert result["action"] == "start"
                assert len(result["services"]) == 2
                assert mock_process.call_count == 2
                self.mock_agent.collect_roles.assert_called_once()

    @pytest.mark.asyncio
    async def test_handle_service_control_partial_failure(self):
        """Test service control with partial failure."""
        parameters = {"action": "restart", "services": ["nginx", "apache2"]}

        async def mock_service_action(_action, service):
            if service == "nginx":
                return {"success": True, "message": "Restarted"}
            return {"success": False, "error": "Service not found"}

        with patch(
            "src.sysmanage_agent.core.agent_utils.is_running_privileged",
            return_value=True,
        ):
            with patch.object(
                self.processor,
                "_process_service_control_action",
                side_effect=mock_service_action,
            ):
                result = await self.processor._handle_service_control(parameters)

                assert result["success"] is False  # Overall failure
                assert result["results"]["nginx"]["success"] is True
                assert result["results"]["apache2"]["success"] is False

    @pytest.mark.asyncio
    async def test_handle_service_control_exception(self):
        """Test service control with exception."""
        parameters = {"action": "stop", "services": ["nginx"]}

        with patch(
            "src.sysmanage_agent.core.agent_utils.is_running_privileged",
            side_effect=Exception("Unexpected error"),
        ):
            result = await self.processor._handle_service_control(parameters)

            assert result["success"] is False
            assert "Unexpected error" in result["error"]

    @pytest.mark.asyncio
    async def test_process_service_control_action_success(self):
        """Test successful service control action."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = ""
        mock_result.stderr = ""

        with patch("shutil.which", return_value="/usr/bin/systemctl"):
            with patch(
                "src.sysmanage_agent.core.agent_utils.run_command_async",
                return_value=mock_result,
            ):
                result = await self.processor._process_service_control_action(
                    "start", "nginx"
                )

                assert result["success"] is True
                assert "successful" in result["message"]

    @pytest.mark.asyncio
    async def test_process_service_control_action_no_systemctl(self):
        """Test service control action when systemctl not found."""
        with patch("shutil.which", return_value=None):
            result = await self.processor._process_service_control_action(
                "start", "nginx"
            )

            assert result["success"] is False
            assert "systemctl not found" in result["error"]

    @pytest.mark.asyncio
    async def test_process_service_control_action_failure(self):
        """Test service control action failure."""
        mock_result = Mock()
        mock_result.returncode = 1
        mock_result.stdout = ""
        mock_result.stderr = "Failed to start service"

        with patch("shutil.which", return_value="/usr/bin/systemctl"):
            with patch(
                "src.sysmanage_agent.core.agent_utils.run_command_async",
                return_value=mock_result,
            ):
                result = await self.processor._process_service_control_action(
                    "start", "nginx"
                )

                assert result["success"] is False
                assert "Failed to start service" in result["error"]

    @pytest.mark.asyncio
    async def test_process_service_control_action_timeout(self):
        """Test service control action timeout."""
        with patch("shutil.which", return_value="/usr/bin/systemctl"):
            with patch(
                "src.sysmanage_agent.core.agent_utils.run_command_async",
                side_effect=asyncio.TimeoutError(),
            ):
                result = await self.processor._process_service_control_action(
                    "restart", "nginx"
                )

                assert result["success"] is False
                assert "timed out" in result["error"]

    @pytest.mark.asyncio
    async def test_process_service_control_action_exception(self):
        """Test service control action with exception."""
        with patch("shutil.which", return_value="/usr/bin/systemctl"):
            with patch(
                "src.sysmanage_agent.core.agent_utils.run_command_async",
                side_effect=Exception("Command execution failed"),
            ):
                result = await self.processor._process_service_control_action(
                    "stop", "nginx"
                )

                assert result["success"] is False
                assert "Command execution failed" in result["error"]

    @pytest.mark.asyncio
    async def test_collect_roles_after_service_change_success(self):
        """Test role collection after service change."""
        await self.processor._collect_roles_after_service_change()

        self.mock_agent.collect_roles.assert_called_once()
        self.mock_logger.info.assert_called()

    @pytest.mark.asyncio
    async def test_collect_roles_after_service_change_failure(self):
        """Test role collection after service change with failure."""
        self.mock_agent.collect_roles.side_effect = Exception("Role collection failed")

        await self.processor._collect_roles_after_service_change()

        self.mock_logger.warning.assert_called()


class TestMessageProcessorServiceStatus:
    """Test cases for MessageProcessor service status methods."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_agent = Mock()
        self.mock_logger = Mock()
        self.processor = MessageProcessor(self.mock_agent, self.mock_logger)

    @pytest.mark.asyncio
    async def test_handle_get_service_status_no_services(self):
        """Test service status check with no services."""
        parameters = {"services": []}

        result = await self.processor._handle_get_service_status(parameters)

        assert result["success"] is False
        assert "No services specified" in result["error"]

    @pytest.mark.asyncio
    async def test_handle_get_service_status_not_privileged(self):
        """Test service status check when not privileged."""
        parameters = {"services": ["nginx"]}

        with patch(
            "src.sysmanage_agent.core.agent_utils.is_running_privileged",
            return_value=False,
        ):
            result = await self.processor._handle_get_service_status(parameters)

            assert result["success"] is False
            assert "requires privileged mode" in result["error"]

    @pytest.mark.asyncio
    async def test_handle_get_service_status_success(self):
        """Test successful service status check."""
        parameters = {"services": ["nginx", "apache2"]}

        with patch(
            "src.sysmanage_agent.core.agent_utils.is_running_privileged",
            return_value=True,
        ):
            with patch.object(
                self.processor, "_detect_single_service_status"
            ) as mock_detect:
                mock_detect.return_value = {
                    "success": True,
                    "status": "active",
                    "active": True,
                }

                result = await self.processor._handle_get_service_status(parameters)

                assert result["success"] is True
                assert len(result["services"]) == 2
                assert mock_detect.call_count == 2

    @pytest.mark.asyncio
    async def test_handle_get_service_status_partial_failure(self):
        """Test service status check with partial failure."""
        parameters = {"services": ["nginx", "nonexistent"]}

        async def mock_status(service):
            if service == "nginx":
                return {"success": True, "status": "active", "active": True}
            return {"success": False, "status": "unknown", "error": "Not found"}

        with patch(
            "src.sysmanage_agent.core.agent_utils.is_running_privileged",
            return_value=True,
        ):
            with patch.object(
                self.processor, "_detect_single_service_status", side_effect=mock_status
            ):
                result = await self.processor._handle_get_service_status(parameters)

                assert result["success"] is False
                assert result["results"]["nginx"]["success"] is True
                assert result["results"]["nonexistent"]["success"] is False

    @pytest.mark.asyncio
    async def test_handle_get_service_status_exception(self):
        """Test service status check with exception."""
        parameters = {"services": ["nginx"]}

        with patch(
            "src.sysmanage_agent.core.agent_utils.is_running_privileged",
            side_effect=Exception("Unexpected error"),
        ):
            result = await self.processor._handle_get_service_status(parameters)

            assert result["success"] is False
            assert "Unexpected error" in result["error"]

    @pytest.mark.asyncio
    async def test_detect_single_service_status_active(self):
        """Test detecting active service status."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "active"
        mock_result.stderr = ""

        with patch("shutil.which", return_value="/usr/bin/systemctl"):
            with patch(
                "src.sysmanage_agent.core.agent_utils.run_command_async",
                return_value=mock_result,
            ):
                result = await self.processor._detect_single_service_status("nginx")

                assert result["success"] is True
                assert result["status"] == "active"
                assert result["active"] is True

    @pytest.mark.asyncio
    async def test_detect_single_service_status_inactive(self):
        """Test detecting inactive service status."""
        mock_result = Mock()
        mock_result.returncode = 3
        mock_result.stdout = "inactive"
        mock_result.stderr = ""

        with patch("shutil.which", return_value="/usr/bin/systemctl"):
            with patch(
                "src.sysmanage_agent.core.agent_utils.run_command_async",
                return_value=mock_result,
            ):
                result = await self.processor._detect_single_service_status("nginx")

                assert result["success"] is True
                assert result["status"] == "inactive"
                assert result["active"] is False

    @pytest.mark.asyncio
    async def test_detect_single_service_status_no_systemctl(self):
        """Test service status detection when systemctl not found."""
        with patch("shutil.which", return_value=None):
            result = await self.processor._detect_single_service_status("nginx")

            assert result["success"] is False
            assert result["status"] == "unknown"
            assert "systemctl not found" in result["error"]

    @pytest.mark.asyncio
    async def test_detect_single_service_status_timeout(self):
        """Test service status detection timeout."""
        with patch("shutil.which", return_value="/usr/bin/systemctl"):
            with patch(
                "src.sysmanage_agent.core.agent_utils.run_command_async",
                side_effect=asyncio.TimeoutError(),
            ):
                result = await self.processor._detect_single_service_status("nginx")

                assert result["success"] is False
                assert result["status"] == "unknown"
                assert "timed out" in result["error"]

    @pytest.mark.asyncio
    async def test_detect_single_service_status_exception(self):
        """Test service status detection with exception."""
        with patch("shutil.which", return_value="/usr/bin/systemctl"):
            with patch(
                "src.sysmanage_agent.core.agent_utils.run_command_async",
                side_effect=Exception("Command failed"),
            ):
                result = await self.processor._detect_single_service_status("nginx")

                assert result["success"] is False
                assert result["status"] == "unknown"
                assert "Command failed" in result["error"]


class TestPrivilegeDetectionAdvanced:
    """Advanced test cases for privilege detection functions."""

    @patch("sys.platform", "linux")
    def test_is_running_privileged_sysmanage_agent_user_with_sudoers(self):
        """Test privilege detection for sysmanage-agent user with sudoers."""
        mock_pwuid = Mock()
        mock_pwuid.pw_name = "sysmanage-agent"

        with patch("os.geteuid", return_value=1001):
            with patch("pwd.getpwuid", return_value=mock_pwuid):
                with patch(
                    "src.sysmanage_agent.core.agent_utils._check_sudoers_privileges",
                    return_value=True,
                ):
                    result = is_running_privileged()
                    assert result is True

    @patch("sys.platform", "linux")
    def test_is_running_privileged_sysmanage_agent_user_without_sudoers(self):
        """Test privilege detection for sysmanage-agent user without sudoers."""
        mock_pwuid = Mock()
        mock_pwuid.pw_name = "sysmanage-agent"

        with patch("os.geteuid", return_value=1001):
            with patch("pwd.getpwuid", return_value=mock_pwuid):
                with patch(
                    "src.sysmanage_agent.core.agent_utils._check_sudoers_privileges",
                    return_value=False,
                ):
                    result = is_running_privileged()
                    assert result is False

    @patch("sys.platform", "linux")
    def test_is_running_privileged_other_user(self):
        """Test privilege detection for other non-root user."""
        mock_pwuid = Mock()
        mock_pwuid.pw_name = "regular-user"

        with patch("os.geteuid", return_value=1000):
            with patch("pwd.getpwuid", return_value=mock_pwuid):
                result = is_running_privileged()
                assert result is False

    @patch("sys.platform", "linux")
    def test_is_running_privileged_pwd_exception(self):
        """Test privilege detection when pwd lookup fails."""
        with patch("os.geteuid", return_value=1001):
            with patch("pwd.getpwuid", side_effect=KeyError("No such user")):
                result = is_running_privileged()
                assert result is False


class TestSudoersPrivilegeChecking:
    """Test cases for sudoers privilege checking functions."""

    def test_check_sudoers_privileges_with_valid_file(self):
        """Test sudoers privilege checking with valid file content."""
        sudoers_content = (
            "sysmanage-agent ALL=(ALL) NOPASSWD: /usr/bin/systemctl, /usr/bin/apt"
        )

        with patch(
            "src.sysmanage_agent.core.agent_utils._read_sudoers_file",
            return_value=sudoers_content,
        ):
            with patch(
                "src.sysmanage_agent.core.agent_utils._parse_sudoers_content"
            ) as mock_parse:
                mock_parse.return_value = {"systemctl", "apt"}

                result = _check_sudoers_privileges("sysmanage-agent")

                assert result is True
                mock_parse.assert_called_once_with(sudoers_content, "sysmanage-agent")

    def test_check_sudoers_privileges_missing_systemctl(self):
        """Test sudoers privilege checking when systemctl is missing."""
        sudoers_content = "sysmanage-agent ALL=(ALL) NOPASSWD: /usr/bin/apt"

        with patch(
            "src.sysmanage_agent.core.agent_utils._read_sudoers_file",
            return_value=sudoers_content,
        ):
            with patch(
                "src.sysmanage_agent.core.agent_utils._parse_sudoers_content"
            ) as mock_parse:
                mock_parse.return_value = {"apt"}

                result = _check_sudoers_privileges("sysmanage-agent")

                assert result is False

    def test_check_sudoers_privileges_missing_package_mgmt(self):
        """Test sudoers privilege checking when package manager is missing."""
        sudoers_content = "sysmanage-agent ALL=(ALL) NOPASSWD: /usr/bin/systemctl"

        with patch(
            "src.sysmanage_agent.core.agent_utils._read_sudoers_file",
            return_value=sudoers_content,
        ):
            with patch(
                "src.sysmanage_agent.core.agent_utils._parse_sudoers_content"
            ) as mock_parse:
                mock_parse.return_value = {"systemctl"}

                result = _check_sudoers_privileges("sysmanage-agent")

                assert result is False

    def test_check_sudoers_privileges_file_not_readable(self):
        """Test sudoers privilege checking when file is not readable."""
        with patch(
            "src.sysmanage_agent.core.agent_utils._read_sudoers_file",
            return_value=None,
        ):
            with patch(
                "src.sysmanage_agent.core.agent_utils._test_sudo_access",
                return_value=True,
            ):
                result = _check_sudoers_privileges("sysmanage-agent")

                assert result is True

    def test_check_sudoers_privileges_exception(self):
        """Test sudoers privilege checking with exception."""
        with patch(
            "src.sysmanage_agent.core.agent_utils._read_sudoers_file",
            side_effect=Exception("File error"),
        ):
            result = _check_sudoers_privileges("sysmanage-agent")

            assert result is False

    def test_check_sudoers_privileges_with_yum(self):
        """Test sudoers privilege checking with yum package manager."""
        sudoers_content = (
            "sysmanage-agent ALL=(ALL) NOPASSWD: /usr/bin/systemctl, /usr/bin/yum"
        )

        with patch(
            "src.sysmanage_agent.core.agent_utils._read_sudoers_file",
            return_value=sudoers_content,
        ):
            with patch(
                "src.sysmanage_agent.core.agent_utils._parse_sudoers_content"
            ) as mock_parse:
                mock_parse.return_value = {"systemctl", "yum"}

                result = _check_sudoers_privileges("sysmanage-agent")

                assert result is True

    def test_check_sudoers_privileges_with_dnf(self):
        """Test sudoers privilege checking with dnf package manager."""
        sudoers_content = (
            "sysmanage-agent ALL=(ALL) NOPASSWD: /usr/bin/systemctl, /usr/bin/dnf"
        )

        with patch(
            "src.sysmanage_agent.core.agent_utils._read_sudoers_file",
            return_value=sudoers_content,
        ):
            with patch(
                "src.sysmanage_agent.core.agent_utils._parse_sudoers_content"
            ) as mock_parse:
                mock_parse.return_value = {"systemctl", "dnf"}

                result = _check_sudoers_privileges("sysmanage-agent")

                assert result is True


class TestReadSudoersFile:
    """Test cases for _read_sudoers_file function."""

    def test_read_sudoers_file_success(self):
        """Test successful reading of sudoers file."""
        expected_content = "sysmanage-agent ALL=(ALL) NOPASSWD: /usr/bin/systemctl"

        with patch(
            "builtins.open",
            MagicMock(
                return_value=MagicMock(
                    __enter__=MagicMock(
                        return_value=MagicMock(
                            read=MagicMock(return_value=expected_content)
                        )
                    ),
                    __exit__=MagicMock(),
                )
            ),
        ):
            result = _read_sudoers_file("/etc/sudoers.d/sysmanage-agent")

            assert result == expected_content

    def test_read_sudoers_file_permission_error(self):
        """Test reading sudoers file with permission denied."""
        with patch("builtins.open", side_effect=PermissionError("Access denied")):
            result = _read_sudoers_file("/etc/sudoers.d/sysmanage-agent")

            assert result is None


class TestParseSudoersContent:
    """Test cases for _parse_sudoers_content function."""

    def test_parse_sudoers_content_full_privileges(self):
        """Test parsing sudoers content with full privileges."""
        content = """# Sudoers file for sysmanage-agent
sysmanage-agent ALL=(ALL) NOPASSWD: /usr/bin/systemctl *
sysmanage-agent ALL=(ALL) NOPASSWD: /usr/bin/apt *
"""
        result = _parse_sudoers_content(content, "sysmanage-agent")

        assert "systemctl" in result
        assert "apt" in result

    def test_parse_sudoers_content_empty(self):
        """Test parsing empty sudoers content."""
        content = ""
        result = _parse_sudoers_content(content, "sysmanage-agent")

        assert result == set()

    def test_parse_sudoers_content_comments_only(self):
        """Test parsing sudoers content with only comments."""
        content = """# This is a comment
# Another comment
"""
        result = _parse_sudoers_content(content, "sysmanage-agent")

        assert result == set()


class TestParseSudoersLine:
    """Test cases for _parse_sudoers_line function."""

    def test_parse_sudoers_line_empty(self):
        """Test parsing empty line."""
        result = _parse_sudoers_line("", "user", ["systemctl", "apt"])
        assert result == set()

    def test_parse_sudoers_line_comment(self):
        """Test parsing comment line."""
        result = _parse_sudoers_line(
            "# This is a comment", "user", ["systemctl", "apt"]
        )
        assert result == set()

    def test_parse_sudoers_line_no_nopasswd(self):
        """Test parsing line without NOPASSWD."""
        result = _parse_sudoers_line(
            "user ALL=(ALL) /usr/bin/systemctl", "user", ["systemctl", "apt"]
        )
        assert result == set()

    def test_parse_sudoers_line_different_user(self):
        """Test parsing line for different user."""
        result = _parse_sudoers_line(
            "other ALL=(ALL) NOPASSWD: /usr/bin/systemctl", "user", ["systemctl", "apt"]
        )
        assert result == set()

    def test_parse_sudoers_line_matching_commands(self):
        """Test parsing line with matching commands."""
        result = _parse_sudoers_line(
            "sysmanage-agent ALL=(ALL) NOPASSWD: /usr/bin/systemctl, /usr/bin/apt",
            "sysmanage-agent",
            ["systemctl", "apt"],
        )
        assert "systemctl" in result
        assert "apt" in result

    def test_parse_sudoers_line_partial_match(self):
        """Test parsing line with partial command match."""
        result = _parse_sudoers_line(
            "sysmanage-agent ALL=(ALL) NOPASSWD: /usr/bin/systemctl",
            "sysmanage-agent",
            ["systemctl", "apt"],
        )
        assert "systemctl" in result
        assert "apt" not in result

    def test_parse_sudoers_line_nopasswd_at_end_no_commands(self):
        """Test parsing line where NOPASSWD is at end with nothing after it."""
        # This covers line 907: when split produces only 1 part after NOPASSWD:
        result = _parse_sudoers_line(
            "sysmanage-agent ALL=(ALL) NOPASSWD:",
            "sysmanage-agent",
            ["systemctl", "apt"],
        )
        assert result == set()


class TestTestSudoAccess:
    """Test cases for _test_sudo_access function."""

    def test_test_sudo_access_success(self):
        """Test sudo access when command succeeds."""
        mock_result = Mock()
        mock_result.returncode = 0

        with patch("subprocess.run", return_value=mock_result):
            result = _test_sudo_access()
            assert result is True

    def test_test_sudo_access_service_inactive(self):
        """Test sudo access when service is inactive (exit code 3)."""
        mock_result = Mock()
        mock_result.returncode = 3  # Service inactive is fine

        with patch("subprocess.run", return_value=mock_result):
            result = _test_sudo_access()
            assert result is True

    def test_test_sudo_access_auth_failed(self):
        """Test sudo access when authentication fails (exit code 255)."""
        mock_result = Mock()
        mock_result.returncode = 255  # sudo auth failed

        with patch("subprocess.run", return_value=mock_result):
            result = _test_sudo_access()
            assert result is False

    def test_test_sudo_access_exception(self):
        """Test sudo access when subprocess raises exception."""
        with patch("subprocess.run", side_effect=Exception("Command not found")):
            result = _test_sudo_access()
            assert result is False

    def test_test_sudo_access_timeout(self):
        """Test sudo access when command times out."""
        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired("sudo", 5)):
            result = _test_sudo_access()
            assert result is False
