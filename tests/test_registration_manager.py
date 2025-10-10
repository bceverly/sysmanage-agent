"""
Comprehensive tests for RegistrationManager functionality.

This test suite covers:
- Agent registration workflows
- Certificate fetching and management
- Host approval handling
- Database operations for host approval records
- Error handling for network failures
- Edge cases and error conditions
"""

# pylint: disable=unused-variable,unused-argument,unused-import

import uuid
from unittest.mock import AsyncMock, MagicMock, Mock, patch

import aiohttp
import pytest

from src.sysmanage_agent.registration.registration_manager import RegistrationManager


class TestRegistrationManagerInitialization:
    """Test RegistrationManager initialization."""

    def test_initialization(self, agent, mock_db_manager):
        """Test that RegistrationManager initializes correctly."""
        _ = mock_db_manager
        reg_manager = RegistrationManager(agent)

        assert reg_manager.agent is agent
        assert reg_manager.logger is agent.logger
        assert reg_manager.config is agent.config


class TestAuthToken:
    """Test authentication token retrieval."""

    @pytest.mark.asyncio
    async def test_get_auth_token_success(self, agent, mock_db_manager):
        """Test successful authentication token retrieval."""
        _ = mock_db_manager
        reg_manager = RegistrationManager(agent)

        # Mock the auth_helper
        agent.auth_helper.get_auth_token = AsyncMock(return_value="test-token-123")

        token = await reg_manager.get_auth_token()
        assert token == "test-token-123"
        agent.auth_helper.get_auth_token.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_auth_token_failure(self, agent, mock_db_manager):
        """Test authentication token retrieval failure."""
        _ = mock_db_manager
        reg_manager = RegistrationManager(agent)

        # Mock auth_helper to raise exception
        agent.auth_helper.get_auth_token = AsyncMock(
            side_effect=Exception("Auth error")
        )

        with pytest.raises(Exception, match="Auth error"):
            await reg_manager.get_auth_token()


class TestFetchCertificates:
    """Test certificate fetching functionality."""

    @pytest.mark.asyncio
    async def test_fetch_certificates_success(self, agent, mock_db_manager):
        """Test successful certificate fetching."""
        _ = mock_db_manager
        reg_manager = RegistrationManager(agent)
        host_id = str(uuid.uuid4())

        # Mock auth token
        reg_manager.get_auth_token = AsyncMock(return_value="test-token")

        # Mock certificate data
        cert_data = {
            "certificate": "-----BEGIN CERTIFICATE-----\nCERT_DATA\n-----END CERTIFICATE-----",
            "private_key": "-----BEGIN PRIVATE KEY-----\nKEY_DATA\n-----END PRIVATE KEY-----",
            "ca_certificate": "-----BEGIN CERTIFICATE-----\nCA_DATA\n-----END CERTIFICATE-----",
            "server_fingerprint": "ABC123",
        }

        # Mock aiohttp session
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.json = AsyncMock(return_value=cert_data)
        mock_response.__aenter__ = AsyncMock(return_value=mock_response)
        mock_response.__aexit__ = AsyncMock(return_value=None)

        mock_session = MagicMock()
        mock_session.get = MagicMock(return_value=mock_response)
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session.__aexit__ = AsyncMock(return_value=None)

        # Mock cert_store
        agent.cert_store.store_certificates = Mock()

        with patch("aiohttp.ClientSession", return_value=mock_session):
            with patch("aiohttp.TCPConnector"):
                result = await reg_manager.fetch_certificates(host_id)

        assert result is True
        agent.cert_store.store_certificates.assert_called_once_with(cert_data)

    @pytest.mark.asyncio
    async def test_fetch_certificates_not_approved(self, agent, mock_db_manager):
        """Test certificate fetching when host not approved."""
        _ = mock_db_manager
        reg_manager = RegistrationManager(agent)
        host_id = str(uuid.uuid4())

        reg_manager.get_auth_token = AsyncMock(return_value="test-token")

        # Mock 403 response
        mock_response = AsyncMock()
        mock_response.status = 403
        mock_response.__aenter__ = AsyncMock(return_value=mock_response)
        mock_response.__aexit__ = AsyncMock(return_value=None)

        mock_session = MagicMock()
        mock_session.get = MagicMock(return_value=mock_response)
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session.__aexit__ = AsyncMock(return_value=None)

        with patch("aiohttp.ClientSession", return_value=mock_session):
            with patch("aiohttp.TCPConnector"):
                result = await reg_manager.fetch_certificates(host_id)

        assert result is False

    @pytest.mark.asyncio
    async def test_fetch_certificates_http_error(self, agent, mock_db_manager):
        """Test certificate fetching with HTTP error."""
        _ = mock_db_manager
        reg_manager = RegistrationManager(agent)
        host_id = str(uuid.uuid4())

        reg_manager.get_auth_token = AsyncMock(return_value="test-token")

        # Mock 500 response
        mock_response = AsyncMock()
        mock_response.status = 500
        mock_response.__aenter__ = AsyncMock(return_value=mock_response)
        mock_response.__aexit__ = AsyncMock(return_value=None)

        mock_session = MagicMock()
        mock_session.get = MagicMock(return_value=mock_response)
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session.__aexit__ = AsyncMock(return_value=None)

        with patch("aiohttp.ClientSession", return_value=mock_session):
            with patch("aiohttp.TCPConnector"):
                result = await reg_manager.fetch_certificates(host_id)

        assert result is False

    @pytest.mark.asyncio
    async def test_fetch_certificates_network_error(self, agent, mock_db_manager):
        """Test certificate fetching with network error."""
        _ = mock_db_manager
        reg_manager = RegistrationManager(agent)
        host_id = str(uuid.uuid4())

        reg_manager.get_auth_token = AsyncMock(return_value="test-token")

        # Mock network error
        mock_session = MagicMock()
        mock_session.get = MagicMock(side_effect=aiohttp.ClientError("Network error"))
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session.__aexit__ = AsyncMock(return_value=None)

        with patch("aiohttp.ClientSession", return_value=mock_session):
            with patch("aiohttp.TCPConnector"):
                result = await reg_manager.fetch_certificates(host_id)

        assert result is False

    @pytest.mark.asyncio
    async def test_fetch_certificates_with_ssl(self, agent, mock_db_manager):
        """Test certificate fetching with SSL enabled."""
        _ = mock_db_manager
        reg_manager = RegistrationManager(agent)
        host_id = str(uuid.uuid4())

        # Configure SSL
        agent.config.get_server_config = Mock(
            return_value={
                "hostname": "secure.example.com",
                "port": 8443,
                "use_https": True,
            }
        )
        agent.config.should_verify_ssl = Mock(return_value=False)

        reg_manager.get_auth_token = AsyncMock(return_value="test-token")

        cert_data = {
            "certificate": "CERT",
            "private_key": "KEY",
            "ca_certificate": "CA",
        }

        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.json = AsyncMock(return_value=cert_data)
        mock_response.__aenter__ = AsyncMock(return_value=mock_response)
        mock_response.__aexit__ = AsyncMock(return_value=None)

        mock_session = MagicMock()
        mock_session.get = MagicMock(return_value=mock_response)
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session.__aexit__ = AsyncMock(return_value=None)

        agent.cert_store.store_certificates = Mock()

        with patch("aiohttp.ClientSession", return_value=mock_session):
            with patch("aiohttp.TCPConnector") as mock_connector:
                with patch("ssl.create_default_context") as mock_ssl_context:
                    result = await reg_manager.fetch_certificates(host_id)

        assert result is True
        mock_ssl_context.assert_called_once()


class TestEnsureCertificates:
    """Test certificate validation and retrieval."""

    @pytest.mark.asyncio
    async def test_ensure_certificates_already_valid(self, agent, mock_db_manager):
        """Test ensure_certificates when valid certificates exist."""
        _ = mock_db_manager
        reg_manager = RegistrationManager(agent)

        agent.cert_store.has_certificates = Mock(return_value=True)

        result = await reg_manager.ensure_certificates()

        assert result is True
        agent.cert_store.has_certificates.assert_called_once()

    @pytest.mark.asyncio
    async def test_ensure_certificates_no_certificates(self, agent, mock_db_manager):
        """Test ensure_certificates when no certificates exist."""
        _ = mock_db_manager
        reg_manager = RegistrationManager(agent)

        agent.cert_store.has_certificates = Mock(return_value=False)
        agent.registration.get_system_info = Mock(
            return_value={"hostname": "test-host"}
        )

        # Mock fingerprint retrieval - will fail and return False
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.json = AsyncMock(return_value={"fingerprint": "ABC123"})
        mock_response.__aenter__ = AsyncMock(return_value=mock_response)
        mock_response.__aexit__ = AsyncMock(return_value=None)

        mock_session = MagicMock()
        mock_session.get = MagicMock(return_value=mock_response)
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session.__aexit__ = AsyncMock(return_value=None)

        with patch("aiohttp.ClientSession", return_value=mock_session):
            with patch("aiohttp.TCPConnector"):
                result = await reg_manager.ensure_certificates()

        # Should return False as manual approval is required
        assert result is False

    @pytest.mark.asyncio
    async def test_ensure_certificates_fingerprint_error(self, agent, mock_db_manager):
        """Test ensure_certificates when fingerprint retrieval fails."""
        _ = mock_db_manager
        reg_manager = RegistrationManager(agent)

        agent.cert_store.has_certificates = Mock(return_value=False)

        # Mock network error for fingerprint retrieval
        mock_session = MagicMock()
        mock_session.get = MagicMock(side_effect=Exception("Network error"))
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session.__aexit__ = AsyncMock(return_value=None)

        with patch("aiohttp.ClientSession", return_value=mock_session):
            with patch("aiohttp.TCPConnector"):
                result = await reg_manager.ensure_certificates()

        assert result is False


class TestRegistrationSuccess:
    """Test registration success handling."""

    @pytest.mark.asyncio
    async def test_handle_registration_success_with_approval(
        self, agent, mock_db_manager
    ):
        """Test handling registration success with immediate approval."""
        _ = mock_db_manager
        reg_manager = RegistrationManager(agent)

        host_id = str(uuid.uuid4())
        message = {"host_id": host_id, "host_token": "token-123", "approved": True}

        reg_manager.clear_stored_host_id = AsyncMock()
        reg_manager.store_host_approval = AsyncMock()
        agent.send_initial_data_updates = AsyncMock()

        await reg_manager.handle_registration_success(message)

        reg_manager.clear_stored_host_id.assert_called_once()
        reg_manager.store_host_approval.assert_called_once_with(
            host_id, "approved", host_token="token-123"
        )
        assert agent.registration_confirmed is True
        agent.send_initial_data_updates.assert_called_once()

    @pytest.mark.asyncio
    async def test_handle_registration_success_pending_approval(
        self, agent, mock_db_manager
    ):
        """Test handling registration success with pending approval."""
        _ = mock_db_manager
        reg_manager = RegistrationManager(agent)

        host_id = str(uuid.uuid4())
        message = {"host_id": host_id, "host_token": "token-123", "approved": False}

        reg_manager.clear_stored_host_id = AsyncMock()
        reg_manager.store_host_approval = AsyncMock()
        agent.send_initial_data_updates = AsyncMock()

        await reg_manager.handle_registration_success(message)

        reg_manager.store_host_approval.assert_called_once_with(
            host_id, "pending", host_token="token-123"
        )
        assert agent.registration_confirmed is True
        # Should not send initial data when pending
        agent.send_initial_data_updates.assert_not_called()

    @pytest.mark.asyncio
    async def test_handle_registration_success_no_host_id(self, agent, mock_db_manager):
        """Test handling registration success without host_id."""
        _ = mock_db_manager
        reg_manager = RegistrationManager(agent)

        message = {}

        await reg_manager.handle_registration_success(message)

        # Should not crash, just log info
        assert agent.last_registration_time is not None

    @pytest.mark.asyncio
    async def test_handle_registration_success_error(self, agent, mock_db_manager):
        """Test handling registration success with error during processing."""
        _ = mock_db_manager
        reg_manager = RegistrationManager(agent)

        message = {
            "host_id": str(uuid.uuid4()),
            "host_token": "token-123",
            "approved": True,
        }

        # Mock error during store operation
        reg_manager.clear_stored_host_id = AsyncMock()
        reg_manager.store_host_approval = AsyncMock(side_effect=Exception("DB error"))

        # Should not raise exception, just log error
        await reg_manager.handle_registration_success(message)


class TestHostApproval:
    """Test host approval handling."""

    @pytest.mark.asyncio
    async def test_handle_host_approval_success(self, agent, mock_db_manager):
        """Test successful host approval handling."""
        _ = mock_db_manager
        reg_manager = RegistrationManager(agent)

        host_id = str(uuid.uuid4())
        message = {
            "data": {
                "host_id": host_id,
                "approval_status": "approved",
                "certificate": "CERT_DATA",
            }
        }

        reg_manager.store_host_approval = AsyncMock()
        agent.create_system_info_message = Mock(return_value={"type": "system_info"})
        agent.message_handler.queue_outbound_message = AsyncMock()

        await reg_manager.handle_host_approval(message)

        reg_manager.store_host_approval.assert_called_once_with(
            host_id, "approved", "CERT_DATA"
        )
        agent.message_handler.queue_outbound_message.assert_called_once()

    @pytest.mark.asyncio
    async def test_handle_host_approval_no_certificate(self, agent, mock_db_manager):
        """Test host approval handling without certificate."""
        _ = mock_db_manager
        reg_manager = RegistrationManager(agent)

        host_id = str(uuid.uuid4())
        message = {"data": {"host_id": host_id, "approval_status": "approved"}}

        reg_manager.store_host_approval = AsyncMock()
        agent.create_system_info_message = Mock(return_value={"type": "system_info"})
        agent.message_handler.queue_outbound_message = AsyncMock()

        await reg_manager.handle_host_approval(message)

        reg_manager.store_host_approval.assert_called_once_with(
            host_id, "approved", None
        )

    @pytest.mark.asyncio
    async def test_handle_host_approval_error(self, agent, mock_db_manager):
        """Test host approval handling with error."""
        _ = mock_db_manager
        reg_manager = RegistrationManager(agent)

        message = {
            "data": {"host_id": str(uuid.uuid4()), "approval_status": "approved"}
        }

        # Mock error during store
        reg_manager.store_host_approval = AsyncMock(side_effect=Exception("DB error"))

        # Should not raise exception
        await reg_manager.handle_host_approval(message)


class TestServerAPICall:
    """Test server API call functionality."""

    @pytest.mark.asyncio
    async def test_call_server_api_success(self, agent, mock_db_manager):
        """Test successful API call."""
        reg_manager = RegistrationManager(agent)

        # Mock host token
        reg_manager.get_stored_host_token_sync = Mock(return_value="api-token")

        # Mock response
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.json = AsyncMock(return_value={"result": "success"})
        mock_response.__aenter__ = AsyncMock(return_value=mock_response)
        mock_response.__aexit__ = AsyncMock(return_value=None)

        mock_session = MagicMock()
        mock_session.request = MagicMock(return_value=mock_response)
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session.__aexit__ = AsyncMock(return_value=None)

        with patch("aiohttp.ClientSession", return_value=mock_session):
            result = await reg_manager.call_server_api(
                "test/endpoint", method="POST", data={"key": "value"}
            )

        assert result == {"result": "success"}

    @pytest.mark.asyncio
    async def test_call_server_api_no_token(self, agent, mock_db_manager):
        """Test API call without authentication token."""
        _ = mock_db_manager
        reg_manager = RegistrationManager(agent)

        reg_manager.get_stored_host_token_sync = Mock(return_value=None)

        result = await reg_manager.call_server_api("test/endpoint")

        assert result is None

    @pytest.mark.asyncio
    async def test_call_server_api_http_error(self, agent, mock_db_manager):
        """Test API call with HTTP error."""
        _ = mock_db_manager
        reg_manager = RegistrationManager(agent)

        reg_manager.get_stored_host_token_sync = Mock(return_value="api-token")

        # Mock error response
        mock_response = AsyncMock()
        mock_response.status = 500
        mock_response.text = AsyncMock(return_value="Internal Server Error")
        mock_response.__aenter__ = AsyncMock(return_value=mock_response)
        mock_response.__aexit__ = AsyncMock(return_value=None)

        mock_session = MagicMock()
        mock_session.request = MagicMock(return_value=mock_response)
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session.__aexit__ = AsyncMock(return_value=None)

        with patch("aiohttp.ClientSession", return_value=mock_session):
            result = await reg_manager.call_server_api("test/endpoint", method="POST")

        assert result is None

    @pytest.mark.asyncio
    async def test_call_server_api_network_error(self, agent, mock_db_manager):
        """Test API call with network error."""
        _ = mock_db_manager
        reg_manager = RegistrationManager(agent)

        reg_manager.get_stored_host_token_sync = Mock(return_value="api-token")

        # Mock network error
        mock_session = MagicMock()
        mock_session.request = MagicMock(side_effect=Exception("Network error"))
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session.__aexit__ = AsyncMock(return_value=None)

        with patch("aiohttp.ClientSession", return_value=mock_session):
            result = await reg_manager.call_server_api("test/endpoint")

        assert result is None

    @pytest.mark.asyncio
    async def test_call_server_api_non_json_response(self, agent, mock_db_manager):
        """Test API call with non-JSON response."""
        _ = mock_db_manager
        reg_manager = RegistrationManager(agent)

        reg_manager.get_stored_host_token_sync = Mock(return_value="api-token")

        # Mock response that fails JSON parsing
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.json = AsyncMock(side_effect=Exception("Not JSON"))
        mock_response.__aenter__ = AsyncMock(return_value=mock_response)
        mock_response.__aexit__ = AsyncMock(return_value=None)

        mock_session = MagicMock()
        mock_session.request = MagicMock(return_value=mock_response)
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session.__aexit__ = AsyncMock(return_value=None)

        with patch("aiohttp.ClientSession", return_value=mock_session):
            result = await reg_manager.call_server_api("test/endpoint")

        # Should return success dict when JSON parsing fails
        assert result == {"success": True}

    @pytest.mark.asyncio
    async def test_call_server_api_with_ssl(self, agent, mock_db_manager):
        """Test API call with SSL configuration."""
        _ = mock_db_manager
        reg_manager = RegistrationManager(agent)

        # Override config to use SSL
        agent.config.get = Mock(
            return_value={
                "server": {
                    "host": "secure.example.com",
                    "port": 8443,
                    "ssl": {"enabled": True, "verify": False},
                }
            }
        )

        reg_manager.get_stored_host_token_sync = Mock(return_value="api-token")

        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.json = AsyncMock(return_value={"status": "ok"})
        mock_response.__aenter__ = AsyncMock(return_value=mock_response)
        mock_response.__aexit__ = AsyncMock(return_value=None)

        mock_session = MagicMock()
        mock_session.request = MagicMock(return_value=mock_response)
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session.__aexit__ = AsyncMock(return_value=None)

        with patch("aiohttp.ClientSession", return_value=mock_session):
            result = await reg_manager.call_server_api("test/endpoint", method="GET")

        # Should succeed with SSL configuration
        assert result == {"status": "ok"}

    @pytest.mark.asyncio
    async def test_call_server_api_get_method(self, agent, mock_db_manager):
        """Test API call with GET method."""
        _ = mock_db_manager
        reg_manager = RegistrationManager(agent)

        reg_manager.get_stored_host_token_sync = Mock(return_value="api-token")

        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.json = AsyncMock(return_value={"data": "test"})
        mock_response.__aenter__ = AsyncMock(return_value=mock_response)
        mock_response.__aexit__ = AsyncMock(return_value=None)

        mock_session = MagicMock()
        mock_session.request = MagicMock(return_value=mock_response)
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session.__aexit__ = AsyncMock(return_value=None)

        with patch("aiohttp.ClientSession", return_value=mock_session):
            result = await reg_manager.call_server_api("test/endpoint", method="GET")

        # Verify GET was used
        call_args = mock_session.request.call_args
        assert call_args[1]["method"] == "GET"
        assert result == {"data": "test"}


class TestEdgeCases:
    """Test edge cases and error conditions."""

    @pytest.mark.asyncio
    async def test_handle_registration_success_with_none_values(
        self, agent, mock_db_manager
    ):
        """Test registration success handling with None values."""
        _ = mock_db_manager
        reg_manager = RegistrationManager(agent)

        message = {"host_id": None, "host_token": None, "approved": None}

        # Should not crash
        await reg_manager.handle_registration_success(message)

    @pytest.mark.asyncio
    async def test_handle_registration_success_updates_timestamp(
        self, agent, mock_db_manager
    ):
        """Test that registration success updates timestamp."""
        _ = mock_db_manager
        reg_manager = RegistrationManager(agent)

        message = {}
        initial_time = agent.last_registration_time

        await reg_manager.handle_registration_success(message)

        # Timestamp should be updated
        assert agent.last_registration_time is not None
        assert agent.last_registration_time != initial_time

    @pytest.mark.asyncio
    async def test_clear_stored_host_id_continues_on_error(self, agent):
        """Test that clear operation continues even on error."""
        reg_manager = RegistrationManager(agent)

        # Mock database manager to fail
        with patch(
            "src.database.base.get_database_manager", side_effect=Exception("DB error")
        ):
            # Should not raise exception
            await reg_manager.clear_stored_host_id()
