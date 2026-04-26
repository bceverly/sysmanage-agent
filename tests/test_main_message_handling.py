"""
Tests for main.SysManageAgent message-handling helpers.

Pattern follows the existing tests/test_main_targeted.py: build agents via
``object.__new__(SysManageAgent)`` and stub the dependencies the method under
test reaches for, so we exercise the logic without spinning up the full
agent lifecycle.

Targets:
- _parse_server_error_timestamp (date parsing variants)
- _is_stale_error_message (no timestamp / no last-reg / stale / fresh / parse-error)
- _handle_server_error (each branch of the error_code switch)
- _handle_host_not_registered (clears state + sets re-register flag)
- _process_received_message (each message_type branch + return value)
- _log_ack_message (queue_id + acked_message_id paths)
- _create_ssl_context (with certs / without certs / verify-ssl off)
"""

# pylint: disable=protected-access
# pylint: disable=missing-class-docstring,missing-function-docstring

from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from main import SysManageAgent


def _agent():
    agent = object.__new__(SysManageAgent)
    agent.logger = MagicMock()
    return agent


# ---------------------------------------------------------------------------
# _parse_server_error_timestamp
# ---------------------------------------------------------------------------


class TestParseServerErrorTimestamp:
    def test_iso_with_z_suffix(self):
        agent = _agent()
        result = agent._parse_server_error_timestamp("2026-04-26T12:00:00Z")
        assert result.tzinfo is not None
        assert result.year == 2026

    def test_iso_with_plus_zero(self):
        agent = _agent()
        result = agent._parse_server_error_timestamp("2026-04-26T12:00:00+00:00")
        assert result.tzinfo is not None

    def test_naive_datetime_gets_utc_added(self):
        agent = _agent()
        naive = datetime(2026, 4, 26, 12, 0, 0)
        result = agent._parse_server_error_timestamp(naive)
        assert result.tzinfo == timezone.utc

    def test_aware_datetime_passes_through(self):
        agent = _agent()
        aware = datetime(2026, 4, 26, 12, 0, 0, tzinfo=timezone.utc)
        result = agent._parse_server_error_timestamp(aware)
        assert result == aware


# ---------------------------------------------------------------------------
# _is_stale_error_message
# ---------------------------------------------------------------------------


class TestIsStaleErrorMessage:
    def test_no_timestamp_returns_false(self):
        agent = _agent()
        agent.last_registration_time = datetime.now(timezone.utc)
        assert agent._is_stale_error_message({}, "host_not_registered") is False

    def test_no_last_registration_time_returns_false(self):
        agent = _agent()
        agent.last_registration_time = None
        assert (
            agent._is_stale_error_message({"timestamp": "2026-04-26T12:00:00Z"}, "x")
            is False
        )

    def test_message_older_than_registration_is_stale(self):
        agent = _agent()
        agent.last_registration_time = datetime(
            2026, 4, 26, 13, 0, 0, tzinfo=timezone.utc
        )
        # Message from one hour BEFORE last registration → stale.
        assert (
            agent._is_stale_error_message(
                {"timestamp": "2026-04-26T12:00:00Z"}, "host_not_registered"
            )
            is True
        )

    def test_message_after_registration_is_not_stale(self):
        agent = _agent()
        agent.last_registration_time = datetime(
            2026, 4, 26, 12, 0, 0, tzinfo=timezone.utc
        )
        assert (
            agent._is_stale_error_message(
                {"timestamp": "2026-04-26T13:00:00Z"}, "host_not_registered"
            )
            is False
        )

    def test_naive_last_registration_gets_utc_added(self):
        agent = _agent()
        # Bypass tz check by giving naive datetimes both sides.
        agent.last_registration_time = datetime(2026, 4, 26, 13, 0, 0)
        # Stale check still works.
        assert (
            agent._is_stale_error_message({"timestamp": "2026-04-26T12:00:00Z"}, "x")
            is True
        )

    def test_unparseable_timestamp_returns_false(self):
        agent = _agent()
        agent.last_registration_time = datetime.now(timezone.utc)
        assert agent._is_stale_error_message({"timestamp": "not-a-date"}, "x") is False


# ---------------------------------------------------------------------------
# _handle_server_error  (branches: stale, host_not_registered, host_not_approved,
# missing_hostname, queue_error, unknown)
# ---------------------------------------------------------------------------


class TestHandleServerError:
    @pytest.mark.asyncio
    async def test_stale_message_short_circuits(self):
        agent = _agent()
        agent.last_registration_time = datetime.now(timezone.utc) + timedelta(hours=1)
        # Use an old timestamp so the stale check fires.
        called = {"n": 0}

        async def _handler():
            called["n"] += 1

        agent._handle_host_not_registered = _handler
        await agent._handle_server_error(
            {
                "error_type": "host_not_registered",
                "timestamp": "2020-01-01T00:00:00Z",
            }
        )
        assert called["n"] == 0  # Short-circuited.

    @pytest.mark.asyncio
    async def test_host_not_registered_dispatches_to_handler(self):
        agent = _agent()
        agent.last_registration_time = None
        called = {"n": 0}

        async def _handler():
            called["n"] += 1

        agent._handle_host_not_registered = _handler
        await agent._handle_server_error({"error_type": "host_not_registered"})
        assert called["n"] == 1

    @pytest.mark.asyncio
    async def test_host_not_approved_logs_warning(self):
        agent = _agent()
        agent.last_registration_time = None
        # No exception → branch handled.
        await agent._handle_server_error({"error_type": "host_not_approved"})
        agent.logger.warning.assert_called()

    @pytest.mark.asyncio
    async def test_missing_hostname_logs_error(self):
        agent = _agent()
        agent.last_registration_time = None
        await agent._handle_server_error({"error_type": "missing_hostname"})
        agent.logger.error.assert_called()

    @pytest.mark.asyncio
    async def test_queue_error_logs_error(self):
        agent = _agent()
        agent.last_registration_time = None
        await agent._handle_server_error(
            {"error_type": "queue_error", "message": "queue down"}
        )
        agent.logger.error.assert_called()

    @pytest.mark.asyncio
    async def test_unknown_error_code_only_logs_top_level(self):
        agent = _agent()
        agent.last_registration_time = None
        # Doesn't dispatch anywhere — just logs the top-level "Server error" line.
        await agent._handle_server_error(
            {"error_type": "completely_new_code", "message": "?"}
        )


# ---------------------------------------------------------------------------
# _handle_host_not_registered
# ---------------------------------------------------------------------------


class TestHandleHostNotRegistered:
    @pytest.mark.asyncio
    async def test_clears_state_and_marks_for_reregistration(self):
        agent = _agent()
        agent.clear_stored_host_id = AsyncMock()
        agent.registration_status = "registered"
        agent.registration_confirmed = True
        agent.registration = MagicMock(registered=True)
        agent.needs_registration = False
        agent.running = True

        await agent._handle_host_not_registered()

        agent.clear_stored_host_id.assert_awaited_once()
        assert agent.registration_status is None
        assert agent.registration_confirmed is False
        assert agent.registration.registered is False
        assert agent.needs_registration is True
        assert agent.running is False

    @pytest.mark.asyncio
    async def test_clear_failure_logged_but_not_raised(self):
        agent = _agent()
        agent.clear_stored_host_id = AsyncMock(side_effect=RuntimeError("db down"))
        agent.registration_status = "registered"
        agent.registration_confirmed = True
        agent.registration = MagicMock(registered=True)
        agent.needs_registration = False
        agent.running = True

        # Must not raise — we still want to mark for re-registration.
        await agent._handle_host_not_registered()
        agent.logger.error.assert_called()
        # State still mutated despite the clear failure.
        assert agent.needs_registration is True
        assert agent.running is False


# ---------------------------------------------------------------------------
# _process_received_message
# ---------------------------------------------------------------------------


class TestProcessReceivedMessage:
    @pytest.mark.asyncio
    async def test_command_dispatches_to_handle_command(self):
        agent = _agent()
        agent.handle_command = AsyncMock()
        result = await agent._process_received_message(
            {"message_type": "command", "data": {"cmd": "x"}}
        )
        assert result is True
        agent.handle_command.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_ping_replies_with_pong(self):
        agent = _agent()
        agent.send_message = AsyncMock()
        agent.registration_manager = MagicMock()
        agent.registration_manager.get_stored_host_id_sync = MagicMock(
            return_value=None
        )
        agent.registration_manager.get_stored_host_token_sync = MagicMock(
            return_value=None
        )
        result = await agent._process_received_message(
            {"message_type": "ping", "message_id": "p-1"}
        )
        assert result is True
        sent = agent.send_message.await_args.args[0]
        assert sent["message_type"] == "pong"
        assert sent["data"]["ping_id"] == "p-1"

    @pytest.mark.asyncio
    async def test_ack_dispatches_to_log_ack_message(self):
        agent = _agent()
        result = await agent._process_received_message(
            {"message_type": "ack", "queue_id": "q-1", "status": "queued"}
        )
        assert result is True

    @pytest.mark.asyncio
    async def test_error_returns_false_when_needs_registration(self):
        agent = _agent()
        agent.last_registration_time = None
        agent.clear_stored_host_id = AsyncMock()
        agent.registration_status = "x"
        agent.registration_confirmed = True
        agent.registration = MagicMock(registered=True)
        agent.needs_registration = False
        agent.running = True
        result = await agent._process_received_message(
            {"message_type": "error", "error_type": "host_not_registered"}
        )
        # _handle_host_not_registered set needs_registration=True → returns False.
        assert result is False

    @pytest.mark.asyncio
    async def test_error_returns_true_when_needs_registration_unset(self):
        agent = _agent()
        agent.last_registration_time = None
        agent.needs_registration = False
        agent.running = True
        result = await agent._process_received_message(
            {"message_type": "error", "error_type": "queue_error"}
        )
        assert result is True

    @pytest.mark.asyncio
    async def test_host_approved_dispatches_to_handler(self):
        agent = _agent()
        agent.handle_host_approval = AsyncMock()
        result = await agent._process_received_message(
            {"message_type": "host_approved"}
        )
        assert result is True
        agent.handle_host_approval.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_registration_success_dispatches_to_handler(self):
        agent = _agent()
        agent.handle_registration_success = AsyncMock()
        result = await agent._process_received_message(
            {"message_type": "registration_success"}
        )
        assert result is True
        agent.handle_registration_success.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_diagnostic_result_ack_just_logs(self):
        agent = _agent()
        result = await agent._process_received_message(
            {"message_type": "diagnostic_result_ack", "status": "ok"}
        )
        assert result is True

    @pytest.mark.asyncio
    async def test_unknown_message_type_logs_warning(self):
        agent = _agent()
        result = await agent._process_received_message(
            {"message_type": "totally_unknown"}
        )
        assert result is True
        agent.logger.warning.assert_called()


# ---------------------------------------------------------------------------
# _log_ack_message
# ---------------------------------------------------------------------------


class TestLogAckMessage:
    def test_with_queue_id_logs_queue_id(self):
        agent = _agent()
        agent._log_ack_message({"queue_id": "q-1", "status": "queued"})
        agent.logger.debug.assert_called()
        msg = agent.logger.debug.call_args.args[0]
        assert "queue_id" in msg

    def test_without_queue_id_uses_acked_message_id(self):
        agent = _agent()
        agent._log_ack_message(
            {
                "data": {"acked_message_id": "m-1"},
                "status": "ok",
            }
        )
        msg = agent.logger.debug.call_args.args[0]
        assert "acknowledged message" in msg

    def test_falls_back_to_top_level_message_id(self):
        agent = _agent()
        agent._log_ack_message({"message_id": "m-1", "data": {}, "status": "ok"})
        msg = agent.logger.debug.call_args.args[0]
        assert "acknowledged message" in msg


# ---------------------------------------------------------------------------
# _create_ssl_context
# ---------------------------------------------------------------------------


class TestCreateSslContext:
    def test_with_client_certs_loads_them(self):
        agent = _agent()
        agent.cert_store = MagicMock()
        agent.cert_store.load_certificates.return_value = (
            "/c/client.pem",
            "/c/key.pem",
            "/c/ca.pem",
        )
        agent.config = MagicMock()
        with patch("main.ssl.create_default_context") as ctx_factory:
            ctx = MagicMock()
            ctx_factory.return_value = ctx
            agent._create_ssl_context()
        ctx.load_cert_chain.assert_called_once_with("/c/client.pem", "/c/key.pem")
        ctx.load_verify_locations.assert_called_once_with("/c/ca.pem")
        assert ctx.check_hostname is True

    def test_no_certs_with_verify_off_disables_verification(self):
        agent = _agent()
        agent.cert_store = MagicMock()
        agent.cert_store.load_certificates.return_value = None
        agent.config = MagicMock()
        agent.config.should_verify_ssl.return_value = False
        with patch("main.ssl.create_default_context") as ctx_factory:
            ctx = MagicMock()
            ctx_factory.return_value = ctx
            agent._create_ssl_context()
        assert ctx.check_hostname is False

    def test_no_certs_with_verify_on_keeps_default(self):
        agent = _agent()
        agent.cert_store = MagicMock()
        agent.cert_store.load_certificates.return_value = None
        agent.config = MagicMock()
        agent.config.should_verify_ssl.return_value = True
        with patch("main.ssl.create_default_context") as ctx_factory:
            ctx = MagicMock()
            ctx_factory.return_value = ctx
            result = agent._create_ssl_context()
        # Returns the context; no explicit override of check_hostname/verify_mode.
        assert result is ctx


# ---------------------------------------------------------------------------
# _autostart_child_hosts — exception is logged, not raised
# ---------------------------------------------------------------------------


class TestAutostartChildHosts:
    @pytest.mark.asyncio
    async def test_success_path(self):
        agent = _agent()
        agent.child_host_ops = MagicMock()
        agent.child_host_ops.autostart_child_hosts = AsyncMock()
        await agent._autostart_child_hosts()
        agent.child_host_ops.autostart_child_hosts.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_exception_is_logged_and_swallowed(self):
        agent = _agent()
        agent.child_host_ops = MagicMock()
        agent.child_host_ops.autostart_child_hosts = AsyncMock(
            side_effect=RuntimeError("vm boot failed")
        )
        # Must not raise.
        await agent._autostart_child_hosts()
        agent.logger.warning.assert_called()
