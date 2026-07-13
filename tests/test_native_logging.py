"""Tests for platform-native log handler selection (Phase 13.3)."""

# pylint: disable=protected-access

import logging
from unittest.mock import MagicMock, patch

from src.sysmanage_agent.utils import native_logging
from src.sysmanage_agent.utils.native_logging import build_native_handler


class TestAutoTarget:
    """Tests for _auto_target platform mapping."""

    def test_linux_journald(self):
        """Linux defaults to journald."""
        assert native_logging._auto_target("Linux") == "journald"

    def test_windows_eventlog(self):
        """Windows defaults to the Event Log."""
        assert native_logging._auto_target("Windows") == "eventlog"

    def test_darwin_and_bsd_syslog(self):
        """macOS and the BSDs default to syslog."""
        assert native_logging._auto_target("Darwin") == "syslog"
        assert native_logging._auto_target("FreeBSD") == "syslog"


class TestSyslogAddress:
    """Tests for _syslog_address per platform."""

    def test_addresses(self):
        """Each platform maps to its syslog socket."""
        assert native_logging._syslog_address("Linux") == "/dev/log"
        assert native_logging._syslog_address("Darwin") == "/var/run/syslog"
        assert native_logging._syslog_address("OpenBSD") == "/dev/log"
        assert native_logging._syslog_address("Plan9") == ("localhost", 514)


class TestBuildNativeHandler:
    """Tests for build_native_handler dispatch + fallbacks."""

    def test_none_target(self):
        """An explicit none/off target yields no handler."""
        assert build_native_handler("none") is None
        assert build_native_handler("off") is None

    def test_syslog(self):
        """syslog target builds a SysLogHandler."""
        fake = MagicMock(spec=logging.Handler)
        with patch.object(
            native_logging, "_syslog_handler", return_value=fake
        ) as mock_fn:
            handler = build_native_handler("syslog", "ident", system="Linux")
        assert handler is fake
        mock_fn.assert_called_once_with("ident", "Linux")

    def test_journald_falls_back_to_syslog(self):
        """When journald is unavailable, the Linux path falls back to syslog."""
        fake_syslog = MagicMock(spec=logging.Handler)
        with patch.object(
            native_logging, "_journald_handler", return_value=None
        ), patch.object(native_logging, "_syslog_handler", return_value=fake_syslog):
            handler = build_native_handler("journald", "ident", system="Linux")
        assert handler is fake_syslog

    def test_journald_used_when_available(self):
        """When journald is available it's used (no syslog fallback)."""
        fake_journal = MagicMock(spec=logging.Handler)
        with patch.object(
            native_logging, "_journald_handler", return_value=fake_journal
        ), patch.object(native_logging, "_syslog_handler") as syslog_m:
            handler = build_native_handler("journald", "ident", system="Linux")
        assert handler is fake_journal
        syslog_m.assert_not_called()

    def test_auto_windows_eventlog(self):
        """auto on Windows routes to the Event Log handler."""
        fake = MagicMock(spec=logging.Handler)
        with patch.object(
            native_logging, "_eventlog_handler", return_value=fake
        ) as mock_fn:
            handler = build_native_handler("auto", "ident", system="Windows")
        assert handler is fake
        mock_fn.assert_called_once_with("ident", "Windows")

    def test_unknown_target(self):
        """An unrecognised target yields no handler."""
        assert build_native_handler("carrier-pigeon", system="Linux") is None

    def test_syslog_remote_dispatch(self):
        """syslog_remote routes to _syslog_remote_handler with the remote params."""
        fake = MagicMock(spec=logging.Handler)
        with patch.object(
            native_logging, "_syslog_remote_handler", return_value=fake
        ) as mock_fn:
            handler = build_native_handler(
                "syslog_remote",
                "ident",
                system="Linux",
                host="loghost",
                port=1514,
                facility="local0",
                protocol="tcp",
            )
        assert handler is fake
        mock_fn.assert_called_once_with("ident", "loghost", 1514, "local0", "tcp")


def _mock_syslog(return_value=None):
    """A SysLogHandler stand-in that preserves the real facility constants/dict.

    Patching the whole class with a bare MagicMock would turn ``LOG_USER`` and
    ``facility_names`` into mocks, so the handler's facility resolution couldn't
    be asserted.
    """
    real = logging.handlers.SysLogHandler
    mock = MagicMock(return_value=return_value)
    mock.LOG_USER = real.LOG_USER
    mock.facility_names = real.facility_names
    return mock


class TestSyslogRemoteHandler:
    """Tests for _syslog_remote_handler (Phase 14.5 remote forwarding)."""

    def test_no_host_returns_none(self):
        """Without a host there is nothing to forward to — no handler."""
        assert (
            native_logging._syslog_remote_handler("ident", None, 514, None, None)
            is None
        )
        assert (
            native_logging._syslog_remote_handler("ident", "", 514, None, None) is None
        )

    def test_udp_default(self):
        """A host with no protocol/port/facility → UDP, port 514, LOG_USER."""
        fake = MagicMock(spec=logging.Handler)
        syslog_cls = _mock_syslog(fake)
        with patch.object(native_logging.logging.handlers, "SysLogHandler", syslog_cls):
            handler = native_logging._syslog_remote_handler(
                "ident", "loghost", None, None, None
            )
        assert handler is fake
        kwargs = syslog_cls.call_args.kwargs
        assert kwargs["address"] == ("loghost", 514)
        assert kwargs["socktype"] == native_logging.socket.SOCK_DGRAM
        assert kwargs["facility"] == logging.handlers.SysLogHandler.LOG_USER

    def test_tcp_and_facility_and_port(self):
        """protocol=tcp → SOCK_STREAM; a named facility resolves; port honoured."""
        fake = MagicMock(spec=logging.Handler)
        syslog_cls = _mock_syslog(fake)
        with patch.object(native_logging.logging.handlers, "SysLogHandler", syslog_cls):
            native_logging._syslog_remote_handler(
                "ident", "loghost", 6514, "local3", "tcp"
            )
        kwargs = syslog_cls.call_args.kwargs
        assert kwargs["address"] == ("loghost", 6514)
        assert kwargs["socktype"] == native_logging.socket.SOCK_STREAM
        assert kwargs["facility"] == logging.handlers.SysLogHandler.LOG_LOCAL3

    def test_bad_facility_falls_back_to_user(self):
        """An unknown facility name falls back to LOG_USER rather than raising."""
        fake = MagicMock(spec=logging.Handler)
        syslog_cls = _mock_syslog(fake)
        with patch.object(native_logging.logging.handlers, "SysLogHandler", syslog_cls):
            native_logging._syslog_remote_handler(
                "ident", "loghost", 514, "not-a-facility", "udp"
            )
        assert (
            syslog_cls.call_args.kwargs["facility"]
            == logging.handlers.SysLogHandler.LOG_USER
        )

    def test_bad_port_falls_back_to_514(self):
        """A non-numeric port falls back to 514 instead of exploding."""
        fake = MagicMock(spec=logging.Handler)
        syslog_cls = _mock_syslog(fake)
        with patch.object(native_logging.logging.handlers, "SysLogHandler", syslog_cls):
            native_logging._syslog_remote_handler(
                "ident", "loghost", "not-a-number", None, None
            )
        assert syslog_cls.call_args.kwargs["address"] == ("loghost", 514)

    def test_socket_error_returns_none(self):
        """A failed TCP connect (OSError) yields None — file logging survives."""
        with patch.object(
            native_logging.logging.handlers,
            "SysLogHandler",
            side_effect=OSError("connection refused"),
        ):
            assert (
                native_logging._syslog_remote_handler(
                    "ident", "loghost", 514, None, "tcp"
                )
                is None
            )


class TestEventlogGuard:
    """_eventlog_handler must never return a degraded off-Windows handler."""

    def test_off_windows_returns_none(self):
        """Off-Windows, no Event Log handler is created."""
        assert native_logging._eventlog_handler("ident", "Linux") is None

    def test_degraded_handler_rejected(self):
        """A pywin32-less NTEventLogHandler (no _welu) is rejected."""
        degraded = MagicMock()
        degraded._welu = None
        with patch.object(
            native_logging.logging.handlers,
            "NTEventLogHandler",
            return_value=degraded,
        ):
            assert native_logging._eventlog_handler("ident", "Windows") is None
