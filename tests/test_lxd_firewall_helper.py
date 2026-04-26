"""
Tests for sysmanage_agent.operations.lxd_firewall_helper.

The module shells out heavily, so all tests mock subprocess.run at the
module-level. The goal is to drive each branch of configure_lxd_firewall
plus the private helpers (_ufw_available, _enable_ip_forwarding,
_set_ufw_forward_policy, _add_ufw_bridge_route_rules, _detect_bridge_subnet,
_configure_nat_masquerade).
"""

# pylint: disable=redefined-outer-name,protected-access
# pylint: disable=missing-class-docstring,missing-function-docstring

import logging
import subprocess
from unittest.mock import MagicMock, mock_open, patch

import pytest

from src.sysmanage_agent.operations import lxd_firewall_helper as mod


def _completed(returncode=0, stdout="", stderr=""):
    proc = MagicMock(spec=subprocess.CompletedProcess)
    proc.returncode = returncode
    proc.stdout = stdout
    proc.stderr = stderr
    return proc


@pytest.fixture
def logger():
    return logging.getLogger("test")


# ---------------------------------------------------------------------------
# _ufw_available
# ---------------------------------------------------------------------------


class TestUfwAvailable:
    def test_returns_true_when_which_finds_ufw(self):
        with patch.object(mod.subprocess, "run", return_value=_completed(0)):
            assert mod._ufw_available() is True

    def test_returns_false_when_which_missing(self):
        with patch.object(mod.subprocess, "run", return_value=_completed(1)):
            assert mod._ufw_available() is False

    def test_returns_false_on_filenotfound(self):
        with patch.object(mod.subprocess, "run", side_effect=FileNotFoundError):
            assert mod._ufw_available() is False

    def test_returns_false_on_timeout(self):
        with patch.object(
            mod.subprocess,
            "run",
            side_effect=subprocess.TimeoutExpired(cmd="which", timeout=5),
        ):
            assert mod._ufw_available() is False


# ---------------------------------------------------------------------------
# _enable_ip_forwarding
# ---------------------------------------------------------------------------


class TestEnableIpForwarding:
    def test_already_enabled_short_circuits(self, logger):
        # /proc/sys/net/ipv4/ip_forward reads "1\n" → no subprocess called.
        errors = []
        with patch("builtins.open", mock_open(read_data="1\n")), patch.object(
            mod.subprocess, "run"
        ) as run:
            mod._enable_ip_forwarding(logger, errors)
        assert not errors
        run.assert_not_called()

    def test_disabled_enables_via_sysctl(self, logger):
        errors = []
        # First read returns "0\n" → triggers sysctl call.
        with patch("builtins.open", mock_open(read_data="0\n")), patch.object(
            mod.subprocess, "run", return_value=_completed(0)
        ) as run:
            mod._enable_ip_forwarding(logger, errors)
        assert not errors
        # Two subprocess calls: sysctl -w and the persist sed/echo.
        assert run.call_count == 2

    def test_unreadable_proc_records_error(self, logger):
        errors = []
        with patch("builtins.open", side_effect=OSError("denied")):
            mod._enable_ip_forwarding(logger, errors)
        assert any("ip_forward" in e for e in errors)

    def test_sysctl_failure_records_error(self, logger):
        errors = []
        with patch("builtins.open", mock_open(read_data="0\n")), patch.object(
            mod.subprocess,
            "run",
            return_value=_completed(1, stderr="boom"),
        ):
            mod._enable_ip_forwarding(logger, errors)
        assert any("Failed to enable IP forwarding" in e for e in errors)

    def test_persist_failure_logs_warning_only(self, logger):
        errors = []
        # First call (sysctl -w) succeeds, second (persist) fails.
        with patch("builtins.open", mock_open(read_data="0\n")), patch.object(
            mod.subprocess,
            "run",
            side_effect=[_completed(0), _completed(1, stderr="ro fs")],
        ):
            mod._enable_ip_forwarding(logger, errors)
        # No error appended — persist failure is logger.warning only.
        assert not errors


# ---------------------------------------------------------------------------
# _set_ufw_forward_policy
# ---------------------------------------------------------------------------


class TestSetUfwForwardPolicy:
    def test_success_does_not_record_error(self):
        errors = []
        with patch.object(mod.subprocess, "run", return_value=_completed(0)):
            mod._set_ufw_forward_policy(errors)
        assert not errors

    def test_failure_records_error(self):
        errors = []
        with patch.object(
            mod.subprocess, "run", return_value=_completed(1, stderr="bad sed")
        ):
            mod._set_ufw_forward_policy(errors)
        assert any("forward policy" in e.lower() for e in errors)


# ---------------------------------------------------------------------------
# _add_ufw_bridge_route_rules
# ---------------------------------------------------------------------------


class TestAddUfwBridgeRouteRules:
    def test_runs_four_rules(self, logger):
        with patch.object(mod.subprocess, "run", return_value=_completed(0)) as run:
            mod._add_ufw_bridge_route_rules(logger, "lxdbr0")
        # Exactly four rules: route in, route out, port 67, port 53.
        assert run.call_count == 4

    def test_skipping_in_stdout_is_treated_as_ok(self, logger):
        with patch.object(
            mod.subprocess,
            "run",
            return_value=_completed(1, stdout="Skipping adding existing rule"),
        ):
            mod._add_ufw_bridge_route_rules(logger, "lxdbr0")
        # Should not raise — "Skipping" is the no-op signal.

    def test_already_exists_in_stderr_is_treated_as_ok(self, logger):
        with patch.object(
            mod.subprocess,
            "run",
            return_value=_completed(1, stderr="Rule already exists"),
        ):
            mod._add_ufw_bridge_route_rules(logger, "lxdbr0")

    def test_genuine_failure_is_logged(self, logger):
        # Genuine failure → logger.warning called once per failing rule (4 rules).
        with patch.object(
            mod.subprocess,
            "run",
            return_value=_completed(2, stderr="syntax error"),
        ):
            with patch.object(logger, "warning") as warn:
                mod._add_ufw_bridge_route_rules(logger, "lxdbr0")
        assert warn.call_count == 4


# ---------------------------------------------------------------------------
# _detect_bridge_subnet
# ---------------------------------------------------------------------------


class TestDetectBridgeSubnet:
    def test_parses_inet_cidr_from_ip_output(self):
        ip_output = "5: lxdbr0    inet 10.151.131.1/24 scope global lxdbr0\\\n"
        with patch.object(
            mod.subprocess, "run", return_value=_completed(0, stdout=ip_output)
        ):
            assert mod._detect_bridge_subnet("lxdbr0") == "10.151.131.0/24"

    def test_falls_back_when_command_fails(self):
        with patch.object(mod.subprocess, "run", return_value=_completed(1)):
            assert mod._detect_bridge_subnet("lxdbr0") == "10.0.0.0/8"

    def test_falls_back_when_output_empty(self):
        with patch.object(mod.subprocess, "run", return_value=_completed(0, stdout="")):
            assert mod._detect_bridge_subnet("lxdbr0") == "10.0.0.0/8"

    def test_falls_back_on_subprocess_error(self):
        with patch.object(
            mod.subprocess,
            "run",
            side_effect=subprocess.SubprocessError("oops"),
        ):
            assert mod._detect_bridge_subnet("lxdbr0") == "10.0.0.0/8"

    def test_falls_back_on_invalid_cidr(self):
        # ipaddress.ip_network raises ValueError on garbage.
        bad_output = "5: lxdbr0    inet not-a-cidr scope global lxdbr0\\\n"
        with patch.object(
            mod.subprocess, "run", return_value=_completed(0, stdout=bad_output)
        ):
            assert mod._detect_bridge_subnet("lxdbr0") == "10.0.0.0/8"


# ---------------------------------------------------------------------------
# _configure_nat_masquerade
# ---------------------------------------------------------------------------


class TestConfigureNatMasquerade:
    def test_already_present_skips_write(self, logger):
        existing = "# header\n# LXD NAT rules - added by sysmanage-agent\n# tail\n"
        errors = []
        # _detect_bridge_subnet runs first and shells out — that's expected.
        # We just want to confirm the second (write) subprocess never runs.
        responses = [_completed(0, stdout="5: lxdbr0    inet 10.0.0.1/24")]
        with patch("builtins.open", mock_open(read_data=existing)), patch.object(
            mod.subprocess, "run", side_effect=responses
        ) as run:
            mod._configure_nat_masquerade(logger, "lxdbr0", errors)
        # Exactly one subprocess call (the ip addr show) — no write happened.
        assert run.call_count == 1
        assert not errors

    def test_unreadable_before_rules_records_error(self, logger):
        errors = []
        with patch("builtins.open", side_effect=OSError("perm denied")), patch.object(
            mod.subprocess, "run"
        ):
            mod._configure_nat_masquerade(logger, "lxdbr0", errors)
        assert any("before.rules" in e for e in errors)

    def test_rule_insertion_succeeds(self, logger):
        errors = []
        # Existing before.rules has no LXD marker → triggers the write path.
        # _detect_bridge_subnet runs first, then the sh -c insertion.
        responses = [
            _completed(0, stdout="5: lxdbr0    inet 10.0.0.1/24 scope global"),
            _completed(0),  # the sh -c that prepends NAT rules
        ]
        with patch(
            "builtins.open", mock_open(read_data="# nothing yet\n")
        ), patch.object(mod.subprocess, "run", side_effect=responses):
            mod._configure_nat_masquerade(logger, "lxdbr0", errors)
        assert not errors

    def test_rule_insertion_failure_records_error(self, logger):
        errors = []
        responses = [
            _completed(0, stdout="5: lxdbr0    inet 10.0.0.1/24"),
            _completed(1, stderr="tee failed"),
        ]
        with patch(
            "builtins.open", mock_open(read_data="# nothing yet\n")
        ), patch.object(mod.subprocess, "run", side_effect=responses):
            mod._configure_nat_masquerade(logger, "lxdbr0", errors)
        assert any("NAT rules" in e for e in errors)


# ---------------------------------------------------------------------------
# configure_lxd_firewall — top-level orchestrator
# ---------------------------------------------------------------------------


class TestConfigureLxdFirewall:
    def test_skipped_when_ufw_missing(self, logger):
        with patch.object(mod, "_ufw_available", return_value=False):
            out = mod.configure_lxd_firewall(logger)
        assert out == {
            "success": True,
            "message": "UFW not installed; skipping LXD bridge firewall config",
        }

    def test_happy_path(self, logger):
        with patch.object(mod, "_ufw_available", return_value=True), patch.object(
            mod, "_enable_ip_forwarding"
        ), patch.object(mod, "_set_ufw_forward_policy"), patch.object(
            mod, "_add_ufw_bridge_route_rules"
        ), patch.object(
            mod, "_configure_nat_masquerade"
        ), patch.object(
            mod.subprocess, "run", return_value=_completed(0)
        ):
            out = mod.configure_lxd_firewall(logger)
        assert out["success"] is True
        assert "successfully" in out["message"].lower()

    def test_reload_failure_collected_into_errors(self, logger):
        with patch.object(mod, "_ufw_available", return_value=True), patch.object(
            mod, "_enable_ip_forwarding"
        ), patch.object(mod, "_set_ufw_forward_policy"), patch.object(
            mod, "_add_ufw_bridge_route_rules"
        ), patch.object(
            mod, "_configure_nat_masquerade"
        ), patch.object(
            mod.subprocess, "run", return_value=_completed(1, stderr="reload failed")
        ):
            out = mod.configure_lxd_firewall(logger)
        assert out["success"] is False
        assert "reload" in out["error"].lower()

    def test_helper_errors_are_propagated(self, logger):
        # Have the helpers append a synthetic error so configure_lxd_firewall
        # observes it and returns failure.
        def _record_error(_logger, errors):
            errors.append("forwarding broke")

        with patch.object(mod, "_ufw_available", return_value=True), patch.object(
            mod, "_enable_ip_forwarding", side_effect=_record_error
        ), patch.object(mod, "_set_ufw_forward_policy"), patch.object(
            mod, "_add_ufw_bridge_route_rules"
        ), patch.object(
            mod, "_configure_nat_masquerade"
        ), patch.object(
            mod.subprocess, "run", return_value=_completed(0)
        ):
            out = mod.configure_lxd_firewall(logger)
        assert out["success"] is False
        assert "forwarding broke" in out["error"]

    def test_default_bridge_name_is_lxdbr0(self, logger):
        captured = {}

        def _capture(_logger, name):
            captured["name"] = name

        with patch.object(mod, "_ufw_available", return_value=True), patch.object(
            mod, "_enable_ip_forwarding"
        ), patch.object(mod, "_set_ufw_forward_policy"), patch.object(
            mod, "_add_ufw_bridge_route_rules", side_effect=_capture
        ), patch.object(
            mod, "_configure_nat_masquerade"
        ), patch.object(
            mod.subprocess, "run", return_value=_completed(0)
        ):
            mod.configure_lxd_firewall(logger)
        assert captured["name"] == "lxdbr0"
