"""Tests for the agent applying server-pushed logging config live (Phase 13.3)."""

# pylint: disable=protected-access,redefined-outer-name

import logging
from unittest.mock import MagicMock, patch

import pytest

import main as agent_main
from main import SysManageAgent


@pytest.fixture
def agent(tmp_path):
    """A bare SysManageAgent (no __init__) with a stub config + logger."""
    inst = object.__new__(SysManageAgent)
    inst.logger = MagicMock()
    inst._logging_overrides = {}
    cfg = MagicMock()
    cfg.get_log_level.return_value = "INFO"
    cfg.get_log_file.return_value = str(tmp_path / "agent.log")
    cfg.get_log_native.return_value = False
    cfg.get_log_native_target.return_value = "auto"
    cfg.get_log_native_identifier.return_value = "sysmanage-agent"
    inst.config = cfg
    return inst


@pytest.fixture(autouse=True)
def _restore_root_logging():
    """Save/restore root logger state so these tests don't leak globally."""
    root = logging.getLogger()
    saved = root.handlers[:]
    saved_level = root.level
    yield
    for handler in root.handlers[:]:
        handler.close()
        root.removeHandler(handler)
    for handler in saved:
        root.addHandler(handler)
    root.setLevel(saved_level)


class TestApplyLoggingConfig:
    """Tests for SysManageAgent.apply_logging_config."""

    def test_stores_overrides_and_reconfigures(self, agent):
        """A pushed config is stored and setup_logging is re-run."""
        with patch.object(agent, "setup_logging") as setup_m:
            agent.apply_logging_config({"log_level": "DEBUG"})
        assert agent._logging_overrides == {"log_level": "DEBUG"}
        setup_m.assert_called_once()

    def test_non_dict_ignored(self, agent):
        """A non-dict payload is ignored (no crash, no reconfigure)."""
        with patch.object(agent, "setup_logging") as setup_m:
            agent.apply_logging_config(None)
        setup_m.assert_not_called()

    def test_level_override_wins_over_yaml(self, agent):
        """Override log level takes effect over the yaml config value."""
        agent.apply_logging_config({"log_level": "DEBUG", "native_enabled": False})
        assert logging.getLogger().level == logging.DEBUG

    def test_native_override_enables_handler(self, agent):
        """Override enabling native logging attaches the built handler."""
        fake = logging.StreamHandler()
        with patch.object(
            agent_main, "build_native_handler", return_value=fake
        ) as build_m:
            agent.apply_logging_config(
                {
                    "log_level": "INFO",
                    "native_enabled": True,
                    "native_target": "syslog",
                    "native_identifier": "sm",
                }
            )
        build_m.assert_called_once_with(target="syslog", identifier="sm")
        assert fake in logging.getLogger().handlers

    def test_yaml_used_when_no_override(self, agent):
        """With no overrides, setup_logging falls back to the yaml config."""
        agent._logging_overrides = {}
        agent.config.get_log_native.return_value = True
        agent.config.get_log_native_target.return_value = "journald"
        fake = logging.StreamHandler()
        with patch.object(
            agent_main, "build_native_handler", return_value=fake
        ) as build_m:
            agent.setup_logging()
        build_m.assert_called_once_with(target="journald", identifier="sysmanage-agent")
