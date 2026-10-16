# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""An enrollment token in the wrong section must be reported, not silently
ignored: a hand-written config once nested it under ``script_execution``
and the host registered with no tenant."""

import logging

from src.sysmanage_agent.core.config import ConfigManager


def _config(data):
    config = ConfigManager.__new__(ConfigManager)
    config.logger = logging.getLogger("test_config_enrollment_token")
    config.config_data = data
    return config


def test_top_level_security_token_is_read_without_warning(caplog):
    config = _config({"security": {"enrollment_token": "sme_x"}})
    with caplog.at_level(logging.WARNING):
        assert config.get_enrollment_token() == "sme_x"
    assert not caplog.records


def test_nested_token_is_ignored_and_named(caplog):
    config = _config({"script_execution": {"security": {"enrollment_token": "sme_x"}}})
    with caplog.at_level(logging.WARNING):
        assert config.get_enrollment_token() is None
    assert "script_execution.security.enrollment_token" in caplog.text
    assert "sme_x" not in caplog.text


def test_no_token_anywhere_is_quiet(caplog):
    config = _config({"server": {"url": "https://example.com"}})
    with caplog.at_level(logging.WARNING):
        assert config.get_enrollment_token() is None
    assert not caplog.records
