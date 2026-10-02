# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""Server Phase 22.2: the agent fingerprints the logging config it runs with
so the server can skip re-pushing an unchanged one on every reconnect."""

from src.sysmanage_agent.core.logging_digest import config_digest

# Pinned: the server's logging_config_service.config_digest must produce the
# same value for the same config, or every reconnect would push again.
SAMPLE = {"log_level": "INFO", "native_enabled": True, "native_target": "syslog"}
SAMPLE_DIGEST = "560e87ee45f64103171ff86cc6d4a4bfcb10087ddcb909f5ae6b30a0ba676791"


def test_nothing_pushed_means_no_fingerprint():
    assert config_digest({}) is None
    assert config_digest(None) is None


def test_key_order_does_not_matter():
    reordered = dict(reversed(list(SAMPLE.items())))
    assert config_digest(SAMPLE) == config_digest(reordered)


def test_any_change_changes_it():
    assert config_digest(SAMPLE) != config_digest({**SAMPLE, "log_level": "DEBUG"})


def test_the_value_matches_the_servers():
    assert config_digest(SAMPLE) == SAMPLE_DIGEST
