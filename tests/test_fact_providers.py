# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""Tests for the fact provider bootstrap — Phase 21.1 S3.

The bug this file exists to prevent is a QUIET one.  An unbootstrapped
registry does not raise: ``build_fact_coverage`` truthfully reports that no
provider is registered, and the host advertises no facts at all while every
collector on it works perfectly.  So the first test asserts the wiring itself
-- that building a capability report registers the providers -- because that
is the step whose absence looks exactly like success.
"""

import json
from unittest.mock import patch

import pytest

from src.sysmanage_agent.collection import fact_osquery as fo
from src.sysmanage_agent.collection import fact_providers as fp
from src.sysmanage_agent.core import fact_schema as fs
from src.sysmanage_agent.core.capabilities import build_capability_report


class Config:
    """Minimal ConfigManager stand-in: dotted key, default."""

    def __init__(self, **values):
        self._values = values

    def get(self, key_path, default=None):
        return self._values.get(key_path, default)


class BrokenConfig:
    def get(self, key_path, default=None):
        raise RuntimeError("config not loaded yet")


@pytest.fixture(autouse=True)
def clean_registry():
    fs.clear_providers()
    fo.reset_cache()
    fp._bootstrapped = False  # pylint: disable=protected-access
    yield
    fs.clear_providers()
    fo.reset_cache()
    fp._bootstrapped = False  # pylint: disable=protected-access


HANDLERS = {"get_system_info": lambda: None}


def test_building_a_report_bootstraps_the_providers():
    """The wiring test.  Without it the agent advertises zero fact tables and
    nothing anywhere fails."""
    report = build_capability_report(HANDLERS)
    assert report["facts"]["served"], "capability report advertised no fact tables"


def test_native_is_registered_without_any_config():
    fp.bootstrap_fact_providers(None)
    assert fs.PROVIDER_NATIVE in fs.registered_providers("os_version")


def test_osquery_is_off_unless_asked_for():
    """Installed is not chosen: a host that happens to have osquery keeps the
    native provider until an operator opts in."""
    with patch.object(fo.shutil, "which", return_value="/usr/bin/osqueryi"):
        fp.bootstrap_fact_providers(Config())
    assert fs.registered_providers("users") == (fs.PROVIDER_NATIVE,)


def test_opting_in_registers_osquery_alongside_native():
    rows = json.dumps([{"name": "users"}])
    with patch.object(fo.shutil, "which", return_value="/usr/bin/osqueryi"):
        with patch.object(fo.subprocess, "run", lambda *a, **k: _completed(rows)):
            fp.bootstrap_fact_providers(Config(**{fp.OSQUERY_ENABLED_KEY: True}))
    assert fs.registered_providers("users") == (
        fs.PROVIDER_OSQUERY,
        fs.PROVIDER_NATIVE,
    )
    # And the table osquery did NOT report stays native-only.
    assert fs.registered_providers("os_version") == (fs.PROVIDER_NATIVE,)


def _completed(stdout):
    import subprocess  # pylint: disable=import-outside-toplevel

    return subprocess.CompletedProcess(["osqueryi"], 0, stdout=stdout, stderr="")


def test_a_config_that_cannot_answer_means_the_floor_not_a_crash():
    """Some call paths build a report before config is loaded.  'I don't know'
    reads as native, never as an exception that costs the whole report."""
    fp.bootstrap_fact_providers(BrokenConfig())
    assert fs.registered_providers("os_version") == (fs.PROVIDER_NATIVE,)


def test_bootstrap_is_idempotent():
    """The report is built on two paths; re-probing osquery on each would put
    a subprocess launch behind every capability query."""
    with patch.object(
        fp.fact_native,
        "register_native_provider",
        side_effect=fp.fact_native.register_native_provider,
    ) as register:
        fp.bootstrap_fact_providers(None)
        fp.bootstrap_fact_providers(None)
        fp.bootstrap_fact_providers(None)
    assert register.call_count == 1


def test_force_re_runs_it_for_a_flipped_opt_in():
    fp.bootstrap_fact_providers(Config())
    assert fs.registered_providers("users") == (fs.PROVIDER_NATIVE,)
    rows = json.dumps([{"name": "users"}])
    with patch.object(fo.shutil, "which", return_value="/usr/bin/osqueryi"):
        with patch.object(fo.subprocess, "run", lambda *a, **k: _completed(rows)):
            fp.bootstrap_fact_providers(
                Config(**{fp.OSQUERY_ENABLED_KEY: True}), force=True
            )
    assert fs.PROVIDER_OSQUERY in fs.registered_providers("users")


def test_a_cleared_registry_is_re_bootstrapped_not_left_empty():
    """The flag alone would go stale here.

    Anything that clears the registry after a bootstrap -- a test, a reload --
    would otherwise leave the flag saying "done" while nothing is registered,
    and the next capability report would advertise a host with no facts at all
    while every collector on it works. Silent, and wrong in the direction that
    looks like success.
    """
    fp.bootstrap_fact_providers(None)
    assert fs.has_providers()

    fs.clear_providers()
    assert not fs.has_providers()

    fp.bootstrap_fact_providers(None)
    assert fs.registered_providers("os_version") == (fs.PROVIDER_NATIVE,)
