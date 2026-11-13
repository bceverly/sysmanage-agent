# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""An update that includes sysmanage-agent itself must not kill its own
package manager (production, 2026-11-13): the package scripts stop or
restart the agent's unit, and systemd's default kill mode took apt and dpkg
with it, leaving the agent half-installed and stopped on six hosts."""

import configparser
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
LINUX_UNITS = sorted(ROOT.glob("installer/*/sysmanage-agent.service"))


def test_the_linux_units_were_found():
    assert {p.parent.name for p in LINUX_UNITS} >= {"ubuntu", "centos", "opensuse"}


@pytest.mark.parametrize("unit", LINUX_UNITS, ids=lambda p: p.parent.name)
def test_stopping_the_agent_leaves_its_package_manager_running(unit):
    parser = configparser.ConfigParser(strict=False, interpolation=None)
    parser.optionxform = str
    parser.read(unit, encoding="utf-8")
    assert parser["Service"].get("KillMode") == "process"
