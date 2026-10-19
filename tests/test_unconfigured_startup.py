# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""A freshly installed agent must not hammer ``sysmanage.example.com``.

The deb/rpm packages start the service with the example config; until the
operator sets a real server the agent explains what to edit and either exits
EX_CONFIG (systemd, whose units carry RestartPreventExitStatus=78) or waits
quietly and restarts itself once the file is fixed (2026-10-17)."""

import logging
from pathlib import Path

import pytest

from src.sysmanage_agent.core import unconfigured as uc


class _Config:
    def __init__(self, server, config_file="/etc/sysmanage-agent.yaml"):
        self._server = server
        self.config_file = config_file

    def get_server_config(self):
        return self._server


@pytest.mark.parametrize(
    "server",
    [
        {},
        {"url": ""},
        {"url": "https://sysmanage.example.com"},
        {"url": "wss://sysmanage.example.com:8443"},
        {"url": "https://example.org"},
        {"hostname": "server.example.net", "port": 443},
        {"url": "https://box.invalid"},
    ],
)
def test_placeholder_or_missing_server_is_unconfigured(server):
    assert uc.unconfigured_reason(_Config(server))


@pytest.mark.parametrize(
    "server",
    [
        {"url": "https://sysmanage.theeverlys.com"},
        {"url": "http://localhost:8080"},
        {"hostname": "192.168.4.132", "port": 8080},
        {"url": "https://notexample.com"},  # a real domain that merely ends in it
    ],
)
def test_a_real_server_is_configured(server):
    assert uc.unconfigured_reason(_Config(server)) is None


def test_under_systemd_it_exits_ex_config_with_the_fix_in_the_log(caplog, capsys):
    with caplog.at_level(logging.ERROR), pytest.raises(SystemExit) as exc:
        uc.ensure_configured(
            _Config({"url": "https://sysmanage.example.com"}),
            logging.getLogger("t"),
            under_systemd=True,
        )
    assert exc.value.code == uc.EX_CONFIG == 78
    assert "server.url" in caplog.text and "/etc/sysmanage-agent.yaml" in caplog.text
    assert "server.url" in capsys.readouterr().err


def test_elsewhere_it_waits_then_restarts_once_configured(tmp_path, monkeypatch):
    config_file = tmp_path / "sysmanage-agent.yaml"
    config_file.write_text("server:\n  url: https://sysmanage.example.com\n")
    naps = []
    restarted = []

    def nap(seconds):
        naps.append(seconds)
        if len(naps) == 2:  # the operator fixes the file during the wait
            config_file.write_text("server:\n  url: https://sysmanage.corp.lan\n")

    monkeypatch.setattr(uc.os, "name", "posix")
    from src.sysmanage_agent.core.config import ConfigManager

    uc.ensure_configured(
        ConfigManager(str(config_file)),
        logging.getLogger("t"),
        under_systemd=False,
        sleep=nap,
        restart=lambda: restarted.append(True),
    )
    assert restarted == [True]
    assert naps == [uc.RECHECK_SECONDS, uc.RECHECK_SECONDS]


def test_a_configured_agent_starts_without_delay():
    uc.ensure_configured(
        _Config({"url": "https://sysmanage.corp.lan"}),
        logging.getLogger("t"),
        under_systemd=True,
        sleep=lambda _s: pytest.fail("must not wait"),
    )


@pytest.mark.parametrize("distro", ["ubuntu", "centos", "opensuse"])
def test_every_systemd_unit_stops_restarting_on_ex_config(distro):
    unit = (
        Path(__file__).resolve().parents[1]
        / "installer"
        / distro
        / "sysmanage-agent.service"
    )
    assert "RestartPreventExitStatus=78" in unit.read_text(encoding="utf-8")


def test_reexec_restarts_the_entry_script_and_nothing_else(tmp_path, monkeypatch):
    """The restart command is the interpreter plus the entry script: never the
    old command line, which let untrusted input reach exec (Semgrep #168)."""
    import sys
    import types

    script = tmp_path / "main.py"
    script.write_text("pass\n")
    monkeypatch.setitem(
        sys.modules, "__main__", types.SimpleNamespace(__file__=str(script))
    )
    monkeypatch.setattr(sys, "argv", [str(script), "--evil", "$(reboot)"])
    calls = []
    monkeypatch.setattr(uc.os, "execv", lambda path, argv: calls.append((path, argv)))
    uc._reexec()  # pylint: disable=protected-access
    assert len(calls) == 1
    path, argv = calls[0]
    assert argv == [path, str(script.resolve())]
    assert "--evil" not in argv


def test_reexec_refuses_when_the_entry_script_is_not_a_python_file(
    tmp_path, monkeypatch
):
    import sys
    import types

    monkeypatch.setitem(sys.modules, "__main__", types.SimpleNamespace(__file__=None))
    with pytest.raises(RuntimeError):
        uc._reexec_argv()  # pylint: disable=protected-access
    bogus = tmp_path / "main.sh"
    bogus.write_text("")
    monkeypatch.setitem(
        sys.modules, "__main__", types.SimpleNamespace(__file__=str(bogus))
    )
    with pytest.raises(RuntimeError):
        uc._reexec_argv()  # pylint: disable=protected-access
