# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""``make release`` shows the current and next version and asks first.

Pushing the tag publishes, so an explicit "y" is the only way through; Enter,
"n" or no terminal stop it with nothing changed.  Git is never called here:
the tag lookup and the guards are stubbed.
"""

import importlib.util
import sys
from pathlib import Path

import pytest

_SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "release.py"


@pytest.fixture
def release(monkeypatch):
    spec = importlib.util.spec_from_file_location("release_under_test", _SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.setattr(module, "known_tags", lambda: {(3, 9, 0, 26), (3, 8, 0, 4)})
    monkeypatch.setattr(module, "check_guards", lambda *a: None)

    def must_not_bump(*_a, **_k):
        raise AssertionError("bumped without confirmation")

    monkeypatch.setattr(module, "bump_markers", must_not_bump)
    return module


def _run(release, monkeypatch, argv, answer=None, tty=True):
    monkeypatch.setattr(sys, "argv", ["release.py", *argv])
    monkeypatch.setattr(sys.stdin, "isatty", lambda: tty)
    if answer is not None:
        monkeypatch.setattr("builtins.input", lambda _prompt: answer)
    return release.main()


@pytest.mark.parametrize("answer", ["", "n", "no", "maybe"])
def test_anything_but_yes_stops_with_nothing_changed(
    release, monkeypatch, capsys, answer
):
    assert _run(release, monkeypatch, [], answer=answer) == 0
    out = capsys.readouterr().out
    assert "Current version:  v3.9.0.26" in out
    assert "Next version:     v3.9.0.27  (auto-increment)" in out
    assert "Stopped; nothing was changed." in out


def test_an_explicit_version_is_confirmed_too(release, monkeypatch, capsys):
    assert _run(release, monkeypatch, ["--version", "3.10.0.0"], answer="n") == 0
    out = capsys.readouterr().out
    assert "Next version:     v3.10.0.0  (explicit)" in out


def test_an_explicit_version_below_the_current_one_is_flagged(
    release, monkeypatch, capsys
):
    _run(release, monkeypatch, ["--version", "3.9.0.1"], answer="n")
    assert "is not above the current v3.9.0.26" in capsys.readouterr().out


def test_no_terminal_and_no_yes_refuses(release, monkeypatch, capsys):
    assert _run(release, monkeypatch, [], tty=False) == 1
    assert "Pass YES=1 to release unattended." in capsys.readouterr().err
