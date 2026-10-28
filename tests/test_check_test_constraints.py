# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""scripts/check_test_constraints.py: the test toolchain stays pinned."""

import importlib.util
from pathlib import Path

import pytest

SCRIPT = (
    Path(__file__).resolve().parent.parent / "scripts" / "check_test_constraints.py"
)


@pytest.fixture(scope="module")
def gate():
    spec = importlib.util.spec_from_file_location("check_test_constraints", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _workflow(tmp_path, body, name="ci.yml"):
    path = tmp_path / name
    path.write_text(body, encoding="utf-8")
    return path


def test_unconstrained_test_installs_are_found(gate, tmp_path):
    path = _workflow(
        tmp_path,
        "steps:\n"
        "  - run: |\n"
        "      pip install -r requirements.txt\n"
        "      python -m pip install pytest pytest-asyncio\n"
        "      DISABLE_X=1 python -m pip install \\\n"
        "        aiofiles pytest\n"
        "      pip install -c constraints-test.txt -r requirements-dev.txt\n"
        "      pip install --constraint=constraints-test.txt pytest\n"
        "      pip install -r requirements-prod.txt\n"
        "      pip install cyclonedx-bom bandit\n"
        "      # pip install pytest  (a comment)\n",
    )
    found = gate.unconstrained_installs(path)
    assert [number for number, _cmd in found] == [3, 4, 5]


def test_the_canary_is_exempt_and_the_repo_passes(gate, tmp_path, capsys):
    canary = _workflow(
        tmp_path, "run: pip install --upgrade pytest\n", name=gate.CANARY
    )
    assert gate.main([str(canary)]) == 0
    assert gate.main([]) == 0, capsys.readouterr().out


def test_a_failure_says_how_to_fix_it(gate, tmp_path, capsys):
    path = _workflow(tmp_path, "run: pip install pytest\n")
    assert gate.main([str(path)]) == 1
    out = capsys.readouterr().out
    assert "pip install without -c" in out and "1. Add '-c constraints-test.txt'" in out


def test_the_constraints_file_must_pin_pytest(gate, tmp_path):
    assert gate.constraints_problems(tmp_path) == ["constraints-test.txt is missing"]
    (tmp_path / gate.CONSTRAINTS).write_text("pytest==9.2.0\n", encoding="utf-8")
    assert gate.constraints_problems(tmp_path) == [
        "constraints-test.txt does not pin pytest-asyncio"
    ]


def test_sibling_copies_must_match(gate, tmp_path):
    for name, text in (("sysmanage", "a"), ("sysmanage-agent", "a"),
                       ("sysmanage-professional-plus", "b")):  # fmt: skip
        (tmp_path / name).mkdir()
        (tmp_path / name / gate.CONSTRAINTS).write_text(text, encoding="utf-8")
    assert gate.sibling_drift(tmp_path / "sysmanage") == ["sysmanage-professional-plus"]
