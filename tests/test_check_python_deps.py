# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""scripts/check_python_deps.py: the environment meets the requirements files,
and pip-audit exceptions are reviewed decisions (a reason, optional expiry)."""

import datetime as dt
import importlib.util
from importlib import metadata
from pathlib import Path

import pytest

_SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "check_python_deps.py"
_PYTEST = metadata.version("pytest")


@pytest.fixture(scope="module")
def deps():
    spec = importlib.util.spec_from_file_location("check_python_deps", _SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _req(tmp_path, name, text):
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    return path


def test_a_satisfied_requirement_passes(deps, tmp_path):
    path = _req(tmp_path, "r.txt", f"pytest>={_PYTEST}  # comment\n")
    assert deps.stale_requirements([path]) == []


def test_a_raised_floor_the_venv_misses_is_reported(deps, tmp_path):
    path = _req(tmp_path, "r.txt", "pytest>=999.0\n")
    (problem,) = deps.stale_requirements([path])
    assert problem.startswith(f"pytest: {_PYTEST} installed")


def test_a_version_above_a_cap_is_reported_too(deps, tmp_path):
    path = _req(tmp_path, "r.txt", "pytest<1.0\n")
    assert deps.stale_requirements([path])


def test_a_missing_package_is_reported(deps, tmp_path):
    path = _req(tmp_path, "r.txt", "no-such-package-sysmanage>=1\n")
    (problem,) = deps.stale_requirements([path])
    assert "not installed" in problem


def test_markers_for_other_environments_are_skipped(deps, tmp_path):
    path = _req(tmp_path, "r.txt", "pytest>=999.0; python_version < '3.0'\n")
    assert deps.stale_requirements([path]) == []


def test_includes_are_followed(deps, tmp_path):
    _req(tmp_path, "base.txt", "pytest>=999.0\n")
    path = _req(tmp_path, "dev.txt", "-r base.txt\n--index-url https://example\n")
    assert len(deps.stale_requirements([path])) == 1


def _ignore(tmp_path, body):
    return _req(tmp_path, ".pip-audit-ignore.yml", body)


def test_a_reasoned_ignore_is_honored(deps, tmp_path):
    path = _ignore(tmp_path, "vulnerabilities:\n  - id: CVE-1\n    reason: x\n")
    assert deps.load_ignores(path) == (["CVE-1"], [])


def test_an_ignore_without_a_reason_is_refused(deps, tmp_path):
    path = _ignore(tmp_path, "vulnerabilities:\n  - id: CVE-1\n")
    ids, problems = deps.load_ignores(path)
    assert ids == [] and "no reason" in problems[0]


def test_an_expired_ignore_fails(deps, tmp_path):
    path = _ignore(
        tmp_path,
        "vulnerabilities:\n  - id: CVE-1\n    reason: x\n    expires: 2026-01-01\n",
    )
    ids, problems = deps.load_ignores(path, today=dt.date(2026, 6, 1))
    assert ids == [] and "expired on 2026-01-01" in problems[0]


def test_an_unexpired_ignore_is_honored(deps, tmp_path):
    path = _ignore(
        tmp_path,
        "vulnerabilities:\n  - id: CVE-1\n    reason: x\n    expires: 2026-12-31\n",
    )
    assert deps.load_ignores(path, today=dt.date(2026, 6, 1)) == (["CVE-1"], [])


def test_no_ignore_file_means_no_ignores(deps, tmp_path):
    assert deps.load_ignores(tmp_path / "absent.yml") == ([], [])


def test_every_repository_ignore_file_is_valid(deps):
    """The checked-in exceptions themselves pass the rules."""
    _ids, problems = deps.load_ignores(_SCRIPT.parents[1] / ".pip-audit-ignore.yml")
    assert problems == []
