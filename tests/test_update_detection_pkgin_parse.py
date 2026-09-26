# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""
Unit tests for pkgsrc ``name-version`` splitting in the pkgin mixin.

The split used to be the regex ``^(.+)-(\\d[^\\s]*)$``, which backtracks
super-linearly on a long token with many hyphens. These tests pin the linear
replacement to exactly what that regex matched and captured.
"""

# pylint: disable=protected-access

import re
import time
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from src.sysmanage_agent.collection.update_detection_pkgin import PkginUpdateMixin

_ORIGINAL_REGEX = re.compile(r"^(.+)-(\d[^\s]*)$")

_SPLIT = PkginUpdateMixin._split_pkgsrc_name_version


def _regex_split(token):
    match = _ORIGINAL_REGEX.match(token)
    return (match.group(1), match.group(2)) if match else None


@pytest.mark.parametrize(
    "token,expected",
    [
        ("gcc12-libs-12.5.0nb4", ("gcc12-libs", "12.5.0nb4")),
        ("curl-8.9.1", ("curl", "8.9.1")),
        ("-1.0", None),
        ("curl", None),
        ("curl-", None),
        ("curl-abc", None),
        ("", None),
        ("a-1 b", None),
        ("a b-1", ("a b", "1")),
        ("a\nb-1", None),
        ("curl-1.0\n", ("curl", "1.0")),
        ("a--1", ("a-", "1")),
        ("x-1-y-2-z", ("x-1-y", "2-z")),
    ],
)
def test_split_matches_original_regex(token, expected):
    """Each case agrees with the regex it replaced (and with the stated value)."""
    got = _SPLIT(token)
    assert got == _regex_split(token)
    if expected is not None:
        assert got == expected


def test_split_last_digit_hyphen_wins():
    """pkgsrc versions start at the LAST hyphen followed by a digit."""
    assert _SPLIT("py311-foo-bar-1.0-rc1") == ("py311-foo-bar", "1.0-rc1")


def test_split_agrees_with_regex_on_generated_tokens():
    """An exhaustive sweep over short tokens from a tricky alphabet."""
    alphabet = ["-", "a", "1", " ", "\n", "\u0663", "\u00b2"]
    tokens = [""]
    for _ in range(5):
        tokens = [token + char for token in tokens for char in alphabet]
        for token in tokens:
            assert _SPLIT(token) == _regex_split(token), repr(token)


@pytest.mark.parametrize(
    "token",
    [
        "a-" * 50000 + " ",
        "-" * 100000 + "x",
        "a-" * 50000,
    ],
)
def test_split_is_linear_on_pathological_input(token):
    """Inputs that made the old regex backtrack quadratically return quickly."""
    start = time.monotonic()
    assert _SPLIT(token) is None
    assert time.monotonic() - start < 1.0


def test_parse_update_line_uses_split():
    """The upgrade-list parser builds its dict from the split."""
    update = PkginUpdateMixin._parse_pkgin_update_line(
        SimpleNamespace(_split_pkgsrc_name_version=_SPLIT), "  gcc12-libs-12.5.0nb4 "
    )
    assert update["package_name"] == "gcc12-libs"
    assert update["available_version"] == "12.5.0nb4"
    assert update["current_version"] is None
    assert update["package_manager"] == "pkgin"


@pytest.mark.parametrize("line", ["", "   ", "pkg_summary-1.0", "curl", None])
def test_parse_update_line_rejects(line):
    """Blank, pkg_summary and unsplittable lines are not updates."""
    stub = SimpleNamespace(_split_pkgsrc_name_version=_SPLIT)
    assert PkginUpdateMixin._parse_pkgin_update_line(stub, line) is None


def test_installed_versions_uses_split():
    """``pkgin list`` output is keyed by name with the pkgsrc version."""
    stdout = (
        "gcc12-libs-12.5.0nb4 The GNU Compiler Collection support libs\n"
        "curl-8.9.1 Command line tool for transferring data\n"
        "\n"
        "notaversion Something without a version\n"
    )
    result = SimpleNamespace(returncode=0, stdout=stdout)
    stub = SimpleNamespace(_split_pkgsrc_name_version=_SPLIT)
    with patch(
        "src.sysmanage_agent.collection.update_detection_pkgin.subprocess.run",
        return_value=result,
    ):
        installed = PkginUpdateMixin._pkgin_installed_versions(stub)
    assert installed == {"gcc12-libs": "12.5.0nb4", "curl": "8.9.1"}
