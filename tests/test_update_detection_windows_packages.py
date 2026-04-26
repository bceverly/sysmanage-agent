"""
Tests for sysmanage_agent.collection.update_detection_windows_packages.

The mixin parses winget/choco/scoop output via column-positional logic.
Mocked at the subprocess level — the parsing helpers are exercised both
directly (pure-text parsing) and through the orchestration methods.
"""

# pylint: disable=redefined-outer-name,protected-access
# pylint: disable=missing-class-docstring,missing-function-docstring

import subprocess
from unittest.mock import MagicMock, patch

import pytest

from src.sysmanage_agent.collection.update_detection_windows_packages import (
    WindowsPackageDetectorMixin,
)


@pytest.fixture
def detector():
    class _Bag(WindowsPackageDetectorMixin):
        def __init__(self):
            self.available_updates = []

    return _Bag()


def _completed(returncode=0, stdout="", stderr=""):
    proc = MagicMock(spec=subprocess.CompletedProcess)
    proc.returncode = returncode
    proc.stdout = stdout
    proc.stderr = stderr
    return proc


# ---------------------------------------------------------------------------
# Header parsing
# ---------------------------------------------------------------------------


WINGET_HEADER = (
    "Name                Id                       Version    Available  Source\n"
    "------------------------------------------------------------------------\n"
)
WINGET_LINE = (
    "PowerToys           Microsoft.PowerToys      0.74.0     0.75.0     winget\n"
)


class TestParseWingetHeader:
    def test_parses_full_header(self, detector):
        cols, idx = detector._parse_winget_header(WINGET_HEADER.split("\n"))
        assert cols is not None
        assert cols["name_start"] == 0
        assert cols["id_start"] > cols["name_start"]
        assert cols["version_start"] > cols["id_start"]
        # Header line + separator line skipped.
        assert idx == 2

    def test_returns_none_when_no_header(self, detector):
        cols, idx = detector._parse_winget_header(["random text", "more"])
        assert cols is None
        assert idx == 0


# ---------------------------------------------------------------------------
# Field extraction helpers
# ---------------------------------------------------------------------------


class TestFieldExtraction:
    def test_extract_field_by_range_in_bounds(self, detector):
        result = detector._extract_field_by_range("hello world", 0, 5)
        assert result == "hello"

    def test_extract_field_by_range_to_end_of_line(self, detector):
        result = detector._extract_field_by_range("foo bar baz", 4, -1)
        # End-of-line extraction takes the first whitespace-separated token.
        assert result == "bar"

    def test_extract_field_by_range_empty_returns_default(self, detector):
        result = detector._extract_field_by_range("foo   ", 6, -1, default="dflt")
        assert result == "dflt"


# ---------------------------------------------------------------------------
# Line parsing — column-aware and fallback
# ---------------------------------------------------------------------------


class TestParseWingetLine:
    def test_parses_well_formed_line(self, detector):
        cols, _ = detector._parse_winget_header(WINGET_HEADER.split("\n"))
        result = detector._parse_winget_line_by_columns(WINGET_LINE.rstrip(), cols)
        assert result["package_name"] == "PowerToys"
        assert result["bundle_id"] == "Microsoft.PowerToys"
        assert result["current_version"] == "0.74.0"
        assert result["available_version"] == "0.75.0"

    def test_falls_back_when_id_before_name(self, detector):
        # Synthetic broken cols → fallback to whitespace split.
        bad_cols = {
            "name_start": 10,
            "id_start": 0,  # earlier than name → triggers fallback
            "version_start": 20,
            "available_start": 30,
            "source_start": 40,
        }
        result = detector._parse_winget_line_by_columns("pkg-a id-a 1.0 2.0", bad_cols)
        assert result["package_name"] == "pkg-a"

    def test_fallback_returns_none_on_one_token(self, detector):
        assert detector._parse_winget_line_fallback("just-one-thing") is None


# ---------------------------------------------------------------------------
# _process_winget_update_line — early-return arms
# ---------------------------------------------------------------------------


class TestProcessWingetUpdateLine:
    def test_appends_real_update(self, detector):
        cols, _ = detector._parse_winget_header(WINGET_HEADER.split("\n"))
        detector._process_winget_update_line(WINGET_LINE.rstrip(), cols)
        assert len(detector.available_updates) == 1
        assert detector.available_updates[0]["package_manager"] == "winget"

    def test_skips_when_available_equals_current(self, detector):
        cols, _ = detector._parse_winget_header(WINGET_HEADER.split("\n"))
        # Same version in current and available → no update needed.
        same_line = (
            "PowerToys           Microsoft.PowerToys      0.75.0     0.75.0     winget"
        )
        detector._process_winget_update_line(same_line, cols)
        assert detector.available_updates == []

    def test_skips_unparseable_line(self, detector):
        cols, _ = detector._parse_winget_header(WINGET_HEADER.split("\n"))
        # Empty line should be skipped silently.
        detector._process_winget_update_line("", cols)
        assert detector.available_updates == []


# ---------------------------------------------------------------------------
# _detect_winget_updates — orchestration
# ---------------------------------------------------------------------------


class TestDetectWingetUpdates:
    def test_subprocess_failure_returns_silently(self, detector):
        with patch(
            "src.sysmanage_agent.collection.update_detection_windows_packages.subprocess.run",
            return_value=_completed(1, stderr="winget missing"),
        ):
            detector._detect_winget_updates()
        assert detector.available_updates == []

    def test_no_header_returns_silently(self, detector):
        with patch(
            "src.sysmanage_agent.collection.update_detection_windows_packages.subprocess.run",
            return_value=_completed(0, stdout="random output\nno header here"),
        ):
            detector._detect_winget_updates()
        assert detector.available_updates == []

    def test_happy_path_with_one_update(self, detector):
        output = WINGET_HEADER + WINGET_LINE
        with patch(
            "src.sysmanage_agent.collection.update_detection_windows_packages.subprocess.run",
            return_value=_completed(0, stdout=output),
        ):
            detector._detect_winget_updates()
        assert len(detector.available_updates) == 1

    def test_skips_marketing_lines(self, detector):
        output = (
            WINGET_HEADER
            + WINGET_LINE
            + "\n"
            + "12 upgrades available.\n"
            + "No applicable updates.\n"
        )
        with patch(
            "src.sysmanage_agent.collection.update_detection_windows_packages.subprocess.run",
            return_value=_completed(0, stdout=output),
        ):
            detector._detect_winget_updates()
        # Marketing lines are filtered.
        assert len(detector.available_updates) == 1

    def test_subprocess_exception_logged_silently(self, detector):
        with patch(
            "src.sysmanage_agent.collection.update_detection_windows_packages.subprocess.run",
            side_effect=RuntimeError("winget exploded"),
        ):
            # Must not raise.
            detector._detect_winget_updates()


# ---------------------------------------------------------------------------
# _detect_chocolatey_updates
# ---------------------------------------------------------------------------


class TestDetectChocolateyUpdates:
    def test_parses_pipe_separated_output(self, detector):
        # choco outdated -r format: pkg|cur|new|pinned
        output = "git|2.40|2.42|false\nnodejs|18.0|20.0|false\n"
        with patch(
            "src.sysmanage_agent.collection.update_detection_windows_packages.subprocess.run",
            return_value=_completed(0, stdout=output),
        ):
            detector._detect_chocolatey_updates()
        assert len(detector.available_updates) == 2
        assert {u["package_name"] for u in detector.available_updates} == {
            "git",
            "nodejs",
        }

    def test_short_lines_are_skipped(self, detector):
        output = "git|2.40|2.42|false\nbroken|incomplete\n"
        with patch(
            "src.sysmanage_agent.collection.update_detection_windows_packages.subprocess.run",
            return_value=_completed(0, stdout=output),
        ):
            detector._detect_chocolatey_updates()
        assert len(detector.available_updates) == 1

    def test_subprocess_exception_logged(self, detector):
        with patch(
            "src.sysmanage_agent.collection.update_detection_windows_packages.subprocess.run",
            side_effect=RuntimeError("choco died"),
        ):
            detector._detect_chocolatey_updates()


# ---------------------------------------------------------------------------
# _detect_scoop_updates
# ---------------------------------------------------------------------------


class TestDetectScoopUpdates:
    def test_parses_update_line(self, detector):
        # The scoop parser fires on lines containing both ":" and "Update".
        output = "git: Update available -> 2.42\nnpm: Status OK\n"
        with patch(
            "src.sysmanage_agent.collection.update_detection_windows_packages.subprocess.run",
            return_value=_completed(0, stdout=output),
        ):
            detector._detect_scoop_updates()
        # One match — git:Update.
        assert any(u["package_name"] == "git:" for u in detector.available_updates)

    def test_subprocess_exception_logged(self, detector):
        with patch(
            "src.sysmanage_agent.collection.update_detection_windows_packages.subprocess.run",
            side_effect=RuntimeError("scoop died"),
        ):
            detector._detect_scoop_updates()


# ---------------------------------------------------------------------------
# _detect_microsoft_store_updates — placeholder
# ---------------------------------------------------------------------------


class TestDetectMicrosoftStoreUpdates:
    def test_just_logs(self, detector):
        # Placeholder — no side effects expected.
        detector._detect_microsoft_store_updates()
        assert detector.available_updates == []
