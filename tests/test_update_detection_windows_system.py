"""
Tests for sysmanage_agent.collection.update_detection_windows_system.

The mixin shells out to PowerShell for Windows Update detection.  Mocked
at the subprocess level — exercises:

- _detect_windows_system_updates (success / ERROR: prefix / timeout / exception)
- _parse_windows_update_output (single update / list / null / invalid JSON)
- _classify_windows_update (security vs regular branches)
- _extract_category_text (list of dicts / string)
- _detect_windows_version_upgrades
"""

# pylint: disable=redefined-outer-name,protected-access
# pylint: disable=missing-class-docstring,missing-function-docstring

import json
import subprocess
from unittest.mock import MagicMock, patch

import pytest

from src.sysmanage_agent.collection.update_detection_windows_system import (
    WindowsSystemDetectorMixin,
)


@pytest.fixture
def detector():
    class _Bag(WindowsSystemDetectorMixin):
        def __init__(self):
            self.available_updates = []

        @staticmethod
        def _format_size_mb(num_bytes):
            return f"{num_bytes / (1024 * 1024):.1f} MB" if num_bytes else "0 MB"

    return _Bag()


def _completed(returncode=0, stdout="", stderr=""):
    proc = MagicMock(spec=subprocess.CompletedProcess)
    proc.returncode = returncode
    proc.stdout = stdout
    proc.stderr = stderr
    return proc


# ---------------------------------------------------------------------------
# _extract_category_text  (static helper)
# ---------------------------------------------------------------------------


class TestExtractCategoryText:
    def test_list_of_dicts(self):
        cats = [{"Name": "Security Updates"}, {"Name": "Critical Updates"}]
        text = WindowsSystemDetectorMixin._extract_category_text(cats)
        assert "security" in text
        assert "critical" in text

    def test_list_of_strings(self):
        text = WindowsSystemDetectorMixin._extract_category_text(["Drivers"])
        assert "drivers" in text

    def test_string_passthrough(self):
        text = WindowsSystemDetectorMixin._extract_category_text("Updates")
        assert text == "updates"


# ---------------------------------------------------------------------------
# _classify_windows_update — security vs regular
# ---------------------------------------------------------------------------


class TestClassifyWindowsUpdate:
    def test_security_category_is_security(self, detector):
        entry = detector._classify_windows_update(
            {
                "Title": "Patch Tuesday",
                "Categories": [{"Name": "Security Updates"}],
                "SeverityText": "Important",
            }
        )
        assert entry["update_type"] == "security"

    def test_critical_severity_is_security(self, detector):
        entry = detector._classify_windows_update(
            {
                "Title": "Random patch",
                "Categories": [{"Name": "Drivers"}],
                "SeverityText": "Critical",
            }
        )
        assert entry["update_type"] == "security"

    def test_kb_in_title_is_security(self, detector):
        entry = detector._classify_windows_update(
            {
                "Title": "KB1234567 update",
                "Categories": [],
                "SeverityText": "Low",
            }
        )
        assert entry["update_type"] == "security"

    def test_plain_update_is_regular(self, detector):
        entry = detector._classify_windows_update(
            {
                "Title": "Driver Update for Acme",
                "Categories": [{"Name": "Drivers"}],
                "SeverityText": "Low",
            }
        )
        assert entry["update_type"] == "regular"

    def test_includes_revision_number_in_available_version(self, detector):
        entry = detector._classify_windows_update(
            {
                "Title": "x",
                "RevisionNumber": 42,
                "Categories": [],
                "SeverityText": "Low",
            }
        )
        assert "Rev.42" in entry["available_version"]


# ---------------------------------------------------------------------------
# _parse_windows_update_output
# ---------------------------------------------------------------------------


class TestParseWindowsUpdateOutput:
    def test_null_output_yields_no_updates(self, detector):
        detector._parse_windows_update_output("null")
        assert detector.available_updates == []

    def test_single_dict_wrapped_into_list(self, detector):
        single = {
            "Title": "KB123",
            "RevisionNumber": 1,
            "Categories": [{"Name": "Security Updates"}],
            "SeverityText": "Important",
            "Description": "test",
            "SizeInBytes": 1024,
            "IsDownloaded": False,
            "UpdateID": "u-1",
        }
        detector._parse_windows_update_output(json.dumps(single))
        assert len(detector.available_updates) == 1
        assert detector.available_updates[0]["update_type"] == "security"

    def test_list_of_updates_all_appended(self, detector):
        updates = [
            {
                "Title": f"Update {i}",
                "RevisionNumber": i,
                "Categories": [],
                "SeverityText": "Low",
                "Description": "",
                "SizeInBytes": 0,
                "IsDownloaded": False,
                "UpdateID": f"u-{i}",
            }
            for i in range(3)
        ]
        detector._parse_windows_update_output(json.dumps(updates))
        assert len(detector.available_updates) == 3

    def test_invalid_json_logged_silently(self, detector):
        # Must not raise.
        detector._parse_windows_update_output("<<not-json>>")
        assert detector.available_updates == []


# ---------------------------------------------------------------------------
# _detect_windows_system_updates orchestration
# ---------------------------------------------------------------------------


class TestDetectWindowsSystemUpdates:
    def test_returncode_nonzero_returns_silently(self, detector):
        with patch.object(
            detector,
            "_run_windows_update_query",
            return_value=_completed(1, stdout=""),
        ):
            detector._detect_windows_system_updates()
        assert detector.available_updates == []

    def test_empty_stdout_returns_silently(self, detector):
        with patch.object(
            detector,
            "_run_windows_update_query",
            return_value=_completed(0, stdout=""),
        ):
            detector._detect_windows_system_updates()
        assert detector.available_updates == []

    def test_error_prefix_logs_warning(self, detector):
        with patch.object(
            detector,
            "_run_windows_update_query",
            return_value=_completed(0, stdout="ERROR: WUApi blew up"),
        ):
            # Doesn't raise; available_updates remains empty.
            detector._detect_windows_system_updates()
        assert detector.available_updates == []

    def test_happy_path_appends_updates(self, detector):
        single = {
            "Title": "KB456",
            "RevisionNumber": 1,
            "Categories": [{"Name": "Security Updates"}],
            "SeverityText": "Critical",
            "Description": "",
            "SizeInBytes": 0,
            "IsDownloaded": False,
            "UpdateID": "u",
        }
        with patch.object(
            detector,
            "_run_windows_update_query",
            return_value=_completed(0, stdout=json.dumps(single)),
        ):
            detector._detect_windows_system_updates()
        assert len(detector.available_updates) == 1

    def test_timeout_logged_silently(self, detector):
        with patch.object(
            detector,
            "_run_windows_update_query",
            side_effect=subprocess.TimeoutExpired(cmd="ps", timeout=120),
        ):
            detector._detect_windows_system_updates()

    def test_unexpected_exception_logged_silently(self, detector):
        with patch.object(
            detector,
            "_run_windows_update_query",
            side_effect=RuntimeError("crash"),
        ):
            detector._detect_windows_system_updates()


# ---------------------------------------------------------------------------
# _run_windows_update_query — non-Windows path
# ---------------------------------------------------------------------------


class TestRunWindowsUpdateQuery:
    def test_invokes_powershell_with_no_creation_flags_off_windows(self, detector):
        with patch(
            "src.sysmanage_agent.collection.update_detection_windows_system.platform.system",
            return_value="Linux",
        ), patch(
            "src.sysmanage_agent.collection.update_detection_windows_system.subprocess.run",
            return_value=_completed(0, stdout="null"),
        ) as run:
            detector._run_windows_update_query()
        # creationflags should be 0 on non-Windows
        assert run.call_args.kwargs.get("creationflags") == 0


# ---------------------------------------------------------------------------
# _detect_windows_version_upgrades
# ---------------------------------------------------------------------------


class TestDetectWindowsVersionUpgrades:
    def test_no_output_returns_silently(self, detector):
        with patch(
            "src.sysmanage_agent.collection.update_detection_windows_system.subprocess.run",
            return_value=_completed(0, stdout=""),
        ):
            detector._detect_windows_version_upgrades()
        assert detector.available_updates == []

    def test_subprocess_error_logged_silently(self, detector):
        with patch(
            "src.sysmanage_agent.collection.update_detection_windows_system.subprocess.run",
            side_effect=RuntimeError("ps died"),
        ):
            detector._detect_windows_version_upgrades()
