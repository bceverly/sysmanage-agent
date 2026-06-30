"""Tests for Canonical Livepatch status collection (Ubuntu Pro, Phase 13.3)."""

# pylint: disable=redefined-outer-name,protected-access

import json
from unittest.mock import Mock, patch

import pytest

from src.sysmanage_agent.collection import os_info_collection
from src.sysmanage_agent.collection.os_info_collection import OSInfoCollector


@pytest.fixture
def collector():
    """Return an OSInfoCollector instance."""
    return OSInfoCollector()


_FULL = json.dumps(
    {
        "Client-Version": "10.6.1",
        "Architecture": "x86_64",
        "Last-Check": "2026-06-30T12:00:00Z",
        "Status": [
            {
                "Kernel": "5.15.0-101.111-generic",
                "Running": True,
                "Livepatch": {
                    "CheckState": "checked",
                    "State": "applied",
                    "Version": "97.1",
                    "Fixes": "* CVE-2026-1111\n* CVE-2026-2222",
                },
            }
        ],
    }
)


class TestParseLivepatchOutput:
    """Tests for OSInfoCollector._parse_livepatch_output."""

    def test_full_status(self, collector):
        """A complete status JSON is normalised with fixes split to a list."""
        out = collector._parse_livepatch_output(_FULL)
        assert out["enabled"] is True
        assert out["client_version"] == "10.6.1"
        assert out["kernel"] == "5.15.0-101.111-generic"
        assert out["patch_state"] == "applied"
        assert out["check_state"] == "checked"
        assert out["patch_version"] == "97.1"
        assert out["last_check"] == "2026-06-30T12:00:00Z"
        assert out["fixes"] == ["CVE-2026-1111", "CVE-2026-2222"]

    def test_list_fixes_and_non_running_fallback(self, collector):
        """List-form Fixes and a non-running kernel (fallback to first) work."""
        data = json.dumps(
            {
                "Client-Version": "9.0",
                "Status": [
                    {
                        "Kernel": "k1",
                        "Running": False,
                        "Livepatch": {"State": "nothing-to-apply", "Fixes": ["CVE-1"]},
                    }
                ],
            }
        )
        out = collector._parse_livepatch_output(data)
        assert out["kernel"] == "k1"
        assert out["patch_state"] == "nothing-to-apply"
        assert out["fixes"] == ["CVE-1"]

    def test_prefers_running_kernel(self, collector):
        """When multiple kernels are present, the running one is chosen."""
        data = json.dumps(
            {
                "Status": [
                    {"Kernel": "old", "Running": False, "Livepatch": {"State": "x"}},
                    {
                        "Kernel": "cur",
                        "Running": True,
                        "Livepatch": {"State": "applied"},
                    },
                ]
            }
        )
        out = collector._parse_livepatch_output(data)
        assert out["kernel"] == "cur"
        assert out["patch_state"] == "applied"

    def test_invalid_json_returns_none(self, collector):
        """Malformed JSON yields None rather than raising."""
        assert collector._parse_livepatch_output("not json") is None

    def test_empty_status(self, collector):
        """No kernel entries still yields a dict with empty fields."""
        out = collector._parse_livepatch_output('{"Client-Version": "1.0"}')
        assert out["enabled"] is True
        assert out["kernel"] == ""
        assert out["fixes"] == []


class TestGetLivepatchInfo:
    """Tests for OSInfoCollector._get_livepatch_info."""

    def test_success(self, collector):
        """A successful canonical-livepatch call returns the parsed dict."""
        proc = Mock(returncode=0, stdout=_FULL)
        with patch.object(os_info_collection.subprocess, "run", return_value=proc):
            out = collector._get_livepatch_info()
        assert out["patch_state"] == "applied"

    def test_binary_missing_returns_none(self, collector):
        """A missing canonical-livepatch binary returns None."""
        with patch.object(
            os_info_collection.subprocess, "run", side_effect=FileNotFoundError()
        ):
            assert collector._get_livepatch_info() is None

    def test_nonzero_returncode_returns_none(self, collector):
        """A non-zero exit returns None."""
        proc = Mock(returncode=1, stdout="")
        with patch.object(os_info_collection.subprocess, "run", return_value=proc):
            assert collector._get_livepatch_info() is None

    def test_timeout_returns_none(self, collector):
        """A timeout returns None rather than raising."""
        with patch.object(
            os_info_collection.subprocess,
            "run",
            side_effect=os_info_collection.subprocess.TimeoutExpired("cmd", 10),
        ):
            assert collector._get_livepatch_info() is None


class TestLivepatchIntegration:
    """Livepatch is collected only when the Pro service is enabled."""

    def test_collected_when_service_enabled(self, collector):
        """An enabled livepatch service triggers livepatch detail collection."""
        pro = json.dumps(
            {
                "attached": True,
                "services": [
                    {"name": "livepatch", "status": "enabled", "available": "yes"}
                ],
            }
        )
        info = {"available": False, "attached": False, "services": []}
        with patch.object(
            collector, "_get_livepatch_info", return_value={"enabled": True}
        ) as mock_lp:
            collector._parse_ubuntu_pro_output(pro, info)
        mock_lp.assert_called_once()
        assert info["livepatch"] == {"enabled": True}

    def test_skipped_when_service_disabled(self, collector):
        """A disabled livepatch service does not trigger collection."""
        pro = json.dumps(
            {
                "attached": True,
                "services": [
                    {"name": "livepatch", "status": "disabled", "available": "yes"}
                ],
            }
        )
        info = {"available": False, "attached": False, "services": []}
        with patch.object(collector, "_get_livepatch_info") as mock_lp:
            collector._parse_ubuntu_pro_output(pro, info)
        mock_lp.assert_not_called()
        assert "livepatch" not in info
