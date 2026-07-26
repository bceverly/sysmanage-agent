# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""Tests for OSInfoCollector image-mode (bootc / rpm-ostree) detection — Phase 17.3."""

import json
from unittest.mock import patch

import pytest

from src.sysmanage_agent.collection.os_info_collection import OSInfoCollector

BOOTC_STATUS = {
    "status": {
        "staged": {
            "image": {
                "image": {"image": "quay.io/fedora/fedora-bootc:41"},
                "imageDigest": "sha256:" + "1" * 64,
            }
        },
        "booted": {
            "image": {
                "image": {"image": "quay.io/fedora/fedora-bootc:41"},
                "imageDigest": "sha256:" + "2" * 64,
            }
        },
        "rollback": {
            "image": {
                "image": {"image": "quay.io/fedora/fedora-bootc:41"},
                "imageDigest": "sha256:" + "3" * 64,
            }
        },
    }
}

RPM_OSTREE_STATUS = {
    "deployments": [
        {
            "container-image-reference": "ostree-unverified-registry:quay.io/fedora/fedora-coreos:stable",
            "container-image-reference-digest": "sha256:" + "5" * 64,
            "booted": False,
            "staged": True,
        },
        {
            "container-image-reference": "ostree-unverified-registry:quay.io/fedora/fedora-coreos:stable",
            "container-image-reference-digest": "sha256:" + "6" * 64,
            "booted": True,
            "staged": False,
        },
        {
            "container-image-reference": "ostree-unverified-registry:quay.io/fedora/fedora-coreos:stable",
            "container-image-reference-digest": "sha256:" + "7" * 64,
            "booted": False,
            "staged": False,
        },
    ]
}


class _FakeProc:
    def __init__(self, returncode=0, stdout=""):
        self.returncode = returncode
        self.stdout = stdout


class TestImageModeNormalizers:
    """The static parsers — no subprocess/mocking needed."""

    @pytest.fixture
    def collector(self):
        return OSInfoCollector()

    def test_normalize_bootc(self, collector):
        out = collector._normalize_bootc_status(BOOTC_STATUS)
        assert out["is_image_mode"] is True
        assert out["image_backend"] == "bootc"
        assert out["booted_image_ref"] == "quay.io/fedora/fedora-bootc:41"
        assert out["booted_image_digest"].endswith("2" * 4)
        assert out["staged_image_digest"].endswith("1" * 4)
        assert out["rollback_available"] is True

    def test_normalize_bootc_fresh(self, collector):
        out = collector._normalize_bootc_status(
            {"status": {"staged": None, "booted": {"image": {}}, "rollback": None}}
        )
        assert out["staged_image_ref"] is None
        assert out["rollback_available"] is False

    def test_normalize_rpm_ostree(self, collector):
        out = collector._normalize_rpm_ostree_status(RPM_OSTREE_STATUS)
        assert out["image_backend"] == "rpm-ostree"
        assert out["booted_image_ref"] == "quay.io/fedora/fedora-coreos:stable"
        assert out["booted_image_digest"].endswith("6" * 4)
        assert out["staged_image_digest"].endswith("5" * 4)
        assert out["rollback_available"] is True

    def test_normalize_rpm_ostree_package_mode(self, collector):
        out = collector._normalize_rpm_ostree_status(
            {"deployments": [{"booted": True, "staged": False}]}
        )
        assert out["is_image_mode"] is True
        assert out["booted_image_ref"] is None
        assert out["rollback_available"] is False


class TestImageModeDetection:
    @pytest.fixture
    def collector(self):
        return OSInfoCollector()

    def test_not_image_mode(self, collector):
        with patch("os.path.exists", return_value=False):
            out = collector._collect_image_mode_info()
        assert out == {"is_image_mode": False}

    def test_bootc_detected_and_parsed(self, collector):
        with patch(
            "os.path.exists", side_effect=lambda p: p == "/usr/lib/bootc"
        ), patch("shutil.which", return_value="/usr/bin/bootc"), patch(
            "subprocess.run",
            return_value=_FakeProc(0, json.dumps(BOOTC_STATUS)),
        ):
            out = collector._collect_image_mode_info()
        assert out["image_backend"] == "bootc"
        assert out["booted_image_ref"] == "quay.io/fedora/fedora-bootc:41"

    def test_rpm_ostree_detected_and_parsed(self, collector):
        with patch(
            "os.path.exists", side_effect=lambda p: p == "/run/ostree-booted"
        ), patch("shutil.which", return_value="/usr/bin/rpm-ostree"), patch(
            "subprocess.run",
            return_value=_FakeProc(0, json.dumps(RPM_OSTREE_STATUS)),
        ):
            out = collector._collect_image_mode_info()
        assert out["image_backend"] == "rpm-ostree"
        assert out["rollback_available"] is True

    def test_status_command_failure_still_flags_image_mode(self, collector):
        with patch(
            "os.path.exists", side_effect=lambda p: p == "/usr/lib/bootc"
        ), patch("shutil.which", return_value="/usr/bin/bootc"), patch(
            "subprocess.run", return_value=_FakeProc(1, "")
        ):
            out = collector._collect_image_mode_info()
        assert out == {"is_image_mode": True, "image_backend": "bootc"}

    def test_status_bad_json_still_flags_image_mode(self, collector):
        with patch(
            "os.path.exists", side_effect=lambda p: p == "/usr/lib/bootc"
        ), patch("shutil.which", return_value="/usr/bin/bootc"), patch(
            "subprocess.run", return_value=_FakeProc(0, "not json{")
        ):
            out = collector._collect_image_mode_info()
        assert out == {"is_image_mode": True, "image_backend": "bootc"}
