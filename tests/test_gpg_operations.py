# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""
Tests for GPG key management operations (GPG Key Management Slice 3).

Covers the ``install_gpg_key`` / ``remove_gpg_key`` handlers in
``gpg_operations.py``: install success, remove success, gpg-not-found,
unknown-user, and the guarantee that the armored (private) key material is
never written to a log line.

subprocess and ``shutil.which`` are mocked so no real gpg keyring is touched.
"""

# pylint: disable=missing-class-docstring,missing-function-docstring,redefined-outer-name,protected-access

import logging
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.sysmanage_agent.operations.gpg_operations import GpgOperations

ARMORED = (
    "-----BEGIN PGP PRIVATE KEY BLOCK-----\n"
    "SUPERSECRETPRIVATEMATERIALdeadbeef1234567890\n"
    "-----END PGP PRIVATE KEY BLOCK-----\n"
)
FPR = "ABCDEF0123456789ABCDEF0123456789ABCDEF01"


@pytest.fixture
def gpg_ops():
    return GpgOperations(MagicMock())


def _mock_run_gpg(results):
    """Return an AsyncMock that yields the given (rc, out, err) tuples in order,
    then repeats the last one."""
    seq = list(results)

    async def _run(*_args, **_kwargs):
        if len(seq) > 1:
            return seq.pop(0)
        return seq[0]

    return AsyncMock(side_effect=_run)


class TestFindGpg:
    def test_prefers_gpg2_on_unix(self, gpg_ops):
        with patch("platform.system", return_value="Linux"), patch(
            "shutil.which",
            side_effect=lambda n: "/usr/bin/gpg2" if n == "gpg2" else None,
        ):
            assert gpg_ops._find_gpg() == "/usr/bin/gpg2"

    def test_none_when_missing(self, gpg_ops):
        with patch("shutil.which", return_value=None):
            assert gpg_ops._find_gpg() is None


class TestInstall:
    @pytest.mark.asyncio
    async def test_install_success_host_level(self, gpg_ops):
        # import rc=0, then list-keys rc=0 (present)
        with patch.object(
            gpg_ops, "_find_gpg", return_value="/usr/bin/gpg"
        ), patch.object(gpg_ops, "_run_gpg", _mock_run_gpg([(0, "", ""), (0, "", "")])):
            out = await gpg_ops.install_gpg_key(
                {
                    "armored_key": ARMORED,
                    "fingerprint": FPR,
                    "target_username": None,
                    "key_id": "k1",
                }
            )
        assert out["success"] is True
        assert out["fingerprint"] == FPR
        assert out["key_id"] == "k1"
        assert out["target_username"] is None

    @pytest.mark.asyncio
    async def test_install_gpg_not_found(self, gpg_ops):
        with patch.object(gpg_ops, "_find_gpg", return_value=None):
            out = await gpg_ops.install_gpg_key(
                {"armored_key": ARMORED, "fingerprint": FPR, "key_id": "k1"}
            )
        assert out["success"] is False
        assert "gpg" in out["error"].lower()

    @pytest.mark.asyncio
    async def test_install_unknown_user(self, gpg_ops):
        with patch.object(gpg_ops, "_find_gpg", return_value="/usr/bin/gpg"), patch(
            "platform.system", return_value="Linux"
        ), patch.object(gpg_ops, "_resolve_user_home", return_value=None):
            out = await gpg_ops.install_gpg_key(
                {
                    "armored_key": ARMORED,
                    "fingerprint": FPR,
                    "target_username": "ghost",
                    "key_id": "k1",
                }
            )
        assert out["success"] is False
        assert "does not exist" in out["error"]

    @pytest.mark.asyncio
    async def test_install_missing_armored_key(self, gpg_ops):
        out = await gpg_ops.install_gpg_key({"fingerprint": FPR, "key_id": "k1"})
        assert out["success"] is False
        assert "armored_key" in out["error"]

    @pytest.mark.asyncio
    async def test_install_import_fails(self, gpg_ops):
        with patch.object(
            gpg_ops, "_find_gpg", return_value="/usr/bin/gpg"
        ), patch.object(gpg_ops, "_run_gpg", _mock_run_gpg([(2, "", "bad key")])):
            out = await gpg_ops.install_gpg_key(
                {"armored_key": ARMORED, "fingerprint": FPR, "key_id": "k1"}
            )
        assert out["success"] is False
        assert "rc=2" in out["error"]

    @pytest.mark.asyncio
    async def test_install_windows_target_user_note(self, gpg_ops):
        with patch.object(gpg_ops, "_find_gpg", return_value="C:\\gpg.exe"), patch(
            "platform.system", return_value="Windows"
        ), patch.object(gpg_ops, "_run_gpg", _mock_run_gpg([(0, "", ""), (0, "", "")])):
            out = await gpg_ops.install_gpg_key(
                {
                    "armored_key": ARMORED,
                    "fingerprint": FPR,
                    "target_username": "someuser",
                    "key_id": "k1",
                }
            )
        assert out["success"] is True
        assert "note" in out
        assert "Windows" in out["note"]


class TestRemove:
    @pytest.mark.asyncio
    async def test_remove_success(self, gpg_ops):
        # delete-secret rc=0, delete-keys rc=0, list-keys rc=2 (gone)
        with patch.object(
            gpg_ops, "_find_gpg", return_value="/usr/bin/gpg"
        ), patch.object(
            gpg_ops,
            "_run_gpg",
            _mock_run_gpg([(0, "", ""), (0, "", ""), (2, "", "no such key")]),
        ):
            out = await gpg_ops.remove_gpg_key(
                {
                    "fingerprint": FPR,
                    "target_username": None,
                    "key_id": "k1",
                    "has_private": True,
                }
            )
        assert out["success"] is True
        assert out["fingerprint"] == FPR

    @pytest.mark.asyncio
    async def test_remove_still_present_fails(self, gpg_ops):
        # delete-keys rc=2, list-keys rc=0 (still there)
        with patch.object(
            gpg_ops, "_find_gpg", return_value="/usr/bin/gpg"
        ), patch.object(
            gpg_ops, "_run_gpg", _mock_run_gpg([(2, "", "err"), (0, "", "")])
        ):
            out = await gpg_ops.remove_gpg_key(
                {"fingerprint": FPR, "has_private": False, "key_id": "k1"}
            )
        assert out["success"] is False

    @pytest.mark.asyncio
    async def test_remove_gpg_not_found(self, gpg_ops):
        with patch.object(gpg_ops, "_find_gpg", return_value=None):
            out = await gpg_ops.remove_gpg_key({"fingerprint": FPR, "key_id": "k1"})
        assert out["success"] is False
        assert "gpg" in out["error"].lower()

    @pytest.mark.asyncio
    async def test_remove_missing_fingerprint(self, gpg_ops):
        out = await gpg_ops.remove_gpg_key({"key_id": "k1"})
        assert out["success"] is False
        assert "fingerprint" in out["error"]

    @pytest.mark.asyncio
    async def test_remove_unknown_user(self, gpg_ops):
        with patch.object(gpg_ops, "_find_gpg", return_value="/usr/bin/gpg"), patch(
            "platform.system", return_value="Linux"
        ), patch.object(gpg_ops, "_resolve_user_home", return_value=None):
            out = await gpg_ops.remove_gpg_key(
                {"fingerprint": FPR, "target_username": "ghost", "key_id": "k1"}
            )
        assert out["success"] is False
        assert "does not exist" in out["error"]


class TestNoSecretLeak:
    @pytest.mark.asyncio
    async def test_armored_material_never_logged(self, gpg_ops, caplog):
        with caplog.at_level(logging.DEBUG):
            with patch.object(
                gpg_ops, "_find_gpg", return_value="/usr/bin/gpg"
            ), patch.object(
                gpg_ops, "_run_gpg", _mock_run_gpg([(0, "", ""), (0, "", "")])
            ):
                await gpg_ops.install_gpg_key(
                    {
                        "armored_key": ARMORED,
                        "fingerprint": FPR,
                        "target_username": None,
                        "key_id": "k1",
                    }
                )
        combined = "\n".join(r.getMessage() for r in caplog.records)
        assert "SUPERSECRETPRIVATEMATERIAL" not in combined
        assert "PRIVATE KEY BLOCK" not in combined
