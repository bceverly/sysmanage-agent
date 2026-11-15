# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""Windows sharing violations while the pins file is swapped in."""

from unittest.mock import patch

import pytest

from src.security import certificate_store as cs
from src.security.certificate_store import CertificateStore


def _flaky(times, result="ok"):
    calls = {"n": 0}

    def call():
        calls["n"] += 1
        if calls["n"] <= times:
            raise PermissionError("sharing violation")
        return result

    return call, calls


def test_windows_retries_a_brief_sharing_violation():
    call, calls = _flaky(3)
    with patch.object(cs.os, "name", "nt"), patch.object(cs.time, "sleep"):
        assert cs._sharing_retry(call) == "ok"
    assert calls["n"] == 4


def test_windows_gives_up_after_the_retries():
    call, _ = _flaky(10**6)
    with patch.object(cs.os, "name", "nt"), patch.object(cs.time, "sleep"):
        with pytest.raises(PermissionError):
            cs._sharing_retry(call)


def test_elsewhere_a_permission_error_is_not_retried():
    call, calls = _flaky(1)
    with patch.object(cs.os, "name", "posix"):
        with pytest.raises(PermissionError):
            cs._sharing_retry(call)
    assert calls["n"] == 1


def test_load_pins_reads_through_a_sharing_violation(tmp_path):
    store = CertificateStore(str(tmp_path / "certs"))
    store.save_pins("a" * 64, ["b" * 64])
    real = type(store.pins_path).read_text
    state = {"n": 0}

    def read_text(self, *args, **kwargs):
        state["n"] += 1
        if state["n"] == 1:
            raise PermissionError("sharing violation")
        return real(self, *args, **kwargs)

    with patch.object(cs.os, "name", "nt"), patch.object(cs.time, "sleep"):
        with patch.object(type(store.pins_path), "read_text", read_text):
            pins = store.load_pins()
    assert pins["spki_sha256"] == ["b" * 64]
