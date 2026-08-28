# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""The agent echoes the profile identifiers back (Phase 20.1).

The server records a run from the RESULT message, and that message carries
nothing from the command's parameters. So a result that does not echo the
profile id and name produces a stored run with neither -- which is exactly
what happened: the apply dialog's "Profile name" field was sent, ignored, and
the run history's profile column was always empty.

The echo has to survive EVERY outcome, not just success. A failed run is the
one an operator most wants to trace back to a profile.
"""

import logging

import pytest

from src.sysmanage_agent.operations import config_mgmt_operations as ops


def make():
    obj = ops.ConfigMgmtOperations.__new__(ops.ConfigMgmtOperations)
    obj.logger = logging.getLogger("test")
    return obj


IDS = {
    "profile_id": "44444444-4444-4444-8444-444444444444",
    "profile_name": "baseline",
}


class TestEcho:
    @pytest.mark.asyncio
    async def test_spec_results_carry_the_identifiers(self, monkeypatch):
        obj = make()

        async def fake_spec(_spec, _timeout):
            return {"success": True, "changed": False}

        monkeypatch.setattr(obj, "_apply_with_spec", fake_spec)
        out = await obj.apply_config_profile({"spec": {"argv": ["x"]}, **IDS})
        assert out["profile_id"] == IDS["profile_id"]
        assert out["profile_name"] == "baseline"

    @pytest.mark.asyncio
    async def test_a_missing_executor_still_carries_them(self, monkeypatch):
        # The failure case is the one worth tracing back to a profile.
        monkeypatch.setattr(ops.locator, "find_executor", lambda: None)
        out = await make().apply_config_profile({"profile": {"playbook": "x"}, **IDS})
        assert out["success"] is False
        assert out["profile_id"] == IDS["profile_id"]
        assert out["profile_name"] == "baseline"

    @pytest.mark.asyncio
    async def test_ansible_results_carry_them(self, monkeypatch):
        obj = make()
        monkeypatch.setattr(ops.locator, "find_executor", lambda: "ansible-playbook")
        monkeypatch.setattr(ops.platform, "system", lambda: "Linux")

        async def fake_ansible(*_a, **_k):
            return {"success": True, "changed": True}

        monkeypatch.setattr(obj, "_apply_with_ansible", fake_ansible)
        out = await obj.apply_config_profile({"profile": {"playbook": "x"}, **IDS})
        assert out["profile_name"] == "baseline"

    @pytest.mark.asyncio
    async def test_absent_identifiers_are_not_invented(self, monkeypatch):
        # An ad-hoc apply has no stored profile; writing empty strings would
        # make the run look associated with a profile that does not exist.
        obj = make()
        monkeypatch.setattr(ops.locator, "find_executor", lambda: "ansible-playbook")
        monkeypatch.setattr(ops.platform, "system", lambda: "Linux")

        async def fake_ansible(*_a, **_k):
            return {"success": True, "changed": False}

        monkeypatch.setattr(obj, "_apply_with_ansible", fake_ansible)
        out = await obj.apply_config_profile({"profile": {"playbook": "x"}})
        assert "profile_id" not in out
        assert "profile_name" not in out

    @pytest.mark.asyncio
    async def test_the_echo_does_not_overwrite_run_results(self, monkeypatch):
        obj = make()

        async def fake_spec(_spec, _timeout):
            return {"success": False, "changed": True, "exit_code": 2}

        monkeypatch.setattr(obj, "_apply_with_spec", fake_spec)
        out = await obj.apply_config_profile({"spec": {"argv": ["x"]}, **IDS})
        assert out["success"] is False
        assert out["changed"] is True
        assert out["exit_code"] == 2
