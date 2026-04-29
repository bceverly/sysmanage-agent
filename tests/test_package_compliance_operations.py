"""
Tests for the agent-side package-compliance evaluator (Phase 8.3).

The evaluator must produce identical output to the server's copy
(``backend/services/package_compliance.py`` in sysmanage); these tests
mirror the server's coverage so any divergence between the two
implementations gets caught.
"""

# pylint: disable=missing-class-docstring,missing-function-docstring,redefined-outer-name

from unittest.mock import MagicMock

import pytest

from src.sysmanage_agent.operations.package_compliance_operations import (
    CONSTRAINT_BLOCKED,
    CONSTRAINT_REQUIRED,
    STATUS_COMPLIANT,
    STATUS_NON_COMPLIANT,
    PackageComplianceOperations,
    _evaluate,
)

# ------------------------------------------------------------------
# Pure evaluator (no agent / no IO)
# ------------------------------------------------------------------


class TestEvaluator:
    def test_required_present_no_version(self):
        installed = [{"name": "curl", "version": "7.68.0"}]
        constraints = [
            {"id": "1", "package_name": "curl", "constraint_type": CONSTRAINT_REQUIRED}
        ]
        status, viols = _evaluate(installed, constraints)
        assert status == STATUS_COMPLIANT
        assert not viols

    def test_required_missing(self):
        installed = []
        constraints = [
            {
                "id": "1",
                "package_name": "wget",
                "constraint_type": CONSTRAINT_REQUIRED,
            }
        ]
        status, viols = _evaluate(installed, constraints)
        assert status == STATUS_NON_COMPLIANT
        assert viols[0]["package_name"] == "wget"

    def test_required_with_version_constraint(self):
        installed = [{"name": "curl", "version": "7.68.0"}]
        constraints = [
            {
                "id": "1",
                "package_name": "curl",
                "constraint_type": CONSTRAINT_REQUIRED,
                "version_op": ">=",
                "version": "7.0.0",
            }
        ]
        status, _ = _evaluate(installed, constraints)
        assert status == STATUS_COMPLIANT

    def test_required_version_constraint_unmet(self):
        installed = [{"name": "curl", "version": "6.0.0"}]
        constraints = [
            {
                "id": "1",
                "package_name": "curl",
                "constraint_type": CONSTRAINT_REQUIRED,
                "version_op": ">=",
                "version": "7.0.0",
            }
        ]
        status, viols = _evaluate(installed, constraints)
        assert status == STATUS_NON_COMPLIANT
        assert viols[0]["constraint_type"] == CONSTRAINT_REQUIRED

    def test_blocked_present_no_version(self):
        installed = [{"name": "telnet", "version": "0.17"}]
        constraints = [
            {"id": "1", "package_name": "telnet", "constraint_type": CONSTRAINT_BLOCKED}
        ]
        status, viols = _evaluate(installed, constraints)
        assert status == STATUS_NON_COMPLIANT
        assert "blocked" in viols[0]["reason"]

    def test_blocked_with_version_op_only_fires_on_match(self):
        # Block versions >= 3.0.0; installed 1.0.0 → compliant.
        constraints = [
            {
                "id": "1",
                "package_name": "openssl",
                "constraint_type": CONSTRAINT_BLOCKED,
                "version_op": ">=",
                "version": "3.0.0",
            }
        ]
        status_ok, _ = _evaluate([{"name": "openssl", "version": "1.0.0"}], constraints)
        assert status_ok == STATUS_COMPLIANT

        # And 3.1.0 → non-compliant.
        status_bad, viols = _evaluate(
            [{"name": "openssl", "version": "3.1.0"}], constraints
        )
        assert status_bad == STATUS_NON_COMPLIANT
        assert "3.1.0" in viols[0]["reason"]

    def test_package_manager_filter(self):
        installed = [
            {"name": "curl", "version": "1.0.0", "manager": "apt"},
            {"name": "curl", "version": "2.0.0", "manager": "snap"},
        ]
        constraints = [
            {
                "id": "1",
                "package_name": "curl",
                "package_manager": "snap",
                "constraint_type": CONSTRAINT_REQUIRED,
                "version_op": "==",
                "version": "2.0.0",
            }
        ]
        status, _ = _evaluate(installed, constraints)
        assert status == STATUS_COMPLIANT


# ------------------------------------------------------------------
# Operation class — tests the agent-side wrapper around _evaluate
# ------------------------------------------------------------------


class TestPackageComplianceOperations:
    def _make(self, installed):
        agent = MagicMock()
        agent.registration.get_software_inventory_info.return_value = {
            "software_packages": installed
        }
        return PackageComplianceOperations(agent_instance=agent)

    @pytest.mark.asyncio
    async def test_evaluate_returns_compliant(self):
        ops = self._make([{"package_name": "curl", "package_version": "7.68.0"}])
        result = await ops.evaluate_package_compliance(
            {
                "profile_id": "p1",
                "profile_name": "test",
                "constraints": [
                    {
                        "id": "c1",
                        "package_name": "curl",
                        "constraint_type": CONSTRAINT_REQUIRED,
                    }
                ],
            }
        )
        assert result["success"] is True
        assert result["status"] == STATUS_COMPLIANT
        assert result["profile_id"] == "p1"
        assert result["installed_count"] == 1

    @pytest.mark.asyncio
    async def test_evaluate_returns_non_compliant_with_violations(self):
        ops = self._make([])
        result = await ops.evaluate_package_compliance(
            {
                "profile_id": "p1",
                "constraints": [
                    {
                        "id": "c1",
                        "package_name": "wget",
                        "constraint_type": CONSTRAINT_REQUIRED,
                    }
                ],
            }
        )
        assert result["success"] is True
        assert result["status"] == STATUS_NON_COMPLIANT
        assert len(result["violations"]) == 1

    @pytest.mark.asyncio
    async def test_evaluate_missing_profile_id(self):
        ops = self._make([])
        result = await ops.evaluate_package_compliance({"constraints": []})
        assert result["success"] is False
        assert "profile_id" in result["error"]

    @pytest.mark.asyncio
    async def test_evaluate_inventory_failure_returns_error(self):
        agent = MagicMock()
        agent.registration.get_software_inventory_info.side_effect = RuntimeError(
            "kaboom"
        )
        ops = PackageComplianceOperations(agent_instance=agent)
        result = await ops.evaluate_package_compliance(
            {"profile_id": "p1", "constraints": []}
        )
        assert result["success"] is False
        assert "kaboom" in result["error"]
