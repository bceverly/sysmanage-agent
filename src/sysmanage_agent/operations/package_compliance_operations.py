"""
Agent-side package compliance evaluator (Phase 8.3 wire-up).

The server's ``backend/services/package_compliance.py`` and this file
implement the SAME evaluation algorithm.  Two copies exist for a
reason:  the server's copy is a fallback (when the host is offline),
and this copy runs locally on the host and reports back via the
existing command-result WS channel.  Keeping the server's copy means
we can scan offline-or-stale hosts without forcing a wait for them
to come online.

If the algorithm changes, BOTH copies must be updated together.  See
``backend/services/package_compliance.py`` for the canonical reference.

The agent path here is intentionally dependency-light:  it tries to
use ``packaging.version.Version`` for SemVer comparisons but falls
back to lex-compare if ``packaging`` isn't available, so it works on
minimal Python installs.
"""

import logging
from typing import Any, Dict, List, Tuple

try:
    from packaging.specifiers import SpecifierSet
    from packaging.version import InvalidVersion, Version
except ImportError:  # pragma: no cover
    Version = None  # type: ignore
    InvalidVersion = Exception  # type: ignore
    SpecifierSet = None  # type: ignore


CONSTRAINT_REQUIRED = "REQUIRED"
CONSTRAINT_BLOCKED = "BLOCKED"
STATUS_COMPLIANT = "COMPLIANT"
STATUS_NON_COMPLIANT = "NON_COMPLIANT"


class PackageComplianceOperations:
    """Local package-compliance evaluator.  No external IO; takes the
    constraints inline in the command parameters and reads the live
    package inventory via the agent's existing software inventory
    collector."""

    def __init__(self, agent_instance, logger=None):
        self.agent = agent_instance
        self.logger = logger or logging.getLogger(__name__)

    async def evaluate_package_compliance(
        self, parameters: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Evaluate the local host against a profile's constraints.

        Parameters:
            constraints: list of dicts with keys:
                - id (str)
                - package_name (str, required)
                - package_manager (str, optional — None = any manager)
                - constraint_type (REQUIRED | BLOCKED)
                - version_op (str, optional)
                - version (str, optional)
            profile_id (str, required for the result envelope)
            profile_name (str, optional)

        Returns:
            ``{success, status, violations, profile_id, profile_name}``
        """
        constraints = parameters.get("constraints", [])
        profile_id = parameters.get("profile_id")
        profile_name = parameters.get("profile_name", "")

        if not profile_id:
            return {"success": False, "error": "profile_id is required"}
        if not isinstance(constraints, list):
            return {"success": False, "error": "constraints must be a list"}

        try:
            installed = self._collect_installed_packages()
        except Exception as exc:  # pylint: disable=broad-exception-caught
            self.logger.error("Failed to collect installed packages: %s", exc)
            return {
                "success": False,
                "profile_id": profile_id,
                "profile_name": profile_name,
                "error": f"package inventory collection failed: {exc}",
            }

        status, violations = _evaluate(installed, constraints)
        return {
            "success": True,
            "profile_id": profile_id,
            "profile_name": profile_name,
            "status": status,
            "violations": violations,
            "installed_count": len(installed),
        }

    def _collect_installed_packages(self) -> List[Dict[str, Any]]:
        """Pull the live software inventory from the agent's existing
        registration collector — same source the agent uses for
        periodic ``software_inventory_update`` messages.  Normalize
        each entry to ``{name, version, manager}`` to match the
        server's evaluator schema."""
        info = self.agent.registration.get_software_inventory_info()
        # The collector returns a wrapper; the actual list lives under
        # one of these keys depending on the agent build.  Defensive lookup.
        rows = (
            info.get("software_packages")
            or info.get("packages")
            or info.get("installed_packages")
            or []
        )
        out = []
        for row in rows:
            if not isinstance(row, dict):
                continue
            out.append(
                {
                    "name": row.get("package_name") or row.get("name") or "",
                    "version": row.get("package_version") or row.get("version") or "",
                    "manager": row.get("package_manager") or row.get("manager"),
                }
            )
        return out


# ----------------------------------------------------------------------
# Pure-Python evaluator — mirrors backend/services/package_compliance.py
# ----------------------------------------------------------------------


def _compare_versions(installed: str, version_op: str, target: str) -> Tuple[bool, str]:
    if Version is None:
        return _lex_compare(installed, version_op, target), ""
    try:
        installed_v = Version(installed)
        target_v = Version(target)
    except InvalidVersion:
        passed = _lex_compare(installed, version_op, target)
        if passed:
            return True, ""
        return (
            False,
            f"non-SemVer version comparison ({installed} {version_op} {target})",
        )
    if version_op in ("=", "=="):
        return (installed_v == target_v, "")
    if version_op == "!=":
        return (installed_v != target_v, "")
    if version_op == ">":
        return (installed_v > target_v, "")
    if version_op == ">=":
        return (installed_v >= target_v, "")
    if version_op == "<":
        return (installed_v < target_v, "")
    if version_op == "<=":
        return (installed_v <= target_v, "")
    if version_op == "~=":
        if SpecifierSet is None:  # pragma: no cover
            return (False, "compatible-release (~=) requires the packaging library")
        try:
            return (installed_v in SpecifierSet(f"~={target}"), "")
        except Exception:  # pragma: no cover  pylint: disable=broad-exception-caught
            return (False, f"unsupported version operator: {version_op}")
    return (False, f"unknown version operator: {version_op}")


def _lex_compare(installed: str, version_op: str, target: str) -> bool:
    if version_op in ("=", "=="):
        return installed == target
    if version_op == "!=":
        return installed != target
    if version_op == ">":
        return installed > target
    if version_op == ">=":
        return installed >= target
    if version_op == "<":
        return installed < target
    if version_op == "<=":
        return installed <= target
    return False


def _matches(constraint: Dict[str, Any], pkg: Dict[str, Any]) -> bool:
    if pkg.get("name") != constraint.get("package_name"):
        return False
    required_manager = constraint.get("package_manager")
    if required_manager and pkg.get("manager") != required_manager:
        return False
    return True


def _evaluate(
    installed: List[Dict[str, Any]], constraints: List[Dict[str, Any]]
) -> Tuple[str, List[Dict[str, Any]]]:
    violations: List[Dict[str, Any]] = []
    for constraint in constraints:
        ctype = constraint.get("constraint_type", CONSTRAINT_REQUIRED)
        version_op = constraint.get("version_op")
        ver = constraint.get("version")
        matches = [p for p in installed if _matches(constraint, p)]

        if ctype == CONSTRAINT_REQUIRED:
            if not matches:
                violations.append(
                    {
                        "constraint_id": constraint.get("id"),
                        "package_name": constraint.get("package_name"),
                        "constraint_type": CONSTRAINT_REQUIRED,
                        "reason": "package not installed",
                    }
                )
                continue
            if version_op and ver:
                passed = False
                fail_reason = "no installed version satisfies the constraint"
                for pkg in matches:
                    passes, why = _compare_versions(
                        pkg.get("version", ""), version_op, ver
                    )
                    if passes:
                        passed = True
                        break
                    if why:
                        fail_reason = why
                if not passed:
                    violations.append(
                        {
                            "constraint_id": constraint.get("id"),
                            "package_name": constraint.get("package_name"),
                            "constraint_type": CONSTRAINT_REQUIRED,
                            "reason": fail_reason,
                        }
                    )

        elif ctype == CONSTRAINT_BLOCKED:
            if not matches:
                continue
            if version_op and ver:
                offending = []
                for pkg in matches:
                    passes, _ = _compare_versions(
                        pkg.get("version", ""), version_op, ver
                    )
                    if passes:
                        offending.append(pkg.get("version", ""))
                if offending:
                    violations.append(
                        {
                            "constraint_id": constraint.get("id"),
                            "package_name": constraint.get("package_name"),
                            "constraint_type": CONSTRAINT_BLOCKED,
                            "reason": (
                                "installed version(s) match blocked constraint: "
                                + ", ".join(offending)
                            ),
                        }
                    )
            else:
                violations.append(
                    {
                        "constraint_id": constraint.get("id"),
                        "package_name": constraint.get("package_name"),
                        "constraint_type": CONSTRAINT_BLOCKED,
                        "reason": "package is installed but blocked",
                    }
                )

    status = STATUS_COMPLIANT if not violations else STATUS_NON_COMPLIANT
    return status, violations
