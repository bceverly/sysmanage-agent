# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""Tests for ``sysmanage_agent.core.fact_schema`` -- Phase 21.1 S1.

The load-bearing test is EXHAUSTIVENESS: every contract table must land in
exactly one of served / unsupported / not_applicable.  If a table can fall
through all three, a consumer sees no rows for it and cannot tell "never
measured" from "measured, found nothing" -- and "found nothing" is what gets
rendered as compliant.  That ambiguity is the defect this slice exists to
prevent, so it is tested directly rather than implied.
"""

import pytest

from src.sysmanage_agent.core import fact_schema as fs


@pytest.fixture(autouse=True)
def _clean_registry():
    fs.clear_providers()
    yield
    fs.clear_providers()


def test_every_table_lands_in_exactly_one_bucket():
    for platform_name in ("linux", "darwin", "windows", "freebsd", "openbsd", "netbsd"):
        cov = fs.build_fact_coverage(platform_name)
        buckets = (cov["served"], cov["unsupported"], cov["not_applicable"])
        seen = [t for bucket in buckets for t in bucket]
        assert sorted(seen) == sorted(fs.FACT_TABLES), platform_name
        assert len(seen) == len(set(seen)), f"{platform_name}: table in two buckets"


def test_unregistered_tables_are_unsupported_not_absent():
    # The S1 state: nothing registered yet.  A host must say so out loud.
    cov = fs.build_fact_coverage("linux")
    assert cov["served"] == {}
    assert cov["unsupported"]["users"] == fs.REASON_NO_PROVIDER


def test_registered_and_available_is_served_with_its_provider():
    fs.register_provider("users", fs.PROVIDER_NATIVE, lambda: True)
    cov = fs.build_fact_coverage("linux")
    assert cov["served"]["users"] == fs.PROVIDER_NATIVE
    assert "users" not in cov["unsupported"]


def test_registered_but_unavailable_is_missing_tool():
    fs.register_provider("users", fs.PROVIDER_OSQUERY, lambda: False)
    cov = fs.build_fact_coverage("linux")
    assert cov["unsupported"]["users"] == fs.REASON_MISSING_TOOL


def test_a_probe_that_raises_is_not_served():
    # A provider that cannot answer for itself is unhealthy.  Counting it as
    # served because the check blew up is precisely the silent-degradation
    # this module exists to prevent.
    def explode():
        raise OSError("osqueryd socket gone")

    fs.register_provider("users", fs.PROVIDER_OSQUERY, explode)
    cov = fs.build_fact_coverage("linux")
    assert cov["unsupported"]["users"] == fs.REASON_PROVIDER_FAILED
    assert "users" not in cov["served"]


def test_platform_scoping_is_applicability_not_a_gap():
    linux = fs.build_fact_coverage("linux")
    windows = fs.build_fact_coverage("windows")
    # Windows has no POSIX mounts table and no homebrew; Linux has no
    # Windows "programs".  None of those is a gap in the agent.
    assert linux["not_applicable"]["programs"] == fs.REASON_WRONG_PLATFORM
    assert windows["not_applicable"]["mounts"] == fs.REASON_WRONG_PLATFORM
    assert "programs" not in linux["unsupported"]


def test_the_portable_package_table_is_applicable_everywhere():
    # The BSDs have no osquery package table at all -- this is the table that
    # keeps package facts, and therefore vuln matching, portable.
    for platform_name in ("linux", "darwin", "windows", "freebsd", "openbsd", "netbsd"):
        cov = fs.build_fact_coverage(platform_name)
        assert "sysmanage_packages" not in cov["not_applicable"], platform_name


def test_registration_refuses_tables_outside_the_contract():
    # An unknown table would be collected and then ignored by every consumer,
    # which is far harder to notice than a loud error here.
    with pytest.raises(KeyError):
        fs.register_provider("not_a_real_table", fs.PROVIDER_NATIVE, lambda: True)
    with pytest.raises(ValueError):
        fs.register_provider("users", "telepathy", lambda: True)


def test_osquery_named_tables_keep_osquery_names():
    # The contract's value is that a published pack runs unmodified, which
    # holds only while these names are osquery's.
    osquery_tables = set(fs.contract_tables("osquery"))
    assert {"os_version", "users", "deb_packages", "programs"} <= osquery_tables
    assert not any(t.startswith("sysmanage_") for t in osquery_tables)
    assert all(t.startswith("sysmanage_") for t in fs.contract_tables("sysmanage"))
