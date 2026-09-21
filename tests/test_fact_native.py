# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""Tests for ``sysmanage_agent.collection.fact_native`` — Phase 21.1 S2.

These are FIDELITY tests, not coverage tests.  A pack written against osquery
must get osquery's meaning or nothing at all, so the cases that matter are the
ones where our collector's field is nearly-but-not-quite the osquery column:
``home_directory`` vs ``directory``, ``group_name`` vs ``groupname``, and
``is_system_user``, which is NOT ``is_hidden`` however much it reads like it.
A wrong mapping does not fail loudly — the query succeeds and answers about
the wrong thing.
"""

import pytest

from src.sysmanage_agent.collection import fact_native as fn
from src.sysmanage_agent.core import fact_schema as fs
from src.sysmanage_agent.core.fact_store import FactStore


class FakeUsers:
    def get_user_accounts(self):
        return [
            {
                "username": "root",
                "uid": 0,
                "home_directory": "/root",
                "shell": "/bin/sh",
                "is_system_user": True,
                "groups": ["root", "ghosts"],
            }
        ]

    def get_user_groups(self):
        return [{"group_name": "root", "gid": 0, "is_system_group": True}]


class FakeOS:
    def get_os_version_info(self):
        return {
            "platform": "NetBSD",
            "platform_release": "10.1",
            "machine_architecture": "amd64",
            "os_info": {"distribution": "NetBSD", "distribution_version": "10.1"},
        }


class FakePackages:
    def get_software_inventory(self):
        return {
            "software_packages": [
                {
                    "package_name": "nginx",
                    "version": "1.26.2",
                    "package_manager": "pkgin",
                    "architecture": "amd64",
                }
            ]
        }


class Exploding:
    def get_user_accounts(self):
        raise OSError("passwd database unreadable")

    def get_user_groups(self):
        raise OSError("group database unreadable")


@pytest.fixture(autouse=True)
def _clean():
    fs.clear_providers()
    fn.NATIVE_TABLES.clear()
    yield
    fs.clear_providers()
    fn.NATIVE_TABLES.clear()


def test_users_uses_osquery_column_names():
    row = fn.build_users(FakeUsers())[0]
    assert row["directory"] == "/root"  # NOT home_directory
    assert "home_directory" not in row


def test_is_system_user_is_not_reported_as_is_hidden():
    """They sound alike and mean different things: osquery's is_hidden is about
    the login UI, not about being a system account.  Mapping one onto the
    other would answer a pack's question wrongly and never error."""
    row = fn.build_users(FakeUsers())[0]
    assert row.get("is_hidden") is None


def test_gid_is_left_null_rather_than_guessed():
    """Our collector reports group NAMES, not a primary gid.  A plausible
    guess is worse than a null, because a pack filtering on gid would then
    select the wrong hosts silently."""
    assert fn.build_users(FakeUsers())[0].get("gid") is None


def test_groups_uses_groupname_not_group_name():
    row = fn.build_groups(FakeUsers())[0]
    assert row["groupname"] == "root"
    assert "group_name" not in row


def test_unresolvable_membership_is_dropped_not_invented():
    # "ghosts" has no gid, so it must produce no row at all.
    pairs = fn.build_user_groups(FakeUsers())
    assert pairs == [{"uid": 0, "gid": 0}]


def test_every_builder_emits_only_contract_columns():
    cases = [
        ("users", fn.build_users(FakeUsers())),
        ("groups", fn.build_groups(FakeUsers())),
        ("user_groups", fn.build_user_groups(FakeUsers())),
        ("os_version", fn.build_os_version(FakeOS())),
        ("sysmanage_packages", fn.build_sysmanage_packages(FakePackages())),
    ]
    for table, rows in cases:
        allowed = set(fs.columns(table))
        for row in rows:
            assert set(row) <= allowed, f"{table}: {set(row) - allowed}"


def test_a_failing_collector_yields_no_rows_without_crashing():
    fn.NATIVE_TABLES["users"] = (Exploding, fn.build_users)
    assert fn.collect(["users"]) == {"users": []}


def test_packages_are_portable_to_a_platform_osquery_cannot_reach():
    # NetBSD: no osquery port, no osquery package table. This row is the only
    # way vuln matching happens there.
    rows = fn.build_sysmanage_packages(FakePackages())
    with FactStore() as store:
        store.materialize("sysmanage_packages", rows)
        found = store.query(
            "SELECT name, version FROM sysmanage_packages WHERE package_manager = ?",
            ["pkgin"],
        )
    assert found == [{"name": "nginx", "version": "1.26.2"}]


def test_registration_makes_coverage_report_the_tables_as_served():
    fn.register_native_provider()
    coverage = fs.build_fact_coverage("linux")
    for table in ("users", "groups", "user_groups", "os_version", "sysmanage_packages"):
        assert coverage["served"][table] == fs.PROVIDER_NATIVE
        assert table not in coverage["unsupported"]


def test_tables_without_a_provider_stay_honestly_unsupported():
    """Partial coverage must read as partial.

    Asserts the PROPERTY rather than whichever table happens to be unimplemented
    today: an earlier version of this test named ``processes`` and went stale
    the moment that builder landed.  A table nobody serves has to say so, or it
    appears as an empty result -- which is "measured, found none".
    """
    fs.register_provider("users", fs.PROVIDER_NATIVE, lambda: True)
    coverage = fs.build_fact_coverage("linux")
    assert coverage["served"]["users"] == fs.PROVIDER_NATIVE
    assert coverage["unsupported"]["processes"] == fs.REASON_NO_PROVIDER


# ---------------------------------------------------------------------------
# The remaining tables.  Same rule as above: the interesting cases are where
# our field is nearly-but-not-quite the osquery column.
# ---------------------------------------------------------------------------


class FakeProcs:
    def collect_processes(self):
        return (
            [
                {
                    "pid": 42,
                    "name": "sshd",
                    "command_line": "/usr/sbin/sshd -D",
                    "status": "sleeping",
                    "memory_rss_bytes": 8192,
                    "parent_pid": 1,
                    "username": "root",
                }
            ],
            False,
        )


class FakeCerts:
    def collect_certificates(self):
        return [
            {
                "certificate_name": "self",
                "subject": "CN=me",
                "issuer": "CN=me",
                "is_ca": True,
                "file_path": "/etc/ssl/me.pem",
                "serial_number": "01",
                "not_before": "2026-01-01",
                "not_after": "2027-01-01",
            },
            {
                "certificate_name": "signed",
                "subject": "CN=me",
                "issuer": "CN=ca",
                "is_ca": False,
            },
        ]


class FakeHardware:
    def get_hardware_info(self):
        return {
            "cpu_model": "Intel(R) Xeon(R)",
            "cpu_vendor": "GenuineIntel",
            "cpu_cores": 4,
            "cpu_threads": 8,
            "memory_total_mb": 2048,
            "network_interfaces": [
                {
                    "name": "eth0",
                    "ipv4_address": "10.0.0.5",
                    "ipv6_address": "fe80::1",
                    "subnet_mask": "255.255.255.0",
                }
            ],
            "storage_devices": [
                {
                    "name": "/dev/wd0a",
                    "mount_point": "/",
                    "file_system": "ffs",
                    "size": 123,
                }
            ],
        }


class FakeUpdates:
    def get_available_updates(self):
        return {
            "available_updates": [
                {
                    "package_name": "openssl",
                    "current_version": "3.0.1",
                    "available_version": "3.0.2",
                    "package_manager": "pkgin",
                    "is_security_update": True,
                }
            ]
        }


def test_process_state_is_translated_to_osquerys_letter():
    """osquery reports the /proc letter; psutil reports a word.  A published
    pack filters on `state = 'R'` and would match nothing against 'running'."""
    row = fn.build_processes(FakeProcs())[0]
    assert row["state"] == "S"
    assert row["cmdline"] == "/usr/sbin/sshd -D"
    assert row["resident_size"] == 8192 and row["parent"] == 1


def test_process_uid_is_not_guessed_from_username():
    assert fn.build_processes(FakeProcs())[0].get("uid") is None


def test_self_signed_is_derived_the_way_osquery_defines_it():
    rows = fn.build_certificates(FakeCerts())
    assert rows[0]["self_signed"] == 1 and rows[0]["ca"] == 1
    assert rows[1]["self_signed"] == 0 and rows[1]["ca"] == 0


def test_one_row_per_address_not_one_per_interface():
    """osquery's shape is a row per ADDRESS; collapsing v4 and v6 onto one row
    would make any pack that counts addresses wrong."""
    rows = fn.build_interface_addresses(FakeHardware())
    assert [r["address"] for r in rows] == ["10.0.0.5", "fe80::1"]
    # the v4 mask must not be restated on the v6 row
    assert rows[0]["mask"] == "255.255.255.0"
    assert rows[1].get("mask") is None


def test_mounts_leaves_block_counts_null_rather_than_deriving_them():
    row = fn.build_mounts(FakeHardware())[0]
    assert row["device"] == "/dev/wd0a" and row["type"] == "ffs"
    assert row.get("blocks") is None and row.get("blocks_size") is None


def test_physical_memory_is_bytes_and_cpu_type_is_the_arch():
    row = fn.build_system_info(FakeHardware())[0]
    assert row["physical_memory"] == 2048 * 1024 * 1024
    assert row["cpu_brand"] == "Intel(R) Xeon(R)"
    # cpu_type is the machine architecture in osquery, NOT the vendor string.
    assert row["cpu_type"] != "GenuineIntel"


def test_available_updates_marks_security_updates():
    row = fn.build_available_updates(FakeUpdates())[0]
    assert row["name"] == "openssl" and row["is_security"] == 1
    assert row["available_version"] == "3.0.2"


def test_package_tables_are_filtered_by_their_package_manager():
    class Mixed:
        def get_software_inventory(self):
            return {
                "software_packages": [
                    {"package_name": "nginx", "version": "1", "package_manager": "apt"},
                    {"package_name": "httpd", "version": "2", "package_manager": "dnf"},
                ]
            }

    assert [r["name"] for r in fn.build_deb_packages(Mixed())] == ["nginx"]
    assert [r["name"] for r in fn.build_rpm_packages(Mixed())] == ["httpd"]
    # and both still appear in the portable table
    assert len(fn.build_sysmanage_packages(Mixed())) == 2


def test_listening_ports_is_withheld_without_privilege(monkeypatch):
    """A partial socket list is worse than none: "nothing is listening on 22"
    reads as safe, and a pack cannot tell a true negative from a blind spot."""
    monkeypatch.setattr(fn, "can_enumerate_sockets", lambda: False)
    fn.register_native_provider()
    coverage = fs.build_fact_coverage("linux")
    assert coverage["unsupported"]["listening_ports"] == (
        fs.REASON_INSUFFICIENT_PRIVILEGE
    )
    assert "listening_ports" not in coverage["served"]


def test_listening_ports_is_served_when_privileged(monkeypatch):
    monkeypatch.setattr(fn, "can_enumerate_sockets", lambda: True)
    fn.register_native_provider()
    assert fs.build_fact_coverage("linux")["served"]["listening_ports"] == (
        fs.PROVIDER_NATIVE
    )
