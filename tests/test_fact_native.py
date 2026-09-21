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
    would make any pack that counts addresses wrong.

    Driven through psutil rather than the hardware collector since 2026-09-21:
    the collector could hold only ONE address per family per interface, so a
    second address vanished, and it omitted loopback entirely. The PROPERTY
    this test guards is unchanged — only the source it reads.
    """
    import socket as _socket
    from collections import namedtuple
    from unittest.mock import patch

    import psutil

    Snic = namedtuple("Snic", "family address netmask broadcast ptp")
    addrs = {
        "eth0": [
            Snic(_socket.AF_INET, "10.0.0.5", "255.255.255.0", None, None),
            Snic(_socket.AF_INET, "10.0.0.6", "255.255.255.0", None, None),
            Snic(_socket.AF_INET6, "fe80::1", "ffff:ffff:ffff:ffff::", None, None),
            # A link-layer address is not an interface_address in osquery.
            Snic(psutil.AF_LINK, "aa:bb:cc:dd:ee:ff", None, None, None),
        ]
    }
    with patch.object(psutil, "net_if_addrs", return_value=addrs):
        rows = fn.build_interface_addresses()
    assert [r["address"] for r in rows] == ["10.0.0.5", "10.0.0.6", "fe80::1"]
    # Each address carries ITS OWN mask, rather than the v4 one being
    # restated on the v6 row.
    assert rows[0]["mask"] == "255.255.255.0"
    assert rows[2]["mask"] == "ffff:ffff:ffff:ffff::"


def test_mounts_leaves_block_counts_null_rather_than_deriving_them():
    """Block/inode counts stay NULL: filling them means a statvfs per mount,
    which blocks on an unreachable network mount and turns one dead NFS
    server into a hung collection every interval."""
    from collections import namedtuple
    from unittest.mock import patch

    import psutil

    Part = namedtuple("Part", "device mountpoint fstype opts")
    with patch.object(
        psutil,
        "disk_partitions",
        return_value=[Part("/dev/wd0a", "/", "ffs", "rw,local")],
    ):
        row = fn.build_mounts()[0]
    assert row["device"] == "/dev/wd0a" and row["type"] == "ffs"
    assert row["path"] == "/" and row["flags"] == "rw,local"
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


class TestListeningPortProtocol:
    """``protocol`` is the IANA IP protocol number, not the socket type.

    The trap: psutil reports SOCK_STREAM (1) / SOCK_DGRAM (2); osquery reports
    IPPROTO_TCP (6) / IPPROTO_UDP (17). A published pack filters TCP with
    ``WHERE protocol = 6``. Emit the socket type and that matches NOTHING
    while ``protocol = 1`` -- ICMP, in IANA terms -- matches every TCP socket.
    The query succeeds either way, which is what makes it worth a test.

    Found in the field on 2026-09-21: a FreeBSD host reported sshd on port 22
    with protocol 1.
    """

    def _rows(self, conns):
        # psutil is imported INSIDE the builder, so the patch has to land on
        # the psutil module rather than on fact_native's namespace.
        from unittest.mock import patch

        import psutil

        with patch.object(psutil, "net_connections", return_value=conns):
            # The builder directly: collect() swallows builder exceptions by
            # design, which would turn a real failure here into an empty list
            # and a passing test that asserts nothing.
            return fn.build_listening_ports()

    def _conn(self, sock_type, port=22):
        import socket as _socket
        from collections import namedtuple

        import psutil

        Addr = namedtuple("Addr", "ip port")
        Conn = namedtuple("Conn", "fd family type laddr raddr status pid")
        return Conn(
            fd=7,
            family=_socket.AF_INET,
            type=sock_type,
            laddr=Addr("0.0.0.0", port),
            raddr=None,
            status=psutil.CONN_LISTEN,
            pid=1234,
        )

    def test_a_tcp_socket_reports_protocol_6(self):
        import socket as _socket

        rows = self._rows([self._conn(_socket.SOCK_STREAM)])
        assert rows and rows[0]["protocol"] == int(_socket.IPPROTO_TCP)

    def test_a_udp_socket_reports_protocol_17(self):
        import socket as _socket

        rows = self._rows([self._conn(_socket.SOCK_DGRAM, port=53)])
        assert rows and rows[0]["protocol"] == int(_socket.IPPROTO_UDP)

    def test_the_socket_type_is_never_emitted_as_the_protocol(self):
        import socket as _socket

        rows = self._rows(
            [self._conn(_socket.SOCK_STREAM), self._conn(_socket.SOCK_DGRAM, 53)]
        )
        assert {r["protocol"] for r in rows} == {
            int(_socket.IPPROTO_TCP),
            int(_socket.IPPROTO_UDP),
        }

    def test_family_is_passed_through_because_it_already_matches(self):
        """psutil's AddressFamily values ARE the OS AF_* constants, which is
        what osquery reports — so a map here would be the bug."""
        import socket as _socket

        rows = self._rows([self._conn(_socket.SOCK_STREAM)])
        assert rows[0]["family"] == int(_socket.AF_INET)


def test_collect_registers_itself_rather_than_answering_nothing():
    """An unregistered registry must not read as "this host has no facts".

    ``NATIVE_TABLES`` is filled by ``register_native_provider()``. A caller
    that collected without bootstrapping got ``{}`` back -- no error, just
    silence, which is wrong in the direction that looks like data. The
    conformance harness did exactly that and reported the native provider
    empty on a host serving 1,116 packages.
    """
    fn.NATIVE_TABLES.clear()
    try:
        rows = fn.collect(["os_version"])
        assert rows.get(
            "os_version"
        ), "collect() answered nothing from an empty registry"
    finally:
        fn.register_native_provider()


class TestMountsAreTheMountTable:
    """``mounts`` is the mount table, not the storage-device inventory.

    The two look interchangeable and are not. Measured on FreeBSD 14.4 on
    2026-09-21, reading the device inventory produced raw devices with no
    mount point and ``type`` of ``unknown`` for every real filesystem, so
    ``WHERE type = 'zfs'`` matched nothing while the query succeeded. osquery
    reported all 27 mounts with true types.
    """

    def test_every_row_has_a_path_and_a_type(self):
        rows = fn.build_mounts()
        assert rows, "no mounts on a running host"
        assert all(r["path"] for r in rows)
        assert all(r["type"] for r in rows)

    def test_no_row_reports_type_unknown(self):
        """The exact symptom the FreeBSD comparison exposed."""
        rows = fn.build_mounts()
        assert not [r for r in rows if r["type"] == "unknown"]

    def test_the_root_filesystem_is_present(self):
        rows = fn.build_mounts()
        assert any(r["path"] in ("/", "C:\\") for r in rows)


class TestInterfaceAddressesIncludeLoopback:
    """Loopback is an address like any other.

    It was absent entirely: osquery reported lo0 with 127.0.0.1, ::1 and
    fe80::1%lo0 while we reported none of them, so a pack asking whether a
    service is bound to loopback -- an ordinary security question -- got a
    confidently empty answer.
    """

    def test_loopback_is_reported(self):
        rows = fn.build_interface_addresses()
        loopback = [r for r in rows if r["address"] in ("127.0.0.1", "::1")]
        assert loopback, "loopback address missing from interface_addresses"

    def test_each_address_carries_its_own_mask(self):
        """The old code reused the v4 mask for v4 and left v6 NULL; the fix is
        reading the mask that belongs to each address."""
        rows = fn.build_interface_addresses()
        v4 = [r for r in rows if r["address"] == "127.0.0.1"]
        assert v4 and v4[0]["mask"]

    def test_one_row_per_address(self):
        """osquery's shape. An interface with several addresses must not
        collapse to one row -- the inventory held only one per family, so the
        extras simply vanished."""
        rows = fn.build_interface_addresses()
        assert len(rows) >= len({r["interface"] for r in rows})


class TestCertificateCommonName:
    def test_the_cn_is_pulled_out_of_the_subject(self):
        assert (
            fn.common_name_of("C = ES, O = FNMT-RCM, CN = AC RAIZ FNMT-RCM")
            == "AC RAIZ FNMT-RCM"
        )

    def test_both_openssl_spacings_work(self):
        assert fn.common_name_of("CN=example.com,O=Acme") == "example.com"

    def test_a_subject_with_no_cn_is_none_not_a_guess(self):
        assert fn.common_name_of("C = US, O = NoCommonName") is None

    def test_an_organisation_name_is_not_mistaken_for_a_cn(self):
        """``O = ...`` must not match: a substring search for 'CN' would find
        the one inside 'FNMT-RCM'."""
        assert fn.common_name_of("C = ES, O = FNMT-RCM") is None


class TestOsVersionPlatformIsTheDistribution:
    """osquery's ``os_version.platform`` is the DISTRIBUTION, not the kernel.

    It reports ``ubuntu``/``debian``/``rhel`` from os-release ``ID``. We
    reported ``linux``, so ``WHERE platform = 'ubuntu'`` -- the documented
    osquery idiom -- matched nothing here while the query succeeded. Measured
    against osquery 5.20.0 on Ubuntu 26.04, 2026-09-21.
    """

    RELEASE = (
        'NAME="Ubuntu"\n'
        'VERSION="26.04.1 LTS (Resolute Raccoon)"\n'
        "ID=ubuntu\n"
        "ID_LIKE=debian\n"
        'VERSION_ID="26.04"\n'
        "VERSION_CODENAME=resolute\n"
    )

    def _row(self):
        from unittest.mock import mock_open, patch

        with patch("builtins.open", mock_open(read_data=self.RELEASE)):
            return fn.build_os_version(FakeOS())[0]

    def test_platform_is_the_distro_id(self):
        assert self._row()["platform"] == "ubuntu"

    def test_platform_like_is_populated(self):
        """It was always NULL before, so a pack keying on the family had
        nothing to match."""
        assert self._row()["platform_like"] == "debian"

    def test_version_is_the_full_version_string(self):
        """osquery reports VERSION, not VERSION_ID."""
        assert self._row()["version"] == "26.04.1 LTS (Resolute Raccoon)"

    def test_a_host_with_no_os_release_still_reports_a_platform(self):
        """The BSDs, macOS and Windows have no /etc/os-release and already
        agreed with osquery — that path must keep working."""
        from unittest.mock import patch

        with patch("builtins.open", side_effect=OSError("no such file")):
            row = fn.build_os_version(FakeOS())[0]
        assert row["platform"]
        assert row["platform_like"] is None
