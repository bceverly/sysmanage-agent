# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""Tests for ``sysmanage_agent.collection.fact_osquery`` -- Phase 21.1 S3.

osquery is not installed on CI runners and is not installable on two of the
platforms this agent supports, so every test here drives a FAKE ``osqueryi``.
That is not a compromise: the behavior worth pinning is what happens when the
binary is absent, lying, or broken, and those are the cases a real osquery
would not give us on demand.

The load-bearing one is ``test_broken_osquery_degrades_to_native``.  FreeBSD's
port carries seven downstream patches from a maintainer's personal fork, so
"osquery is installed but does not work" is a state that WILL occur in the
field.  It must cost fidelity, never coverage.
"""

import json
import subprocess
from unittest.mock import patch

import pytest

from src.sysmanage_agent.collection import fact_native as fn
from src.sysmanage_agent.collection import fact_osquery as fo
from src.sysmanage_agent.core import fact_schema as fs


def fake_run(stdout="[]", returncode=0, stderr=""):
    """A ``subprocess.run`` stand-in returning one canned osqueryi result."""

    def _run(*_args, **_kwargs):
        return subprocess.CompletedProcess(
            args=["osqueryi"], returncode=returncode, stdout=stdout, stderr=stderr
        )

    return _run


def registry_rows(*names):
    return json.dumps([{"name": n} for n in names])


@pytest.fixture(autouse=True)
def clean_registry():
    """Providers and the probed-table cache are module state; reset both."""
    fs.clear_providers()
    fo.reset_cache()
    yield
    fs.clear_providers()
    fo.reset_cache()


# --------------------------------------------------------------------------
# finding the binary
# --------------------------------------------------------------------------


def test_no_binary_anywhere_is_none_not_an_exception():
    with patch.object(fo.shutil, "which", return_value=None):
        assert fo.osquery_path() is None


def test_binary_on_path_wins():
    with patch.object(fo.shutil, "which", side_effect=lambda p: "/usr/bin/osqueryi"):
        assert fo.osquery_path() == "/usr/bin/osqueryi"


def test_binary_off_path_is_still_found():
    """A service account's PATH is frequently not an operator's."""

    def which(path):
        return path if path == "/opt/osquery/bin/osqueryi" else None

    with patch.object(fo.shutil, "which", side_effect=which):
        assert fo.osquery_path() == "/opt/osquery/bin/osqueryi"


# --------------------------------------------------------------------------
# which tables this build actually has
# --------------------------------------------------------------------------


def test_available_tables_is_asked_not_assumed():
    rows = registry_rows("users", "os_version", "yara_events", "curl")
    with patch.object(fo.shutil, "which", return_value="/usr/bin/osqueryi"):
        with patch.object(fo.subprocess, "run", fake_run(rows)):
            tables = fo.available_tables()
    # Intersected with the contract: osquery has hundreds of tables we do not
    # model, and claiming them would advertise coverage we cannot serve.
    assert "users" in tables and "os_version" in tables
    assert "yara_events" not in tables and "curl" not in tables


def test_sysmanage_tables_are_never_served_by_osquery():
    """Even if a build somehow had the name, the namespace is ours."""
    rows = registry_rows("users", "sysmanage_repositories")
    with patch.object(fo.shutil, "which", return_value="/usr/bin/osqueryi"):
        with patch.object(fo.subprocess, "run", fake_run(rows)):
            assert fo.available_tables() == {"users"}


def test_missing_binary_yields_empty_set_quietly():
    with patch.object(fo.shutil, "which", return_value=None):
        assert fo.available_tables() == set()


def test_unhealthy_osquery_yields_empty_set_rather_than_raising():
    """A nonzero exit is a normal field condition, not a crash."""
    with patch.object(fo.shutil, "which", return_value="/usr/bin/osqueryi"):
        with patch.object(fo.subprocess, "run", fake_run("", 1, "boom")):
            assert fo.available_tables() == set()


def test_timeout_yields_empty_set_rather_than_hanging_the_report():
    def explode(*_a, **_k):
        raise subprocess.TimeoutExpired(cmd="osqueryi", timeout=60)

    with patch.object(fo.shutil, "which", return_value="/usr/bin/osqueryi"):
        with patch.object(fo.subprocess, "run", explode):
            assert fo.available_tables() == set()


def test_table_set_is_probed_once_not_once_per_table():
    """build_fact_coverage() probes every table; sixteen shell-outs per
    capability report would be a self-inflicted performance bug."""
    calls = []

    def counting(*args, **kwargs):
        calls.append(args)
        return fake_run(registry_rows("users"))(*args, **kwargs)

    with patch.object(fo.shutil, "which", return_value="/usr/bin/osqueryi"):
        with patch.object(fo.subprocess, "run", counting):
            fo.available_tables()
            fo.available_tables()
            fo.available_tables()
    assert len(calls) == 1


def test_reset_cache_forces_a_re_probe():
    with patch.object(fo.shutil, "which", return_value="/usr/bin/osqueryi"):
        with patch.object(fo.subprocess, "run", fake_run(registry_rows("users"))):
            assert fo.available_tables() == {"users"}
        fo.reset_cache()
        with patch.object(
            fo.subprocess, "run", fake_run(registry_rows("users", "os_version"))
        ):
            assert fo.available_tables() == {"users", "os_version"}


# --------------------------------------------------------------------------
# registration and provider choice
# --------------------------------------------------------------------------


def test_opt_out_registers_nothing():
    """Installed is not the same as chosen.  A host that happens to have
    osquery must not silently start using it."""
    with patch.object(fo.shutil, "which", return_value="/usr/bin/osqueryi"):
        with patch.object(fo.subprocess, "run", fake_run(registry_rows("users"))):
            fo.register_osquery_provider(enabled=False)
    assert fs.registered_providers("users") == ()


def test_osquery_is_preferred_over_native_when_healthy():
    fn.register_native_provider()
    with patch.object(fo.shutil, "which", return_value="/usr/bin/osqueryi"):
        with patch.object(fo.subprocess, "run", fake_run(registry_rows("users"))):
            fo.register_osquery_provider(enabled=True)
            coverage = fs.build_fact_coverage("linux")
    assert coverage["served"]["users"] == fs.PROVIDER_OSQUERY


def test_a_table_osquery_lacks_still_comes_from_native():
    """Provider selection is PER TABLE.  The FreeBSD port has no package
    tables at all, and that must not cost the host its user facts."""
    fn.register_native_provider()
    with patch.object(fo.shutil, "which", return_value="/usr/bin/osqueryi"):
        with patch.object(fo.subprocess, "run", fake_run(registry_rows("users"))):
            fo.register_osquery_provider(enabled=True)
            coverage = fs.build_fact_coverage("linux")
    assert coverage["served"]["users"] == fs.PROVIDER_OSQUERY
    assert coverage["served"]["os_version"] == fs.PROVIDER_NATIVE


def test_broken_osquery_degrades_to_native_not_to_nothing():
    """THE FreeBSD case: the binary is present, the port is patched seven ways,
    and the probe blows up.  The walk must continue to the next provider."""
    fn.register_native_provider()

    def detonate():
        raise RuntimeError("osquery segfaulted")

    fs.register_provider("users", fs.PROVIDER_OSQUERY, detonate)
    coverage = fs.build_fact_coverage("linux")
    assert coverage["served"]["users"] == fs.PROVIDER_NATIVE
    assert "users" not in coverage["unsupported"]


def test_osquery_alone_and_broken_is_unsupported_not_silently_empty():
    """With no native fallback the honest answer is 'unsupported', which is
    what keeps 'not measured' distinguishable from 'measured and empty'."""

    def detonate():
        raise RuntimeError("osquery segfaulted")

    fs.register_provider("users", fs.PROVIDER_OSQUERY, detonate)
    coverage = fs.build_fact_coverage("linux")
    assert "users" not in coverage["served"]
    assert coverage["unsupported"]["users"] == fs.REASON_PROVIDER_FAILED


# --------------------------------------------------------------------------
# reading rows
# --------------------------------------------------------------------------


def test_collect_returns_rows():
    rows = json.dumps([{"username": "root", "uid": "0"}])
    with patch.object(fo.shutil, "which", return_value="/usr/bin/osqueryi"):
        with patch.object(fo.subprocess, "run", fake_run(rows)):
            got = fo.collect(["users"])
    assert got["users"][0]["username"] == "root"


def test_a_failing_table_is_omitted_not_reported_empty():
    """An empty list would read as 'measured, found no users', which is a
    different and much worse claim than 'could not measure'."""
    with patch.object(fo.shutil, "which", return_value="/usr/bin/osqueryi"):
        with patch.object(fo.subprocess, "run", fake_run("", 1, "no such table")):
            got = fo.collect(["users"])
    assert "users" not in got


def test_empty_output_is_an_empty_table_not_a_parse_error():
    with patch.object(fo.shutil, "which", return_value="/usr/bin/osqueryi"):
        with patch.object(fo.subprocess, "run", fake_run("")):
            assert fo.collect(["users"]) == {"users": []}


def test_run_without_a_binary_raises_rather_than_returning_nothing():
    with patch.object(fo.shutil, "which", return_value=None):
        with pytest.raises(FileNotFoundError):
            fo._run("SELECT 1")  # pylint: disable=protected-access


# --------------------------------------------------------------------------
# conformance
# --------------------------------------------------------------------------


def test_json_string_typing_is_not_reported_as_disagreement():
    """osqueryi returns "0"; the native provider returns 0.  A raw diff would
    call every row different and tell us nothing about the facts."""
    native = [{"username": "root", "uid": 0}]
    osquery = [{"username": "root", "uid": "0"}]
    diff = fo.conformance_diff(["username", "uid"], native, osquery)
    assert diff == {"native_only": [], "osquery_only": []}


def test_a_real_disagreement_is_reported_from_both_sides():
    native = [{"username": "root"}, {"username": "ghost"}]
    osquery = [{"username": "root"}, {"username": "daemon"}]
    diff = fo.conformance_diff(["username"], native, osquery)
    assert diff["native_only"] == [("ghost",)]
    assert diff["osquery_only"] == [("daemon",)]


def test_row_order_is_not_a_disagreement():
    native = [{"username": "a"}, {"username": "b"}]
    osquery = [{"username": "b"}, {"username": "a"}]
    assert fo.conformance_diff(["username"], native, osquery) == {
        "native_only": [],
        "osquery_only": [],
    }


def test_deliberately_unfilled_columns_are_excluded_by_the_caller():
    """Native leaves ``users.gid`` NULL on purpose.  Comparing on the columns
    that identify the fact is what makes the answer about the fact."""
    native = [{"username": "root", "gid": None}]
    osquery = [{"username": "root", "gid": "0"}]
    assert fo.conformance_diff(["username"], native, osquery)["osquery_only"] == []
    assert fo.conformance_diff(["username", "gid"], native, osquery)[
        "osquery_only"
    ] == [("root", "0")]


def test_the_invocation_does_not_pin_a_database_path():
    """osqueryi keeps its own ephemeral database, which is what lets it run on
    a host where osqueryd holds the RocksDB lock.  Passing --database_path is
    how that turns into 'IO error: lock hold by current process'."""
    seen = {}

    def capture(argv, **kwargs):
        seen["argv"] = argv
        return fake_run("[]")(argv, **kwargs)

    with patch.object(fo.shutil, "which", return_value="/usr/bin/osqueryi"):
        with patch.object(fo.subprocess, "run", capture):
            fo.collect(["users"])
    assert not any(a.startswith("--database_path") for a in seen["argv"])
    assert "--disable_extensions" in seen["argv"]


def test_the_sql_is_one_argv_element_never_a_shell_string():
    """From S4 the statement is tenant-authored.  It must reach osquery as a
    single argument, not as text some shell gets to re-parse."""
    seen = {}

    def capture(argv, **kwargs):
        seen["argv"] = argv
        seen["shell"] = kwargs.get("shell", False)
        return fake_run("[]")(argv, **kwargs)

    with patch.object(fo.shutil, "which", return_value="/usr/bin/osqueryi"):
        with patch.object(fo.subprocess, "run", capture):
            fo._run("SELECT 1")  # pylint: disable=protected-access
    assert seen["argv"][-1] == "SELECT 1"
    assert seen["shell"] is False


class TestDenylist:
    """Tables this osquery build HAS but must not be used for.

    Measured on FreeBSD 14.4 with the 5.23.0 port: ``listening_ports``
    returned 459 rows, 425 of them with ``port = 0``, while the native
    provider reported the six real listeners correctly. The table is present
    and the probe says healthy, so nothing else in the path would decline it
    -- and osquery is PREFERRED when healthy, so without this the fragile
    FreeBSD leg would replace correct data with garbage.
    """

    def test_freebsd_listening_ports_is_denied(self):
        denied = fo.denied_tables("freebsd")
        assert "listening_ports" in denied
        assert "port=0" in denied["listening_ports"]

    def test_linux_is_not_affected(self):
        """The denylist is per platform: Linux's listening_ports is fine."""
        assert fo.denied_tables("linux") == {}

    def test_a_denied_table_never_enters_the_served_set(self):
        """Dropped at discovery, not at query time, so coverage reports it
        against the native provider and the host keeps a correct answer."""
        rows = registry_rows("users", "listening_ports", "os_version")
        with patch.object(fo, "platform") as fake_platform:
            fake_platform.system.return_value = "FreeBSD"
            with patch.object(fo.shutil, "which", return_value="/usr/bin/osqueryi"):
                with patch.object(fo.subprocess, "run", fake_run(rows)):
                    tables = fo.available_tables()
        assert "users" in tables and "os_version" in tables
        assert "listening_ports" not in tables

    def test_the_denied_table_still_gets_served_natively(self):
        """The point of the whole exercise: coverage must not lose the table,
        it must stop reading it through the broken provider."""
        fn.register_native_provider()
        rows = registry_rows("users", "listening_ports")
        with patch.object(fo, "platform") as fake_platform:
            fake_platform.system.return_value = "FreeBSD"
            with patch.object(fo.shutil, "which", return_value="/usr/bin/osqueryi"):
                with patch.object(fo.subprocess, "run", fake_run(rows)):
                    fo.register_osquery_provider(enabled=True)
        coverage = fs.build_fact_coverage("freebsd")
        assert coverage["served"]["users"] == fs.PROVIDER_OSQUERY
        # Native, or unsupported for privilege -- but NEVER osquery.
        assert coverage["served"].get("listening_ports") != fs.PROVIDER_OSQUERY
