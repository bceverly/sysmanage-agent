# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""Column-level fact coverage: the advertisement must say what is FILLED.

Both directions are defects. A column advertised but never filled reads as
real NULL data -- "filesystem over 90% full" answered "does not fire" on a host
whose capacity was never read (21.2 S0, 2026-09-23). A column filled but not
advertised makes a rule refuse a host it could have assessed. So the declared
list is held EQUAL to what each builder's rows carry, read from the builder's
own source rather than retyped here.
"""

# pylint: disable=protected-access

import ast
import inspect

import pytest

from src.sysmanage_agent.collection import fact_native as fn
from src.sysmanage_agent.collection.fact_native_columns import NATIVE_COLUMNS
from src.sysmanage_agent.core import fact_schema as fs

# The builder behind each table (several are registered through a lambda).
BUILDERS = {
    "users": fn.build_users,
    "groups": fn.build_groups,
    "user_groups": fn.build_user_groups,
    "os_version": fn.build_os_version,
    "system_info": fn.build_system_info,
    "interface_addresses": fn.build_interface_addresses,
    "mounts": fn.build_mounts,
    "processes": fn.build_processes,
    "listening_ports": fn.build_listening_ports,
    "certificates": fn.build_certificates,
    "sysmanage_packages": fn.build_sysmanage_packages,
    "sysmanage_available_updates": fn.build_available_updates,
    "deb_packages": fn.build_deb_packages,
    "rpm_packages": fn.build_rpm_packages,
    "homebrew_packages": fn.build_homebrew_packages,
    "programs": fn.build_programs,
}

_MODULE_FUNCS = {name: obj for name, obj in vars(fn).items() if inspect.isfunction(obj)}


def _row_keys(func, seen=None):
    """String keys of every dict literal in ``func`` and the fact_native
    helpers it calls -- the columns its rows can carry."""
    seen = seen if seen is not None else set()
    if func.__name__ in seen:
        return set()
    seen.add(func.__name__)
    keys = set()
    for node in ast.walk(ast.parse(inspect.getsource(func).lstrip())):
        if isinstance(node, ast.Dict):
            keys |= {
                k.value
                for k in node.keys
                if isinstance(k, ast.Constant) and isinstance(k.value, str)
            }
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            helper = _MODULE_FUNCS.get(node.func.id)
            if helper is not None and helper.__module__ == fn.__name__:
                keys |= _row_keys(helper, seen)
    return keys


@pytest.mark.parametrize("table", sorted(BUILDERS))
def test_declared_columns_are_exactly_what_the_builder_emits(table):
    assert set(NATIVE_COLUMNS[table]) == _row_keys(BUILDERS[table]) & set(
        fs.columns(table)
    )


def test_every_declared_table_has_a_builder_and_contract_columns():
    assert set(NATIVE_COLUMNS) == set(BUILDERS)
    for table, cols in NATIVE_COLUMNS.items():
        assert set(cols) <= set(fs.columns(table)), table


def test_coverage_advertises_columns_for_every_served_table():
    fn.register_native_provider()
    cov = fs.build_fact_coverage(fn.platform_name())
    assert set(cov["columns"]) == set(cov["served"])
    if "processes" in cov["served"] and cov["served"]["processes"] == "native":
        assert "path" not in cov["columns"]["processes"]  # native leaves it NULL


def test_a_table_without_a_declaration_advertises_all_contract_columns():
    fn.register_native_provider()
    assert fs.populated_columns("sysmanage_file_state", "native") == fs.columns(
        "sysmanage_file_state"
    )


def test_registering_a_non_contract_column_is_refused():
    with pytest.raises(KeyError):
        fs.register_provider("users", "native", lambda: True, columns=("not_a_column",))
