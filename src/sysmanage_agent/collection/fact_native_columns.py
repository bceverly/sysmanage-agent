# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""The contract columns each native fact builder actually FILLS.

Advertised to the server with the fact coverage, so a consumer that reads a
column the native provider leaves NULL (``processes.path``, ``users.gid``)
gets "not measured" rather than evaluating against NULLs and finding nothing.
That is not hypothetical: native ``mounts`` served the table while filling
none of its capacity columns, and "filesystem over 90% full" answered "does
not fire" on a real host (Phase 21.2 S0, 2026-09-23).

A table not listed here fills every contract column (``sysmanage_file_state``,
``sysmanage_process_packages``). ``tests/test_fact_native_columns.py`` holds
this equal to what the builders really emit.
"""

from typing import Dict, Tuple


def _cols(names: str) -> Tuple[str, ...]:
    return tuple(names.split())


NATIVE_COLUMNS: Dict[str, Tuple[str, ...]] = {
    "users": _cols("uid username directory shell"),
    "groups": _cols("gid groupname"),
    "user_groups": _cols("uid gid"),
    "os_version": _cols("name version build platform platform_like codename arch"),
    "system_info": _cols(
        "hostname cpu_type cpu_brand cpu_physical_cores cpu_logical_cores"
        " physical_memory"
    ),
    "interface_addresses": _cols("interface address mask broadcast point_to_point"),
    "mounts": _cols(
        "device path type flags blocks_size blocks blocks_free blocks_available"
        " inodes inodes_free"
    ),
    "processes": _cols("pid name cmdline state parent resident_size"),
    "listening_ports": _cols("pid port protocol family address fd path"),
    "certificates": _cols(
        "common_name subject issuer ca self_signed not_valid_before"
        " not_valid_after key_usage path serial"
    ),
    "sysmanage_packages": _cols(
        "name version package_manager architecture description source"
    ),
    "sysmanage_available_updates": _cols(
        "name current_version available_version package_manager is_security"
    ),
    "deb_packages": _cols("name version"),
    "rpm_packages": _cols("name version"),
    "homebrew_packages": _cols("name version"),
    "programs": _cols("name version"),
}
