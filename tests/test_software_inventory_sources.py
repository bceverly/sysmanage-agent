# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""Source packages in the Linux inventory (2026-11-23): Debian, Fedora and
Alpine advisories name the SOURCE package, so each installed package carries
the one it was built from; and dnf5's inventory, which came back empty."""


def test_dnf5_header_is_recognized_and_source_packages_are_kept():
    """Fedora 41+ (dnf5) prints "Installed packages"; the collector waited for
    "Installed Packages" and collected nothing (2026-11-23).  Each package
    also carries its source RPM's name, which Fedora's advisories use."""
    from unittest.mock import Mock, patch  # pylint: disable=import-outside-toplevel

    from src.sysmanage_agent.collection.software_inventory_linux import (  # pylint: disable=import-outside-toplevel
        LinuxSoftwareInventoryCollector,
    )

    def run(argv, **_kw):
        if argv[0] == "rpm":
            return Mock(
                returncode=0, stdout="openssl-libs\topenssl-3.2.4-3.fc42.src.rpm\n"
            )
        return Mock(
            returncode=0,
            stdout=(
                "Installed packages\n"
                "openssl-libs.x86_64     1:3.2.4-3.fc42     updates\n"
            ),
        )

    collector = LinuxSoftwareInventoryCollector()
    collector.collected_packages = []
    with patch("subprocess.run", side_effect=run):
        collector._collect_dnf_packages()  # pylint: disable=protected-access
    assert [
        (p["package_name"], p["version"], p["source_package"])
        for p in collector.collected_packages
    ] == [("openssl-libs", "1:3.2.4-3.fc42", "openssl")]


def test_source_rpm_names():
    from src.sysmanage_agent.collection.software_inventory_linux import (  # pylint: disable=import-outside-toplevel
        rpm_source_name,
    )

    assert rpm_source_name("openssl-3.0.7-27.el9.src.rpm") == "openssl"
    assert rpm_source_name("python3.12-3.12.9-1.el9.src.rpm") == "python3.12"
    assert rpm_source_name("(none)") is None and rpm_source_name("") is None
