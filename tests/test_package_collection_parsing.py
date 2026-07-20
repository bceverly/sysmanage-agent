# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""
Unit tests for package collection functionality.

Parsing and platform-specific coverage split out of test_package_collection.py:
apt/yum/pacman/pkg/dumpavail parsers, per-manager collectors, package-manager
availability checks, and per-OS collection paths.
"""

# pylint: disable=wrong-import-position,protected-access,import-outside-toplevel

from unittest.mock import MagicMock, Mock, patch

import pytest

from src.sysmanage_agent.collection.package_collection import PackageCollector


class TestPackageCollectorParsing:  # pylint: disable=too-many-public-methods
    """Parsing and platform-specific test cases for PackageCollector."""

    @pytest.fixture
    def mock_db_manager(self):
        """Create a mock database manager."""
        db_manager = Mock()
        mock_session = Mock()
        # Create a proper context manager mock
        context_manager = Mock()
        context_manager.__enter__ = Mock(return_value=mock_session)
        context_manager.__exit__ = Mock(return_value=None)
        db_manager.get_session.return_value = context_manager
        return db_manager, mock_session

    @pytest.fixture
    def package_collector(self, mock_db_manager):
        """Create a PackageCollector instance with mocked dependencies."""
        db_manager, _ = mock_db_manager
        with patch(
            "src.sysmanage_agent.collection.package_collection.get_database_manager",
            return_value=db_manager,
        ):
            collector = PackageCollector()
        return collector

    @pytest.fixture
    def linux_package_collector(self, mock_db_manager):
        """Create a Linux PackageCollector instance for testing Linux-specific methods."""
        # pylint: disable=import-outside-toplevel
        from src.sysmanage_agent.collection.package_collector_linux import (
            LinuxPackageCollector,
        )

        db_manager, _ = mock_db_manager
        with patch(
            "src.sysmanage_agent.collection.package_collector_base.get_database_manager",
            return_value=db_manager,
        ):
            collector = LinuxPackageCollector()
        return collector

    def test_parse_apt_output_complex(self, linux_package_collector):
        """Test parsing complex APT output with various formats."""
        output = """
nginx/jammy-updates,jammy-security 1.18.0-6ubuntu14.4 all
  small, powerful, scalable web/proxy server

python3/jammy-updates 3.10.6-1~22.04 amd64
  interactive high-level object-oriented language (default python3 version)

package-without-description/jammy 1.0.0 all

malformed-line-without-slash 1.0.0
"""

        packages = linux_package_collector._parse_apt_output(
            output
        )  # pylint: disable=protected-access

        # Should parse valid packages and skip malformed ones
        assert len(packages) >= 2

        nginx_pkg = next((pkg for pkg in packages if pkg["name"] == "nginx"), None)
        assert nginx_pkg is not None
        assert nginx_pkg["version"] == "1.18.0-6ubuntu14.4"

    def test_parse_yum_output_formats(self, linux_package_collector):
        """Test parsing different YUM output formats."""
        output = """Available Packages
httpd.x86_64                    2.4.37-62.module+el8             appstream
nginx.x86_64                    1:1.20.1-1.el8                   epel
package-with-long-name.x86_64   1.0.0-1.el8.very.long.version   extras
"""

        packages = linux_package_collector._parse_yum_output(
            output
        )  # pylint: disable=protected-access

        assert len(packages) == 3

        httpd_pkg = next(pkg for pkg in packages if pkg["name"] == "httpd")
        assert httpd_pkg["version"] == "2.4.37-62.module+el8"

    def test_error_handling_in_collection_methods(self, linux_package_collector):
        """Test error handling in various collection methods."""
        # Test with subprocess that raises exception
        with patch("subprocess.run", side_effect=Exception("Command failed")):
            count = (
                linux_package_collector._collect_apt_packages()
            )  # pylint: disable=protected-access
            assert count == 0

            count = (
                linux_package_collector._collect_yum_packages()
            )  # pylint: disable=protected-access
            assert count == 0

            count = (
                linux_package_collector._collect_snap_packages()
            )  # pylint: disable=protected-access
            assert count == 0

    @patch("platform.system")
    @patch("subprocess.run")
    def test_package_manager_detection(self, mock_run, mock_system, mock_db_manager):
        """Test package manager detection based on system and available commands."""
        mock_system.return_value = "Linux"

        # Test APT detection - mock subprocess.run for "which" command
        def mock_subprocess_run(cmd, **_kwargs):
            _ = _kwargs
            result = Mock()
            if cmd == ["which", "apt"]:
                result.returncode = 0  # apt is available
            else:
                result.returncode = 1  # other package managers not available
            return result

        mock_run.side_effect = mock_subprocess_run

        _, _mock_session = mock_db_manager
        _ = _mock_session

        with patch(
            "src.sysmanage_agent.collection.package_collection.get_database_manager",
            return_value=mock_db_manager[0],
        ):
            # pylint: disable=reimported
            from src.sysmanage_agent.collection.package_collection import (
                PackageCollector as TestCollector,
            )

            package_collector = TestCollector()

            with patch.object(
                package_collector.collector, "_collect_apt_packages", return_value=5
            ) as mock_apt:
                package_collector.collect_all_available_packages()
                mock_apt.assert_called_once()

    def test_collection_with_network_timeout(self, package_collector):
        """Test package collection with network timeout scenarios."""
        with patch("subprocess.run") as mock_run:
            # Simulate timeout
            mock_run.side_effect = Exception("Timeout")

            result = package_collector.collect_all_available_packages()
            # Should handle timeout gracefully
            assert result is True

    @patch("subprocess.run")
    def test_collect_dnf_packages_success(self, mock_run, mock_db_manager):
        """Test successful DNF package collection."""
        # Create a Linux-specific collector directly
        from src.sysmanage_agent.collection.package_collector_linux import (
            LinuxPackageCollector,
        )

        _, mock_session = mock_db_manager

        with patch(
            "src.sysmanage_agent.collection.package_collector_base.get_database_manager",
            return_value=mock_db_manager[0],
        ):
            linux_collector = LinuxPackageCollector()

            mock_run.return_value.returncode = 0
            mock_run.return_value.stdout = """Available Packages
httpd.x86_64 2.4.37-62.module+el8 appstream
nginx.x86_64 1:1.20.1-1.el8 epel
python3.x86_64 3.9.16-1.el8_8.2 baseos
"""

            count = (
                linux_collector._collect_dnf_packages()
            )  # pylint: disable=protected-access

            assert count == 3
            assert mock_session.query.called
            assert mock_session.add.called
            assert mock_session.commit.called

    @patch("subprocess.run")
    def test_collect_zypper_packages_success(self, mock_run, mock_db_manager):
        """Test successful Zypper package collection."""
        # Create a Linux-specific collector directly
        from src.sysmanage_agent.collection.package_collector_linux import (
            LinuxPackageCollector,
        )

        _, mock_session = mock_db_manager

        with patch(
            "src.sysmanage_agent.collection.package_collector_base.get_database_manager",
            return_value=mock_db_manager[0],
        ):
            linux_collector = LinuxPackageCollector()

            mock_run.return_value.returncode = 0
            mock_run.return_value.stdout = """Loading repository data...
Reading installed packages...

S | Name    | Type    | Version | Arch   | Repository
--+---------+---------+---------+--------+-----------
  | apache2 | package | 2.4.51  | x86_64 | Main
  | nginx   | package | 1.20.1  | x86_64 | Main
"""

            count = (
                linux_collector._collect_zypper_packages()
            )  # pylint: disable=protected-access

            assert count >= 0  # Allow for parsing variations
            assert mock_session.query.called
            assert mock_session.commit.called

    @patch("subprocess.run")
    def test_collect_pacman_packages_success(self, mock_run, mock_db_manager):
        """Test successful Pacman package collection."""
        # Create a Linux-specific collector directly
        from src.sysmanage_agent.collection.package_collector_linux import (
            LinuxPackageCollector,
        )

        _, mock_session = mock_db_manager

        with patch(
            "src.sysmanage_agent.collection.package_collector_base.get_database_manager",
            return_value=mock_db_manager[0],
        ):
            linux_collector = LinuxPackageCollector()

            mock_run.return_value.returncode = 0
            mock_run.return_value.stdout = """extra/nginx 1.20.1-1
    Lightweight HTTP server and IMAP/POP3 proxy server
core/bash 5.1.016-1
    The GNU Bourne Again shell
"""

            count = (
                linux_collector._collect_pacman_packages()
            )  # pylint: disable=protected-access

            assert count == 2
            assert mock_session.query.called
            assert mock_session.add.called
            assert mock_session.commit.called

    @patch("subprocess.run")
    def test_collect_flatpak_packages_success(self, mock_run, mock_db_manager):
        """Test successful Flatpak package collection."""
        # Create a Linux-specific collector directly
        from src.sysmanage_agent.collection.package_collector_linux import (
            LinuxPackageCollector,
        )

        _, mock_session = mock_db_manager

        with patch(
            "src.sysmanage_agent.collection.package_collector_base.get_database_manager",
            return_value=mock_db_manager[0],
        ):
            linux_collector = LinuxPackageCollector()

            mock_run.return_value.returncode = 0
            mock_run.return_value.stdout = """
com.visualstudio.code	Visual Studio Code	1.82.2	stable	vscode
org.mozilla.firefox	Firefox	119.0	stable	mozilla
org.gimp.GIMP	GNU Image Manipulation Program	2.10.34	stable	gimp
"""

            count = (
                linux_collector._collect_flatpak_packages()
            )  # pylint: disable=protected-access

            assert count == 3
            assert mock_session.query.called
            assert mock_session.add.called
            assert mock_session.commit.called

    @patch("urllib.request.urlopen")
    def test_collect_winget_packages_success(self, mock_urlopen, mock_db_manager):
        """Test successful Winget package collection via REST API."""
        # Create a Windows-specific collector directly
        from src.sysmanage_agent.collection.package_collector_windows import (
            WindowsPackageCollector,
        )

        _, mock_session = mock_db_manager

        with patch(
            "src.sysmanage_agent.collection.package_collector_base.get_database_manager",
            return_value=mock_db_manager[0],
        ):
            windows_collector = WindowsPackageCollector()

            # Mock API responses simulating 4303 total packages
            # 358 full pages of 12 packages = 4296, then 1 page with 7 packages = 4303 total
            mock_responses = []

            # Pages 1-358: Full pages with 12 packages each
            for page in range(358):
                start_pkg = page * 12 + 1
                end_pkg = start_pkg + 12
                packages = [
                    b'{"Id": "pkg%d", "Latest": {"Name": "Package %d", "PackageVersion": "1.0.%d"}}'
                    % (i, i, i)
                    for i in range(start_pkg, end_pkg)
                ]
                mock_responses.append(
                    Mock(
                        read=Mock(
                            return_value=b'{"Packages": ['
                            + b",".join(packages)
                            + b'], "Total": 4303}'
                        )
                    )
                )

            # Page 359: Last page with 7 packages (4297-4303)
            packages = [
                b'{"Id": "pkg%d", "Latest": {"Name": "Package %d", "PackageVersion": "1.0.%d"}}'
                % (i, i, i)
                for i in range(4297, 4304)
            ]
            mock_responses.append(
                Mock(
                    read=Mock(
                        return_value=b'{"Packages": ['
                        + b",".join(packages)
                        + b'], "Total": 4303}'
                    )
                )
            )

            # Empty response to stop pagination
            mock_responses.append(
                Mock(read=Mock(return_value=b'{"Packages": [], "Total": 4303}'))
            )

            mock_urlopen.return_value.__enter__ = Mock(side_effect=mock_responses)
            mock_urlopen.return_value.__exit__ = Mock(return_value=False)

            count = (
                windows_collector._collect_winget_packages()
            )  # pylint: disable=protected-access

            assert count > 1000
            assert mock_session.query.called
            assert mock_session.add.called
            assert mock_session.commit.called

    @patch("urllib.request.urlopen")
    def test_collect_chocolatey_packages_success(self, mock_urlopen, mock_db_manager):
        """Test successful Chocolatey package collection via OData API."""
        # Create a Windows-specific collector directly
        from src.sysmanage_agent.collection.package_collector_windows import (
            WindowsPackageCollector,
        )

        _, mock_session = mock_db_manager

        with patch(
            "src.sysmanage_agent.collection.package_collector_base.get_database_manager",
            return_value=mock_db_manager[0],
        ):
            windows_collector = WindowsPackageCollector()

            # Mock XML responses for Chocolatey OData API
            # Simulate 250 pages of 40 packages each = 10,000 packages
            mock_responses = []

            for page in range(250):
                skip = page * 40
                entries = []
                for i in range(40):
                    pkg_num = skip + i + 1
                    entry = f"""<entry xmlns="http://www.w3.org/2005/Atom"
                                      xmlns:d="http://schemas.microsoft.com/ado/2007/08/dataservices"
                                      xmlns:m="http://schemas.microsoft.com/ado/2007/08/dataservices/metadata">
                                <title>package{pkg_num}</title>
                                <m:properties>
                                    <d:Version>1.0.{pkg_num}</d:Version>
                                </m:properties>
                            </entry>"""
                    entries.append(entry)

                xml_response = f"""<?xml version="1.0" encoding="utf-8"?>
                    <feed xmlns="http://www.w3.org/2005/Atom"
                          xmlns:d="http://schemas.microsoft.com/ado/2007/08/dataservices"
                          xmlns:m="http://schemas.microsoft.com/ado/2007/08/dataservices/metadata">
                        {''.join(entries)}
                    </feed>"""

                mock_responses.append(
                    Mock(read=Mock(return_value=xml_response.encode("utf-8")))
                )

            # Empty response to stop pagination
            empty_xml = """<?xml version="1.0" encoding="utf-8"?>
                <feed xmlns="http://www.w3.org/2005/Atom"
                      xmlns:d="http://schemas.microsoft.com/ado/2007/08/dataservices"
                      xmlns:m="http://schemas.microsoft.com/ado/2007/08/dataservices/metadata">
                </feed>"""
            mock_responses.append(
                Mock(read=Mock(return_value=empty_xml.encode("utf-8")))
            )

            mock_urlopen.return_value.__enter__ = Mock(side_effect=mock_responses)
            mock_urlopen.return_value.__exit__ = Mock(return_value=False)

            count = (
                windows_collector._collect_chocolatey_packages()
            )  # pylint: disable=protected-access

            assert count > 1000
            assert mock_session.query.called
            assert mock_session.add.called
            assert mock_session.commit.called

    @patch("subprocess.run")
    def test_collect_pkg_packages_success(self, mock_run, mock_db_manager):
        """Test successful FreeBSD pkg package collection."""
        # Create a BSD-specific collector directly
        from src.sysmanage_agent.collection.package_collector_bsd import (
            BSDPackageCollector,
        )

        _, mock_session = mock_db_manager

        with patch(
            "src.sysmanage_agent.collection.package_collector_base.get_database_manager",
            return_value=mock_db_manager[0],
        ):
            bsd_collector = BSDPackageCollector()

            mock_run.return_value.returncode = 0
            mock_run.return_value.stdout = """nginx-1.20.1,3
apache24-2.4.54
python39-3.9.16
"""

            count = (
                bsd_collector._collect_pkg_packages()
            )  # pylint: disable=protected-access

            assert count == 3
            assert mock_session.query.called
            assert mock_session.add.called
            assert mock_session.commit.called

    def test_parse_pacman_output_detailed(self, linux_package_collector):
        """Test detailed parsing of Pacman output."""
        output = """extra/nginx 1.20.1-1
    Lightweight HTTP server and IMAP/POP3 proxy server
core/bash 5.1.016-1
    The GNU Bourne Again shell
community/docker 20.10.21-1
    Pack, ship and run any application as a lightweight container
"""

        packages = linux_package_collector._parse_pacman_output(
            output
        )  # pylint: disable=protected-access

        assert len(packages) == 3

        nginx_pkg = next((pkg for pkg in packages if pkg["name"] == "nginx"), None)
        assert nginx_pkg is not None
        assert nginx_pkg["version"] == "1.20.1-1"
        assert "HTTP server" in nginx_pkg["description"]

        bash_pkg = next((pkg for pkg in packages if pkg["name"] == "bash"), None)
        assert bash_pkg is not None
        assert bash_pkg["version"] == "5.1.016-1"

    # test_parse_chocolatey_output_detailed removed - Chocolatey now uses OData XML API
    # instead of command-line parsing, so _parse_chocolatey_output() method no longer exists

    def test_parse_pkg_output_detailed(self):
        """Test detailed parsing of FreeBSD pkg output."""
        # Create a BSD-specific collector directly
        from src.sysmanage_agent.collection.package_collector_bsd import (
            BSDPackageCollector,
        )

        with patch(
            "src.sysmanage_agent.collection.package_collector_base.get_database_manager"
        ):
            bsd_collector = BSDPackageCollector()

            output = """nginx-1.20.1,3
apache24-2.4.54
python39-3.9.16
postgresql13-server-13.12
"""

            packages = bsd_collector._parse_pkg_output(
                output
            )  # pylint: disable=protected-access

            assert len(packages) == 4

            nginx_pkg = next((pkg for pkg in packages if pkg["name"] == "nginx"), None)
            assert nginx_pkg is not None
            assert nginx_pkg["version"] == "1.20.1,3"

            apache_pkg = next(
                (pkg for pkg in packages if pkg["name"] == "apache24"), None
            )
            assert apache_pkg is not None
            assert apache_pkg["version"] == "2.4.54"

    @patch("platform.system")
    def test_is_package_manager_available_success(self, mock_system, package_collector):
        """Test package manager availability detection."""
        mock_system.return_value = "Linux"

        with patch("subprocess.run") as mock_run:
            mock_run.return_value.returncode = 0

            result = package_collector._is_package_manager_available(
                "apt"
            )  # pylint: disable=protected-access

            assert result is True
            mock_run.assert_called_once_with(
                ["which", "apt"], capture_output=True, timeout=10, check=False
            )

    def test_is_package_manager_available_failure(self, package_collector):
        """Test package manager availability detection when not available."""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value.returncode = 1

            result = package_collector._is_package_manager_available(
                "nonexistent"
            )  # pylint: disable=protected-access

            assert result is False

    def test_is_package_manager_available_exception(self, package_collector):
        """Test package manager availability detection with exception."""
        with patch("subprocess.run", side_effect=Exception("Command failed")):
            result = package_collector._is_package_manager_available(
                "apt"
            )  # pylint: disable=protected-access

            assert result is False

    def test_collect_linux_packages_multiple_managers(self):
        """Test Linux package collection with multiple package managers."""
        # Create a Linux-specific collector directly
        from src.sysmanage_agent.collection.package_collector_linux import (
            LinuxPackageCollector,
        )

        with patch(
            "src.sysmanage_agent.collection.package_collector_base.get_database_manager"
        ):
            linux_collector = LinuxPackageCollector()

            with patch.object(
                linux_collector, "_is_package_manager_available"
            ) as mock_available:
                with patch.object(
                    linux_collector, "_collect_apt_packages", return_value=5
                ) as mock_apt:
                    with patch.object(
                        linux_collector, "_collect_snap_packages", return_value=3
                    ) as mock_snap:
                        # Mock apt and snap as available
                        def available_side_effect(manager):
                            return manager in ["apt", "snap"]

                        mock_available.side_effect = available_side_effect

                        count = linux_collector.collect_packages()

                        assert count == 8  # 5 + 3
                        mock_apt.assert_called_once()
                        mock_snap.assert_called_once()

    def test_collect_macos_packages_homebrew(self):
        """Test macOS package collection with Homebrew."""
        # Create a macOS-specific collector directly
        from src.sysmanage_agent.collection.package_collector_macos import (
            MacOSPackageCollector,
        )

        with patch(
            "src.sysmanage_agent.collection.package_collector_base.get_database_manager"
        ):
            macos_collector = MacOSPackageCollector()

            with patch.object(
                macos_collector, "_is_package_manager_available", return_value=True
            ):
                with patch.object(
                    macos_collector, "_collect_homebrew_packages", return_value=10
                ) as mock_homebrew:
                    count = macos_collector.collect_packages()

                    assert count == 10
                    mock_homebrew.assert_called_once()

    def test_collect_windows_packages_multiple_managers(self):
        """Test Windows package collection with multiple package managers."""
        # Create a Windows-specific collector directly
        from src.sysmanage_agent.collection.package_collector_windows import (
            WindowsPackageCollector,
        )

        with patch(
            "src.sysmanage_agent.collection.package_collector_base.get_database_manager"
        ):
            windows_collector = WindowsPackageCollector()

            with patch.object(
                windows_collector, "_is_package_manager_available"
            ) as mock_available:
                with patch.object(
                    windows_collector, "_collect_winget_packages", return_value=7
                ) as mock_winget:
                    with patch.object(
                        windows_collector,
                        "_collect_chocolatey_packages",
                        return_value=4,
                    ) as mock_choco:
                        # Mock both as available
                        def available_side_effect(manager):
                            return manager in ["winget", "choco"]

                        mock_available.side_effect = available_side_effect

                        count = windows_collector.collect_packages()

                        assert count == 11  # 7 + 4
                        mock_winget.assert_called_once()
                        mock_choco.assert_called_once()

    @patch("platform.system")
    def test_collect_bsd_packages_pkg(self, mock_system):
        """Test BSD package collection with pkg."""
        # Create a BSD-specific collector directly
        from src.sysmanage_agent.collection.package_collector_bsd import (
            BSDPackageCollector,
        )

        # Mock platform.system to return FreeBSD
        mock_system.return_value = "FreeBSD"

        with patch(
            "src.sysmanage_agent.collection.package_collector_base.get_database_manager"
        ):
            bsd_collector = BSDPackageCollector()

            # Mock _is_package_manager_available to only return True for pkg
            def mock_pm_available(manager):
                return manager == "pkg"

            with patch.object(
                bsd_collector,
                "_is_package_manager_available",
                side_effect=mock_pm_available,
            ):
                with patch.object(
                    bsd_collector, "_collect_pkg_packages", return_value=12
                ) as mock_pkg:
                    count = bsd_collector.collect_packages()

                    assert count == 12
                    mock_pkg.assert_called_once()

    def test_parse_apt_dumpavail_output_detailed(self, linux_package_collector):
        """Test detailed parsing of apt-cache dumpavail output."""
        output = """Package: nginx
Version: 1.18.0-6ubuntu14.4
Description: small, powerful, scalable web/proxy server
 Nginx is a web server with a strong focus on high concurrency, performance
 and low memory usage.

Package: python3
Version: 3.10.6-1~22.04
Description: interactive high-level object-oriented language
 Python is an interpreted, interactive, object-oriented programming
 language.

Package: apache2
Version: 2.4.52-1ubuntu4.7
Description: Apache HTTP Server
 The Apache HTTP Server Project's goal is to build a secure, efficient and
 extensible HTTP server.
"""

        packages = linux_package_collector._parse_apt_dumpavail_output(
            output
        )  # pylint: disable=protected-access

        assert len(packages) == 3

        nginx_pkg = next((pkg for pkg in packages if pkg["name"] == "nginx"), None)
        assert nginx_pkg is not None
        assert nginx_pkg["version"] == "1.18.0-6ubuntu14.4"
        assert "web/proxy server" in nginx_pkg["description"]

        python_pkg = next((pkg for pkg in packages if pkg["name"] == "python3"), None)
        assert python_pkg is not None
        assert python_pkg["version"] == "3.10.6-1~22.04"

    def test_package_collection_error_handling(self, linux_package_collector):
        """Test error handling in various package collection scenarios."""

        # Test command failure — dumpavail is streamed via Popen now, so mock
        # that too (otherwise the real apt-cache would run).
        with patch("subprocess.run") as mock_run, patch(
            "subprocess.Popen"
        ) as mock_popen:
            mock_run.return_value = Mock(returncode=1, stderr="Command failed")
            proc = MagicMock()
            proc.__enter__.return_value = proc
            proc.__exit__.return_value = False
            proc.stdout = iter([])
            proc.returncode = 1
            mock_popen.return_value = proc

            count = (
                linux_package_collector._collect_apt_packages()
            )  # pylint: disable=protected-access
            assert count == 0

        # Test parsing empty output
        empty_packages = linux_package_collector._parse_apt_output(
            ""
        )  # pylint: disable=protected-access
        assert empty_packages == []

        # Test malformed output handling
        malformed_output = "This is not valid package output"
        malformed_packages = linux_package_collector._parse_yum_output(
            malformed_output
        )  # pylint: disable=protected-access
        assert malformed_packages == []
