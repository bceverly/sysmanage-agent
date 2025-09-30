#!/usr/bin/env python3
"""
Install development dependencies with platform-specific handling.

This script handles installation of dev dependencies with special cases for:
- NetBSD: grpcio requires C++17 flag due to GCC 10.5 limitations
- OpenBSD: Similar C++ standard issues
- Other platforms: Standard installation
"""

import os
import platform
import subprocess
import sys


def get_platform():
    """Detect the current platform."""
    system = platform.system().lower()
    return system


def install_packages_with_env(packages, env_vars=None):
    """Install packages with optional environment variables."""
    if env_vars is None:
        env_vars = {}

    # Merge with current environment
    env = os.environ.copy()
    env.update(env_vars)

    cmd = [sys.executable, "-m", "pip", "install"] + packages

    print(f"Installing: {' '.join(packages)}")
    if env_vars:
        print(f"With environment: {env_vars}")

    result = subprocess.run(cmd, env=env)
    return result.returncode == 0


def install_grpcio_netbsd():
    """Install grpcio on NetBSD with C++17 flag and system libraries."""
    print("\n=== NetBSD detected: Installing grpcio with C++17 support ===")

    # grpcio requires:
    # - C++17 for std::optional support
    # - -fpermissive to work around abseil alloca() declaration conflicts
    # - System c-ares library (bundled version is incomplete)
    # - Proper include/library paths for /usr/pkg
    env_vars = {
        "CFLAGS": "-I/usr/pkg/include",
        "CXXFLAGS": "-std=c++17 -I/usr/pkg/include -fpermissive",
        "LDFLAGS": "-L/usr/pkg/lib -Wl,-R/usr/pkg/lib",
        "GRPC_PYTHON_BUILD_SYSTEM_OPENSSL": "1",
        "GRPC_PYTHON_BUILD_SYSTEM_ZLIB": "1",
        "GRPC_PYTHON_BUILD_SYSTEM_CARES": "1",
    }

    # First try without building (use wheel if available)
    print("Attempting to install grpcio from pre-built wheel...")
    result = subprocess.run(
        [sys.executable, "-m", "pip", "install", "grpcio"], capture_output=True
    )

    if result.returncode == 0:
        print("✓ grpcio installed from wheel")
        return True

    # If wheel fails, build from source with C++17
    print("Wheel not available, building from source with C++17...")
    success = install_packages_with_env(["grpcio", "--no-binary", "grpcio"], env_vars)

    if success:
        print("✓ grpcio built and installed with C++17")
    else:
        print("⚠ grpcio installation failed - semgrep may not work fully")
        print("  This is non-critical for development")

    return success


def main():
    """Main installation routine."""
    system = get_platform()

    print(f"Platform detected: {system}")
    print("=" * 60)

    # Standard dev dependencies (no special handling needed)
    standard_deps = [
        "pytest",
        "pytest-cov",
        "pytest-asyncio",
        "pylint",
        "black",
        "isort",
        "bandit",
        "safety",
    ]

    # Install standard deps
    print("\n=== Installing standard development dependencies ===")
    if not install_packages_with_env(standard_deps):
        print("ERROR: Failed to install standard dependencies")
        sys.exit(1)
    print("✓ Standard dependencies installed")

    # Install requirements.txt
    print("\n=== Installing requirements.txt ===")
    if not install_packages_with_env(["-r", "requirements.txt"]):
        print("ERROR: Failed to install requirements.txt")
        sys.exit(1)
    print("✓ requirements.txt installed")

    # Handle platform-specific packages
    if system in ["netbsd", "openbsd"]:
        # Install semgrep which pulls in grpcio
        print(f"\n=== Installing semgrep for {system} ===")

        if system == "netbsd":
            # Pre-install grpcio with C++17 flag before semgrep
            install_grpcio_netbsd()

        # Now install semgrep (will use already-installed grpcio or skip if failed)
        print("\nInstalling semgrep...")
        result = subprocess.run(
            [sys.executable, "-m", "pip", "install", "semgrep"],
            capture_output=True,
            text=True,
        )

        if result.returncode == 0:
            print("✓ semgrep installed")
        else:
            # Check if semgrep is already installed
            check = subprocess.run(
                [sys.executable, "-c", "import semgrep"], capture_output=True
            )
            if check.returncode == 0:
                print("✓ semgrep already available")
            else:
                print("⚠ semgrep installation incomplete")
                print("  Security scanning in CI/CD will still work")
    else:
        # Linux, macOS, Windows - standard installation
        print("\n=== Installing semgrep ===")
        if install_packages_with_env(["semgrep"]):
            print("✓ semgrep installed")
        else:
            print("⚠ semgrep installation failed (non-critical)")

    print("\n" + "=" * 60)
    print("✓ Development dependencies installation complete!")

    return 0


if __name__ == "__main__":
    sys.exit(main())
