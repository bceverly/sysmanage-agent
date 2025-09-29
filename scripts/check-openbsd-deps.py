#!/usr/bin/env python3
"""
Coverage.py C tracer checker and installer.
Detects if coverage.py C tracer is unavailable and attempts to fix it.
Works on all platforms, with specific OpenBSD 7.7 support.
"""

import platform
import subprocess
import sys
import warnings


def check_bsd_system():
    """Check if we're running on a BSD system."""
    system = platform.system().lower()
    return system in ["openbsd", "netbsd"]


def check_openbsd_system():
    """Check if we're running on OpenBSD (legacy function)."""
    return platform.system().lower() == "openbsd"


def check_netbsd_system():
    """Check if we're running on NetBSD."""
    return platform.system().lower() == "netbsd"


def check_pkg_installed(package_name):
    """Check if a BSD package is installed."""
    if check_openbsd_system():
        # OpenBSD uses pkg_info
        try:
            result = subprocess.run(
                ["pkg_info", "-e", package_name], capture_output=True, text=True
            )
            return result.returncode == 0
        except FileNotFoundError:
            return False
    elif check_netbsd_system():
        # NetBSD uses pkgin
        try:
            result = subprocess.run(
                ["pkgin", "list", package_name], capture_output=True, text=True
            )
            # pkgin list returns 0 if found, but we need to check if it's actually listed
            if result.returncode == 0 and result.stdout.strip():
                # If package is listed and not empty output, it's installed
                return package_name in result.stdout
            return False
        except FileNotFoundError:
            return False
    else:
        return False


def check_c_tracer_available():
    """Check if coverage C tracer is available using coverage debug command."""
    try:
        result = subprocess.run(
            [sys.executable, "-m", "coverage", "debug", "sys"],
            capture_output=True,
            text=True,
            timeout=10,
        )

        if result.returncode == 0:
            output = result.stdout.lower()

            # Check for CTracer status in debug output
            if "ctracer:" in output:
                if "available" in output and "unavailable" not in output:
                    print("✅ Coverage C tracer is available and active")
                    return True
                elif "unavailable" in output:
                    print("⚠️  Coverage C tracer is unavailable - needs reinstallation")
                    return False

            # Fallback: try direct import
            try:
                import coverage.tracer

                print("✅ Coverage C tracer is available (verified by import)")
                return True
            except ImportError:
                print(
                    "⚠️  Coverage C tracer not available - using Python tracer (slower)"
                )
                return False
        else:
            print("⚠️  Could not check C tracer status via coverage debug")
            return False

    except (subprocess.TimeoutExpired, FileNotFoundError, Exception) as e:
        print(f"⚠️  Error checking C tracer status: {e}")
        # Fallback to import test
        try:
            import coverage.tracer

            print("✅ Coverage C tracer available (fallback check)")
            return True
        except ImportError:
            print("⚠️  Coverage C tracer not available (fallback check)")
            return False


def install_coverage_with_c_extension():
    """Reinstall coverage with C extension on OpenBSD."""
    try:
        print("🔧 Reinstalling coverage with C extension...")

        # Uninstall existing coverage
        subprocess.run(
            [sys.executable, "-m", "pip", "uninstall", "-y", "coverage"],
            check=False,
            capture_output=True,
        )

        # Reinstall with forced compilation
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "pip",
                "install",
                "--force-reinstall",
                "--no-binary=:all:",
                "coverage",
            ],
            capture_output=True,
            text=True,
        )

        if result.returncode == 0:
            print("✅ Coverage reinstalled with C extension")
            return True
        else:
            print(f"❌ Failed to reinstall coverage: {result.stderr}")
            return False

    except Exception as e:
        print(f"❌ Error reinstalling coverage: {e}")
        return False


def verify_c_tracer():
    """Verify C tracer is working after installation."""
    try:
        result = subprocess.run(
            [sys.executable, "-m", "coverage", "debug", "sys"],
            capture_output=True,
            text=True,
        )

        if "CTracer" in result.stdout:
            print("✅ C tracer is active and working")
            return True
        else:
            print("⚠️  C tracer not active, using Python tracer")
            return False

    except Exception as e:
        print(f"❌ Error checking tracer status: {e}")
        return False


def main():
    print("Coverage.py C Tracer Dependency Check")
    print("=" * 40)

    system_name = platform.system()
    print(f"🔍 Detected {system_name} system")

    # Check C tracer status first (applies to all platforms)
    if check_c_tracer_available():
        print("✅ C tracer already working - no action needed")
        return

    print("🔧 C tracer not available - checking dependencies...")

    # BSD-specific package checks
    if check_openbsd_system():
        # Check if development tools are available on OpenBSD
        required_packages = [
            "gcc",  # C compiler
            "py3-cffi",  # Python CFFI for C extensions
        ]

        missing_packages = []
        for package in required_packages:
            if not check_pkg_installed(package):
                missing_packages.append(package)

        if missing_packages:
            print("⚠️  Missing required packages for C extension compilation:")
            for pkg in missing_packages:
                print(f"   - {pkg}")
            print()
            print("To install missing packages:")
            print(f"   doas pkg_add {' '.join(missing_packages)}")
            print()
            print("Note: C tracer will use Python fallback (slower but functional)")
            return

        print("✅ Required compilation tools are available")
    elif check_netbsd_system():
        # Check if development tools are available on NetBSD
        required_packages = [
            "gcc13",  # C compiler (NetBSD often uses versioned GCC)
            "py312-cffi",  # Python CFFI for C extensions
        ]

        missing_packages = []
        for package in required_packages:
            if not check_pkg_installed(package):
                missing_packages.append(package)

        if missing_packages:
            print("⚠️  Missing required packages for C extension compilation:")
            for pkg in missing_packages:
                print(f"   - {pkg}")
            print()
            print("To install missing packages:")
            print(f"   doas pkgin install {' '.join(missing_packages)}")
            print()
            print("Note: C tracer will use Python fallback (slower but functional)")
            return

        print("✅ Required compilation tools are available")
    else:
        # Non-BSD systems - assume dev tools are available or user can install them
        print("ℹ️  Non-BSD system - assuming development tools are available")

    # Try to reinstall coverage with C extension (works on all platforms)
    print("🔧 Attempting to reinstall coverage with C extension...")

    if install_coverage_with_c_extension():
        # Verify it worked
        if verify_c_tracer():
            print("\n🎉 C tracer successfully enabled!")
            print("Coverage.py will now run at native speed")
        else:
            print("\n⚠️  C tracer installation completed but not active")
            print("Coverage will work but use slower Python implementation")
    else:
        print("\n⚠️  Could not install C tracer - using Python fallback")
        print("Coverage will work but run slower")
        if not check_bsd_system():
            print("You may need to install development tools (gcc, python-dev, etc.)")

    print("\nNote: This only affects test coverage speed, not functionality")


if __name__ == "__main__":
    # Suppress coverage warnings during this check
    warnings.filterwarnings("ignore", message="Couldn't import C tracer")
    main()
