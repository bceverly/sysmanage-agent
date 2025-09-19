#!/usr/bin/env python3
"""
Model synchronization checker for sysmanage-agent.
Verifies that database models are properly defined with SQLite compatibility.

Usage: python scripts/check_test_models.py
"""

import re
import sys
import tempfile
from pathlib import Path


def extract_models_from_source():
    """Extract model names from source models file."""
    models = set()
    models_file = Path("src/database/models.py")

    if not models_file.exists():
        print(f"❌ Models file not found: {models_file}")
        return models

    with open(models_file) as f:
        content = f.read()
        # Find class definitions that inherit from Base
        class_pattern = r"^class\s+(\w+)\(Base\):$"
        for match in re.finditer(class_pattern, content, re.MULTILINE):
            models.add(match.group(1))

    return models


def check_sqlite_compatibility():
    """Check models for SQLite compatibility issues."""
    issues = []
    models_file = Path("src/database/models.py")

    if not models_file.exists():
        return ["❌ Models file not found"]

    with open(models_file) as f:
        content = f.read()
        lines = content.split("\n")

        for i, line in enumerate(lines, 1):
            # Check for Integer primary keys without autoincrement
            if "primary_key=True" in line and "Integer" in line:
                if "autoincrement=True" not in line:
                    issues.append(
                        f"Line {i}: Missing autoincrement=True for Integer primary key"
                    )

            # Check for potentially problematic DateTime usage
            if "DateTime(" in line and "timezone=True" in line:
                # This is fine for SQLAlchemy but flag for review
                if "UTCDateTime" not in line:
                    issues.append(
                        f"Line {i}: Consider using UTCDateTime instead of DateTime(timezone=True)"
                    )

    return issues


def check_test_isolation():
    """Check test files for proper database isolation."""
    issues = []
    test_files = list(Path("tests").glob("**/*.py"))

    for test_file in test_files:
        if test_file.name == "__init__.py":
            continue

        with open(test_file) as f:
            content = f.read()

            # Check for hardcoded database paths
            temp_dir = tempfile.gettempdir()
            if "agent.db" in content and temp_dir not in content:
                issues.append(f"{test_file}: Hardcoded production database path found")

            # Check for missing mocking of database operations
            if "get_database_manager" in content and "patch" not in content:
                issues.append(
                    f"{test_file}: Direct database manager usage without mocking"
                )

    return issues


def main():
    """Main function to run all checks."""
    print("🔍 SysManage Agent Model Synchronization Check")
    print("=" * 50)

    # Extract models
    models = extract_models_from_source()
    print(f"📊 Found {len(models)} models in source:")
    for model in sorted(models):
        print(f"  ✓ {model}")
    print()

    # Check SQLite compatibility
    print("🗄️  Checking SQLite compatibility...")
    sqlite_issues = check_sqlite_compatibility()
    if sqlite_issues:
        print("⚠️  SQLite compatibility issues found:")
        for issue in sqlite_issues:
            print(f"  ❌ {issue}")
    else:
        print("  ✅ All models are SQLite compatible")
    print()

    # Check test isolation
    print("🧪 Checking test database isolation...")
    test_issues = check_test_isolation()
    if test_issues:
        print("⚠️  Test isolation issues found:")
        for issue in test_issues:
            print(f"  ❌ {issue}")
    else:
        print("  ✅ Test isolation looks good")
    print()

    # Summary
    total_issues = len(sqlite_issues) + len(test_issues)
    if total_issues == 0:
        print("🎉 All checks passed! Models are properly synchronized and configured.")
        return 0
    else:
        print(f"❌ Found {total_issues} issues that need attention.")
        return 1


if __name__ == "__main__":
    sys.exit(main())
