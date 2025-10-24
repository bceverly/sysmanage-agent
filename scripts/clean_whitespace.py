#!/usr/bin/env python3
"""
Clean trailing whitespace from Python files.
Cross-platform utility for the SysManage Agent build system.
"""

import os
import re


def clean_whitespace():
    """Remove trailing whitespace from all Python files in the project."""
    files_cleaned = 0

    # Skip these directories
    skip_dirs = {
        ".venv",
        "__pycache__",
        ".git",
        "node_modules",
        ".pytest_cache",
        "htmlcov",
        "parts",
        "stage",
        "prime",
        "installer",
    }

    for root, dirs, files in os.walk("."):
        # Remove skip directories from dirs list to avoid walking them
        dirs[:] = [d for d in dirs if d not in skip_dirs]

        for file in files:
            if file.endswith(".py"):
                filepath = os.path.join(root, file)
                try:
                    with open(filepath, "r", encoding="utf-8") as f:
                        content = f.read()

                    # Remove trailing whitespace from each line
                    cleaned = re.sub(r"[ \t]+$", "", content, flags=re.MULTILINE)

                    if content != cleaned:
                        with open(filepath, "w", encoding="utf-8") as f:
                            f.write(cleaned)
                        files_cleaned += 1
                        print(f"Cleaned: {filepath}")

                except Exception as e:
                    print(f"Warning: Could not clean {filepath}: {e}")
                    pass

    if files_cleaned > 0:
        print(f"[OK] Cleaned trailing whitespace from {files_cleaned} Python files")
    else:
        print("[OK] No trailing whitespace found in Python files")


if __name__ == "__main__":
    clean_whitespace()
