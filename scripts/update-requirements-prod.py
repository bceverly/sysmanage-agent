#!/usr/bin/env python3
"""
Update requirements-prod.txt from requirements.txt

This script extracts production runtime dependencies from requirements.txt
and generates requirements-prod.txt, excluding development/testing dependencies.
"""

import re
from pathlib import Path


def parse_requirements(requirements_file: Path) -> tuple[list[str], list[str]]:
    """
    Parse requirements.txt and separate production from development dependencies.

    Returns:
        tuple: (production_deps, dev_deps)
    """
    production_deps = []
    dev_deps = []
    in_dev_section = False

    with open(requirements_file, "r") as f:
        for line in f:
            line = line.rstrip()

            # Skip empty lines in output collection
            if not line:
                continue

            # Check if we've hit the development dependencies section
            if "Development dependencies" in line or "development" in line.lower():
                in_dev_section = True
                continue

            # Skip comments that aren't section markers
            if line.startswith("#") and not in_dev_section:
                # Keep section comments for production
                production_deps.append(line)
                continue

            # Skip pure comment lines in dev section
            if line.startswith("#") and in_dev_section:
                continue

            # Add dependencies to appropriate list
            if not in_dev_section and not line.startswith("#"):
                production_deps.append(line)
            elif in_dev_section and not line.startswith("#"):
                dev_deps.append(line)

    return production_deps, dev_deps


def generate_requirements_prod(production_deps: list[str], output_file: Path):
    """Generate requirements-prod.txt with production dependencies only."""

    header = [
        "# Production runtime dependencies only",
        "# This file is AUTO-GENERATED from requirements.txt",
        "# DO NOT EDIT MANUALLY - run scripts/update-requirements-prod.py instead",
        "#",
        "# For development dependencies, see requirements.txt",
        "",
    ]

    with open(output_file, "w") as f:
        # Write header
        for line in header:
            f.write(line + "\n")

        # Write production dependencies
        current_section = None
        for line in production_deps:
            # Track sections to add blank lines between them
            if line.startswith("#"):
                if current_section is not None:
                    f.write("\n")
                current_section = line

            f.write(line + "\n")

        # Ensure file ends with newline
        if not production_deps[-1].endswith("\n"):
            f.write("\n")


def main():
    # Get script directory and project root
    script_dir = Path(__file__).parent
    project_root = script_dir.parent

    requirements_file = project_root / "requirements.txt"
    requirements_prod_file = project_root / "requirements-prod.txt"

    # Check if requirements.txt exists
    if not requirements_file.exists():
        print(f"ERROR: {requirements_file} not found!")
        return 1

    print(f"Reading {requirements_file}...")
    production_deps, dev_deps = parse_requirements(requirements_file)

    print(f"Found {len(production_deps)} production dependencies")
    print(f"Found {len(dev_deps)} development dependencies")

    # Show what will be in production
    print("\nProduction dependencies:")
    for dep in production_deps:
        if not dep.startswith("#"):
            print(f"  - {dep}")

    print(f"\nGenerating {requirements_prod_file}...")
    generate_requirements_prod(production_deps, requirements_prod_file)

    print(f"✓ Successfully generated {requirements_prod_file}")
    print("\nDevelopment dependencies excluded:")
    for dep in dev_deps:
        print(f"  - {dep}")

    return 0


if __name__ == "__main__":
    exit(main())
