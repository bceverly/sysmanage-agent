#!/usr/bin/env python3
# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""Test script for macOS Microsoft Defender detection."""

import sys
import os
import traceback

# Add parent directory to path so we can import from src
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from src.sysmanage_agent.collection.commercial_antivirus_collection import (
    CommercialAntivirusCollector,
)


def main():
    print("Testing macOS Microsoft Defender Detection")
    print("=" * 50)

    try:
        collector = CommercialAntivirusCollector()
        print(f"System detected: {collector.system}")
        print()

        print("Calling collect_commercial_antivirus_status()...")
        result = collector.collect_commercial_antivirus_status()
        print()

        if result:
            print("SUCCESS! Detected commercial antivirus:")
            for key, value in result.items():
                print(f"  {key}: {value}")
        else:
            print("Result is None - no commercial antivirus detected")

    except Exception as e:
        print(f"ERROR: {e}")
        print()
        print("Full traceback:")
        traceback.print_exc()
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
