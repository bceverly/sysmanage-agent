#!/usr/bin/env python3
# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.
"""Regenerate installer/windows/sysmanage-agent.ico from its SVG source.

The .ico is a build input for both the MSI (Add/Remove Programs icon) and the
bundle (installer + ARP icon), so it is committed rather than built on demand --
Windows CI has no SVG rasteriser.  Committing a binary you cannot regenerate is
how assets drift away from the brand they came from, hence this script.

    python3 scripts/build_windows_icon.py [--check]

--check regenerates into a temporary file and compares, so CI can fail if the
.ico and the .svg have parted company.

WHY THIS SOURCE
---------------
sysmanage-agent-icon.svg is the project's SMALL-size mark (a rounded square with
a white server glyph), vendored from sysmanage-docs' favicon.svg.  The other
candidate -- the hub-and-spokes sysmanage-icon.svg -- renders beautifully at
256px and turns into four illegible dots at 16px, because its connector strokes
are 3/120 of the canvas.  An installer icon is seen at 16 and 32 in Explorer and
Add/Remove Programs far more often than it is seen large.

Requires Pillow and ImageMagick (`magick`).
"""

import argparse
import filecmp
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent.parent
SVG = HERE / "installer" / "windows" / "sysmanage-agent-icon.svg"
ICO = HERE / "installer" / "windows" / "sysmanage-agent.ico"

# Windows picks the nearest size and downsamples; supplying the exact sizes it
# asks for avoids it doing that badly.  256 is what modern Explorer wants.
SIZES = [16, 24, 32, 48, 64, 128, 256]


def render(dest: Path) -> None:
    from PIL import Image  # noqa: PLC0415 -- optional dep, only needed here

    if not shutil.which("magick"):
        sys.exit("ERROR: ImageMagick ('magick') is required to rasterise the SVG.")

    with tempfile.TemporaryDirectory() as tmp:
        png = Path(tmp) / "base.png"
        # Rasterise ONCE at high resolution and downsample with Lanczos.  Asking
        # the SVG renderer for 16x16 directly gives visibly worse small sizes.
        subprocess.run(
            [
                "magick",
                "-background",
                "none",
                "-density",
                "2400",
                str(SVG),
                "-resize",
                "1024x1024",
                str(png),
            ],
            check=True,
        )
        base = Image.open(png).convert("RGBA")
        base.resize((256, 256), Image.LANCZOS).save(
            dest, format="ICO", sizes=[(s, s) for s in SIZES]
        )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="verify the committed .ico matches the .svg instead of rewriting it",
    )
    args = parser.parse_args()

    if not SVG.is_file():
        sys.exit(f"ERROR: missing icon source {SVG}")

    if args.check:
        with tempfile.TemporaryDirectory() as tmp:
            candidate = Path(tmp) / "candidate.ico"
            render(candidate)
            if not ICO.is_file():
                sys.exit(f"ERROR: {ICO} does not exist; run without --check.")
            if not filecmp.cmp(candidate, ICO, shallow=False):
                sys.exit(
                    f"ERROR: {ICO.name} is stale relative to {SVG.name}.\n"
                    "       Run: python3 scripts/build_windows_icon.py"
                )
        print(f"[OK] {ICO.name} matches {SVG.name}")
        return 0

    render(ICO)
    print(f"[OK] wrote {ICO} ({ICO.stat().st_size} bytes, sizes {SIZES})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
