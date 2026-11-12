# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""iCloud Live Photos (server ROADMAP 25.8): the still and its video both
downloaded, the video beside the still as ``<name>_HEVC.MOV`` (icloudpd's
``suffix`` policy), both counted, and both counted as present on the next
run.  icloudpd dates the video from the photo's creation date as it does the
still (``download.set_utime``); what the agent owns is the command line and
the counts, so that is what is pinned here."""

# pylint: disable=protected-access

from src.sysmanage_agent.cloud_backup import layout, runner
from tests.test_cloud_backup import _job

STAMP = "2026-11-12 08:00:00"


def _line(level, message):
    return f"{STAMP} {level:<8} {message}"


def _counted(*lines):
    outcome = runner.Outcome()
    for line in lines:
        runner.classify_line(outcome, line, "download", lambda text: text)
    return outcome


def test_live_photo_videos_are_downloaded_beside_the_still(tmp_path):
    line = layout.argv("/usr/bin/icloudpd", _job(tmp_path))
    policy = line.index("--live-photo-mov-filename-policy")
    assert line[policy + 1] == "suffix"  # IMG_0001.HEIC -> IMG_0001_HEVC.MOV
    assert "--skip-live-photos" not in line
    # The video's own size is left at icloudpd's default, the original.
    assert "--live-photo-size" not in line


def test_a_live_photo_counts_its_still_and_its_video():
    first = _counted(
        _line("DEBUG", "Downloading /photos/2026/11/03/IMG_0001.HEIC..."),
        _line("INFO", "Downloaded /photos/2026/11/03/IMG_0001.HEIC"),
        _line("DEBUG", "Downloading /photos/2026/11/03/IMG_0001_HEVC.MOV..."),
        _line("INFO", "Downloaded /photos/2026/11/03/IMG_0001_HEVC.MOV"),
    )
    assert (first.downloaded, first.present, first.failed) == (2, 0, 0)


def test_a_second_run_skips_both():
    again = _counted(
        _line("DEBUG", "/photos/2026/11/03/IMG_0001.HEIC already exists"),
        _line("DEBUG", "/photos/2026/11/03/IMG_0001_HEVC.MOV already exists"),
    )
    assert (again.downloaded, again.present) == (0, 2)
