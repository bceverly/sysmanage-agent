# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""iCloud Photos to local storage (server ROADMAP 24.12, Community).

Runs on the backup target's STORAGE HOST only, never on a backed-up host:

* ``tool`` -- the pinned icloudpd (a checksum-checked release executable on
  Linux x86_64/aarch64, a venv from the checksum-checked wheel elsewhere);
* ``layout`` -- where things go (the cloud root under the storage path, each
  account's own dataset or directory, the private session directories) and
  the checks on what the server sent;
* ``runner`` -- drives one icloudpd run: answers its password and two-factor
  prompts from the server, over HTTPS, at the moment it asks, and reads its
  output into counts;
* ``operations`` -- the command handlers.
"""
