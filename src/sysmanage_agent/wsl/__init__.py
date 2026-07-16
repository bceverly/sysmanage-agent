# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""
WSL (Windows Subsystem for Linux) support for the sysmanage agent.

Houses the post-cutover home for WSL-related agent functionality that
previously lived in ``operations/_virtualization_windows.py`` and
``operations/child_host_collector.py``:

* ``capability`` — WSL availability/version detection + blocker
  identification (BIOS virt missing, Virtual Machine Platform missing).
* ``keepalive`` — ``~/.wslconfig`` management + per-distro
  ``sleep infinity`` Popen lifecycle that prevents WSL distros from
  auto-shutting-down (workaround for WSL 2.6.x regression).

These modules are independent of the legacy ``child_host_*`` cluster
so the agent can drop the legacy code without losing WSL-specific
parent-host runtime behavior.  Until the legacy is deleted, both the
new modules and the legacy ones coexist; the import switch happens in
``main.py`` / ``data_collector.py`` / ``role_detection.py`` as part of
the cutover.
"""
