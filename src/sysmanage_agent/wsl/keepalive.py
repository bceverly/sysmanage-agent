# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""
WSL keep-alive support for the sysmanage agent (Windows hosts).

Post-cutover home for the WSL keep-alive logic that previously lived
in ``communication/child_host_collector.ChildHostCollector``.  Two
distinct concerns the engine path doesn't replicate:

1. **``~/.wslconfig`` management** — write ``[wsl2] vmIdleTimeout=-1``
   and ``[wsl] autoStop=false`` so the WSL VM doesn't auto-shutdown
   when idle.  Run ``wsl --shutdown`` after editing so the new config
   takes effect on the next boot.

2. **Per-distro ``sleep infinity`` Popen** — workaround for the
   WSL 2.6.x regression (`microsoft/wsl#13416`) where WSL distros
   shut down even with active systemd services.  Maintain a long-lived
   ``wsl -d <distro> -- sleep infinity`` subprocess per distro;
   restart any that exit; clean up when the distro is removed.

Both behaviors are silently no-ops on non-Windows hosts.

Design notes
------------

* The class is intentionally agent-instance-free — no reference to
  ``SysManageAgent`` is required.  This makes it easy to instantiate
  from any subsystem (data collector, role detector, a future
  dedicated WSL service) without circular imports.
* No imports from the legacy ``operations/child_host_*`` cluster.
* :class:`WslKeepalive` mirrors the legacy public surface so call
  sites that switch from ``ChildHostCollector`` to this class only
  change the import.
"""

import configparser
import logging
import os
import platform
import subprocess  # nosec B404 # required for wsl.exe lifecycle
from pathlib import Path
from typing import Dict

from src.i18n import _


def _subprocess_creationflags() -> int:
    """Return ``CREATE_NO_WINDOW`` on Windows; 0 elsewhere."""
    return subprocess.CREATE_NO_WINDOW if hasattr(subprocess, "CREATE_NO_WINDOW") else 0


class WslKeepalive:
    """Keep WSL distros alive on a Windows parent host.

    Public methods used by callers:

    * :meth:`ensure_wslconfig` — idempotent; returns True if the file
      was modified (caller should restart WSL).
    * :meth:`restart_wsl` — runs ``wsl --shutdown``.
    * :meth:`ensure_keepalive_processes` — starts/restarts/cleans up
      the per-distro ``sleep infinity`` Popen handles.
    * :meth:`stop_all_keepalive_processes` — graceful shutdown for the
      whole set (call from agent shutdown hook).
    """

    def __init__(self, logger: logging.Logger = None):
        self.logger = logger or logging.getLogger(__name__)
        # distro_name -> Popen
        self._wsl_keepalive_processes: Dict[str, subprocess.Popen] = {}

    # ------------------------------------------------------------------
    # ~/.wslconfig management
    # ------------------------------------------------------------------

    def ensure_wslconfig(self) -> bool:
        """Write/repair ``~/.wslconfig``; return True if a write happened.

        Sets:
        * ``[wsl2] vmIdleTimeout=-1`` — prevents WSL VM from shutting
          down when idle.
        * ``[wsl] autoStop=false`` — workaround for the WSL 2.6.x
          regression (https://github.com/microsoft/wsl/issues/13416).

        Uses ``configparser.RawConfigParser`` with ``optionxform = str``
        so the (case-sensitive) WSL setting names round-trip cleanly.
        """
        user_home = Path(os.path.expanduser("~"))
        wslconfig_path = user_home / ".wslconfig"
        config = configparser.RawConfigParser()
        config.optionxform = str  # preserve key case
        creating_new_file = not wslconfig_path.exists()
        if wslconfig_path.exists():
            try:
                config.read(str(wslconfig_path))
            except configparser.Error as exc:
                self.logger.warning(_("Could not parse existing .wslconfig: %s"), exc)
        needs_update = self._configure_wsl2_idle_timeout(config)
        needs_update = self._configure_wsl_autostop(config) or needs_update
        if not needs_update:
            self.logger.debug(".wslconfig already configured correctly")
            return False
        return self._write_wslconfig(config, wslconfig_path, creating_new_file)

    def _configure_wsl2_idle_timeout(
        self, config: configparser.RawConfigParser
    ) -> bool:
        needs_update = False
        if not config.has_section("wsl2"):
            config.add_section("wsl2")
            needs_update = True
        has_correct = config.has_option("wsl2", "vmIdleTimeout")
        has_lowercase = config.has_option("wsl2", "vmidletimeout")
        current = config.get("wsl2", "vmIdleTimeout", fallback=None)
        if has_lowercase and not has_correct:
            config.remove_option("wsl2", "vmidletimeout")
            self.logger.info(
                _("Removing lowercase vmidletimeout, will add vmIdleTimeout")
            )
            needs_update = True
        if current != "-1":
            config.set("wsl2", "vmIdleTimeout", "-1")
            needs_update = True
        return needs_update

    def _configure_wsl_autostop(self, config: configparser.RawConfigParser) -> bool:
        needs_update = False
        if not config.has_section("wsl"):
            config.add_section("wsl")
            needs_update = True
        has_correct = config.has_option("wsl", "autoStop")
        has_lowercase = config.has_option("wsl", "autostop")
        current = config.get("wsl", "autoStop", fallback=None)
        if has_lowercase and not has_correct:
            config.remove_option("wsl", "autostop")
            self.logger.info(_("Removing lowercase autostop, will add autoStop"))
            needs_update = True
        if current != "false":
            config.set("wsl", "autoStop", "false")
            needs_update = True
        return needs_update

    def _write_wslconfig(
        self,
        config: configparser.RawConfigParser,
        wslconfig_path: Path,
        creating_new_file: bool,
    ) -> bool:
        try:
            if creating_new_file:
                self.logger.info(
                    _(
                        ".wslconfig not found, creating to prevent WSL auto-shutdown at %s"
                    ),
                    wslconfig_path,
                )
            else:
                self.logger.info(
                    _("Updating .wslconfig to prevent WSL auto-shutdown at %s"),
                    wslconfig_path,
                )
            with open(wslconfig_path, "w", encoding="utf-8") as cfg:
                config.write(cfg)
            self.logger.info(_(".wslconfig saved successfully"))
            return True
        except PermissionError:
            self.logger.error(_("Permission denied writing to %s"), wslconfig_path)
        except Exception as exc:  # pylint: disable=broad-exception-caught
            self.logger.error(_("Failed to write .wslconfig: %s"), exc)
        return False

    def restart_wsl(self) -> None:
        """Run ``wsl --shutdown`` so a freshly-edited ``~/.wslconfig`` takes effect."""
        try:
            self.logger.info(_("Shutting down WSL to apply .wslconfig changes..."))
            result = subprocess.run(  # nosec B603 B607
                ["wsl", "--shutdown"],
                capture_output=True,
                timeout=30,
                check=False,
                creationflags=_subprocess_creationflags(),
            )
            if result.returncode == 0:
                self.logger.info(
                    _("WSL shutdown complete, new settings will apply on next start")
                )
            else:
                stderr = result.stderr.decode("utf-8", errors="ignore")
                self.logger.warning(_("WSL shutdown returned non-zero: %s"), stderr)
        except subprocess.TimeoutExpired:
            self.logger.warning(_("WSL shutdown timed out"))
        except Exception as exc:  # pylint: disable=broad-exception-caught
            self.logger.error(_("Failed to shutdown WSL: %s"), exc)

    # ------------------------------------------------------------------
    # Per-distro sleep-infinity Popen lifecycle
    # ------------------------------------------------------------------

    def get_wsl_distros(self) -> list:
        """Return a list of WSL distribution names known to ``wsl --list --quiet``.

        ``wsl.exe`` outputs UTF-16LE; we decode that explicitly here.  We
        skip lines starting with ``"Windows"`` because some Windows
        builds prepend a banner.
        """
        try:
            result = subprocess.run(  # nosec B603 B607
                ["wsl", "--list", "--quiet"],
                capture_output=True,
                timeout=10,
                check=False,
                creationflags=_subprocess_creationflags(),
            )
            if result.returncode != 0:
                return []
            try:
                output = result.stdout.decode("utf-16-le").strip()
            except UnicodeDecodeError:
                output = result.stdout.decode("utf-8", errors="ignore").strip()
            return [
                line.strip()
                for line in output.splitlines()
                if line.strip() and not line.strip().startswith("Windows")
            ]
        except Exception as exc:  # pylint: disable=broad-exception-caught
            self.logger.debug("Failed to get WSL distros: %s", exc)
            return []

    def _start_keepalive_process(self, distro: str) -> bool:
        """Spawn ``wsl -d <distro> -- sleep infinity`` and remember the Popen."""
        try:
            # pylint: disable-next=consider-using-with
            process = subprocess.Popen(  # nosec B603 B607
                ["wsl", "-d", distro, "--", "sleep", "infinity"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                creationflags=_subprocess_creationflags(),
            )
            self._wsl_keepalive_processes[distro] = process
            self.logger.info(
                _("Started keep-alive process for WSL instance: %s"), distro
            )
            return True
        except Exception as exc:  # pylint: disable=broad-exception-caught
            self.logger.error(
                _("Failed to start keep-alive for WSL instance %s: %s"), distro, exc
            )
            return False

    def _stop_keepalive_process(self, distro: str) -> None:
        process = self._wsl_keepalive_processes.pop(distro, None)
        if not process:
            return
        try:
            process.terminate()
            process.wait(timeout=5)
            self.logger.debug("Stopped keep-alive process for WSL instance: %s", distro)
        except subprocess.TimeoutExpired:
            process.kill()
            self.logger.warning(
                _("Had to kill keep-alive process for WSL instance: %s"), distro
            )
        except Exception as exc:  # pylint: disable=broad-exception-caught
            self.logger.debug("Error stopping keep-alive for %s: %s", distro, exc)

    def stop_all_keepalive_processes(self) -> None:
        """Graceful shutdown for the whole keep-alive set."""
        # Snapshot keys via tuple() so we can mutate the dict while iterating.
        for distro in tuple(self._wsl_keepalive_processes.keys()):
            self._stop_keepalive_process(distro)

    def ensure_keepalive_processes(self) -> None:
        """Start/restart/cleanup per-distro keep-alives so each current distro has one running."""
        current = set(self.get_wsl_distros())
        # Drop processes whose distro no longer exists.  Snapshot keys so we
        # can mutate the dict (via _stop_keepalive_process) while iterating.
        for distro in tuple(self._wsl_keepalive_processes.keys()):
            if distro not in current:
                self.logger.info(
                    _("WSL distribution %s no longer exists, stopping keep-alive"),
                    distro,
                )
                self._stop_keepalive_process(distro)
        # Start/restart for each current distro.
        for distro in current:
            if not distro:
                continue
            process = self._wsl_keepalive_processes.get(distro)
            if process is not None:
                poll_result = process.poll()
                if poll_result is not None:
                    self.logger.debug(
                        "Keep-alive process for %s exited (code %s), restarting",
                        distro,
                        poll_result,
                    )
                    del self._wsl_keepalive_processes[distro]
                    process = None
            if process is None:
                self._start_keepalive_process(distro)


def is_windows() -> bool:
    """True iff this host is Windows.  Used by callers to gate keep-alive."""
    return platform.system().lower() == "windows"
