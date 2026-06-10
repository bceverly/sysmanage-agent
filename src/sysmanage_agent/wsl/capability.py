"""
WSL capability detection.

Post-cutover home for the WSL-availability + version + blocker logic
that previously lived in
``operations/_virtualization_windows.WindowsVirtualizationMixin``.
The legacy mixin remains in place during the cutover; this module is
the destination so deletion of the legacy file doesn't lose the richer
parsing the engine's ``build_check_virtualization_support_plan``
doesn't replicate.

Public surface:
* :func:`check_wsl_support` — full capability dict suitable for
  ``host.virtualization_capabilities['wsl']``.
* :func:`check_hyperv_support` — Hyper-V availability via PowerShell.
* :func:`detect_wsl_blockers` — identifies BIOS virtualization +
  Virtual Machine Platform feature failure modes from ``wsl --status``
  output.  Used by :func:`check_wsl_support` and the role detector.
* :func:`parse_wsl_version` — WSL 1 vs WSL 2 default-version parsing.

Decoder: WSL output is UTF-16LE on Windows.  We import the canonical
:func:`generic_deployment._decode_command_output` helper rather than
duplicating the heuristic — single source of truth for that quirk.
"""

import logging
import os
import platform
import subprocess  # nosec B404 # required for WSL/PowerShell capability checks
from typing import Any, Dict

from src.sysmanage_agent.operations.generic_deployment import _decode_command_output

_logger = logging.getLogger(__name__)


def _subprocess_creationflags() -> int:
    """Return ``CREATE_NO_WINDOW`` on Windows; 0 elsewhere."""
    return subprocess.CREATE_NO_WINDOW if hasattr(subprocess, "CREATE_NO_WINDOW") else 0


def detect_wsl_blockers(output_lower: str, result: Dict[str, Any]) -> bool:
    """Detect WSL blockers from ``wsl --status`` output (lowercased).

    Updates ``result`` in place with the specific failure mode and
    returns True if a blocker was found.  Recognized blockers:

    * BIOS virtualization disabled — ``"bios"`` and ``"virtualization"``
      both appear in the output.  Sets ``needs_bios_virtualization``.
    * Virtual Machine Platform Windows feature missing —
      ``"virtual machine platform"`` appears.  Sets ``needs_enable``.
    """
    if "bios" in output_lower and "virtualization" in output_lower:
        result["enabled"] = False
        result["needs_enable"] = False
        result["needs_bios_virtualization"] = True
        _logger.warning("WSL requires BIOS virtualization to be enabled")
        return True
    if "virtual machine platform" in output_lower:
        result["enabled"] = False
        result["needs_enable"] = True
        _logger.info("WSL requires Virtual Machine Platform to be enabled")
        return True
    return False


def parse_wsl_version(output: str, result: Dict[str, Any]) -> None:
    """Parse WSL default version (1 vs 2) from ``wsl --status`` output.

    Sets ``result['default_version']`` and ``result['version']``.
    Falls back to 2 when the output doesn't carry an unambiguous marker
    — modern Windows installations default to WSL 2.
    """
    if "Default Version: 2" in output or "Default Version: WSL 2" in output:
        result["default_version"] = 2
        result["version"] = "2"
    elif "Default Version: 1" in output or "Default Version: WSL 1" in output:
        result["default_version"] = 1
        result["version"] = "1"
    elif "WSL 1" in output:
        result["version"] = "1"
        result["default_version"] = 1
    else:
        result["version"] = "2"
        result["default_version"] = 2


def check_wsl_support() -> Dict[str, Any]:
    """Return a capability dict for WSL on this host.

    Keys: ``available`` (wsl.exe present), ``enabled`` (default version
    advertised), ``version``, ``default_version``, ``needs_enable``,
    ``needs_bios_virtualization``.
    """
    result: Dict[str, Any] = {
        "available": False,
        "enabled": False,
        "version": None,
        "needs_enable": False,
        "needs_bios_virtualization": False,
        "default_version": None,
    }
    try:
        if platform.system().lower() != "windows":
            return result
        wsl_path = os.path.join(
            os.environ.get("SystemRoot", "C:\\Windows"), "System32", "wsl.exe"
        )
        if not os.path.exists(wsl_path):
            _logger.debug("WSL executable not found at %s", wsl_path)
            return result
        result["available"] = True
        try:
            status_result = subprocess.run(  # nosec B603 B607
                ["wsl", "--status"],
                capture_output=True,
                timeout=30,
                check=False,
                creationflags=_subprocess_creationflags(),
            )
            output = _decode_command_output(
                status_result.stdout, argv=["wsl", "--status"]
            )
            output += _decode_command_output(
                status_result.stderr, argv=["wsl", "--status"]
            )
            output_lower = output.lower()
            if detect_wsl_blockers(output_lower, result):
                return result
            if status_result.returncode == 0 and "default version:" in output_lower:
                result["enabled"] = True
                parse_wsl_version(output, result)
                _logger.info(
                    "WSL is enabled, default version: %s", result["default_version"]
                )
            else:
                result["enabled"] = False
                result["needs_enable"] = True
                _logger.info("WSL is available but not fully enabled")
        except subprocess.TimeoutExpired:
            _logger.warning("WSL status check timed out")
            result["enabled"] = False
            result["needs_enable"] = True
        except FileNotFoundError:
            result["enabled"] = False
            result["needs_enable"] = True
    except Exception as exc:  # pylint: disable=broad-exception-caught
        _logger.exception("Error checking WSL support: %s", exc)
    return result


def check_hyperv_support() -> Dict[str, Any]:
    """Return a capability dict for Hyper-V on this host.

    Probes via PowerShell ``Get-WindowsOptionalFeature
    -FeatureName Microsoft-Hyper-V-All``.  Returns ``{available, enabled}``.
    """
    result: Dict[str, Any] = {"available": False, "enabled": False}
    try:
        if platform.system().lower() != "windows":
            return result
        ps_command = (
            "Get-WindowsOptionalFeature -FeatureName Microsoft-Hyper-V-All "
            "-Online | Select-Object -ExpandProperty State"
        )
        ps_result = subprocess.run(  # nosec B603 B607
            ["powershell", "-Command", ps_command],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
            creationflags=_subprocess_creationflags(),
        )
        if ps_result.returncode == 0:
            state = ps_result.stdout.strip()
            result["available"] = True
            result["enabled"] = state.lower() == "enabled"
    except Exception as exc:  # pylint: disable=broad-exception-caught
        _logger.debug("Error checking Hyper-V support: %s", exc)
    return result
