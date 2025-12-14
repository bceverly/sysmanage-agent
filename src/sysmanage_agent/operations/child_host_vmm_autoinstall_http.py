"""
HTTP server for serving OpenBSD autoinstall files.

This module handles starting and managing the HTTP server used for
serving install.conf and related files during autoinstall.
"""

import http.server
import os
import socketserver
import threading
from typing import Any, Dict, Optional

from src.i18n import _

# Default autoinstall HTTP server settings
AUTOINSTALL_DIR = "/var/vmm/autoinstall"
AUTOINSTALL_PORT = 80  # OpenBSD autoinstall looks for HTTP on port 80
AUTOINSTALL_BIND = "100.64.0.1"  # vmd local network address (matches pf.conf vm_net)


class AutoinstallHttpHandler(http.server.SimpleHTTPRequestHandler):
    """HTTP handler for serving autoinstall files."""

    def __init__(self, *args, directory=None, logger=None, **kwargs):
        self.logger = logger
        super().__init__(*args, directory=directory, **kwargs)

    def log_message(self, format, *args):  # pylint: disable=redefined-builtin
        """Log HTTP requests."""
        if self.logger:
            self.logger.debug("Autoinstall HTTP: %s", format % args)

    def do_GET(self):
        """Handle GET requests."""
        if self.logger:
            self.logger.info(
                _("Autoinstall HTTP request: %s from %s"),
                self.path,
                self.client_address[0],
            )
        super().do_GET()


class AutoinstallHttpServer:
    """Manages the autoinstall HTTP server lifecycle."""

    def __init__(self, logger):
        """
        Initialize HTTP server manager.

        Args:
            logger: Logger instance
        """
        self.logger = logger
        self._http_server = None
        self._http_thread = None

    def start(
        self, bind_address: Optional[str] = None, port: Optional[int] = None
    ) -> Dict[str, Any]:
        """
        Start HTTP server to serve autoinstall files.

        Args:
            bind_address: Address to bind to (default: 100.64.0.1)
            port: Port to listen on (default: 80)

        Returns:
            Dict with success status
        """
        if self._http_server is not None:
            return {
                "success": True,
                "message": _("HTTP server already running"),
            }

        bind_addr = bind_address or AUTOINSTALL_BIND
        listen_port = port or AUTOINSTALL_PORT

        try:
            # Ensure autoinstall directory exists
            if not os.path.exists(AUTOINSTALL_DIR):
                os.makedirs(AUTOINSTALL_DIR, mode=0o755)

            # Create handler with directory
            def handler(*args, **kwargs):
                return AutoinstallHttpHandler(
                    *args,
                    directory=AUTOINSTALL_DIR,
                    logger=self.logger,
                    **kwargs,
                )

            # Allow address reuse
            socketserver.TCPServer.allow_reuse_address = True

            self._http_server = socketserver.TCPServer(
                (bind_addr, listen_port), handler
            )

            # Start in background thread
            self._http_thread = threading.Thread(
                target=self._http_server.serve_forever,
                daemon=True,
            )
            self._http_thread.start()

            self.logger.info(
                _("Started autoinstall HTTP server on %s:%d"), bind_addr, listen_port
            )

            return {
                "success": True,
                "address": bind_addr,
                "port": listen_port,
            }

        except OSError as error:
            if error.errno == 98:  # Address already in use
                # Another process might be serving on this address
                # That's OK, autoinstall should still work
                self.logger.warning(
                    _("HTTP port %d already in use, autoinstall may still work"),
                    listen_port,
                )
                return {
                    "success": True,
                    "warning": _("Port already in use"),
                }

            self.logger.error(_("Failed to start HTTP server: %s"), error)
            return {
                "success": False,
                "error": str(error),
            }
        except Exception as error:
            self.logger.error(_("Failed to start HTTP server: %s"), error)
            return {
                "success": False,
                "error": str(error),
            }

    def stop(self) -> Dict[str, Any]:
        """
        Stop the autoinstall HTTP server.

        Returns:
            Dict with success status
        """
        if self._http_server is None:
            return {
                "success": True,
                "message": _("HTTP server not running"),
            }

        try:
            self._http_server.shutdown()
            self._http_server = None
            self._http_thread = None

            self.logger.info(_("Stopped autoinstall HTTP server"))

            return {"success": True}

        except Exception as error:
            self.logger.error(_("Failed to stop HTTP server: %s"), error)
            return {
                "success": False,
                "error": str(error),
            }

    @property
    def is_running(self) -> bool:
        """Check if HTTP server is running."""
        return self._http_server is not None


def write_install_conf(
    vm_name: str,
    content: str,
    logger,
) -> Dict[str, Any]:
    """
    Write install.conf file for a VM.

    Creates the file at /var/vmm/autoinstall/install.conf

    Args:
        vm_name: Name of the VM (used for logging)
        content: install.conf content to write
        logger: Logger instance

    Returns:
        Dict with success status and file path
    """
    try:
        # Ensure autoinstall directory exists
        if not os.path.exists(AUTOINSTALL_DIR):
            os.makedirs(AUTOINSTALL_DIR, mode=0o755)
            logger.info(_("Created autoinstall directory: %s"), AUTOINSTALL_DIR)

        # Write to file
        # OpenBSD autoinstall looks for install.conf in web root
        conf_path = os.path.join(AUTOINSTALL_DIR, "install.conf")

        with open(conf_path, "w", encoding="utf-8") as conf_file:
            conf_file.write(content)

        os.chmod(conf_path, 0o644)

        logger.info(_("Generated install.conf for VM %s at %s"), vm_name, conf_path)

        return {
            "success": True,
            "conf_path": conf_path,
        }

    except Exception as error:
        logger.error(_("Failed to write install.conf: %s"), error)
        return {
            "success": False,
            "error": str(error),
        }
