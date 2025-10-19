"""
Windows Service wrapper for SysManage Agent.
This allows the agent to run as a proper Windows Service in production.

For development, just run main.py directly.
For production, install as a service using this wrapper.
"""

# DEBUG: Log which Python is being used - BEFORE any other imports
import sys
import os

# CRITICAL: Add venv site-packages to sys.path BEFORE importing pywin32 modules
# When pythonservice.exe runs, it doesn't automatically know about the venv's modules
# This must be done before any pywin32 imports or the service will fail to start
SERVICE_DIR = os.path.dirname(os.path.abspath(__file__))
VENV_SITE_PACKAGES = os.path.join(SERVICE_DIR, ".venv", "Lib", "site-packages")
if os.path.exists(VENV_SITE_PACKAGES) and VENV_SITE_PACKAGES not in sys.path:
    sys.path.insert(0, VENV_SITE_PACKAGES)

# Also add the service directory itself
if SERVICE_DIR not in sys.path:
    sys.path.insert(0, SERVICE_DIR)

try:
    debug_log = r"C:\ProgramData\SysManage\logs\service-debug.log"
    os.makedirs(os.path.dirname(debug_log), exist_ok=True)
    with open(debug_log, "a") as f:
        f.write(f"\n{'='*60}\n")
        f.write(
            f"Service starting at: {os.popen('echo %DATE% %TIME%').read().strip()}\n"
        )
        f.write(f"Python executable: {sys.executable}\n")
        f.write(f"Python version: {sys.version}\n")
        f.write(f"Working directory: {os.getcwd()}\n")
        f.write(f"Added to sys.path: {VENV_SITE_PACKAGES}\n")
        f.write(f"sys.path:\n")
        for p in sys.path:
            f.write(f"  {p}\n")
        f.write(f"{'='*60}\n")
except Exception as e:
    pass  # Ignore errors in debug logging

import asyncio
import traceback

try:
    debug_log = r"C:\ProgramData\SysManage\logs\service-debug.log"
    with open(debug_log, "a") as f:
        f.write("\nAttempting to import win32serviceutil...\n")
        import win32serviceutil

        f.write("SUCCESS: win32serviceutil imported\n")

        f.write("Attempting to import win32service...\n")
        import win32service

        f.write("SUCCESS: win32service imported\n")

        f.write("Attempting to import win32event...\n")
        import win32event

        f.write("SUCCESS: win32event imported\n")

        f.write("Attempting to import servicemanager...\n")
        import servicemanager

        f.write("SUCCESS: servicemanager imported\n")
        f.write("\n>>> About to define SysManageAgentService class\n")
except Exception as e:
    try:
        with open(debug_log, "a") as f:
            f.write(f"FAILED to import: {e}\n")
            f.write(f"Traceback:\n{traceback.format_exc()}\n")
    except:
        pass
    raise


class SysManageAgentService(win32serviceutil.ServiceFramework):
    """Windows Service wrapper for SysManage Agent."""

    _svc_name_ = "SysManageAgent"
    _svc_display_name_ = "SysManage Agent"
    _svc_description_ = "System management and monitoring agent for SysManage platform"

    # Use pythonservice.exe but configure it to use the venv Python
    # Don't set _exe_name_ - let pywin32 use pythonservice.exe by default

    def __init__(self, args):
        debug_log = r"C:\ProgramData\SysManage\logs\service-debug.log"
        try:
            with open(debug_log, "a") as f:
                f.write("\n>>> __init__ called with args: {}\n".format(args))
        except:
            pass

        # CRITICAL: Set event loop policy BEFORE parent __init__
        # pythonservice.exe is incompatible with ProactorEventLoop (Python 3.8+ default on Windows)
        # This MUST be set here, not in SvcDoRun, or the service will fail to start
        try:
            with open(debug_log, "a") as f:
                f.write(">>> Setting WindowsSelectorEventLoopPolicy\n")
        except:
            pass

        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

        try:
            with open(debug_log, "a") as f:
                f.write(">>> WindowsSelectorEventLoopPolicy set successfully\n")
        except:
            pass

        win32serviceutil.ServiceFramework.__init__(self, args)

        try:
            with open(debug_log, "a") as f:
                f.write(">>> ServiceFramework.__init__ completed\n")
        except:
            pass

        self.stop_event = win32event.CreateEvent(None, 0, 0, None)
        self.running = True

        try:
            with open(debug_log, "a") as f:
                f.write(">>> __init__ completed successfully\n")
        except:
            pass

    def SvcStop(self):
        """Called when the service is requested to stop."""
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        win32event.SetEvent(self.stop_event)
        self.running = False
        servicemanager.LogMsg(
            servicemanager.EVENTLOG_INFORMATION_TYPE,
            servicemanager.PYS_SERVICE_STOPPED,
            (self._svc_name_, ""),
        )

    def SvcDoRun(self):
        """Called when the service is started."""
        debug_log = r"C:\ProgramData\SysManage\logs\service-debug.log"
        try:
            with open(debug_log, "a") as f:
                f.write("\n>>> SvcDoRun called\n")

            # Set up paths for the service FIRST
            # When running as a service, we need to ensure the correct working directory
            SERVICE_DIR = os.path.dirname(os.path.abspath(__file__))

            with open(debug_log, "a") as f:
                f.write(f">>> SERVICE_DIR: {SERVICE_DIR}\n")

            os.chdir(SERVICE_DIR)

            with open(debug_log, "a") as f:
                f.write(f">>> Changed directory to: {os.getcwd()}\n")

            if SERVICE_DIR not in sys.path:
                sys.path.insert(0, SERVICE_DIR)

            # Add venv site-packages to path so we can import dependencies
            VENV_SITE_PACKAGES = os.path.join(
                SERVICE_DIR, ".venv", "Lib", "site-packages"
            )
            if (
                os.path.exists(VENV_SITE_PACKAGES)
                and VENV_SITE_PACKAGES not in sys.path
            ):
                sys.path.insert(0, VENV_SITE_PACKAGES)

            with open(debug_log, "a") as f:
                f.write(">>> About to report SERVICE_RUNNING\n")

            # Report running status IMMEDIATELY to avoid timeout
            # We'll do the actual initialization after reporting
            self.ReportServiceStatus(win32service.SERVICE_RUNNING)

            with open(debug_log, "a") as f:
                f.write(">>> SERVICE_RUNNING reported successfully\n")

            servicemanager.LogMsg(
                servicemanager.EVENTLOG_INFORMATION_TYPE,
                servicemanager.PYS_SERVICE_STARTED,
                (self._svc_name_, ""),
            )

            # Set environment variable for config location
            config_path = os.getenv("SYSMANAGE_CONFIG")
            if not config_path:
                config_path = r"C:\ProgramData\SysManage\sysmanage-agent.yaml"

            os.environ["SYSMANAGE_CONFIG"] = config_path

            # Import and create the agent
            from main import SysManageAgent

            agent = SysManageAgent(config_path)

            # Run the agent's async main loop
            # Event loop policy was already set in __init__ before parent initialization
            # This ensures pythonservice.exe compatibility with asyncio
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)

            try:
                loop.run_until_complete(agent.run())
            finally:
                loop.close()

        except Exception as e:
            # Log the error to Windows Event Log
            error_msg = (
                f"SysManage Agent service failed: {str(e)}\n{traceback.format_exc()}"
            )
            servicemanager.LogErrorMsg(error_msg)

            # Also log to file for debugging
            try:
                log_file = r"C:\ProgramData\SysManage\logs\service-error.log"
                with open(log_file, "a") as f:
                    from datetime import datetime

                    f.write(f"\n{datetime.now()}: {error_msg}\n")
            except:
                pass

            # Set service to stopped state
            self.SvcStop()


# Log that class definition completed
try:
    debug_log = r"C:\ProgramData\SysManage\logs\service-debug.log"
    with open(debug_log, "a") as f:
        f.write(">>> SysManageAgentService class defined successfully\n")
except:
    pass

if __name__ == "__main__":
    try:
        debug_log = r"C:\ProgramData\SysManage\logs\service-debug.log"
        with open(debug_log, "a") as f:
            f.write(f">>> __main__ block entered, sys.argv = {sys.argv}\n")
    except:
        pass

    if len(sys.argv) == 1:
        # Called without arguments - start the service
        try:
            with open(debug_log, "a") as f:
                f.write(">>> Starting service (no arguments provided)\n")
        except:
            pass

        servicemanager.Initialize()

        try:
            with open(debug_log, "a") as f:
                f.write(">>> servicemanager.Initialize() completed\n")
        except:
            pass

        servicemanager.PrepareToHostSingle(SysManageAgentService)

        try:
            with open(debug_log, "a") as f:
                f.write(">>> PrepareToHostSingle completed\n")
        except:
            pass

        servicemanager.StartServiceCtrlDispatcher()

        try:
            with open(debug_log, "a") as f:
                f.write(">>> StartServiceCtrlDispatcher completed\n")
        except:
            pass
    else:
        # Called with arguments - handle install/remove/start/stop commands
        try:
            with open(debug_log, "a") as f:
                f.write(">>> Handling command line arguments\n")
        except:
            pass

        win32serviceutil.HandleCommandLine(SysManageAgentService)
