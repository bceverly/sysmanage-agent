#!/bin/sh
# SysManage Agent Privileged Runner
# Cross-platform script for macOS (zsh), Ubuntu (bash), and OpenBSD (ksh)
#
# This script runs the SysManage Agent with elevated privileges needed for
# package management operations (updates, installations, etc.)

set -e

# Get the directory where this script is located
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# Change to the project root directory (parent of scripts directory)
AGENT_DIR="$(dirname "$SCRIPT_DIR")"
cd "$AGENT_DIR"

# Platform detection
detect_platform() {
    if [ "$(uname)" = "Darwin" ]; then
        echo "macos"
    elif [ "$(uname)" = "OpenBSD" ]; then
        echo "openbsd"
    elif [ "$(uname)" = "FreeBSD" ]; then
        echo "freebsd"
    elif [ "$(uname)" = "NetBSD" ]; then
        echo "netbsd"
    elif [ "$(uname)" = "Linux" ]; then
        echo "linux"
    else
        echo "unknown"
    fi
}

# Check if virtual environment exists
check_venv() {
    if [ ! -d ".venv" ]; then
        echo "❌ Virtual environment not found at: $AGENT_DIR/.venv"
        echo "📋 Please run setup first:"
        echo "   python3 -m venv .venv"
        echo "   .venv/bin/pip install -r requirements.txt"
        exit 1
    fi
    
    if [ ! -f ".venv/bin/python" ]; then
        echo "❌ Python executable not found in virtual environment"
        exit 1
    fi
}

# Check sudo access
check_sudo() {
    platform="$1"
    
    case "$platform" in
        "macos")
            if ! sudo -n true 2>/dev/null; then
                echo "🔐 This script requires administrator privileges for package management."
                echo "📝 You may be prompted for your password."
            fi
            ;;
        "linux")
            if ! sudo -n true 2>/dev/null; then
                echo "🔐 This script requires sudo privileges for package management."
                echo "📝 You may be prompted for your password."
            fi
            ;;
        "openbsd"|"netbsd"|"freebsd")
            if ! doas true 2>/dev/null && ! sudo -n true 2>/dev/null; then
                echo "🔐 This script requires elevated privileges (doas or sudo) for package management."
                echo "📝 You may be prompted for your password."
            fi
            ;;
    esac
}

# Get the appropriate privilege escalation command
get_priv_cmd() {
    platform="$1"
    
    case "$platform" in
        "openbsd"|"netbsd"|"freebsd")
            # BSD systems prefer doas, fallback to sudo
            if command -v doas >/dev/null 2>&1; then
                echo "doas"
            elif command -v sudo >/dev/null 2>&1; then
                echo "sudo -E"
            else
                echo "❌ Neither doas nor sudo found. Please install one of them."
                exit 1
            fi
            ;;
        *)
            # macOS and Linux use sudo
            if command -v sudo >/dev/null 2>&1; then
                echo "sudo -E"
            else
                echo "❌ sudo not found. Please install sudo."
                exit 1
            fi
            ;;
    esac
}

# Function to check for running agent processes
check_existing_processes() {
    found_processes=false

    # More specific pattern to avoid matching other Python processes
    # Look for processes that contain both "python" and the specific path to this agent
    agent_dir_pattern="sysmanage-agent"
    main_py_pattern="main.py"

    # Check for agent processes by pattern (cross-platform approach)
    agent_pids=""
    if command -v pgrep >/dev/null 2>&1; then
        # Use pgrep - more reliable for finding main.py processes
        agent_pids=$(pgrep -f "main.py" 2>/dev/null | grep -v $$) # Exclude this script's PID
    else
        # Fallback: use ps and grep, look for .venv pattern (NetBSD truncation issue)
        agent_pids=$(ps aux 2>/dev/null | grep "\.venv.*python" | grep -v grep | grep -v $$ | awk '{print $2}')
    fi

    if [ -n "$agent_pids" ]; then
        echo "⚠️  Found existing agent processes:"
        echo "$agent_pids" | while read pid; do
            if [ -n "$pid" ]; then
                cmd=$(ps -p "$pid" -o command= 2>/dev/null | cut -c1-80)
                if [ -z "$cmd" ]; then
                    # Fallback for systems where ps -p doesn't work the same way
                    cmd=$(ps aux 2>/dev/null | awk -v p="$pid" '$2==p {for(i=11;i<=NF;i++) printf "%s ", $i; print ""}' | cut -c1-80)
                fi
                echo "   PID $pid: $cmd"
            fi
        done
        found_processes=true
    fi

    # Check PID file
    if [ -f "logs/agent.pid" ]; then
        pid_file_pid=$(cat logs/agent.pid 2>/dev/null)
        if [ -n "$pid_file_pid" ] && kill -0 "$pid_file_pid" 2>/dev/null; then
            echo "⚠️  Found agent process from PID file (PID: $pid_file_pid)"
            found_processes=true
        fi
    fi

    if [ "$found_processes" = true ]; then
        echo "Attempting to stop existing processes..."
        return 0  # Found processes
    else
        echo "No existing SysManage Agent processes found"
        return 1  # No processes found
    fi
}

# Function to get configuration value from config file with priority
get_config_value() {
    key=$1
    config_file=""
    
    # Use same priority as ConfigManager: /etc/sysmanage-agent.yaml then ./sysmanage-agent.yaml
    if [ -f "/etc/sysmanage-agent.yaml" ]; then
        config_file="/etc/sysmanage-agent.yaml"
    elif [ -f "./sysmanage-agent.yaml" ]; then
        config_file="./sysmanage-agent.yaml"
    else
        return 1
    fi
    
    "$AGENT_DIR/.venv/bin/python" -c "
import yaml
import sys
try:
    with open('$config_file', 'r') as f:
        config = yaml.safe_load(f)
    keys = '$key'.split('.')
    value = config
    for k in keys:
        value = value[k]
    print(value)
except:
    sys.exit(1)
" 2>/dev/null
}

# Check if script is being run with elevated privileges
check_not_root() {
    # Check if running as root (UID 0)
    if [ "$(id -u)" -eq 0 ]; then
        echo "❌ ERROR: This script should NOT be run with elevated privileges!"
        echo ""
        echo "🚫 Do not run this script with:"
        echo "   - sudo ./run-privileged.sh"
        echo "   - doas ./run-privileged.sh"
        echo "   - As root user"
        echo ""
        echo "✅ Instead, run it as your regular user:"
        echo "   ./run-privileged.sh"
        echo ""
        echo "The script will handle privilege escalation internally and"
        echo "prompt you for your password when needed."
        echo ""
        exit 1
    fi
    
    # Check if SUDO_USER environment variable is set (indicates running under sudo)
    if [ -n "$SUDO_USER" ]; then
        echo "❌ ERROR: This script should NOT be run with sudo!"
        echo ""
        echo "🚫 You ran: sudo ./run-privileged.sh"
        echo "✅ Instead run: ./run-privileged.sh"
        echo ""
        echo "The script will handle privilege escalation internally and"
        echo "prompt you for your password when needed."
        echo ""
        exit 1
    fi
    
    # Check if running under doas (check for DOAS_USER on OpenBSD)
    if [ -n "$DOAS_USER" ]; then
        echo "❌ ERROR: This script should NOT be run with doas!"
        echo ""
        echo "🚫 You ran: doas ./run-privileged.sh"
        echo "✅ Instead run: ./run-privileged.sh"
        echo ""
        echo "The script will handle privilege escalation internally and"
        echo "prompt you for your password when needed."
        echo ""
        exit 1
    fi
}

# Main execution
main() {
    platform=""
    priv_cmd=""
    venv_path=""
    python_path=""
    current_path=""
    
    # Check that we're not running with elevated privileges
    check_not_root
    
    platform=$(detect_platform)
    
    echo "🚀 SysManage Agent Privileged Runner"
    echo "🖥️  Platform: $platform ($(uname))"
    echo "📁 Working directory: $AGENT_DIR"
    
    # Create logs directory if it doesn't exist with proper permissions
    if [ ! -d logs ]; then
        mkdir -p logs
        chmod 755 logs
    elif [ ! -w logs ]; then
        # If logs exists but isn't writable, we have a problem
        echo "⚠️  ERROR: logs directory exists but is not writable!"
        echo "   Owner: $(ls -ld logs | awk '{print $3}')"
        echo "   Permissions: $(ls -ld logs | awk '{print $1}')"
        echo ""
        echo "   To fix, run:"
        echo "     rm -rf logs"
        echo "     mkdir logs"
        echo ""
        exit 1
    fi
    
    # Stop any existing agent
    if check_existing_processes; then
        echo "Attempting to stop existing processes using regular stop script..."
        sh ./scripts/stop.sh
        sleep 2

        # Verify they were stopped
        if check_existing_processes >/dev/null 2>&1; then
            echo "⚠️  Regular stop script failed. Trying to kill processes as regular user first..."

            # First, try to kill processes as regular user (silently)
            # Get process PIDs that match our pattern (using same logic as check_existing_processes)
            agent_dir_pattern="sysmanage-agent"
            main_py_pattern="main.py"
            agent_pids=""
            if command -v pgrep >/dev/null 2>&1; then
                agent_pids=$(pgrep -f "main.py" 2>/dev/null | grep -v $$)
            else
                agent_pids=$(ps aux 2>/dev/null | grep "\.venv.*python" | grep -v grep | grep -v $$ | awk '{print $2}')
            fi

            regular_user_success=false
            if [ -n "$agent_pids" ]; then
                echo "Found agent processes owned by current user, attempting to kill them..."
                for pid in $agent_pids; do
                    # Try to kill as regular user (silently)
                    if kill "$pid" 2>/dev/null; then
                        echo "  ✅ Stopped PID $pid as regular user"
                        regular_user_success=true
                    else
                        # If regular kill fails, try SIGKILL as regular user
                        if kill -9 "$pid" 2>/dev/null; then
                            echo "  ✅ Force killed PID $pid as regular user"
                            regular_user_success=true
                        fi
                    fi
                done

                # Give processes time to exit
                sleep 2
            fi

            # Check if regular user killing worked
            if check_existing_processes >/dev/null 2>&1; then
                echo "⚠️  Regular user kill failed. Trying with elevated privileges..."

                # Try to stop with elevated privileges
                priv_cmd_temp=$(get_priv_cmd "$platform")

                # Re-check for remaining processes that might be owned by root or other users
                agent_pids=""
                if command -v pgrep >/dev/null 2>&1; then
                    agent_pids=$(pgrep -f "main.py" 2>/dev/null | grep -v $$)
                else
                    agent_pids=$(ps aux 2>/dev/null | grep "\.venv.*python" | grep -v grep | grep -v $$ | awk '{print $2}')
                fi

                if [ -n "$agent_pids" ]; then
                echo "Found agent processes: $agent_pids"
                echo "Attempting to stop them with $priv_cmd_temp..."

                for pid in $agent_pids; do
                    echo "  Stopping PID $pid..."
                    if [ "$priv_cmd_temp" = "doas" ]; then
                        if doas kill "$pid" 2>/dev/null; then
                            echo "    ✅ Stopped PID $pid with doas"
                        else
                            echo "    ⚠️  Failed to stop PID $pid with doas, trying SIGKILL..."
                            doas kill -9 "$pid" 2>/dev/null && echo "    ✅ Force killed PID $pid"
                        fi
                    else
                        if $priv_cmd_temp kill "$pid" 2>/dev/null; then
                            echo "    ✅ Stopped PID $pid with sudo"
                        else
                            echo "    ⚠️  Failed to stop PID $pid with sudo, trying SIGKILL..."
                            $priv_cmd_temp kill -9 "$pid" 2>/dev/null && echo "    ✅ Force killed PID $pid"
                        fi
                    fi
                done

                sleep 3

                # Final check
                if check_existing_processes >/dev/null 2>&1; then
                    echo "❌ ERROR: Still failed to stop existing agent processes."
                    echo ""
                    echo "This often happens when switching between user mode (make start) and"
                    echo "privileged mode (make start-privileged). The existing processes may be"
                    echo "running in a different session or as a different user."
                    echo ""
                    echo "Options to resolve this:"
                    echo "1. Manually check for agent processes:"
                    echo "   ps -ef | grep 'python.*main.py'"
                    echo ""
                    echo "2. Try killing specific PIDs with elevated privileges:"
                    if [ "$priv_cmd_temp" = "doas" ]; then
                        echo "   doas kill <PID>"
                        echo "   doas kill -9 <PID>  # for stubborn processes"
                        echo ""
                        echo "   To kill all sysmanage-agent processes safely:"
                        echo "   doas pkill -f 'sysmanage-agent.*main.py'"
                    else
                        echo "   sudo kill <PID>"
                        echo "   sudo kill -9 <PID>  # for stubborn processes"
                        echo ""
                        echo "   To kill all sysmanage-agent processes safely:"
                        echo "   sudo pkill -f 'sysmanage-agent.*main.py'"
                    fi
                    echo ""
                    echo "3. If processes are stuck/orphaned, reboot the system"
                    echo ""
                    echo "4. To force start anyway (not recommended), run:"
                    echo "   FORCE=1 make start-privileged"

                    # Check for FORCE environment variable
                    if [ "$FORCE" = "1" ]; then
                        echo ""
                        echo "⚠️  FORCE mode enabled - starting anyway despite existing processes"
                        echo "   This may result in multiple agents running simultaneously!"
                    else
                        exit 1
                    fi
                else
                    echo "✅ Successfully stopped existing processes with elevated privileges"
                fi
            else
                echo "⚠️  No agent processes found in second check - they may have stopped"
            fi
            else
                echo "✅ Successfully stopped existing processes as regular user"
            fi
        else
            echo "✅ Successfully stopped existing processes"
        fi
    fi
    
    check_venv
    check_sudo "$platform"
    
    priv_cmd=$(get_priv_cmd "$platform")
    venv_path="$AGENT_DIR/.venv/bin"
    python_path="$AGENT_DIR/.venv/bin/python"
    
    # Preserve current PATH and add venv binaries
    current_path="$venv_path:$PATH"
    
    # Get system information for startup message
    HOSTNAME=$($python_path -c "import socket; print(socket.getfqdn())" 2>/dev/null || echo "unknown")
    PLATFORM=$($python_path -c "import platform; print(platform.system())" 2>/dev/null || echo "unknown")
    
    # Determine which config file to use and get server configuration
    CONFIG_FILE=""
    if [ -f "/etc/sysmanage-agent.yaml" ]; then
        CONFIG_FILE="/etc/sysmanage-agent.yaml"
    elif [ -f "./sysmanage-agent.yaml" ]; then
        CONFIG_FILE="./sysmanage-agent.yaml"
    fi

    if [ -n "$CONFIG_FILE" ]; then
        echo "Using configuration file: $CONFIG_FILE"
        SERVER_HOST=$(get_config_value "server.hostname")
        if [ $? -ne 0 ] || [ -z "$SERVER_HOST" ]; then
            SERVER_HOST="unknown"
        fi
        
        SERVER_PORT=$(get_config_value "server.port")
        if [ $? -ne 0 ] || [ -z "$SERVER_PORT" ]; then
            SERVER_PORT="unknown"
        fi
        
        USE_HTTPS_BOOL=$(get_config_value "server.use_https")
        if [ $? -ne 0 ] || [ -z "$USE_HTTPS_BOOL" ]; then
            USE_HTTPS="unknown"
        elif [ "$USE_HTTPS_BOOL" = "True" ] || [ "$USE_HTTPS_BOOL" = "true" ]; then
            USE_HTTPS="https"
        else
            USE_HTTPS="http"
        fi
    else
        echo "⚠️  WARNING: Configuration file not found! Expected /etc/sysmanage-agent.yaml or ./sysmanage-agent.yaml"
        SERVER_HOST="unknown"
        SERVER_PORT="unknown"
        USE_HTTPS="unknown"
    fi
    
    echo "🐍 Python: $python_path"
    echo "🔧 Privilege escalation: $priv_cmd"
    echo ""
    echo "Agent Details:"
    echo "  🖥️  Hostname: $HOSTNAME"
    echo "  🔧 Platform: $PLATFORM"
    echo "  📁 Directory: $AGENT_DIR"
    echo "  🌐 Server: $USE_HTTPS://$SERVER_HOST:$SERVER_PORT"
    echo ""
    echo "🔐 Starting SysManage Agent with elevated privileges..."
    echo "    This requires administrative access for package management operations."
    echo "    You will be prompted for your password if needed."
    echo ""
    
    # Start the agent in background (Python logging handles file output)
    case "$priv_cmd" in
        "doas")
            # OpenBSD doas - use exec to replace shell and daemonize properly
            echo "🔑 Requesting elevated privileges with doas..."
            # Create a wrapper script that doas will execute
            cat > /tmp/sysmanage_agent_$$.sh << EOF
#!/bin/sh
# Change to agent directory
cd "$AGENT_DIR"

# Start the agent (Python logging writes to logs/agent.log)
env PATH="$current_path" PYTHONPATH="$AGENT_DIR" "$python_path" main.py "$@" &
echo \$! > "$AGENT_DIR/logs/agent.pid"
EOF
            chmod +x /tmp/sysmanage_agent_$$.sh

            # Run the wrapper script with doas (will prompt for password in foreground)
            $priv_cmd /tmp/sysmanage_agent_$$.sh
            DOAS_RESULT=$?

            # Clean up
            rm -f /tmp/sysmanage_agent_$$.sh

            # Check if doas succeeded
            if [ $DOAS_RESULT -ne 0 ]; then
                echo "❌ ERROR: doas command failed with exit code $DOAS_RESULT"
                exit 1
            fi

            # Wait a moment for the PID file to be written
            sleep 1

            # Get the PID
            if [ -f logs/agent.pid ]; then
                AGENT_PID=$(cat logs/agent.pid)
            else
                # Try to find the process directly
                AGENT_PID=$(ps aux | grep "[p]ython.*main.py" | awk '{print $2}' | head -1)
                if [ -n "$AGENT_PID" ]; then
                    echo $AGENT_PID > logs/agent.pid
                else
                    AGENT_PID=""
                fi
            fi
            ;;
        *)
            # sudo with -E flag preserves environment
            echo "🔑 Requesting elevated privileges with sudo..."
            # First, validate sudo access interactively (this will prompt for password if needed)
            if ! $priv_cmd true; then
                echo "❌ ERROR: Failed to obtain sudo privileges"
                exit 1
            fi

            # Now run the agent in background (Python logging writes to logs/agent.log)
            # Use PYTHONDONTWRITEBYTECODE=1 to prevent .pyc caching issues
            $priv_cmd PATH="$current_path" PYTHONPATH="$AGENT_DIR" PYTHONDONTWRITEBYTECODE=1 "$python_path" -B main.py "$@" &
            AGENT_PID=$!
            ;;
    esac
    
    # Save PID (only for non-doas cases, doas handles it internally)
    if [ "$priv_cmd" != "doas" ] && [ -n "$AGENT_PID" ]; then
        echo $AGENT_PID > logs/agent.pid
    fi
    
    # Give it a moment to start
    sleep 3
    
    # Check if the process is still running
    # First check if AGENT_PID is set
    if [ -z "$AGENT_PID" ]; then
        echo "⚠️  WARNING: Could not get agent process ID from PID file"
        # Try to find the process anyway
        AGENT_PID=$(ps aux | grep "[p]ython.*main.py" | awk '{print $2}' | head -1)
        if [ -z "$AGENT_PID" ]; then
            echo "❌ ERROR: Failed to get agent process ID"
            echo ""
            echo "Check the log file for details:"
            echo "  tail logs/agent.log"
            echo ""
            rm -f logs/agent.pid
            exit 1
        fi
    fi
    
    # Check if the process is still running
    # Note: On OpenBSD with doas, we might not have permission to signal the root-owned process
    # So we check if the process exists in the process list instead
    if ps -p "$AGENT_PID" >/dev/null 2>&1 || ps aux | grep -q "^root.*$AGENT_PID"; then
        echo ""
        echo "✅ SysManage Agent is successfully running with elevated privileges!"
        echo ""
        echo "Agent Information:"
        echo "  🆔 Process ID: $AGENT_PID"
        echo "  🖥️  Hostname: $HOSTNAME" 
        echo "  🔗 Server: $USE_HTTPS://$SERVER_HOST:$SERVER_PORT"
        echo "  🔐 Running with: $priv_cmd"
        echo ""
        echo "Logs:"
        echo "  📄 Agent Log: tail -f logs/agent.log"
        echo ""
        echo "To stop the agent: make stop"
        echo ""
    else
        echo ""
        echo "❌ ERROR: SysManage Agent failed to start!"
        echo ""
        echo "Check the log file for details:"
        echo "  tail logs/agent.log"
        echo ""
        # Clean up PID file
        rm -f logs/agent.pid
        exit 1
    fi
}

# Help function
show_help() {
    cat << EOF
SysManage Agent Privileged Runner

USAGE:
    ./run-privileged.sh [OPTIONS]

DESCRIPTION:
    Runs the SysManage Agent with elevated privileges required for package 
    management operations. Run as a regular user - the script will prompt
    for your password when elevated privileges are needed.
    Works cross-platform on macOS, Linux, and OpenBSD.

PLATFORMS:
    macOS    - Uses sudo with Homebrew package management
    Linux    - Uses sudo with apt/yum/dnf package management  
    OpenBSD  - Uses doas (preferred) or sudo with pkg_add

EXAMPLES:
    ./run-privileged.sh                    # Start agent (will prompt for password)
    ./run-privileged.sh --help             # Show agent help
    ./run-privileged.sh --config custom.yaml  # Use custom config

REQUIREMENTS:
    - Virtual environment (.venv) must be set up
    - sudo access (or doas on OpenBSD) for package management
    - Network connectivity to SysManage server

NOTE:
    Run this script as your regular user account. Do NOT run with doas/sudo
    directly - the script will handle privilege escalation internally.

EOF
}

# Handle help flag
if [ "$1" = "--help" ] || [ "$1" = "-h" ]; then
    if [ "$2" = "runner" ] || [ "$#" -eq 1 ]; then
        show_help
        exit 0
    fi
fi

# Run main function
main "$@"