#!/bin/sh
# SysManage Agent Privileged Runner
# Cross-platform script for macOS (zsh), Ubuntu (bash), and OpenBSD (ksh)
#
# This script runs the SysManage Agent with elevated privileges needed for
# package management operations (updates, installations, etc.)

set -e

# Get the absolute path to the script directory
AGENT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$AGENT_DIR"

# Platform detection
detect_platform() {
    if [ "$(uname)" = "Darwin" ]; then
        echo "macos"
    elif [ "$(uname)" = "OpenBSD" ]; then
        echo "openbsd"  
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
    local platform="$1"
    
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
        "openbsd")
            if ! doas true 2>/dev/null && ! sudo -n true 2>/dev/null; then
                echo "🔐 This script requires elevated privileges (doas or sudo) for package management."
                echo "📝 You may be prompted for your password."
            fi
            ;;
    esac
}

# Get the appropriate privilege escalation command
get_priv_cmd() {
    local platform="$1"
    
    case "$platform" in
        "openbsd")
            # OpenBSD prefers doas, fallback to sudo
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
    local found_processes=false
    
    # Check for agent processes by pattern (cross-platform approach)
    local agent_pids=""
    if command -v pgrep >/dev/null 2>&1; then
        # Use pgrep if available (Linux, modern macOS, some BSD)
        agent_pids=$(pgrep -f "python3.*main.py" 2>/dev/null | grep -v $$) # Exclude this script's PID
    else
        # Fallback: use ps and grep for older systems
        agent_pids=$(ps -ef 2>/dev/null | grep "python3.*main.py" | grep -v grep | grep -v $$ | awk '{print $2}')
    fi
    
    if [ -n "$agent_pids" ]; then
        echo "⚠️  Found existing agent processes:"
        echo "$agent_pids" | while read pid; do
            if [ -n "$pid" ]; then
                local cmd=$(ps -p "$pid" -o command= 2>/dev/null | cut -c1-80)
                if [ -z "$cmd" ]; then
                    # Fallback for systems where ps -p doesn't work the same way
                    cmd=$(ps -ef 2>/dev/null | awk -v p="$pid" '$2==p {for(i=8;i<=NF;i++) printf "%s ", $i; print ""}' | cut -c1-80)
                fi
                echo "   PID $pid: $cmd"
            fi
        done
        found_processes=true
    fi
    
    # Check PID file
    if [ -f "logs/agent.pid" ]; then
        local pid_file_pid=$(cat logs/agent.pid 2>/dev/null)
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
    local key=$1
    local config_file=""
    
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

# Main execution
main() {
    local platform
    local priv_cmd
    local venv_path
    local python_path
    local current_path
    
    platform=$(detect_platform)
    
    echo "🚀 SysManage Agent Privileged Runner"
    echo "🖥️  Platform: $platform ($(uname))"
    echo "📁 Working directory: $AGENT_DIR"
    
    # Create logs directory if it doesn't exist
    mkdir -p logs
    
    # Stop any existing agent
    if check_existing_processes; then
        sh ./stop.sh
        sleep 2
        
        # Verify they were stopped
        if check_existing_processes >/dev/null 2>&1; then
            echo "❌ ERROR: Failed to stop existing agent processes. Please manually stop them before continuing."
            echo ""
            echo "To manually check for agent processes:"
            echo "  ps -ef | grep 'python3.*main.py'"
            echo ""
            echo "To manually kill all agent processes:"
            if command -v pkill >/dev/null 2>&1; then
                echo "  pkill -f 'python3.*main.py'"
            else
                echo "  kill \$(ps -ef | grep 'python3.*main.py' | grep -v grep | awk '{print \$2}')"
            fi
            exit 1
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
    echo "▶️  Starting SysManage Agent with elevated privileges..."
    echo ""
    
    # Start the agent in background with proper environment and logging
    case "$priv_cmd" in
        "doas")
            # OpenBSD doas - create a wrapper script to handle backgrounding properly
            cat > /tmp/sysmanage_agent_start.sh << EOF
#!/bin/sh
cd "$AGENT_DIR"
export PATH="$current_path"
export PYTHONPATH="$AGENT_DIR" 
exec "$python_path" main.py "$@" > logs/agent.log 2>&1 &
echo \$! > logs/agent.pid
EOF
            chmod +x /tmp/sysmanage_agent_start.sh
            doas /tmp/sysmanage_agent_start.sh
            sleep 1
            if [ -f logs/agent.pid ]; then
                AGENT_PID=$(cat logs/agent.pid)
            else
                AGENT_PID=""
            fi
            rm -f /tmp/sysmanage_agent_start.sh
            ;;
        *)
            # sudo with -E flag preserves environment
            nohup $priv_cmd PATH="$current_path" PYTHONPATH="$AGENT_DIR" "$python_path" main.py "$@" > logs/agent.log 2>&1 &
            AGENT_PID=$!
            ;;
    esac
    
    # Save PID (only for non-doas cases, doas case already saves it)
    if [ "$priv_cmd" != "doas" ]; then
        echo $AGENT_PID > logs/agent.pid
    fi
    
    # Give it a moment to start
    sleep 2
    
    # Check if the process is still running
    if kill -0 "$AGENT_PID" 2>/dev/null; then
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
        echo "To stop the agent: ./stop.sh"
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
    management operations. Works cross-platform on macOS, Linux, and OpenBSD.

PLATFORMS:
    macOS    - Uses sudo with Homebrew package management
    Linux    - Uses sudo with apt/yum/dnf package management  
    OpenBSD  - Uses doas (preferred) or sudo with pkg_add

EXAMPLES:
    ./run-privileged.sh                    # Start agent normally
    ./run-privileged.sh --help             # Show agent help
    ./run-privileged.sh --config custom.yaml  # Use custom config

REQUIREMENTS:
    - Virtual environment (.venv) must be set up
    - sudo access (or doas on OpenBSD) for package management
    - Network connectivity to SysManage server

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