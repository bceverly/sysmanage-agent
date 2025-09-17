#!/bin/sh

# SysManage Agent Stop Script
# Stops the SysManage agent daemon

echo "Stopping SysManage Agent..."

# Get the directory where this script is located
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# Change to the project root directory (parent of scripts directory)
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_ROOT"

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
    
    python3 -c "
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

# Function to kill process by PID file
kill_by_pidfile() {
    local pidfile=$1
    
    if [ -f "$pidfile" ]; then
        local pid=$(cat "$pidfile")
        if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
            echo "Stopping SysManage Agent (PID: $pid)..."
            
            # First try graceful shutdown
            kill "$pid"
            
            # Wait up to 10 seconds for graceful shutdown
            local count=0
            while [ $count -lt 10 ] && kill -0 "$pid" 2>/dev/null; do
                sleep 1
                count=$((count + 1))
                echo -n "."
            done
            echo
            
            # Force kill if still running
            if kill -0 "$pid" 2>/dev/null; then
                echo "Force stopping SysManage Agent..."
                kill -9 "$pid" 2>/dev/null
                sleep 1
            fi
            
            # Verify it's stopped
            if kill -0 "$pid" 2>/dev/null; then
                echo "⚠️  Warning: Agent process may still be running (PID: $pid)"
                return 1
            else
                echo "Agent stopped successfully"
            fi
        else
            echo "Agent PID file found but process not running"
        fi
        rm -f "$pidfile"
        return 0  # Successfully handled PID file case
    else
        echo "No PID file found, checking for running processes..."
        return 1  # No PID file, need to check for processes by pattern
    fi
}

# Function to kill agent processes by pattern with privilege handling
kill_by_pattern() {
    local pattern="python[[:space:]]*main\.py"

    # Cross-platform process finding with user information
    local process_info=""

    # Use ps -eaf format which works reliably on OpenBSD
    process_info=$(ps -eaf 2>/dev/null | grep "$pattern" | grep -v grep | grep -v $$)

    # If no results with simplified pattern, try with the original pattern we know works
    if [ -z "$process_info" ]; then
        process_info=$(ps -eaf 2>/dev/null | grep "python.*main\.py" | grep -v grep | grep -v $$)
    fi

    if [ -n "$process_info" ]; then
        local process_count=$(echo "$process_info" | wc -l)
        echo "Found $process_count SysManage Agent process(es), attempting to stop them..."

        # Track current user info
        local current_user=$(id -un)
        local current_uid=$(id -u)

        # Write process info to temp file to avoid subshell issues
        local temp_file="/tmp/sysmanage_processes_$$"
        echo "$process_info" > "$temp_file"

        # Process each line of process_info
        while IFS= read -r proc_line; do
            if [ -n "$proc_line" ]; then
                local pid=$(echo "$proc_line" | awk '{print $1}')
                # For ps -eaf format, user info is not easily available, so we'll determine it by trying to kill
                local cmd=$(echo "$proc_line" | cut -d' ' -f5- | cut -c1-60)

                echo "  Found PID $pid: $cmd"

                # Try to kill the process
                if kill "$pid" 2>/dev/null; then
                    echo "    ✅ Successfully sent TERM signal to PID $pid"
                else
                    echo "    ⚠️  Could not send TERM signal to PID $pid - trying with elevated privileges..."

                    # Try with elevated privileges (doas/sudo)
                    local killed=false
                    if command -v doas >/dev/null 2>&1 && doas -n true 2>/dev/null; then
                        if doas kill "$pid" 2>/dev/null; then
                            echo "    ✅ Successfully sent signal via doas"
                            killed=true
                        fi
                    elif command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null; then
                        if sudo kill "$pid" 2>/dev/null; then
                            echo "    ✅ Successfully sent signal via sudo"
                            killed=true
                        fi
                    fi

                    if [ "$killed" = false ]; then
                        echo "    ❌ Could not kill process $pid (may require manual intervention)"
                    fi
                fi
            fi
        done < "$temp_file"

        # Clean up temp file
        rm -f "$temp_file"

        # Wait a moment for graceful shutdown
        sleep 3

        # Check for remaining processes and force kill if needed
        local remaining_info=""
        remaining_info=$(ps -eaf 2>/dev/null | grep "$pattern" | grep -v grep | grep -v $$)

        # If no results with simplified pattern, try with the original pattern we know works
        if [ -z "$remaining_info" ]; then
            remaining_info=$(ps -eaf 2>/dev/null | grep "python.*main\.py" | grep -v grep | grep -v $$)
        fi

        if [ -n "$remaining_info" ]; then
            local remaining_count=$(echo "$remaining_info" | wc -l)
            echo "⚠️  $remaining_count agent process(es) still running, attempting force kill..."

            # Write remaining process info to temp file
            local temp_file2="/tmp/sysmanage_remaining_$$"
            echo "$remaining_info" > "$temp_file2"

            while IFS= read -r proc_line; do
                if [ -n "$proc_line" ]; then
                    local pid=$(echo "$proc_line" | awk '{print $1}')

                    echo "  Force killing PID $pid..."

                    # Try force kill
                    if kill -9 "$pid" 2>/dev/null; then
                        echo "    ✅ Force killed PID $pid"
                    else
                        echo "    ⚠️  Could not force kill PID $pid - trying with elevated privileges..."

                        # Try with elevated privileges
                        local killed=false
                        if command -v doas >/dev/null 2>&1 && doas -n true 2>/dev/null; then
                            if doas kill -9 "$pid" 2>/dev/null; then
                                echo "    ✅ Force killed via doas"
                                killed=true
                            fi
                        elif command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null; then
                            if sudo kill -9 "$pid" 2>/dev/null; then
                                echo "    ✅ Force killed via sudo"
                                killed=true
                            fi
                        fi

                        if [ "$killed" = false ]; then
                            echo "    ❌ Could not force kill process $pid (may require manual intervention)"
                        fi
                    fi
                fi
            done < "$temp_file2"

            # Clean up temp file
            rm -f "$temp_file2"
        fi
    fi
}

# Try to stop using PID file first
killed_by_pid=false
if kill_by_pidfile "logs/agent.pid"; then
    killed_by_pid=true
fi

# Fallback: kill by process pattern if PID method didn't work or find any processes
if [ "$killed_by_pid" = false ]; then
    kill_by_pattern
fi

# Clean up log directory if it exists but is empty (except for log files)
if [ -d "logs" ]; then
    # Remove PID file if it still exists
    rm -f logs/agent.pid
    
    # Check if there are only log files left
    if [ -n "$(find logs -name "*.pid" -o -name "processes.env" 2>/dev/null)" ]; then
        find logs -name "*.pid" -delete 2>/dev/null
        find logs -name "processes.env" -delete 2>/dev/null
    fi
fi

# Final verification
sleep 1

# Cross-platform process count check
remaining_processes=0
remaining_processes=$(ps -eaf 2>/dev/null | grep "python.*main\.py" | grep -v grep | grep -v $$ | wc -l)

if [ "$remaining_processes" -eq 0 ]; then
    echo ""
    echo "✅ SysManage Agent stopped successfully!"
else
    echo ""
    echo "⚠️  Warning: $remaining_processes agent process(es) may still be running"
    echo ""
    echo "To manually check for agent processes:"
    echo "  ps -ef | grep 'python.*main.py'"
    echo ""
    echo "To manually kill all agent processes (as last resort):"
    if command -v pkill >/dev/null 2>&1; then
        echo "  pkill -f 'python.*main.py'"
    else
        echo "  kill \$(ps -ef | grep 'python.*main.py' | grep -v grep | awk '{print \$2}')"
    fi
fi

echo ""