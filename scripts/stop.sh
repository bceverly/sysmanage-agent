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
    else
        echo "No PID file found, checking for running processes..."
    fi
}

# Function to kill agent processes by pattern
kill_by_pattern() {
    local pattern="python3.*main.py"
    
    # Cross-platform process finding
    local pids=""
    if command -v pgrep >/dev/null 2>&1; then
        # Use pgrep if available (Linux, modern macOS, some BSD)
        pids=$(pgrep -f "$pattern" 2>/dev/null | grep -v $$) # Exclude this script's PID
    else
        # Fallback: use ps and grep for older systems
        pids=$(ps -ef 2>/dev/null | grep "$pattern" | grep -v grep | grep -v $$ | awk '{print $2}')
    fi
    
    if [ -n "$pids" ]; then
        local pid_count=$(echo "$pids" | wc -l)
        echo "Found $pid_count SysManage Agent process(es), stopping them..."
        echo "$pids" | while read pid; do
            if [ -n "$pid" ]; then
                local cmd=$(ps -p "$pid" -o command= 2>/dev/null | cut -c1-60)
                if [ -z "$cmd" ]; then
                    # Fallback for systems where ps -p doesn't work the same way
                    cmd=$(ps -ef 2>/dev/null | awk -v p="$pid" '$2==p {for(i=8;i<=NF;i++) printf "%s ", $i; print ""}' | cut -c1-60)
                fi
                echo "  Stopping PID $pid: $cmd"
                kill "$pid" 2>/dev/null
            fi
        done
        
        # Wait a moment
        sleep 2
        
        # Force kill if still running - check again with same cross-platform approach
        local remaining_pids=""
        if command -v pgrep >/dev/null 2>&1; then
            remaining_pids=$(pgrep -f "$pattern" 2>/dev/null | grep -v $$)
        else
            remaining_pids=$(ps -ef 2>/dev/null | grep "$pattern" | grep -v grep | grep -v $$ | awk '{print $2}')
        fi
        
        if [ -n "$remaining_pids" ]; then
            local remaining_count=$(echo "$remaining_pids" | wc -l)
            echo "⚠️  $remaining_count agent process(es) still running, force stopping..."
            echo "$remaining_pids" | while read pid; do
                if [ -n "$pid" ]; then
                    kill -9 "$pid" 2>/dev/null
                fi
            done
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
if command -v pgrep >/dev/null 2>&1; then
    remaining_processes=$(pgrep -f "python3.*main.py" 2>/dev/null | grep -v $$ | wc -l)
else
    remaining_processes=$(ps -ef 2>/dev/null | grep "python3.*main.py" | grep -v grep | grep -v $$ | wc -l)
fi

if [ "$remaining_processes" -eq 0 ]; then
    echo ""
    echo "✅ SysManage Agent stopped successfully!"
else
    echo ""
    echo "⚠️  Warning: $remaining_processes agent process(es) may still be running"
    echo ""
    echo "To manually check for agent processes:"
    echo "  ps -ef | grep 'python3.*main.py'"
    echo ""
    echo "To manually kill all agent processes (as last resort):"
    if command -v pkill >/dev/null 2>&1; then
        echo "  pkill -f 'python3.*main.py'"
    else
        echo "  kill \$(ps -ef | grep 'python3.*main.py' | grep -v grep | awk '{print \$2}')"
    fi
fi

echo ""