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
    
    check_venv
    check_sudo "$platform"
    
    priv_cmd=$(get_priv_cmd "$platform")
    venv_path="$AGENT_DIR/.venv/bin"
    python_path="$AGENT_DIR/.venv/bin/python"
    
    # Preserve current PATH and add venv binaries
    current_path="$venv_path:$PATH"
    
    echo "🐍 Python: $python_path"
    echo "🔧 Privilege escalation: $priv_cmd"
    echo ""
    echo "▶️  Starting SysManage Agent with elevated privileges..."
    echo ""
    
    # Execute with proper environment
    case "$priv_cmd" in
        "doas")
            # OpenBSD doas doesn't have -E flag, so we pass environment explicitly
            doas env PATH="$current_path" PYTHONPATH="$AGENT_DIR" "$python_path" main.py "$@"
            ;;
        *)
            # sudo with -E flag preserves environment
            $priv_cmd PATH="$current_path" PYTHONPATH="$AGENT_DIR" "$python_path" main.py "$@"
            ;;
    esac
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