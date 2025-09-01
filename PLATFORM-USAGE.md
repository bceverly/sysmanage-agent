# Cross-Platform Usage for SysManage Agent

The SysManage Agent supports multiple operating systems with platform-specific startup scripts.

## Supported Platforms

### Unix-like Systems (Linux, macOS, BSD, etc.)
- **Start**: `./run.sh` or `./start`
- **Stop**: `./stop.sh` or `./stop`

### Windows
- **Start**: `run.cmd` or `./start`
- **Stop**: `stop.cmd` or `./stop`

## Automatic Platform Detection

The `start` and `stop` scripts (without extensions) automatically detect your platform and run the appropriate script:

```bash
# Cross-platform - works on all systems
./start    # Automatically runs run.sh or run.cmd
./stop     # Automatically runs stop.sh or stop.cmd
```

## Platform-Specific Features

### Unix/Linux/macOS/BSD
- Uses `pgrep`/`pkill` where available, falls back to `ps`/`grep`/`awk` for older systems
- Uses `lsof` for port checking (server scripts)
- Supports POSIX shell constructs

### Windows
- Uses `tasklist`/`taskkill` for process management
- Uses Windows-specific batch file syntax
- Handles Windows path separators and environment variables
- Supports both `python` and `python3` commands

## Requirements

### All Platforms
- Python 3.6 or later
- Required Python packages (installed automatically from requirements.txt)

### Unix-like Systems
- POSIX-compliant shell (bash, sh, zsh, etc.)
- Standard Unix utilities (ps, awk, grep)

### Windows
- Command Prompt or PowerShell
- Windows 7 or later (for tasklist/taskkill commands)

## Configuration

All platforms use the same `sysmanage-agent.yaml` configuration file format. The agent automatically adapts to platform-specific requirements while maintaining consistent behavior across all supported systems.