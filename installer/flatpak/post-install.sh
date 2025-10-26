#!/bin/bash
#
# SysManage Agent - Flatpak Post-Install Information Script
# This script displays installation instructions and copies service scripts
#

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo ""
echo -e "${GREEN}====================================${NC}"
echo -e "${GREEN}SysManage Agent Installation Complete!${NC}"
echo -e "${GREEN}====================================${NC}"
echo ""

# Copy service scripts to ~/.local/bin/
echo -e "${YELLOW}Setting up systemd service scripts...${NC}"
mkdir -p ~/.local/bin

# Copy scripts from the Flatpak installation
FLATPAK_APP_DIR="/var/lib/flatpak/app/org.sysmanage.Agent/current/active/files"
FLATPAK_USER_DIR="$HOME/.local/share/flatpak/app/org.sysmanage.Agent/current/active/files"

if [ -d "$FLATPAK_USER_DIR/share/sysmanage-agent/scripts" ]; then
    SCRIPT_SOURCE="$FLATPAK_USER_DIR/share/sysmanage-agent/scripts"
elif [ -d "$FLATPAK_APP_DIR/share/sysmanage-agent/scripts" ]; then
    SCRIPT_SOURCE="$FLATPAK_APP_DIR/share/sysmanage-agent/scripts"
else
    echo -e "${YELLOW}Warning: Could not find service scripts in Flatpak installation${NC}"
    SCRIPT_SOURCE=""
fi

if [ -n "$SCRIPT_SOURCE" ]; then
    install -m 755 "$SCRIPT_SOURCE/sysmanage-service-install.sh" ~/.local/bin/sysmanage-service-install.sh 2>/dev/null
    install -m 755 "$SCRIPT_SOURCE/sysmanage-service-uninstall.sh" ~/.local/bin/sysmanage-service-uninstall.sh 2>/dev/null
    echo -e "${GREEN}✓ Service scripts installed to ~/.local/bin/${NC}"
else
    echo -e "${YELLOW}Service scripts will need to be installed manually${NC}"
fi

echo ""
echo -e "${BLUE}Configuration:${NC}"
echo "  ~/.var/app/org.sysmanage.Agent/config/sysmanage/sysmanage-agent.yaml"
echo ""
echo -e "${BLUE}Database:${NC}"
echo "  ~/.var/app/org.sysmanage.Agent/data/sysmanage/agent.db"
echo ""
echo -e "${BLUE}Logs:${NC}"
echo "  ~/.var/app/org.sysmanage.Agent/data/sysmanage/logs/agent.log"
echo ""
echo -e "${BLUE}Run manually with:${NC}"
echo "  flatpak run org.sysmanage.Agent"
echo ""

if [ -f ~/.local/bin/sysmanage-service-install.sh ]; then
    echo -e "${BLUE}Or install as systemd service (starts at boot):${NC}"
    echo "  ~/.local/bin/sysmanage-service-install.sh"
    echo ""
    echo -e "${BLUE}To uninstall systemd service later:${NC}"
    echo "  ~/.local/bin/sysmanage-service-uninstall.sh"
    echo ""
fi

echo -e "${BLUE}View logs:${NC}"
echo "  From outside Flatpak:"
echo "    flatpak run --command=sh org.sysmanage.Agent -c 'tail -f ~/.var/app/org.sysmanage.Agent/data/sysmanage/logs/agent.log'"
echo "  Systemd service logs:"
echo "    journalctl --user -u sysmanage-agent -f"
echo ""
echo -e "${BLUE}Edit configuration (use your preferred editor):${NC}"
echo "  vi ~/.var/app/org.sysmanage.Agent/config/sysmanage/sysmanage-agent.yaml"
echo "  OR"
echo "  nano ~/.var/app/org.sysmanage.Agent/config/sysmanage/sysmanage-agent.yaml"
echo ""
echo "  After editing, restart the service:"
echo "  systemctl --user restart sysmanage-agent"
echo ""
