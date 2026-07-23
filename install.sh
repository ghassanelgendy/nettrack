#!/bin/bash
# NetTrack Installation Script

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0;m' # No Color

echo -e "${BLUE}====================================================${NC}"
echo -e "${BLUE}             NetTrack Installer for Linux           ${NC}"
echo -e "${BLUE}====================================================${NC}"

# Check if script is run with sudo
if [ "$EUID" -ne 0 ]; then
  echo -e "${RED}Error: Please run this installer with sudo:${NC}"
  echo -e "  sudo ./install.sh"
  exit 1
fi

# 1. Install dependencies
echo -e "\n${BLUE}[1/6] Checking dependencies (nethogs + tcpdump)...${NC}"
if ! command -v nethogs &> /dev/null; then
  echo -e "nethogs not found. Installing nethogs..."
  if command -v apt-get &> /dev/null; then
    apt-get update && apt-get install -y nethogs
  elif command -v pacman &> /dev/null; then
    pacman -S --noconfirm nethogs
  elif command -v dnf &> /dev/null; then
    dnf install -y nethogs
  else
    echo -e "${RED}Error: Could not install nethogs automatically. Please install it manually.${NC}"
    exit 1
  fi
else
  echo -e "${GREEN}nethogs is already installed.${NC}"
fi

if ! command -v tcpdump &> /dev/null; then
  echo -e "tcpdump not found. Installing tcpdump..."
  if command -v apt-get &> /dev/null; then
    apt-get install -y tcpdump
  elif command -v pacman &> /dev/null; then
    pacman -S --noconfirm tcpdump
  elif command -v dnf &> /dev/null; then
    dnf install -y tcpdump
  else
    echo -e "${YELLOW}Warning: Could not install tcpdump automatically. Per-device monitoring may use Scapy fallback.${NC}"
  fi
else
  echo -e "${GREEN}tcpdump is already installed.${NC}"
fi

# 2. Detect primary network interface
echo -e "\n${BLUE}[2/6] Detecting primary network interface...${NC}"
IFACE=$(ip -o -4 route show default 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev") print $(i+1); exit}')
if [ -z "$IFACE" ]; then
  IFACE=$(ls /sys/class/net | grep -v -E '^(lo|docker|veth)' | head -n1)
fi
if [ -z "$IFACE" ]; then
  IFACE="eth0"
fi
echo -e "${GREEN}Detected interface: ${IFACE}${NC}"

# 3. Setup database directory
echo -e "\n${BLUE}[3/6] Creating database directory...${NC}"
mkdir -p /var/lib/nettrack
chmod 777 /var/lib/nettrack
echo -e "${GREEN}Database directory created at /var/lib/nettrack${NC}"

# 4. Setup systemd service for process monitor
echo -e "\n${BLUE}[4/6] Creating process-monitor Systemd service...${NC}"
CAT_SERVICE_PATH="/etc/systemd/system/nettrack.service"
cat << 'EOF' > "$CAT_SERVICE_PATH"
[Unit]
Description=NetTrack Network Usage Tracking Daemon (per-process)
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 /home/ghesso/nettrack/nettrack_daemon.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
echo -e "${GREEN}Systemd service file created at $CAT_SERVICE_PATH${NC}"

# 5. Setup systemd service for device sniffer (per-device, promiscuous mode)
echo -e "\n${BLUE}[5/6] Creating per-device sniffer Systemd service...${NC}"
DEVICE_SERVICE_PATH="/etc/systemd/system/nettrack-device.service"
cat << EOF > "$DEVICE_SERVICE_PATH"
[Unit]
Description=NetTrack Device Daemon – passive per-device traffic monitor
After=network.target

[Service]
Type=simple
ExecStartPre=/sbin/ip link set ${IFACE} promisc on
ExecStart=/usr/bin/python3 /home/ghesso/nettrack/nettrack_device_daemon.py -i ${IFACE}
ExecStopPost=/sbin/ip link set ${IFACE} promisc off
Restart=always
RestartSec=5
# Needs CAP_NET_RAW for promiscuous capture
AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN

[Install]
WantedBy=multi-user.target
EOF
echo -e "${GREEN}Device daemon service created at $DEVICE_SERVICE_PATH${NC}"

# 5b. Install global CLI command wrapper
echo -e "   Creating global CLI executable..."
CLI_WRAPPER="/usr/local/bin/nettrack"
cat << 'EOF' > "$CLI_WRAPPER"
#!/bin/bash
python3 /home/ghesso/nettrack/nettrack_cli.py "$@"
EOF
chmod +x "$CLI_WRAPPER"
echo -e "${GREEN}CLI wrapper installed at $CLI_WRAPPER${NC}"

# 6. Enable and start both services
echo -e "\n${BLUE}[6/6] Enabling and starting services...${NC}"
systemctl daemon-reload
systemctl enable nettrack.service
systemctl restart nettrack.service
systemctl enable nettrack-device.service
systemctl restart nettrack-device.service

if systemctl is-active --quiet nettrack.service; then
  echo -e "${GREEN}Process monitor service started successfully!${NC}"
else
  echo -e "${YELLOW}Warning: nettrack.service is not running. Check: systemctl status nettrack.service${NC}"
fi

if systemctl is-active --quiet nettrack-device.service; then
  echo -e "${GREEN}Device sniffer service started successfully on ${IFACE}!${NC}"
else
  echo -e "${YELLOW}Warning: nettrack-device.service is not running. Check: systemctl status nettrack-device.service${NC}"
fi

echo -e "\n${GREEN}====================================================${NC}"
echo -e "${GREEN}        Installation complete!                      ${NC}"
echo -e " Run '${BLUE}nettrack${NC}' to view today's process usage."
echo -e " Run '${BLUE}nettrack --week${NC}' for weekly process usage."
echo -e " Run '${BLUE}nettrack --web${NC}' to launch the web dashboard."
echo -e "   ${YELLOW}→ Open the 'Devices' tab to see per-device usage.${NC}"
echo -e "\n Services:"
echo -e "   nettrack.service         (per-process via nethogs)"
echo -e "   nettrack-device.service  (per-device sniffer on ${IFACE})"
echo -e "${GREEN}====================================================${NC}"
