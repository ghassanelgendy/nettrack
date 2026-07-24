#!/bin/bash
# Check if root
if [ "$EUID" -ne 0 ]; then
  echo "Please run as root (sudo ./setup_gateway.sh)"
  exit 1
fi

# Detect primary network interface
IFACE=$(ip -o -4 route show default | awk '{for(i=1;i<=NF;i++) if($i=="dev") print $(i+1)}')
if [ -z "$IFACE" ]; then
  IFACE="eno1"
fi

echo "Detected primary interface: $IFACE"

# Install dnsmasq if not present for central DHCP
if ! command -v dnsmasq &> /dev/null; then
  echo "Installing dnsmasq for central DHCP..."
  apt-get update && apt-get install -y dnsmasq
fi

# Configure dnsmasq
echo "Configuring dnsmasq DHCP settings..."
[ -f /etc/dnsmasq.conf ] && mv /etc/dnsmasq.conf /etc/dnsmasq.conf.bak 2>/dev/null

MAC_ADDR=$(cat /sys/class/net/$IFACE/address)

cat <<EOF > /etc/dnsmasq.conf
# Run DHCP only, disable local DNS server to prevent conflicts
port=0
interface=$IFACE
dhcp-authoritative
# Disable pinging IPs before offering them (prevents client connection timeouts)
no-ping
dhcp-range=192.168.1.101,192.168.1.250,255.255.255.0,2m
# Explicitly set gateway (option 3) to NetTrack
dhcp-option=3,192.168.1.100
# Set DNS (option 6) to resolvers
dhcp-option=6,1.1.1.1,8.8.8.8

# Ignore DHCP requests from the server itself to prevent routing loops
dhcp-host=$MAC_ADDR,ignore

# Load custom static reservations from NetTrack Dashboard
conf-file=/etc/nettrack_static_leases.conf
EOF

# Ensure static leases file exists
touch /etc/nettrack_static_leases.conf

echo "Restarting dnsmasq DHCP server..."
systemctl enable dnsmasq
systemctl restart dnsmasq

echo "Creating nettrack-gateway systemd service for boot persistence..."
cat <<EOF > /etc/systemd/system/nettrack-gateway.service
[Unit]
Description=NetTrack Gateway NAT Router Setup
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/sbin/sysctl -w net.ipv4.ip_forward=1
ExecStart=/sbin/iptables -t nat -I POSTROUTING 1 -p udp --dport 67:68 --sport 67:68 -j ACCEPT
ExecStart=/sbin/iptables -t nat -A POSTROUTING -o $IFACE -j MASQUERADE
ExecStart=/sbin/iptables -I INPUT 1 -p udp --dport 67:68 --sport 67:68 -j ACCEPT
ExecStart=/bin/sh -c "/sbin/iptables -t mangle -A POSTROUTING -p udp --dport 68 -j CHECKSUM --checksum-fill 2>/dev/null || /sbin/iptables -t mangle -A POSTROUTING -p udp --dport 68 -j CHECKSUM --fill 2>/dev/null || true"
ExecStop=/sbin/iptables -t nat -D POSTROUTING -o $IFACE -j MASQUERADE
ExecStop=/sbin/iptables -t nat -D POSTROUTING -p udp --dport 67:68 --sport 67:68 -j ACCEPT 2>/dev/null || true
ExecStop=/sbin/iptables -D INPUT -p udp --dport 67:68 --sport 67:68 -j ACCEPT 2>/dev/null || true
ExecStop=/bin/sh -c "/sbin/iptables -t mangle -D POSTROUTING -p udp --dport 68 -j CHECKSUM --checksum-fill 2>/dev/null || /sbin/iptables -t mangle -D POSTROUTING -p udp --dport 68 -j CHECKSUM --fill 2>/dev/null || true"

[Install]
WantedBy=multi-user.target
EOF

echo "Creating nettrack-portal systemd service for Captive Portal Daemon..."
cat <<EOF > /etc/systemd/system/nettrack-portal.service
[Unit]
Description=NetTrack Captive Portal Firewall Daemon
After=network-online.target nettrack-gateway.service
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 /home/ghesso/nettrack/nettrack_portal.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

echo "Creating nettrack-web systemd service for Web Dashboard..."
cat <<EOF > /etc/systemd/system/nettrack-web.service
[Unit]
Description=NetTrack Web Dashboard Server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 /home/ghesso/nettrack/nettrack_cli.py --web
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

echo "Creating nettrack-device systemd service for Per-Device Sniffer..."
cat <<EOF > /etc/systemd/system/nettrack-device.service
[Unit]
Description=NetTrack Passive Per-Device Sniffer
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 /home/ghesso/nettrack/nettrack_device_daemon.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

echo "Creating nettrack systemd service for Host Process Monitor..."
cat <<EOF > /etc/systemd/system/nettrack.service
[Unit]
Description=NetTrack Process Bandwidth Daemon
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 /home/ghesso/nettrack/nettrack_daemon.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

# Initialize Database
echo "Initializing database..."
/usr/bin/python3 /home/ghesso/nettrack/init_db.py

# Clean up case-sensitive username 'ghassan' (keeping 'Ghassan')
echo "Cleaning up user data..."
/usr/bin/python3 -c "import sqlite3; conn = sqlite3.connect('/var/lib/nettrack/nettrack.db'); cursor = conn.cursor(); cursor.execute(\"DELETE FROM users WHERE username = 'ghassan'\"); conn.commit(); conn.close()"

# Reload systemd, enable and start the services
echo "Enabling and starting nettrack services..."
systemctl daemon-reload
systemctl enable nettrack-gateway.service
systemctl restart nettrack-gateway.service

systemctl enable nettrack-portal.service
systemctl restart nettrack-portal.service

systemctl enable nettrack-web.service
systemctl restart nettrack-web.service

systemctl enable nettrack-device.service
systemctl restart nettrack-device.service

systemctl enable nettrack.service
systemctl restart nettrack.service

echo ""
echo "========================================================"
echo "          CAPTIVE PORTAL SETUP COMPLETE"
echo "========================================================"
echo "All NetTrack components are installed and active."
echo "Unregistered devices are blocked and redirected to:"
echo "http://192.168.1.100:6054/"
echo "========================================================"
