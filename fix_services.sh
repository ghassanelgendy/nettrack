#!/bin/bash
# Run with: sudo bash /home/ghesso/nettrack/fix_services.sh

echo "======================================"
echo " NetTrack Service Fix Script"
echo "======================================"
echo ""

# 1. Stop the crash-looping DNS service (7000+ restarts, file doesn't exist)
echo "[1] Stopping nettrack-dns (crash-looping, file missing)..."
systemctl stop nettrack-dns 2>/dev/null
systemctl disable nettrack-dns 2>/dev/null
echo "    Done."

# 2. Restart the web server (picks up threading + memory watchdog fixes)
echo "[2] Restarting nettrack-web with reliability fixes..."
systemctl restart nettrack-web
sleep 2
if systemctl is-active --quiet nettrack-web; then
    echo "    ✓ nettrack-web is running"
else
    echo "    ✗ nettrack-web failed to start!"
    systemctl status nettrack-web --no-pager -l
fi

# 3. Check port
echo ""
echo "[3] Port 6054 status:"
ss -tlnp | grep 6054 && echo "    ✓ Port is OPEN" || echo "    ✗ Port NOT open"

# 4. Quick connectivity test
echo ""
echo "[4] HTTP connectivity test:"
curl -s -o /dev/null -w "    HTTP status: %{http_code}\n" http://192.168.1.100:6054/ --max-time 5 || echo "    ✗ Could not connect"

echo ""
echo "[5] Services summary:"
systemctl status nettrack nettrack-web nettrack-device nettrack-portal --no-pager | grep -E 'service|Active:|Main PID'

echo ""
echo "======================================"
echo " DONE. Try http://192.168.1.100:6054/"
echo "======================================"
