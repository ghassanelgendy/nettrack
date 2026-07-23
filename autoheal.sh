#!/bin/bash
# NetTrack Autoheal / Watchdog Script
# ==================================
# Checks all NetTrack services and critical networking configurations.
# Restarts any failed/inactive service and ensures they are enabled on boot.

export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

LOG_DIR="/var/log/nettrack"
mkdir -p "$LOG_DIR"
LOG_FILE="$LOG_DIR/autoheal.log"

log_msg() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" >> "$LOG_FILE"
}

SERVICES=(
    "nettrack.service"
    "nettrack-device.service"
    "nettrack-dns.service"
    "nettrack-gateway.service"
    "nettrack-portal.service"
    "nettrack-web.service"
)

# 1. Ensure all services are enabled on boot
for SVC in "${SERVICES[@]}"; do
    if ! systemctl is-enabled --quiet "$SVC" 2>/dev/null; then
        log_msg "Enabling $SVC for startup boot..."
        systemctl enable "$SVC" >/dev/null 2>&1
    fi
done

# 2. Monitor and autoheal services
for SVC in "${SERVICES[@]}"; do
    if [[ "$SVC" == "nettrack-gateway.service" ]]; then
        # Gateway is a oneshot setup service. It should be active (exited).
        STATUS=$(systemctl show -p ActiveState --value "$SVC")
        if [ "$STATUS" != "active" ]; then
            log_msg "$SVC is down (Status: $STATUS). Running gateway setup..."
            systemctl restart "$SVC" >/dev/null 2>&1
        fi
    else
        # Normal running daemons
        if ! systemctl is-active --quiet "$SVC"; then
            log_msg "$SVC is down! Restarting service..."
            systemctl restart "$SVC" >/dev/null 2>&1
        fi
    fi
done

# 3. Verify IP Forwarding is active for routing
if [ "$(sysctl -n net.ipv4.ip_forward)" -ne 1 ]; then
    log_msg "IP forwarding was disabled! Re-enabling ipv4 forward..."
    sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1
fi
