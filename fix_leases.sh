#!/bin/bash
# Fix broken dnsmasq static leases — run with: sudo bash fix_leases.sh

echo "=== Fixing /etc/nettrack_static_leases.conf ==="

cat > /etc/nettrack_static_leases.conf << 'EOF'
dhcp-host=d8:93:d4:d9:68:d8,192.168.1.199,redmi-note-14,infinite
dhcp-host=5e:e4:e0:8c:d8:7e,192.168.1.179,iphone-13,infinite
dhcp-host=ba:15:43:36:d2:35,192.168.1.214,unnamed-device-214,infinite
dhcp-host=64:d0:d6:bb:94:f0,192.168.1.138,samsung-a07,infinite
dhcp-host=70:9c:d1:03:4a:f8,192.168.1.143,unnamed-device-143,infinite
dhcp-host=e0:cc:f8:45:86:70,192.168.1.198,redmi-note-8,infinite
dhcp-host=e8:98:47:92:07:0a,192.168.1.175,redmi-note-13,infinite
dhcp-host=18:34:51:05:b5:f9,192.168.1.106,iphone-4s,infinite
dhcp-host=64:d0:d6:70:54:e0,192.168.1.204,samsung-a35,infinite
dhcp-host=46:11:e4:5f:5d:d7,192.168.1.211,unnamed-device-211,infinite
dhcp-host=02:eb:d8:05:f2:e0,192.168.1.220,talia,infinite
dhcp-host=8a:40:c2:e3:91:0e,192.168.1.241,redmi-note-9,infinite
dhcp-host=e8:fb:1c:54:48:67,192.168.1.102,laptop,infinite
dhcp-host=f0:ee:7a:3d:ed:4a,192.168.1.117,iphone-13-pro,infinite
dhcp-host=40:a8:f0:3d:9a:89,192.168.1.100,nettrack-server--self,infinite
EOF

echo "--- Validating config ---"
dnsmasq --test --conf-file=/etc/dnsmasq.conf 2>&1

if [ $? -eq 0 ]; then
    echo "--- Config OK, restarting dnsmasq ---"
    systemctl restart dnsmasq
    sleep 1
    systemctl status dnsmasq --no-pager
    echo ""
    echo "=== SUCCESS: dnsmasq is running, Wi-Fi DHCP restored ==="
else
    echo "=== ERROR: config still invalid, NOT restarting ==="
fi
