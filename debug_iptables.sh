#!/bin/bash
echo "=== FILTER TABLE ===" > /home/ghesso/nettrack/iptables_dump.txt
iptables -t filter -S >> /home/ghesso/nettrack/iptables_dump.txt
echo "=== NAT TABLE ===" >> /home/ghesso/nettrack/iptables_dump.txt
iptables -t nat -S >> /home/ghesso/nettrack/iptables_dump.txt
echo "=== IP FORWARD STATUS ===" >> /home/ghesso/nettrack/iptables_dump.txt
sysctl net.ipv4.ip_forward >> /home/ghesso/nettrack/iptables_dump.txt
chmod 666 /home/ghesso/nettrack/iptables_dump.txt
