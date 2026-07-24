#!/usr/bin/env python3
import os
import sys
import time
import sqlite3
import subprocess
import threading
import argparse

DB_PATH = "/var/lib/nettrack/nettrack.db"
VAULT_DB_PATH = "/var/lib/nettrack/vault.db"

# Accumulator lock
lock = threading.Lock()
# { (mac, ip): { 'sent': 0, 'received': 0 } }
stats_accumulator = {}

# Vault accumulator
vault_lock = threading.Lock()
vault_accumulator = []

# Tracker for last seen iptables bytes: { ip: { 'sent': last_sent, 'recv': last_recv } }
iptables_last_seen = {}

def normalize_mac(mac):
    try:
        parts = mac.split(':')
        if len(parts) == 6:
            return ":".join(f"{int(p, 16):02x}" for p in parts)
    except Exception:
        pass
    return mac.lower().strip()

def get_mac_from_arp(ip):
    # Try resolving MAC from DHCP leases first to get the client's real MAC
    try:
        if os.path.exists("/var/lib/misc/dnsmasq.leases"):
            with open("/var/lib/misc/dnsmasq.leases", "r") as f:
                for line in f:
                    parts = line.strip().split()
                    if len(parts) >= 3 and parts[2] == ip:
                        return normalize_mac(parts[1])
    except Exception:
        pass

    # Fallback to local ARP table
    try:
        with open("/proc/net/arp", "r") as f:
            lines = f.readlines()
        for line in lines[1:]:
            parts = line.split()
            if len(parts) >= 4 and parts[0] == ip:
                return normalize_mac(parts[3])
    except Exception:
        pass
    return "unknown"

def get_primary_interface():
    try:
        res = subprocess.run("ip -o -4 route show default", shell=True, capture_output=True, text=True)
        parts = res.stdout.split()
        if "dev" in parts:
            return parts[parts.index("dev") + 1]
    except Exception:
        pass
    return "eno1"

def init_vault_db():
    try:
        os.makedirs("/var/lib/nettrack", exist_ok=True)
        conn = sqlite3.connect(VAULT_DB_PATH)
        cursor = conn.cursor()
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS raw_traffic (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            src_mac TEXT,
            src_ip TEXT,
            dst_mac TEXT,
            dst_ip TEXT,
            bytes INTEGER
        );
        """)
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[device] Error initializing vault db: {e}", file=sys.stderr, flush=True)

def parse_iptables_counters():
    global iptables_last_seen, stats_accumulator
    try:
        # Get raw byte counts from iptables ALLOW chain
        res = subprocess.run("iptables -L NETTRACK-PORTAL-ALLOW -v -n -x", shell=True, capture_output=True, text=True)
        lines = res.stdout.splitlines()
        
        # Temporary storage for current check
        # { ip: { 'sent': bytes, 'recv': bytes } }
        current_counters = {}
        
        for line in lines:
            parts = line.strip().split()
            # Expecting: pkts bytes target prot opt in out source destination
            if len(parts) >= 9 and parts[2] == "ACCEPT":
                try:
                    bytes_val = int(parts[1])
                    src = parts[7]
                    dst = parts[8]
                    
                    if src.startswith("192.168.1.") and dst == "0.0.0.0/0":
                        ip = src
                        if ip not in current_counters:
                            current_counters[ip] = {'sent': 0, 'recv': 0}
                        current_counters[ip]['sent'] = bytes_val
                        
                    elif dst.startswith("192.168.1.") and src == "0.0.0.0/0":
                        ip = dst
                        if ip not in current_counters:
                            current_counters[ip] = {'sent': 0, 'recv': 0}
                        current_counters[ip]['recv'] = bytes_val
                except ValueError:
                    continue
        
        # Calculate deltas and update stats_accumulator
        with lock:
            for ip, counts in current_counters.items():
                mac = get_mac_from_arp(ip)
                if mac == "unknown":
                    continue
                    
                last = iptables_last_seen.get(ip, {'sent': 0, 'recv': 0})
                
                # Sent delta
                if counts['sent'] >= last['sent']:
                    sent_delta = counts['sent'] - last['sent']
                else:
                    sent_delta = counts['sent'] # Chain was flushed
                    
                # Recv delta
                if counts['recv'] >= last['recv']:
                    recv_delta = counts['recv'] - last['recv']
                else:
                    recv_delta = counts['recv'] # Chain was flushed
                
                if sent_delta > 0 or recv_delta > 0:
                    key = (mac, ip)
                    if key not in stats_accumulator:
                        stats_accumulator[key] = {'sent': 0, 'received': 0}
                    stats_accumulator[key]['sent'] += sent_delta
                    stats_accumulator[key]['received'] += recv_delta
                    
            # Save current state for next loop iteration
            iptables_last_seen = current_counters
            
    except Exception as e:
        print(f"[device] Error parsing iptables counters: {e}", file=sys.stderr, flush=True)

def iptables_accounting_loop():
    print("[device] Starting 100% accurate iptables byte accounting loop...", flush=True)
    while True:
        parse_iptables_counters()
        time.sleep(5) # Query every 5 seconds for high resolution limit enforcement

def flush_stats():
    global stats_accumulator
    while True:
        time.sleep(10)
        with lock:
            if not stats_accumulator:
                continue
            to_flush = stats_accumulator.copy()
            stats_accumulator.clear()

        # Write to SQLite
        try:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            
            # Current hour timestamp for aggregate
            hour_ts = time.strftime("%Y-%m-%d %H:00:00", time.gmtime())
            
            for (mac, ip), bytes_data in to_flush.items():
                sent = bytes_data['sent']
                recv = bytes_data['received']
                
                # Check if entry exists for this MAC and hour
                cursor.execute("""
                SELECT sent_bytes, received_bytes FROM device_usage
                WHERE mac_address = ? AND timestamp = ?;
                """, (mac, hour_ts))
                row = cursor.fetchone()
                
                if row:
                    new_sent = row[0] + sent
                    new_recv = row[1] + recv
                    cursor.execute("""
                    UPDATE device_usage
                    SET sent_bytes = ?, received_bytes = ?, ip_address = ?
                    WHERE mac_address = ? AND timestamp = ?;
                    """, (new_sent, new_recv, ip, mac, hour_ts))
                else:
                    cursor.execute("""
                    INSERT INTO device_usage (mac_address, ip_address, timestamp, sent_bytes, received_bytes)
                    VALUES (?, ?, ?, ?, ?);
                    """, (mac, ip, hour_ts, sent, recv))
            
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"[device] Error flushing stats: {e}", file=sys.stderr, flush=True)

def flush_vault():
    global vault_accumulator
    while True:
        time.sleep(5)
        with vault_lock:
            if not vault_accumulator:
                continue
            to_flush = list(vault_accumulator)
            vault_accumulator.clear()

        try:
            conn = sqlite3.connect(VAULT_DB_PATH)
            cursor = conn.cursor()
            cursor.executemany("""
                INSERT INTO raw_traffic (src_mac, src_ip, dst_mac, dst_ip, bytes)
                VALUES (?, ?, ?, ?, ?);
            """, to_flush)
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"[device] Error flushing vault stats: {e}", file=sys.stderr, flush=True)

def parse_tcpdump(iface):
    print(f"[device] Starting tcpdump packet capture on interface: {iface}", flush=True)
    
    server_mac = "00:00:00:00:00:00"
    try:
        with open(f"/sys/class/net/{iface}/address", "r") as f:
            server_mac = normalize_mac(f.read().strip())
    except Exception:
        pass
        
    # Enable promiscuous mode on interface
    subprocess.run(f"ip link set {iface} promisc on", shell=True)
    
    # Run tcpdump to capture IP packets with link-level headers
    # Using quiet mode (-q) to reduce stdout printing overhead
    cmd = ["tcpdump", "-q", "-l", "-n", "-e", "-i", iface, "ip"]
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
    
    try:
        for line in proc.stdout:
            parts = line.strip().split()
            if len(parts) < 10:
                continue
            
            try:
                # Find length
                length_idx = -1
                for idx, part in enumerate(parts):
                    if part == "length" and idx + 1 < len(parts):
                        length_idx = idx + 1
                        break
                if length_idx == -1:
                    continue
                
                length_str = parts[length_idx].rstrip(':')
                pkt_len = int(length_str)
                
                # MAC addresses
                src_mac = normalize_mac(parts[1])
                dst_mac = normalize_mac(parts[3].rstrip(','))
                
                # IP addresses
                ip_part = parts[length_idx + 1]
                src_ip = ".".join(ip_part.split(".")[:4])
                
                dst_ip_part = parts[length_idx + 3].rstrip(':')
                dst_ip = ".".join(dst_ip_part.split(".")[:4])
                
                # Log server local traffic (which bypasses forward chain iptables counters)
                if src_ip == "192.168.1.100" or dst_ip == "192.168.1.100":
                    with lock:
                        key = (server_mac, "192.168.1.100")
                        if key not in stats_accumulator:
                            stats_accumulator[key] = {'sent': 0, 'received': 0}
                        if src_ip == "192.168.1.100":
                            stats_accumulator[key]['sent'] += pkt_len
                        if dst_ip == "192.168.1.100":
                            stats_accumulator[key]['received'] += pkt_len

                # Log to vault
                with vault_lock:
                    if len(vault_accumulator) < 5000:
                        vault_accumulator.append((src_mac, src_ip, dst_mac, dst_ip, pkt_len))
            except Exception:
                continue
    except KeyboardInterrupt:
        pass
    finally:
        proc.terminate()
        # Disable promiscuous mode on interface
        subprocess.run(f"ip link set {iface} promisc off", shell=True)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--interface", help="Interface to sniff on")
    args = parser.parse_args()
    
    iface = args.interface or get_primary_interface()
    
    init_vault_db()
    
    # Run stats flush threads
    threading.Thread(target=flush_stats, daemon=True).start()
    threading.Thread(target=flush_vault, daemon=True).start()
    threading.Thread(target=iptables_accounting_loop, daemon=True).start()
    
    # Parse tcpdump for Vault connection flow
    parse_tcpdump(iface)

if __name__ == "__main__":
    main()
