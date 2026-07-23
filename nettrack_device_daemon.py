#!/usr/bin/env python3
"""
NetTrack Device Daemon
======================
Passively monitors per-device (IP/MAC) network usage across all connected
devices by sniffing traffic on the specified interface in promiscuous mode.

Data is stored hourly in /var/lib/nettrack/nettrack.db under the
`device_usage` table, separate from per-process tracking.

Usage:
    sudo python3 nettrack_device_daemon.py [-i INTERFACE] [--db DB_PATH]

Requires: tcpdump (apt install tcpdump) OR python3-scapy (apt install python3-scapy)
"""

import subprocess
import os
import sys
import time
import sqlite3
import threading
import signal
import re
import struct
import socket
import argparse

# ──────────────────────────────────────────────────────────────────────────────
# Configuration
# ──────────────────────────────────────────────────────────────────────────────
DB_DIR  = "/var/lib/nettrack"
DB_PATH = os.path.join(DB_DIR, "nettrack.db")

# IP Addresses to exclude from traffic accounting (e.g. localhost)
EXCLUDED_IPS = {"127.0.0.1"}
try:
    import subprocess
    out = subprocess.check_output(["hostname", "-I"], text=True)
    for ip in out.split():
        # Keep 192.168.1.100 out of EXCLUDED_IPS so its local app traffic can be monitored
        if ip != "192.168.1.100":
            EXCLUDED_IPS.add(ip)
except Exception:
    pass

# Active NAT ports tracking to prevent double-counting forwarded client traffic
active_nat_ports = set()
nat_ports_lock = threading.Lock()

def update_nat_ports_loop():
    global active_nat_ports
    print("[device] NAT port tracking thread started.", flush=True)
    while not stop_event.is_set():
        ports = set()
        try:
            if os.path.exists("/proc/net/nf_conntrack"):
                with open("/proc/net/nf_conntrack", "r") as f:
                    for line in f:
                        parts = line.strip().split()
                        
                        # Find original source IP (first src= parameter)
                        original_src = None
                        for p in parts:
                            if p.startswith("src="):
                                original_src = p.split("=")[1]
                                break
                                
                        # Only track NAT ports for local physical LAN clients (192.168.1.X)
                        # This avoids excluding Docker/Tailscale/VPN container traffic, leaving them to be counted as Server traffic.
                        if original_src and original_src.startswith("192.168.1.") and original_src != "192.168.1.100":
                            if "dst=192.168.1.100" in parts:
                                idx = parts.index("dst=192.168.1.100")
                                for p in parts[idx:]:
                                    if p.startswith("dport="):
                                        ports.add(int(p.split("=")[1]))
                                        break
        except Exception:
            pass
        with nat_ports_lock:
            active_nat_ports = ports
        time.sleep(2)

# ──────────────────────────────────────────────────────────────────────────────
# Thread-safe state
# ──────────────────────────────────────────────────────────────────────────────
# accumulator: { hour_ts: { ip: { mac, sent, recv } } }
accumulator = {}
lock        = threading.Lock()
stop_event  = threading.Event()


# ──────────────────────────────────────────────────────────────────────────────
# Database helpers
# ──────────────────────────────────────────────────────────────────────────────
def init_db():
    try:
        os.makedirs(DB_DIR, exist_ok=True)
        conn   = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()

        # Create normalized tables
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            daily_limit_mb INTEGER DEFAULT 2048
        );
        """)

        cursor.execute("""
        CREATE TABLE IF NOT EXISTS devices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
            device_name TEXT NOT NULL,
            floor TEXT NOT NULL DEFAULT '',
            device_type TEXT NOT NULL DEFAULT '',
            cookie_uuid TEXT,
            is_low_end INTEGER DEFAULT 0,
            approved INTEGER DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        """)

        cursor.execute("""
        CREATE TABLE IF NOT EXISTS device_macs (
            mac_address TEXT PRIMARY KEY,
            device_id INTEGER REFERENCES devices(id) ON DELETE CASCADE
        );
        """)

        cursor.execute("""
        CREATE TABLE IF NOT EXISTS device_ips (
            ip_address TEXT PRIMARY KEY,
            device_id INTEGER REFERENCES devices(id) ON DELETE CASCADE,
            mac_address TEXT REFERENCES device_macs(mac_address) ON DELETE SET NULL,
            last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        """)

        # Per-device hourly usage
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS device_usage (
            hour_timestamp INTEGER,
            ip_address     TEXT    NOT NULL,
            mac_address    TEXT    NOT NULL DEFAULT '',
            sent_bytes     INTEGER NOT NULL DEFAULT 0,
            received_bytes INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY (hour_timestamp, ip_address)
        );
        """)

        # Friendly labels for devices
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS device_labels (
            ip_address  TEXT PRIMARY KEY,
            mac_address TEXT    NOT NULL DEFAULT '',
            label       TEXT    NOT NULL DEFAULT '',
            floor       TEXT    NOT NULL DEFAULT '',
            device_type TEXT    NOT NULL DEFAULT ''
        );
        """)

        conn.commit()
        conn.close()

        os.chmod(DB_DIR,  0o777)
        os.chmod(DB_PATH, 0o666)
        print(f"[device] Database ready at {DB_PATH}", flush=True)
    except Exception as exc:
        print(f"[device] DB init error: {exc}", file=sys.stderr, flush=True)
        sys.exit(1)


def get_hour_ts():
    now = time.time()
    return int(now - (now % 3600))


def flush_accumulator():
    global accumulator
    with lock:
        if not accumulator:
            return
        snapshot    = accumulator
        accumulator = {}

    try:
        conn   = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        for hour_ts, devices in snapshot.items():
            for ip, data in devices.items():
                # Query the correct MAC address from the database (populated by the ARP loop)
                mac = ""
                cursor.execute("SELECT mac_address FROM device_ips WHERE ip_address = ?", (ip,))
                db_row = cursor.fetchone()
                if db_row and db_row[0]:
                    mac = db_row[0]

                cursor.execute("""
                INSERT INTO device_usage
                    (hour_timestamp, ip_address, mac_address, sent_bytes, received_bytes)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(hour_timestamp, ip_address) DO UPDATE SET
                    mac_address    = CASE WHEN excluded.mac_address != '' THEN excluded.mac_address
                                         ELSE mac_address END,
                    sent_bytes     = sent_bytes     + excluded.sent_bytes,
                    received_bytes = received_bytes + excluded.received_bytes;
                """, (
                    hour_ts,
                    ip,
                    mac,
                    int(data.get("sent", 0)),
                    int(data.get("recv", 0)),
                ))
        conn.commit()
        conn.close()

        try:
            os.chmod(DB_PATH, 0o666)
        except Exception:
            pass

    except Exception as exc:
        print(f"[device] Flush error: {exc}", file=sys.stderr, flush=True)
        # Restore lost data back into accumulator
        with lock:
            for hour_ts, devices in snapshot.items():
                accumulator.setdefault(hour_ts, {})
                for ip, data in devices.items():
                    entry = accumulator[hour_ts].setdefault(
                        ip, {"mac": data.get("mac", ""), "sent": 0, "recv": 0}
                    )
                    entry["sent"] += data.get("sent", 0)
                    entry["recv"] += data.get("recv", 0)


def flush_loop():
    while not stop_event.is_set():
        for _ in range(20):
            if stop_event.is_set():
                break
            time.sleep(0.5)
        flush_accumulator()


# ──────────────────────────────────────────────────────────────────────────────
# Promiscuous mode helpers
# ──────────────────────────────────────────────────────────────────────────────
def enable_promisc(iface):
    """Enable promiscuous mode using `ip link set <iface> promisc on`."""
    try:
        result = subprocess.run(
            ["ip", "link", "set", iface, "promisc", "on"],
            capture_output=True, text=True
        )
        if result.returncode == 0:
            print(f"[device] Promiscuous mode enabled on {iface}", flush=True)
        else:
            print(
                f"[device] Warning: could not enable promisc on {iface}: "
                f"{result.stderr.strip()}",
                flush=True
            )
    except Exception as exc:
        print(f"[device] Warning: promisc enable failed: {exc}", flush=True)


def disable_promisc(iface):
    try:
        subprocess.run(
            ["ip", "link", "set", iface, "promisc", "off"],
            capture_output=True, text=True
        )
        print(f"[device] Promiscuous mode disabled on {iface}", flush=True)
    except Exception:
        pass


# ──────────────────────────────────────────────────────────────────────────────
# IP helpers
# ──────────────────────────────────────────────────────────────────────────────
_PRIVATE_NETS = [
    (0xC0A80000, 0xFFFF0000),   # 192.168.0.0/16
    (0xAC100000, 0xFFF00000),   # 172.16.0.0/12
    (0x0A000000, 0xFF000000),   # 10.0.0.0/8
]

def _ip_to_int(ip_str):
    try:
        packed = socket.inet_aton(ip_str)
        return struct.unpack("!I", packed)[0]
    except Exception:
        return None

def is_private_ip(ip_str):
    val = _ip_to_int(ip_str)
    if val is None:
        return False
    for net, mask in _PRIVATE_NETS:
        if (val & mask) == net:
            return True
    return False

def is_multicast_or_broadcast(ip_str):
    val = _ip_to_int(ip_str)
    if val is None:
        return True
    if (val & 0xF0000000) == 0xE0000000:  # 224.0.0.0/4  multicast
        return True
    if val == 0xFFFFFFFF:                  # 255.255.255.255
        return True
    return False

def normalize_mac(mac_str):
    return mac_str.lower().strip()


# ──────────────────────────────────────────────────────────────────────────────
# Packet accounting
# ──────────────────────────────────────────────────────────────────────────────
def account_packet(src_ip, dst_ip, pkt_len, src_mac="", dst_mac="", src_port=None, dst_port=None):
    """
    Record a packet in the in-memory accumulator.
    sent_bytes for the src_ip, received_bytes for dst_ip.
    Only private LAN IPs are tracked.
    """
    # Exclude explicitly configured local loopback or other interfaces
    if src_ip in EXCLUDED_IPS or dst_ip in EXCLUDED_IPS:
        return

    # For the server's primary IP, ignore packets if they correspond to active client NAT ports (double-counting prevention)
    if src_ip == "192.168.1.100" and src_port is not None:
        with nat_ports_lock:
            if src_port in active_nat_ports or dst_port in active_nat_ports:
                return
    if dst_ip == "192.168.1.100" and dst_port is not None:
        with nat_ports_lock:
            if src_port in active_nat_ports or dst_port in active_nat_ports:
                return

    hour_ts = get_hour_ts()

    with lock:
        accumulator.setdefault(hour_ts, {})

        if src_ip and is_private_ip(src_ip) and not is_multicast_or_broadcast(src_ip):
            entry = accumulator[hour_ts].setdefault(
                src_ip, {"mac": "", "sent": 0, "recv": 0}
            )
            entry["sent"] += pkt_len

        if dst_ip and is_private_ip(dst_ip) and not is_multicast_or_broadcast(dst_ip):
            entry = accumulator[hour_ts].setdefault(
                dst_ip, {"mac": "", "sent": 0, "recv": 0}
            )
            entry["recv"] += pkt_len


# ──────────────────────────────────────────────────────────────────────────────
# Backend 1: tcpdump (preferred – no extra Python lib required)
# ──────────────────────────────────────────────────────────────────────────────
# Example tcpdump line (-n -e -q ip):
# 12:00:00.000000 aa:bb:cc:dd:ee:ff > 11:22:33:44:55:66, ethertype IPv4 (0x0800), length 1514: 192.168.1.5.443 > 192.168.1.10.51234: ...
_TCPDUMP_LINE = re.compile(
    r"(?P<src_mac>[0-9a-f]{2}(?::[0-9a-f]{2}){5})\s*>\s*"
    r"(?P<dst_mac>[0-9a-f]{2}(?::[0-9a-f]{2}){5}).*?length\s+(?P<length>\d+):\s*"
    r"(?P<src_ip>\d{1,3}(?:\.\d{1,3}){3})(?:\.(?P<src_port>\d+))?\s*>\s*"
    r"(?P<dst_ip>\d{1,3}(?:\.\d{1,3}){3})(?:\.(?P<dst_port>\d+))?",
    re.IGNORECASE
)

def sniff_with_tcpdump(iface):
    """Run tcpdump and parse its line-based output. Returns True if started OK."""
    cmd = [
        "tcpdump",
        "-i", iface,
        "-n",               # No DNS resolution
        "-e",               # Print MAC addresses
        "-q",               # Quiet output
        "-l",               # Line-buffered
        "--immediate-mode",
        "ip",               # IPv4 only
    ]

    print(f"[device] Starting tcpdump backend on {iface} ...", flush=True)

    while not stop_event.is_set():
        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
            )
        except FileNotFoundError:
            print(
                "[device] tcpdump not found. Install: sudo apt install tcpdump",
                file=sys.stderr, flush=True
            )
            return False
        except Exception as exc:
            print(f"[device] tcpdump launch error: {exc}", file=sys.stderr, flush=True)
            return False

        print(f"[device] tcpdump running (PID {proc.pid})", flush=True)

        while not stop_event.is_set():
            line = proc.stdout.readline()
            if not line:
                if proc.poll() is not None:
                    print("[device] tcpdump exited unexpectedly, restarting in 5s...", flush=True)
                    break
                continue

            m = _TCPDUMP_LINE.search(line)
            if m:
                try:
                    src_port = int(m.group("src_port")) if m.group("src_port") else None
                    dst_port = int(m.group("dst_port")) if m.group("dst_port") else None
                    account_packet(
                        src_ip  = m.group("src_ip"),
                        dst_ip  = m.group("dst_ip"),
                        pkt_len = int(m.group("length")),
                        src_mac = m.group("src_mac"),
                        dst_mac = m.group("dst_mac"),
                        src_port = src_port,
                        dst_port = dst_port,
                    )
                except Exception:
                    pass

        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()

        if not stop_event.is_set():
            for _ in range(10):
                if stop_event.is_set():
                    break
                time.sleep(0.5)

    return True


# ──────────────────────────────────────────────────────────────────────────────
# Backend 2: Scapy (fallback)
# ──────────────────────────────────────────────────────────────────────────────
def sniff_with_scapy(iface):
    """Use Scapy for packet capture. Returns True if started OK."""
    try:
        from scapy.all import sniff as scapy_sniff, Ether, IP, TCP, UDP  # type: ignore
    except ImportError:
        print(
            "[device] Scapy not installed. Install: sudo apt install python3-scapy",
            file=sys.stderr, flush=True
        )
        return False

    print(f"[device] Starting Scapy backend on {iface} ...", flush=True)

    def handle_packet(pkt):
        if stop_event.is_set():
            return
        try:
            if IP in pkt:
                src_port = None
                dst_port = None
                if TCP in pkt:
                    src_port = pkt[TCP].sport
                    dst_port = pkt[TCP].dport
                elif UDP in pkt:
                    src_port = pkt[UDP].sport
                    dst_port = pkt[UDP].dport
                account_packet(
                    src_ip  = pkt[IP].src,
                    dst_ip  = pkt[IP].dst,
                    pkt_len = len(pkt),
                    src_mac = pkt[Ether].src if Ether in pkt else "",
                    dst_mac = pkt[Ether].dst if Ether in pkt else "",
                    src_port = src_port,
                    dst_port = dst_port,
                )
        except Exception:
            pass

    while not stop_event.is_set():
        try:
            scapy_sniff(
                iface=iface,
                prn=handle_packet,
                store=False,
                stop_filter=lambda _: stop_event.is_set(),
                timeout=10,
                filter="ip",
            )
        except Exception as exc:
            if not stop_event.is_set():
                print(f"[device] Scapy error: {exc} – retrying in 5s...", flush=True)
                for _ in range(10):
                    if stop_event.is_set():
                        break
                    time.sleep(0.5)

    return True


# ──────────────────────────────────────────────────────────────────────────────
# ARP cache refresher
# ──────────────────────────────────────────────────────────────────────────────
def is_mac_shared(mac_address):
    if not mac_address or mac_address == "00:00:00:00:00:00":
        return False
    mac_lower = mac_address.lower().strip()
    count = 0
    try:
        with open("/proc/net/arp", "r") as f:
            for line in f.readlines()[1:]:
                parts = line.split()
                if len(parts) >= 4:
                    if parts[3].lower().strip() == mac_lower:
                        count += 1
                        if count > 1:
                            return True
    except Exception:
        pass
    return False

def refresh_arp_cache():
    """Parse /proc/net/arp and update MAC addresses in device_labels."""
    arp_table = {}
    try:
        with open("/proc/net/arp", "r") as f:
            for line in f.readlines()[1:]:
                parts = line.split()
                if len(parts) >= 4:
                    ip  = parts[0]
                    mac = parts[3]
                    if mac and mac != "00:00:00:00:00:00":
                        arp_table[ip] = normalize_mac(mac)
    except Exception:
        pass

    if not arp_table:
        return

    # Count occurrences to detect shared MACs
    mac_counts = {}
    for ip, mac in arp_table.items():
        if mac and mac != "00:00:00:00:00:00":
            mac_counts[mac] = mac_counts.get(mac, 0) + 1

    try:
        conn   = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        for ip, mac in arp_table.items():
            if mac and mac != "00:00:00:00:00:00":
                is_shared = mac_counts.get(mac, 0) > 1

                # If this IP is already mapped to an approved device,
                # and the current MAC is shared, do not overwrite the mapping
                # to prevent signing out the registered device.
                cursor.execute("""
                    SELECT d.approved FROM device_ips di
                    JOIN devices d ON di.device_id = d.id
                    WHERE di.ip_address = ?
                """, (ip,))
                existing_row = cursor.fetchone()
                if existing_row and existing_row[0] == 1 and is_shared:
                    continue

                cursor.execute("SELECT device_id FROM device_macs WHERE mac_address = ?", (mac,))
                d_row = cursor.fetchone()
                if d_row:
                    device_id = d_row[0]
                else:
                    cursor.execute("INSERT INTO devices (user_id, device_name, floor, device_type, approved) VALUES (NULL, 'Discovered Device', '', '', 0)")
                    device_id = cursor.lastrowid
                    cursor.execute("INSERT OR IGNORE INTO device_macs (mac_address, device_id) VALUES (?, ?)", (mac, device_id))
                
                cursor.execute("""
                INSERT INTO device_ips (ip_address, device_id, mac_address, last_seen)
                VALUES (?, ?, ?, datetime('now', 'localtime'))
                ON CONFLICT(ip_address) DO UPDATE SET
                    device_id = excluded.device_id,
                    mac_address = excluded.mac_address,
                    last_seen = excluded.last_seen;
                """, (ip, device_id, mac))
                
                if not is_shared:
                    cursor.execute("DELETE FROM device_ips WHERE mac_address = ? AND ip_address != ?", (mac, ip))
        conn.commit()
        conn.close()
    except Exception as exc:
        print(f"[device] ARP refresh DB error: {exc}", flush=True)


def arp_loop():
    while not stop_event.is_set():
        refresh_arp_cache()
        for _ in range(60):   # every ~30 s
            if stop_event.is_set():
                break
            time.sleep(0.5)


# ──────────────────────────────────────────────────────────────────────────────
# Interface auto-detection
# ──────────────────────────────────────────────────────────────────────────────
def detect_interface():
    try:
        result = subprocess.run(
            ["ip", "-o", "-4", "route", "show", "default"],
            capture_output=True, text=True
        )
        for line in result.stdout.strip().splitlines():
            parts = line.split()
            if "dev" in parts:
                return parts[parts.index("dev") + 1]
    except Exception:
        pass

    try:
        for iface in sorted(os.listdir("/sys/class/net")):
            if iface != "lo" and not iface.startswith("docker") and not iface.startswith("veth"):
                return iface
    except Exception:
        pass

    return "eth0"


# ──────────────────────────────────────────────────────────────────────────────
# Signal handling
# ──────────────────────────────────────────────────────────────────────────────
_iface_global = None

def signal_handler(signum, frame):
    print(f"\n[device] Signal {signum} received. Shutting down...", flush=True)
    stop_event.set()


# ──────────────────────────────────────────────────────────────────────────────
# Entry point
# ──────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="NetTrack Device Daemon – passive per-device traffic monitor"
    )
    parser.add_argument(
        "-i", "--interface", default=None,
        help="Network interface to sniff (default: auto-detect)"
    )
    parser.add_argument(
        "--db", default=DB_PATH,
        help=f"Path to SQLite database (default: {DB_PATH})"
    )
    parser.add_argument(
        "--no-promisc", action="store_true",
        help="Skip enabling promiscuous mode (testing only)"
    )
    args = parser.parse_args()

    if os.geteuid() != 0:
        print("[device] Error: must run as root (sudo).", file=sys.stderr, flush=True)
        sys.exit(1)

    iface   = args.interface or detect_interface()
    DB_PATH = args.db
    _iface_global = iface

    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGINT,  signal_handler)

    print(f"[device] NetTrack Device Daemon  |  interface: {iface}  |  db: {DB_PATH}", flush=True)

    init_db()

    if not args.no_promisc:
        enable_promisc(iface)

    # Background threads
    flush_thread = threading.Thread(target=flush_loop, daemon=True)
    flush_thread.start()

    arp_thread = threading.Thread(target=arp_loop, daemon=True)
    arp_thread.start()

    nat_thread = threading.Thread(target=update_nat_ports_loop, daemon=True)
    nat_thread.start()

    # Try tcpdump first, fall back to Scapy
    success = sniff_with_tcpdump(iface)
    if not success:
        success = sniff_with_scapy(iface)

    if not success:
        print("[device] No packet capture backend available. Exiting.", file=sys.stderr, flush=True)
        stop_event.set()
        sys.exit(1)

    flush_thread.join(timeout=5)
    arp_thread.join(timeout=5)
    nat_thread.join(timeout=5)

    flush_accumulator()

    if not args.no_promisc:
        disable_promisc(iface)

    print("[device] Daemon stopped.", flush=True)
