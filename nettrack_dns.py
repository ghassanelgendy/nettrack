#!/usr/bin/env python3
"""
NetTrack DNS Proxy Firewall
===========================
Intercepts local network DNS requests (redirected to port 6053),
logs visited domains, blocks blacklisted domains with NXDOMAIN response,
and forwards allowed requests to upstream DNS (1.1.1.1 / 8.8.8.8).
"""

import socket
import sys
import os
import sqlite3
import time
import threading

DB_DIR  = "/var/lib/nettrack"
DB_PATH = os.path.join(DB_DIR, "nettrack.db")
UPSTREAM_DNS = "1.1.1.1"
LISTEN_PORT = 6053

# Thread-safe in-memory cache of blacklist
blacklist_cache = set()
blacklist_lock = threading.Lock()

def init_db():
    try:
        os.makedirs(DB_DIR, exist_ok=True)
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # Blacklist table
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS dns_blacklist (
            domain TEXT PRIMARY KEY
        );
        """)
        
        # Logs table
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS dns_logs (
            timestamp INTEGER,
            ip_address TEXT,
            domain TEXT,
            status TEXT
        );
        """)
        
        # Create an index for performance
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_dns_logs_ts ON dns_logs(timestamp);")
        
        # Populate default DNS-over-HTTPS (DoH) domains to force browsers to fallback to standard UDP DNS
        doh_domains = [
            "chrome.cloudflare-dns.com",
            "cloudflare-dns.com",
            "dns.google",
            "dns.quad9.net",
            "doh.opendns.com",
            "doh.cleanbrowsing.org"
        ]
        for domain in doh_domains:
            cursor.execute("INSERT OR IGNORE INTO dns_blacklist (domain) VALUES (?)", (domain,))
            
        conn.commit()
        conn.close()
    except Exception as exc:
        print(f"[dns] DB init error: {exc}", file=sys.stderr, flush=True)

def load_blacklist():
    global blacklist_cache
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT domain FROM dns_blacklist;")
        domains = {row[0].strip().lower() for row in cursor.fetchall()}
        conn.close()
        with blacklist_lock:
            blacklist_cache = domains
    except Exception as exc:
        print(f"[dns] Load blacklist error: {exc}", file=sys.stderr, flush=True)

def check_blacklist_loop():
    # Reload blacklist from database every 5 seconds to get updates from Web UI
    while True:
        load_blacklist()
        time.sleep(5)

def log_dns_query(ip, domain, status):
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO dns_logs (timestamp, ip_address, domain, status) VALUES (?, ?, ?, ?)",
            (int(time.time()), ip, domain, status)
        )
        conn.commit()
        conn.close()
    except Exception as exc:
        print(f"[dns] Log query error: {exc}", file=sys.stderr, flush=True)

def decode_dns_name(data):
    # DNS header is 12 bytes, QNAME starts at byte 12
    try:
        parts = []
        offset = 12
        while True:
            length = data[offset]
            if length == 0:
                break
            parts.append(data[offset+1 : offset+1+length].decode('utf-8', errors='ignore'))
            offset += 1 + length
        return ".".join(parts).lower().strip(), offset
    except Exception:
        return None, 12

def is_blacklisted(domain):
    with blacklist_lock:
        # Check if the domain contains any of the blacklisted keywords/phrases
        for item in blacklist_cache:
            if item in domain:
                return True
    return False

def make_nxdomain_response(query_data):
    if len(query_data) < 12:
        return None
    # Copy transaction ID
    tx_id = query_data[0:2]
    # Standard query response, recursion available, Name error (NXDOMAIN) -> 0x8183
    flags = b'\x81\x83'
    # Questions count (usually 1)
    qd_count = query_data[4:6]
    # Answer count, Authority count, Additional count all 0
    counts = b'\x00\x00\x00\x00\x00\x00'
    
    # Locate end of Question Section to copy it
    offset = 12
    while offset < len(query_data):
        length = query_data[offset]
        if length == 0:
            offset += 5 # Skip 0 byte, QTYPE (2B) and QCLASS (2B)
            break
        offset += 1 + length
    question_section = query_data[12:offset]
    return tx_id + flags + qd_count + counts + question_section

def handle_client(sock, client_addr, query_data):
    domain, qname_end = decode_dns_name(query_data)
    if not domain:
        return
        
    ip = client_addr[0]
    
    # Block AAAA (IPv6) queries: return NODATA (No Error, 0 Answers) to force client to fall back to IPv4 (A) immediately
    try:
        qtype = query_data[qname_end+1 : qname_end+3]
        if qtype == b'\x00\x1c': # 28 is AAAA
            tx_id = query_data[0:2]
            flags = b'\x81\x80' # Response, No Error
            qd_count = query_data[4:6]
            counts = b'\x00\x00\x00\x00\x00\x00' # 0 Answers
            question_section = query_data[12 : qname_end+5]
            response = tx_id + flags + qd_count + counts + question_section
            sock.sendto(response, client_addr)
            return
    except Exception:
        pass
    
    if is_blacklisted(domain):
        # Block: Send NXDOMAIN response
        response = make_nxdomain_response(query_data)
        if response:
            sock.sendto(response, client_addr)
            log_dns_query(ip, domain, "Blocked")
    else:
        # Forward to upstream DNS server
        try:
            up_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            up_sock.settimeout(2.0)
            up_sock.sendto(query_data, (UPSTREAM_DNS, 53))
            resp_data, _ = up_sock.recvfrom(2048)
            up_sock.close()
            sock.sendto(resp_data, client_addr)
            log_dns_query(ip, domain, "Allowed")
        except socket.timeout:
            # Fallback to secondary DNS (8.8.8.8) on timeout
            try:
                up_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                up_sock.settimeout(2.0)
                up_sock.sendto(query_data, ("8.8.8.8", 53))
                resp_data, _ = up_sock.recvfrom(2048)
                up_sock.close()
                sock.sendto(resp_data, client_addr)
                log_dns_query(ip, domain, "Allowed")
            except Exception:
                pass
        except Exception:
            pass

def main():
    init_db()
    load_blacklist()
    
    # Thread to reload blacklist periodically
    threading.Thread(target=check_blacklist_loop, daemon=True).start()
    
    # Bind DNS UDP server
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        server_sock.bind(('0.0.0.0', LISTEN_PORT))
        print(f"[dns] DNS Proxy Firewall listening on UDP port {LISTEN_PORT}...", flush=True)
    except Exception as exc:
        print(f"[dns] Bind error on port {LISTEN_PORT}: {exc}", file=sys.stderr, flush=True)
        sys.exit(1)
        
    while True:
        try:
            data, addr = server_sock.recvfrom(2048)
            # Handle query in thread to avoid blocking main socket loop
            threading.Thread(target=handle_client, args=(server_sock, addr, data), daemon=True).start()
        except Exception as exc:
            pass

if __name__ == "__main__":
    main()
