#!/usr/bin/env python3
import os
import sys
import time
import sqlite3
import subprocess
import threading

DB_PATH = "/var/lib/nettrack/nettrack.db"
# { process_name: { 'sent': 0, 'received': 0 } }
stats_accumulator = {}
lock = threading.Lock()

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
            
            for process, bytes_data in to_flush.items():
                sent = bytes_data['sent']
                recv = bytes_data['received']
                
                # Check if entry exists
                cursor.execute("""
                SELECT sent_bytes, received_bytes FROM hourly_usage
                WHERE process_name = ? AND timestamp = ?;
                """, (process, hour_ts))
                row = cursor.fetchone()
                
                if row:
                    new_sent = row[0] + sent
                    new_recv = row[1] + recv
                    cursor.execute("""
                    UPDATE hourly_usage
                    SET sent_bytes = ?, received_bytes = ?
                    WHERE process_name = ? AND timestamp = ?;
                    """, (new_sent, new_recv, process, hour_ts))
                else:
                    cursor.execute("""
                    INSERT INTO hourly_usage (process_name, timestamp, sent_bytes, received_bytes)
                    VALUES (?, ?, ?, ?);
                    """, (process, hour_ts, sent, recv))
            
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"[daemon] Error flushing stats: {e}", file=sys.stderr, flush=True)

def parse_nethogs():
    print("[daemon] Starting nethogs process traffic monitoring...", flush=True)
    # Run nethogs in trace mode (-t) on all interfaces (-a)
    cmd = ["nethogs", "-a", "-t", "-c", "999999"]
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
    
    try:
        for line in proc.stdout:
            # Lines look like:
            # PROGRAM/PID/UID   SENT_KB/s   RECV_KB/s
            # e.g., /usr/bin/python3/12345/1000   1.2   4.5
            parts = line.strip().split()
            if len(parts) < 3:
                continue
            
            prog_path = parts[0]
            if "/" not in prog_path or prog_path.startswith("Refreshing"):
                continue
                
            try:
                # Extract program name/path (ignoring PID and UID at the end)
                # Format is typically: path/PID/UID
                subparts = prog_path.split('/')
                if len(subparts) >= 3:
                    # Reconstruct path and get binary name
                    bin_path = "/".join(subparts[:-2])
                    prog_name = os.path.basename(bin_path) or bin_path
                else:
                    prog_name = prog_path
                
                # Nethogs outputs KB/s. Convert to bytes (assuming 1s interval)
                sent_bytes = int(float(parts[1]) * 1024)
                recv_bytes = int(float(parts[2]) * 1024)
                
                if sent_bytes > 0 or recv_bytes > 0:
                    with lock:
                        if prog_name not in stats_accumulator:
                            stats_accumulator[prog_name] = {'sent': 0, 'received': 0}
                        stats_accumulator[prog_name]['sent'] += sent_bytes
                        stats_accumulator[prog_name]['received'] += recv_bytes
            except Exception:
                continue
    except KeyboardInterrupt:
        pass
    finally:
        proc.terminate()

def main():
    # Apply dnsmasq ignore rule for server MAC to prevent routing loop
    try:
        import subprocess
        # Get primary interface
        res = subprocess.run("ip -o -4 route show default | awk '{for(i=1;i<=NF;i++) if($i==\"dev\") print $(i+1)}'", shell=True, capture_output=True, text=True)
        iface = res.stdout.strip() or "eno1"
        with open(f"/sys/class/net/{iface}/address", "r") as f:
            mac = f.read().strip()
        
        dnsmasq_conf_path = "/etc/dnsmasq.conf"
        if os.path.exists(dnsmasq_conf_path):
            with open(dnsmasq_conf_path, "r") as f:
                content = f.read()
            ignore_line = f"dhcp-host={mac},ignore"
            if ignore_line not in content:
                lines = [line for line in content.splitlines() if not (line.startswith("dhcp-host=") and line.endswith(",ignore"))]
                lines.append(ignore_line)
                with open(dnsmasq_conf_path, "w") as f:
                    f.write("\n".join(lines) + "\n")
                subprocess.run("systemctl restart dnsmasq", shell=True)
                print(f"[daemon] Applied dnsmasq ignore line for {mac} and restarted dnsmasq.", flush=True)
    except Exception as e:
        print(f"[daemon] Error applying dnsmasq fix: {e}", flush=True)

    # Make sure DB exists
    if not os.path.exists(DB_PATH):
        import init_db
        init_db.init_database()
        
    # Run stats flush thread
    threading.Thread(target=flush_stats, daemon=True).start()
    
    # Parse nethogs
    parse_nethogs()

if __name__ == "__main__":
    main()
