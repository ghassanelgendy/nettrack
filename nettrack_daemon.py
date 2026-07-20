#!/usr/bin/env python3
import subprocess
import os
import sys
import time
import sqlite3
import threading
import signal
import re

DB_DIR = "/var/lib/nettrack"
DB_PATH = os.path.join(DB_DIR, "nettrack.db")

# In-memory accumulator
# Structure: { hour_timestamp: { program: { 'sent': bytes, 'recv': bytes } } }
accumulator = {}
lock = threading.Lock()
stop_event = threading.Event()

def init_db():
    try:
        os.makedirs(DB_DIR, exist_ok=True)
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS hourly_usage (
            hour_timestamp INTEGER,
            program TEXT,
            sent_bytes INTEGER,
            received_bytes INTEGER,
            PRIMARY KEY (hour_timestamp, program)
        );
        """)
        conn.commit()
        conn.close()
        # Set permissions so any user can read the database
        os.chmod(DB_DIR, 0o755)
        os.chmod(DB_PATH, 0o644)
        print(f"Database initialized at {DB_PATH}", flush=True)
    except Exception as e:
        print(f"Error initializing database: {e}", file=sys.stderr, flush=True)
        sys.exit(1)

def get_hour_timestamp():
    now = time.time()
    return int(now - (now % 3600))

def flush_accumulator():
    global accumulator
    with lock:
        if not accumulator:
            return
        temp_acc = accumulator
        accumulator = {}
    
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        for hour_ts, programs in temp_acc.items():
            for program, bytes_data in programs.items():
                cursor.execute("""
                INSERT INTO hourly_usage (hour_timestamp, program, sent_bytes, received_bytes)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(hour_timestamp, program) DO UPDATE SET
                    sent_bytes = sent_bytes + excluded.sent_bytes,
                    received_bytes = received_bytes + excluded.received_bytes;
                """, (hour_ts, program, int(bytes_data['sent']), int(bytes_data['recv'])))
        conn.commit()
        conn.close()
        # Ensure database stays readable by everyone
        try:
            os.chmod(DB_PATH, 0o644)
        except:
            pass
    except Exception as e:
        print(f"Error flushing to DB: {e}", file=sys.stderr, flush=True)
        # Put back in accumulator
        with lock:
            for hour_ts, programs in temp_acc.items():
                if hour_ts not in accumulator:
                    accumulator[hour_ts] = {}
                for program, bytes_data in programs.items():
                    if program not in accumulator[hour_ts]:
                        accumulator[hour_ts][program] = {'sent': 0, 'recv': 0}
                    accumulator[hour_ts][program]['sent'] += bytes_data['sent']
                    accumulator[hour_ts][program]['recv'] += bytes_data['recv']

def flush_loop():
    while not stop_event.is_set():
        # sleep in small steps to notice stop_event early
        for _ in range(20):
            if stop_event.is_set():
                break
            time.sleep(0.5)
        flush_accumulator()
def is_docker_pid(pid):
    if not pid or pid == "0":
        return False
    try:
        cgroup_path = f"/proc/{pid}/cgroup"
        if os.path.exists(cgroup_path):
            with open(cgroup_path, "r") as f:
                content = f.read()
                if "docker" in content or "containerd" in content or "sandbox" in content:
                    return True
    except:
        pass
    return False

def is_docker_ip(prog_str):
    if not prog_str:
        return False
    ips = re.findall(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', prog_str)
    for ip in ips:
        parts = ip.split('.')
        if len(parts) == 4:
            try:
                first = int(parts[0])
                second = int(parts[1])
                if first == 172 and 16 <= second <= 31:
                    return True
            except ValueError:
                pass
    return False

def parse_nethogs():
    cmd = ["nethogs", "-a", "-t", "-C"]
    print("Starting nethogs trace process (all interfaces, TCP and UDP enabled)...", flush=True)
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, bufsize=1)
    except FileNotFoundError:
        print("Error: nethogs command not found. Please install nethogs (e.g. sudo apt install nethogs).", file=sys.stderr, flush=True)
        sys.exit(1)
    except Exception as e:
        print(f"Error starting nethogs: {e}", file=sys.stderr, flush=True)
        sys.exit(1)

    print("nethogs process started. Monitoring all interfaces...", flush=True)

    while not stop_event.is_set():
        line = proc.stdout.readline()
        if not line:
            if proc.poll() is not None:
                print("nethogs process terminated unexpectedly. Restarting in 5s...", file=sys.stderr, flush=True)
                for _ in range(10):
                    if stop_event.is_set():
                        break
                    time.sleep(0.5)
                if not stop_event.is_set():
                    try:
                        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, bufsize=1)
                        continue
                    except Exception as e:
                        print(f"Failed to restart nethogs: {e}", file=sys.stderr, flush=True)
                break
            continue
        
        line = line.strip()
        if not line or line.startswith("Refreshing:"):
            continue
        
        parts = line.split()
        if len(parts) < 3:
            continue
        
        prog_pid_uid = parts[0]
        try:
            sent_kb = float(parts[1])
            recv_kb = float(parts[2])
        except ValueError:
            continue
        
        # Parse program path, pid, uid
        subparts = prog_pid_uid.rsplit('/', 2)
        if len(subparts) == 3:
            program = subparts[0]
            pid = subparts[1]
        else:
            program = prog_pid_uid
            pid = None
        
        # Check if process is running inside Docker
        is_docker = pid and is_docker_pid(pid)
        
        # Normalize unknown programs, connection strings, or clean up paths
        if not program or program in ("unknown TCP", "unknown UDP") or pid == "0":
            if program and is_docker_ip(program):
                program = "[Docker] Container Traffic (Unmapped)"
            elif program and ("127.0.0.1" in program or "::1" in program or "localhost" in program):
                program = "Local Loopback / Unassociated"
            else:
                program = "System / Unknown"
        elif "-" in program and ":" in program:
            # Check for connection string format (e.g. IP:port-IP:port)
            if is_docker_ip(program):
                program = "[Docker] Container Traffic (Unmapped)"
            elif "127.0.0.1" in program or "::1" in program or "localhost" in program:
                program = "Local Loopback / Unassociated"
            else:
                program = "System / Unknown"

        # Apply Docker prefix and cleanup path if relevant
        if is_docker:
            if "docker/overlay2" in program:
                parts_path = program.split("/merged/")
                if len(parts_path) == 2:
                    program = f"[Docker] {parts_path[1]}"
                else:
                    program = f"[Docker] {os.path.basename(program)}"
            else:
                program = f"[Docker] {program}"
        
        # Simplify common programs for premium display
        if "chrome" in program.lower():
            if is_docker:
                program = "[Docker] Google Chrome"
            else:
                program = "Google Chrome"
        elif "firefox" in program.lower():
            if is_docker:
                program = "[Docker] Mozilla Firefox"
            else:
                program = "Mozilla Firefox"
        elif "tailscaled" in program.lower():
            program = "Tailscale VPN"

        if sent_kb == 0.0 and recv_kb == 0.0:
            continue
            
        sent_bytes = sent_kb * 1024
        recv_bytes = recv_kb * 1024
        
        hour_ts = get_hour_timestamp()
        
        with lock:
            if hour_ts not in accumulator:
                accumulator[hour_ts] = {}
            if program not in accumulator[hour_ts]:
                accumulator[hour_ts][program] = {'sent': 0.0, 'recv': 0.0}
            accumulator[hour_ts][program]['sent'] += sent_bytes
            accumulator[hour_ts][program]['recv'] += recv_bytes

    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()

def signal_handler(signum, frame):
    print(f"Received signal {signum}. Shutting down...", flush=True)
    stop_event.set()

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("Error: This daemon must be run as root (sudo) to access network sockets via nethogs.", file=sys.stderr, flush=True)
        sys.exit(1)
        
    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)
    
    init_db()
    
    # Start flushing thread
    flush_thread = threading.Thread(target=flush_loop)
    flush_thread.start()
    
    # Run main nethogs loop
    parse_nethogs()
    
    # Wait for flush thread to finish
    flush_thread.join()
    # Final flush
    flush_accumulator()
    print("Daemon stopped gracefully.", flush=True)
