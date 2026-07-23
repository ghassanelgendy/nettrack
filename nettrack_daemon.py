#!/usr/bin/env python3
import subprocess
import os
import sys
import time
import sqlite3
import threading
import signal
import re
import glob

DB_DIR = "/var/lib/nettrack"
DB_PATH = os.path.join(DB_DIR, "nettrack.db")

# In-memory accumulator
# Structure: { hour_timestamp: { program: { 'sent': bytes, 'recv': bytes } } }
accumulator = {}
lock = threading.Lock()
stop_event = threading.Event()

# Thread-safe global variables for docker and socket mapping
global_socket_map = {}
containers_cache = {}
pid_name_cache = {}

# Store last seen bytes for each veth interface
# Structure: { interface_name: (rx_bytes, tx_bytes) }
veth_last_bytes = {}
# Map container_id -> veth interface name
container_veth_map = {}

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
        # Set permissions so any user can read/write the database
        os.chmod(DB_DIR, 0o777)
        os.chmod(DB_PATH, 0o666)
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
            os.chmod(DB_PATH, 0o666)
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

# --- Docker & Socket Mapping Helpers ---

def refresh_containers_cache():
    global containers_cache
    try:
        res = subprocess.run(["docker", "ps", "--no-trunc", "--format", "{{.ID}}\t{{.Names}}"], capture_output=True, text=True)
        if res.returncode == 0:
            new_cache = {}
            for line in res.stdout.strip().split("\n"):
                if not line:
                    continue
                parts = line.split("\t")
                if len(parts) == 2:
                    new_cache[parts[0]] = parts[1]
            containers_cache = new_cache
    except Exception as e:
        print(f"Error refreshing containers cache: {e}", flush=True)

def get_container_info_for_pid(pid):
    try:
        with open(f"/proc/{pid}/cgroup", "r") as f:
            content = f.read()
        match = re.search(r'\b([0-9a-f]{64})\b', content)
        if match:
            return match.group(1)
    except:
        pass
    return None

def get_container_veth(pid):
    try:
        iflink_path = f"/proc/{pid}/root/sys/class/net/eth0/iflink"
        if not os.path.exists(iflink_path):
            net_path = f"/proc/{pid}/root/sys/class/net"
            if os.path.exists(net_path):
                for iface in os.listdir(net_path):
                    if iface != "lo":
                        iflink_path = f"/proc/{pid}/root/sys/class/net/{iface}/iflink"
                        break
        
        if os.path.exists(iflink_path):
            with open(iflink_path, "r") as f:
                iflink = f.read().strip()
                
            for host_iface in os.listdir("/sys/class/net"):
                host_ifindex_path = f"/sys/class/net/{host_iface}/ifindex"
                if os.path.exists(host_ifindex_path):
                    with open(host_ifindex_path, "r") as f_host:
                        ifindex = f_host.read().strip()
                        if ifindex == iflink:
                            return host_iface
    except Exception:
        pass
    return None

def get_veth_for_container(container_id):
    if container_id in container_veth_map:
        veth = container_veth_map[container_id]
        if os.path.exists(f"/sys/class/net/{veth}"):
            return veth
            
    try:
        res = subprocess.run(["docker", "inspect", "--format", "{{.State.Pid}}", container_id], capture_output=True, text=True)
        if res.returncode == 0:
            pid = res.stdout.strip()
            if pid and pid != "0":
                veth = get_container_veth(pid)
                if veth:
                    container_veth_map[container_id] = veth
                    return veth
    except:
        pass
    return None

def build_socket_map():
    # Maps inode (int) -> program name (str)
    inode_to_prog = {}
    
    for pid_dir in glob.glob("/proc/[0-9]*"):
        pid = os.path.basename(pid_dir)
        try:
            exe_path = os.readlink(f"{pid_dir}/exe")
            prog_name = os.path.basename(exe_path)
            
            with open(f"{pid_dir}/cmdline", "r") as f:
                cmd_content = f.read().split("\x00")
            cmd_line_str = " ".join(cmd_content)
            
            # Check if process is in Docker
            container_id = get_container_info_for_pid(pid)
            if container_id:
                container_name = containers_cache.get(container_id, container_id[:12])
                veth = get_veth_for_container(container_id)
                if veth:
                    # Bridge networking container: track via veth polling, ignore in nethogs
                    prog_name = "__DOCKER__"
                else:
                    # Host networking container: track under container name
                    prog_name = f"[Docker] {container_name}"
            else:
                # Script/program normalization
                if prog_name.startswith("python"):
                    if len(cmd_content) > 1 and cmd_content[1].endswith(".py"):
                        prog_name = os.path.basename(cmd_content[1])
                
                # Premium name mappings
                if "chrome" in prog_name.lower():
                    if "google-chrome-ytv" in cmd_line_str or "youtube.com/tv" in cmd_line_str:
                        prog_name = "YouTube Wrapped"
                    else:
                        prog_name = "Google Chrome"
                elif "firefox" in prog_name.lower():
                    prog_name = "Mozilla Firefox"
                elif "tailscaled" in prog_name.lower():
                    prog_name = "Tailscale VPN"
            
            fd_dir = f"{pid_dir}/fd"
            if os.path.exists(fd_dir):
                for fd in os.listdir(fd_dir):
                    try:
                        link = os.readlink(os.path.join(fd_dir, fd))
                        if link.startswith("socket:["):
                            inode = int(link[8:-1])
                            inode_to_prog[inode] = prog_name
                    except:
                        pass
        except:
            pass
            
    # Read /proc/net/tcp, tcp6, udp, udp6
    port_to_prog = {}
    
    def parse_proc_net(filename):
        if not os.path.exists(filename):
            return
        try:
            with open(filename, "r") as f:
                lines = f.readlines()
            for line in lines[1:]:
                parts = line.strip().split()
                if len(parts) >= 10:
                    local_addr = parts[1]
                    inode = int(parts[9])
                    
                    local_port_hex = local_addr.split(":")[1]
                    local_port = int(local_port_hex, 16)
                    
                    if inode in inode_to_prog:
                        port_to_prog[local_port] = inode_to_prog[inode]
        except Exception:
            pass

    parse_proc_net("/proc/net/tcp")
    parse_proc_net("/proc/net/tcp6")
    parse_proc_net("/proc/net/udp")
    parse_proc_net("/proc/net/udp6")
    
    return port_to_prog

def get_program_name_by_pid(pid):
    global pid_name_cache
    if pid in pid_name_cache:
        return pid_name_cache[pid]
    try:
        exe_path = os.readlink(f"/proc/{pid}/exe")
        prog_name = os.path.basename(exe_path)
        
        with open(f"/proc/{pid}/cmdline", "r") as f:
            cmd = f.read().split("\x00")
        cmd_line_str = " ".join(cmd)
        
        container_id = get_container_info_for_pid(pid)
        if container_id:
            container_name = containers_cache.get(container_id, container_id[:12])
            veth = get_veth_for_container(container_id)
            if veth:
                prog_name = "__DOCKER__"
            else:
                prog_name = f"[Docker] {container_name}"
        else:
            if prog_name.startswith("python"):
                if len(cmd) > 1 and cmd[1].endswith(".py"):
                    prog_name = os.path.basename(cmd[1])
            
            if "chrome" in prog_name.lower():
                if "google-chrome-ytv" in cmd_line_str or "youtube.com/tv" in cmd_line_str:
                    prog_name = "YouTube Wrapped"
                else:
                    prog_name = "Google Chrome"
            elif "firefox" in prog_name.lower():
                prog_name = "Mozilla Firefox"
            elif "tailscaled" in prog_name.lower():
                prog_name = "Tailscale VPN"
                
        pid_name_cache[pid] = prog_name
        return prog_name
    except:
        pass
    return None

def resolve_program_from_ports(prog_str, port_map):
    try:
        parts = prog_str.split("-")
        if len(parts) == 2:
            port1 = int(parts[0].split(":")[-1])
            port2 = int(parts[1].split(":")[-1])
            if port1 in port_map:
                return port_map[port1]
            if port2 in port_map:
                return port_map[port2]
    except:
        pass
    return None

# --- Background Task Loops ---

def socket_map_loop():
    global global_socket_map, pid_name_cache
    while not stop_event.is_set():
        refresh_containers_cache()
        global_socket_map = build_socket_map()
        # Clear PID cache periodically to reflect PID reuse/updates
        pid_name_cache.clear()
        
        # Sleep in small steps
        for _ in range(10):
            if stop_event.is_set():
                break
            time.sleep(0.5)

def docker_traffic_loop():
    global veth_last_bytes
    while not stop_event.is_set():
        iface_bytes = {}
        try:
            if os.path.exists("/proc/net/dev"):
                with open("/proc/net/dev", "r") as f:
                    lines = f.readlines()
                for line in lines[2:]:
                    parts = line.strip().split()
                    if len(parts) >= 10:
                        iface = parts[0].rstrip(":")
                        rx = int(parts[1])
                        tx = int(parts[9])
                        iface_bytes[iface] = (rx, tx)
        except Exception as e:
            print(f"Error reading /proc/net/dev in thread: {e}", flush=True)
            
        hour_ts = get_hour_timestamp()
        
        for container_id, container_name in list(containers_cache.items()):
            veth = get_veth_for_container(container_id)
            if veth and veth in iface_bytes:
                rx, tx = iface_bytes[veth]
                
                if veth in veth_last_bytes:
                    last_rx, last_tx = veth_last_bytes[veth]
                    if rx >= last_rx and tx >= last_tx:
                        delta_rx = rx - last_rx
                        delta_tx = tx - last_tx
                        
                        if delta_rx > 0 or delta_tx > 0:
                            prog_name = f"[Docker] {container_name}"
                            with lock:
                                if hour_ts not in accumulator:
                                    accumulator[hour_ts] = {}
                                if prog_name not in accumulator[hour_ts]:
                                    accumulator[hour_ts][prog_name] = {'sent': 0.0, 'recv': 0.0}
                                # rx is sent by container (upload), tx is received by container (download)
                                accumulator[hour_ts][prog_name]['sent'] += delta_rx
                                accumulator[hour_ts][prog_name]['recv'] += delta_tx
                                
                veth_last_bytes[veth] = (rx, tx)
                
        # Sleep in small steps
        for _ in range(4):
            if stop_event.is_set():
                break
            time.sleep(0.5)

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

# --- Main Nethogs Loop ---

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
        
        # Resolve program name via port map or pid lookup
        resolved = None
        if "-" in program and ":" in program:
            resolved = resolve_program_from_ports(program, global_socket_map)
            
        if not resolved and pid and pid != "0":
            resolved = get_program_name_by_pid(pid)
            
        # Ignore bridge container traffic (handled by docker_traffic_loop)
        if resolved == "__DOCKER__":
            continue
            
        if resolved:
            program = resolved
        else:
            # Fallback normalizations
            if not program or program in ("unknown TCP", "unknown UDP") or pid == "0":
                if program and is_docker_ip(program):
                    continue # Ignore container traffic
                elif program and ("127.0.0.1" in program or "::1" in program or "localhost" in program):
                    program = "Local Loopback / Unassociated"
                else:
                    program = "System / Unknown"
            elif "-" in program and ":" in program:
                if is_docker_ip(program):
                    continue # Ignore container traffic
                elif "127.0.0.1" in program or "::1" in program or "localhost" in program:
                    program = "Local Loopback / Unassociated"
                else:
                    program = "System / Unknown"
            else:
                program = os.path.basename(program)
                
            # Secondary check for common programs
            if "chrome" in program.lower():
                program = "Google Chrome"
            elif "firefox" in program.lower():
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
        print("Error: This daemon must be run as root (sudo) to access network sockets.", file=sys.stderr, flush=True)
        sys.exit(1)
        
    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)
    
    init_db()
    
    # Initialize container cache once before starting threads
    refresh_containers_cache()
    global_socket_map = build_socket_map()
    
    # Start thread for mapping socket changes
    map_thread = threading.Thread(target=socket_map_loop)
    map_thread.start()
    
    # Start thread for polling docker veth traffic
    docker_thread = threading.Thread(target=docker_traffic_loop)
    docker_thread.start()
    
    # Start flushing thread
    flush_thread = threading.Thread(target=flush_loop)
    flush_thread.start()
    
    # Run main nethogs loop
    parse_nethogs()
    
    # Wait for background threads to finish
    map_thread.join()
    docker_thread.join()
    flush_thread.join()
    
    # Final flush
    flush_accumulator()
    print("Daemon stopped gracefully.", flush=True)
