# NetTrack

A lightweight, zero-dependency network traffic monitoring tool for Linux.  
It runs as **two system daemons**, stores statistics hourly in a local SQLite database, and provides both a terminal CLI dashboard and an embedded web dashboard.

## Features

- 📊 **CLI Dashboard** – Real-time summary of today / week / month network usage with ASCII bar charts.
- 🐳 **App/Service Breakdown** – Processes sorted by bandwidth (Download, Upload, Total).
- 📡 **Per-Device Monitoring** – Passive sniffer using promiscuous mode captures traffic from every device on your LAN (phones, APs, laptops, TVs) — **no extra hardware, no network impact**.
- 🏷️ **Device Labelling** – Assign friendly names, floor/location tags, and device-type icons to each IP/MAC directly from the web dashboard.
- 🌐 **Embedded Web UI** – Two-tab dashboard (Applications + Devices) with Chart.js, auto-refresh, and a glassmorphism design. No external server required.
- ⚙️ **Systemd Daemon Integration** – Two auto-starting services:
  - `nettrack.service` — per-process monitoring via `nethogs`
  - `nettrack-device.service` — passive per-device sniffer via `tcpdump`

## Requirements

| Tool | Purpose |
|------|---------|
| `nethogs` | Per-process bandwidth tracking |
| `tcpdump` | Per-device passive packet capture (or `python3-scapy` as fallback) |

The installer handles both automatically.

## Installation

Run the installer with root privileges:

```bash
cd /home/ghesso/nettrack
sudo ./install.sh
```

The installer will:
1. Install `nethogs` and `tcpdump` if not present.
2. Auto-detect your primary network interface (e.g. `eth0`, `enp3s0`).
3. Create `/var/lib/nettrack/nettrack.db` (SQLite, world-readable).
4. Set up **two** systemd services:
   - `nettrack.service` (per-process via nethogs)
   - `nettrack-device.service` (per-device, promiscuous mode via tcpdump)
5. Install the `nettrack` global CLI command.

## CLI Usage

```bash
nettrack            # Today's per-process stats (live mode)
nettrack --week     # Last 7 days
nettrack --month    # Last 30 days
nettrack --once     # Print once and exit (good for scripts)
```

### Web Dashboard

```bash
nettrack --web [port]   # Default port: 6054
```

Open `http://localhost:6054` (or your server's IP from another device).

**Dashboard tabs:**
- **📊 Applications** – per-process usage + trend chart with Today/Week/Month filters
- **📡 Devices** – per-device table with IP, MAC, sent/received bytes, last seen, and a **Label** button

### Labelling Devices

1. Open the web dashboard → click the **Devices** tab.
2. Click the **✏ Label** button next to any discovered device.
3. Enter a friendly name (e.g. *"5th Floor AP"*, *"Phone"*, *"Server Local"*), floor/location, and device type.
4. Click **Save Label** — the dashboard updates immediately.

Labels persist across reboots in the `device_labels` SQLite table.

## How Per-Device Monitoring Works

The device daemon (`nettrack_device_daemon.py`):

1. **Enables promiscuous mode** on your Ethernet interface via `ip link set <iface> promisc on` — your server's NIC will now receive all frames on the segment, not just its own.
2. **Runs `tcpdump`** as a subprocess with `-e` (MAC addresses) to passively parse IPv4 packets — zero impact on network throughput.
3. **Accounts only private LAN IPs** (`10.x`, `172.16-31.x`, `192.168.x`) and ignores multicast/broadcast.
4. **Refreshes the ARP cache** from `/proc/net/arp` every 30 s to keep MAC → IP mappings current.
5. **Flushes to SQLite** every 10 s with upsert logic — no data loss on restart.

> **Note:** Promiscuous mode only captures traffic that reaches your server's network segment. In a switched network, you'll see broadcast traffic and traffic to/from your server, but not traffic between two other devices on the same switch unless the switch mirrors the port or you're on a hub/Wi-Fi AP. For full visibility you would typically connect the server to a router/AP's monitoring port or use a managed switch with port mirroring.

## Service Management

```bash
# Per-process daemon
systemctl status  nettrack.service
sudo systemctl start/stop/restart nettrack.service

# Per-device sniffer
systemctl status  nettrack-device.service
sudo systemctl start/stop/restart nettrack-device.service

# Logs
sudo journalctl -u nettrack.service -f
sudo journalctl -u nettrack-device.service -f
```

## Database

SQLite at `/var/lib/nettrack/nettrack.db`, readable by all users.

| Table | Description |
|-------|-------------|
| `hourly_usage` | Per-process bytes per hour |
| `device_usage` | Per-device (IP/MAC) bytes per hour |
| `device_labels` | Friendly names, floor, device type per IP |
