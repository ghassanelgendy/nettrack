# NetTrack

A lightweight, zero-dependency network traffic logging and historical analysis tool for Linux. It runs as a system daemon, monitoring per-process and per-service network utilization using `nethogs`, stores statistics hourly in a local SQLite database, and provides a beautiful terminal-based ASCII dashboard as well as an embedded web dashboard.

## Features
- 📊 **CLI Dashboard:** Real-time summary of today, week, or month network usage with ASCII bar charts showing traffic trends.
- 🐳 **App/Service Breakdown:** List of processes sorted by bandwidth consumption (Download, Upload, and Total).
- 🌐 **Embedded Web UI:** Run a local lightweight web server with charts (via Chart.js) and tables, with auto-refresh (no external server required, 100% zero-dependency).
- ⚙️ **Systemd Daemon Integration:** Automatically logs traffic in the background on startup, using negligible resources.

## Installation
Run the installer with root privileges:
```bash
cd /home/ghesso/nettrack
sudo ./install.sh
```

The installer will:
1. Ensure `nethogs` is installed on your machine.
2. Initialize the SQLite database under `/var/lib/nettrack/nettrack.db` (readable by everyone, writeable by root).
3. Set up the `nettrack` system daemon service.
4. Install the `nettrack` global CLI command in `/usr/local/bin/`.

## CLI Usage

View today's traffic:
```bash
nettrack
```

View weekly usage (last 7 days):
```bash
nettrack --week
```

View monthly usage (last 30 days):
```bash
nettrack --month
```

### Embedded Web Server Dashboard
Start a local web server to visualize statistics in your browser:
```bash
nettrack --web [port]
```
*(Default port is `8080` if not specified. Access it at `http://localhost:8080`)*

## Service Management

Check tracking status:
```bash
systemctl status nettrack.service
```

Stop tracking:
```bash
sudo systemctl stop nettrack.service
```

Start tracking:
```bash
sudo systemctl start nettrack.service
```

View logs:
```bash
sudo journalctl -u nettrack.service
```
