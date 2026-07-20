#!/usr/bin/env python3
import os
import sys
import sqlite3
import datetime
import argparse
import json
from http.server import BaseHTTPRequestHandler, HTTPServer
import urllib.parse

DB_PATH = "/var/lib/nettrack/nettrack.db"

def format_bytes(n):
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if n < 1024:
            return f"{n:.2f} {unit}"
        n /= 1024
    return f"{n:.2f} PB"

def check_db():
    if not os.path.exists(DB_PATH):
        print(f"Error: Database file not found at {DB_PATH}.", file=sys.stderr)
        print("Please make sure the nettrack daemon is running.", file=sys.stderr)
        sys.exit(1)

def get_stats(since_ts):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Total sent / received
    cursor.execute("""
    SELECT SUM(sent_bytes), SUM(received_bytes) 
    FROM hourly_usage 
    WHERE hour_timestamp >= ?
    """, (since_ts,))
    totals = cursor.fetchone()
    total_sent = totals[0] or 0
    total_recv = totals[1] or 0
    
    # Process breakdown
    cursor.execute("""
    SELECT program, SUM(sent_bytes) as sent, SUM(received_bytes) as recv, SUM(sent_bytes + received_bytes) as total
    FROM hourly_usage
    WHERE hour_timestamp >= ?
    GROUP BY program
    ORDER BY total DESC
    """, (since_ts,))
    programs = cursor.fetchall()
    
    conn.close()
    return total_sent, total_recv, programs

def get_today():
    local_today = datetime.datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
    start_ts = int(local_today.timestamp())
    
    total_sent, total_recv, programs = get_stats(start_ts)
    
    # Hourly trend
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
    SELECT hour_timestamp, SUM(sent_bytes + received_bytes)
    FROM hourly_usage
    WHERE hour_timestamp >= ?
    GROUP BY hour_timestamp
    ORDER BY hour_timestamp ASC
    """, (start_ts,))
    trend = cursor.fetchall()
    conn.close()
    
    return total_sent, total_recv, programs, trend, "Today"

def get_week():
    local_start = (datetime.datetime.now() - datetime.timedelta(days=6)).replace(hour=0, minute=0, second=0, microsecond=0)
    start_ts = int(local_start.timestamp())
    
    total_sent, total_recv, programs = get_stats(start_ts)
    
    # Daily trend in local time
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
    SELECT strftime('%Y-%m-%d', datetime(hour_timestamp, 'unixepoch', 'localtime')) as day,
           SUM(sent_bytes + received_bytes)
    FROM hourly_usage
    WHERE hour_timestamp >= ?
    GROUP BY day
    ORDER BY day ASC
    """, (start_ts,))
    trend = cursor.fetchall()
    conn.close()
    
    return total_sent, total_recv, programs, trend, "Last 7 Days"

def get_month():
    local_start = (datetime.datetime.now() - datetime.timedelta(days=29)).replace(hour=0, minute=0, second=0, microsecond=0)
    start_ts = int(local_start.timestamp())
    
    total_sent, total_recv, programs = get_stats(start_ts)
    
    # Daily trend in local time
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
    SELECT strftime('%Y-%m-%d', datetime(hour_timestamp, 'unixepoch', 'localtime')) as day,
           SUM(sent_bytes + received_bytes)
    FROM hourly_usage
    WHERE hour_timestamp >= ?
    GROUP BY day
    ORDER BY day ASC
    """, (start_ts,))
    trend = cursor.fetchall()
    conn.close()
    
    return total_sent, total_recv, programs, trend, "Last 30 Days"

def get_term_size():
    import shutil
    try:
        cols, lines = shutil.get_terminal_size()
        return cols, lines
    except Exception:
        return 80, 24

def compute_layout(lines, trend_len, apps_len, is_live):
    if not is_live:
        return min(trend_len, 24), min(apps_len, 20)
        
    if lines < 12:
        return 0, 0
        
    # Standard terminal height adaptive routing
    if lines < 20:
        app_rows = max(0, lines - 13)
        return 0, app_rows
        
    available = lines - 18
    if available < 6:
        app_rows = max(0, lines - 13)
        return 0, app_rows
        
    chart_rows = min(trend_len, 5)
    app_rows = available - chart_rows
    
    if app_rows > 10:
        extra_chart = min(trend_len - chart_rows, 5)
        if extra_chart > 0:
            chart_rows += extra_chart
            app_rows = available - chart_rows
            
    if app_rows < 3:
        needed = 3 - app_rows
        shrinkable = chart_rows - 3
        if shrinkable >= needed:
            chart_rows -= needed
            app_rows += needed
        else:
            app_rows = max(0, lines - 13)
            chart_rows = 0
            
    return chart_rows, max(0, app_rows)

def draw_chart_responsive(trend, period_type, width):
    if not trend:
        return
    labels = []
    values = []
    for row in trend:
        if period_type == "Today":
            dt = datetime.datetime.fromtimestamp(row[0])
            labels.append(dt.strftime("%H:00"))
        else:
            labels.append(row[0])
        values.append(row[1])
        
    max_val = max(values) if values else 0
    if max_val == 0:
        max_val = 1
        
    print("-" * width)
    print("TRAFFIC TREND CHART".center(width))
    print("-" * width)
    
    max_bar_width = max(5, width - 26)
    for label, val in zip(labels, values):
        bar_len = int((val / max_val) * max_bar_width)
        bar = "█" * bar_len + "░" * (max_bar_width - bar_len)
        print(f" {label:<10} [{bar}] {format_bytes(val)}")
    print("-" * width)

def print_dashboard(total_sent, total_recv, programs, trend, period_label, is_live=False):
    cols, lines = get_term_size()
    width = max(40, min(cols - 2, 90))
    
    chart_rows, app_rows = compute_layout(lines, len(trend), len(programs), is_live)
    
    # Header
    print("=" * width)
    title = f"NETTRACK NETWORK MONITOR - {period_label.upper()}"
    if len(title) > width:
        title = f"NETTRACK - {period_label.upper()}"
    if len(title) > width:
        title = "NETTRACK"
    print(title.center(width))
    print("=" * width)
    
    # Stats
    if width >= 60:
        print(f" Downloaded : {format_bytes(total_recv):<18} Uploaded : {format_bytes(total_sent)}")
        print(f" Total      : {format_bytes(total_recv + total_sent)}")
    else:
        print(f" Down: {format_bytes(total_recv):<10} Up: {format_bytes(total_sent)}")
        print(f" Total: {format_bytes(total_recv + total_sent)}")
        
    # Chart
    if chart_rows > 0:
        print("")  # Spacer
        trend_slice = trend[-chart_rows:] if len(trend) > chart_rows else trend
        draw_chart_responsive(trend_slice, period_label, width)
        
    # Apps
    if app_rows > 0:
        print("")  # Spacer
        print(f"TOP APPLICATIONS ({period_label.upper()})".center(width))
        print("-" * width)
        
        if width >= 55:
            app_width = width - 43
            print(f"  {'Rank':<4} {'Application':<{app_width}} {'Uploaded':>10} {'Downloaded':>10} {'Total':>10}")
            print("-" * width)
            for idx, (program, sent, recv, total) in enumerate(programs[:app_rows], 1):
                display_name = program
                if len(display_name) > app_width:
                    display_name = "..." + display_name[-(app_width - 3):]
                print(f"  {idx:<4} {display_name:<{app_width}} {format_bytes(sent):>10} {format_bytes(recv):>10} {format_bytes(total):>10}")
        else:
            app_width = width - 19
            print(f"  {'Rank':<4} {'Application':<{app_width}} {'Total':>10}")
            print("-" * width)
            for idx, (program, sent, recv, total) in enumerate(programs[:app_rows], 1):
                display_name = program
                if len(display_name) > app_width:
                    display_name = "..." + display_name[-(app_width - 3):]
                print(f"  {idx:<4} {display_name:<{app_width}} {format_bytes(total):>10}")
    print("=" * width)

# --- Web Server Component ---
class WebDashboardHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        # Silence default request logging in terminal
        return

    def get_api_data(self):
        # Compile stats for today, week, month
        check_db()
        
        # Today
        ts_today = int(datetime.datetime.now().replace(hour=0, minute=0, second=0, microsecond=0).timestamp())
        sent_t, recv_t, progs_t = get_stats(ts_today)
        
        # Week
        ts_week = int((datetime.datetime.now() - datetime.timedelta(days=6)).replace(hour=0, minute=0, second=0, microsecond=0).timestamp())
        sent_w, recv_w, progs_w = get_stats(ts_week)
        
        # Month
        ts_month = int((datetime.datetime.now() - datetime.timedelta(days=29)).replace(hour=0, minute=0, second=0, microsecond=0).timestamp())
        sent_m, recv_m, progs_m = get_stats(ts_month)
        
        # Trends
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # Today hourly trend
        cursor.execute("""
        SELECT hour_timestamp, SUM(sent_bytes), SUM(received_bytes)
        FROM hourly_usage WHERE hour_timestamp >= ? GROUP BY hour_timestamp ORDER BY hour_timestamp ASC
        """, (ts_today,))
        trend_today = [{"label": datetime.datetime.fromtimestamp(r[0]).strftime("%H:00"), "sent": r[1], "recv": r[2]} for r in cursor.fetchall()]
        
        # Week daily trend
        cursor.execute("""
        SELECT strftime('%Y-%m-%d', datetime(hour_timestamp, 'unixepoch', 'localtime')) as day,
               SUM(sent_bytes), SUM(received_bytes)
        FROM hourly_usage WHERE hour_timestamp >= ? GROUP BY day ORDER BY day ASC
        """, (ts_week,))
        trend_week = [{"label": r[0], "sent": r[1], "recv": r[2]} for r in cursor.fetchall()]
        
        conn.close()
        
        def serialize_progs(progs):
            return [{"name": p[0], "sent": p[1], "recv": p[2], "total": p[3]} for p in progs]
            
        return {
            "today": {"sent": sent_t, "recv": recv_t, "total": sent_t + recv_t, "apps": serialize_progs(progs_t[:15]), "trend": trend_today},
            "week": {"sent": sent_w, "recv": recv_w, "total": sent_w + recv_w, "apps": serialize_progs(progs_w[:15]), "trend": trend_week},
            "month": {"sent": sent_m, "recv": recv_m, "total": sent_m + recv_m, "apps": serialize_progs(progs_m[:15])}
        }

    def do_GET(self):
        parsed_url = urllib.parse.urlparse(self.path)
        if parsed_url.path == "/api/data":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            data = self.get_api_data()
            self.wfile.write(json.dumps(data).encode('utf-8'))
            return
            
        # HTML Page
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        
        html = """<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>NetTrack - Network Usage Dashboard</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-color: #0b0f19;
            --card-bg: rgba(22, 30, 49, 0.7);
            --text-color: #f1f5f9;
            --text-muted: #94a3b8;
            --primary: #3b82f6;
            --primary-light: #60a5fa;
            --accent: #10b981;
            --border-color: rgba(255, 255, 255, 0.08);
            --font-family: 'Outfit', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
        }
        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }
        body {
            font-family: var(--font-family);
            background: radial-gradient(circle at top left, #111827, #0b0f19);
            color: var(--text-color);
            padding: 2rem;
            line-height: 1.5;
            min-height: 100vh;
        }
        header {
            margin-bottom: 2rem;
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid var(--border-color);
            padding-bottom: 1.5rem;
            flex-wrap: wrap;
            gap: 1.5rem;
            animation: fadeIn 0.6s cubic-bezier(0.16, 1, 0.3, 1) both;
        }
        h1 {
            font-size: 2rem;
            font-weight: 700;
            background: linear-gradient(to right, #ffffff, #94a3b8);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            letter-spacing: -0.02em;
        }
        .timeframe-selector {
            display: flex;
            gap: 0.5rem;
        }
        .btn {
            background-color: rgba(30, 41, 59, 0.5);
            border: 1px solid var(--border-color);
            color: var(--text-color);
            padding: 0.6rem 1.2rem;
            border-radius: 8px;
            cursor: pointer;
            font-weight: 600;
            font-size: 0.875rem;
            transition: all 0.25s cubic-bezier(0.4, 0, 0.2, 1);
        }
        .btn:hover {
            background-color: rgba(59, 130, 246, 0.1);
            border-color: var(--primary);
            transform: translateY(-1px);
        }
        .btn.active {
            background: linear-gradient(135deg, var(--primary), #2563eb);
            border-color: var(--primary);
            box-shadow: 0 4px 12px rgba(59, 130, 246, 0.3);
            color: #ffffff;
        }
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
            gap: 1.5rem;
            margin-bottom: 2rem;
        }
        .card {
            background: var(--card-bg);
            backdrop-filter: blur(12px);
            -webkit-backdrop-filter: blur(12px);
            border: 1px solid var(--border-color);
            border-radius: 16px;
            padding: 1.5rem;
            box-shadow: 0 10px 30px -10px rgba(0,0,0,0.5);
            transition: transform 0.3s ease, box-shadow 0.3s ease, border-color 0.3s ease;
            animation: fadeIn 0.6s cubic-bezier(0.16, 1, 0.3, 1) both;
        }
        .card:hover {
            transform: translateY(-2px);
            box-shadow: 0 15px 35px -5px rgba(0,0,0,0.6);
            border-color: rgba(59, 130, 246, 0.3);
        }
        .stats-grid .card:nth-child(1) { animation-delay: 0.05s; }
        .stats-grid .card:nth-child(2) { animation-delay: 0.1s; }
        .stats-grid .card:nth-child(3) { animation-delay: 0.15s; }
        
        .card-title {
            color: var(--text-muted);
            font-size: 0.75rem;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.08em;
            margin-bottom: 0.75rem;
        }
        .card-value {
            font-size: 2.25rem;
            font-weight: 700;
            color: #ffffff;
            letter-spacing: -0.03em;
        }
        .dashboard-layout {
            display: grid;
            grid-template-columns: 3fr 2fr;
            gap: 1.5rem;
        }
        .dashboard-layout > .card:nth-child(1) { animation-delay: 0.2s; }
        .dashboard-layout > .card:nth-child(2) { animation-delay: 0.25s; }
        
        h3 {
            font-size: 1.25rem;
            font-weight: 600;
            color: #ffffff;
            margin-bottom: 1.25rem;
            letter-spacing: -0.01em;
        }
        .chart-container {
            position: relative;
            height: clamp(200px, 38vh, 360px);
            width: 100%;
        }
        .app-table {
            width: 100%;
            border-collapse: collapse;
            min-width: 400px;
        }
        .app-table th, .app-table td {
            text-align: left;
            padding: 0.85rem 1rem;
            border-bottom: 1px solid rgba(255,255,255,0.04);
        }
        .app-table th {
            color: var(--text-muted);
            font-weight: 600;
            font-size: 0.8rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            border-bottom: 1px solid var(--border-color);
        }
        .app-table tr {
            transition: background-color 0.2s ease;
        }
        .app-table tr:hover {
            background-color: rgba(255,255,255,0.02);
        }
        .text-right {
            text-align: right;
        }
        .app-name-cell {
            display: flex;
            align-items: center;
            gap: 0.75rem;
            max-width: 100%;
        }
        .app-name {
            font-weight: 600;
            color: #f8fafc;
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
            max-width: 180px;
        }
        .badge {
            display: inline-block;
            padding: 0.2rem 0.5rem;
            border-radius: 6px;
            font-size: 0.65rem;
            font-weight: 700;
            letter-spacing: 0.05em;
            text-transform: uppercase;
            background-color: rgba(59, 130, 246, 0.12);
            color: var(--primary-light);
            border: 1px solid rgba(59, 130, 246, 0.2);
        }
        
        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(12px); }
            to { opacity: 1; transform: translateY(0); }
        }
        
        /* Media Queries for responsiveness */
        @media(max-width: 1024px) {
            .dashboard-layout {
                grid-template-columns: 1fr;
            }
        }
        @media (max-width: 640px) {
            body {
                padding: 1rem;
            }
            header {
                flex-direction: column;
                align-items: flex-start;
                gap: 1rem;
                padding-bottom: 1rem;
            }
            .timeframe-selector {
                width: 100%;
            }
            .timeframe-selector .btn {
                flex: 1;
                text-align: center;
                padding: 0.5rem;
                font-size: 0.8rem;
            }
            .stats-grid {
                grid-template-columns: 1fr;
                gap: 1rem;
            }
            .card {
                padding: 1.25rem;
            }
            .card-value {
                font-size: 1.85rem;
            }
            .app-name {
                max-width: 120px;
            }
        }
        @media (min-width: 768px) {
            .app-name {
                max-width: 250px;
            }
        }
        @media (min-width: 1200px) {
            .app-name {
                max-width: 380px;
            }
        }
    </style>
</head>
<body>
    <header>
        <div>
            <h1>NetTrack Network Dashboard</h1>
            <p style="color: var(--text-muted); font-size: 0.875rem; margin-top: 0.25rem;">Real-time historical app network analyzer</p>
        </div>
        <div class="timeframe-selector">
            <button class="btn active" onclick="switchTimeframe('today', event)">Today</button>
            <button class="btn" onclick="switchTimeframe('week', event)">Last 7 Days</button>
            <button class="btn" onclick="switchTimeframe('month', event)">Last 30 Days</button>
        </div>
    </header>

    <div class="stats-grid">
        <div class="card">
            <div class="card-title">Total Download</div>
            <div class="card-value" id="stat-download">0.00 B</div>
        </div>
        <div class="card">
            <div class="card-title">Total Upload</div>
            <div class="card-value" id="stat-upload">0.00 B</div>
        </div>
        <div class="card">
            <div class="card-title">Combined Usage</div>
            <div class="card-value" id="stat-total" style="color: var(--primary-light);">0.00 B</div>
        </div>
    </div>

    <div class="dashboard-layout">
        <div class="card">
            <h3>Traffic Trend</h3>
            <div class="chart-container">
                <canvas id="trendChart"></canvas>
            </div>
        </div>
        <div class="card">
            <h3>Top Apps & Services</h3>
            <div style="overflow-x: auto;">
                <table class="app-table">
                    <thead>
                        <tr>
                            <th>Application</th>
                            <th class="text-right">Up</th>
                            <th class="text-right">Down</th>
                            <th class="text-right">Total</th>
                        </tr>
                    </thead>
                    <tbody id="app-tbody">
                        <!-- Filled by JS -->
                    </tbody>
                </table>
            </div>
        </div>
    </div>

    <script>
        let apiData = null;
        let chart = null;
        let currentTimeframe = 'today';

        function formatBytes(bytes) {
            if (bytes === 0) return '0 B';
            const k = 1024;
            const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
            const i = Math.floor(Math.log(bytes) / Math.log(k));
            return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
        }

        function renderDashboard() {
            const data = apiData[currentTimeframe];
            document.getElementById('stat-download').innerText = formatBytes(data.recv);
            document.getElementById('stat-upload').innerText = formatBytes(data.sent);
            document.getElementById('stat-total').innerText = formatBytes(data.total);

            // Table
            const tbody = document.getElementById('app-tbody');
            tbody.innerHTML = '';
            data.apps.forEach(app => {
                const tr = document.createElement('tr');
                tr.innerHTML = `
                    <td title="${app.name}">
                        <div class="app-name-cell">
                            <span class="badge">App</span>
                            <span class="app-name">${app.name}</span>
                        </div>
                    </td>
                    <td class="text-right" style="color: var(--text-muted);">${formatBytes(app.sent)}</td>
                    <td class="text-right" style="color: var(--text-muted);">${formatBytes(app.recv)}</td>
                    <td class="text-right" style="font-weight: 600; color: #ffffff;">${formatBytes(app.total)}</td>
                `;
                tbody.appendChild(tr);
            });

            // Chart
            if (data.trend) {
                const labels = data.trend.map(t => t.label);
                const rxData = data.trend.map(t => t.recv);
                const txData = data.trend.map(t => t.sent);

                if (chart) {
                    chart.data.labels = labels;
                    chart.data.datasets[0].data = rxData;
                    chart.data.datasets[1].data = txData;
                    chart.update('none'); // Update without animation/flashing
                } else {
                    const ctx = document.getElementById('trendChart').getContext('2d');
                    chart = new Chart(ctx, {
                        type: 'bar',
                        data: {
                            labels: labels,
                            datasets: [
                                {
                                    label: 'Download',
                                    data: rxData,
                                    backgroundColor: '#3b82f6',
                                    borderRadius: 4
                                },
                                {
                                    label: 'Upload',
                                    data: txData,
                                    backgroundColor: '#10b981',
                                    borderRadius: 4
                                }
                            ]
                        },
                        options: {
                            responsive: true,
                            maintainAspectRatio: false,
                            plugins: {
                                legend: {
                                    labels: { color: '#f8fafc', font: { family: 'Outfit' } }
                                }
                            },
                            scales: {
                                x: {
                                    grid: { color: 'rgba(255, 255, 255, 0.05)' },
                                    ticks: { color: '#94a3b8', font: { family: 'Outfit' } }
                                },
                                y: {
                                    grid: { color: 'rgba(255, 255, 255, 0.05)' },
                                    ticks: {
                                        color: '#94a3b8',
                                        font: { family: 'Outfit' },
                                        callback: function(value) { return formatBytes(value); }
                                    }
                                }
                            }
                        }
                    });
                }
            } else {
                if (chart) {
                    chart.destroy();
                    chart = null;
                }
            }
        }

        function switchTimeframe(tf, event) {
            currentTimeframe = tf;
            document.querySelectorAll('.timeframe-selector .btn').forEach(btn => {
                btn.classList.remove('active');
            });
            if (event && event.target) {
                event.target.classList.add('active');
            }
            renderDashboard();
        }

        async function fetchData() {
            try {
                const response = await fetch('/api/data');
                apiData = await response.json();
                renderDashboard();
            } catch (err) {
                console.error("Error fetching data:", err);
            }
        }

        fetchData();
        // Auto refresh every 10 seconds
        setInterval(fetchData, 10000);
    </script>
</body>
</html>
"""
        self.wfile.write(html.encode('utf-8'))

def run_web_server(port):
    server_address = ('', port)
    try:
        httpd = HTTPServer(server_address, WebDashboardHandler)
        print(f"============================================================")
        print(f"   NetTrack Web Dashboard running at http://localhost:{port}")
        print(f"   Access it from your local network via your server's IP.")
        print(f"   Press Ctrl+C to stop.")
        print(f"============================================================")
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nWeb server stopped.")
    except Exception as e:
        print(f"Error starting web server: {e}", file=sys.stderr)

def run_live_dashboard(initial_period):
    check_db()
    
    current_period = initial_period
    
    import select
    import tty
    import termios
    import time
    
    class RawTerminal:
        def __enter__(self):
            self.enabled = False
            try:
                self.old_settings = termios.tcgetattr(sys.stdin)
                tty.setcbreak(sys.stdin.fileno())
                # Switch to alternate screen buffer and hide cursor
                sys.stdout.write("\033[?1049h\033[?25l")
                sys.stdout.flush()
                self.enabled = True
            except termios.error:
                pass
            return self

        def __exit__(self, type, value, traceback):
            if self.enabled:
                # Switch back to normal screen buffer and show cursor
                sys.stdout.write("\033[?1049l\033[?25h")
                sys.stdout.flush()
                termios.tcsetattr(sys.stdin, termios.TCSADRAIN, self.old_settings)

    try:
        last_cols, last_lines = None, None
        with RawTerminal():
            while True:
                cols, lines = get_term_size()
                if last_cols is None or (cols, lines) != (last_cols, last_lines):
                    sys.stdout.write("\033[2J\033[H")
                    sys.stdout.flush()
                    last_cols, last_lines = cols, lines
                else:
                    sys.stdout.write("\033[H")
                    sys.stdout.flush()
                
                # Fetch stats
                if current_period == "week":
                    sent, recv, programs, trend, label = get_week()
                elif current_period == "month":
                    sent, recv, programs, trend, label = get_month()
                else:
                    sent, recv, programs, trend, label = get_today()
                
                # Print dashboard
                print_dashboard(sent, recv, programs, trend, label, is_live=True)
                
                # Print footer/controls
                now_str = datetime.datetime.now().strftime("%H:%M:%S")
                print(f" Last Updated: {now_str} | Controls: [d/1] Today  [w/2] Week  [m/3] Month  [r] Refresh  [q] Quit")
                
                # Clear remainder of screen to remove any ghost characters
                sys.stdout.write("\033[J")
                sys.stdout.flush()
                
                # Wait for input (2 seconds timeout)
                try:
                    rlist, _, _ = select.select([sys.stdin], [], [], 2.0)
                except (InterruptedError, OSError):
                    # Handle window resize or signal interrupt
                    continue
                
                if rlist:
                    key = sys.stdin.read(1)
                    if not key:
                        # EOF on stdin (e.g. redirected input ended)
                        # Sleep to prevent high CPU usage, then check again
                        time.sleep(2.0)
                        continue
                    if key.lower() == 'q':
                        break
                    elif key in ('1', 'd', 'D'):
                        current_period = "today"
                    elif key in ('2', 'w', 'W'):
                        current_period = "week"
                    elif key in ('3', 'm', 'M'):
                        current_period = "month"
                    elif key in ('r', 'R'):
                        pass # Loop will update immediately
    except KeyboardInterrupt:
        pass

# --- Main CLI ---
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="NetTrack - CLI Network History Monitor")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("-d", "--today", action="store_true", help="Show statistics for today (default)")
    group.add_argument("-w", "--week", action="store_true", help="Show statistics for the last 7 days")
    group.add_argument("-m", "--month", action="store_true", help="Show statistics for the last 30 days")
    group.add_argument("--web", type=int, nargs='?', const=8080, help="Run local web server dashboard. Specify optional port (default: 8080)")
    
    parser.add_argument("-l", "--live", action="store_true", help="Stay active and update stats in real-time (default in interactive terminal)")
    parser.add_argument("-o", "--once", action="store_true", help="Display stats once and exit (default when output is piped/redirected)")
    
    args = parser.parse_args()
    
    if args.web is not None:
        run_web_server(args.web)
        sys.exit(0)
        
    check_db()
    
    if args.week:
        initial_period = "week"
    elif args.month:
        initial_period = "month"
    else:
        initial_period = "today"
        
    # Determine if we should run in live mode
    is_live = False
    if args.live:
        is_live = True
    elif args.once:
        is_live = False
    else:
        # Default to live mode if both stdin and stdout are interactive TTYs
        is_live = sys.stdout.isatty() and sys.stdin.isatty()
        
    if is_live:
        run_live_dashboard(initial_period)
    else:
        if initial_period == "week":
            sent, recv, programs, trend, label = get_week()
        elif initial_period == "month":
            sent, recv, programs, trend, label = get_month()
        else:
            sent, recv, programs, trend, label = get_today()
        print_dashboard(sent, recv, programs, trend, label)

