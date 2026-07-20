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

def draw_chart(trend, period_type):
    if not trend:
        print("\nNo trend data available for this period.")
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
        
    max_val = max(values)
    if max_val == 0:
        max_val = 1
        
    max_bar_width = 30
    print("\n" + "=" * 55)
    print("                 TRAFFIC TREND CHART")
    print("=" * 55)
    for label, val in zip(labels, values):
        bar_len = int((val / max_val) * max_bar_width)
        bar = "█" * bar_len + "░" * (max_bar_width - bar_len)
        print(f" {label:<10} [{bar}] {format_bytes(val)}")
    print("=" * 55)

def print_dashboard(total_sent, total_recv, programs, trend, period_label):
    print("=" * 75)
    print(f"              NETTRACK NETWORK MONITOR - {period_label.upper()}")
    print("=" * 75)
    print(f" Downloaded : {format_bytes(total_recv):<20} Uploaded : {format_bytes(total_sent)}")
    print(f" Total      : {format_bytes(total_recv + total_sent)}")
    
    draw_chart(trend, period_label)
    
    print("\n--- Top Applications ---")
    print(f"  {'Rank':<5} {'Application':<33} {'Uploaded':>10} {'Downloaded':>10} {'Total':>10}")
    print("-" * 75)
    for idx, (program, sent, recv, total) in enumerate(programs[:20], 1):
        display_name = program
        if len(display_name) > 31:
            display_name = "..." + display_name[-28:]
        print(f"  {idx:<5} {display_name:<33} {format_bytes(sent):>10} {format_bytes(recv):>10} {format_bytes(total):>10}")
    
    if len(programs) > 20:
        print(f"  ... and {len(programs) - 20} more applications.")
    print("=" * 75)

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
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;600;700&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-color: #0f172a;
            --card-bg: #1e293b;
            --text-color: #f8fafc;
            --text-muted: #94a3b8;
            --primary: #3b82f6;
            --primary-light: #60a5fa;
            --accent: #10b981;
            --border-color: #334155;
        }
        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }
        body {
            font-family: 'Inter', sans-serif;
            background-color: var(--bg-color);
            color: var(--text-color);
            padding: 2rem;
            line-height: 1.5;
        }
        header {
            margin-bottom: 2rem;
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid var(--border-color);
            padding-bottom: 1rem;
        }
        h1 {
            font-size: 1.8rem;
            font-weight: 700;
            color: #ffffff;
        }
        .timeframe-selector {
            display: flex;
            gap: 0.5rem;
        }
        .btn {
            background-color: var(--card-bg);
            border: 1px solid var(--border-color);
            color: var(--text-color);
            padding: 0.5rem 1rem;
            border-radius: 6px;
            cursor: pointer;
            font-weight: 600;
            font-size: 0.875rem;
            transition: all 0.2s;
        }
        .btn.active, .btn:hover {
            background-color: var(--primary);
            border-color: var(--primary);
        }
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
            gap: 1.5rem;
            margin-bottom: 2rem;
        }
        .card {
            background-color: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 1.5rem;
            box-shadow: 0 4px 6px -1px rgb(0 0 0 / 0.1), 0 2px 4px -2px rgb(0 0 0 / 0.1);
        }
        .card-title {
            color: var(--text-muted);
            font-size: 0.875rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            margin-bottom: 0.5rem;
        }
        .card-value {
            font-size: 2rem;
            font-weight: 700;
            color: #ffffff;
        }
        .dashboard-layout {
            display: grid;
            grid-template-columns: 3fr 2fr;
            gap: 1.5rem;
        }
        @media(max-width: 1024px) {
            .dashboard-layout {
                grid-template-columns: 1fr;
            }
        }
        .chart-container {
            position: relative;
            height: 300px;
            width: 100%;
        }
        .app-table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 1rem;
        }
        .app-table th, .app-table td {
            text-align: left;
            padding: 0.75rem 1rem;
            border-bottom: 1px solid var(--border-color);
        }
        .app-table th {
            color: var(--text-muted);
            font-weight: 600;
            font-size: 0.875rem;
        }
        .app-table tr:hover {
            background-color: rgba(255,255,255,0.02);
        }
        .text-right {
            text-align: right;
        }
        .badge {
            display: inline-block;
            padding: 0.25rem 0.5rem;
            border-radius: 4px;
            font-size: 0.75rem;
            font-weight: 700;
            background-color: var(--border-color);
        }
    </style>
</head>
<body>
    <header>
        <div>
            <h1>NetTrack Network Dashboard</h1>
            <p style="color: var(--text-muted); font-size: 0.875rem;">Real-time historical app network analyzer</p>
        </div>
        <div class="timeframe-selector">
            <button class="btn active" onclick="switchTimeframe('today')">Today</button>
            <button class="btn" onclick="switchTimeframe('week')">Last 7 Days</button>
            <button class="btn" onclick="switchTimeframe('month')">Last 30 Days</button>
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
            <h3 style="margin-bottom: 1rem;">Traffic Trend</h3>
            <div class="chart-container">
                <canvas id="trendChart"></canvas>
            </div>
        </div>
        <div class="card">
            <h3 style="margin-bottom: 1rem;">Top Apps & Services</h3>
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
                let appName = app.name;
                if (appName.length > 25) {
                    appName = '...' + appName.substring(appName.length - 22);
                }
                tr.innerHTML = `
                    <td title="${app.name}"><span class="badge">App</span> <strong>${appName}</strong></td>
                    <td class="text-right" style="color: var(--text-muted);">${formatBytes(app.sent)}</td>
                    <td class="text-right" style="color: var(--text-muted);">${formatBytes(app.recv)}</td>
                    <td class="text-right" style="font-weight: 600;">${formatBytes(app.total)}</td>
                `;
                tbody.appendChild(tr);
            });

            // Chart
            if (data.trend) {
                const labels = data.trend.map(t => t.label);
                const rxData = data.trend.map(t => t.recv);
                const txData = data.trend.map(t => t.sent);

                if (chart) {
                    chart.destroy();
                }

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
                                labels: { color: '#f8fafc' }
                            }
                        },
                        scales: {
                            x: {
                                grid: { color: 'rgba(255, 255, 255, 0.05)' },
                                ticks: { color: '#94a3b8' }
                            },
                            y: {
                                grid: { color: 'rgba(255, 255, 255, 0.05)' },
                                ticks: {
                                    color: '#94a3b8',
                                    callback: function(value) { return formatBytes(value); }
                                }
                            }
                        }
                    }
                });
            } else {
                if (chart) {
                    chart.destroy();
                    chart = null;
                }
            }
        }

        function switchTimeframe(tf) {
            currentTimeframe = tf;
            document.querySelectorAll('.timeframe-selector .btn').forEach(btn => {
                btn.classList.remove('active');
            });
            event.target.classList.add('active');
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

# --- Main CLI ---
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="NetTrack - CLI Network History Monitor")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("-d", "--today", action="store_true", help="Show statistics for today (default)")
    group.add_argument("-w", "--week", action="store_true", help="Show statistics for the last 7 days")
    group.add_argument("-m", "--month", action="store_true", help="Show statistics for the last 30 days")
    group.add_argument("--web", type=int, nargs='?', const=8080, help="Run local web server dashboard. Specify optional port (default: 8080)")
    
    args = parser.parse_args()
    
    if args.web is not None:
        run_web_server(args.web)
        sys.exit(0)
        
    check_db()
    
    if args.week:
        sent, recv, programs, trend, label = get_week()
    elif args.month:
        sent, recv, programs, trend, label = get_month()
    else:
        # Default is today
        sent, recv, programs, trend, label = get_today()
        
    print_dashboard(sent, recv, programs, trend, label)
