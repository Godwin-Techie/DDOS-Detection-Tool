import psutil            # A library that lets us see how much CPU/Memory the computer is using.
import time              # Used for timing how long the dashboard has been running (uptime).
from flask import Flask, render_template_string, jsonify  # 'Flask' is a tool for building websites quickly.
import threading         # This allows the dashboard to run in the "background" without stopping the rest of the code.

def format_uptime(seconds):
    """Convert seconds into H:M:S format."""
    # This math breaks a big number of seconds into hours, minutes, and remaining seconds.
    hours = seconds // 3600
    minutes = (seconds % 3600) // 60
    secs = seconds % 60
    return f"{hours}h {minutes}m {secs}s"

class Dashboard:
    def __init__(self, detector, blocker, baseline,
                 refresh_interval=3,
                 show_system_metrics=True,
                 show_uptime=True):
        # We give the dashboard access to our other tools: detector, blocker, and baseline.
        self.detector = detector
        self.blocker = blocker
        self.baseline = baseline
        self.refresh_interval = refresh_interval
        self.show_system_metrics = show_system_metrics
        self.show_uptime = show_uptime
        self.start_time = time.time()  # Mark exactly when the dashboard started.
        self.app = Flask(__name__)     # Initialize the Flask web application.

        # This tells Flask what to show when you visit the main page (the "/" address).
        @self.app.route("/")
        def index():
            # Gather all the latest data from our tools.
            mean = self.baseline.effective_mean()
            stddev = self.baseline.effective_stddev()
            
            # Check the computer's health (CPU/RAM) if enabled.
            cpu_usage = psutil.cpu_percent() if self.show_system_metrics else None
            memory_usage = psutil.virtual_memory().percent if self.show_system_metrics else None
            
            # Calculate how long the program has been online.
            uptime_seconds = int(time.time() - self.start_time) if self.show_uptime else None
            uptime_str = format_uptime(uptime_seconds) if uptime_seconds is not None else None
            
            # Ask the detector for the "Top 10" most active users.
            top_ips = self.detector.top_ips(10)
            global_rps = self.detector.current_rps()

            # This big block of text is 'HTML' and 'CSS'. 
            # It defines how the dashboard looks (colors, boxes, and fonts).
            return render_template_string("""
            <html>
            <head>
                <title>DDoS Detector Dashboard</title>
                <meta http-equiv="refresh" content="{{ refresh_interval }}">
                <style>
                    body { font-family: Arial, sans-serif; margin: 20px; background: #f0f2f5; }
                    h1 { color: #222; margin-bottom: 20px; }
                    .grid { display: grid; grid-template-columns: repeat(2, 1fr); gap: 20px; }
                    .card {
                        background: white;
                        padding: 20px;
                        border-radius: 10px;
                        box-shadow: 0 4px 8px rgba(0,0,0,0.1);
                    }
                    .card h2 { margin-top: 0; color: #007bff; }
                    .metric { font-size: 1.1em; margin: 8px 0; }
                    .highlight { color: #007bff; font-weight: bold; }
                    .danger { color: #dc3545; font-weight: bold; }
                    .success { color: #28a745; font-weight: bold; }
                    table { width: 100%; border-collapse: collapse; margin-top: 10px; }
                    th, td { padding: 8px; text-align: left; border-bottom: 1px solid #ddd; }
                    th { background: #007bff; color: white; }
                </style>
            </head>
            <body>
                <h1>HNG Stage 3 — Anomaly Detection Dashboard</h1>

                <div class="grid">
                    <div class="card">
                        <h2>Top Metrics</h2>
                        <p class="metric"><b>GLOBAL REQ/S:</b> <span class="highlight">{{ global_rps }}</span></p>
                        <p class="metric"><b>LOGS PROCESSED:</b> {{ detector.total_logs }}</p>
                        <p class="metric"><b>BANNED IPS:</b> <span class="danger">{{ blocker.blocked_ips|length }}</span></p>
                        {% if uptime_str %}
                        <p class="metric"><b>UPTIME:</b> {{ uptime_str }}</p>
                        {% endif %}
                        {% if cpu_usage is not none %}
                        <p class="metric"><b>CPU USAGE:</b> {{ cpu_usage }}%</p>
                        <p class="metric"><b>MEMORY USAGE:</b> {{ memory_usage }}%</p>
                        {% endif %}
                    </div>

                    <div class="card">
                        <h2>Effective Baseline</h2>
                        <p class="metric"><b>MEAN:</b> {{ mean }}</p>
                        <p class="metric"><b>STDDEV:</b> {{ stddev }}</p>
                        <p class="metric"><b>Z-SCORE THRESHOLD:</b> 3.0</p>
                        <p class="metric"><b>RATE MULTIPLIER:</b> 5×</p>
                    </div>

                    <div class="card">
                        <h2>Banned IPs</h2>
                        {% if blocker.blocked_ips %}
                            <ul>
                            {% for ip in blocker.blocked_ips %}
                                <li class="danger">{{ ip }}</li>
                            {% endfor %}
                            </ul>
                        {% else %}
                            <p class="success">No active bans — all clear</p>
                        {% endif %}
                    </div>

                    <div class="card">
                        <h2>Top 10 Source IPs</h2>
                        <table>
                            <tr><th>IP Address</th><th>Total Requests Seen</th></tr>
                            {% for ip, count in top_ips %}
                            <tr><td>{{ ip }}</td><td>{{ count }}</td></tr>
                            {% endfor %}
                        </table>
                    </div>
                </div>
            </body>
            </html>
            """, mean=mean, stddev=stddev,
               blocker=self.blocker,
               detector=self.detector,
               refresh_interval=self.refresh_interval,
               cpu_usage=cpu_usage,
               memory_usage=memory_usage,
               uptime_str=uptime_str,
               top_ips=top_ips,
               global_rps=global_rps)

        # This secondary page gives raw 'JSON' data (perfect for other machines to read).
        @self.app.route("/metrics")
        def metrics():
            return jsonify({
                "blocked_ips": list(self.blocker.blocked_ips),
                "global_rps": self.detector.current_rps(),
                "top_ips": self.detector.top_ips(10),
                "cpu": psutil.cpu_percent() if self.show_system_metrics else None,
                "memory": psutil.virtual_memory().percent if self.show_system_metrics else None,
                "mean": self.baseline.effective_mean(),
                "stddev": self.baseline.effective_stddev(),
                "uptime": format_uptime(int(time.time() - self.start_time)) if self.show_uptime else None
            })

    def run(self, port=8081):
        """Start the website in a separate thread so it doesn't block the main program."""
        # We use a Thread so the security code can keep running while this website stays open.
        t = threading.Thread(target=self.app.run,
                             kwargs={"host": "0.0.0.0", "port": port, "debug": False})
        t.daemon = True # This means "if the main program closes, close this thread too."
        t.start()