# HNG Project - DDoS Detector

# Server & Dashboard

- Server IP: `172.174.232.228:8080`
- Metrics Dashboard URL: http://172.174.232.228:8081  
  _(Both live during grading)_

# Language Choice

I chose Python because:

- Native support for efficient data structures like `deque` (used in sliding window).
- Rich ecosystem for networking, logging, and visualization.
- Readable syntax that makes collaborative development easier.
- Easy integration with Docker for reproducible deployments.

# Project Structure

hng-project/
├── Screenshots/ # Evidence of system behavior
│ ├── Tool-running.png
│ ├── Ban-Slack.png
│ ├── Unban-slack.png
│ ├── Global-alert-slack.png
│ ├── Iptables-banned.png
│ ├── Audit-log.png
│ └── Baseline-graph.png
│
├── detector/ # Core detection logic
│ ├── baseline.py # Baseline calculation and recalibration
│ ├── blocker.py # Applies iptables bans
│ ├── config.example.yml # Config thresholds, intervals, etc.
│ ├── dashboard.py # Metrics dashboard server
│ ├── detector.py # Main detection loop
│ ├── main.py # Entry point
│ ├── monitor.py # Traffic monitoring
│ ├── notifier.py # Slack/email notifications
│ ├── requirements.txt # Python dependencies
│ ├── sliding_window.py # Sliding window implementation
│ └── unbanner.py # Removes bans after expiry
│
|----Docs/
| |architecture.png  
|
├── nginx/
│ └── nginx.conf # Reverse proxy configuration
│
├── .dockerignore # Ignore unnecessary files in Docker build
├── .gitignore # Ignore **pycache**, logs, etc.
├── Dockerfile # Container build instructions
├── docker-compose.yml # Multi-service orchestration
├── README.md # Project documentation
├── audit.log # Sample log of detector events
├── baseline_graph.png # Baseline effective mean visualization
└── baseline_plot.py # Script to generate baseline graph

# Sliding Window Logic

Implemented in `sliding_window.py`:

- Deque structure: New events appended to the right.
- Eviction logic: Old events popped from the left once they fall outside the configured time window.
- Efficiency: Constant‑time operations, memory bounded by window size.

# Baseline Calculation

Defined in `baseline.py`:

- Window Size: Configurable (default 60 minutes).
- Recalculation Interval: Every 5 minutes, recomputes effective mean.
- Floor Values: Minimum thresholds enforced to avoid false positives.
- Visualization: `baseline_plot.py` generates `baseline_graph.png` showing effective mean over time.

# Blocking & Unbanning

- blocker.py: Applies iptables rules to block offending IPs.
- unbanner.py: Periodically removes bans after expiry.
- audit.log: Records BAN/UNBAN events for traceability.

# Dashboard & Notifications

- dashboard.py: Serves metrics dashboard at `http://<server-ip>:3000`.
- notifier.py: Sends alerts to Slack/email when anomalies are detected.

# Docker Compose Setup

From a fresh VPS:

1. Install Docker & Compose:
   ```bash
   sudo apt update && sudo apt install docker.io docker-compose -y
   ```

# Clone the Repository

https://github.com/Godwin-Techie/DDOS-Detection-Tool.git

# Start the Stack

docker-compose up -d

# Check logs

docker logs hng-detector -f

# Screenshot

Screenshots are stored in the screenshots/ folder

# GitHub Repository

https://github.com/Godwin-Techie/DDOS-Detection-Tool.git

Blog: https://hng13devopsstage4.blogspot.com/2026/04/beginners-guide-building-ddos-detection.html

