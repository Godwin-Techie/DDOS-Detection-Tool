import time
import yaml # This library allows Python to read the '.yml' settings file we saw earlier.
from baseline import Baseline
from detector import Detector
from blocker import Blocker
from unbanner import Unbanner
from notifier import Notifier
from dashboard import Dashboard
from monitor import tail_log, process_log_line, requests_per_ip

# This is the path to the file where your website records every single visit.
LOGFILE = "/var/log/nginx/hng-access.log"

# --- Load config file ---
# We open the settings file so the program knows its limits (thresholds, ports, etc.).
with open("detector/config.yml", "r") as f:
    config = yaml.safe_load(f)

# --- Initialize modules using config ---
# Here we "build" all our tools using the settings from the config file.

# 1. Setup the math brain (Baseline)
baseline = Baseline(window=config["baseline_window"], recalc_interval=config["recalc_interval"])

# 2. Setup the messenger (Notifier) for Slack
notifier = Notifier(
    slack_webhook=config["slack_webhook"],
    cooldown=config["cooldown"]
)

# 3. Setup the enforcement (Blocker and Unbanner)
blocker = Blocker(notifier=notifier, ban_durations=config["ban_durations"])
unbanner = Unbanner(blocker=blocker, notifier=notifier, schedule=config["unban_schedule"])

# 4. Setup the logic (Detector)
detector = Detector(
    baseline,
    z_threshold=config["z_threshold"],
    spike_factor=config["spike_factor"],
    ip_threshold=config["ip_threshold"],
    global_threshold=config["global_threshold"],
    error_multiplier=config["error_multiplier"],
    blocker=blocker
)

# 5. Setup the visual website (Dashboard)
dashboard = Dashboard(
    detector,
    blocker,
    baseline,
    refresh_interval=config["refresh_interval"],
    show_system_metrics=config["show_system_metrics"],
    show_uptime=config["show_uptime"]
)
# Start the dashboard website so we can see the charts.
dashboard.run(port=config["dashboard_port"])

def main():
    print("[MAIN] Starting DDoS detector...")
    last_baseline_print = time.time()

    # 'tail_log' stays open and waits for new lines to appear in the access log.
    for log_line in tail_log(LOGFILE):
        # Break the log line apart to see who visited (IP) and what they did.
        process_log_line(log_line)

        # Count total requests across all users to see the "Global" traffic level.
        total_requests = sum(len(q) for q in requests_per_ip.values())
        
        # Tell the baseline math tool about the new traffic.
        baseline.add_count(total_requests)

        # Send the number to the dashboard so the chart updates.
        detector.record_traffic(total_requests)

        # --- Global anomaly check ---
        # Ask: "Is the whole server under attack right now?"
        is_global, reason = detector.check_global_anomaly(total_requests)
        if is_global:
            mean = baseline.effective_mean()
            stddev = baseline.effective_stddev()
            # If yes, send a big emergency alert to Slack.
            notifier.send_global_alert(
                reason,
                global_rate=total_requests,
                baseline_mean=mean,
                stddev=stddev
            )

        # --- Per-IP anomaly check ---
        # Look at every single visitor one by one.
        for ip, q in requests_per_ip.items():
            ip_rate = len(q)
            is_ip, reason = detector.check_ip_anomaly(ip, ip_rate)
            
            if is_ip:
                # If one specific person is being bad:
                # 1. Block them in the firewall.
                blocker.block_ip(ip, condition=reason, rate=ip_rate, baseline=baseline.effective_mean())
                
                # 2. Send a Slack alert about that specific IP.
                mean = baseline.effective_mean()
                stddev = baseline.effective_stddev()
                notifier.send_alert(
                    ip,
                    reason,
                    global_rate=total_requests,
                    baseline_mean=mean,
                    stddev=stddev
                )
                
                # 3. Start a timer to eventually let them back in (Unban).
                unbanner.schedule_unblock(ip)

        # --- Housekeeping ---
        # Every 60 seconds, print the current "Normal" stats to the console and the log file.
        if time.time() - last_baseline_print >= 60:
            mean = baseline.effective_mean()
            stddev = baseline.effective_stddev()
            print(f"[BASELINE] mean={mean:.2f}, stddev={stddev:.2f}")

            with open("audit.log", "a") as audit:
                audit.write(
                    f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] BASELINE mean={mean:.2f}, stddev={stddev:.2f}\n"
                )

            last_baseline_print = time.time()

# This part ensures the 'main' function runs when you start the script.
if __name__ == "__main__":
    main()