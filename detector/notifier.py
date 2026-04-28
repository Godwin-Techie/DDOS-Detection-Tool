import time
import threading # Used to run the notification helper in the background.
import requests  # This is the tool that sends data over the internet to Slack.
from datetime import datetime # Used to create precise time labels.

class Notifier:
    def __init__(self, slack_webhook, cooldown=30):
        """
        Slack Notifier with batching, cooldown, timestamps, and styled alerts.
        """
        self.webhook_url = slack_webhook # The secret URL address for your Slack channel.
        self.cooldown = cooldown         # How many seconds to wait between sending message batches.

        # Internal state
        self.queue = []            # A list of messages waiting to be sent.
        self.lock = threading.Lock() # A "safety key" to prevent two parts of the code from editing the queue at the same time.
        self.last_sent = 0         # The timestamp of the last time we sent a message.

        # Start background worker thread: This runs the '_worker' function in the background
        # so the rest of the security system doesn't have to stop and wait for the internet.
        t = threading.Thread(target=self._worker, daemon=True)
        t.start()

    def send_alert(self, ip, reason, global_rate=None, baseline_mean=None, stddev=None):
        """Queue alert for a specific IP anomaly (red)."""
        # Create a timestamp in UTC (Standard Universal Time).
        timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
        
        # Build the text for the message line by line.
        text_lines = [
            f"• Condition: {reason}",
            f"• IP: {ip}",
            f"• Timestamp: {timestamp}"
        ]
        
        # If we have extra info like traffic rates or math averages, add them to the list.
        if global_rate is not None:
            text_lines.insert(1, f"• Global rate: {global_rate} req/60s")
        if baseline_mean is not None and stddev is not None:
            text_lines.append(f"• Baseline mean: {baseline_mean:.4f} | stddev: {stddev:.4f}")

        # 'message' is a dictionary formatted specifically for Slack.
        message = {
            "color": "danger",  # This puts a Red bar on the side of the Slack message.
            "title": ":rotating_light: ALERT — IP Anomaly",
            "text": "\n".join(text_lines)
        }
        print(f"[ALERT] {timestamp} — IP {ip}: {reason}")
        self._queue_message(message) # Put the message in the waiting line.

    def send_global_alert(self, reason, global_rate=None, baseline_mean=None, stddev=None):
        """Queue alert for global traffic anomaly (yellow)."""
        timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
        text_lines = [
            f"• Condition: {reason}",
            f"• Timestamp: {timestamp}"
        ]
        if global_rate is not None:
            text_lines.insert(1, f"• Global rate: {global_rate} req/60s")
        if baseline_mean is not None and stddev is not None:
            text_lines.append(f"• Baseline mean: {baseline_mean:.4f} | stddev: {stddev:.4f}")

        message = {
            "color": "warning",  # This puts a Yellow bar on the side of the Slack message.
            "title": ":warning: GLOBAL TRAFFIC ANOMALY",
            "text": "\n".join(text_lines)
        }
        print(f"[GLOBAL ALERT] {timestamp} — {reason}")
        self._queue_message(message)

    def send_ban(self, ip, duration, reason="threshold exceeded"):
        """Queue alert for a ban event (red)."""
        timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
        text_lines = [
            f"• BAN: IP {ip}",
            f"• Reason: {reason}",
            f"• Duration: {duration}s",
            f"• Timestamp: {timestamp}"
        ]
        message = {
            "color": "danger",
            "title": "🚫 BAN Notification",
            "text": "\n".join(text_lines)
        }
        print(f"[BAN] {timestamp} — IP {ip} banned for {duration}s ({reason})")
        self._queue_message(message)

    def send_unban(self, ip, reason="ban expired"):
        """Queue alert for an unban event (green)."""
        timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
        text_lines = [
            f"• UNBAN: IP {ip}",
            f"• Reason: {reason}",
            f"• Timestamp: {timestamp}"
        ]
        message = {
            "color": "good",  # This puts a Green bar on the side of the Slack message.
            "title": "✅ UNBAN Notification",
            "text": "\n".join(text_lines)
        }
        print(f"[UNBAN] {timestamp} — IP {ip} unbanned ({reason})")
        self._queue_message(message)

    def _queue_message(self, message):
        """Add message to queue safely."""
        # Using 'with self.lock' ensures that we don't crash if two alerts happen at once.
        with self.lock:
            self.queue.append(message)

    def _worker(self):
        """Background thread that flushes queue to Slack at cooldown intervals."""
        # This loop runs forever in the background.
        while True:
            now = time.time()
            # If the 'cooldown' time has passed AND there are messages waiting...
            if now - self.last_sent >= self.cooldown and self.queue:
                with self.lock:
                    # Take everything out of the queue (the batch).
                    batch = self.queue[:]
                    self.queue.clear()

                try:
                    # Send all the gathered messages to Slack in one go.
                    response = requests.post(self.webhook_url, json={"attachments": batch})
                    
                    # Error check: If Slack says we are sending too fast (Rate Limited).
                    if response.status_code == 429:
                        retry_after = response.json().get("retry_after", 1)
                        print(f"[NOTIFIER] Slack rate limited, retrying after {retry_after}s")
                        time.sleep(retry_after)
                        continue
                    # Any other error codes (like 404 or 500).
                    elif response.status_code != 200:
                        print(f"[NOTIFIER] Slack error: {response.status_code}, {response.text}")
                except Exception as e:
                    # If the internet connection fails or the URL is wrong.
                    print(f"[NOTIFIER] Failed to send Slack alert: {e}")

                self.last_sent = time.time() # Update the timer so we start a new cooldown.
            
            # Wait 1 second before checking the queue again to save CPU energy.
            time.sleep(1)