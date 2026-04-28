import time
from collections import Counter # A Counter is a special dictionary that counts how many times it sees something.
from blocker import audit_log, Blocker # We bring in our logging and blocking tools from the other files.

class Detector:
    def __init__(self, baseline, z_threshold, spike_factor, ip_threshold,
                 global_threshold, error_multiplier, blocker):
        """
        Detector checks traffic against baseline stats using config-driven thresholds.
        """
        # We save all the "rules" from our config file into the detector.
        self.baseline = baseline
        self.z_threshold = z_threshold
        self.spike_factor = spike_factor
        self.ip_threshold = ip_threshold
        self.global_threshold = global_threshold
        self.error_multiplier = error_multiplier

        self.anomalies = []          # A list to keep a history of "weird" events.
        self.traffic_history = []    # A list of numbers to draw the chart on the dashboard.
        self.ip_counts = Counter()   # This counts requests per IP (e.g., {"1.2.3.4": 50}).
        self.blocker = blocker       # The "Security Guard" we talk to when we want to ban someone.

    def record_traffic(self, value, ip=None):
        """Store traffic values for dashboard charts and update IP counts."""
        self.traffic_history.append(value) # Add the latest RPS (Requests Per Second) to history.
        
        # If the history gets too long (over 1000 entries), remove the oldest one to save memory.
        if len(self.traffic_history) > 1000:
            self.traffic_history.pop(0) 
            
        if ip:
            self.ip_counts[ip] += 1 # If an IP is provided, increase its specific counter by 1.

    def current_rps(self):
        """Return latest requests per second sample."""
        # This returns the very last number added to our history.
        return self.traffic_history[-1] if self.traffic_history else 0

    def top_ips(self, n=10):
        """Return top N source IPs by request count."""
        # This looks at our Counter and gives us the top 10 most active users.
        return [ip for ip, _ in self.ip_counts.most_common(n)]

    def check_global_anomaly(self, current_rate):
        """Check global traffic against baseline."""
        # Get the "Normal" average and variation from the baseline tool.
        mean = self.baseline.effective_mean()
        stddev = self.baseline.effective_stddev()

        # Math check: The Z-Score tells us how many "standard deviations" we are away from normal.
        z_score = 0 if stddev == 0 else (current_rate - mean) / stddev

        # Test 1: Is the Z-Score too high? (Is the math too weird?)
        if z_score > self.z_threshold:
            reason = f"Global anomaly: z-score={z_score:.2f} > {self.z_threshold}"
            self.anomalies.append(reason)
            return True, reason

        # Test 2: Is there a sudden spike? (Is it 5x higher than average?)
        if mean > 0 and current_rate > mean * self.spike_factor:
            reason = f"Global anomaly: rate={current_rate} > {self.spike_factor}×mean={mean:.2f}"
            self.anomalies.append(reason)
            return True, reason

        # Test 3: Did we cross a hard limit? (Regardless of average, is it just "too much"?)
        if current_rate > self.global_threshold:
            reason = f"Global anomaly: {current_rate} > threshold {self.global_threshold}"
            self.anomalies.append(reason)
            return True, reason

        return False, "normal"

    def check_ip_anomaly(self, ip, ip_count):
        """Check per-IP anomaly."""
        # This checks if one specific person is asking for too much stuff.
        if ip_count > self.ip_threshold:
            reason = f"IP {ip} anomaly: {ip_count} > threshold {self.ip_threshold}"
            self.anomalies.append(reason)
            return True, reason

        return False, "normal"

    def check_error_surge(self, ip, ip_error_rate, baseline_error_rate):
        """
        If an IP’s error rate is 3x the baseline error rate,
        tighten thresholds and log the event.
        """
        # This looks for "Scanning" behavior (where an attacker hits many pages that don't exist).
        if ip_error_rate >= 3 * baseline_error_rate:
            reason = f"Error surge: IP {ip} error rate={ip_error_rate:.2f} >= 3×baseline={baseline_error_rate:.2f}"
            self.anomalies.append(reason)
            print(f"[DETECTOR] {reason}")
            
            # Write this to our audit file.
            audit_log("ERROR_SURGE", ip=ip,
                      condition="error rate 3x baseline",
                      rate=ip_error_rate,
                      baseline=baseline_error_rate)
            
            # Command the 'Blocker' to ban this IP immediately for suspicious errors.
            self.blocker.block_ip(ip,
                                  condition="error surge",
                                  rate=ip_error_rate,
                                  baseline=baseline_error_rate)
            return True, reason
        return False, "normal"