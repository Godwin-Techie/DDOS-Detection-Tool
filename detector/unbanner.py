import threading # Used to run timers in the background without stopping the whole program.

class Unbanner:
    def __init__(self, blocker, notifier, schedule):
        """
        Args:
            blocker: The Blocker tool that handles the actual firewall rules.
            notifier: The Notifier tool for sending Slack alerts.
            schedule: A list of wait times (e.g., [600, 1800, 7200]) for each offense.
        """
        self.blocker = blocker
        self.notifier = notifier
        # This 'schedule' tells the program how many seconds to wait for the 1st, 2nd, and 3rd ban.
        self.schedule = schedule  # This data is pulled from your config.yml file.
        self.offense_count = {}  # A dictionary to remember how many times an IP has been naughty (ip -> number).

    def schedule_unblock(self, ip):
        """Schedule an unblock with progressive backoff, or permanent ban."""
        # Check how many times this IP has been blocked before. Default to 0.
        count = self.offense_count.get(ip, 0)

        # If they haven't run out of "chances" in our schedule list:
        if count < len(self.schedule):
            # Pick the wait time based on their current offense number.
            timeout = self.schedule[count]
            # Update their record to show they've committed one more offense.
            self.offense_count[ip] = count + 1
            
            print(f"[UNBANNER] Scheduled unblock of {ip} in {timeout} seconds (offense #{count+1})")
            
            # Create a "Timer". This tells Python: "Wait 'timeout' seconds, then run the unblock_ip function."
            t = threading.Timer(timeout, self.unblock_ip, [ip])
            t.daemon = True # This ensures the timer closes if you stop the main program.
            t.start() # Start the countdown.
        else:
            # If they have broken the rules more times than we have wait-times for, it's a permanent ban.
            self.offense_count[ip] = count + 1
            print(f"[UNBANNER] {ip} has reached permanent ban (offense #{count+1})")
            
            # Send a specific Slack alert to let you know this IP is gone for good.
            # We use '-1' to symbolize "forever."
            self.notifier.send_ban(ip, duration=-1, reason="permanent ban")

    def unblock_ip(self, ip):
        """Actually unblock the IP (simulated)."""
        # Call the blocker module to remove the 'iptables' rule.
        self.blocker.unblock_ip(ip)
        print(f"[UNBANNER] Auto-unblocked IP {ip}")

        # Send a final Slack notification so you know the user is allowed back in.
        self.notifier.send_unban(ip, reason="ban expired")