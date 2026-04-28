# 'logging' for saving records, 'time' for timestamps, and 'subprocess' to talk to the computer's system.
import logging
import time
import subprocess

# Configure audit logging: Sets up a text file called "audit.log" to track every ban and unban.
logging.basicConfig(filename="audit.log", level=logging.INFO, format="%(message)s")

# A helper function that formats information into a nice, readable line for our log file.
def audit_log(action, ip=None, condition=None, rate=None, baseline=None, duration=None):
    """Write structured audit log entries."""
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    entry = f"[{timestamp}] {action} {ip or '-'} | {condition or '-'} | {rate or '-'} | {baseline or '-'} | {duration or '-'}"
    logging.info(entry)

# The 'Blocker' class acts like a digital security guard for your server.
class Blocker:
    def __init__(self, notifier, ban_durations=[600, 1800, 7200]):
        """
        Blocker handles IP bans using iptables.
        - notifier: a tool used to send alerts (like to a Slack channel).
        - ban_durations: a list of "time-outs" (in seconds) that get longer if someone keeps breaking rules.
        """
        self.blocked_ips = set()            # A 'set' is a list of unique items; we store blocked IPs here.
        self.ban_durations = ban_durations  # Default: 10 mins, 30 mins, or 2 hours.
        self.notifier = notifier            # This lets the blocker "speak" to your notification system.

        # Ensure baseline firewall policy allows Docker traffic
        try:
            subprocess.run(["sudo", "iptables", "-P", "FORWARD", "ACCEPT"], check=True)
            print("[BLOCKER] Reset FORWARD chain policy to ACCEPT (safe baseline)")
        except Exception as e:
            print(f"[BLOCKER] Failed to reset FORWARD policy: {e}")

    def _iptables_block(self, ip):
        """Apply iptables DROP rule for given IP (host-level enforcement)."""
        try:
            # 🔥 CRITICAL FIX: Block NEW connections at host entry point (pre-Docker)
            subprocess.run([
                "sudo", "iptables",
                "-I", "INPUT", "1",
                "-m", "conntrack", "--ctstate", "NEW",
                "-s", ip,
                "-j", "DROP"
            ], check=True)

            print(f"[BLOCKER] DROP rule inserted for {ip} in INPUT (conntrack NEW)")
        except Exception as e:
            print(f"[BLOCKER] Failed to block {ip}: {e}")

    def _iptables_unblock(self, ip):
        """Remove iptables DROP rule for given IP (host-level enforcement)."""
        try:
            subprocess.run([
                "sudo", "iptables",
                "-D", "INPUT",
                "-m", "conntrack", "--ctstate", "NEW",
                "-s", ip,
                "-j", "DROP"
            ], check=True)

            print(f"[BLOCKER] DROP rule removed for {ip} from INPUT")
        except Exception as e:
            print(f"[BLOCKER] Failed to unblock {ip}: {e}")

    def block_ip(self, ip, condition="threshold exceeded", rate=None, baseline=None, offense=0):
        """Block an IP using iptables + audit + Slack."""
        if ip not in self.blocked_ips:
            self.blocked_ips.add(ip)
            duration = self.ban_durations[min(offense, len(self.ban_durations)-1)]
            print(f"[BLOCKER] Blocking IP {ip}. Ban duration: {duration}s")

            self._iptables_block(ip)
            audit_log("BAN", ip=ip, condition=condition, rate=rate, baseline=baseline, duration=duration)
            self.notifier.send_ban(ip, duration, reason=condition)
        else:
            print(f"[BLOCKER] IP {ip} is already blocked")

    def unblock_ip(self, ip):
        """Unblock an IP using iptables + audit + Slack."""
        if ip in self.blocked_ips:
            self.blocked_ips.remove(ip)
            print(f"[BLOCKER] Unblocking IP {ip}")

            self._iptables_unblock(ip)
            audit_log("UNBAN", ip=ip, condition="timeout expired")
            self.notifier.send_unban(ip, reason="ban expired")
        else:
            print(f"[BLOCKER] IP {ip} is not currently blocked")