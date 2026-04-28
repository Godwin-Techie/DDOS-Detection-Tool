import json
import time
from collections import defaultdict, deque

# These are the default "hard" limits if no config file is used.
LOGFILE = "/var/log/nginx/hng-access.log"
WINDOW = 60              # We only care about requests that happened in the last 60 seconds.
IP_THRESHOLD = 20        # Max requests allowed per person in that 60s window.
GLOBAL_THRESHOLD = 50    # Max total requests allowed on the whole server in that 60s window.

# 'defaultdict(deque)' creates a dictionary where every new IP gets its own fast-acting list (deque).
# Example: {"1.2.3.4": [timestamp1, timestamp2]}
requests_per_ip = defaultdict(deque)

def tail_log(file_path=LOGFILE):
    """Generator that yields new log lines as they are written."""
    # This works like the 'tail -f' command in Linux.
    with open(file_path, "r") as f:
        f.seek(0, 2)  # Start at the very end of the file (ignore old history).
        while True:
            line = f.readline()
            if line:
                yield line.strip() # Give the next line to the program.
            else:
                time.sleep(0.5) # If the file is quiet, wait half a second before checking again.

def process_log_line(line):
    """Parse a JSON log line and update per-IP request counts."""
    try:
        # We assume the Nginx logs are in JSON format (like a dictionary).
        data = json.loads(line)
        ip = data.get("remote_addr")    # The visitor's address.
        method = data.get("request_method") # GET, POST, etc.
        path = data.get("request")      # The page they visited.
        ts = time.time()                # The exact time this log was processed.

        print(f"[INFO] {ip} -> {method} {path}")

        if ip:
            # 1. Add the current time (timestamp) to this specific IP's list.
            requests_per_ip[ip].append(ts)
            
            # 2. Cleanup: Remove any timestamps that are older than 60 seconds (WINDOW).
            # This is the "Sliding Window"—we only keep the most recent data.
            while requests_per_ip[ip] and requests_per_ip[ip][0] < ts - WINDOW:
                requests_per_ip[ip].popleft()

            # 3. Quick Check: If this one IP has too many timestamps in the list, alert!
            if len(requests_per_ip[ip]) > IP_THRESHOLD:
                print(f"[ALERT] Possible DDoS from {ip}: {len(requests_per_ip[ip])} requests in {WINDOW}s")

        # 4. Global Check: Add up the number of requests from EVERY IP combined.
        total_requests = sum(len(q) for q in requests_per_ip.values())
        if total_requests > GLOBAL_THRESHOLD:
            print(f"[ALERT] Global traffic spike: {total_requests} requests in {WINDOW}s")

    except Exception as e:
        # If a line is messy or not JSON, we skip it and print an error.
        print(f"[MONITOR] Failed to parse line: {e}")