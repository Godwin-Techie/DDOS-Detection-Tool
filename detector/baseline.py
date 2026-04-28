# 'import' brings in pre-made toolkits to help our code do more.
import time          # Used for tracking time and dates.
import statistics    # Used for calculating averages and math patterns.
import logging       # Used for writing records to a file.
from collections import deque  # A 'deque' is a special list that's very fast at adding/removing items.

# Configure audit logging: This sets up a file named "audit.log" where our program will write notes.
logging.basicConfig(
    filename="audit.log",
    level=logging.INFO,
    format="%(message)s"
)

# This function creates a standardized text entry to save in our log file.
def audit_log(action, ip=None, condition=None, rate=None, baseline=None, duration=None):
    """Write structured audit log entries."""
    # Get the current time and turn it into a readable format (Year-Month-Day Hour:Minute:Second).
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    # Combine all the info into one string, using a "-" if a piece of info is missing.
    entry = f"[{timestamp}] {action} {ip or '-'} | {condition or '-'} | {rate or '-'} | {baseline or '-'} | {duration or '-'}"
    # Save the string into the log file.
    logging.info(entry)


# A 'Class' is a blueprint for an object. Here, 'Baseline' tracks "normal" website traffic.
class Baseline:
    def __init__(self, window=1800, recalc_interval=None):
        """
        Rolling baseline for traffic analysis.
        """
        self.window = window  # How many seconds of history we want to remember (default is 1800s / 30m).
        self.recalc_interval = recalc_interval
        self.counts = deque()  # A list that will store pairs of (time, number_of_requests).
        self.last_recalc = time.time() # Keeps track of the last time we updated our math.

    def add_count(self, count):
        """
        Add a new per-second request count.
        """
        ts = time.time()  # Get the current time.
        self.counts.append((ts, count))  # Add the new traffic data to our list.

        # "Evict" or remove data that is older than our 'window' (e.g., older than 30 minutes).
        # This keeps the memory usage low and the data relevant.
        while self.counts and self.counts[0][0] < ts - self.window:
            self.counts.popleft() # Remove the oldest item from the left side of the list.

    def effective_mean(self):
        """Calculate average requests per second over the rolling window."""
        if not self.counts:
            return 0.0 # If no data exists, the average is zero.
        # Extract just the numbers (counts) from our (time, count) pairs.
        values = [c for _, c in self.counts]
        return statistics.mean(values) # Return the mathematical average.

    def effective_stddev(self):
        """Calculate standard deviation of requests per second."""
        # Standard deviation measures how much the traffic "swings" or varies.
        if len(self.counts) < 2:
            return 0.0 # We need at least two numbers to calculate a variation.
        values = [c for _, c in self.counts]
        return statistics.pstdev(values)  # 'pstdev' calculates the standard deviation for the whole group.

    def size(self):
        """Return number of entries currently in the window."""
        return len(self.counts) # Tell us how many data points we have collected so far.

    def values(self):
        """Return list of counts for debugging or dashboarding."""
        # This just gives us a clean list of the traffic numbers without the timestamps.
        return [c for _, c in self.counts]

    def recalculate(self):
        """
        Recalculate baseline stats and log the event.
        """
        # Run the math functions defined above.
        mean = self.effective_mean()
        stddev = self.effective_stddev()
        # Record the new "Normal" traffic levels in the log file.
        audit_log("BASELINE_RECALC", baseline=f"mean={mean:.2f}, stddev={stddev:.2f}")
        self.last_recalc = time.time() # Reset the timer for the next recalculation.
        return mean, stddev