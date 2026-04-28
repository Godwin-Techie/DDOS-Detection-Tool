from collections import deque # 'deque' is a fast list that lets us add/remove items from both ends easily.
import time # Used to get the current system time.

class SlidingWindow:
    def __init__(self, window_size=60):
        # We store (timestamp, count) pairs. 
        # For example: (1714400000, 5) means 5 requests happened at that specific second.
        self.window = deque()
        self.window_size = window_size # Default is 60 seconds.

    def add(self, count=1):
        """Add a new request count for the current second."""
        now = int(time.time()) # Get current time as a whole number (seconds).

        # Check if we already have an entry for this exact second.
        if self.window and self.window[-1][0] == now:
            # If we do, take it out, add the new count to it, and put it back.
            ts, c = self.window.pop()
            self.window.append((ts, c + count))
        else:
            # If this is a new second, just add it to the list.
            self.window.append((now, count))
        
        # Clean up the list so we don't remember things from a long time ago.
        self._evict_old(now)

    def _evict_old(self, now):
        """Remove entries older than window_size seconds."""
        # While there is data in our list AND the oldest item is too old...
        while self.window and now - self.window[0][0] >= self.window_size:
            # ...remove the oldest item from the left (front) of the list.
            self.window.popleft()

    def rate(self):
        """Return total requests in the window."""
        # Add up all the 'counts' currently in our list to see the total traffic.
        return sum(c for _, c in self.window)

    def per_second_counts(self):
        """Return list of counts per second in the window."""
        # Create a simple list of just the numbers (counts) without the time labels.
        return [c for _, c in self.window]