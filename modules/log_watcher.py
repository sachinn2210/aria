"""
ARIA – Log Watcher
Uses the Watchdog library to tail one or more log files in real time.
Falls back to a simple polling tail if Watchdog is unavailable.
"""

import os
import time
import threading
from typing import Callable, List


class LogWatcher:
    """
    Monitors a list of log file paths and calls `callback(line, source)`
    for every new line appended to any of the files.
    """

    def __init__(self, paths: List[str], callback: Callable[[str, str], None]):
        self.paths    = paths
        self.callback = callback
        self._threads: List[threading.Thread] = []
        self._stop    = threading.Event()

    def start(self):
        for path in self.paths:
            t = threading.Thread(
                target=self._tail, args=(path,), daemon=True, name=f"tail:{path}"
            )
            self._threads.append(t)
            t.start()

    def stop(self):
        self._stop.set()

    # ── Core tail loop ─────────────────────────────────────────────────────────

    def _tail(self, path: str):
        """Tail a single file, blocking until new lines appear."""
        # Wait for the file to exist (useful during demo / tests)
        waited = 0
        while not os.path.exists(path):
            if self._stop.is_set():
                return
            time.sleep(1)
            waited += 1
            if waited > 30:
                print(f"[ARIA] Watcher: {path} not found after 30 s, giving up.")
                return

        source = os.path.basename(path)
        print(f"[ARIA] Watching {path}")

        with open(path, "r", errors="replace") as fh:
            # Seek to end so we only see new lines
            fh.seek(0, 2)
            while not self._stop.is_set():
                line = fh.readline()
                if line:
                    self.callback(line, source)
                else:
                    time.sleep(0.1)   # 100 ms poll interval
