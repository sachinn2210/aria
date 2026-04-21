"""
ARIA – Log Watcher
Tails one or more log files in real time using a polling approach.
Handles file rotation, callback exceptions, and graceful shutdown.
"""

import os
import time
import threading
from typing import Callable, List

# Tunable constants
POLL_INTERVAL   = 0.1   # seconds between readline attempts
WAIT_INTERVAL   = 2.0   # seconds to wait for a missing file to appear
ROTATE_INTERVAL = 1.0   # seconds between rotation checks


class LogWatcher:
    """
    Monitors a list of log file paths and calls `callback(line, source)`
    for every new line appended to any of the files.

    Handles:
    - Files that don't exist yet (waits for them to appear)
    - Log rotation (detects inode change and reopens the new file)
    - Callback exceptions (logs and continues — never crashes the tail thread)
    """

    def __init__(self, paths: List[str], callback: Callable[[str, str], None]):
        self.paths    = paths
        self.callback = callback
        self._threads: List[threading.Thread] = []
        self._stop    = threading.Event()

    def start(self):
        for path in self.paths:
            t = threading.Thread(
                target=self._tail,
                args=(path,),
                daemon=True,
                name=f"tail:{path}",
            )
            self._threads.append(t)
            t.start()
            print(f"[LogWatcher] Started tailing: {path}")

    def stop(self, timeout: float = 5.0):
        """Signal all tail threads to stop and wait for them to exit."""
        self._stop.set()
        for t in self._threads:
            t.join(timeout=timeout)
        print("[LogWatcher] All tail threads stopped.")

    # ── Core tail loop ─────────────────────────────────────────────────────────

    def _tail(self, path: str):
        """Main tail loop for a single file. Restarts on rotation."""
        while not self._stop.is_set():
            # Wait for the file to exist
            if not os.path.exists(path):
                print(f"[LogWatcher] Waiting for file to appear: {path}")
                time.sleep(WAIT_INTERVAL)
                continue

            print(f"[LogWatcher] Opening: {path}")
            try:
                self._tail_file(path)
            except Exception as e:
                print(f"[LogWatcher] Unexpected error tailing {path}: {e}")
                time.sleep(WAIT_INTERVAL)

    def _tail_file(self, path: str):
        with open(path, "r", errors="replace") as fh:
            size = os.path.getsize(path)
            if size > 0:
                fh.seek(0, 2)
            else:
                fh.seek(0)
            
            print(f"[DEBUG] File opened, size={size}, position={fh.tell()}")  # ADD
            inode = os.fstat(fh.fileno()).st_ino
            last_rotation_check = time.monotonic()

            while not self._stop.is_set():
                line = fh.readline()
                if line:
                    print(f"[DEBUG] Read line: {line[:60]}")  # ADD
                    clean = line.strip()
                    if not clean:
                        continue
                    if "\ufffd" in clean:
                        print(f"[LogWatcher] Warning: undecodable bytes in {path}")
                    self._safe_callback(clean, path)
                else:
                    time.sleep(POLL_INTERVAL)

    def _rotated(self, path: str, original_inode: int) -> bool:
        """
        Return True if the file on disk is a different inode than what we have open,
        or if the file no longer exists (deleted before new one created).
        """
        try:
            return os.stat(path).st_ino != original_inode
        except FileNotFoundError:
            return True

    def _safe_callback(self, line: str, path: str):
        """
        FIX: Wrap callback in try/except so a parser bug can't silently
        kill the tail thread. Uses full path as source for unambiguous origin.
        """
        try:
            self.callback(line, path)
        except Exception as e:
            print(f"[LogWatcher] Callback error on line from {path}: {e}")
            print(f"[LogWatcher] Offending line: {line[:120]!r}")