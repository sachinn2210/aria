"""
ARIA – Real Log Ingestion
Provides three ingestion methods:
  1. Windows Event Log reader (pywin32, Windows only)
  2. Log file upload parser  (paste / upload any log text)
  3. URL-based log fetcher   (fetch raw logs exposed over HTTP)
"""

import os
import re
import sys
import platform
from datetime import datetime
from typing import Generator


# ── 1. Windows Event Log ───────────────────────────────────────────────────────

def is_windows() -> bool:
    return platform.system() == "Windows"


def read_windows_event_logs(
    log_name: str = "Security",
    max_events: int = 200,
    event_ids: list = None,
) -> Generator[str, None, None]:
    """
    Yield Windows Event Log entries as text lines (Apache-ish format).
    Requires: pip install pywin32  (Windows only)

    Yields fake-Apache lines that ARIA's parser can handle via _try_windows().
    """
    if not is_windows():
        yield "# Windows Event Log reader: not running on Windows"
        return

    try:
        import win32evtlog
        import win32con
        import winerror
    except ImportError:
        yield "# pywin32 not installed. Run: pip install pywin32"
        return

    if event_ids is None:
        event_ids = {4624, 4625, 4648, 4672, 4768, 4769, 4771}
    else:
        event_ids = set(event_ids)

    try:
        hand = win32evtlog.OpenEventLog(None, log_name)
        flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
        count = 0

        while count < max_events:
            events = win32evtlog.ReadEventLog(hand, flags, 0)
            if not events:
                break

            for ev in events:
                if ev.EventID not in event_ids:
                    continue

                ts  = ev.TimeGenerated.Format()
                eid = ev.EventID
                src = ev.SourceName
                # Extract strings from the event
                strs = list(ev.StringInserts or [])

                # Build a ARIA-parseable Windows-style line
                user_str = strs[5] if len(strs) > 5 else ""
                ip_str   = strs[18] if len(strs) > 18 else strs[-1] if strs else "0.0.0.0"
                ip_str   = ip_str.strip() if ip_str and ip_str.strip() not in ("-", "") else "0.0.0.0"

                line = (
                    f"TimeCreated: {ts} "
                    f"EventID: {eid} "
                    f"Source: {src} "
                    f"Account Name: {user_str} "
                    f"Source Address: {ip_str} "
                    f"Strings: {' | '.join(str(s) for s in strs[:8])}"
                )
                yield line
                count += 1
                if count >= max_events:
                    break

        win32evtlog.CloseEventLog(hand)

    except Exception as e:
        yield f"# Windows Event Log error: {e}"


# ── 2. Uploaded / Pasted Log Text ─────────────────────────────────────────────

# Known formats and their patterns for identification
_FORMAT_HINTS = [
    ("auth.log",   re.compile(r"\b(sshd|sudo|su)\[\d+\]:")),
    ("apache",     re.compile(r'"\w+ /\S+ HTTP/\d\.\d" \d{3}')),
    ("nginx",      re.compile(r'"\w+ /\S+ HTTP/\d\.\d" \d{3}')),
    ("windows",    re.compile(r"EventID:\s*\d+")),
    ("iis",        re.compile(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} \S+ \S+ \w+ /\S+ ")),
    ("syslog",     re.compile(r"\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2}\s+\S+")),
    ("csv",        re.compile(r"^\d{4}-\d{2}-\d{2}[T,]")),
    ("generic",    re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")),
]


def detect_log_format(sample: str) -> str:
    """Best-guess the log format from a sample of lines."""
    for fmt, pattern in _FORMAT_HINTS:
        if pattern.search(sample):
            return fmt
    return "unknown"


def parse_uploaded_log(text: str, source_tag: str = "upload") -> list[dict]:
    """
    Parse a block of pasted/uploaded log text.
    Returns list of raw line strings ready for ARIA's parser.
    Handles mixed formats, skips blanks and comment lines.
    """
    lines = []
    for raw in text.splitlines():
        raw = raw.strip()
        if not raw or raw.startswith("#"):
            continue
        lines.append(raw)
    return lines


def save_uploaded_log(text: str, filename: str = None) -> str:
    """
    Save uploaded log text to the logs/ directory so LogWatcher can pick it up.
    Returns the path written to.
    """
    os.makedirs("logs", exist_ok=True)
    if not filename:
        ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        filename = f"uploaded_{ts}.log"

    # Sanitise filename
    filename = re.sub(r"[^\w\-_\.]", "_", filename)
    if not filename.endswith(".log"):
        filename += ".log"

    path = os.path.join("logs", filename)
    with open(path, "a") as f:
        f.write(text.rstrip() + "\n")
        f.flush()
    return path


# ── 3. URL-based Log Fetcher ───────────────────────────────────────────────────

def fetch_remote_log(url: str, timeout: int = 10) -> dict:
    """
    Fetch a plaintext log file exposed over HTTP/HTTPS.
    Returns {"ok": True, "lines": [...], "format": "...", "count": N}
    or      {"ok": False, "error": "..."}
    """
    import urllib.request

    try:
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "ARIA-LogFetcher/1.0"},
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            content_type = resp.headers.get("Content-Type", "")
            if "html" in content_type.lower():
                return {
                    "ok":    False,
                    "error": "URL returned HTML, not a log file. "
                             "Paste the log content directly instead.",
                }
            raw = resp.read().decode("utf-8", errors="replace")

        lines = parse_uploaded_log(raw, source_tag=url)
        fmt   = detect_log_format(raw[:2000])

        return {
            "ok":     True,
            "lines":  lines,
            "format": fmt,
            "count":  len(lines),
            "url":    url,
        }

    except Exception as e:
        return {"ok": False, "error": str(e)}


# ── Convenience: ingest a block of text directly into ARIA ────────────────────

def ingest_log_text(text: str, callback, source_tag: str = "upload"):
    """
    Parse text and fire the ARIA callback for each line.
    `callback` is the same on_new_log_line(line, source) from app.py.
    Returns number of lines processed.
    """
    lines = parse_uploaded_log(text, source_tag)
    for line in lines:
        try:
            callback(line, source_tag)
        except Exception as e:
            print(f"[ARIA/Ingest] Error processing line: {e}")
    return len(lines)