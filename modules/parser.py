"""
ARIA – Log Parser
Converts raw log lines into a normalized event dict.
Supports: Linux auth.log, Apache/Nginx access logs, Windows Event Logs (text export).
"""

import re
from datetime import datetime
from typing import Optional

# ── Regex patterns ─────────────────────────────────────────────────────────────

AUTH_PATTERN = re.compile(
    r"(?P<month>\w{3})\s+(?P<day>\d+)\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<service>[^\[\s]+)(?:\[(?P<pid>\d+)\])?:\s+(?P<message>.+)"
)

APACHE_PATTERN = re.compile(
    r'(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<datetime>[^\]]+)\]\s+'
    r'"(?P<method>\S+)\s+(?P<path>\S+)\s+\S+"\s+'
    r'(?P<status>\d{3})\s+(?P<size>\S+)'
)

# FIX: Split WIN_PATTERN into focused per-field patterns to avoid slow DOTALL .*?
WIN_EVENTID  = re.compile(r"EventID:\s*(?P<eid>\d+)")
WIN_USER     = re.compile(r"Account Name:\s*(?P<user>\S+)")
WIN_IP       = re.compile(r"Source Address:\s*(?P<ip>[\d.]+)")

# FIX: Validated IP regex — rejects octets > 255
IP_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b"
)

# Path traversal variants including encoded forms
TRAVERSAL_RE = re.compile(
    r"\.\./|\.\.%2f|%2e%2e[%/\\]|%252e%252e|\.\.%5c",
    re.IGNORECASE
)

# SQL injection signal patterns in query strings
SQLI_RE = re.compile(
    r"(?:'|%27|--|%3B|union\s+select|select\s+\*|drop\s+table)",
    re.IGNORECASE
)


class LogParser:
    def parse(self, raw_line: str, source: str = "") -> Optional[dict]:
        raw_line = raw_line.strip()
        if not raw_line:
            return None

        event = {
            "timestamp":      datetime.utcnow().isoformat(),
            "source":         source,
            "raw_log":        raw_line,
            "source_ip":      "",
            "target_service": "",
            "attack_type":    "",
            "mitre_tag":      "",
            "anomaly_score":  0.0,
            "severity":       "LOW",
            "llm_summary":    "",
            "extra":          {},
        }

        if self._try_auth(raw_line, event):
            return event
        if self._try_apache(raw_line, event):
            return event
        if self._try_windows(raw_line, event):
            return event

        # Generic fallback: only return an event if we find at least an IP
        ips = IP_RE.findall(raw_line)
        if ips:
            event["source_ip"]      = ips[0]
            event["target_service"] = "unknown"
            return event

        # FIX: Return None for lines with no parseable content — don't pollute DB
        return None

    # ── Parser helpers ─────────────────────────────────────────────────────────

    def _try_auth(self, line: str, event: dict) -> bool:
        m = AUTH_PATTERN.match(line)
        if not m:
            return False

        msg     = m.group("message")
        msg_l   = msg.lower()
        # FIX: service name is now cleanly captured without bracket contamination
        event["target_service"] = m.group("service")

        ips = IP_RE.findall(msg)
        if ips:
            event["source_ip"] = ips[0]

        if "failed password" in msg_l or "authentication failure" in msg_l:
            event["attack_type"] = "Brute Force"
        elif "invalid user" in msg_l:
            event["attack_type"] = "Invalid User"
        elif "accepted password" in msg_l or "accepted publickey" in msg_l:
            event["attack_type"] = "Successful Login"
        elif "sudo" in msg_l:
            event["attack_type"] = "Privilege Escalation"
        else:
            event["attack_type"] = "Failed Login"

        event["extra"] = {
            "host":    m.group("host"),
            "pid":     m.group("pid") or "",
            "message": msg,
        }
        # FIX: Pass month name for year-rollover-aware timestamp parsing
        event["timestamp"] = _auth_ts(m)
        return True

    def _try_apache(self, line: str, event: dict) -> bool:
        m = APACHE_PATTERN.match(line)
        if not m:
            return False

        status    = int(m.group("status"))
        path      = m.group("path")
        path_l    = path.lower()

        event["source_ip"]      = m.group("ip")
        event["target_service"] = "http"
        event["extra"] = {
            "method": m.group("method"),
            "path":   path,
            "status": status,
        }

        # FIX: Check specific attack types before generic status codes
        # so a traversal returning 500 isn't swallowed as "Server Error"
        if TRAVERSAL_RE.search(path):
            event["attack_type"] = "Path Traversal"
        elif SQLI_RE.search(path):
            # FIX: Detect SQL injection attempts missed in original
            event["attack_type"] = "SQL Injection"
        elif status >= 500:
            event["attack_type"] = "Server Error"
        elif status == 404 and any(
            x in path_l for x in [".php", ".env", ".git", "admin", "wp-"]
        ):
            event["attack_type"] = "Directory Enumeration"
        elif status in (401, 403):
            event["attack_type"] = "Unauthorized Access"
        else:
            event["attack_type"] = "HTTP Request"

        return True

    def _try_windows(self, line: str, event: dict) -> bool:
        eid_m  = WIN_EVENTID.search(line)
        if not eid_m:
            return False

        # FIX: Parse fields independently — no slow DOTALL .*? backtracking
        user_m = WIN_USER.search(line)
        ip_m   = WIN_IP.search(line)

        eid = int(eid_m.group("eid"))
        event["source_ip"]      = ip_m.group("ip")   if ip_m   else ""
        event["target_service"] = "windows"
        event["extra"] = {
            "user":     user_m.group("user") if user_m else "",
            "event_id": eid,
        }

        eid_map = {
            4625: "Failed Login",
            4624: "Successful Login",
            4672: "Privilege Escalation",
            4648: "Explicit Credential Use",
            4768: "Kerberos TGT Request",
        }
        event["attack_type"] = eid_map.get(eid, f"Windows Event {eid}")
        return True


# ── Helpers ────────────────────────────────────────────────────────────────────

def _auth_ts(m) -> str:
    """
    Best-effort timestamp from auth.log (no year in format).
    FIX: Handles year rollover — if the parsed month is ahead of the current
    month, the log line is from the previous year (e.g. Dec log read in Jan).
    """
    now   = datetime.utcnow()
    year  = now.year
    raw   = f"{year} {m.group('month')} {m.group('day')} {m.group('time')}"
    try:
        dt = datetime.strptime(raw, "%Y %b %d %H:%M:%S")
        # If the resulting timestamp is more than 7 days in the future, it's
        # a December log being read in January — subtract one year
        if (dt - now).days > 7:
            dt = dt.replace(year=year - 1)
        return dt.isoformat()
    except ValueError:
        return now.isoformat()