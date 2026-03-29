"""
ARIA – Log Parser
Converts raw log lines into a normalized event dict.
Supports: Linux auth.log, Apache/Nginx access logs, Windows Event Logs (text export).
"""

import re
from datetime import datetime
from typing import Optional

# ── Regex patterns ─────────────────────────────────────────────────────────────

# auth.log  →  May 10 14:23:01 hostname sshd[1234]: Failed password for root from 1.2.3.4 port 22 ssh2
AUTH_PATTERN = re.compile(
    r"(?P<month>\w{3})\s+(?P<day>\d+)\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<service>\S+)\[?(?P<pid>\d*)\]?:\s+(?P<message>.+)"
)

# Apache/Nginx combined log format
APACHE_PATTERN = re.compile(
    r'(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<datetime>[^\]]+)\]\s+'
    r'"(?P<method>\S+)\s+(?P<path>\S+)\s+\S+"\s+'
    r'(?P<status>\d{3})\s+(?P<size>\S+)'
)

# Windows Event Log text export (EventID-based)
WIN_PATTERN = re.compile(
    r"EventID:\s*(?P<eid>\d+).*?Account Name:\s*(?P<user>\S+).*?Source Address:\s*(?P<ip>[\d.]+)",
    re.DOTALL,
)

# IP extraction fallback
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


class LogParser:
    def parse(self, raw_line: str, source: str = "") -> Optional[dict]:
        raw_line = raw_line.strip()
        if not raw_line:
            return None

        event = {
            "timestamp": datetime.utcnow().isoformat(),
            "source": source,
            "raw_log": raw_line,
            "source_ip": "",
            "target_service": "",
            "attack_type": "",
            "mitre_tag": "",
            "anomaly_score": 0.0,
            "severity": "LOW",
            "llm_summary": "",
            "extra": {},
        }

        # Try each pattern in priority order
        if self._try_auth(raw_line, event):
            pass
        elif self._try_apache(raw_line, event):
            pass
        elif self._try_windows(raw_line, event):
            pass
        else:
            # Generic fallback: extract IPs if any
            ips = IP_RE.findall(raw_line)
            if ips:
                event["source_ip"] = ips[0]
            event["target_service"] = "unknown"

        return event

    # ── Parser helpers ─────────────────────────────────────────────────────────

    def _try_auth(self, line: str, event: dict) -> bool:
        m = AUTH_PATTERN.match(line)
        if not m:
            return False
        msg = m.group("message")
        event["target_service"] = m.group("service").split("[")[0]

        ips = IP_RE.findall(msg)
        if ips:
            event["source_ip"] = ips[0]

        # Classify action
        msg_lower = msg.lower()
        if "failed password" in msg_lower or "authentication failure" in msg_lower:
            event["attack_type"] = "Brute Force"
        elif "accepted password" in msg_lower or "accepted publickey" in msg_lower:
            event["attack_type"] = "Successful Login"
        elif "invalid user" in msg_lower:
            event["attack_type"] = "Invalid User"
        elif "sudo" in msg_lower:
            event["attack_type"] = "Privilege Escalation"

        event["extra"] = {
            "host": m.group("host"),
            "pid": m.group("pid"),
            "message": msg,
        }
        event["timestamp"] = _auth_ts(m)
        return True

    def _try_apache(self, line: str, event: dict) -> bool:
        m = APACHE_PATTERN.match(line)
        if not m:
            return False
        status = int(m.group("status"))
        path   = m.group("path")
        event["source_ip"]      = m.group("ip")
        event["target_service"] = "http"
        event["extra"] = {
            "method": m.group("method"),
            "path": path,
            "status": status,
        }

        # Classify
        path_lower = path.lower()
        if status >= 500:
            event["attack_type"] = "Server Error"
        elif status == 404 and any(x in path_lower for x in [".php", ".env", ".git", "admin", "wp-"]):
            event["attack_type"] = "Directory Enumeration"
        elif "../" in path or "%2e%2e" in path_lower:
            event["attack_type"] = "Path Traversal"
        elif status == 401 or status == 403:
            event["attack_type"] = "Unauthorized Access"
        else:
            event["attack_type"] = "HTTP Request"
        return True

    def _try_windows(self, line: str, event: dict) -> bool:
        m = WIN_PATTERN.search(line)
        if not m:
            return False
        eid = int(m.group("eid"))
        event["source_ip"]      = m.group("ip")
        event["target_service"] = "windows"
        event["extra"] = {"user": m.group("user"), "event_id": eid}

        eid_map = {
            4625: "Failed Login",
            4624: "Successful Login",
            4672: "Privilege Escalation",
            4648: "Explicit Credential Use",
            4768: "Kerberos TGT Request",
        }
        event["attack_type"] = eid_map.get(eid, f"Windows Event {eid}")
        return True


def _auth_ts(m) -> str:
    """Best-effort timestamp from auth.log (no year → use current year)."""
    year = datetime.utcnow().year
    raw  = f"{year} {m.group('month')} {m.group('day')} {m.group('time')}"
    try:
        return datetime.strptime(raw, "%Y %b %d %H:%M:%S").isoformat()
    except ValueError:
        return datetime.utcnow().isoformat()
