"""
ARIA – Event Correlator
Rule-based engine that maps parsed log events to MITRE ATT&CK techniques
and decides whether to raise an incident alert.
"""

from typing import Optional
from collections import defaultdict
from datetime import datetime, timedelta

# MITRE ATT&CK tag definitions
MITRE_MAP = {
    "Brute Force":            ("T1110", "Brute Force"),
    "Invalid User":           ("T1110.001", "Password Guessing"),
    "Privilege Escalation":   ("T1548", "Abuse Elevation Control Mechanism"),
    "Path Traversal":         ("T1083", "File and Directory Discovery"),
    "Directory Enumeration":  ("T1083", "File and Directory Discovery"),
    "Unauthorized Access":    ("T1078", "Valid Accounts"),
    "Successful Login":       ("T1078", "Valid Accounts"),
    "Explicit Credential Use":("T1078.003", "Local Accounts"),
    "Failed Login":           ("T1110", "Brute Force"),
    "Kerberos TGT Request":   ("T1558.003", "Kerberoasting"),
    "Server Error":           ("T1499", "Endpoint Denial of Service"),
}

# Score thresholds to raise an alert per attack type
ALERT_THRESHOLDS = {
    "Brute Force": 0.35,
    "Invalid User": 0.30,
    "Privilege Escalation": 0.20,
    "Path Traversal": 0.25,
    "Directory Enumeration": 0.30,
    "Unauthorized Access": 0.25,
    "Successful Login": 0.70,   # only flag if very anomalous (off-hours, etc.)
    "Server Error": 0.50,
}

DEFAULT_THRESHOLD = 0.40


class EventCorrelator:
    def __init__(self):
        # ip → deque of recent timestamps for burst detection
        self._ip_events: dict[str, list] = defaultdict(list)

    def correlate(self, event: dict) -> Optional[dict]:
        """
        Evaluate the event against rules.
        Returns an incident dict if the event should trigger an alert, else None.
        """
        attack_type = event.get("attack_type", "")
        score       = float(event.get("anomaly_score", 0.0))
        ip          = event.get("source_ip", "")

        # Track per-IP event times (rolling 5-minute window)
        if ip:
            self._ip_events[ip].append(datetime.utcnow())
            self._prune_window(ip, minutes=5)

        # ── Rule 1: Burst detection ────────────────────────────────────────────
        if ip and len(self._ip_events[ip]) >= 10:
            return self._make_incident(event, "Brute Force", boost_score=True)

        # ── Rule 2: Attack-type threshold ──────────────────────────────────────
        threshold = ALERT_THRESHOLDS.get(attack_type, DEFAULT_THRESHOLD)
        if score >= threshold and attack_type:
            return self._make_incident(event, attack_type)

        # ── Rule 3: Always alert on privilege escalation ───────────────────────
        if "Privilege Escalation" in attack_type or "sudo" in event.get("raw_log", "").lower():
            return self._make_incident(event, "Privilege Escalation")

        return None

    # ── Helpers ────────────────────────────────────────────────────────────────

    def _make_incident(
        self, event: dict, attack_type: str, boost_score: bool = False
    ) -> dict:
        mitre_id, mitre_name = MITRE_MAP.get(attack_type, ("T0000", "Unknown"))
        score = float(event.get("anomaly_score", 0.0))
        if boost_score:
            score = min(score + 0.30, 1.0)
        return {
            "attack_type": attack_type,
            "mitre_tag":   f"{mitre_id} – {mitre_name}",
            "anomaly_score": round(score, 4),
        }

    def _prune_window(self, ip: str, minutes: int):
        cutoff = datetime.utcnow() - timedelta(minutes=minutes)
        self._ip_events[ip] = [t for t in self._ip_events[ip] if t > cutoff]
