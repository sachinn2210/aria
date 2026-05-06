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
    "Brute Force":             ("T1110",     "Brute Force"),
    "Invalid User":            ("T1110.001", "Password Guessing"),
    "Privilege Escalation":    ("T1548",     "Abuse Elevation Control Mechanism"),
    "Path Traversal":          ("T1083",     "File and Directory Discovery"),
    "Directory Enumeration":   ("T1083",     "File and Directory Discovery"),
    "Unauthorized Access":     ("T1078",     "Valid Accounts"),
    "Successful Login":        ("T1078",     "Valid Accounts"),
    "Explicit Credential Use": ("T1078.003", "Local Accounts"),
    "Failed Login":            ("T1110",     "Brute Force"),
    "Kerberos TGT Request":    ("T1558.003", "Kerberoasting"),
    "Server Error":            ("T1499",     "Endpoint Denial of Service"),
}

# Score thresholds to raise an alert per attack type.
# Every key in MITRE_MAP should have an explicit entry here.
ALERT_THRESHOLDS = {
    "Brute Force":             0.35,
    "Invalid User":            0.30,
    "Failed Login":            0.35,
    "Privilege Escalation":    0.20,
    "Path Traversal":          0.25,
    "Directory Enumeration":   0.30,
    "Unauthorized Access":     0.25,
    "Successful Login":        0.70,  # only flag if very anomalous (off-hours, etc.)
    "Explicit Credential Use": 0.40,
    "Kerberos TGT Request":    0.30,
    "Server Error":            0.50,
}

DEFAULT_THRESHOLD = 0.40

# Burst detection: alerts if an IP exceeds this many events in the window
BURST_THRESHOLD = 10
BURST_WINDOW_MINUTES = 5


class EventCorrelator:
    def __init__(self):
        # ip → list of recent event timestamps for burst detection
        self._ip_events: dict[str, list] = defaultdict(list)

    def correlate(self, event: dict) -> Optional[dict]:
        """
        Evaluate the event against rules.
        Returns an incident dict if the event should trigger an alert, else None.
        """
        attack_type = event.get("attack_type", "")
        score       = float(event.get("anomaly_score", 0.0))
        ip          = event.get("source_ip", "")

        # Track per-IP event times (rolling window)
        if ip:
            self._ip_events[ip].append(datetime.utcnow())
            self._prune_window(ip, minutes=BURST_WINDOW_MINUTES)

        # Rule 1: Burst detection ────────────────────────────────────────────
        if ip and len(self._ip_events[ip]) >= BURST_THRESHOLD:
            return self._make_incident(event, "Brute Force", boost_score=True)

        # Rule 2: sudo in raw log → always escalate regardless of score ──────
        # FIX: Moved before Rule 3 so privilege escalation via raw log is never
        # shadowed by an earlier threshold match on a different attack_type
        if "sudo" in event.get("raw_log", "").lower():
            return self._make_incident(event, "Privilege Escalation")

        # Rule 3: Attack-type threshold ──────────────────────────────────────
        threshold = ALERT_THRESHOLDS.get(attack_type, DEFAULT_THRESHOLD)
        if score >= threshold and attack_type:
            return self._make_incident(event, attack_type)

        return None


    def _make_incident(
        self, event: dict, attack_type: str, boost_score: bool = False
    ) -> dict:
        mitre_id, mitre_name = MITRE_MAP.get(attack_type, ("T0000", "Unknown"))
        score = float(event.get("anomaly_score", 0.0))
        if boost_score:
            score = min(score + 0.30, 1.0)

        # FIX: Write boosted score back to event so downstream readers are consistent
        event["anomaly_score"] = round(score, 4)

        return {
            "attack_type":   attack_type,
            "mitre_tag":     f"{mitre_id} – {mitre_name}",
            "anomaly_score": round(score, 4),
        }

    def _prune_window(self, ip: str, minutes: int):
        cutoff = datetime.utcnow() - timedelta(minutes=minutes)
        pruned = [t for t in self._ip_events[ip] if t > cutoff]

        if pruned:
            self._ip_events[ip] = pruned
        else:
            del self._ip_events[ip]