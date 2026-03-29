"""
ARIA – ML Anomaly Detector
Uses scikit-learn Isolation Forest to score each log event.
Score is normalised to [0, 1]: 1 = most anomalous.
"""

import os
import pickle
import random
import numpy as np
from datetime import datetime

MODEL_PATH = os.getenv("ARIA_MODEL_PATH", "aria_model.pkl")


class AnomalyDetector:
    def __init__(self):
        self.model = None
        self._load_or_init()

    # ── Public API ─────────────────────────────────────────────────────────────

    def score(self, event: dict) -> float:
        """Return anomaly score [0,1]. Higher = more suspicious."""
        features = self._extract_features(event)
        arr = np.array([features])

        if self.model is None:
            return round(random.uniform(0.1, 0.4), 3)   # fallback before fit

        raw = self.model.decision_function(arr)[0]       # negative = anomalous
        # Normalise: typical range is [-0.5, 0.5]; clip and invert
        score = float(np.clip((-raw + 0.5) / 1.0, 0.0, 1.0))
        return round(score, 4)

    def fit_baseline(self, n_samples: int = 500):
        """
        Fit the Isolation Forest on synthetic 'normal' traffic.
        In production, replace this with real baseline logs.
        """
        from sklearn.ensemble import IsolationForest
        X = self._synthetic_normal(n_samples)
        self.model = IsolationForest(
            n_estimators=100,
            contamination=0.05,
            random_state=42,
        )
        self.model.fit(X)
        self._save()
        print(f"[ARIA] Isolation Forest fitted on {n_samples} baseline samples.")

    # ── Feature engineering ────────────────────────────────────────────────────

    def _extract_features(self, event: dict) -> list:
        """
        Numeric feature vector extracted from one log event.
        Feature list (length 8):
          0: hour of day (0–23)
          1: ip_last_octet – rough location proxy
          2: attack_type_code – mapped int
          3: service_code – mapped int
          4: is_auth_failure (bool)
          5: is_root_user (bool)
          6: anomaly_score hint (0 if not yet scored)
          7: port (0 if unknown)
        """
        ts   = event.get("timestamp", datetime.utcnow().isoformat())
        hour = _hour_from_ts(ts)

        ip       = event.get("source_ip", "0.0.0.0")
        last_oct = _last_octet(ip)

        attack = event.get("attack_type", "").lower()
        service = event.get("target_service", "").lower()
        raw_log = event.get("raw_log", "").lower()

        attack_code = _attack_code(attack)
        service_code = _service_code(service)
        is_failure  = int("failed" in attack or "invalid" in attack or "fail" in raw_log)
        is_root     = int("root" in raw_log or "root" in event.get("extra", {}).get("user", ""))
        port        = _extract_port(raw_log)

        return [hour, last_oct, attack_code, service_code, is_failure, is_root, 0, port]

    def _synthetic_normal(self, n: int) -> np.ndarray:
        """Generate plausible 'normal' log feature vectors for baseline fitting."""
        rng = np.random.default_rng(42)
        data = []
        for _ in range(n):
            hour        = int(rng.normal(12, 4))   # business hours
            last_oct    = int(rng.integers(1, 255))
            attack_code = 0                          # mostly normal traffic
            svc_code    = int(rng.choice([0, 1, 2]))
            is_failure  = int(rng.random() < 0.05)  # rare failures
            is_root     = 0
            hint        = 0
            port        = int(rng.choice([22, 80, 443, 8080, 3306, 0]))
            data.append([hour, last_oct, attack_code, svc_code, is_failure, is_root, hint, port])
        return np.array(data, dtype=float)

    # ── Persistence ────────────────────────────────────────────────────────────

    def _save(self):
        with open(MODEL_PATH, "wb") as f:
            pickle.dump(self.model, f)

    def _load_or_init(self):
        if os.path.exists(MODEL_PATH):
            try:
                with open(MODEL_PATH, "rb") as f:
                    self.model = pickle.load(f)
                print("[ARIA] Loaded existing ML model.")
                return
            except Exception:
                pass
        self.model = None


# ── Helpers ────────────────────────────────────────────────────────────────────

def _hour_from_ts(ts: str) -> int:
    try:
        return datetime.fromisoformat(ts).hour
    except Exception:
        return 12


def _last_octet(ip: str) -> int:
    try:
        return int(ip.split(".")[-1])
    except Exception:
        return 0


def _extract_port(raw: str) -> int:
    import re
    m = re.search(r"\bport\s+(\d+)\b", raw)
    if m:
        try:
            return int(m.group(1))
        except Exception:
            pass
    return 0


def _attack_code(attack: str) -> int:
    mapping = {
        "brute force": 5,
        "path traversal": 4,
        "privilege escalation": 4,
        "directory enumeration": 3,
        "unauthorized access": 3,
        "server error": 2,
        "invalid user": 2,
        "successful login": 1,
        "http request": 0,
    }
    for k, v in mapping.items():
        if k in attack:
            return v
    return 0


def _service_code(service: str) -> int:
    mapping = {"sshd": 3, "ssh": 3, "sudo": 4, "http": 1, "windows": 2}
    return mapping.get(service, 0)
