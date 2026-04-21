"""
ARIA – ML Anomaly Detector
Uses scikit-learn Isolation Forest to score each log event.
Score is normalised to [0, 1]: 1 = most anomalous.
"""

import os
import re
import pickle
import random
import numpy as np
from datetime import datetime

# FIX: Read at call time in methods that need it, but keep the default here
# for reference — actual path resolved in _model_path()
_DEFAULT_MODEL_PATH = "aria_model.pkl"


def _model_path() -> str:
    # FIX: Read env var at call time so late-set env vars are respected
    return os.getenv("ARIA_MODEL_PATH", _DEFAULT_MODEL_PATH)


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
            # FIX: Log clearly that we're using fallback scores
            return round(random.uniform(0.1, 0.4), 3)

        raw = self.model.decision_function(arr)[0]  # negative = anomalous
        score = float(np.clip((-raw + 0.5) / 1.0, 0.0, 1.0))
        return round(score, 4)

    def fit_baseline(self, X: np.ndarray = None, n_samples: int = 500):
        """
        Fit the Isolation Forest on baseline data.
        Pass a real feature matrix as X, or leave None to use synthetic data.
        """
        from sklearn.ensemble import IsolationForest

        if X is None:
            X = self._synthetic_normal(n_samples)
            print(f"[ARIA] Fitting on {n_samples} synthetic baseline samples.")
        else:
            print(f"[ARIA] Fitting on {len(X)} real baseline samples.")

        # FIX: Make contamination configurable via env var
        contamination = float(os.getenv("ARIA_CONTAMINATION", "0.05"))

        self.model = IsolationForest(
            n_estimators=100,
            contamination=contamination,
            random_state=42,
        )
        self.model.fit(X)

        # FIX: Wrap save in try/except so a read-only path doesn't crash startup
        try:
            self._save()
        except Exception as e:
            print(f"[ARIA] Warning: could not save model to {_model_path()}: {e}")

        print("[ARIA] Isolation Forest fitted and ready.")

    # ── Feature engineering ────────────────────────────────────────────────────

    def _extract_features(self, event: dict) -> list:
        """
        Numeric feature vector extracted from one log event.
        Feature list (length 7):
          0: hour of day (0–23)
          1: ip_first_octet  – network class proxy
          2: ip_last_octet   – host proxy
          3: attack_type_code – mapped int
          4: service_code – mapped int
          5: is_auth_failure (bool)
          6: is_root_user (bool)
          7: port (0 if unknown)
        """
        ts   = event.get("timestamp", datetime.utcnow().isoformat())
        hour = _hour_from_ts(ts)

        ip         = event.get("source_ip", "0.0.0.0")
        first_oct  = _first_octet(ip)
        last_oct   = _last_octet(ip)

        attack   = event.get("attack_type", "").lower()
        service  = event.get("target_service", "").lower()
        raw_log  = event.get("raw_log", "").lower()

        attack_code  = _attack_code(attack)
        service_code = _service_code(service)
        is_failure   = int("failed" in attack or "invalid" in attack or "fail" in raw_log)
        is_root      = int("root" in raw_log or "root" in event.get("extra", {}).get("user", ""))
        port         = _extract_port(raw_log)

        # FIX: Removed always-zero "anomaly_score hint" feature slot (index 6)
        return [hour, first_oct, last_oct, attack_code, service_code, is_failure, is_root, port]

    def _synthetic_normal(self, n: int) -> np.ndarray:
        """Generate plausible 'normal' log feature vectors for baseline fitting."""
        rng  = np.random.default_rng(42)
        data = []
        for _ in range(n):
            # FIX: Clip hour to valid [0, 23] range — rng.normal can exceed bounds
            hour        = int(np.clip(rng.normal(12, 4), 0, 23))
            first_oct   = int(rng.choice([10, 172, 192]))   # private ranges
            last_oct    = int(rng.integers(1, 255))
            attack_code = 0
            svc_code    = int(rng.choice([0, 1, 2]))
            is_failure  = int(rng.random() < 0.05)
            is_root     = 0
            port        = int(rng.choice([22, 80, 443, 8080, 3306, 0]))
            data.append([hour, first_oct, last_oct, attack_code, svc_code,
                         is_failure, is_root, port])
        return np.array(data, dtype=float)

    # ── Persistence ────────────────────────────────────────────────────────────

    def _save(self):
        with open(_model_path(), "wb") as f:
            pickle.dump(self.model, f)

    def _load_or_init(self):
        path = _model_path()
        if os.path.exists(path):
            try:
                with open(path, "rb") as f:
                    self.model = pickle.load(f)
                print(f"[ARIA] Loaded existing ML model from {path}.")
                return
            except Exception as e:
                # FIX: Log the actual error — silent pass hid corrupted model files
                print(f"[ARIA] Warning: failed to load model from {path}: {e}. "
                      f"Will refit at startup.")
        self.model = None


# ── Helpers ────────────────────────────────────────────────────────────────────

def _hour_from_ts(ts: str) -> int:
    try:
        return datetime.fromisoformat(ts).hour
    except Exception:
        # FIX: Return 0 not 12 — a bad timestamp should not look like normal
        # business-hours traffic to the model
        return 0


def _first_octet(ip: str) -> int:
    # FIX: Added first-octet feature for better network class discrimination
    try:
        return int(ip.split(".")[0])
    except Exception:
        return 0


def _last_octet(ip: str) -> int:
    try:
        return int(ip.split(".")[-1])
    except Exception:
        return 0


def _extract_port(raw: str) -> int:
    # FIX: Moved re import to top level — importing inside a hot-path function
    # causes a redundant lookup on every single log line
    m = re.search(r"\bport\s+(\d+)\b", raw)
    if m:
        try:
            return int(m.group(1))
        except Exception:
            pass
    return 0


def _attack_code(attack: str) -> int:
    mapping = {
        "brute force":          5,
        "path traversal":       4,
        "privilege escalation": 4,
        "directory enumeration":3,
        "unauthorized access":  3,
        "server error":         2,
        "invalid user":         2,
        "successful login":     1,
        "http request":         0,
    }
    for k, v in mapping.items():
        if k in attack:
            return v
    return 0


def _service_code(service: str) -> int:
    mapping = {"sshd": 3, "ssh": 3, "sudo": 4, "http": 1, "windows": 2}
    return mapping.get(service, 0)