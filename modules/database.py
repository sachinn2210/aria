"""
ARIA – Database layer (SQLite)
Handles alert persistence and all query helpers used by Flask routes.
"""

import sqlite3
import json
import os
import threading
from datetime import datetime, timedelta
from typing import Optional

DB_PATH = os.getenv("ARIA_DB_PATH", "aria.db")

# Severity rank for correct ordering (SQLite has no native enum)
_SEVERITY_CASE = """
    CASE severity
        WHEN 'CRITICAL' THEN 4
        WHEN 'HIGH'     THEN 3
        WHEN 'MEDIUM'   THEN 2
        WHEN 'LOW'      THEN 1
        ELSE 0
    END
"""


class Database:
    def __init__(self, path: str = DB_PATH):
        self.path = path
        # FIX: One connection per thread via threading.local()
        self._local = threading.local()
        self._init_schema()

    # ── Connection helper ──────────────────────────────────────────────────────

    def _conn(self) -> sqlite3.Connection:
        """Return a per-thread cached connection."""
        if not getattr(self._local, "conn", None):
            conn = sqlite3.connect(self.path, check_same_thread=False, timeout=10)
            conn.row_factory = sqlite3.Row
            self._local.conn = conn
        return self._local.conn

    # ── Schema ─────────────────────────────────────────────────────────────────

    def _init_schema(self):
        ddl = """
        CREATE TABLE IF NOT EXISTS alerts (
            id             INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp      TEXT    NOT NULL,
            source         TEXT    NOT NULL DEFAULT '',
            raw_log        TEXT    NOT NULL DEFAULT '',
            source_ip      TEXT    DEFAULT '',
            target_service TEXT    DEFAULT '',
            attack_type    TEXT    DEFAULT '',
            mitre_tag      TEXT    DEFAULT '',
            anomaly_score  REAL    DEFAULT 0.0,
            severity       TEXT    DEFAULT 'LOW',
            llm_summary    TEXT    DEFAULT '',
            extra          TEXT    DEFAULT '{}'
        );
        CREATE INDEX IF NOT EXISTS idx_severity  ON alerts(severity);
        CREATE INDEX IF NOT EXISTS idx_timestamp ON alerts(timestamp);
        CREATE INDEX IF NOT EXISTS idx_ip        ON alerts(source_ip);
        """
        conn = self._conn()
        # FIX: Set WAL mode once at init, not on every connection
        conn.execute("PRAGMA journal_mode=WAL")
        conn.executescript(ddl)

    # ── Write ──────────────────────────────────────────────────────────────────

    def insert_alert(self, event: dict) -> int:
        sql = """
        INSERT INTO alerts
            (timestamp, source, raw_log, source_ip, target_service,
             attack_type, mitre_tag, anomaly_score, severity, extra)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """
        params = (
            event.get("timestamp", datetime.utcnow().isoformat()),
            event.get("source", ""),
            event.get("raw_log", ""),
            event.get("source_ip", ""),
            event.get("target_service", ""),
            event.get("attack_type", ""),
            event.get("mitre_tag", ""),
            float(event.get("anomaly_score", 0.0)),
            event.get("severity", "LOW"),
            json.dumps(event.get("extra", {})),
        )
        conn = self._conn()
        with conn:
            cur = conn.execute(sql, params)
            return cur.lastrowid

    def update_alert_summary(self, alert_id: int, summary: str):
        conn = self._conn()
        with conn:
            conn.execute(
                "UPDATE alerts SET llm_summary=? WHERE id=?", (summary, alert_id)
            )

    # ── Read ───────────────────────────────────────────────────────────────────

    def get_alert_by_id(self, alert_id: int) -> Optional[dict]:
        row = self._conn().execute(
            "SELECT * FROM alerts WHERE id=?", (alert_id,)
        ).fetchone()
        return dict(row) if row else None

    def get_alerts(
        self,
        page: int = 1,
        limit: int = 50,
        severity: str = "",
        search: str = "",
    ) -> dict:
        offset = (page - 1) * limit
        conditions, params = [], []

        if severity:
            conditions.append("severity = ?")
            params.append(severity.upper())

        if search:
            # FIX: Escape % and _ so they aren't treated as LIKE wildcards
            escaped = search.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
            like = f"%{escaped}%"
            conditions.append(
                "(source_ip LIKE ? ESCAPE '\\' OR attack_type LIKE ? ESCAPE '\\' OR mitre_tag LIKE ? ESCAPE '\\')"
            )
            params.extend([like, like, like])

        where    = ("WHERE " + " AND ".join(conditions)) if conditions else ""
        count_sql = f"SELECT COUNT(*) FROM alerts {where}"
        data_sql  = f"""
            SELECT id, timestamp, source_ip, target_service, attack_type,
                   mitre_tag, anomaly_score, severity, llm_summary
            FROM alerts {where}
            ORDER BY timestamp DESC, anomaly_score DESC
            LIMIT ? OFFSET ?
        """
        conn  = self._conn()
        total = conn.execute(count_sql, params).fetchone()[0]
        rows  = conn.execute(data_sql, params + [limit, offset]).fetchall()

        return {
            "total":  total,
            "page":   page,
            "limit":  limit,
            "alerts": [dict(r) for r in rows],
        }

    def get_stats(self) -> dict:
        # FIX: Single query instead of 5 separate round-trips
        row = self._conn().execute("""
            SELECT
                COUNT(*)                                                AS total,
                SUM(severity = 'CRITICAL')                             AS critical,
                SUM(severity = 'HIGH')                                 AS high,
                SUM(timestamp >= datetime('now', '-1 hour'))           AS last_1h,
                COALESCE(AVG(anomaly_score), 0.0)                      AS avg_score
            FROM alerts
        """).fetchone()
        return {
            "total_alerts":      row["total"],
            "critical":          row["critical"] or 0,
            "high":              row["high"] or 0,
            "last_1h":           row["last_1h"] or 0,
            "avg_anomaly_score": round(float(row["avg_score"]), 3),
        }

    def get_timeline(self, minutes: int = 60) -> list:
        since = (datetime.utcnow() - timedelta(minutes=minutes)).isoformat()
        sql = """
        SELECT strftime('%Y-%m-%dT%H:%M:00', timestamp) AS bucket,
               COUNT(*) AS count
        FROM alerts
        WHERE timestamp >= ?
        GROUP BY bucket
        ORDER BY bucket
        """
        rows = self._conn().execute(sql, (since,)).fetchall()
        return [dict(r) for r in rows]

    def get_severity_breakdown(self) -> dict:
        sql = "SELECT severity, COUNT(*) AS cnt FROM alerts GROUP BY severity"
        rows = self._conn().execute(sql).fetchall()
        return {r["severity"]: r["cnt"] for r in rows}

    def get_top_ips(self, limit: int = 10) -> list:
        # FIX: Use CASE expression for correct severity ordering
        # MAX(severity) is lexicographic — 'MEDIUM' > 'CRITICAL' alphabetically
        sql = f"""
        SELECT source_ip,
               COUNT(*)          AS hit_count,
               MAX(anomaly_score) AS max_score,
               MAX({_SEVERITY_CASE}) AS severity_rank,
               CASE MAX({_SEVERITY_CASE})
                   WHEN 4 THEN 'CRITICAL'
                   WHEN 3 THEN 'HIGH'
                   WHEN 2 THEN 'MEDIUM'
                   WHEN 1 THEN 'LOW'
                   ELSE 'UNKNOWN'
               END               AS max_severity
        FROM alerts
        WHERE source_ip != ''
        GROUP BY source_ip
        ORDER BY hit_count DESC
        LIMIT ?
        """
        rows = self._conn().execute(sql, (limit,)).fetchall()
        return [dict(r) for r in rows]