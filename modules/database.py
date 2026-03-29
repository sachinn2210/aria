"""
ARIA – Database layer (SQLite)
Handles alert persistence and all query helpers used by Flask routes.
"""

import sqlite3
import json
import os
from datetime import datetime, timedelta
from typing import Optional

DB_PATH = os.getenv("ARIA_DB_PATH", "aria.db")


class Database:
    def __init__(self, path: str = DB_PATH):
        self.path = path
        self._init_schema()

    # ── Connection helper ──────────────────────────────────────────────────────

    def _conn(self):
        conn = sqlite3.connect(self.path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        return conn

    # ── Schema ─────────────────────────────────────────────────────────────────

    def _init_schema(self):
        ddl = """
        CREATE TABLE IF NOT EXISTS alerts (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp     TEXT    NOT NULL,
            source        TEXT    NOT NULL DEFAULT '',
            raw_log       TEXT    NOT NULL DEFAULT '',
            source_ip     TEXT    DEFAULT '',
            target_service TEXT   DEFAULT '',
            attack_type   TEXT    DEFAULT '',
            mitre_tag     TEXT    DEFAULT '',
            anomaly_score REAL    DEFAULT 0.0,
            severity      TEXT    DEFAULT 'LOW',
            llm_summary   TEXT    DEFAULT '',
            extra         TEXT    DEFAULT '{}'
        );
        CREATE INDEX IF NOT EXISTS idx_severity  ON alerts(severity);
        CREATE INDEX IF NOT EXISTS idx_timestamp ON alerts(timestamp);
        CREATE INDEX IF NOT EXISTS idx_ip        ON alerts(source_ip);
        """
        with self._conn() as conn:
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
        with self._conn() as conn:
            cur = conn.execute(sql, params)
            return cur.lastrowid

    def update_alert_summary(self, alert_id: int, summary: str):
        with self._conn() as conn:
            conn.execute(
                "UPDATE alerts SET llm_summary=? WHERE id=?", (summary, alert_id)
            )

    # ── Read ───────────────────────────────────────────────────────────────────

    def get_alert_by_id(self, alert_id: int) -> Optional[dict]:
        with self._conn() as conn:
            row = conn.execute(
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
            params.append(severity)
        if search:
            conditions.append(
                "(source_ip LIKE ? OR attack_type LIKE ? OR mitre_tag LIKE ?)"
            )
            like = f"%{search}%"
            params.extend([like, like, like])

        where = ("WHERE " + " AND ".join(conditions)) if conditions else ""
        count_sql = f"SELECT COUNT(*) FROM alerts {where}"
        data_sql  = f"""
            SELECT id, timestamp, source_ip, target_service, attack_type,
                   mitre_tag, anomaly_score, severity, llm_summary
            FROM alerts {where}
            ORDER BY anomaly_score DESC, timestamp DESC
            LIMIT ? OFFSET ?
        """
        with self._conn() as conn:
            total = conn.execute(count_sql, params).fetchone()[0]
            rows  = conn.execute(data_sql, params + [limit, offset]).fetchall()

        return {
            "total": total,
            "page": page,
            "limit": limit,
            "alerts": [dict(r) for r in rows],
        }

    def get_stats(self) -> dict:
        with self._conn() as conn:
            total    = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
            critical = conn.execute(
                "SELECT COUNT(*) FROM alerts WHERE severity='CRITICAL'"
            ).fetchone()[0]
            high     = conn.execute(
                "SELECT COUNT(*) FROM alerts WHERE severity='HIGH'"
            ).fetchone()[0]
            last_1h  = conn.execute(
                "SELECT COUNT(*) FROM alerts WHERE timestamp >= datetime('now', '-1 hour')"
            ).fetchone()[0]
            avg_score = conn.execute(
                "SELECT AVG(anomaly_score) FROM alerts"
            ).fetchone()[0] or 0.0
        return {
            "total_alerts": total,
            "critical": critical,
            "high": high,
            "last_1h": last_1h,
            "avg_anomaly_score": round(float(avg_score), 3),
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
        with self._conn() as conn:
            rows = conn.execute(sql, (since,)).fetchall()
        return [dict(r) for r in rows]

    def get_severity_breakdown(self) -> dict:
        sql = "SELECT severity, COUNT(*) AS cnt FROM alerts GROUP BY severity"
        with self._conn() as conn:
            rows = conn.execute(sql).fetchall()
        return {r["severity"]: r["cnt"] for r in rows}

    def get_top_ips(self, limit: int = 10) -> list:
        sql = """
        SELECT source_ip,
               COUNT(*) AS hit_count,
               MAX(anomaly_score) AS max_score,
               MAX(severity) AS max_severity
        FROM alerts
        WHERE source_ip != ''
        GROUP BY source_ip
        ORDER BY hit_count DESC
        LIMIT ?
        """
        with self._conn() as conn:
            rows = conn.execute(sql, (limit,)).fetchall()
        return [dict(r) for r in rows]
