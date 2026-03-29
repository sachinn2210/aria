"""
ARIA - Autonomous Real-time Incident Analysis & Response Agent
Main Flask Application
"""

import os
import json
import threading
import time
from datetime import datetime
from flask import Flask, render_template, jsonify, request, Response
from modules.log_watcher import LogWatcher
from modules.parser import LogParser
from modules.database import Database
from modules.ml_detector import AnomalyDetector
from modules.correlator import EventCorrelator
from modules.alerter import Alerter
from modules.llm_summarizer import LLMSummarizer

app = Flask(__name__)

# ── Global state ──────────────────────────────────────────────────────────────
db = Database()
parser = LogParser()
detector = AnomalyDetector()
correlator = EventCorrelator()
alerter = Alerter()
summarizer = LLMSummarizer()
event_queue = []          # SSE broadcast queue
watcher = None

# ── Routes ────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/stats")
def stats():
    """Summary counts for dashboard cards."""
    return jsonify(db.get_stats())


@app.route("/api/alerts")
def alerts():
    """Paginated alert table."""
    page   = int(request.args.get("page", 1))
    limit  = int(request.args.get("limit", 50))
    sev    = request.args.get("severity", "")
    search = request.args.get("q", "")
    return jsonify(db.get_alerts(page=page, limit=limit, severity=sev, search=search))


@app.route("/api/alerts/<int:alert_id>/summary")
def alert_summary(alert_id):
    """LLM-generated plain-English summary for one alert."""
    alert = db.get_alert_by_id(alert_id)
    if not alert:
        return jsonify({"error": "Not found"}), 404
    summary = summarizer.summarize(alert)
    db.update_alert_summary(alert_id, summary)
    return jsonify({"summary": summary})


@app.route("/api/timeline")
def timeline():
    """Event count per minute for the live chart."""
    return jsonify(db.get_timeline(minutes=60))


@app.route("/api/severity_breakdown")
def severity_breakdown():
    return jsonify(db.get_severity_breakdown())


@app.route("/api/top_ips")
def top_ips():
    return jsonify(db.get_top_ips(limit=10))


@app.route("/stream")
def stream():
    """Server-Sent Events endpoint for real-time log feed."""
    def generate():
        last_seen = 0
        while True:
            if len(event_queue) > last_seen:
                for evt in event_queue[last_seen:]:
                    yield f"data: {json.dumps(evt)}\n\n"
                last_seen = len(event_queue)
            time.sleep(0.5)
    return Response(generate(), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


# ── Log ingestion callback ─────────────────────────────────────────────────────

def on_new_log_line(raw_line: str, source: str):
    """Called by LogWatcher for every new line."""
    event = parser.parse(raw_line, source)
    if not event:
        return

    # ML scoring
    score = detector.score(event)
    event["anomaly_score"] = score

    # Rule correlation + MITRE tagging
    incident = correlator.correlate(event)
    if incident:
        event["mitre_tag"]   = incident.get("mitre_tag", "")
        event["attack_type"] = incident.get("attack_type", "Unknown")
        severity = _score_to_severity(score)
        event["severity"] = severity

        # Persist
        alert_id = db.insert_alert(event)
        event["id"] = alert_id

        # LLM summary (async so it doesn't block the feed)
        threading.Thread(
            target=_async_summarize, args=(alert_id, event), daemon=True
        ).start()

        # Alerting
        if severity in ("HIGH", "CRITICAL"):
            threading.Thread(
                target=alerter.send, args=(event,), daemon=True
            ).start()

    # Always push raw event to SSE queue (cap at 1000)
    event_queue.append(event)
    if len(event_queue) > 1000:
        event_queue.pop(0)


def _score_to_severity(score: float) -> str:
    if score >= 0.85:   return "CRITICAL"
    if score >= 0.65:   return "HIGH"
    if score >= 0.40:   return "MEDIUM"
    return "LOW"


def _async_summarize(alert_id: int, event: dict):
    summary = summarizer.summarize(event)
    db.update_alert_summary(alert_id, summary)


# ── Startup ───────────────────────────────────────────────────────────────────

def start_watcher():
    global watcher
    log_paths = [
        p.strip() for p in os.getenv("ARIA_LOG_PATHS", "logs/demo.log").split(",") if p.strip()
    ]
    watcher = LogWatcher(log_paths, callback=on_new_log_line)
    watcher.start()


if __name__ == "__main__":
    # Seed the ML model with some baseline data before watching
    detector.fit_baseline()
    threading.Thread(target=start_watcher, daemon=True).start()
    app.run(debug=True, threaded=True, port=5000)
