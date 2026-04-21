import os
import json
import threading
import time
from collections import deque
from datetime import datetime
from flask import Flask, render_template, jsonify, request, Response
from modules.log_watcher import LogWatcher
from modules.parser import LogParser
from modules.database import Database
from modules.ml_detector import AnomalyDetector
from modules.correlator import EventCorrelator
from modules.alerter import Alerter
from modules.llm_summarizer import LLMSummarizer
from prometheus_flask_exporter import PrometheusMetrics
from prometheus_client import Counter
import requests

app = Flask(__name__)

metrics = PrometheusMetrics(app)

db = Database()
parser = LogParser()
detector = AnomalyDetector()
correlator = EventCorrelator()
alerter = Alerter()
summarizer = LLMSummarizer()

# Thread-safe, auto-capped queue (no manual pop needed)
event_queue = deque(maxlen=1000)

watcher = None

ARIA_ALERTS = Counter("aria_alerts_total", "Total alerts sent")
ARIA_ANOMALIES = Counter("aria_anomalies_total", "Total anomalies detected")

# FIX: Removed premature .inc() calls that were inflating metrics on every startup


def push_to_loki(event):
    """Push a correlated event to Loki asynchronously (fire-and-forget)."""
    try:
        payload = {
            "streams": [{
                "stream": {"job": "aria", "severity": event.get("severity", "INFO")},
                "values": [[
                    str(int(time.time() * 1e9)),
                    f"{event['attack_type']} from {event['source_ip']}"
                ]]
            }]
        }
        requests.post(
            "http://localhost:3100/loki/api/v1/push",
            json=payload,
            timeout=0.5
        )
    except Exception as e:
        print(f"[ARIA] Loki push failed: {e}")

def _async_summarize_then_alert(alert_id: int, event: dict):
    """Generate summary first, THEN send email so body contains the summary."""
    summary = summarizer.summarize(event)
    db.update_alert_summary(alert_id, summary)

    # Write summary into event dict before alerter reads it
    event["llm_summary"] = summary

    severity = event.get("severity", "")
    if severity in ("HIGH", "CRITICAL"):
        alerter.send(event)

def on_new_log_line(raw_line: str, source: str):
    print(f"[DEBUG] Callback received: {raw_line[:60]}") 
    event = parser.parse(raw_line, source)
    if not event:
        return

    score = detector.score(event)
    event["anomaly_score"] = score

    incident = correlator.correlate(event)
    if incident:
        ARIA_ANOMALIES.inc()

        event["mitre_tag"]   = incident.get("mitre_tag", "")
        event["attack_type"] = incident.get("attack_type", "Unknown")

                
        effective_score = score + incident.get("boost", 0.0)
        effective_score = min(effective_score, 1.0)

        severity = _score_to_severity(effective_score)
        event["severity"] = severity
        event["anomaly_score"] = effective_score

        
        severity = _score_to_severity(score)
        event["severity"] = severity

        # FIX: Push to Loki off the main ingestion thread so a slow/down
        # Loki instance doesn't block log processing for up to 0.5s per event
        threading.Thread(target=push_to_loki, args=(event,), daemon=True).start()

        # Persist to DB
        alert_id = db.insert_alert(event)
        event["id"] = alert_id

        # Async LLM summarization
        #threading.Thread(target=_async_summarize, args=(alert_id, event), daemon=True).start()

        if severity in ("HIGH", "CRITICAL"):
            ARIA_ALERTS.inc()
            threading.Thread(
                    target=_async_summarize_then_alert,
                    args=(alert_id, event),
                    daemon=True
                ).start()
            #threading.Thread(target=alerter.send, args=(event,), daemon=True).start()

    # FIX: deque(maxlen=1000) handles thread-safety and capping automatically
    event_queue.append(event)


def _score_to_severity(score: float) -> str:
    if score >= 0.75: return "CRITICAL"
    if score >= 0.55: return "HIGH"
    if score >= 0.30: return "MEDIUM"
    return "LOW"

def start_watcher():
    global watcher
    log_paths = [
        p.strip()
        for p in os.getenv("ARIA_LOG_PATHS", "logs/demo.log").split(",")
        if p.strip()
    ]
    watcher = LogWatcher(log_paths, callback=on_new_log_line)
    watcher.start()


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
    """Return cached summary if available; generate and cache if not."""
    alert = db.get_alert_by_id(alert_id)
    if not alert:
        return jsonify({"error": "Not found"}), 404

    # FIX: Avoid redundant LLM calls — return cached summary when it exists
    if alert.get("llm_summary"):
       return jsonify({"summary": alert["llm_summary"]})

    summary = summarizer.summarize(alert)
    db.update_alert_summary(alert_id, summary)
    return jsonify({"summary": summary})


@app.route("/api/timeline")
def timeline():
    return jsonify(db.get_timeline(minutes=60))


@app.route("/api/severity_breakdown")
def severity_breakdown():
    return jsonify(db.get_severity_breakdown())


@app.route("/api/top_ips")
def top_ips():
    return jsonify(db.get_top_ips(limit=10))


@app.route("/stream")
def stream():
    """
    SSE endpoint. Uses a snapshot index into the deque on each poll cycle.
    Because deque is ordered and capped, we track the last emitted count
    and emit only new tail items each tick.
    """
    def generate():
        last_len = len(event_queue)
        while True:
            current_len = len(event_queue)
            if current_len > last_len:
                # Slice new items from the tail of the deque
                new_events = list(event_queue)[last_len:]
                for evt in new_events:
                    yield f"data: {json.dumps(evt)}\n\n"
                last_len = current_len
            time.sleep(0.5)

    return Response(
        generate(),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"}
    )


if __name__ == "__main__":
    # Seed the ML model with baseline data before watching logs
   # detector.fit_baseline()

    # FIX: Guard against double-start in Werkzeug reloader without relying on
    # the internal WERKZEUG_RUN_MAIN env var — prefer running under a proper
    # WSGI server (gunicorn/uvicorn) in production where debug=False.
    if os.environ.get("WERKZEUG_RUN_MAIN") == "true" or not app.debug:
        threading.Thread(target=start_watcher, daemon=True).start()
        print("[ARIA] Log Watcher started.")

    app.run(debug=False, threaded=True, port=5000)