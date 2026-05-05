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
from modules.vapi_caller import trigger_voice_alert
from prometheus_flask_exporter import PrometheusMetrics
from prometheus_client import Counter
import requests as http_requests

app = Flask(__name__)
metrics = PrometheusMetrics(app)

db         = Database()
parser     = LogParser()
detector   = AnomalyDetector()
correlator = EventCorrelator()
alerter    = Alerter()
summarizer = LLMSummarizer()

event_queue = deque(maxlen=1000)
watcher     = None

ARIA_ALERTS    = Counter("aria_alerts_total",    "Total alerts sent")
ARIA_ANOMALIES = Counter("aria_anomalies_total", "Total anomalies detected")


# ── Loki push ─────────────────────────────────────────────────────────────────

def push_to_loki(event):
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
        http_requests.post(
            "http://localhost:3100/loki/api/v1/push",
            json=payload,
            timeout=0.5
        )
    except Exception as e:
        print(f"[ARIA] Loki push failed: {e}")


# ── Alert pipeline ────────────────────────────────────────────────────────────

def _async_summarize_then_alert(alert_id: int, event: dict):
    """
    1. Generate LLM summary
    2. Persist it
    3. Send email/Telegram via Alerter
    4. Trigger VAPI voice call (CRITICAL by default, configurable)
    """
    summary = summarizer.summarize(event)
    db.update_alert_summary(alert_id, summary)
    event["llm_summary"] = summary

    severity = event.get("severity", "")
    if severity in ("HIGH", "CRITICAL"):
        # Email + Telegram
        alerter.send(event)
        # VAPI voice call (runs in its own thread to avoid blocking)
        threading.Thread(
            target=trigger_voice_alert,
            args=(event,),
            daemon=True,
        ).start()


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
        event["mitre_tag"]    = incident.get("mitre_tag", "")
        event["attack_type"]  = incident.get("attack_type", "Unknown")
        event["anomaly_score"] = incident.get("anomaly_score", score)

        severity = _score_to_severity(event["anomaly_score"])
        event["severity"] = severity

        threading.Thread(target=push_to_loki, args=(event,), daemon=True).start()

        alert_id   = db.insert_alert(event)
        event["id"] = alert_id

        if severity in ("HIGH", "CRITICAL"):
            ARIA_ALERTS.inc()
            threading.Thread(
                target=_async_summarize_then_alert,
                args=(alert_id, event),
                daemon=True,
            ).start()

    event_queue.append(event)


def _score_to_severity(score: float) -> str:
    if score >= 0.75: return "CRITICAL"
    if score >= 0.55: return "HIGH"
    if score >= 0.30: return "MEDIUM"
    return "LOW"


# ── Routes ────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/stats")
def stats():
    return jsonify(db.get_stats())


@app.route("/api/alerts")
def alerts():
    page   = int(request.args.get("page", 1))
    limit  = int(request.args.get("limit", 50))
    sev    = request.args.get("severity", "")
    search = request.args.get("q", "")
    return jsonify(db.get_alerts(page=page, limit=limit, severity=sev, search=search))


@app.route("/api/alerts/<int:alert_id>/summary")
def alert_summary(alert_id):
    alert = db.get_alert_by_id(alert_id)
    if not alert:
        return jsonify({"error": "Not found"}), 404
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
    def generate():
        last_len = len(event_queue)
        while True:
            current_len = len(event_queue)
            if current_len > last_len:
                for evt in list(event_queue)[last_len:]:
                    yield f"data: {json.dumps(evt)}\n\n"
                last_len = current_len
            time.sleep(0.5)
    return Response(
        generate(),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


# ── VAPI webhook: external systems can POST an event to trigger a call ────────

@app.route("/aria/event", methods=["POST"])
def aria_event():
    """
    POST an ARIA event dict here to immediately trigger a VAPI voice call.
    Can be used from external scripts or to manually test the voice pipeline.

    Example:
        curl -X POST http://localhost:5000/aria/event \\
             -H 'Content-Type: application/json' \\
             -d '{"severity":"CRITICAL","attack_type":"Brute Force",
                  "source_ip":"1.2.3.4","llm_summary":"Test alert."}'
    """
    event  = request.get_json(silent=True) or {}
    result = trigger_voice_alert(event)
    if result:
        return jsonify({"ok": True,  "callId": result.get("id"), "status": result.get("status")})
    return jsonify({"ok": False, "reason": "Call not placed — check logs for details."}), 400


# ── Startup ───────────────────────────────────────────────────────────────────

def start_watcher():
    global watcher
    log_paths = [
        p.strip()
        for p in os.getenv("ARIA_LOG_PATHS", "logs/demo.log").split(",")
        if p.strip()
    ]
    watcher = LogWatcher(log_paths, callback=on_new_log_line)
    watcher.start()


if __name__ == "__main__":
    if os.environ.get("WERKZEUG_RUN_MAIN") == "true" or not app.debug:
        threading.Thread(target=start_watcher, daemon=True).start()
        print("[ARIA] Log Watcher started.")

    app.run(debug=False, threaded=True, port=5000)