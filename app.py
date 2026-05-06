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
from modules.proxy_server import start_proxy, stop_proxy, proxy_status
from modules.log_ingestion import ingest_log_text, fetch_remote_log, detect_log_format, save_uploaded_log
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
    summary = summarizer.summarize(event)
    db.update_alert_summary(alert_id, summary)
    event["llm_summary"] = summary

    severity = event.get("severity", "")
    if severity in ("HIGH", "CRITICAL"):
        alerter.send(event)
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


# ── Core Routes ────────────────────────────────────────────────────────────────

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


# ── VAPI webhook ──────────────────────────────────────────────────────────────

@app.route("/aria/event", methods=["POST"])
def aria_event():
    event  = request.get_json(silent=True) or {}
    result = trigger_voice_alert(event)
    if result:
        return jsonify({"ok": True, "callId": result.get("id"), "status": result.get("status")})
    return jsonify({"ok": False, "reason": "Call not placed — check logs for details."}), 400


# ── Proxy Routes ──────────────────────────────────────────────────────────────

@app.route("/api/proxy/start", methods=["POST"])
def proxy_start():
    """
    Start the reverse proxy.
    Body: { "target": "https://example.com", "port": 8888 }
    The proxy log file is automatically added to ARIA's watch list.
    """
    data       = request.get_json(silent=True) or {}
    target     = data.get("target", "").strip()
    port       = int(data.get("port", 8888))
    log_file   = data.get("log_file", "logs/proxy_access.log")

    if not target:
        return jsonify({"ok": False, "error": "target URL is required"}), 400

    result = start_proxy(target, port, log_file)
    if not result["ok"]:
        return jsonify(result), 500

    # Hot-add the proxy log file to the running watcher
    global watcher
    if watcher and log_file not in watcher.paths:
        watcher.paths.append(log_file)
        t = threading.Thread(
            target=watcher._tail,
            args=(log_file,),
            daemon=True,
            name=f"tail:{log_file}",
        )
        watcher._threads.append(t)
        t.start()
        print(f"[ARIA] Hot-added proxy log to watcher: {log_file}")

    return jsonify(result)


@app.route("/api/proxy/stop", methods=["POST"])
def proxy_stop():
    return jsonify(stop_proxy())


@app.route("/api/proxy/status")
def proxy_status_route():
    return jsonify(proxy_status())


# ── Log Ingestion Routes ──────────────────────────────────────────────────────

@app.route("/api/ingest/text", methods=["POST"])
def ingest_text():
    """
    Paste raw log lines directly into ARIA.
    Body: { "text": "<raw log content>", "source": "my-server" }
    """
    data   = request.get_json(silent=True) or {}
    text   = data.get("text", "").strip()
    source = data.get("source", "upload").strip() or "upload"

    if not text:
        return jsonify({"ok": False, "error": "No log text provided"}), 400

    fmt   = detect_log_format(text[:2000])
    count = ingest_log_text(text, on_new_log_line, source_tag=source)

    # Also persist to disk so the watcher re-ingests on restart
    try:
        path = save_uploaded_log(text, filename=f"{source}.log")
    except Exception:
        path = None

    return jsonify({
        "ok":      True,
        "lines":   count,
        "format":  fmt,
        "saved_to": path,
        "source":  source,
    })


@app.route("/api/ingest/url", methods=["POST"])
def ingest_url():
    """
    Fetch a raw log file from a URL and ingest into ARIA.
    Body: { "url": "http://myserver/access.log", "source": "my-server" }
    """
    data   = request.get_json(silent=True) or {}
    url    = data.get("url", "").strip()
    source = data.get("source", "remote").strip() or "remote"

    if not url:
        return jsonify({"ok": False, "error": "url is required"}), 400

    result = fetch_remote_log(url)
    if not result["ok"]:
        return jsonify(result), 400

    processed = 0
    for line in result["lines"]:
        try:
            on_new_log_line(line, source)
            processed += 1
        except Exception:
            pass

    return jsonify({
        "ok":        True,
        "fetched":   result["count"],
        "processed": processed,
        "format":    result["format"],
        "url":       url,
    })


@app.route("/api/ingest/upload", methods=["POST"])
def ingest_upload():
    """
    Multipart file upload endpoint for log files.
    Form field: file  (the log file)
                source (optional label)
    """
    if "file" not in request.files:
        return jsonify({"ok": False, "error": "No file part"}), 400

    f      = request.files["file"]
    source = request.form.get("source", f.filename or "upload")

    try:
        text = f.read().decode("utf-8", errors="replace")
    except Exception as e:
        return jsonify({"ok": False, "error": f"Could not read file: {e}"}), 400

    fmt   = detect_log_format(text[:2000])
    count = ingest_log_text(text, on_new_log_line, source_tag=source)

    try:
        path = save_uploaded_log(text, filename=f.filename or "upload.log")
    except Exception:
        path = None

    return jsonify({
        "ok":      True,
        "lines":   count,
        "format":  fmt,
        "saved_to": path,
        "source":  source,
    })


@app.route("/api/ingest/windows", methods=["GET"])
def ingest_windows():
    """
    Read Windows Event Logs from the local machine (Windows only).
    Query params: log=Security&max=200
    """
    from modules.log_ingestion import read_windows_event_logs, is_windows
    if not is_windows():
        return jsonify({
            "ok":    False,
            "error": "Windows Event Log reader is only available on Windows. "
                     "Use the log upload or paste feature on Linux/Mac."
        }), 400

    log_name   = request.args.get("log", "Security")
    max_events = int(request.args.get("max", 200))

    lines     = list(read_windows_event_logs(log_name, max_events))
    processed = 0
    for line in lines:
        if not line.startswith("#"):
            try:
                on_new_log_line(line, f"windows:{log_name}")
                processed += 1
            except Exception:
                pass

    return jsonify({
        "ok":        True,
        "read":      len(lines),
        "processed": processed,
        "log":       log_name,
    })


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