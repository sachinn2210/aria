# ARIA – Autonomous Real-time Incident Analysis & Response Agent

> AI-powered lightweight SIEM alternative.  
> Detects, correlates, and explains security incidents in real time.

---

## Quick Start (3 commands)

```bash
pip install -r requirements.txt
python app.py                    # Terminal 1 — Flask server
python demo_log_gen.py           # Terminal 2 — synthetic log traffic
```

Open **http://localhost:5000** to see the dashboard.

---

## Project Structure

```
aria/
├── app.py                   ← Flask app + SSE + route wiring
├── demo_log_gen.py          ← Generates fake logs for testing
├── test_telegram.py         ← Standalone Telegram alert test
├── requirements.txt
├── prometheus.yml           ← Prometheus scrape config
├── .env                     ← Credentials (never commit this)
├── modules/
│   ├── database.py          ← SQLite persistence (WAL, per-thread conn)
│   ├── parser.py            ← Log parser: auth.log, Apache/Nginx, Windows
│   ├── log_watcher.py       ← File tail watcher with rotation detection
│   ├── ml_detector.py       ← Isolation Forest anomaly scoring
│   ├── correlator.py        ← Rule engine + MITRE ATT&CK tagging
│   ├── alerter.py           ← Email (SendGrid + SMTP) + Telegram + Pushover
│   └── llm_summarizer.py    ← Gemini API / template fallback summaries
├── static/
│   ├── css/aria.css         ← Dashboard stylesheet
│   └── js/aria.js           ← Dashboard JavaScript (SSE, charts, table)
└── templates/
    └── index.html           ← Dashboard HTML (links external CSS/JS only)
```

---

## Configuration (environment variables)

Create a `.env` file in the project root. All variables are optional — ARIA
runs without any of them using safe defaults and template-based summaries.

| Variable                  | Default                 | Description                                    |
|---------------------------|-------------------------|------------------------------------------------|
| `ARIA_LOG_PATHS`          | `logs/demo.log`         | Comma-separated file paths to watch            |
| `ARIA_DB_PATH`            | `aria.db`               | SQLite database file path                      |
| `ARIA_MODEL_PATH`         | `aria_model.pkl`        | Isolation Forest model file path               |
| `ARIA_CONTAMINATION`      | `0.05`                  | Isolation Forest contamination rate (0–0.5)    |
| `ARIA_DASHBOARD_URL`      | `http://localhost:5000` | URL embedded in alert messages                 |
| `GEMINI_API_KEY`          | *(empty)*               | Gemini API key for LLM summaries               |
| `ARIA_ALERT_TO`           | *(empty)*               | Sender email address (SendGrid from-address)   |
| `ARIA_RECEIVER_EMAIL`     | *(empty)*               | Recipient email address                        |
| `SENDGRID_API_KEY`        | *(empty)*               | SendGrid API key (primary email delivery)      |
| `FALLBACK_SMTP_HOST`      | `smtp.gmail.com`        | SMTP server (used only if SendGrid fails)      |
| `FALLBACK_SMTP_PORT`      | `587`                   | SMTP port                                      |
| `FALLBACK_SMTP_USER`      | *(empty)*               | SMTP username / Gmail address                  |
| `FALLBACK_SMTP_PASSWORD`  | *(empty)*               | SMTP password / Gmail app password             |
| `ARIA_TELEGRAM_TOKEN`     | *(empty)*               | Telegram Bot token                             |
| `ARIA_TELEGRAM_CHAT_ID`   | *(empty)*               | Telegram chat ID                               |
| `ARIA_PUSHOVER_TOKEN`     | *(empty)*               | Pushover application token                     |
| `ARIA_PUSHOVER_USER`      | *(empty)*               | Pushover user key                              |

Load your `.env` before starting:

```bash
export $(cat .env | grep -v '^#' | xargs) && python app.py
```

> **Note:** The `grep -v '^#'` strips comment lines that `xargs` cannot handle.

---

## Monitoring Real Logs

Point `ARIA_LOG_PATHS` at your actual log files:

```bash
# Linux auth log + Apache
ARIA_LOG_PATHS=/var/log/auth.log,/var/log/apache2/access.log python app.py

# Multiple paths
ARIA_LOG_PATHS=/var/log/auth.log,/var/log/nginx/access.log,/var/log/syslog python app.py
```

ARIA will wait for files to appear if they don't exist yet, and automatically
handles log rotation (inode change detection) without missing any lines.

---

## Alert Delivery

Alerts are sent for **HIGH** and **CRITICAL** severity events only.

**Delivery order:**
1. **Telegram** — instant push notification (fastest)
2. **Email via SendGrid** — primary email delivery
3. **Email via SMTP** — fallback only if SendGrid fails or is unconfigured
4. **Pushover** — optional additional channel

All channels are independent — a failure in one does not block the others.

To test Telegram before running the full app:

```bash
python test_telegram.py
```

---

## Prometheus & Grafana

ARIA exposes Prometheus metrics at `/metrics` (via `prometheus_flask_exporter`).

| Metric                  | Description                          |
|-------------------------|--------------------------------------|
| `aria_alerts_total`     | Total HIGH/CRITICAL alerts sent      |
| `aria_anomalies_total`  | Total correlated incidents detected  |

Use the provided `prometheus.yml` to scrape ARIA:

```bash
prometheus --config.file=prometheus.yml
```

Point Grafana at your Prometheus instance and import a dashboard using the
`aria_alerts_total` and `aria_anomalies_total` metrics.

---

## MITRE ATT&CK Coverage

| Technique ID | Name                             | Triggered by                        |
|--------------|----------------------------------|-------------------------------------|
| T1110        | Brute Force                      | ≥10 auth failures in 5 min          |
| T1110.001    | Password Guessing                | Invalid user login attempts         |
| T1548        | Abuse Elevation Control          | sudo / privilege escalation         |
| T1083        | File and Directory Discovery     | Path traversal / directory scan     |
| T1078        | Valid Accounts                   | Unauthorized or anomalous login     |
| T1078.003    | Local Accounts                   | Explicit credential use             |
| T1499        | Endpoint Denial of Service       | HTTP 5xx spikes                     |
| T1558.003    | Kerberoasting                    | Kerberos TGT requests (Windows)     |

---

## Dashboard Features

| Component           | Description                                                   |
|---------------------|---------------------------------------------------------------|
| Stat Cards          | Live counts: Critical, High, Last Hour, Total                |
| Timeline Chart      | Events per minute over last 60 minutes (Chart.js)            |
| Anomaly Gauge       | Average anomaly score with color-coded needle                |
| Severity Doughnut   | LOW / MEDIUM / HIGH / CRITICAL breakdown                     |
| Top Offending IPs   | Ranked by hit count with correct max-severity badge          |
| Live Event Feed     | SSE-powered real-time log ticker (up to 200 lines)           |
| Alert Table         | Searchable and filterable by severity, IP, attack type, MITRE|
| AI Summary Modal    | Gemini-generated plain-English incident explanation          |

---

## Log Format Support

| Format               | Example source                        | Detected by         |
|----------------------|---------------------------------------|---------------------|
| Linux auth.log       | `/var/log/auth.log`                   | `sshd`, `sudo`      |
| Apache/Nginx access  | `/var/log/apache2/access.log`         | Combined log format |
| Windows Event Log    | Text export with EventID fields       | EventID 4624/4625+  |
| Generic              | Any log containing a valid IP address | IP regex fallback   |

---

## ML Model

ARIA uses an **Isolation Forest** trained on synthetic baseline traffic at
startup. For better accuracy on your infrastructure:

```python
# In modules/ml_detector.py, replace fit_baseline() with real data:
import numpy as np
X_real = np.load("your_baseline_features.npy")   # shape: (n_samples, 8)
detector.fit_baseline(X=X_real)
```

The model is persisted to `aria_model.pkl` after fitting. Delete this file to
force a refit on next startup.

**Feature vector (8 dimensions):**

| Index | Feature         | Description                     |
|-------|-----------------|---------------------------------|
| 0     | hour            | Hour of day (0–23)              |
| 1     | first_octet     | Source IP first octet           |
| 2     | last_octet      | Source IP last octet            |
| 3     | attack_code     | Encoded attack type (0–5)       |
| 4     | service_code    | Encoded target service (0–4)    |
| 5     | is_failure      | Auth failure flag (0/1)         |
| 6     | is_root         | Root user involved (0/1)        |
| 7     | port            | Source port (0 if unknown)      |

---

## Production Deployment

```bash
pip install gunicorn
gunicorn -w 1 -b 0.0.0.0:5000 --timeout 120 app:app
```

> Use `-w 1` (single worker) — ARIA's in-memory `event_queue` and ML model
> are not shared across workers. For multi-worker setups, move the queue to
> Redis and the model to a shared store.

Recommended stack: **nginx → gunicorn → ARIA**, with Prometheus + Grafana for
metrics visualization and Loki for log aggregation.

---

## What's Complete vs. What's Left

### ✅ Complete
- Log watcher with rotation detection and graceful shutdown
- Parser for auth.log, Apache/Nginx, Windows Event Logs, and generic IP fallback
- SQLite database with WAL mode, per-thread connections, and correct severity ordering
- Isolation Forest ML detector with feature engineering and model persistence
- Event correlator with burst detection, threshold rules, and MITRE tagging
- LLM summarizer with Gemini API + template fallback
- Alerter with SendGrid → SMTP fallback, Telegram, and Pushover
- Flask API with SSE streaming and Prometheus metrics
- Dashboard with live feed, charts, gauge, and AI summary modal

### 🔧 To complete for your environment
1. **Add API keys** — Set `GEMINI_API_KEY` in `.env` and run `python test_telegram.py` to verify alerts
2. **Point at real logs** — Set `ARIA_LOG_PATHS` to your actual log file paths
3. **Tune the ML model** — Replace synthetic baseline with real traffic features for better accuracy
4. **Set `ARIA_CONTAMINATION`** — Adjust the anomaly sensitivity for your environment (default `0.05`)
5. **Optional: Twilio voice alerts** — Add `alerter._send_twilio()` for critical-alert phone calls
6. **Deploy** — Use gunicorn + nginx on a VPS; configure Prometheus + Grafana for observability