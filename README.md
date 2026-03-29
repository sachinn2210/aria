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
├── requirements.txt
├── modules/
│   ├── database.py          ← SQLite persistence layer
│   ├── parser.py            ← Log parsing (auth.log, Apache, Windows)
│   ├── log_watcher.py       ← File tail watcher (Watchdog-style)
│   ├── ml_detector.py       ← Isolation Forest anomaly scoring
│   ├── correlator.py        ← Rule engine + MITRE ATT&CK tagging
│   ├── alerter.py           ← Email + Telegram notifications
│   └── llm_summarizer.py    ← Gemini API / template summaries
└── templates/
    └── index.html           ← Full dashboard (Chart.js + SSE)
```

---

## Configuration (environment variables)

| Variable              | Default           | Description                              |
|-----------------------|-------------------|------------------------------------------|
| `ARIA_LOG_PATHS`      | `logs/demo.log`   | Comma-separated paths to watch           |
| `ARIA_DB_PATH`        | `aria.db`         | SQLite database file                     |
| `ARIA_MODEL_PATH`     | `aria_model.pkl`  | Isolation Forest model file              |
| `GEMINI_API_KEY`      | *(empty)*         | Gemini API key for LLM summaries         |
| `ARIA_SMTP_HOST`      | `smtp.gmail.com`  | SMTP server for email alerts             |
| `ARIA_SMTP_PORT`      | `587`             | SMTP port                                |
| `ARIA_SMTP_USER`      | *(empty)*         | Your Gmail address                       |
| `ARIA_SMTP_PASSWORD`  | *(empty)*         | Gmail app password                       |
| `ARIA_ALERT_TO`       | *(empty)*         | Recipient email address                  |
| `ARIA_TELEGRAM_TOKEN` | *(empty)*         | Telegram Bot token                       |
| `ARIA_TELEGRAM_CHAT`  | *(empty)*         | Telegram chat ID                         |
| `ARIA_DASHBOARD_URL`  | `http://localhost:5000` | Link in alert messages           |

Set these in a `.env` file and load with:
```bash
export $(cat .env | xargs) && python app.py
```

---

## Monitoring Real Logs

Point `ARIA_LOG_PATHS` at your actual log files:

```bash
# Linux auth log + Apache
ARIA_LOG_PATHS=/var/log/auth.log,/var/log/apache2/access.log python app.py

# Multiple paths
ARIA_LOG_PATHS=/var/log/auth.log,/var/log/nginx/access.log,/var/log/syslog python app.py
```

---

## What's Built (75%)

### ✅ Complete
- **Log Watcher** — file tail with threading, auto-wait for file creation
- **Log Parser** — regex-based parser for auth.log, Apache/Nginx, Windows Event Logs
- **SQLite Database** — full schema, all queries, WAL mode for concurrency
- **ML Detector** — Isolation Forest with feature engineering + baseline fit
- **Event Correlator** — burst detection, threshold rules, MITRE ATT&CK tagging
- **LLM Summarizer** — Gemini API integration with template fallback
- **Alerter** — Email (smtplib) + Telegram Bot API
- **Flask API** — `/api/stats`, `/api/alerts`, `/api/timeline`, `/api/severity_breakdown`, `/api/top_ips`, `/stream` (SSE)
- **Dashboard** — Real-time event feed, anomaly gauge, timeline chart, severity doughnut, top IPs table, alert table with search/filter, AI summary modal

### 🔧 Your 25% to complete
1. **Gemini API Key** — Add your free key to `.env` and test LLM summaries
2. **Email/Telegram config** — Fill in credentials in `.env` to enable real alerts
3. **Real log paths** — Point `ARIA_LOG_PATHS` at `/var/log/auth.log` etc.
4. **Optional Voice Agent** — Add Twilio integration in `alerter.py` for critical alerts (Twilio free trial)
5. **Tune ML model** — Replace `fit_baseline()` synthetic data with real baseline logs from your server for better accuracy
6. **Deploy** — Host on a VPS or cloud VM; add `gunicorn` for production serving

---

## MITRE ATT&CK Coverage

| Technique ID    | Name                              | Triggered by               |
|-----------------|-----------------------------------|----------------------------|
| T1110           | Brute Force                       | ≥10 auth failures / 5 min  |
| T1110.001       | Password Guessing                 | Invalid user events         |
| T1548           | Abuse Elevation Control           | sudo / privilege escalation |
| T1083           | File and Directory Discovery      | Path traversal / enumeration |
| T1078           | Valid Accounts                    | Unauthorized / anomalous login |
| T1499           | Endpoint Denial of Service        | HTTP 5xx spikes             |
| T1558.003       | Kerberoasting                     | Kerberos TGT requests       |

---

## Dashboard Features

| Component             | Description                                              |
|-----------------------|----------------------------------------------------------|
| Stat Cards            | Live counts: Critical, High, Last Hour, Total           |
| Timeline Chart        | Events per minute over last 60 min (Chart.js)           |
| Anomaly Gauge         | Average anomaly score with color-coded needle           |
| Severity Doughnut     | LOW / MEDIUM / HIGH / CRITICAL breakdown                |
| Top Offending IPs     | Ranked by hit count with max severity badge             |
| Live Event Feed       | SSE-powered real-time log ticker                        |
| Alert Table           | Searchable, filterable, sortable by risk score          |
| AI Summary Modal      | Gemini-generated plain-English incident explanation     |
