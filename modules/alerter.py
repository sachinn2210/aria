"""
ARIA – Alerter
Sends notifications via Email (smtplib) and/or Telegram Bot API
when a HIGH or CRITICAL incident is detected.
"""

import os
import json
import smtplib
import urllib.request
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# ── Config from environment ────────────────────────────────────────────────────
SMTP_HOST     = os.getenv("ARIA_SMTP_HOST", "smtp.gmail.com")
SMTP_PORT     = int(os.getenv("ARIA_SMTP_PORT", "587"))
SMTP_USER     = os.getenv("ARIA_SMTP_USER", "")
SMTP_PASSWORD = os.getenv("ARIA_SMTP_PASSWORD", "")
ALERT_TO      = os.getenv("ARIA_ALERT_TO", "")          # recipient email

TELEGRAM_TOKEN  = os.getenv("ARIA_TELEGRAM_TOKEN", "")
TELEGRAM_CHAT   = os.getenv("ARIA_TELEGRAM_CHAT", "")

DASHBOARD_URL   = os.getenv("ARIA_DASHBOARD_URL", "http://localhost:5000")


class Alerter:
    def send(self, event: dict):
        """Dispatch alerts to all configured channels."""
        if SMTP_USER and SMTP_PASSWORD and ALERT_TO:
            try:
                self._send_email(event)
            except Exception as e:
                print(f"[ARIA] Email alert failed: {e}")

        if TELEGRAM_TOKEN and TELEGRAM_CHAT:
            try:
                self._send_telegram(event)
            except Exception as e:
                print(f"[ARIA] Telegram alert failed: {e}")

        if not (SMTP_USER or TELEGRAM_TOKEN):
            # Dev mode – just log
            print(f"[ARIA] ALERT: {event.get('severity')} | "
                  f"{event.get('attack_type')} | {event.get('source_ip')}")

    # ── Email ──────────────────────────────────────────────────────────────────

    def _send_email(self, event: dict):
        subject = (
            f"[ARIA] {event.get('severity','?')} Alert – "
            f"{event.get('attack_type','Unknown')} from {event.get('source_ip','?')}"
        )
        body = self._format_body(event)

        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"]    = SMTP_USER
        msg["To"]      = ALERT_TO
        msg.attach(MIMEText(body, "plain"))

        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as srv:
            srv.ehlo()
            srv.starttls()
            srv.login(SMTP_USER, SMTP_PASSWORD)
            srv.sendmail(SMTP_USER, ALERT_TO, msg.as_string())
        print(f"[ARIA] Email alert sent to {ALERT_TO}")

    # ── Telegram ───────────────────────────────────────────────────────────────

    def _send_telegram(self, event: dict):
        text = (
            f"🚨 *ARIA ALERT* – {event.get('severity','?')}\n"
            f"*Type:* {event.get('attack_type','Unknown')}\n"
            f"*Source IP:* `{event.get('source_ip','?')}`\n"
            f"*Service:* {event.get('target_service','?')}\n"
            f"*MITRE:* {event.get('mitre_tag','–')}\n"
            f"*Score:* {event.get('anomaly_score', 0.0):.2f}\n"
            f"[Open Dashboard]({DASHBOARD_URL})"
        )
        payload = json.dumps({
            "chat_id": TELEGRAM_CHAT,
            "text": text,
            "parse_mode": "Markdown",
            "disable_web_page_preview": True,
        }).encode()
        url = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"
        req = urllib.request.Request(
            url, data=payload,
            headers={"Content-Type": "application/json"}, method="POST"
        )
        with urllib.request.urlopen(req, timeout=10):
            pass
        print("[ARIA] Telegram alert sent.")

    # ── Formatting ─────────────────────────────────────────────────────────────

    def _format_body(self, event: dict) -> str:
        return (
            f"ARIA Incident Report\n"
            f"{'='*40}\n"
            f"Severity     : {event.get('severity','?')}\n"
            f"Attack Type  : {event.get('attack_type','?')}\n"
            f"Source IP    : {event.get('source_ip','?')}\n"
            f"Service      : {event.get('target_service','?')}\n"
            f"MITRE Tag    : {event.get('mitre_tag','–')}\n"
            f"Anomaly Score: {event.get('anomaly_score',0):.2f}\n"
            f"Timestamp    : {event.get('timestamp','?')}\n"
            f"\nLLM Summary:\n{event.get('llm_summary','(generating...)')}\n"
            f"\nRaw Log:\n{event.get('raw_log','')}\n"
            f"\nDashboard: {DASHBOARD_URL}\n"
        )
