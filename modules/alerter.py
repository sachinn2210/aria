import os
import json
import smtplib
import requests

from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail, Email, To, Content
from dotenv import load_dotenv

load_dotenv()

# ── Environment Config ─────────────────────────────────────────────────────────

ALERT_TO           = os.getenv("ARIA_ALERT_TO", "")
RECEIVER_EMAIL     = os.getenv("ARIA_RECEIVER_EMAIL", "")

SENDGRID_API_KEY   = os.getenv("SENDGRID_API_KEY", "")

FALLBACK_SMTP_HOST     = os.getenv("FALLBACK_SMTP_HOST", "smtp.gmail.com")
FALLBACK_SMTP_PORT     = int(os.getenv("FALLBACK_SMTP_PORT", "587"))
FALLBACK_SMTP_USER     = os.getenv("FALLBACK_SMTP_USER", "")
FALLBACK_SMTP_PASSWORD = os.getenv("FALLBACK_SMTP_PASSWORD", "")

TELEGRAM_TOKEN = os.getenv("ARIA_TELEGRAM_TOKEN", "")
TELEGRAM_CHAT  = os.getenv("ARIA_TELEGRAM_CHAT_ID", "")

PUSHOVER_TOKEN = os.getenv("ARIA_PUSHOVER_TOKEN", "")
PUSHOVER_USER  = os.getenv("ARIA_PUSHOVER_USER", "")

DASHBOARD_URL = os.getenv("ARIA_DASHBOARD_URL", "http://localhost:5000")


# ── Alerter Class ──────────────────────────────────────────────────────────────

class Alerter:
    def send(self, event: dict):
        severity = event.get("severity", "").upper()

        if severity not in ("HIGH", "CRITICAL"):
            print("[ARIA] Alerter: severity filtered, skipping.")
            return

        # Telegram — instant alert
        if TELEGRAM_TOKEN and TELEGRAM_CHAT:
            try:
                self._send_telegram(event)
            except Exception as e:
                print(f"[ARIA] Telegram alert failed: {e}")

        # email — SendGrid with SMTP as true fallback
        if ALERT_TO and RECEIVER_EMAIL:
            try:
                self._send_email(event)
            except Exception as e:
                print(f"[ARIA] All email delivery failed: {e}")

        # Pushover — optional
        if PUSHOVER_TOKEN and PUSHOVER_USER:
            try:
                self._send_pushover(event)
            except Exception as e:
                print(f"[ARIA] Pushover alert failed: {e}")



    def _send_email(self, event: dict):
        """Try SendGrid first; fall back to SMTP only if SendGrid fails."""
        # FIX: SMTP only reached if SendGrid is missing or failed
        self._send_smtp_fallback(event)
        print("[ARIA] Email sent via Normal SMTP Email.")
        if SENDGRID_API_KEY:
            try:
                self._send_sendgrid(event)
                print("[ARIA] Email sent via SendGrid.")
                return  # FIX: Return on success — don't also send SMTP
            except Exception as e:
                print(f"[ARIA] SendGrid failed, falling back to SMTP: {e}")


    def _send_sendgrid(self, event: dict):
        subject = (
            f"[ARIA] {event.get('severity', '?')} Alert – "
            f"{event.get('attack_type', 'Unknown')} from {event.get('source_ip', '?')}"
        )
        body = self._format_body(event)

        message = Mail(
            from_email=Email(ALERT_TO),
            to_emails=To(RECEIVER_EMAIL),
            subject=subject,
            plain_text_content=Content("text/plain", body)
        )

        sg = SendGridAPIClient(SENDGRID_API_KEY)
        response = sg.send(message)

        if response.status_code != 202:
            raise Exception(f"Unexpected SendGrid status: {response.status_code}")

        print(f"[ARIA] SendGrid sent (status {response.status_code}).")



    def _send_smtp_fallback(self, event: dict):
        subject = f"[ARIA Fallback] {event.get('severity', '?')} Alert"
        body    = self._format_body(event)

        msg = MIMEMultipart()
        msg["From"]    = FALLBACK_SMTP_USER
        msg["To"]      = RECEIVER_EMAIL
        msg["Subject"] = subject
        msg.attach(MIMEText(body, "plain"))

        with smtplib.SMTP(FALLBACK_SMTP_HOST, FALLBACK_SMTP_PORT, timeout=20) as server:
            server.ehlo()
            server.starttls()
            server.ehlo()
            server.login(FALLBACK_SMTP_USER, FALLBACK_SMTP_PASSWORD)
            server.sendmail(FALLBACK_SMTP_USER, RECEIVER_EMAIL, msg.as_string())

        print("[ARIA] SMTP fallback sent.")



    def _send_telegram(self, event: dict):
        text = (
            f"<b>🚨 ARIA ALERT</b> – {event.get('severity', '?')}\n"
            f"<b>Type:</b> {event.get('attack_type', 'Unknown')}\n"
            f"<b>Source IP:</b> <code>{event.get('source_ip', '?')}</code>\n"
            f"<b>Service:</b> {event.get('target_service', '?')}\n"
            f"<b>MITRE:</b> {event.get('mitre_tag', '–')}\n"
            f"<b>Score:</b> {event.get('anomaly_score', 0.0):.2f}\n"
            f'<a href="{DASHBOARD_URL}">Open Dashboard</a>'
        )

        # FIX: Use requests consistently instead of mixing urllib.request
        response = requests.post(
            f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage",
            json={
                "chat_id": TELEGRAM_CHAT,
                "text": text,
                "parse_mode": "HTML",
                "disable_web_page_preview": True,
            },
            timeout=10
        )

        result = response.json()
        if not response.ok or not result.get("ok"):
            raise Exception(f"Telegram API error: {result.get('description', 'Unknown')}")

        print("[ARIA] Telegram alert sent.")



    def _send_pushover(self, event: dict):
        text = (
            f"ARIA ALERT [{event.get('severity', '?')}]\n"
            f"{event.get('attack_type', '?')} | {event.get('source_ip', '?')}"
        )

        response = requests.post(
            "https://api.pushover.net/1/messages.json",
            data={
                "token":   PUSHOVER_TOKEN,
                "user":    PUSHOVER_USER,
                "message": text,
            },
            timeout=10
        )

        result = response.json()
        if not response.ok or result.get("status") != 1:
            raise Exception(f"Pushover error: {result.get('errors', 'Unknown')}")

        print("[ARIA] Pushover alert sent.")



    def _format_body(self, event: dict) -> str:
        return (
            f"ARIA Incident Report\n"
            f"{'=' * 40}\n"
            f"Severity     : {event.get('severity', '?')}\n"
            f"Attack Type  : {event.get('attack_type', '?')}\n"
            f"Source IP    : {event.get('source_ip', '?')}\n"
            f"Service      : {event.get('target_service', '?')}\n"
            f"MITRE Tag    : {event.get('mitre_tag', '–')}\n"
            f"Anomaly Score: {event.get('anomaly_score', 0):.2f}\n"
            f"Timestamp    : {event.get('timestamp', '?')}\n"
            f"\nLLM Summary:\n{event.get('llm_summary', '(generating...)')}\n"
            f"\nRaw Log:\n{event.get('raw_log', '')}\n"
            f"\nDashboard: {DASHBOARD_URL}\n"
        )



if __name__ == "__main__":
    test_event = {
        "severity":      "HIGH",
        "attack_type":   "SSH Brute Force",
        "source_ip":     "192.168.1.10",
        "target_service": "ssh",
        "mitre_tag":     "T1110",
        "anomaly_score": 0.92,
    }
    print("Testing Alerter...")
    Alerter().send(test_event)