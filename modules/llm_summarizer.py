"""
ARIA – LLM Incident Summarizer
Calls the Gemini API (free tier) to generate plain-English incident summaries.
Falls back to a template-based summary if the API key is absent.
"""

import os
import json
import urllib.request
import urllib.error
from datetime import datetime

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
GEMINI_URL = (
    "https://generativelanguage.googleapis.com/v1beta/models/"
    "gemini-1.5-flash:generateContent?key={key}"
)

PROMPT_TEMPLATE = """You are a cybersecurity analyst AI. 
Given the following security incident data, write a single concise paragraph 
(2-3 sentences max) in plain English describing what happened, who did it, 
what service was targeted, and how severe it is.
Do NOT use bullet points or markdown. Output only the paragraph.

Incident data:
{data}
"""


class LLMSummarizer:
    def summarize(self, event: dict) -> str:
        """Return a plain-English summary string."""
        if GEMINI_API_KEY:
            try:
                return self._gemini_summary(event)
            except Exception as e:
                print(f"[ARIA] Gemini API error: {e}")
        return self._template_summary(event)

    # ── Gemini ─────────────────────────────────────────────────────────────────

    def _gemini_summary(self, event: dict) -> str:
        prompt_data = {
            "attack_type":   event.get("attack_type", "Unknown"),
            "source_ip":     event.get("source_ip", "Unknown"),
            "target_service":event.get("target_service", "Unknown"),
            "mitre_tag":     event.get("mitre_tag", ""),
            "anomaly_score": event.get("anomaly_score", 0),
            "severity":      event.get("severity", "LOW"),
            "timestamp":     event.get("timestamp", ""),
            "raw_log_snippet": event.get("raw_log", "")[:300],
        }
        prompt = PROMPT_TEMPLATE.format(data=json.dumps(prompt_data, indent=2))

        body = json.dumps({
            "contents": [{"parts": [{"text": prompt}]}],
            "generationConfig": {"maxOutputTokens": 200, "temperature": 0.3},
        }).encode()

        req = urllib.request.Request(
            GEMINI_URL.format(key=GEMINI_API_KEY),
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read())

        return (
            data["candidates"][0]["content"]["parts"][0]["text"].strip()
        )

    # ── Template fallback ──────────────────────────────────────────────────────

    def _template_summary(self, event: dict) -> str:
        attack  = event.get("attack_type", "suspicious activity")
        ip      = event.get("source_ip") or "an unknown host"
        svc     = event.get("target_service") or "an unspecified service"
        sev     = event.get("severity", "LOW")
        score   = event.get("anomaly_score", 0.0)
        ts      = event.get("timestamp", datetime.utcnow().isoformat())[:19].replace("T", " ")
        mitre   = event.get("mitre_tag", "")

        mitre_clause = f" (MITRE {mitre})" if mitre else ""
        return (
            f"Detected {attack}{mitre_clause} from {ip} targeting {svc} at {ts}. "
            f"Anomaly score: {score:.2f}. Severity assessed as {sev}. "
            f"Immediate investigation recommended if severity is HIGH or CRITICAL."
        )
