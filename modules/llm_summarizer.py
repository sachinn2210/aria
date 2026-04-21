"""
ARIA – LLM Incident Summarizer
Calls local Ollama (llama3.2) to generate plain-English incident summaries.
Falls back to a template-based summary if Ollama is unavailable.

Setup:
    1. Install Ollama: https://ollama.com/download
    2. Pull the model: ollama pull llama3.2
    3. Start Ollama:   ollama serve   (runs on localhost:11434 by default)
"""

import re
import json
import requests
import os
from datetime import datetime

# Ollama runs locally — no API key needed
OLLAMA_URL  = os.getenv("OLLAMA_URL", "http://localhost:11434")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "llama3.2")

PROMPT_TEMPLATE = """You are a cybersecurity analyst AI.
Given the following security incident data, write a single concise paragraph
(2-3 sentences max) in plain English describing what happened, who did it,
what service was targeted, and how severe it is.
Do NOT use bullet points or markdown. Output only the paragraph, nothing else.

Incident data:
{data}
"""


class LLMSummarizer:
    def __init__(self):
        self._ollama_available = None   # None = not yet checked

    def summarize(self, event: dict) -> str:
        """Return a plain-English summary string."""
        if self._is_ollama_available():
            try:
                return self._ollama_summary(event)
            except Exception as e:
                print(f"[ARIA] Ollama error: {e}")
                # Mark as unavailable so we don't keep retrying a dead server
                self._ollama_available = False
        return self._template_summary(event)

    # ── Availability check ─────────────────────────────────────────────────────

    def _is_ollama_available(self) -> bool:
        """
        Ping Ollama once and cache the result.
        Re-checks after every failure so recovery is automatic when
        Ollama comes back online.
        """
        if self._ollama_available is True:
            return True
        try:
            r = requests.get(f"{OLLAMA_URL}/api/tags", timeout=3)
            if r.ok:
                # Confirm the required model is actually pulled
                models = [m.get("name", "") for m in r.json().get("models", [])]
                available = any(OLLAMA_MODEL in m for m in models)
                if not available:
                    print(
                        f"[ARIA] Ollama is running but model '{OLLAMA_MODEL}' "
                        f"not found. Run: ollama pull {OLLAMA_MODEL}"
                    )
                    return False
                self._ollama_available = True
                return True
        except Exception:
            pass
        self._ollama_available = False
        print(
            f"[ARIA] Ollama not reachable at {OLLAMA_URL}. "
            f"Using template summaries. Start with: ollama serve"
        )
        return False

    # ── Ollama inference ───────────────────────────────────────────────────────

    def _ollama_summary(self, event: dict) -> str:
        prompt_data = {
            "attack_type":     event.get("attack_type", "Unknown"),
            "source_ip":       event.get("source_ip", "Unknown"),
            "target_service":  event.get("target_service", "Unknown"),
            "mitre_tag":       event.get("mitre_tag", ""),
            "anomaly_score":   event.get("anomaly_score", 0),
            "severity":        event.get("severity", "LOW"),
            "timestamp":       event.get("timestamp", ""),
            "raw_log_snippet": event.get("raw_log", "")[:300],
        }

        # Safe interpolation — avoids str.format() collision with { } in log data
        prompt = PROMPT_TEMPLATE.replace("{data}", json.dumps(prompt_data, indent=2))

        payload = {
            "model":  OLLAMA_MODEL,
            "prompt": prompt,
            "stream": False,        # get full response at once
            "options": {
                "temperature": 0.3,
                "num_predict": 200, # max tokens (~2-3 sentences)
            },
        }

        response = requests.post(
            f"{OLLAMA_URL}/api/generate",
            json=payload,
            timeout=60,     # local inference can be slow on CPU
        )

        if not response.ok:
            raise Exception(
                f"Ollama HTTP {response.status_code}: {response.text[:200]}"
            )

        data = response.json()
        text = data.get("response", "").strip()

        if not text:
            raise Exception("Ollama returned empty response")

        # Strip any markdown the model adds despite the prompt instruction
        text = re.sub(r"```[\w]*\n?", "", text).strip()
        text = re.sub(r"\*{1,2}(.+?)\*{1,2}", r"\1", text)

        # Only return first paragraph in case model adds extra commentary
        first_para = text.split("\n\n")[0].strip()
        return first_para if first_para else text

    # ── Template fallback ──────────────────────────────────────────────────────

    def _template_summary(self, event: dict) -> str:
        attack = event.get("attack_type") or "suspicious activity"
        ip     = event.get("source_ip")   or "an unknown host"
        svc    = event.get("target_service") or "an unspecified service"
        sev    = event.get("severity", "LOW")
        score  = float(event.get("anomaly_score", 0.0))
        ts     = event.get("timestamp", datetime.utcnow().isoformat())[:19].replace("T", " ")
        mitre  = event.get("mitre_tag", "")

        mitre_clause = f" (MITRE {mitre})" if mitre else ""
        return (
            f"Detected {attack}{mitre_clause} from {ip} targeting {svc} at {ts}. "
            f"Anomaly score: {score:.2f}. Severity assessed as {sev}. "
            f"Immediate investigation recommended if severity is HIGH or CRITICAL."
        )