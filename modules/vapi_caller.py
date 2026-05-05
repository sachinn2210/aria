"""
ARIA  VAPI Voice Caller
Triggers an outbound phone call via VAPI when a HIGH/CRITICAL alert fires.
The call uses a VAPI assistant (configured on dashboard.vapi.ai) and passes
the AI-generated incident summary as a variable the assistant reads aloud.

Required environment variables:
    VAPI_PRIVATE_KEY         from dashboard.vapi.ai → Account → API Keys
    VAPI_PHONE_NUMBER_ID     outbound-capable number ID from VAPI dashboard
    ARIA_ALERT_CALL_TO       admin phone number in E.164 format (+91xxxxxxxxxx)

Optional:
    VAPI_ASSISTANT_ID        VAPI assistant ID (default: the one you configured)
    ARIA_VOICE_SEVERITIES    comma-separated severities that trigger a call
                              (default: "CRITICAL")
"""

import os
import requests

VAPI_PRIVATE_KEY      = os.environ.get("VAPI_PRIVATE_KEY", "")
VAPI_ASSISTANT_ID     = os.environ.get("VAPI_ASSISTANT_ID", "335e5f04-54bf-4b56-b2fe-09c42c1e2951")
VAPI_PHONE_NUMBER_ID  = os.environ.get("VAPI_PHONE_NUMBER_ID", "")
ARIA_ALERT_CALL_TO    = os.environ.get("ARIA_ALERT_CALL_TO", "")

VOICE_ALERT_SEVERITIES = set(
    s.strip().upper()
    for s in os.environ.get("ARIA_VOICE_SEVERITIES", "CRITICAL").split(",")
    if s.strip()
)

_VAPI_CALLS_URL = "https://api.vapi.ai/call"


def trigger_voice_alert(event: dict) -> dict | None:
    """
    Place an outbound VAPI call for a security event.
    Returns the VAPI call object on success, None if skipped or misconfigured.

    The VAPI assistant must have a {{summary}} variable in its prompt,
    e.g.: "You are ARIA. Read this alert to the admin: {{summary}}"
    """
    severity = event.get("severity", "").upper()
    if severity not in VOICE_ALERT_SEVERITIES:
        return None

    if not all([VAPI_PRIVATE_KEY, VAPI_PHONE_NUMBER_ID, ARIA_ALERT_CALL_TO]):
        print(
            "[ARIA/VAPI] Skipping voice call — missing one of: "
            "VAPI_PRIVATE_KEY, VAPI_PHONE_NUMBER_ID, ARIA_ALERT_CALL_TO"
        )
        return None

    summary = event.get("llm_summary") or _build_fallback_summary(event)

    payload = {
        "assistantId":    VAPI_ASSISTANT_ID,
        "phoneNumberId":  VAPI_PHONE_NUMBER_ID,
        "customer":       {"number": ARIA_ALERT_CALL_TO},
        "assistantOverrides": {
            "variableValues": {"summary": summary}
        },
    }

    try:
        r = requests.post(
            _VAPI_CALLS_URL,
            headers={
                "Authorization": f"Bearer {VAPI_PRIVATE_KEY}",
                "Content-Type":  "application/json",
            },
            json=payload,
            timeout=20,
        )
        r.raise_for_status()
        result = r.json()
        print(
            f"[ARIA/VAPI] Call placed → {ARIA_ALERT_CALL_TO} "
            f"(callId: {result.get('id')}, status: {result.get('status')})"
        )
        return result
    except requests.HTTPError as e:
        print(f"[ARIA/VAPI] HTTP error placing call: {e.response.status_code}  {e.response.text[:300]}")
    except Exception as e:
        print(f"[ARIA/VAPI] Failed to place call: {e}")
    return None


def _build_fallback_summary(event: dict) -> str:
    """Used when llm_summary is not yet ready."""
    return (
        f"Severity {event.get('severity', 'unknown')} alert. "
        f"{event.get('attack_type', 'Suspicious activity')} detected from "
        f"{event.get('source_ip', 'unknown IP')} targeting "
        f"{event.get('target_service', 'unknown service')}. "
        f"Anomaly score: {float(event.get('anomaly_score', 0)):.2f}. "
        f"Please check the ARIA dashboard immediately."
    )