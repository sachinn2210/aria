import requests
from dotenv import load_dotenv
import os

load_dotenv()

token = os.getenv("ARIA_TELEGRAM_TOKEN")
allowed_chat_id = os.getenv("ARIA_TELEGRAM_CHAT_ID")


def send_telegram_alert(message: str) -> bool:
    if not token or not allowed_chat_id:
        print("[Telegram] Credentials missing — set ARIA_TELEGRAM_TOKEN and ARIA_TELEGRAM_CHAT_ID in .env")
        return False

    url = f"https://api.telegram.org/bot{token}/sendMessage"

    payload = {
        "chat_id": allowed_chat_id,
        "text": message,
        "parse_mode": "HTML",   # Allows <b>, <code>, etc. in alert messages
    }

    try:
        response = requests.post(url, json=payload, timeout=5)
        result = response.json()

        if response.ok and result.get("ok"):
            print("[Telegram] Alert sent successfully.")
            return True
        else:
            print(f"[Telegram] API error: {result.get('description', 'Unknown error')}")
            return False

    except requests.exceptions.RequestException as e:
        print(f"[Telegram] Request failed: {e}")
        return False


# FIX: Guard so this doesn't fire on import
if __name__ == "__main__":
    send_telegram_alert("⚠ ARIA alert pipeline active")