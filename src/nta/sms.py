import requests

from nta.config import settings


def send_sms_alert(message: str) -> dict[str, object]:
    if not all(
        [
            settings.infobip_base_url,
            settings.infobip_api_key,
            settings.infobip_sender,
            settings.alert_phone_number,
        ]
    ):
        return {"sent": False, "reason": "SMS not configured"}

    url = f"{settings.infobip_base_url.rstrip('/')}/sms/2/text/advanced"
    headers = {
        "Authorization": f"App {settings.infobip_api_key}",
        "Content-Type": "application/json",
        "Accept": "application/json",
    }
    payload = {
        "messages": [
            {
                "from": settings.infobip_sender,
                "destinations": [{"to": settings.alert_phone_number}],
                "text": message,
            }
        ]
    }

    response = requests.post(url, json=payload, headers=headers, timeout=10)
    response.raise_for_status()
    return {"sent": True, "status_code": response.status_code}
