import logging
import smtplib
from email.mime.text import MIMEText
from email.utils import formataddr, parseaddr

from nta.config import settings

logger = logging.getLogger(__name__)


def _is_email_configured() -> bool:
    return all(
        [
            settings.smtp_host,
            settings.smtp_user,
            settings.smtp_pass,
            settings.alert_email_to,
        ]
    )


def _format_from_address() -> str:
    if settings.smtp_from:
        name, address = parseaddr(settings.smtp_from)
        if address:
            return formataddr((name or settings.smtp_from_name, address))
    return formataddr((settings.smtp_from_name, settings.smtp_user))


def send_email_alert(subject: str, message: str) -> dict[str, object]:
    if not _is_email_configured():
        return {"sent": False, "reason": "Email not configured", "recipient": settings.alert_email_to}

    body = MIMEText(message, "plain", "utf-8")
    body["Subject"] = subject
    body["From"] = _format_from_address()
    body["To"] = settings.alert_email_to

    from_address = parseaddr(body["From"])[1] or settings.smtp_user

    try:
        if settings.smtp_secure:
            server = smtplib.SMTP_SSL(settings.smtp_host, settings.smtp_port, timeout=20)
        else:
            server = smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=20)
            server.starttls()

        with server:
            server.login(settings.smtp_user, settings.smtp_pass)
            server.sendmail(from_address, [settings.alert_email_to], body.as_string())

        logger.info("Email alert sent to %s", settings.alert_email_to)
        return {
            "sent": True,
            "recipient": settings.alert_email_to,
            "subject": subject,
        }
    except Exception as exc:
        logger.warning("Email alert failed: %s", exc)
        return {
            "sent": False,
            "reason": str(exc),
            "recipient": settings.alert_email_to,
            "subject": subject,
        }
