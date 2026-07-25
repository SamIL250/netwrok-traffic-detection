from sqlalchemy.orm import Session

from nta.email_alerts import send_email_alert
from nta.models import AlertDelivery


def record_alert_delivery(
    db: Session,
    *,
    anomaly_id: int | None,
    channel: str,
    recipient: str,
    subject: str,
    message: str,
    status: str,
    error_detail: str = "",
) -> AlertDelivery:
    delivery = AlertDelivery(
        anomaly_id=anomaly_id,
        channel=channel,
        recipient=recipient,
        subject=subject,
        message=message,
        status=status,
        error_detail=error_detail,
    )
    db.add(delivery)
    db.commit()
    db.refresh(delivery)
    return delivery


def send_anomaly_email_alert(db: Session, anomaly_id: int | None, description: str, severity: str) -> AlertDelivery:
    subject = f"[NTA {severity.upper()}] Network anomaly detected"
    message = (
        "Network Traffic Monitoring System alert\n\n"
        f"Severity: {severity}\n"
        f"Details: {description}\n\n"
        "Review this event in the dashboard under Anomalies."
    )
    result = send_email_alert(subject, message)

    if result.get("sent"):
        status = "sent"
        error_detail = ""
    else:
        status = "failed"
        error_detail = str(result.get("reason", "Unknown error"))

    return record_alert_delivery(
        db,
        anomaly_id=anomaly_id,
        channel="email",
        recipient=str(result.get("recipient", "")),
        subject=subject,
        message=message,
        status=status,
        error_detail=error_detail,
    )


def send_test_email_alert(db: Session) -> AlertDelivery:
    subject = "NTA test alert"
    message = "This is a test email from the Network Traffic Monitoring System. SMTP is working."
    result = send_email_alert(subject, message)

    if result.get("sent"):
        status = "sent"
        error_detail = ""
    else:
        status = "failed"
        error_detail = str(result.get("reason", "Unknown error"))

    return record_alert_delivery(
        db,
        anomaly_id=None,
        channel="email",
        recipient=str(result.get("recipient", "")),
        subject=subject,
        message=message,
        status=status,
        error_detail=error_detail,
    )


def list_alert_deliveries(db: Session, limit: int = 50) -> list[AlertDelivery]:
    return db.query(AlertDelivery).order_by(AlertDelivery.created_at.desc()).limit(limit).all()
