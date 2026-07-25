from datetime import date, datetime, time, timedelta, timezone

from sqlalchemy.orm import Session

from nta.email_alerts import send_email_alert
from nta.models import AlertDelivery, Anomaly, AnomalyFeedback, User


def _ensure_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value


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


def _alert_group_key(delivery: AlertDelivery) -> str:
    if delivery.anomaly_id is not None:
        return f"anomaly-{delivery.anomaly_id}"
    return f"delivery-{delivery.id}"


def _apply_delivery_date_filter(
    query,
    *,
    start_date: date | None,
    end_date: date | None,
):
    if start_date:
        start_dt = datetime.combine(start_date, time.min, tzinfo=timezone.utc)
        query = query.filter(AlertDelivery.created_at >= start_dt)
    if end_date:
        end_dt = datetime.combine(end_date + timedelta(days=1), time.min, tzinfo=timezone.utc)
        query = query.filter(AlertDelivery.created_at < end_dt)
    return query


def list_alerts(
    db: Session,
    *,
    delivery_status: str | None = None,
    severity: str | None = None,
    start_date: date | None = None,
    end_date: date | None = None,
    limit: int = 100,
) -> list[dict[str, object]]:
    query = db.query(AlertDelivery).order_by(AlertDelivery.created_at.desc())
    query = _apply_delivery_date_filter(query, start_date=start_date, end_date=end_date)
    deliveries = query.limit(max(limit * 5, 200)).all()

    grouped: dict[str, list[AlertDelivery]] = {}
    for delivery in deliveries:
        grouped.setdefault(_alert_group_key(delivery), []).append(delivery)

    anomaly_ids = {items[0].anomaly_id for items in grouped.values() if items[0].anomaly_id is not None}
    anomalies_by_id: dict[int, Anomaly] = {}
    if anomaly_ids:
        anomalies = db.query(Anomaly).filter(Anomaly.id.in_(anomaly_ids)).all()
        anomalies_by_id = {item.id: item for item in anomalies}

    alerts: list[dict[str, object]] = []
    for items in grouped.values():
        items.sort(key=lambda item: item.created_at, reverse=True)
        latest = items[0]
        anomaly = anomalies_by_id.get(latest.anomaly_id) if latest.anomaly_id else None

        if delivery_status and latest.status != delivery_status:
            continue
        if severity and (anomaly is None or anomaly.severity != severity):
            continue

        alerts.append(
            {
                "anomaly_id": latest.anomaly_id,
                "delivery_id": latest.id,
                "channel": latest.channel,
                "anomaly_type": anomaly.anomaly_type if anomaly else "test",
                "severity": anomaly.severity if anomaly else "info",
                "anomaly_status": anomaly.status if anomaly else "n/a",
                "source_ip": anomaly.source_ip if anomaly else "",
                "description": anomaly.description if anomaly else latest.message.splitlines()[0],
                "subject": latest.subject,
                "latest_delivery_status": latest.status,
                "latest_error": latest.error_detail,
                "delivery_attempts": len(items),
                "last_attempt_at": _ensure_utc(latest.created_at),
                "can_retry": latest.status == "failed",
            }
        )

    alerts.sort(key=lambda item: item["last_attempt_at"], reverse=True)
    return alerts[:limit]


def get_alert_history(
    db: Session,
    *,
    anomaly_id: int | None = None,
    delivery_id: int | None = None,
) -> list[dict[str, object]]:
    if anomaly_id is None and delivery_id is None:
        raise ValueError("anomaly_id or delivery_id is required")

    entries: list[dict[str, object]] = []

    if anomaly_id is not None:
        deliveries = (
            db.query(AlertDelivery)
            .filter(AlertDelivery.anomaly_id == anomaly_id)
            .order_by(AlertDelivery.created_at.asc())
            .all()
        )
        feedback_rows = (
            db.query(AnomalyFeedback, User.username)
            .join(User)
            .filter(AnomalyFeedback.anomaly_id == anomaly_id)
            .order_by(AnomalyFeedback.created_at.asc())
            .all()
        )
        for feedback, username in feedback_rows:
            detail = feedback.notes.strip() or f"Reviewed by {username}"
            entries.append(
                {
                    "event_type": "review",
                    "status": feedback.classification,
                    "detail": detail,
                    "created_at": _ensure_utc(feedback.created_at),
                    "delivery_id": None,
                }
            )
    else:
        deliveries = db.query(AlertDelivery).filter(AlertDelivery.id == delivery_id).all()

    for delivery in deliveries:
        detail = delivery.error_detail.strip() if delivery.status == "failed" else f"Sent to {delivery.recipient}"
        entries.append(
            {
                "event_type": "delivery",
                "status": delivery.status,
                "detail": detail,
                "created_at": _ensure_utc(delivery.created_at),
                "delivery_id": delivery.id,
            }
        )

    entries.sort(key=lambda item: item["created_at"])
    return entries


def retry_alert_delivery(db: Session, delivery_id: int) -> AlertDelivery:
    original = db.get(AlertDelivery, delivery_id)
    if original is None:
        raise LookupError("Alert delivery not found")
    if original.status != "failed":
        raise ValueError("Only failed deliveries can be retried")

    result = send_email_alert(original.subject, original.message)
    if result.get("sent"):
        status = "sent"
        error_detail = ""
    else:
        status = "failed"
        error_detail = str(result.get("reason", "Unknown error"))

    return record_alert_delivery(
        db,
        anomaly_id=original.anomaly_id,
        channel=original.channel,
        recipient=str(result.get("recipient", original.recipient)),
        subject=original.subject,
        message=original.message,
        status=status,
        error_detail=error_detail,
    )
