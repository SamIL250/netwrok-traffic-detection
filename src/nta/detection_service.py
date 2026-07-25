import logging

from sqlalchemy.orm import Session

from nta.config import settings
from nta.detection import analyze_recent_traffic
from nta.models import Anomaly
from nta.sms import send_sms_alert

logger = logging.getLogger(__name__)


def run_detection_job(db: Session, *, source: str = "manual", user_id: int | None = None) -> list[Anomaly]:
    from nta.auth import log_audit

    anomalies = analyze_recent_traffic(db, window_minutes=settings.detection_window_minutes)

    for anomaly in anomalies:
        if anomaly.severity == "high":
            try:
                send_sms_alert(f"NTA Alert: {anomaly.description}")
            except Exception as exc:
                logger.warning("SMS alert failed: %s", exc)

    log_audit(db, user_id, "run_detection", f"{source}: detected {len(anomalies)} anomalies")
    logger.info("Detection run (%s): %s new anomalies", source, len(anomalies))
    return anomalies
