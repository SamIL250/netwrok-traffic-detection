from datetime import date, datetime, time, timedelta, timezone

from sqlalchemy import func
from sqlalchemy.orm import Session

from nta.models import Anomaly, AnomalyStatus, AnomalyType

ANOMALY_TYPE_LABELS: dict[str, str] = {
    AnomalyType.UNENCRYPTED_TRAFFIC.value: "Unencrypted Traffic",
    AnomalyType.BRUTE_FORCE.value: "Brute Force",
    AnomalyType.PORT_SCAN.value: "Port Scan",
    AnomalyType.SUSPICIOUS_BURST.value: "Suspicious Burst",
}


def _apply_date_filter(query, column, start_date: date | None, end_date: date | None):
    if start_date:
        start_dt = datetime.combine(start_date, time.min, tzinfo=timezone.utc)
        query = query.filter(column >= start_dt)
    if end_date:
        end_dt = datetime.combine(end_date + timedelta(days=1), time.min, tzinfo=timezone.utc)
        query = query.filter(column < end_dt)
    return query


def _format_type_label(anomaly_type: str) -> str:
    return ANOMALY_TYPE_LABELS.get(anomaly_type, anomaly_type.replace("_", " ").title())


def get_intrusion_analytics(
    db: Session,
    start_date: date | None = None,
    end_date: date | None = None,
) -> dict[str, object]:
    base_query = db.query(Anomaly)
    base_query = _apply_date_filter(base_query, Anomaly.detected_at, start_date, end_date)

    total_anomalies = base_query.count()
    open_anomalies = base_query.filter(Anomaly.status == AnomalyStatus.OPEN.value).count()
    confirmed_anomalies = base_query.filter(Anomaly.status == AnomalyStatus.CONFIRMED.value).count()

    type_rows = (
        base_query.with_entities(Anomaly.anomaly_type, func.count(Anomaly.id))
        .group_by(Anomaly.anomaly_type)
        .order_by(func.count(Anomaly.id).desc())
        .all()
    )
    by_type = [
        {
            "anomaly_type": row[0],
            "label": _format_type_label(row[0]),
            "count": row[1],
        }
        for row in type_rows
    ]

    severity_rows = (
        base_query.with_entities(Anomaly.severity, func.count(Anomaly.id))
        .group_by(Anomaly.severity)
        .order_by(func.count(Anomaly.id).desc())
        .all()
    )
    by_severity = [{"severity": row[0], "count": row[1]} for row in severity_rows]

    status_rows = (
        base_query.with_entities(Anomaly.status, func.count(Anomaly.id))
        .group_by(Anomaly.status)
        .order_by(func.count(Anomaly.id).desc())
        .all()
    )
    by_status = [{"status": row[0], "count": row[1]} for row in status_rows]

    trend_rows = (
        base_query.with_entities(
            func.date_trunc("day", Anomaly.detected_at).label("period"),
            Anomaly.anomaly_type,
            func.count(Anomaly.id).label("count"),
        )
        .group_by("period", Anomaly.anomaly_type)
        .order_by("period")
        .all()
    )
    trend: list[dict[str, object]] = []
    for period, anomaly_type, count in trend_rows:
        if period is None:
            continue
        detected_at = period
        if detected_at.tzinfo is None:
            detected_at = detected_at.replace(tzinfo=timezone.utc)
        trend.append(
            {
                "period": detected_at.date().isoformat(),
                "anomaly_type": anomaly_type,
                "label": _format_type_label(anomaly_type),
                "count": count,
            }
        )

    top_source_rows = (
        base_query.with_entities(Anomaly.source_ip, func.count(Anomaly.id))
        .group_by(Anomaly.source_ip)
        .order_by(func.count(Anomaly.id).desc())
        .limit(10)
        .all()
    )
    top_source_ips = [{"source_ip": row[0], "count": row[1]} for row in top_source_rows]

    return {
        "total_anomalies": total_anomalies,
        "open_anomalies": open_anomalies,
        "confirmed_anomalies": confirmed_anomalies,
        "by_type": by_type,
        "by_severity": by_severity,
        "by_status": by_status,
        "trend": trend,
        "top_source_ips": top_source_ips,
    }
