from collections import defaultdict
from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session

from nta.models import Anomaly, AnomalyStatus, AnomalyType, DetectionRule, TrafficLog


DEFAULT_RULES = [
    {"name": "unencrypted_threshold", "rule_type": AnomalyType.UNENCRYPTED_TRAFFIC.value, "threshold": 1.0},
    {"name": "brute_force_threshold", "rule_type": AnomalyType.BRUTE_FORCE.value, "threshold": 10.0},
    {"name": "port_scan_threshold", "rule_type": AnomalyType.PORT_SCAN.value, "threshold": 8.0},
]


def ensure_default_rules(db: Session) -> None:
    for rule in DEFAULT_RULES:
        existing = db.query(DetectionRule).filter(DetectionRule.name == rule["name"]).first()
        if existing is None:
            db.add(DetectionRule(**rule))
    db.commit()


def get_rule_threshold(db: Session, rule_type: str, default: float) -> float:
    rule = db.query(DetectionRule).filter(
        DetectionRule.rule_type == rule_type,
        DetectionRule.enabled.is_(True),
    ).first()
    return rule.threshold if rule else default


def create_anomaly_if_new(
    db: Session,
    *,
    traffic_log_id: int | None,
    anomaly_type: str,
    severity: str,
    description: str,
    source_ip: str,
) -> Anomaly | None:
    recent = (
        db.query(Anomaly)
        .filter(
            Anomaly.anomaly_type == anomaly_type,
            Anomaly.source_ip == source_ip,
            Anomaly.status == AnomalyStatus.OPEN.value,
        )
        .order_by(Anomaly.detected_at.desc())
        .first()
    )
    if recent is not None:
        return None

    anomaly = Anomaly(
        traffic_log_id=traffic_log_id,
        anomaly_type=anomaly_type,
        severity=severity,
        status=AnomalyStatus.OPEN.value,
        description=description,
        source_ip=source_ip,
    )
    db.add(anomaly)
    db.commit()
    db.refresh(anomaly)
    return anomaly


def analyze_recent_traffic(db: Session, window_minutes: int = 5) -> list[Anomaly]:
    ensure_default_rules(db)
    since = datetime.now(timezone.utc) - timedelta(minutes=window_minutes)
    logs = db.query(TrafficLog).filter(TrafficLog.captured_at >= since).all()
    created: list[Anomaly] = []

    for log in logs:
        if not log.encrypted and log.protocol.upper() in {"HTTP", "TCP", "UDP"}:
            anomaly = create_anomaly_if_new(
                db,
                traffic_log_id=log.id,
                anomaly_type=AnomalyType.UNENCRYPTED_TRAFFIC.value,
                severity="medium",
                description=f"Unencrypted traffic detected from {log.src_ip} to {log.dst_ip}",
                source_ip=log.src_ip,
            )
            if anomaly:
                created.append(anomaly)

    connection_attempts: dict[str, int] = defaultdict(int)
    port_targets: dict[str, set[int]] = defaultdict(set)

    for log in logs:
        connection_attempts[log.src_ip] += 1
        if log.dst_port is not None:
            port_targets[log.src_ip].add(log.dst_port)

    brute_force_threshold = int(get_rule_threshold(db, AnomalyType.BRUTE_FORCE.value, 10))
    for src_ip, count in connection_attempts.items():
        if count >= brute_force_threshold:
            anomaly = create_anomaly_if_new(
                db,
                traffic_log_id=None,
                anomaly_type=AnomalyType.BRUTE_FORCE.value,
                severity="high",
                description=f"Rapid connection burst detected: {count} sessions in {window_minutes} minutes",
                source_ip=src_ip,
            )
            if anomaly:
                created.append(anomaly)

    port_scan_threshold = int(get_rule_threshold(db, AnomalyType.PORT_SCAN.value, 8))
    for src_ip, ports in port_targets.items():
        if len(ports) >= port_scan_threshold:
            anomaly = create_anomaly_if_new(
                db,
                traffic_log_id=None,
                anomaly_type=AnomalyType.PORT_SCAN.value,
                severity="high",
                description=f"Possible port scan detected: {len(ports)} destination ports from {src_ip}",
                source_ip=src_ip,
            )
            if anomaly:
                created.append(anomaly)

    return created


def apply_feedback(db: Session, anomaly_id: int, classification: str) -> DetectionRule | None:
    anomaly = db.query(Anomaly).filter(Anomaly.id == anomaly_id).first()
    if anomaly is None:
        return None

    anomaly.status = classification
    rule = db.query(DetectionRule).filter(DetectionRule.rule_type == anomaly.anomaly_type).first()

    if classification == AnomalyStatus.FALSE_POSITIVE.value and rule is not None:
        rule.threshold = round(rule.threshold * 1.1, 2)
    elif classification == AnomalyStatus.CONFIRMED.value and rule is not None:
        rule.threshold = max(1.0, round(rule.threshold * 0.95, 2))

    db.commit()
    if rule is not None:
        db.refresh(rule)
    return rule
