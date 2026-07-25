from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session

from nta.models import Anomaly, AnomalyStatus, AnomalyType, DetectionRule, IntrusionSignature, TrafficLog

DEFAULT_RULES = [
    {"name": "unencrypted_threshold", "rule_type": AnomalyType.UNENCRYPTED_TRAFFIC.value, "threshold": 1.0},
    {"name": "brute_force_threshold", "rule_type": AnomalyType.BRUTE_FORCE.value, "threshold": 10.0},
    {"name": "port_scan_threshold", "rule_type": AnomalyType.PORT_SCAN.value, "threshold": 8.0},
]

SIGNATURE_PATTERN_FIELDS = ("source_ip", "dst_ip", "dst_port", "protocol", "encrypted")
LEARNED_SIGNATURE_THRESHOLD_FACTOR = 0.7


@dataclass
class FeedbackResult:
    rule: DetectionRule | None
    signature: IntrusionSignature | None
    signature_action: str | None = None


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


def _format_signature_pattern(pattern: dict[str, object | None]) -> str:
    parts: list[str] = []
    if pattern.get("source_ip"):
        parts.append(f"src={pattern['source_ip']}")
    if pattern.get("dst_ip"):
        parts.append(f"dst={pattern['dst_ip']}")
    if pattern.get("dst_port") is not None:
        parts.append(f"port={pattern['dst_port']}")
    if pattern.get("protocol"):
        parts.append(f"proto={pattern['protocol']}")
    if pattern.get("encrypted") is not None:
        parts.append(f"encrypted={pattern['encrypted']}")
    return ", ".join(parts) if parts else "any traffic"


def _extract_signature_pattern(db: Session, anomaly: Anomaly) -> dict[str, object | None]:
    pattern: dict[str, object | None] = {
        "anomaly_type": anomaly.anomaly_type,
        "source_ip": anomaly.source_ip,
        "dst_ip": None,
        "dst_port": None,
        "protocol": None,
        "encrypted": None,
    }

    if anomaly.traffic_log_id is not None:
        log = db.query(TrafficLog).filter(TrafficLog.id == anomaly.traffic_log_id).first()
        if log is not None:
            pattern.update(
                {
                    "source_ip": log.src_ip,
                    "dst_ip": log.dst_ip,
                    "dst_port": log.dst_port,
                    "protocol": log.protocol.upper(),
                    "encrypted": log.encrypted,
                }
            )
    return pattern


def _find_signature(db: Session, pattern: dict[str, object | None]) -> IntrusionSignature | None:
    query = db.query(IntrusionSignature).filter(IntrusionSignature.anomaly_type == pattern["anomaly_type"])
    for field in SIGNATURE_PATTERN_FIELDS:
        value = pattern.get(field)
        column = getattr(IntrusionSignature, field)
        if value is None:
            query = query.filter(column.is_(None))
        else:
            query = query.filter(column == value)
    return query.first()


def _is_traffic_signature(signature: IntrusionSignature) -> bool:
    return any(
        getattr(signature, field) is not None
        for field in ("dst_ip", "dst_port", "protocol", "encrypted")
    )


def _is_behavioral_signature(signature: IntrusionSignature) -> bool:
    return signature.source_ip is not None and not _is_traffic_signature(signature)


def learn_signature_from_confirmed(db: Session, anomaly: Anomaly) -> IntrusionSignature:
    pattern = _extract_signature_pattern(db, anomaly)
    signature = _find_signature(db, pattern)
    if signature is None:
        signature = IntrusionSignature(
            anomaly_type=str(pattern["anomaly_type"]),
            source_ip=pattern["source_ip"] if isinstance(pattern["source_ip"], str) else None,
            dst_ip=pattern["dst_ip"] if isinstance(pattern["dst_ip"], str) else None,
            dst_port=pattern["dst_port"] if isinstance(pattern["dst_port"], int) else None,
            protocol=pattern["protocol"] if isinstance(pattern["protocol"], str) else None,
            encrypted=pattern["encrypted"] if isinstance(pattern["encrypted"], bool) else None,
            learned_from_anomaly_id=anomaly.id,
            confirmation_count=1,
        )
        db.add(signature)
    else:
        signature.confirmation_count += 1
        signature.learned_from_anomaly_id = anomaly.id
        signature.enabled = True

    db.flush()
    return signature


def disable_matching_signatures(db: Session, anomaly: Anomaly) -> IntrusionSignature | None:
    pattern = _extract_signature_pattern(db, anomaly)
    signature = _find_signature(db, pattern)
    if signature is None:
        return None
    signature.enabled = False
    db.flush()
    return signature


def signature_matches_log(signature: IntrusionSignature, log: TrafficLog) -> bool:
    if signature.source_ip and signature.source_ip != log.src_ip:
        return False
    if signature.dst_ip and signature.dst_ip != log.dst_ip:
        return False
    if signature.dst_port is not None and signature.dst_port != log.dst_port:
        return False
    if signature.protocol and signature.protocol != log.protocol.upper():
        return False
    if signature.encrypted is not None and signature.encrypted != log.encrypted:
        return False
    return True


def signature_pattern_summary(signature: IntrusionSignature) -> str:
    return _format_signature_pattern(
        {
            "source_ip": signature.source_ip,
            "dst_ip": signature.dst_ip,
            "dst_port": signature.dst_port,
            "protocol": signature.protocol,
            "encrypted": signature.encrypted,
        }
    )


def detect_learned_signatures(
    db: Session,
    logs: list[TrafficLog],
    connection_attempts: dict[str, int],
    port_targets: dict[str, set[int]],
    window_minutes: int,
) -> list[Anomaly]:
    signatures = db.query(IntrusionSignature).filter(IntrusionSignature.enabled.is_(True)).all()
    if not signatures:
        return []

    created: list[Anomaly] = []
    for signature in signatures:
        if _is_traffic_signature(signature):
            for log in logs:
                if not signature_matches_log(signature, log):
                    continue
                signature.match_count += 1
                anomaly = create_anomaly_if_new(
                    db,
                    traffic_log_id=log.id,
                    anomaly_type=signature.anomaly_type,
                    severity="high",
                    description=(
                        f"Matched learned intrusion signature #{signature.id} "
                        f"({signature_pattern_summary(signature)})"
                    ),
                    source_ip=log.src_ip,
                )
                if anomaly:
                    created.append(anomaly)
            continue

        if not _is_behavioral_signature(signature):
            continue

        if signature.anomaly_type == AnomalyType.UNENCRYPTED_TRAFFIC.value:
            for log in logs:
                if log.src_ip != signature.source_ip:
                    continue
                if log.encrypted:
                    continue
                signature.match_count += 1
                anomaly = create_anomaly_if_new(
                    db,
                    traffic_log_id=log.id,
                    anomaly_type=signature.anomaly_type,
                    severity="high",
                    description=(
                        f"Matched learned unencrypted-traffic signature #{signature.id} "
                        f"for source {signature.source_ip}"
                    ),
                    source_ip=log.src_ip,
                )
                if anomaly:
                    created.append(anomaly)
            continue

        if signature.anomaly_type == AnomalyType.BRUTE_FORCE.value:
            count = connection_attempts.get(signature.source_ip or "", 0)
            threshold = max(
                1,
                int(get_rule_threshold(db, AnomalyType.BRUTE_FORCE.value, 10) * LEARNED_SIGNATURE_THRESHOLD_FACTOR),
            )
            if count < threshold:
                continue
            signature.match_count += 1
            anomaly = create_anomaly_if_new(
                db,
                traffic_log_id=None,
                anomaly_type=signature.anomaly_type,
                severity="high",
                description=(
                    f"Matched learned brute-force signature #{signature.id} for {signature.source_ip}: "
                    f"{count} sessions in {window_minutes} minutes"
                ),
                source_ip=signature.source_ip or "",
            )
            if anomaly:
                created.append(anomaly)
            continue

        if signature.anomaly_type == AnomalyType.PORT_SCAN.value:
            ports = port_targets.get(signature.source_ip or "", set())
            threshold = max(
                1,
                int(get_rule_threshold(db, AnomalyType.PORT_SCAN.value, 8) * LEARNED_SIGNATURE_THRESHOLD_FACTOR),
            )
            if len(ports) < threshold:
                continue
            signature.match_count += 1
            anomaly = create_anomaly_if_new(
                db,
                traffic_log_id=None,
                anomaly_type=signature.anomaly_type,
                severity="high",
                description=(
                    f"Matched learned port-scan signature #{signature.id} for {signature.source_ip}: "
                    f"{len(ports)} destination ports"
                ),
                source_ip=signature.source_ip or "",
            )
            if anomaly:
                created.append(anomaly)

    db.commit()
    return created


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

    created.extend(
        detect_learned_signatures(db, logs, connection_attempts, port_targets, window_minutes)
    )
    return created


def apply_feedback(db: Session, anomaly_id: int, classification: str) -> FeedbackResult:
    anomaly = db.query(Anomaly).filter(Anomaly.id == anomaly_id).first()
    if anomaly is None:
        return FeedbackResult(rule=None, signature=None)

    anomaly.status = classification
    rule = db.query(DetectionRule).filter(DetectionRule.rule_type == anomaly.anomaly_type).first()
    signature: IntrusionSignature | None = None
    signature_action: str | None = None

    if classification == AnomalyStatus.FALSE_POSITIVE.value:
        if rule is not None:
            rule.threshold = round(rule.threshold * 1.1, 2)
        signature = disable_matching_signatures(db, anomaly)
        if signature is not None:
            signature_action = "disabled"
    elif classification == AnomalyStatus.CONFIRMED.value:
        if rule is not None:
            rule.threshold = max(1.0, round(rule.threshold * 0.95, 2))
        signature = learn_signature_from_confirmed(db, anomaly)
        signature_action = "learned"

    db.commit()
    if rule is not None:
        db.refresh(rule)
    if signature is not None:
        db.refresh(signature)
    return FeedbackResult(rule=rule, signature=signature, signature_action=signature_action)
