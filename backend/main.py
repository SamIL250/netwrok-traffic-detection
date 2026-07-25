import asyncio
import logging
from contextlib import asynccontextmanager
from datetime import date, datetime, time, timedelta, timezone

from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy import func
from sqlalchemy.orm import Session

from nta.alert_service import (
    get_alert_history,
    list_alert_deliveries,
    list_alerts,
    retry_alert_delivery,
    send_test_email_alert,
)
from nta.analytics_service import get_intrusion_analytics
from nta.auth import (
    authenticate_user,
    create_access_token,
    get_current_user,
    hash_password,
    log_audit,
    require_roles,
    verify_agent_api_key,
    verify_password,
)
from nta.config import settings
from nta.database import SessionLocal, get_db
from nta.detection import apply_feedback, signature_pattern_summary
from nta.detection_service import run_detection_job
from nta.network_service import (
    authorize_discovered_device,
    list_discovered_devices,
    list_known_devices,
    list_scan_history,
    remove_known_device,
    run_network_scan,
)
from nta.models import AlertDelivery, Anomaly, AnomalyFeedback, AnomalyStatus, AuditLog, DiscoveredDevice, IntrusionSignature, KnownDevice, NetworkScan, Role, TrafficLog, User
from nta.password_strength import analyze_password_strength
from nta.report_service import format_report_period, generate_network_report_pdf
from nta.schemas import (
    AlertDeliveryResponse,
    AlertStatusHistoryEntry,
    AlertSummaryResponse,
    AnomalyFeedbackRequest,
    AnomalyResponse,
    AuditLogResponse,
    ClientAuditEventRequest,
    DashboardStats,
    DiscoveredDeviceResponse,
    IntrusionSignatureResponse,
    IntrusionSignatureUpdateRequest,
    IntrusionAnalyticsResponse,
    KnownDeviceCreate,
    KnownDeviceResponse,
    NetworkScanRequest,
    NetworkScanResponse,
    PasswordStrengthResponse,
    TokenResponse,
    TrafficLogCreate,
    TrafficLogResponse,
    AdminPasswordResetRequest,
    PasswordChangeRequest,
    UserCreateRequest,
    UserDetailResponse,
    UserResponse,
    UserUpdateRequest,
)
from nta.seed import init_database, seed_admin

logger = logging.getLogger(__name__)


async def _scheduled_detection_loop() -> None:
    while True:
        await asyncio.sleep(settings.detection_interval_seconds)
        if not settings.detection_auto_enabled:
            continue
        await asyncio.to_thread(_run_scheduled_detection)


def _run_scheduled_detection() -> None:
    db = SessionLocal()
    try:
        run_detection_job(db, source="scheduled")
    except Exception as exc:
        logger.exception("Scheduled detection failed: %s", exc)
    finally:
        db.close()


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_database()
    db = next(get_db())
    try:
        seed_admin(db)
    finally:
        db.close()

    detection_task = None
    if settings.detection_auto_enabled:
        detection_task = asyncio.create_task(_scheduled_detection_loop())
        logger.info(
            "Automatic detection enabled (every %ss, window=%sm)",
            settings.detection_interval_seconds,
            settings.detection_window_minutes,
        )

    yield

    if detection_task is not None:
        detection_task.cancel()
        try:
            await detection_task
        except asyncio.CancelledError:
            pass


app = FastAPI(title="Network Traffic Monitoring API", version="0.1.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/api/auth/login", response_model=TokenResponse)
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)) -> TokenResponse:
    user = authenticate_user(db, form_data.username, form_data.password)
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid username or password")
    log_audit(db, user.id, "login", f"User {user.username} logged in")
    return TokenResponse(access_token=create_access_token(user.username))


@app.get("/api/auth/me", response_model=UserResponse)
def me(current_user: User = Depends(get_current_user)) -> UserResponse:
    return UserResponse(
        id=current_user.id,
        username=current_user.username,
        email=current_user.email,
        role=current_user.role.name,
    )


def _user_to_detail(user: User) -> UserDetailResponse:
    return UserDetailResponse(
        id=user.id,
        username=user.username,
        email=user.email,
        role=user.role.name,
        is_active=user.is_active,
        created_at=user.created_at.isoformat() if user.created_at else "",
    )


@app.post("/api/auth/change-password")
def change_password(
    payload: PasswordChangeRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> dict[str, str]:
    if not verify_password(payload.current_password, current_user.password_hash):
        raise HTTPException(status_code=400, detail="Current password is incorrect")

    strength = analyze_password_strength(payload.new_password)
    if strength["level"] == "weak":
        raise HTTPException(status_code=400, detail="Password is too weak")

    current_user.password_hash = hash_password(payload.new_password)
    db.commit()
    log_audit(db, current_user.id, "change_password", f"User {current_user.username} changed password")
    return {"detail": "Password updated"}


@app.get("/api/users", response_model=list[UserDetailResponse])
def list_users(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles("admin")),
) -> list[UserDetailResponse]:
    users = db.query(User).order_by(User.username).all()
    return [_user_to_detail(user) for user in users]


@app.post("/api/users", response_model=UserResponse)
def create_user(
    payload: UserCreateRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles("admin")),
) -> UserResponse:
    strength = analyze_password_strength(payload.password)
    if strength["level"] == "weak":
        raise HTTPException(status_code=400, detail="Password is too weak")

    role = db.query(Role).filter(Role.name == payload.role_name).first()
    if role is None:
        raise HTTPException(status_code=400, detail="Invalid role")

    if db.query(User).filter((User.username == payload.username) | (User.email == payload.email)).first():
        raise HTTPException(status_code=400, detail="User already exists")

    user = User(
        username=payload.username,
        email=payload.email,
        password_hash=hash_password(payload.password),
        role_id=role.id,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    log_audit(db, current_user.id, "create_user", f"Created user {user.username}")
    return UserResponse(id=user.id, username=user.username, email=user.email, role=role.name)


@app.patch("/api/users/{user_id}", response_model=UserDetailResponse)
def update_user(
    user_id: int,
    payload: UserUpdateRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles("admin")),
) -> UserDetailResponse:
    user = db.query(User).filter(User.id == user_id).first()
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")

    if payload.role_name is None and payload.is_active is None:
        raise HTTPException(status_code=400, detail="No updates provided")

    if user.id == current_user.id:
        if payload.is_active is False:
            raise HTTPException(status_code=400, detail="Cannot disable your own account")
        if payload.role_name is not None and payload.role_name != current_user.role.name:
            raise HTTPException(status_code=400, detail="Cannot change your own role")

    changes: list[str] = []
    if payload.role_name is not None:
        role = db.query(Role).filter(Role.name == payload.role_name).first()
        if role is None:
            raise HTTPException(status_code=400, detail="Invalid role")
        user.role_id = role.id
        changes.append(f"role={payload.role_name}")

    if payload.is_active is not None:
        user.is_active = payload.is_active
        changes.append(f"is_active={payload.is_active}")

    db.commit()
    db.refresh(user)
    log_audit(db, current_user.id, "update_user", f"Updated user {user.username}: {', '.join(changes)}")
    return _user_to_detail(user)


@app.post("/api/users/{user_id}/reset-password")
def reset_user_password(
    user_id: int,
    payload: AdminPasswordResetRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles("admin")),
) -> dict[str, str]:
    user = db.query(User).filter(User.id == user_id).first()
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")

    strength = analyze_password_strength(payload.new_password)
    if strength["level"] == "weak":
        raise HTTPException(status_code=400, detail="Password is too weak")

    user.password_hash = hash_password(payload.new_password)
    db.commit()
    log_audit(db, current_user.id, "reset_password", f"Reset password for user {user.username}")
    return {"detail": "Password reset"}


@app.post("/api/password/strength", response_model=PasswordStrengthResponse)
def password_strength(password: str) -> PasswordStrengthResponse:
    result = analyze_password_strength(password)
    return PasswordStrengthResponse(**result)


@app.post("/api/traffic/logs", response_model=TrafficLogResponse)
def create_traffic_log(
    payload: TrafficLogCreate,
    db: Session = Depends(get_db),
    _: None = Depends(verify_agent_api_key),
) -> TrafficLogResponse:
    log = TrafficLog(**payload.model_dump())
    db.add(log)
    db.commit()
    db.refresh(log)
    return _traffic_log_response(log)


@app.get("/api/traffic/logs", response_model=list[TrafficLogResponse])
def list_traffic_logs(
    src_ip: str | None = None,
    start_date: date | None = None,
    end_date: date | None = None,
    limit: int = 100,
    db: Session = Depends(get_db),
    _: User = Depends(get_current_user),
) -> list[TrafficLogResponse]:
    if start_date and end_date and start_date > end_date:
        raise HTTPException(status_code=400, detail="start_date must be on or before end_date")

    query = db.query(TrafficLog).order_by(TrafficLog.captured_at.desc())
    if src_ip:
        query = query.filter(TrafficLog.src_ip == src_ip)
    if start_date:
        start_dt = datetime.combine(start_date, time.min, tzinfo=timezone.utc)
        query = query.filter(TrafficLog.captured_at >= start_dt)
    if end_date:
        end_dt = datetime.combine(end_date + timedelta(days=1), time.min, tzinfo=timezone.utc)
        query = query.filter(TrafficLog.captured_at < end_dt)
    logs = query.limit(limit).all()
    return [_traffic_log_response(log) for log in logs]


@app.get("/api/dashboard/stats", response_model=DashboardStats)
def dashboard_stats(db: Session = Depends(get_db), _: User = Depends(get_current_user)) -> DashboardStats:
    total_sessions = db.query(func.count(TrafficLog.id)).scalar() or 0
    unique_ips = db.query(func.count(func.distinct(TrafficLog.src_ip))).scalar() or 0
    encrypted_count = db.query(func.count(TrafficLog.id)).filter(TrafficLog.encrypted.is_(True)).scalar() or 0
    encrypted_ratio = (encrypted_count / total_sessions * 100) if total_sessions else 0.0
    open_anomalies = (
        db.query(func.count(Anomaly.id)).filter(Anomaly.status == AnomalyStatus.OPEN.value).scalar() or 0
    )
    return DashboardStats(
        total_sessions=total_sessions,
        unique_ips=unique_ips,
        encrypted_ratio=round(encrypted_ratio, 2),
        open_anomalies=open_anomalies,
    )


@app.post("/api/detection/run", response_model=list[AnomalyResponse])
def run_detection(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles("admin", "analyst")),
) -> list[AnomalyResponse]:
    anomalies = run_detection_job(db, source="manual", user_id=current_user.id)
    return [_anomaly_response(item) for item in anomalies]


@app.post("/api/internal/detection/run", response_model=list[AnomalyResponse])
def run_detection_internal(
    db: Session = Depends(get_db),
    _: None = Depends(verify_agent_api_key),
) -> list[AnomalyResponse]:
    anomalies = run_detection_job(db, source="agent")
    return [_anomaly_response(item) for item in anomalies]


@app.get("/api/anomalies", response_model=list[AnomalyResponse])
def list_anomalies(
    status_filter: str | None = None,
    db: Session = Depends(get_db),
    _: User = Depends(get_current_user),
) -> list[AnomalyResponse]:
    query = db.query(Anomaly).order_by(Anomaly.detected_at.desc())
    if status_filter:
        query = query.filter(Anomaly.status == status_filter)
    return [_anomaly_response(item) for item in query.limit(100).all()]


@app.get("/api/analytics/intrusions", response_model=IntrusionAnalyticsResponse)
def intrusion_analytics(
    start_date: date | None = None,
    end_date: date | None = None,
    db: Session = Depends(get_db),
    _: User = Depends(get_current_user),
) -> IntrusionAnalyticsResponse:
    if start_date and end_date and start_date > end_date:
        raise HTTPException(status_code=400, detail="start_date must be on or before end_date")

    data = get_intrusion_analytics(db, start_date, end_date)
    return IntrusionAnalyticsResponse(**data)


@app.post("/api/anomalies/{anomaly_id}/feedback", response_model=AnomalyResponse)
def review_anomaly(
    anomaly_id: int,
    payload: AnomalyFeedbackRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles("admin", "analyst")),
) -> AnomalyResponse:
    if payload.classification not in {AnomalyStatus.CONFIRMED.value, AnomalyStatus.FALSE_POSITIVE.value}:
        raise HTTPException(status_code=400, detail="Invalid classification")

    anomaly = db.query(Anomaly).filter(Anomaly.id == anomaly_id).first()
    if anomaly is None:
        raise HTTPException(status_code=404, detail="Anomaly not found")

    db.add(
        AnomalyFeedback(
            anomaly_id=anomaly_id,
            user_id=current_user.id,
            classification=payload.classification,
            notes=payload.notes,
        )
    )
    feedback_result = apply_feedback(db, anomaly_id, payload.classification)
    db.refresh(anomaly)
    audit_details = f"Anomaly {anomaly_id} marked {payload.classification}"
    if feedback_result.signature_action == "learned" and feedback_result.signature is not None:
        audit_details += f"; learned signature #{feedback_result.signature.id}"
    elif feedback_result.signature_action == "disabled" and feedback_result.signature is not None:
        audit_details += f"; disabled signature #{feedback_result.signature.id}"
    log_audit(db, current_user.id, "review_anomaly", audit_details)
    return _anomaly_response(anomaly)


@app.get("/api/detection/signatures", response_model=list[IntrusionSignatureResponse])
def list_intrusion_signatures(
    enabled_only: bool = False,
    db: Session = Depends(get_db),
    _: User = Depends(require_roles("admin", "analyst")),
) -> list[IntrusionSignatureResponse]:
    query = db.query(IntrusionSignature).order_by(IntrusionSignature.updated_at.desc())
    if enabled_only:
        query = query.filter(IntrusionSignature.enabled.is_(True))
    signatures = query.limit(200).all()
    return [_intrusion_signature_response(signature) for signature in signatures]


@app.patch("/api/detection/signatures/{signature_id}", response_model=IntrusionSignatureResponse)
def update_intrusion_signature(
    signature_id: int,
    payload: IntrusionSignatureUpdateRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles("admin", "analyst")),
) -> IntrusionSignatureResponse:
    signature = db.query(IntrusionSignature).filter(IntrusionSignature.id == signature_id).first()
    if signature is None:
        raise HTTPException(status_code=404, detail="Signature not found")

    signature.enabled = payload.enabled
    db.commit()
    db.refresh(signature)
    action = "enable_signature" if payload.enabled else "disable_signature"
    log_audit(
        db,
        current_user.id,
        action,
        f"Signature #{signature.id} ({signature.anomaly_type}) set enabled={payload.enabled}",
    )
    return _intrusion_signature_response(signature)


@app.get("/api/alerts", response_model=list[AlertSummaryResponse])
def get_alerts(
    delivery_status: str | None = None,
    severity: str | None = None,
    start_date: date | None = None,
    end_date: date | None = None,
    limit: int = 100,
    db: Session = Depends(get_db),
    _: User = Depends(get_current_user),
) -> list[AlertSummaryResponse]:
    if start_date and end_date and start_date > end_date:
        raise HTTPException(status_code=400, detail="start_date must be on or before end_date")
    if delivery_status and delivery_status not in {"sent", "failed"}:
        raise HTTPException(status_code=400, detail="delivery_status must be sent or failed")
    if severity and severity not in {"low", "medium", "high", "info"}:
        raise HTTPException(status_code=400, detail="Invalid severity filter")

    items = list_alerts(
        db,
        delivery_status=delivery_status,
        severity=severity,
        start_date=start_date,
        end_date=end_date,
        limit=limit,
    )
    return [_alert_summary_response(item) for item in items]


@app.get("/api/alerts/history", response_model=list[AlertStatusHistoryEntry])
def get_alert_status_history(
    anomaly_id: int | None = None,
    delivery_id: int | None = None,
    db: Session = Depends(get_db),
    _: User = Depends(get_current_user),
) -> list[AlertStatusHistoryEntry]:
    if anomaly_id is None and delivery_id is None:
        raise HTTPException(status_code=400, detail="anomaly_id or delivery_id is required")

    try:
        history = get_alert_history(db, anomaly_id=anomaly_id, delivery_id=delivery_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    return [_alert_history_entry_response(item) for item in history]


@app.post("/api/alerts/delivery/{delivery_id}/retry", response_model=AlertDeliveryResponse)
def retry_failed_alert_email(
    delivery_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles("admin", "analyst")),
) -> AlertDeliveryResponse:
    try:
        delivery = retry_alert_delivery(db, delivery_id)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    log_audit(
        db,
        current_user.id,
        "retry_email_alert",
        f"Retried alert delivery #{delivery_id}; new status: {delivery.status}",
    )
    return _alert_delivery_response(delivery)


@app.get("/api/alerts/delivery", response_model=list[AlertDeliveryResponse])
def get_alert_deliveries(
    limit: int = 50,
    db: Session = Depends(get_db),
    _: User = Depends(get_current_user),
) -> list[AlertDeliveryResponse]:
    deliveries = list_alert_deliveries(db, limit=limit)
    return [_alert_delivery_response(item) for item in deliveries]


@app.post("/api/alerts/test-email", response_model=AlertDeliveryResponse)
def send_test_alert_email(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles("admin")),
) -> AlertDeliveryResponse:
    delivery = send_test_email_alert(db)
    log_audit(db, current_user.id, "test_email_alert", f"Test email status: {delivery.status}")
    return _alert_delivery_response(delivery)


ALLOWED_CLIENT_AUDIT_RESOURCES = frozenset({"traffic_logs"})


@app.get("/api/audit/actions", response_model=list[str])
def list_audit_actions(
    db: Session = Depends(get_db),
    _: User = Depends(require_roles("admin")),
) -> list[str]:
    rows = db.query(AuditLog.action).distinct().order_by(AuditLog.action).all()
    return [row[0] for row in rows]


@app.get("/api/audit/logs", response_model=list[AuditLogResponse])
def list_audit_logs(
    action: str | None = None,
    username: str | None = None,
    start_date: date | None = None,
    end_date: date | None = None,
    limit: int = 200,
    db: Session = Depends(get_db),
    _: User = Depends(require_roles("admin")),
) -> list[AuditLogResponse]:
    if start_date and end_date and start_date > end_date:
        raise HTTPException(status_code=400, detail="start_date must be on or before end_date")

    query = db.query(AuditLog, User.username).outerjoin(User).order_by(AuditLog.created_at.desc())
    if action:
        query = query.filter(AuditLog.action == action)
    if username:
        query = query.filter(User.username == username.strip())
    if start_date:
        start_dt = datetime.combine(start_date, time.min, tzinfo=timezone.utc)
        query = query.filter(AuditLog.created_at >= start_dt)
    if end_date:
        end_dt = datetime.combine(end_date + timedelta(days=1), time.min, tzinfo=timezone.utc)
        query = query.filter(AuditLog.created_at < end_dt)

    rows = query.limit(limit).all()
    return [_audit_log_response(log, log_username) for log, log_username in rows]


@app.post("/api/audit/client-events", status_code=status.HTTP_204_NO_CONTENT)
def record_client_audit_event(
    payload: ClientAuditEventRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> None:
    if payload.resource not in ALLOWED_CLIENT_AUDIT_RESOURCES:
        raise HTTPException(status_code=400, detail="Invalid resource")

    action = f"export_{payload.resource}"
    details = payload.details.strip() or f"User {current_user.username} exported {payload.resource.replace('_', ' ')}"
    log_audit(db, current_user.id, action, details)


@app.get("/api/reports/pdf")
def download_pdf_report(
    start_date: date | None = None,
    end_date: date | None = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles("admin")),
) -> Response:
    if start_date and end_date and start_date > end_date:
        raise HTTPException(status_code=400, detail="start_date must be on or before end_date")

    pdf_bytes = generate_network_report_pdf(db, current_user, start_date, end_date)
    period = format_report_period(start_date, end_date)
    log_audit(db, current_user.id, "export_pdf_report", f"Generated PDF report ({period})")

    filename = f"network_report_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.post("/api/network/scans", response_model=NetworkScanResponse)
async def create_network_scan(
    payload: NetworkScanRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles("admin", "analyst")),
) -> NetworkScanResponse:
    scan = await asyncio.to_thread(run_network_scan, payload.subnet_prefix, current_user.id)
    log_audit(
        db,
        current_user.id,
        "network_scan",
        f"Scan completed for {payload.subnet_prefix}: {scan.device_count} devices, {scan.unauthorized_count} unauthorized",
    )
    return _network_scan_response(scan)


@app.get("/api/network/scans", response_model=list[NetworkScanResponse])
def get_network_scans(
    limit: int = 20,
    db: Session = Depends(get_db),
    _: User = Depends(get_current_user),
) -> list[NetworkScanResponse]:
    scans = list_scan_history(db, limit=limit)
    return [_network_scan_response(scan) for scan in scans]


@app.get("/api/network/devices", response_model=list[DiscoveredDeviceResponse])
def get_discovered_devices(
    unauthorized_only: bool = False,
    db: Session = Depends(get_db),
    _: User = Depends(get_current_user),
) -> list[DiscoveredDeviceResponse]:
    devices = list_discovered_devices(db, unauthorized_only=unauthorized_only)
    return [_discovered_device_response(device) for device in devices]


@app.get("/api/network/known-devices", response_model=list[KnownDeviceResponse])
def get_known_devices(db: Session = Depends(get_db), _: User = Depends(get_current_user)) -> list[KnownDeviceResponse]:
    devices = list_known_devices(db)
    return [_known_device_response(device) for device in devices]


@app.post("/api/network/known-devices", response_model=KnownDeviceResponse)
def create_known_device(
    payload: KnownDeviceCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles("admin")),
) -> KnownDeviceResponse:
    device = authorize_discovered_device(db, payload.ip_address, payload.label or payload.ip_address)
    log_audit(db, current_user.id, "authorize_device", f"Authorized device {device.ip_address}")
    return _known_device_response(device)


@app.delete("/api/network/known-devices/{device_id}")
def delete_known_device(
    device_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles("admin")),
) -> dict[str, str]:
    if not remove_known_device(db, device_id):
        raise HTTPException(status_code=404, detail="Known device not found")
    log_audit(db, current_user.id, "remove_known_device", f"Removed known device {device_id}")
    return {"status": "deleted"}


@app.post("/api/internal/network/scans", response_model=NetworkScanResponse)
async def create_network_scan_internal(
    payload: NetworkScanRequest,
    db: Session = Depends(get_db),
    _: None = Depends(verify_agent_api_key),
) -> NetworkScanResponse:
    scan = await asyncio.to_thread(run_network_scan, payload.subnet_prefix, None)
    return _network_scan_response(scan)


def _alert_delivery_response(delivery: AlertDelivery) -> AlertDeliveryResponse:
    created_at = delivery.created_at
    if created_at.tzinfo is None:
        created_at = created_at.replace(tzinfo=timezone.utc)
    return AlertDeliveryResponse(
        id=delivery.id,
        anomaly_id=delivery.anomaly_id,
        channel=delivery.channel,
        recipient=delivery.recipient,
        subject=delivery.subject,
        status=delivery.status,
        error_detail=delivery.error_detail,
        created_at=created_at.isoformat(),
    )


def _alert_summary_response(item: dict[str, object]) -> AlertSummaryResponse:
    last_attempt_at = item["last_attempt_at"]
    if isinstance(last_attempt_at, datetime):
        if last_attempt_at.tzinfo is None:
            last_attempt_at = last_attempt_at.replace(tzinfo=timezone.utc)
        last_attempt_at_str = last_attempt_at.isoformat()
    else:
        last_attempt_at_str = str(last_attempt_at)

    return AlertSummaryResponse(
        anomaly_id=item["anomaly_id"],  # type: ignore[arg-type]
        delivery_id=int(item["delivery_id"]),
        channel=str(item["channel"]),
        anomaly_type=str(item["anomaly_type"]),
        severity=str(item["severity"]),
        anomaly_status=str(item["anomaly_status"]),
        source_ip=str(item["source_ip"]),
        description=str(item["description"]),
        subject=str(item["subject"]),
        latest_delivery_status=str(item["latest_delivery_status"]),
        latest_error=str(item["latest_error"]),
        delivery_attempts=int(item["delivery_attempts"]),
        last_attempt_at=last_attempt_at_str,
        can_retry=bool(item["can_retry"]),
    )


def _alert_history_entry_response(item: dict[str, object]) -> AlertStatusHistoryEntry:
    created_at = item["created_at"]
    if isinstance(created_at, datetime):
        if created_at.tzinfo is None:
            created_at = created_at.replace(tzinfo=timezone.utc)
        created_at_str = created_at.isoformat()
    else:
        created_at_str = str(created_at)

    delivery_id = item.get("delivery_id")
    return AlertStatusHistoryEntry(
        event_type=str(item["event_type"]),
        status=str(item["status"]),
        detail=str(item["detail"]),
        created_at=created_at_str,
        delivery_id=int(delivery_id) if delivery_id is not None else None,
    )


def _network_scan_response(scan: NetworkScan) -> NetworkScanResponse:
    started_at = scan.started_at
    if started_at.tzinfo is None:
        started_at = started_at.replace(tzinfo=timezone.utc)
    completed_at = scan.completed_at
    if completed_at is not None and completed_at.tzinfo is None:
        completed_at = completed_at.replace(tzinfo=timezone.utc)
    return NetworkScanResponse(
        id=scan.id,
        subnet_prefix=scan.subnet_prefix,
        status=scan.status,
        device_count=scan.device_count,
        unauthorized_count=scan.unauthorized_count,
        started_at=started_at.isoformat(),
        completed_at=completed_at.isoformat() if completed_at else None,
    )


def _discovered_device_response(device: DiscoveredDevice) -> DiscoveredDeviceResponse:
    discovered_at = device.discovered_at
    if discovered_at.tzinfo is None:
        discovered_at = discovered_at.replace(tzinfo=timezone.utc)
    return DiscoveredDeviceResponse(
        id=device.id,
        scan_id=device.scan_id,
        ip_address=device.ip_address,
        open_ports=device.open_ports,
        is_authorized=device.is_authorized,
        discovered_at=discovered_at.isoformat(),
        status="authorized" if device.is_authorized else "unauthorized",
    )


def _known_device_response(device: KnownDevice) -> KnownDeviceResponse:
    created_at = device.created_at
    if created_at.tzinfo is None:
        created_at = created_at.replace(tzinfo=timezone.utc)
    return KnownDeviceResponse(
        id=device.id,
        ip_address=device.ip_address,
        label=device.label,
        created_at=created_at.isoformat(),
    )


def _traffic_log_response(log: TrafficLog) -> TrafficLogResponse:
    captured_at = log.captured_at
    if captured_at.tzinfo is None:
        captured_at = captured_at.replace(tzinfo=timezone.utc)
    return TrafficLogResponse(
        id=log.id,
        src_ip=log.src_ip,
        dst_ip=log.dst_ip,
        src_port=log.src_port,
        dst_port=log.dst_port,
        protocol=log.protocol,
        encrypted=log.encrypted,
        packet_count=log.packet_count,
        byte_count=log.byte_count,
        captured_at=captured_at.isoformat(),
    )


def _anomaly_response(anomaly: Anomaly) -> AnomalyResponse:
    detected_at = anomaly.detected_at
    if detected_at.tzinfo is None:
        detected_at = detected_at.replace(tzinfo=timezone.utc)
    return AnomalyResponse(
        id=anomaly.id,
        anomaly_type=anomaly.anomaly_type,
        severity=anomaly.severity,
        status=anomaly.status,
        description=anomaly.description,
        source_ip=anomaly.source_ip,
        detected_at=detected_at.isoformat(),
    )


def _audit_log_response(log: AuditLog, username: str | None) -> AuditLogResponse:
    created_at = log.created_at
    if created_at.tzinfo is None:
        created_at = created_at.replace(tzinfo=timezone.utc)
    return AuditLogResponse(
        id=log.id,
        username=username,
        action=log.action,
        details=log.details,
        created_at=created_at.isoformat(),
    )


def _intrusion_signature_response(signature: IntrusionSignature) -> IntrusionSignatureResponse:
    created_at = signature.created_at
    updated_at = signature.updated_at
    if created_at.tzinfo is None:
        created_at = created_at.replace(tzinfo=timezone.utc)
    if updated_at.tzinfo is None:
        updated_at = updated_at.replace(tzinfo=timezone.utc)
    return IntrusionSignatureResponse(
        id=signature.id,
        anomaly_type=signature.anomaly_type,
        source_ip=signature.source_ip,
        dst_ip=signature.dst_ip,
        dst_port=signature.dst_port,
        protocol=signature.protocol,
        encrypted=signature.encrypted,
        learned_from_anomaly_id=signature.learned_from_anomaly_id,
        match_count=signature.match_count,
        confirmation_count=signature.confirmation_count,
        enabled=signature.enabled,
        pattern_summary=signature_pattern_summary(signature),
        created_at=created_at.isoformat(),
        updated_at=updated_at.isoformat(),
    )
