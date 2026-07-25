import asyncio
import logging
from contextlib import asynccontextmanager
from datetime import datetime, timezone

from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy import func
from sqlalchemy.orm import Session

from nta.auth import (
    authenticate_user,
    create_access_token,
    get_current_user,
    hash_password,
    log_audit,
    require_roles,
    verify_agent_api_key,
)
from nta.config import settings
from nta.database import SessionLocal, get_db
from nta.detection import apply_feedback
from nta.detection_service import run_detection_job
from nta.models import Anomaly, AnomalyFeedback, AnomalyStatus, Role, TrafficLog, User
from nta.password_strength import analyze_password_strength
from nta.schemas import (
    AnomalyFeedbackRequest,
    AnomalyResponse,
    DashboardStats,
    PasswordStrengthResponse,
    TokenResponse,
    TrafficLogCreate,
    TrafficLogResponse,
    UserCreateRequest,
    UserResponse,
)
from nta.seed import seed_admin

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
    limit: int = 100,
    db: Session = Depends(get_db),
    _: User = Depends(get_current_user),
) -> list[TrafficLogResponse]:
    query = db.query(TrafficLog).order_by(TrafficLog.captured_at.desc())
    if src_ip:
        query = query.filter(TrafficLog.src_ip == src_ip)
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
    apply_feedback(db, anomaly_id, payload.classification)
    db.refresh(anomaly)
    log_audit(db, current_user.id, "review_anomaly", f"Anomaly {anomaly_id} marked {payload.classification}")
    return _anomaly_response(anomaly)


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
