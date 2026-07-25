from pydantic import BaseModel, EmailStr, Field


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    must_change_password: bool = False


class LoginRequest(BaseModel):
    username: str
    password: str


class UserCreateRequest(BaseModel):
    username: str = Field(min_length=3, max_length=100)
    email: EmailStr
    password: str = Field(min_length=8)
    role_name: str = "viewer"
    require_password_change: bool = True


class UserResponse(BaseModel):
    id: int
    username: str
    email: EmailStr
    role: str
    must_change_password: bool = False

    model_config = {"from_attributes": True}


class UserDetailResponse(BaseModel):
    id: int
    username: str
    email: EmailStr
    role: str
    is_active: bool
    must_change_password: bool
    created_at: str


class UserUpdateRequest(BaseModel):
    role_name: str | None = None
    is_active: bool | None = None


class AdminPasswordResetRequest(BaseModel):
    new_password: str = Field(min_length=8)
    require_password_change: bool = True


class PasswordChangeRequest(BaseModel):
    current_password: str
    new_password: str = Field(min_length=8)


class PasswordStrengthResponse(BaseModel):
    score: int
    level: str
    message: str
    checks: dict[str, bool]


class TrafficLogCreate(BaseModel):
    src_ip: str
    dst_ip: str
    src_port: int | None = None
    dst_port: int | None = None
    protocol: str = "TCP"
    encrypted: bool = False
    packet_count: int = 1
    byte_count: int = 0


class TrafficLogResponse(BaseModel):
    id: int
    src_ip: str
    dst_ip: str
    src_port: int | None
    dst_port: int | None
    protocol: str
    encrypted: bool
    packet_count: int
    byte_count: int
    captured_at: str

    model_config = {"from_attributes": True}


class AnomalyResponse(BaseModel):
    id: int
    anomaly_type: str
    severity: str
    status: str
    description: str
    source_ip: str
    detected_at: str

    model_config = {"from_attributes": True}


class AnomalyFeedbackRequest(BaseModel):
    classification: str
    notes: str = ""


class DashboardStats(BaseModel):
    total_sessions: int
    unique_ips: int
    encrypted_ratio: float
    open_anomalies: int


class AnomalyTypeCount(BaseModel):
    anomaly_type: str
    label: str
    count: int


class AnomalySeverityCount(BaseModel):
    severity: str
    count: int


class AnomalyStatusCount(BaseModel):
    status: str
    count: int


class AnomalyTrendPoint(BaseModel):
    period: str
    anomaly_type: str
    label: str
    count: int


class AnomalySourceCount(BaseModel):
    source_ip: str
    count: int


class IntrusionAnalyticsResponse(BaseModel):
    total_anomalies: int
    open_anomalies: int
    confirmed_anomalies: int
    by_type: list[AnomalyTypeCount]
    by_severity: list[AnomalySeverityCount]
    by_status: list[AnomalyStatusCount]
    trend: list[AnomalyTrendPoint]
    top_source_ips: list[AnomalySourceCount]


class NetworkScanRequest(BaseModel):
    subnet_prefix: str = Field(default="192.168.1.", max_length=50)


class KnownDeviceCreate(BaseModel):
    ip_address: str
    label: str = Field(default="", max_length=255)


class KnownDeviceResponse(BaseModel):
    id: int
    ip_address: str
    label: str
    created_at: str


class NetworkScanResponse(BaseModel):
    id: int
    subnet_prefix: str
    status: str
    device_count: int
    unauthorized_count: int
    started_at: str
    completed_at: str | None


class DiscoveredDeviceResponse(BaseModel):
    id: int
    scan_id: int
    ip_address: str
    open_ports: str
    is_authorized: bool
    discovered_at: str
    status: str


class AlertDeliveryResponse(BaseModel):
    id: int
    anomaly_id: int | None
    channel: str
    recipient: str
    subject: str
    status: str
    error_detail: str
    created_at: str


class AlertSummaryResponse(BaseModel):
    anomaly_id: int | None
    delivery_id: int
    channel: str
    anomaly_type: str
    severity: str
    anomaly_status: str
    source_ip: str
    description: str
    subject: str
    latest_delivery_status: str
    latest_error: str
    delivery_attempts: int
    last_attempt_at: str
    can_retry: bool


class AlertStatusHistoryEntry(BaseModel):
    event_type: str
    status: str
    detail: str
    created_at: str
    delivery_id: int | None


class AuditLogResponse(BaseModel):
    id: int
    username: str | None
    action: str
    details: str
    created_at: str


class ClientAuditEventRequest(BaseModel):
    resource: str
    details: str = ""


class IntrusionSignatureResponse(BaseModel):
    id: int
    anomaly_type: str
    source_ip: str | None
    dst_ip: str | None
    dst_port: int | None
    protocol: str | None
    encrypted: bool | None
    learned_from_anomaly_id: int | None
    match_count: int
    confirmation_count: int
    enabled: bool
    pattern_summary: str
    created_at: str
    updated_at: str


class IntrusionSignatureUpdateRequest(BaseModel):
    enabled: bool

