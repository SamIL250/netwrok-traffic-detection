from pydantic import BaseModel, EmailStr, Field


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


class LoginRequest(BaseModel):
    username: str
    password: str


class UserCreateRequest(BaseModel):
    username: str = Field(min_length=3, max_length=100)
    email: EmailStr
    password: str = Field(min_length=8)
    role_name: str = "viewer"


class UserResponse(BaseModel):
    id: int
    username: str
    email: EmailStr
    role: str

    model_config = {"from_attributes": True}


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
