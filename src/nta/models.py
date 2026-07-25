from datetime import datetime
from enum import Enum

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Integer, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from nta.database import Base


class UserRole(str, Enum):
    ADMIN = "admin"
    ANALYST = "analyst"
    VIEWER = "viewer"


class AnomalyStatus(str, Enum):
    OPEN = "open"
    CONFIRMED = "confirmed"
    FALSE_POSITIVE = "false_positive"


class AnomalyType(str, Enum):
    UNENCRYPTED_TRAFFIC = "unencrypted_traffic"
    BRUTE_FORCE = "brute_force"
    PORT_SCAN = "port_scan"
    SUSPICIOUS_BURST = "suspicious_burst"


class Role(Base):
    __tablename__ = "roles"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(50), unique=True, nullable=False)
    description: Mapped[str] = mapped_column(String(255), default="")

    users: Mapped[list["User"]] = relationship(back_populates="role")


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(100), unique=True, nullable=False, index=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    role_id: Mapped[int] = mapped_column(ForeignKey("roles.id"), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    role: Mapped["Role"] = relationship(back_populates="users")
    audit_logs: Mapped[list["AuditLog"]] = relationship(back_populates="user")


class TrafficLog(Base):
    __tablename__ = "traffic_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    src_ip: Mapped[str] = mapped_column(String(45), nullable=False, index=True)
    dst_ip: Mapped[str] = mapped_column(String(45), nullable=False, index=True)
    src_port: Mapped[int | None] = mapped_column(Integer)
    dst_port: Mapped[int | None] = mapped_column(Integer)
    protocol: Mapped[str] = mapped_column(String(20), nullable=False, default="TCP")
    encrypted: Mapped[bool] = mapped_column(Boolean, default=False)
    packet_count: Mapped[int] = mapped_column(Integer, default=1)
    byte_count: Mapped[int] = mapped_column(Integer, default=0)
    captured_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), index=True)

    anomalies: Mapped[list["Anomaly"]] = relationship(back_populates="traffic_log")


class Anomaly(Base):
    __tablename__ = "anomalies"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    traffic_log_id: Mapped[int | None] = mapped_column(ForeignKey("traffic_logs.id"))
    anomaly_type: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    severity: Mapped[str] = mapped_column(String(20), nullable=False, default="medium")
    status: Mapped[str] = mapped_column(String(30), nullable=False, default=AnomalyStatus.OPEN.value, index=True)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    source_ip: Mapped[str] = mapped_column(String(45), nullable=False, index=True)
    detected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), index=True)

    traffic_log: Mapped["TrafficLog | None"] = relationship(back_populates="anomalies")
    feedback: Mapped[list["AnomalyFeedback"]] = relationship(back_populates="anomaly")


class AnomalyFeedback(Base):
    __tablename__ = "anomaly_feedback"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    anomaly_id: Mapped[int] = mapped_column(ForeignKey("anomalies.id"), nullable=False)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False)
    classification: Mapped[str] = mapped_column(String(30), nullable=False)
    notes: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    anomaly: Mapped["Anomaly"] = relationship(back_populates="feedback")
    user: Mapped["User"] = relationship()


class DetectionRule(Base):
    __tablename__ = "detection_rules"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)
    rule_type: Mapped[str] = mapped_column(String(50), nullable=False)
    threshold: Mapped[float] = mapped_column(Float, nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class IntrusionSignature(Base):
    __tablename__ = "intrusion_signatures"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    anomaly_type: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    source_ip: Mapped[str | None] = mapped_column(String(45), index=True)
    dst_ip: Mapped[str | None] = mapped_column(String(45))
    dst_port: Mapped[int | None] = mapped_column(Integer)
    protocol: Mapped[str | None] = mapped_column(String(20))
    encrypted: Mapped[bool | None] = mapped_column(Boolean)
    learned_from_anomaly_id: Mapped[int | None] = mapped_column(ForeignKey("anomalies.id"))
    match_count: Mapped[int] = mapped_column(Integer, default=0)
    confirmation_count: Mapped[int] = mapped_column(Integer, default=1)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    learned_from: Mapped["Anomaly | None"] = relationship()


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"))
    action: Mapped[str] = mapped_column(String(100), nullable=False)
    details: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    user: Mapped["User | None"] = relationship(back_populates="audit_logs")


class KnownDevice(Base):
    __tablename__ = "known_devices"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    ip_address: Mapped[str] = mapped_column(String(45), unique=True, nullable=False, index=True)
    label: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class NetworkScan(Base):
    __tablename__ = "network_scans"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    subnet_prefix: Mapped[str] = mapped_column(String(50), nullable=False)
    status: Mapped[str] = mapped_column(String(30), nullable=False, default="running")
    device_count: Mapped[int] = mapped_column(Integer, default=0)
    unauthorized_count: Mapped[int] = mapped_column(Integer, default=0)
    started_by_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"))
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), index=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    started_by: Mapped["User | None"] = relationship()
    devices: Mapped[list["DiscoveredDevice"]] = relationship(back_populates="scan")


class DiscoveredDevice(Base):
    __tablename__ = "discovered_devices"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("network_scans.id"), nullable=False, index=True)
    ip_address: Mapped[str] = mapped_column(String(45), nullable=False, index=True)
    open_ports: Mapped[str] = mapped_column(String(100), default="")
    is_authorized: Mapped[bool] = mapped_column(Boolean, default=False)
    discovered_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    scan: Mapped["NetworkScan"] = relationship(back_populates="devices")


class AlertDelivery(Base):
    __tablename__ = "alert_deliveries"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    anomaly_id: Mapped[int | None] = mapped_column(ForeignKey("anomalies.id"))
    channel: Mapped[str] = mapped_column(String(20), nullable=False, default="email")
    recipient: Mapped[str] = mapped_column(String(255), nullable=False)
    subject: Mapped[str] = mapped_column(String(255), nullable=False)
    message: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False, index=True)
    error_detail: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), index=True)

    anomaly: Mapped["Anomaly | None"] = relationship()
