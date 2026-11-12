from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Index, Integer, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .crypto import EncryptedText
from .database import Base


class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(primary_key=True)
    email: Mapped[str] = mapped_column(String(320), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(Text)
    role: Mapped[str] = mapped_column(String(30), default="admin")
    token_version: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class Server(Base):
    __tablename__ = "servers"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(100))
    host: Mapped[str] = mapped_column(String(255), default="")
    monitor_mode: Mapped[str] = mapped_column(String(20), default="agent")
    check_interval_seconds: Mapped[int] = mapped_column(Integer, default=60)
    endpoint: Mapped[str] = mapped_column(String(500), default="")
    agent_token: Mapped[str | None] = mapped_column(EncryptedText, default=None)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    cpu_threshold: Mapped[float] = mapped_column(Float, default=85)
    memory_threshold: Mapped[float] = mapped_column(Float, default=90)
    disk_threshold: Mapped[float] = mapped_column(Float, default=85)
    load_threshold: Mapped[float] = mapped_column(Float, default=10)
    swap_threshold: Mapped[float] = mapped_column(Float, default=80)
    process_names: Mapped[str] = mapped_column(Text, default="")
    process_threshold: Mapped[float] = mapped_column(Float, default=80)
    last_status: Mapped[str] = mapped_column(String(20), default="unknown")
    last_checked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_error: Mapped[str | None] = mapped_column(Text)
    last_metrics: Mapped[str | None] = mapped_column(Text)
    fail_count: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    public: Mapped[bool] = mapped_column(Boolean, default=False, server_default="false")
    token_hash: Mapped[str | None] = mapped_column(String(64), index=True)
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    services: Mapped[list["Service"]] = relationship(passive_deletes=True)


class Service(Base):
    __tablename__ = "services"
    id: Mapped[int] = mapped_column(primary_key=True)
    server_id: Mapped[int | None] = mapped_column(ForeignKey("servers.id", ondelete="SET NULL"), nullable=True)
    name: Mapped[str] = mapped_column(String(100))
    url: Mapped[str] = mapped_column(String(500))
    expected_status: Mapped[int] = mapped_column(Integer, default=200)
    interval_seconds: Mapped[int] = mapped_column(Integer, default=60)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    public: Mapped[bool] = mapped_column(Boolean, default=False, server_default="false")
    fail_count: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    last_status: Mapped[str] = mapped_column(String(20), default="unknown")
    last_checked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_latency_ms: Mapped[float | None] = mapped_column(Float)
    last_http_status: Mapped[int | None] = mapped_column(Integer)
    last_error: Mapped[str | None] = mapped_column(Text)


class Channel(Base):
    __tablename__ = "channels"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(100))
    type: Mapped[str] = mapped_column(String(30), default="telegram")
    token: Mapped[str | None] = mapped_column(EncryptedText)
    chat_id: Mapped[str | None] = mapped_column(String(200))
    endpoint: Mapped[str | None] = mapped_column(EncryptedText)
    phone_number_id: Mapped[str | None] = mapped_column(String(100))
    template_name: Mapped[str | None] = mapped_column(String(100))
    template_language: Mapped[str | None] = mapped_column(String(20), default="en_US")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class AlertEvent(Base):
    __tablename__ = "alert_events"
    id: Mapped[int] = mapped_column(primary_key=True)
    target_type: Mapped[str] = mapped_column(String(30))
    target_id: Mapped[int] = mapped_column(Integer)
    severity: Mapped[str] = mapped_column(String(20))
    message: Mapped[str] = mapped_column(Text)
    sent: Mapped[bool] = mapped_column(Boolean, default=False)
    delivery_error: Mapped[str | None] = mapped_column(Text)
    delivery_attempts: Mapped[int] = mapped_column(Integer, default=0)
    last_attempt_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class CheckResult(Base):
    """One row per executed check (service probe, server poll, or agent report)."""
    __tablename__ = "check_results"
    __table_args__ = (Index("ix_check_results_target_time", "target_type", "target_id", "checked_at"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    target_type: Mapped[str] = mapped_column(String(20))
    target_id: Mapped[int] = mapped_column(Integer)
    status: Mapped[str] = mapped_column(String(20))
    latency_ms: Mapped[float | None] = mapped_column(Float)
    http_status: Mapped[int | None] = mapped_column(Integer)
    error: Mapped[str | None] = mapped_column(Text)
    checked_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class MetricSample(Base):
    """Host resource time series, written on every agent poll/report."""
    __tablename__ = "metric_samples"
    __table_args__ = (Index("ix_metric_samples_server_time", "server_id", "ts"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    server_id: Mapped[int] = mapped_column(ForeignKey("servers.id", ondelete="CASCADE"))
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    cpu: Mapped[float] = mapped_column(Float)
    memory: Mapped[float] = mapped_column(Float)
    disk: Mapped[float] = mapped_column(Float)
    load: Mapped[float] = mapped_column(Float)
    swap: Mapped[float] = mapped_column(Float)
    net_rx_bps: Mapped[float | None] = mapped_column(Float)
    net_tx_bps: Mapped[float | None] = mapped_column(Float)


class Incident(Base):
    """An outage/alert window. Opened on first failure, resolved on recovery."""
    __tablename__ = "incidents"
    __table_args__ = (Index("ix_incidents_target", "target_type", "target_id", "resolved_at"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    target_type: Mapped[str] = mapped_column(String(20))
    target_id: Mapped[int] = mapped_column(Integer)
    target_name: Mapped[str] = mapped_column(String(100))
    severity: Mapped[str] = mapped_column(String(20), default="critical")
    title: Mapped[str] = mapped_column(Text)
    detail: Mapped[str | None] = mapped_column(Text)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
