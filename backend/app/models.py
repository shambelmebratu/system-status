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
    role: Mapped[str] = mapped_column(String(30), default="admin")   # admin | operator | viewer
    name: Mapped[str] = mapped_column(String(100), default="", server_default="")
    active: Mapped[bool] = mapped_column(Boolean, default=True, server_default="true")
    must_change_password: Mapped[bool] = mapped_column(Boolean, default=False, server_default="false")
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    token_version: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    # JSON {"servers": [ids], "services": [ids], "clusters": [ids]}: the only monitors this person may see. NULL = everything. Ignored for admins.
    access_scope: Mapped[str | None] = mapped_column(Text)
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
    # Per-monitor alert settings (NULL = inherit): which alert types are sent, to which channels, and how often to repeat.
    alert_events: Mapped[str | None] = mapped_column(String(100))      # down,alert,recovered,reminder
    alert_channels: Mapped[str | None] = mapped_column(String(200))    # channel ids; NULL = every channel
    alert_reminder_minutes: Mapped[int | None] = mapped_column(Integer)  # NULL = REMINDER_MINUTES; 0 = never repeat
    # Response-time target (NULL = none): alert when this percentile over the window is slower than the threshold.
    perf_percentile: Mapped[str | None] = mapped_column(String(4))     # p50 | p95 | p99
    perf_threshold_ms: Mapped[int | None] = mapped_column(Integer)
    perf_window_minutes: Mapped[int | None] = mapped_column(Integer)   # NULL = PERF_DEFAULT_WINDOW_MINUTES
    token_hash: Mapped[str | None] = mapped_column(String(64), index=True)
    machine_id: Mapped[str | None] = mapped_column(String(64), index=True)
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_agent_ip: Mapped[str | None] = mapped_column(String(64))
    log_policy: Mapped[str | None] = mapped_column(Text)                  # JSON, see log_policy.py (NULL = unrestricted)
    token_issued_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    pending_token: Mapped[str | None] = mapped_column(EncryptedText)      # new token waiting for the agent to pick it up
    pending_token_hash: Mapped[str | None] = mapped_column(String(64), index=True)
    pending_token_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
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
    # Per-monitor alert settings (NULL = inherit): which alert types are sent, to which channels, and how often to repeat.
    alert_events: Mapped[str | None] = mapped_column(String(100))      # down,alert,recovered,reminder
    alert_channels: Mapped[str | None] = mapped_column(String(200))    # channel ids; NULL = every channel
    alert_reminder_minutes: Mapped[int | None] = mapped_column(Integer)  # NULL = REMINDER_MINUTES; 0 = never repeat
    # Response-time target (NULL = none): alert when this percentile over the window is slower than the threshold.
    perf_percentile: Mapped[str | None] = mapped_column(String(4))     # p50 | p95 | p99
    perf_threshold_ms: Mapped[int | None] = mapped_column(Integer)
    perf_window_minutes: Mapped[int | None] = mapped_column(Integer)   # NULL = PERF_DEFAULT_WINDOW_MINUTES
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
    # Which alerts this channel receives (comma-separated; NULL = everything). See alert routing in monitoring.py.
    notify_kinds: Mapped[str | None] = mapped_column(String(100))     # server,service,cluster
    notify_events: Mapped[str | None] = mapped_column(String(100))    # down,alert,recovered,reminder
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class AlertEvent(Base):
    __tablename__ = "alert_events"
    id: Mapped[int] = mapped_column(primary_key=True)
    target_type: Mapped[str] = mapped_column(String(30))
    target_id: Mapped[int] = mapped_column(Integer)
    severity: Mapped[str] = mapped_column(String(20))
    state: Mapped[str | None] = mapped_column(String(20))            # down | still_down | alert | still_alert | recovered
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
    cpu_peak: Mapped[float | None] = mapped_column(Float)     # highest CPU % seen between two reports (agent 2.12+)
    memory: Mapped[float] = mapped_column(Float)
    disk: Mapped[float] = mapped_column(Float)
    load: Mapped[float] = mapped_column(Float)
    swap: Mapped[float] = mapped_column(Float)
    net_rx_bps: Mapped[float | None] = mapped_column(Float)
    net_tx_bps: Mapped[float | None] = mapped_column(Float)


class TrafficSample(Base):
    """Response times of REAL traffic at a load balancer / web server, summarised by the agent for one reporting window.
    Only a histogram is kept (never the requests themselves), so percentiles stay exact enough to merge across windows."""
    __tablename__ = "traffic_samples"
    __table_args__ = (Index("ix_traffic_samples_server_time", "server_id", "ts"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    server_id: Mapped[int] = mapped_column(ForeignKey("servers.id", ondelete="CASCADE"))
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    window_seconds: Mapped[float] = mapped_column(Float, default=0)
    requests: Mapped[int] = mapped_column(Integer, default=0)
    errors_5xx: Mapped[int] = mapped_column(Integer, default=0)
    errors_4xx: Mapped[int] = mapped_column(Integer, default=0)
    sum_ms: Mapped[float] = mapped_column(Float, default=0)
    max_ms: Mapped[float] = mapped_column(Float, default=0)
    upstream_sum_ms: Mapped[float] = mapped_column(Float, default=0)
    upstream_count: Mapped[int] = mapped_column(Integer, default=0)
    bounds: Mapped[str] = mapped_column(Text)        # JSON list of bucket upper bounds in ms (the last bucket is "above the last bound")
    counts: Mapped[str] = mapped_column(Text)        # JSON list of per-bucket request counts, len(bounds) + 1


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


class Enrollment(Base):
    """A join token an admin hands out; agents present it once to register themselves as new servers."""
    __tablename__ = "enrollments"
    id: Mapped[int] = mapped_column(primary_key=True)
    label: Mapped[str] = mapped_column(String(100), default="")
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    token: Mapped[str] = mapped_column(EncryptedText)  # stored encrypted so the admin can copy the command again later
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    max_uses: Mapped[int | None] = mapped_column(Integer)
    uses: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    revoked: Mapped[bool] = mapped_column(Boolean, default=False, server_default="false")
    created_by: Mapped[str | None] = mapped_column(String(320))
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class ScheduledMessage(Base):
    """A message sent to chosen notification channels on a schedule (e.g. a daily stand-up reminder)."""
    __tablename__ = "scheduled_messages"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(100))
    text: Mapped[str] = mapped_column(Text)
    channel_ids: Mapped[str] = mapped_column(Text, default="[]")          # JSON list of channel ids
    repeat: Mapped[str] = mapped_column(String(10), default="daily")      # once | daily | weekly
    time_of_day: Mapped[str] = mapped_column(String(5), default="09:00")  # HH:MM in `timezone`
    days_of_week: Mapped[str] = mapped_column(String(20), default="")     # "1,2,3,4,5" (Mon=1..Sun=7); empty = every day
    run_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))  # one-time runs (UTC)
    timezone: Mapped[str] = mapped_column(String(64), default="UTC")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    next_run_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)
    pending_channel_ids: Mapped[str | None] = mapped_column(Text)         # channels still to retry for the current run
    attempts: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    last_run_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_status: Mapped[str | None] = mapped_column(String(20))           # sent | partial | failed | missed
    last_error: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class LogRequest(Base):
    """A short-lived, on-demand log fetch: queued by the dashboard, executed by the server's agent, read back by the dashboard."""
    __tablename__ = "log_requests"
    __table_args__ = (Index("ix_log_requests_server_status", "server_id", "status"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    server_id: Mapped[int] = mapped_column(ForeignKey("servers.id", ondelete="CASCADE"))
    query: Mapped[str] = mapped_column(Text)                     # JSON of the validated LogQuery
    status: Mapped[str] = mapped_column(String(10), default="pending")  # pending | running | done | error
    output: Mapped[str | None] = mapped_column(Text)
    error: Mapped[str | None] = mapped_column(Text)
    truncated: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class AuditEvent(Base):
    """Append-only record of security-relevant actions: who did what, to what, from where, and whether it worked."""
    __tablename__ = "audit_events"
    id: Mapped[int] = mapped_column(primary_key=True)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    actor: Mapped[str] = mapped_column(String(320), default="")          # user email, "agent:<name>", or "system"
    actor_role: Mapped[str | None] = mapped_column(String(20))
    action: Mapped[str] = mapped_column(String(60), index=True)          # e.g. auth.login, user.create, logs.read
    target: Mapped[str] = mapped_column(String(200), default="")
    detail: Mapped[str | None] = mapped_column(Text)
    ip: Mapped[str | None] = mapped_column(String(64))
    success: Mapped[bool] = mapped_column(Boolean, default=True, server_default="true")


class Cluster(Base):
    """A Kubernetes cluster observed by an in-cluster agent (read-only; the agent only makes outbound connections)."""
    __tablename__ = "clusters"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(100), unique=True, index=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    token_hash: Mapped[str | None] = mapped_column(String(64), index=True)
    agent_token: Mapped[str | None] = mapped_column(EncryptedText)
    token_issued_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    pending_token: Mapped[str | None] = mapped_column(EncryptedText)
    pending_token_hash: Mapped[str | None] = mapped_column(String(64), index=True)
    pending_token_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_agent_ip: Mapped[str | None] = mapped_column(String(64))
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_checked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_status: Mapped[str] = mapped_column(String(20), default="unknown")
    last_error: Mapped[str | None] = mapped_column(Text)
    k8s_version: Mapped[str | None] = mapped_column(String(40))
    agent_version: Mapped[str | None] = mapped_column(String(32))
    summary: Mapped[str | None] = mapped_column(Text)            # JSON of the latest report
    log_policy: Mapped[str | None] = mapped_column(Text)         # JSON, see k8s.py (NULL = unrestricted)
    # Per-monitor alert settings (NULL = inherit): which alert types are sent, to which channels, and how often to repeat.
    alert_events: Mapped[str | None] = mapped_column(String(100))      # down,alert,recovered,reminder
    alert_channels: Mapped[str | None] = mapped_column(String(200))    # channel ids; NULL = every channel
    alert_reminder_minutes: Mapped[int | None] = mapped_column(Integer)  # NULL = REMINDER_MINUTES; 0 = never repeat
    created_by: Mapped[str | None] = mapped_column(String(320))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class ClusterSample(Base):
    """Small time series per report (counts and usage totals); the detailed objects are never stored."""
    __tablename__ = "cluster_samples"
    __table_args__ = (Index("ix_cluster_samples_cluster_time", "cluster_id", "ts"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    cluster_id: Mapped[int] = mapped_column(ForeignKey("clusters.id", ondelete="CASCADE"))
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    nodes_ready: Mapped[int] = mapped_column(Integer, default=0)
    nodes_total: Mapped[int] = mapped_column(Integer, default=0)
    pods_running: Mapped[int] = mapped_column(Integer, default=0)
    pods_total: Mapped[int] = mapped_column(Integer, default=0)
    pods_failing: Mapped[int] = mapped_column(Integer, default=0)
    cpu_m: Mapped[float | None] = mapped_column(Float)
    cpu_alloc_m: Mapped[float | None] = mapped_column(Float)
    mem_mib: Mapped[float | None] = mapped_column(Float)
    mem_alloc_mib: Mapped[float | None] = mapped_column(Float)


class K8sRequest(Base):
    """An on-demand question for a cluster agent (list pods, read logs, ...). Short-lived, like LogRequest."""
    __tablename__ = "k8s_requests"
    __table_args__ = (Index("ix_k8s_requests_cluster_status", "cluster_id", "status"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    cluster_id: Mapped[int] = mapped_column(ForeignKey("clusters.id", ondelete="CASCADE"))
    query: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(10), default="pending")
    output: Mapped[str | None] = mapped_column(Text)
    error: Mapped[str | None] = mapped_column(Text)
    truncated: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class AppSetting(Base):
    """Small admin-editable settings (JSON values), e.g. the data retention and purge schedule."""
    __tablename__ = "app_settings"
    key: Mapped[str] = mapped_column(String(60), primary_key=True)
    value: Mapped[str] = mapped_column(Text, default="{}")
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)
    updated_by: Mapped[str | None] = mapped_column(String(320))
