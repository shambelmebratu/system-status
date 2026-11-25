from datetime import date, datetime, timezone

from sqlalchemy import Boolean, Date, DateTime, Float, ForeignKey, Index, Integer, String, Text, func
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
    totp_secret: Mapped[str | None] = mapped_column(EncryptedText)      # two-factor sign-in (authenticator app); set during setup
    totp_enabled: Mapped[bool] = mapped_column(Boolean, default=False, server_default="false")
    totp_last_step: Mapped[int | None] = mapped_column(Integer)          # a code is accepted once
    recovery_codes: Mapped[str | None] = mapped_column(Text)            # JSON list of sha256 hashes of unused one-time codes
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
    confirm_checks: Mapped[int | None] = mapped_column(Integer)          # failed checks in a row before an alert (NULL = ALERT_AFTER_FAILURES)
    pause_mode: Mapped[str | None] = mapped_column(String(10))                 # "monitor" = no checks and no alerts; "alerts" = checked, alerts muted
    paused_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))   # NULL with a mode = until resumed
    paused_by: Mapped[str | None] = mapped_column(String(320))
    pause_reason: Mapped[str | None] = mapped_column(String(200))
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
    ssh_alert_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))   # last SSH brute-force alert (one per hour at most)
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
    timeout_seconds: Mapped[int | None] = mapped_column(Integer)       # legacy (before timeout_ms); still read when timeout_ms is NULL
    timeout_ms: Mapped[int | None] = mapped_column(Integer)            # a slower answer is a failed check; NULL = SERVICE_TIMEOUT_SECONDS
    keyword: Mapped[str | None] = mapped_column(String(200))           # content check: text the page must (or must not) contain
    keyword_mode: Mapped[str] = mapped_column(String(10), default="contains", server_default="contains")   # contains | absent
    # TLS certificate expiry (https only): checked every CERT_CHECK_HOURS, alerts at each of cert_alert_days (NULL = CERT_ALERT_DAYS)
    cert_check: Mapped[bool] = mapped_column(Boolean, default=True, server_default="true")
    cert_alert_days: Mapped[str | None] = mapped_column(String(60))     # "30,14,7"
    cert_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    cert_issuer: Mapped[str | None] = mapped_column(String(200))
    cert_subject: Mapped[str | None] = mapped_column(String(300))
    cert_checked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    cert_error: Mapped[str | None] = mapped_column(Text)
    cert_alerted: Mapped[int | None] = mapped_column(Integer)          # the smallest threshold already alerted for this certificate (-1 = expired)
    fail_count: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    confirm_checks: Mapped[int | None] = mapped_column(Integer)          # failed checks in a row before an alert (NULL = ALERT_AFTER_FAILURES)
    pause_mode: Mapped[str | None] = mapped_column(String(10))                 # "monitor" = no checks and no alerts; "alerts" = checked, alerts muted
    paused_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))   # NULL with a mode = until resumed
    paused_by: Mapped[str | None] = mapped_column(String(320))
    pause_reason: Mapped[str | None] = mapped_column(String(200))
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
    notify_kinds: Mapped[str | None] = mapped_column(String(100))     # server,service,cluster,test,dns
    notify_events: Mapped[str | None] = mapped_column(String(100))    # down,alert,recovered,reminder
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class AlertEvent(Base):
    __tablename__ = "alert_events"
    __table_args__ = (Index("ix_alert_events_created_at", "created_at"), Index("ix_alert_events_target", "target_type", "target_id", "id"))
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
    __table_args__ = (Index("ix_check_results_target_time", "target_type", "target_id", "checked_at"),
                      Index("ix_check_results_checked_at", "checked_at"))     # dashboards that look at every target over a time window
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
    __table_args__ = (Index("ix_metric_samples_server_time", "server_id", "ts"), Index("ix_metric_samples_ts", "ts"))
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
    __table_args__ = (Index("ix_traffic_samples_server_time", "server_id", "ts"), Index("ix_traffic_samples_ts", "ts"))
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
    ai_analysis: Mapped[str | None] = mapped_column(Text)                # JSON: the AI explanation (summary, likely causes, checks)
    ai_model: Mapped[str | None] = mapped_column(String(60))
    ai_generated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))   # also set when an attempt failed (no endless retries)


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


class DbConnection(Base):
    """A database an admin connected for the Database section (schema graph and data reports). Read-only access only."""
    __tablename__ = "db_connections"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(100))
    engine: Mapped[str] = mapped_column(String(20))                 # postgresql | mysql
    host: Mapped[str] = mapped_column(String(255))
    port: Mapped[int] = mapped_column(Integer)
    database: Mapped[str] = mapped_column(String(128))
    username: Mapped[str] = mapped_column(String(128))
    password: Mapped[str | None] = mapped_column(EncryptedText)      # never sent back to the browser
    ssl_mode: Mapped[str] = mapped_column(String(20), default="prefer")
    schemas: Mapped[str | None] = mapped_column(String(500))          # comma-separated; empty = every non-system schema
    auth_source: Mapped[str | None] = mapped_column(String(64))        # MongoDB: the database the user is defined in (default: the database itself)
    created_by: Mapped[str | None] = mapped_column(String(320))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_ok_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_error: Mapped[str | None] = mapped_column(Text)
    server_version: Mapped[str | None] = mapped_column(String(60))


class DbReport(Base):
    """A saved report definition: which tables and columns. The data itself is read fresh each time it is opened."""
    __tablename__ = "db_reports"
    id: Mapped[int] = mapped_column(primary_key=True)
    connection_id: Mapped[int] = mapped_column(ForeignKey("db_connections.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(120))
    selection: Mapped[str] = mapped_column(Text)                       # JSON [{"table": "schema.name", "columns": [...]}]
    sample_rows: Mapped[int] = mapped_column(Integer, default=0)
    created_by: Mapped[str | None] = mapped_column(String(320))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)


class ApiTest(Base):
    """A multi-step API test: requests run in order, each with assertions; values can be carried from one step to the next.
    Steps and variables are stored encrypted (they often hold tokens or passwords)."""
    __tablename__ = "api_tests"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(100))
    description: Mapped[str] = mapped_column(String(500), default="", server_default="")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, server_default="true")
    interval_seconds: Mapped[int] = mapped_column(Integer, default=300)
    steps: Mapped[str] = mapped_column(EncryptedText)                  # JSON list of steps
    variables: Mapped[str | None] = mapped_column(EncryptedText)       # JSON {name: value}
    alert_events: Mapped[str | None] = mapped_column(String(100))
    alert_channels: Mapped[str | None] = mapped_column(String(200))
    alert_reminder_minutes: Mapped[int | None] = mapped_column(Integer)
    fail_count: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    last_status: Mapped[str] = mapped_column(String(20), default="unknown")
    last_run_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_checked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_duration_ms: Mapped[float | None] = mapped_column(Float)
    last_error: Mapped[str | None] = mapped_column(Text)
    created_by: Mapped[str | None] = mapped_column(String(320))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class TestRun(Base):
    """One execution of an API test, with the outcome of every step and assertion (secrets masked)."""
    __tablename__ = "test_runs"
    __table_args__ = (Index("ix_test_runs_test_time", "test_id", "started_at"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    test_id: Mapped[int] = mapped_column(ForeignKey("api_tests.id", ondelete="CASCADE"))
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    duration_ms: Mapped[float] = mapped_column(Float, default=0)
    status: Mapped[str] = mapped_column(String(10))                    # passed | failed
    trigger: Mapped[str] = mapped_column(String(340), default="schedule")       # schedule | manual: <email>
    results: Mapped[str] = mapped_column(Text)                         # JSON list of step results
    error: Mapped[str | None] = mapped_column(Text)


class DnsMonitor(Base):
    """Watches a domain's DNS records for changes and its registration for expiry."""
    __tablename__ = "dns_monitors"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(100))
    domain: Mapped[str] = mapped_column(String(253))
    record_types: Mapped[str] = mapped_column(String(60), default="A,AAAA,MX,NS,TXT")
    interval_seconds: Mapped[int] = mapped_column(Integer, default=3600)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, server_default="true")
    baseline: Mapped[str | None] = mapped_column(Text)                 # JSON {type: [values]}: the accepted records
    current: Mapped[str | None] = mapped_column(Text)                  # JSON: what DNS answered last
    changed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    check_expiry: Mapped[bool] = mapped_column(Boolean, default=True, server_default="true")
    expiry_alert_days: Mapped[str | None] = mapped_column(String(60))
    domain_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    registrar: Mapped[str | None] = mapped_column(String(200))
    expiry_checked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    expiry_error: Mapped[str | None] = mapped_column(Text)
    expiry_alerted: Mapped[int | None] = mapped_column(Integer)
    alert_events: Mapped[str | None] = mapped_column(String(100))
    alert_channels: Mapped[str | None] = mapped_column(String(200))
    alert_reminder_minutes: Mapped[int | None] = mapped_column(Integer)
    fail_count: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    last_status: Mapped[str] = mapped_column(String(20), default="unknown")
    last_checked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_error: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Heartbeat(Base):
    """A cron job / backup / batch job that pings SM-Watch. Late or failed pings raise an incident."""
    __tablename__ = "heartbeats"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(100))
    description: Mapped[str] = mapped_column(String(500), default="", server_default="")
    token: Mapped[str] = mapped_column(EncryptedText)                   # shown again in the dashboard (it is in the job's crontab anyway)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    period_seconds: Mapped[int] = mapped_column(Integer, default=86400)  # how often the job runs
    grace_seconds: Mapped[int] = mapped_column(Integer, default=3600)    # how late a ping may be before it counts as missed
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, server_default="true")
    last_ping_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_start_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_duration_ms: Mapped[float | None] = mapped_column(Float)
    alert_events: Mapped[str | None] = mapped_column(String(100))
    alert_channels: Mapped[str | None] = mapped_column(String(200))
    alert_reminder_minutes: Mapped[int | None] = mapped_column(Integer)
    fail_count: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    last_status: Mapped[str] = mapped_column(String(20), default="unknown")
    last_checked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_error: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class HeartbeatPing(Base):
    __tablename__ = "heartbeat_pings"
    __table_args__ = (Index("ix_heartbeat_pings_hb_time", "heartbeat_id", "ts"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    heartbeat_id: Mapped[int] = mapped_column(ForeignKey("heartbeats.id", ondelete="CASCADE"))
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    kind: Mapped[str] = mapped_column(String(10))                       # success | start | fail
    duration_ms: Mapped[float | None] = mapped_column(Float)
    message: Mapped[str | None] = mapped_column(Text)                   # what the job sent (e.g. the last lines of its output), cleaned
    ip: Mapped[str | None] = mapped_column(String(64))


class Maintenance(Base):
    """Planned work: alerts for the chosen monitors are held back while it runs, and the status page announces it."""
    __tablename__ = "maintenance_windows"
    id: Mapped[int] = mapped_column(primary_key=True)
    title: Mapped[str] = mapped_column(String(150))
    description: Mapped[str] = mapped_column(Text, default="")
    starts_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    ends_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    targets: Mapped[str | None] = mapped_column(Text)                   # JSON ["server:1", "service:3"]; NULL = everything
    suppress_alerts: Mapped[bool] = mapped_column(Boolean, default=True)
    show_on_status: Mapped[bool] = mapped_column(Boolean, default=True)
    created_by: Mapped[str | None] = mapped_column(String(320))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Slo(Base):
    """A service level objective: e.g. 99.9 % availability of one monitor over 30 days, with its error budget."""
    __tablename__ = "slos"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(100))
    target_type: Mapped[str] = mapped_column(String(20))
    target_id: Mapped[int] = mapped_column(Integer)
    objective: Mapped[float] = mapped_column(Float)                      # percent, e.g. 99.9
    window_days: Mapped[int] = mapped_column(Integer, default=30)
    burn_alerts: Mapped[bool] = mapped_column(Boolean, default=True)
    alert_state: Mapped[str | None] = mapped_column(String(20))          # none | fast | slow | exhausted: what was last alerted
    alert_state_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_by: Mapped[str | None] = mapped_column(String(320))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class SshFailureSample(Base):
    """Failed SSH login attempts one agent saw between two reports (counts only)."""
    __tablename__ = "ssh_failure_samples"
    __table_args__ = (Index("ix_ssh_failures_server_time", "server_id", "ts"), Index("ix_ssh_failures_time", "ts"))
    id: Mapped[int] = mapped_column(primary_key=True)
    server_id: Mapped[int] = mapped_column(ForeignKey("servers.id", ondelete="CASCADE"))
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    total: Mapped[int] = mapped_column(Integer, default=0)
    ips: Mapped[str] = mapped_column(Text, default="{}")      # JSON {ip: attempts}
    users: Mapped[str] = mapped_column(Text, default="{}")    # JSON {user name: attempts}


class SecurityScan(Base):
    """One exposure scan (open ports of a server) or TLS audit (of a service or a server port)."""
    __tablename__ = "security_scans"
    __table_args__ = (Index("ix_security_scans_target", "kind", "target_type", "target_id", "started_at"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    kind: Mapped[str] = mapped_column(String(10))             # ports | tls
    target_type: Mapped[str] = mapped_column(String(20))
    target_id: Mapped[int] = mapped_column(Integer)
    address: Mapped[str] = mapped_column(String(300), default="")
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    duration_ms: Mapped[float] = mapped_column(Float, default=0)
    grade: Mapped[str | None] = mapped_column(String(4))
    findings: Mapped[int] = mapped_column(Integer, default=0)
    results: Mapped[str] = mapped_column(Text, default="{}")
    error: Mapped[str | None] = mapped_column(Text)


class Anomaly(Base):
    """A metric far outside its own normal range (robust statistics over the previous 7 days). No AI involved."""
    __tablename__ = "anomalies"
    __table_args__ = (Index("ix_anomalies_open", "target_type", "target_id", "metric", "resolved_at"), Index("ix_anomalies_started", "started_at"))
    id: Mapped[int] = mapped_column(primary_key=True)
    target_type: Mapped[str] = mapped_column(String(20))
    target_id: Mapped[int] = mapped_column(Integer)
    target_name: Mapped[str] = mapped_column(String(100), default="")
    metric: Mapped[str] = mapped_column(String(30))
    direction: Mapped[str] = mapped_column(String(5))                    # up | down
    value: Mapped[float] = mapped_column(Float)                          # the recent value (15-minute average)
    peak: Mapped[float] = mapped_column(Float)                           # the most extreme recent value while it lasted
    baseline: Mapped[float] = mapped_column(Float)                       # median of the previous 7 days
    spread: Mapped[float] = mapped_column(Float)                         # robust spread (1.4826 x MAD)
    score: Mapped[float] = mapped_column(Float)                          # how many spreads away
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    alerted: Mapped[bool] = mapped_column(Boolean, default=False)


class SshLoginEvent(Base):
    """A successful SSH login an agent saw (agent 2.15+): who, from where, how, and whether it looked suspicious."""
    __tablename__ = "ssh_login_events"
    __table_args__ = (Index("ix_ssh_logins_server_ip", "server_id", "ip"), Index("ix_ssh_logins_time", "ts"))
    id: Mapped[int] = mapped_column(primary_key=True)
    server_id: Mapped[int] = mapped_column(ForeignKey("servers.id", ondelete="CASCADE"))
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    ip: Mapped[str] = mapped_column(String(45))
    user: Mapped[str] = mapped_column(String(64), default="")
    method: Mapped[str] = mapped_column(String(30), default="")
    failures_before: Mapped[int] = mapped_column(Integer, default=0)      # failed attempts from the same address in the 24 h before
    new_source: Mapped[bool] = mapped_column(Boolean, default=False)       # first login from this address on this server
    kind: Mapped[str] = mapped_column(String(10), default="login")        # login | sftp (a file-transfer session)
    key_type: Mapped[str] = mapped_column(String(30), default="")
    fingerprint: Mapped[str] = mapped_column(String(80), default="")      # SHA256 fingerprint of the key used (never the key)
    key_name: Mapped[str] = mapped_column(String(80), default="")         # the key's comment, usually the device (sam@laptop)


class SecurityFinding(Base):
    """A sign of compromise on one server: from the agent's threat scan, or derived by SM-Watch (suspicious login, new SSH key).
    Open while it is still seen; agent findings resolve themselves when they disappear, the others when someone acknowledges them."""
    __tablename__ = "security_findings"
    __table_args__ = (Index("ix_findings_server_key", "server_id", "key", "resolved_at"), Index("ix_findings_open", "resolved_at", "severity"))
    id: Mapped[int] = mapped_column(primary_key=True)
    server_id: Mapped[int] = mapped_column(ForeignKey("servers.id", ondelete="CASCADE"))
    key: Mapped[str] = mapped_column(String(200))
    source: Mapped[str] = mapped_column(String(10), default="agent")      # agent | smwatch
    kind: Mapped[str] = mapped_column(String(40))
    severity: Mapped[str] = mapped_column(String(10))
    title: Mapped[str] = mapped_column(String(200))
    detail: Mapped[str] = mapped_column(Text, default="")
    evidence: Mapped[str] = mapped_column(Text, default="{}")             # JSON: pid, process, path, user, ip, ...
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    acknowledged_by: Mapped[str | None] = mapped_column(String(320))
    acknowledged_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    note: Mapped[str] = mapped_column(Text, default="")


class ClusterFinding(Base):
    """A security problem in one Kubernetes cluster, from the cluster agent's checks (privileged or host-level workloads, risky mounts,
    miners, reverse shells, cluster-admin given to workloads, ...). One finding per workload and rule, not per pod replica; it
    resolves itself when the agent stops seeing it. Acknowledging keeps it listed as known until it disappears."""
    __tablename__ = "cluster_findings"
    __table_args__ = (Index("ix_cluster_findings_key", "cluster_id", "key", "resolved_at"), Index("ix_cluster_findings_open", "resolved_at", "severity"))
    id: Mapped[int] = mapped_column(primary_key=True)
    cluster_id: Mapped[int] = mapped_column(ForeignKey("clusters.id", ondelete="CASCADE"))
    key: Mapped[str] = mapped_column(String(300))
    kind: Mapped[str] = mapped_column(String(40))
    severity: Mapped[str] = mapped_column(String(10))
    namespace: Mapped[str] = mapped_column(String(253), default="")
    object: Mapped[str] = mapped_column(String(300), default="")
    title: Mapped[str] = mapped_column(String(200))
    detail: Mapped[str] = mapped_column(Text, default="")
    evidence: Mapped[str] = mapped_column(Text, default="{}")             # JSON: container, image, command, path, subject, role, pods, created
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    acknowledged_by: Mapped[str | None] = mapped_column(String(320))
    acknowledged_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    note: Mapped[str] = mapped_column(Text, default="")


class CheckDaily(Base):
    """Checks and available checks per monitor per finished UTC day: uptime over weeks or a year reads these few rows instead of
    millions of check results. A row with target_type "_" marks a day as counted (also when nothing was checked that day)."""
    __tablename__ = "check_daily"
    day: Mapped[date] = mapped_column(Date, primary_key=True)
    target_type: Mapped[str] = mapped_column(String(20), primary_key=True)
    target_id: Mapped[int] = mapped_column(Integer, primary_key=True)
    total: Mapped[int] = mapped_column(Integer, default=0)
    ok: Mapped[int] = mapped_column(Integer, default=0)


class SecuritySnapshot(Base):
    """The security state of every server, recorded every hour by the worker, so Security → Compare can show how it changed from
    hour to hour, day to day, week to week and month to month. Hourly rows are kept 35 days; one row per day is kept 400 days."""
    __tablename__ = "security_snapshots"
    __table_args__ = (Index("ix_security_snapshots_ts", "ts"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    data: Mapped[str] = mapped_column(Text, default="{}")     # JSON {"servers": {id: {...}}}
