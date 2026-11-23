from functools import lru_cache

from pydantic import model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

INSECURE_DEFAULTS = {
    "jwt_secret": {"change-this-secret-before-production", "replace-with-a-long-random-secret"},
    "admin_password": {"change-me-now", "replace-with-a-long-random-password"},
}


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    app_name: str = "SM-Watch"
    environment: str = "production"
    database_url: str = "postgresql+psycopg://smwatch:smwatch@postgres:5432/smwatch"
    jwt_secret: str = "change-this-secret-before-production"
    admin_email: str = "admin@example.com"
    admin_password: str = "change-me-now"
    check_interval_seconds: int = 60
    cors_origins: str = "http://localhost:3000"
    encryption_key: str = ""  # Fernet key; derived from jwt_secret when empty
    session_hours: int = 8
    check_retention_days: int = 365
    metric_retention_days: int = 14
    worker_concurrency: int = 16
    alert_after_failures: int = 2      # consecutive failed checks before a target is declared down
    reminder_minutes: int = 30         # minimum gap between repeat alerts while a target stays down
    alert_retry_minutes: int = 60      # undelivered alerts older than this are expired, not retried
    public_status_enabled: bool = True
    public_status_default_days: int = 30       # the status page opens on this time frame ...
    public_status_ranges: str = "7,30,90"      # ... and visitors can switch between these (days, 1 to 365)
    audit_retention_days: int = 365
    agent_min_report_seconds: float = 2   # an agent may not report more often than this (flood protection)
    dockerhub_username: str = "shambi21"  # where the published images live: <dockerhub_username>/<dockerhub_repo>:<service>-<smwatch_version>
    dockerhub_repo: str = "sm-watch"      # one repository for every service; the tag names the service (api-1.2.3, host-agent-1.2.3 ...)
    smwatch_version: str = "latest"
    agent_image: str = ""                  # full override, e.g. registry.example.com/sm-watch:host-agent-1.2.3
    k8s_agent_image: str = ""              # image the Kubernetes manifest deploys; default <dockerhub_username>/<dockerhub_repo>:k8s-agent-<smwatch_version>
    host_agent_token_file: str = ""  # when set, the API provisions a server entry + token for the bundled host agent
    host_public_ip: str = ""  # optional: public address of the machine running SM-Watch (shown for the bundled agent); default: resolved from PUBLIC_URL
    public_url: str = ""  # externally reachable control-plane URL shown in agent install commands (e.g. https://monitor.example.com)
    cookie_secure: bool = False  # set true when served over HTTPS
    login_max_attempts: int = 5
    login_window_seconds: int = 300
    # A single account is locked far less eagerly than a single address: otherwise anyone who knows an admin's email could keep
    # that admin locked out. (Each guess also costs ~0.25 s of server time because of the password hash.)
    login_account_max_attempts: int = 20
    login_account_window_seconds: int = 900
    # Extra hostnames the monitor must never contact (internal compose services).
    blocked_hosts: str = "postgres,api,worker,migrate,frontend,localhost,metadata.google.internal"
    # When true, RFC1918/ULA private ranges are blocked too (off: monitoring LAN hosts is the point).
    block_private_targets: bool = False
    allow_insecure_pull: bool = False   # pull-mode agents on PUBLIC addresses must use https (the check carries the agent token)
    cpu_threshold: float = 85
    memory_threshold: float = 90
    disk_threshold: float = 85
    load_threshold: float = 10
    swap_threshold: float = 80
    process_threshold: float = 80
    # --- operational limits (all overridable in .env; nothing below is hard-coded elsewhere) ---
    heartbeat_missed_reports: int = 3          # a push agent is "down" after this many report intervals of silence...
    heartbeat_min_grace_seconds: int = 30      # ...but never sooner than this
    k8s_report_interval_seconds: int = 30      # how often the in-cluster agent reports
    k8s_heartbeat_grace_seconds: int = 100     # silence before a cluster is marked down
    k8s_offline_seconds: int = 120             # live queries are refused when the agent has been silent this long
    k8s_max_pending_requests: int = 8          # queued dashboard questions per cluster
    log_result_ttl_minutes: int = 15           # fetched logs are deleted after this long
    log_pickup_timeout_seconds: int = 45       # an agent must pick up a log request within this time
    log_max_pending_per_server: int = 5
    agent_max_open_polls: int = 4              # simultaneous held-open task polls one agent may have (a stolen token cannot exhaust connections)
    max_request_body_kb: int = 256             # largest request body the API accepts ...
    max_agent_result_kb: int = 4096            # ... except agent answers (log text / cluster lists)
    enrollment_default_minutes: int = 15       # install links: default lifetime ...
    enrollment_max_minutes: int = 1440         # ... and the longest an admin may choose
    alert_retention_days: int = 90             # defaults for the admin-editable retention (Settings > Data retention)
    incident_retention_days: int = 365
    link_retention_days: int = 7
    audit_min_retention_days: int = 30         # the audit log can never be kept shorter, or purged, below this
    schedule_max_attempts: int = 3             # scheduled messages: tries per run
    schedule_retry_minutes: int = 1
    schedule_missed_minutes: int = 15          # a reminder this late is skipped instead of sent
    service_timeout_seconds: int = 10          # a service check that takes longer than this fails (per service override)
    cert_alert_days: str = "30,14,7"           # certificate expiry: alert this many days before (per service override)
    cert_check_hours: int = 6                  # how often a service's certificate is re-read
    dns_resolvers: str = ""                    # DNS monitors: resolvers to ask (comma-separated IPs); empty = the system resolver
    test_run_retention_days: int = 30          # API test run history is kept this long
    ssh_attack_threshold: int = 30             # failed SSH logins on one server within 10 minutes that count as an attack
    ssh_success_after_failures: int = 5        # a successful SSH login from an address with at least this many failures (24 h) is a likely break-in
    ssh_new_source_alerts: bool = True
    ssh_daily_login_alert: int = 4             # alert when one server has more SSH logins than this in a day, even legitimate ones (0 = off; admins can change it)         # alert on an SSH login from an address never seen on that server before
    threat_alert_severity: str = "high"        # agent threat findings at or above this severity send an alert: critical | high | medium | off
    ai_enabled: bool = True                     # AI_ENABLED=false removes every AI feature: menu, Ask AI, explanations, log analysis, and their API
    security_scan_hours: int = 24              # how often servers' open ports and services' TLS are re-checked (0 = only on demand); admins can change it in Security → Scans
    agent_threat_minutes: int = 10             # default for how often agents run their threat scan (admins can change it in Security → Scans)
    agent_updates_hours: int = 6               # default for how often agents look for pending updates
    perf_default_window_minutes: int = 10      # response-time targets look at this many recent minutes unless set per monitor
    perf_min_check_samples: int = 5            # a target is not judged on fewer probes than this ...
    perf_min_requests: int = 50                # ... or fewer real requests than this (percentiles of a handful of requests mean nothing)
    traffic_buckets_ms: str = "5,10,25,50,75,100,150,200,300,500,750,1000,1500,2000,3000,5000,10000"   # response-time histogram boundaries agents use (ms)
    usage_warn_percent: float = 70             # dashboard colouring of usage bars (amber)
    usage_bad_percent: float = 90              # (red)
    company_name: str = "SM-Watch"
    brand_primary_color: str = "#c9f36b"
    brand_accent_color: str = "#68d5e8"

    @model_validator(mode="after")
    def reject_insecure_defaults(self):
        if self.environment.lower() in ("development", "dev", "test"):
            return self
        problems = []
        if self.jwt_secret in INSECURE_DEFAULTS["jwt_secret"] or len(self.jwt_secret) < 32:
            problems.append("JWT_SECRET must be set to a random value of at least 32 characters")
        if self.admin_password in INSECURE_DEFAULTS["admin_password"] or len(self.admin_password) < 12:
            problems.append("ADMIN_PASSWORD must be set and at least 12 characters")
        if problems:
            raise ValueError("Refusing to start with insecure configuration: " + "; ".join(problems) + ". Set ENVIRONMENT=development to bypass for local use only.")
        return self


def published_image(settings: "Settings", service: str) -> str:
    """A published image: one repository, the service and version in the tag, e.g. shambi21/sm-watch:host-agent-1.2.3."""
    return f"{settings.dockerhub_username}/{settings.dockerhub_repo}:{service}-{settings.smwatch_version}"


def resolved_agent_image(settings: "Settings") -> str:
    """The image the Docker install command runs. The agent code is baked into it: nothing is downloaded at start-up."""
    return settings.agent_image or published_image(settings, "host-agent")


def resolved_k8s_agent_image(settings: "Settings") -> str:
    return settings.k8s_agent_image or published_image(settings, "k8s-agent")


@lru_cache
def get_settings() -> Settings:
    return Settings()
