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
    audit_retention_days: int = 365
    agent_min_report_seconds: float = 2   # an agent may not report more often than this (flood protection)
    dockerhub_username: str = "shambi21"  # where the published agent image lives (used by the Docker install command)
    smwatch_version: str = "latest"
    agent_image: str = ""                  # full override, e.g. registry.example.com/sm-watch-host-agent:1.2.3
    k8s_agent_image: str = ""              # image the Kubernetes manifest deploys; default <dockerhub_username>/sm-watch-k8s-agent:<smwatch_version>
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
    enrollment_default_minutes: int = 15       # install links: default lifetime ...
    enrollment_max_minutes: int = 1440         # ... and the longest an admin may choose
    alert_retention_days: int = 90             # defaults for the admin-editable retention (Settings > Data retention)
    incident_retention_days: int = 365
    link_retention_days: int = 7
    audit_min_retention_days: int = 30         # the audit log can never be kept shorter, or purged, below this
    schedule_max_attempts: int = 3             # scheduled messages: tries per run
    schedule_retry_minutes: int = 1
    schedule_missed_minutes: int = 15          # a reminder this late is skipped instead of sent
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


def resolved_agent_image(settings: "Settings") -> str:
    """The image the Docker install command runs. The agent code is baked into it: nothing is downloaded at start-up."""
    return settings.agent_image or f"{settings.dockerhub_username}/sm-watch-host-agent:{settings.smwatch_version}"


def resolved_k8s_agent_image(settings: "Settings") -> str:
    return settings.k8s_agent_image or f"{settings.dockerhub_username}/sm-watch-k8s-agent:{settings.smwatch_version}"


@lru_cache
def get_settings() -> Settings:
    return Settings()
