from datetime import datetime

from pydantic import field_validator, BaseModel, ConfigDict, Field, model_validator

from .config import get_settings


class LoginRequest(BaseModel):
    email: str
    password: str


class AlertPrefs(BaseModel):
    """Per-monitor alert settings. Empty / null = inherit (every alert type, every channel, REMINDER_MINUTES)."""
    alert_events: list[str] = Field(default_factory=list, max_length=4)           # down, alert, recovered, reminder
    alert_channels: list[int] = Field(default_factory=list, max_length=100)       # channel ids; empty = every channel
    alert_reminder_minutes: int | None = Field(default=None, ge=0, le=60 * 24 * 14)   # None = default; 0 = never repeat

    @field_validator("alert_events")
    @classmethod
    def known_events(cls, v: list[str]) -> list[str]:
        if any(e not in ("down", "alert", "recovered", "reminder") for e in v):
            raise ValueError("Unknown alert type")
        return list(dict.fromkeys(v))

    @field_validator("alert_channels")
    @classmethod
    def unique_channels(cls, v: list[int]) -> list[int]:
        return list(dict.fromkeys(v))


class ServerCreate(AlertPrefs):
    name: str = Field(min_length=1, max_length=100)
    host: str = Field(default="", max_length=255)
    monitor_mode: str = Field(default="agent", pattern="^(ping|agent|push)$")
    check_interval_seconds: int = Field(default_factory=lambda: get_settings().check_interval_seconds, ge=5, le=86400)
    endpoint: str = Field(default="", max_length=500)
    agent_token: str = ""
    enabled: bool = True
    cpu_threshold: float = Field(default_factory=lambda: get_settings().cpu_threshold, ge=1, le=100)
    memory_threshold: float = Field(default_factory=lambda: get_settings().memory_threshold, ge=1, le=100)
    disk_threshold: float = Field(default_factory=lambda: get_settings().disk_threshold, ge=1, le=100)
    load_threshold: float = Field(default_factory=lambda: get_settings().load_threshold, ge=0)
    swap_threshold: float = Field(default_factory=lambda: get_settings().swap_threshold, ge=1, le=100)
    public: bool = False
    process_names: str = ""
    process_threshold: float = Field(default_factory=lambda: get_settings().process_threshold, ge=1, le=1000)   # per-core %: 100 = one full core

    @model_validator(mode="after")
    def require_agent_fields_for_metrics(self):
        if self.monitor_mode in ("ping", "agent") and not self.host:
            raise ValueError("Host is required for ping and pull-agent monitors")
        if self.monitor_mode == "agent" and not self.endpoint:
            raise ValueError("Agent endpoint is required for host metrics mode")
        return self


class ServiceCreate(AlertPrefs):
    name: str = Field(min_length=1, max_length=100)
    url: str = Field(min_length=8, max_length=500)
    expected_status: int = Field(200, ge=100, le=599)
    interval_seconds: int = Field(60, ge=15, le=86400)
    enabled: bool = True
    public: bool = False
    server_id: int | None = None


class ChannelCreate(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    type: str = Field(default="telegram", pattern="^(telegram|webhook|slack|whatsapp)$")
    token: str = ""
    chat_id: str = ""
    endpoint: str = ""
    phone_number_id: str = ""
    template_name: str = ""
    template_language: str = "en_US"
    enabled: bool = True
    notify_kinds: list[str] = Field(default_factory=list, max_length=3)     # empty = every kind (server, service, cluster)
    notify_events: list[str] = Field(default_factory=list, max_length=4)    # empty = every event (down, alert, recovered, reminder)

    @field_validator("notify_kinds")
    @classmethod
    def known_kinds(cls, v: list[str]) -> list[str]:
        if any(k not in ("server", "service", "cluster") for k in v):
            raise ValueError("Unknown alert kind")
        return list(dict.fromkeys(v))

    @field_validator("notify_events")
    @classmethod
    def known_events(cls, v: list[str]) -> list[str]:
        if any(e not in ("down", "alert", "recovered", "reminder") for e in v):
            raise ValueError("Unknown alert event")
        return list(dict.fromkeys(v))

    @model_validator(mode="after")
    def validate_provider_fields(self):
        if self.type == "telegram" and (len(self.token) < 10 or not self.chat_id):
            raise ValueError("Telegram requires a bot token and chat/group ID")
        if self.type == "slack" and not self.endpoint.startswith("https://hooks.slack.com/"):
            raise ValueError("Slack requires an HTTPS Incoming Webhook URL")
        if self.type == "webhook" and not self.endpoint.startswith(("https://", "http://")):
            raise ValueError("Webhook requires an HTTP or HTTPS URL")
        if self.type == "whatsapp":
            if len(self.token) < 20:
                raise ValueError("WhatsApp requires a Meta Cloud API access token")
            if not self.phone_number_id or not self.chat_id or not self.template_name:
                raise ValueError("WhatsApp requires phone number ID, recipient number, and approved template name")
        return self


class ProcessSample(BaseModel):
    pid: int
    name: str = Field(max_length=100)
    user: str = Field(default="", max_length=100)
    cpu: float = Field(ge=0, le=100000)
    memory: float = Field(default=0, ge=0, le=100)

    @field_validator("name", "user")
    @classmethod
    def printable_only(cls, v: str) -> str:
        return _printable(v)


class IpEntry(BaseModel):
    iface: str = Field(default="", max_length=30)
    ip: str = Field(max_length=45)

    @field_validator("ip")
    @classmethod
    def valid_ip(cls, v: str) -> str:
        import ipaddress
        return str(ipaddress.ip_address(v))


class TrafficReport(BaseModel):
    """What the agent measured from the web server's access log during one reporting window (no individual requests)."""
    source: str = Field(default="", max_length=120)
    window_seconds: float = Field(ge=0, le=86400)
    requests: int = Field(ge=0, le=50_000_000)
    errors_5xx: int = Field(default=0, ge=0, le=50_000_000)
    errors_4xx: int = Field(default=0, ge=0, le=50_000_000)
    sum_ms: float = Field(default=0, ge=0, le=1e13)
    max_ms: float = Field(default=0, ge=0, le=1e9)
    upstream_sum_ms: float = Field(default=0, ge=0, le=1e13)
    upstream_count: int = Field(default=0, ge=0, le=50_000_000)
    bounds: list[float] = Field(min_length=1, max_length=40)
    counts: list[int] = Field(min_length=2, max_length=41)

    @model_validator(mode="after")
    def consistent(self):
        if len(self.counts) != len(self.bounds) + 1:
            raise ValueError("counts must have one more entry than bounds")
        if sorted(self.bounds) != self.bounds or any(b <= 0 for b in self.bounds) or any(c < 0 for c in self.counts):
            raise ValueError("bounds must be positive and ascending, counts non-negative")
        if sum(self.counts) != self.requests:
            raise ValueError("counts must add up to requests")
        return self


class AgentReport(BaseModel):
    cpu: float = Field(ge=0, le=100)
    memory: float = Field(ge=0, le=100)
    disk: float = Field(ge=0, le=100)
    load: float = Field(ge=0, le=100000)
    swap: float = Field(ge=0, le=100)
    uptime_seconds: int | None = Field(default=None, ge=0)
    cpu_count: int | None = Field(default=None, ge=1, le=4096)
    net_rx_bps: float | None = Field(default=None, ge=0)
    net_tx_bps: float | None = Field(default=None, ge=0)
    hostname: str = Field(default="", max_length=255)
    platform: str = Field(default="", max_length=255)
    os: str = Field(default="", max_length=100)
    kernel: str = Field(default="", max_length=60)
    arch: str = Field(default="", max_length=30)
    agent_version: str = Field(default="", max_length=32)
    processes: list[ProcessSample] = Field(default_factory=list, max_length=100)
    capabilities: list[str] = Field(default_factory=list, max_length=20)
    ips: list[IpEntry] = Field(default_factory=list, max_length=10)
    public_ip: str = Field(default="", max_length=45)
    install: str = Field(default="", max_length=20)
    machine: str = Field(default="", max_length=64, pattern="^[0-9a-f]*$")
    traffic: TrafficReport | None = None

    @field_validator("hostname", "platform", "os", "kernel", "arch", "install", "agent_version")
    @classmethod
    def printable_only(cls, v: str) -> str:
        return _printable(v)


def _printable(value: str) -> str:
    return " ".join("".join(ch if ch.isprintable() else " " for ch in value).split())


class TokenBody(BaseModel):
    token: str = Field(min_length=10, max_length=200)


class EnrollmentCreate(BaseModel):
    label: str = Field(default="", max_length=100)
    expires_minutes: int = Field(default_factory=lambda: get_settings().enrollment_default_minutes, ge=1)   # default and maximum come from .env (ENROLLMENT_*)
    max_uses: int | None = Field(default=None, ge=1, le=10000)       # None = unlimited


class EnrollRequest(BaseModel):
    hostname: str = Field(min_length=1, max_length=255)
    machine_id: str = Field(default="", max_length=128)
    platform: str = Field(default="", max_length=255)
    agent_version: str = Field(default="", max_length=32)


class ScheduledMessageIn(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    text: str = Field(min_length=1, max_length=4000)
    channel_ids: list[int] = Field(min_length=1, max_length=50)
    repeat: str = Field(default="daily", pattern="^(once|daily|weekly)$")
    time_of_day: str = Field(default="09:00", pattern=r"^([01]\d|2[0-3]):[0-5]\d$")
    days_of_week: list[int] = Field(default_factory=list, max_length=7)  # 1=Mon..7=Sun; empty = every day
    run_at: datetime | None = None                                       # required for repeat=once
    timezone: str = Field(default="UTC", max_length=64)
    enabled: bool = True


class LogQuery(BaseModel):
    """A log request the dashboard queues for an agent. Every field is re-validated by the agent before use."""
    source: str = Field(pattern="^(inventory|docker|journal|file)$")
    target: str = Field(default="", max_length=300, pattern=r"^[A-Za-z0-9@_.:/\-]*$")  # container name, systemd unit, or file path
    lines: int = Field(default=200, ge=1, le=2000)
    since_minutes: int = Field(default=0, ge=0, le=60 * 24 * 30)                     # 0 = no time limit
    grep: str = Field(default="", max_length=200)                                     # plain substring, case-insensitive (not a regex)
    priority: str = Field(default="", pattern="^(|emerg|alert|crit|err|warning|notice|info|debug)$")


class LogResult(BaseModel):
    ok: bool
    output: str = Field(default="", max_length=600_000)
    error: str = Field(default="", max_length=2000)
    truncated: bool = False


EMAIL_PATTERN = r"^[^@\s]{1,64}@[^@\s]+\.[^@\s]{2,}$"
ROLE_PATTERN = "^(admin|operator|viewer)$"


class UserCreate(BaseModel):
    email: str = Field(max_length=320, pattern=EMAIL_PATTERN)
    name: str = Field(default="", max_length=100)
    role: str = Field(default="viewer", pattern=ROLE_PATTERN)
    password: str = Field(min_length=12, max_length=200)   # temporary: the person must change it at first sign-in


class UserUpdate(BaseModel):
    name: str | None = Field(default=None, max_length=100)
    role: str | None = Field(default=None, pattern=ROLE_PATTERN)
    active: bool | None = None
    password: str | None = Field(default=None, min_length=12, max_length=200)   # admin reset: forces a change at next sign-in


class ProfileUpdate(BaseModel):
    name: str = Field(default="", max_length=100)
    email: str | None = Field(default=None, max_length=320, pattern=EMAIL_PATTERN)
    current_password: str = Field(default="", max_length=200)   # required only when the email changes


class PasswordChange(BaseModel):
    current_password: str
    new_password: str = Field(min_length=12, max_length=200)


class ChannelUpdate(BaseModel):
    """Edit payload: blank secret fields keep the stored value (secrets are never sent back to the browser)."""
    name: str = Field(min_length=1, max_length=100)
    type: str = Field(default="telegram", pattern="^(telegram|webhook|slack|whatsapp)$")
    token: str = ""
    chat_id: str = ""
    endpoint: str = ""
    phone_number_id: str = ""
    template_name: str = ""
    template_language: str = "en_US"
    enabled: bool = True
    notify_kinds: list[str] = Field(default_factory=list, max_length=3)     # empty = every kind (server, service, cluster)
    notify_events: list[str] = Field(default_factory=list, max_length=4)    # empty = every event (down, alert, recovered, reminder)

    @field_validator("notify_kinds")
    @classmethod
    def known_kinds(cls, v: list[str]) -> list[str]:
        if any(k not in ("server", "service", "cluster") for k in v):
            raise ValueError("Unknown alert kind")
        return list(dict.fromkeys(v))

    @field_validator("notify_events")
    @classmethod
    def known_events(cls, v: list[str]) -> list[str]:
        if any(e not in ("down", "alert", "recovered", "reminder") for e in v):
            raise ValueError("Unknown alert event")
        return list(dict.fromkeys(v))


class ORMModel(BaseModel):
    model_config = ConfigDict(from_attributes=True)
