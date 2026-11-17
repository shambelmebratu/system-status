"""AI features: incident explanations, log analysis, and "ask your infrastructure".

The model provider is chosen by an admin (AI → Settings): a free keyless default, Anthropic, OpenAI, Gemini, Groq, OpenRouter, Mistral,
DeepSeek, a local Ollama, or any OpenAI-compatible API (see llm.py). Off until an admin turns it on. The data each feature sends is listed
in the Settings page and README; recognisable secrets are masked before text leaves SM-Watch. A provider's key comes from its environment
variable (e.g. GROQ_API_KEY) or is entered by an admin (stored encrypted, one per provider)."""
from __future__ import annotations

import json
import os
import re
from datetime import datetime, timedelta, timezone
from typing import Literal

from pydantic import BaseModel, Field, field_validator
from sqlalchemy import desc, select
from sqlalchemy.orm import Session

from . import llm
from .llm import AiError, RefusedError  # noqa: F401  (AiError is part of this module's interface)
from .models import AppSetting

KEY = "ai"
DEFAULT_MODEL = llm.PROVIDERS["anthropic"].default_model   # kept for callers that predate providers
DEFAULTS = {"enabled": False, "provider": llm.DEFAULT_PROVIDER, "model": "", "base_url": "", "auto_explain": False, "post_explanations": False,
            "allow_logs": True, "anomaly_alerts": True, "auto_per_hour": 6}


# ------------------------------------------------------------------------------------------------ settings
def _env_provider() -> str | None:
    """With nothing saved yet, a provider whose key is in the environment is picked over the free default."""
    return next((s.id for s in llm.PROVIDERS.values() if s.key_env and s.needs_key and os.getenv(s.key_env)), None)


def load(db: Session) -> dict:
    row = db.get(AppSetting, KEY)
    try:
        saved = json.loads(row.value) if row else {}
    except ValueError:
        saved = {}
    cfg = {**DEFAULTS, **{k: v for k, v in saved.items() if k in DEFAULTS or k in ("api_keys", "usage")}}
    if "provider" not in saved:   # settings from before providers existed were Anthropic-only
        legacy = bool(saved.get("api_key")) or str(saved.get("model", "")).startswith("claude-")
        cfg["provider"] = "anthropic" if legacy else (_env_provider() or llm.DEFAULT_PROVIDER)
    if saved.get("api_key") and not (cfg.get("api_keys") or {}).get("anthropic"):
        cfg["api_keys"] = {**(cfg.get("api_keys") or {}), "anthropic": saved["api_key"]}
    if cfg["provider"] not in llm.PROVIDERS:
        cfg["provider"] = llm.DEFAULT_PROVIDER
    return cfg


def save(db: Session, cfg: dict, user: str) -> None:
    row = db.get(AppSetting, KEY) or AppSetting(key=KEY)
    row.value, row.updated_by = json.dumps({k: v for k, v in cfg.items() if k != "api_key"}), user
    db.add(row)


def provider_spec(cfg: dict) -> llm.Spec:
    return llm.PROVIDERS[cfg["provider"]]


def key_source(cfg: dict) -> str | None:
    return llm.key_source(provider_spec(cfg), cfg)


def is_ready(cfg: dict) -> bool:
    s = provider_spec(cfg)
    return bool(cfg["enabled"] and (key_source(cfg) or not s.needs_key) and (cfg["model"] or s.default_model) and (s.kind == "anthropic" or s.url or cfg["base_url"]))


def public_settings(db: Session) -> dict:
    cfg = load(db)
    s = provider_spec(cfg)
    month = datetime.now(timezone.utc).strftime("%Y-%m")
    keys = cfg.get("api_keys") or {}
    return {**{k: cfg[k] for k in DEFAULTS}, "model": cfg["model"] or s.default_model, "key_source": key_source(cfg), "ready": is_ready(cfg),
            "providers": [{**p, "key_saved": bool(keys.get(p["id"])), "key_in_env": bool(p["key_env"] and os.getenv(p["key_env"]))} for p in llm.catalog()],
            "usage": (cfg.get("usage") or {}).get(month, {"requests": 0, "input_tokens": 0, "output_tokens": 0}), "month": month}


def _provider(cfg: dict) -> llm.Provider:
    from .crypto import decrypt
    return llm.build(cfg, decrypt)


def _ready(db: Session) -> dict:
    cfg = load(db)
    if not cfg["enabled"]:
        raise AiError("AI features are turned off. An admin can turn them on under AI → Settings.")
    return cfg


def _record_usage(db: Session, usage) -> None:
    cfg = load(db)
    month = datetime.now(timezone.utc).strftime("%Y-%m")
    all_usage = cfg.get("usage") or {}
    m = all_usage.setdefault(month, {"requests": 0, "input_tokens": 0, "output_tokens": 0})
    m["requests"] += 1
    m["input_tokens"] += int(getattr(usage, "input_tokens", 0) or 0)
    m["output_tokens"] += int(getattr(usage, "output_tokens", 0) or 0)
    cfg["usage"] = {k: all_usage[k] for k in sorted(all_usage)[-12:]}
    row = db.get(AppSetting, KEY) or AppSetting(key=KEY)
    row.value = json.dumps({k: v for k, v in cfg.items() if k != "api_key"})
    db.add(row)


def _parse(db: Session, system: str, content: str, schema: type[BaseModel], effort: str = "medium") -> tuple[BaseModel, str]:
    cfg = _ready(db)
    provider = _provider(cfg)
    try:
        parsed, model, usage = provider.structured(system, content, schema, effort)
    except RefusedError as error:
        _record_usage(db, error.usage)
        raise
    _record_usage(db, usage)
    return parsed, model


def test_connection(db: Session) -> dict:
    """A tiny request that proves the provider, key and model work (costs a few tokens)."""
    cfg = _ready(db)
    reply = _provider(cfg).complete("Reply with the single word: ready")
    _record_usage(db, reply.usage)
    db.commit()
    return {"ok": True, "provider": cfg["provider"], "model": reply.model, "reply": reply.text[:50]}


# ------------------------------------------------------------------------------------------------ secret masking
_SECRET = [
    (re.compile(r"(?i)\b([A-Z0-9_]*(?:PASSWORD|PASSWD|SECRET|TOKEN|API_?KEY|ACCESS_?KEY|PRIVATE_?KEY|CREDENTIALS?)[A-Z0-9_]*\s*[=:]\s*)(\"[^\"]*\"|'[^']*'|\S+)"), r"\1***"),
    (re.compile(r"(?i)(authorization\s*:\s*(?:bearer|basic|token)\s+)\S+"), r"\1***"),
    (re.compile(r"(?i)(\bbearer\s+)[A-Za-z0-9._~+/=-]{16,}"), r"\1***"),
    (re.compile(r"([A-Za-z][A-Za-z0-9+.-]*://[^/\s:@]+:)[^@\s]+@"), r"\1***@"),
    (re.compile(r"\b(ghp_|gho_|github_pat_|glpat-|xox[abprs]-|sk-ant-|sk-|sk_live_|AKIA|ASIA|AIza)[A-Za-z0-9_\-.]{8,}"), r"\1***"),
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----"), "*** private key ***"),
    (re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"), "*** JWT ***"),
]


def mask(text: str) -> str:
    for pattern, replacement in _SECRET:
        text = pattern.sub(replacement, text)
    return text


# ------------------------------------------------------------------------------------------------ incident explanations
class Cause(BaseModel):
    cause: str = Field(description="One likely cause, in one sentence")
    evidence: str = Field(description="What in the data points to it")
    confidence: Literal["low", "medium", "high"]

    @field_validator("confidence", mode="before")
    @classmethod
    def _lower(cls, v):   # smaller models often answer "High" or "Error"
        return v.strip().lower() if isinstance(v, str) else v


class IncidentAnalysis(BaseModel):
    summary: str = Field(description="What happened, in two or three plain sentences")
    impact: str = Field(description="Who or what is affected")
    likely_causes: list[Cause] = Field(description="Most likely first; at most 4")
    next_checks: list[str] = Field(description="Concrete things to check or run next, most useful first; include commands where helpful; at most 6")
    related: list[str] = Field(description="Other monitors or recent changes that seem connected; empty if none")


INCIDENT_SYSTEM = """You are an experienced site reliability engineer helping an on-call operator understand an incident detected by SM-Watch, a monitoring system.
You get the incident, the monitor's recent check history and metrics, other monitors that failed around the same time, recent configuration changes and maintenance windows.
Reason only from this data. Prefer causes the evidence supports over generic ones, say how sure you are, and say plainly when the data is not enough to tell.
Write for a busy operator: short, concrete, no filler. Times are UTC."""


def incident_context(db: Session, incident) -> str:
    from .models import AlertEvent, AuditEvent, CheckResult, Incident, Maintenance
    from .monitoring import target_of
    from .stats import aware, server_history
    started = aware(incident.started_at)
    target = target_of(db, incident.target_type, incident.target_id)
    lines = [f"# Incident\n{incident.title} ({incident.severity})\nmonitor: {incident.target_type} \"{incident.target_name}\"\nstarted: {started:%Y-%m-%d %H:%M:%S} UTC"
             f"{'' if not incident.resolved_at else f' resolved: {aware(incident.resolved_at):%Y-%m-%d %H:%M:%S} UTC'}\ndetail: {mask(incident.detail or '')}"]
    if target is not None:
        if incident.target_type == "service":
            host = re.sub(r"^https?://([^/]+).*$", r"\1", target.url)
            lines.append(f"# Service\nurl host: {host}; expects HTTP {target.expected_status}; timeout {target.timeout_seconds or 'default'} s; checked every {target.interval_seconds} s"
                         + (f"; content check: page must {'not ' if target.keyword_mode == 'absent' else ''}contain \"{target.keyword}\"" if target.keyword else ""))
        if incident.target_type == "server":
            metrics = json.loads(target.last_metrics or "{}") if target.last_metrics else {}
            keep = {k: metrics.get(k) for k in ("cpu", "cpu_peak", "memory", "disk", "load", "swap", "cpu_count", "os", "kernel", "uptime_seconds", "agent_version", "ssh_sessions") if metrics.get(k) is not None}
            procs = [f"{p.get('name')} cpu {p.get('cpu')}% mem {p.get('memory')}%" for p in (metrics.get("processes") or [])[:8]]
            lines.append(f"# Server\nmode: {target.monitor_mode}; thresholds cpu {target.cpu_threshold} mem {target.memory_threshold} disk {target.disk_threshold} load {target.load_threshold}\nlast metrics: {json.dumps(keep)}\ntop processes: {'; '.join(procs) or 'n/a'}")
            hist = server_history(db, target.id, 6)
            pts = hist["points"][-48:]
            if pts:
                lines.append("# Server metrics, last 6 h (time, cpu avg/max, memory, disk, load)\n" + "\n".join(f"{p['t'][11:16]} cpu {p.get('cpu')}/{p.get('cpu_max')} mem {p.get('memory')} disk {p.get('disk')} load {p.get('load')}" for p in pts[::2]))
    checks = db.execute(select(CheckResult.checked_at, CheckResult.status, CheckResult.latency_ms, CheckResult.http_status, CheckResult.error)
                        .where(CheckResult.target_type == incident.target_type, CheckResult.target_id == incident.target_id, CheckResult.checked_at >= started - timedelta(hours=1), CheckResult.checked_at <= started + timedelta(minutes=30))
                        .order_by(CheckResult.checked_at)).all()
    if checks:
        rows, last_line = [], None
        for t, status, latency, http, error in checks:
            line = f"{status}{f' HTTP {http}' if http else ''}{f' {round(latency)}ms' if latency else ''}{f' {mask(error)[:160]}' if error else ''}"
            if line != last_line or status == "down":
                rows.append(f"{aware(t):%H:%M:%S} {line}")
            last_line = line
        lines.append("# Checks from 1 h before to 30 min after the start (repeats collapsed)\n" + "\n".join(rows[-80:]))
    others = db.scalars(select(Incident).where(Incident.id != incident.id, Incident.started_at >= started - timedelta(minutes=30), Incident.started_at <= started + timedelta(minutes=30))).all()
    if others:
        lines.append("# Other incidents within 30 minutes\n" + "\n".join(f"{aware(o.started_at):%H:%M:%S} {o.target_type} \"{o.target_name}\": {o.title}; {mask(o.detail or '')[:160]}" for o in others[:15]))
    changes = db.scalars(select(AuditEvent).where(AuditEvent.ts >= started - timedelta(hours=24), AuditEvent.ts <= started + timedelta(minutes=5), AuditEvent.success.is_(True),
                                                 ~AuditEvent.action.in_(["auth.login", "auth.logout", "logs.read", "k8s.logs.read", "db.report", "ai.settings", "ai.explain", "ai.logs", "ai.ask"])).order_by(desc(AuditEvent.ts)).limit(20)).all()
    if changes:
        lines.append("# Configuration changes in SM-Watch during the 24 h before\n" + "\n".join(f"{aware(c.ts):%m-%d %H:%M} {c.action} {c.target} {mask(c.detail or '')[:120]}" for c in changes))
    windows = db.scalars(select(Maintenance).where(Maintenance.starts_at <= started + timedelta(hours=1), Maintenance.ends_at >= started - timedelta(hours=1))).all()
    if windows:
        lines.append("# Maintenance windows around then\n" + "\n".join(f"{w.title}: {aware(w.starts_at):%H:%M}-{aware(w.ends_at):%H:%M}" for w in windows))
    alerts = db.scalars(select(AlertEvent).where(AlertEvent.target_type == incident.target_type, AlertEvent.target_id == incident.target_id, AlertEvent.created_at >= started - timedelta(days=7)).order_by(desc(AlertEvent.created_at)).limit(10)).all()
    if alerts:
        lines.append("# This monitor's alerts in the last 7 days\n" + "\n".join(f"{aware(a.created_at):%m-%d %H:%M} {a.state or a.severity}" for a in alerts))
    return "\n\n".join(lines)[:60_000]


def explain_incident(db: Session, incident) -> dict:
    analysis, model = _parse(db, INCIDENT_SYSTEM, incident_context(db, incident), IncidentAnalysis)
    incident.ai_analysis, incident.ai_model, incident.ai_generated_at = analysis.model_dump_json(), (model or "")[:60], datetime.now(timezone.utc)
    db.commit()
    return analysis.model_dump()


def auto_explain(db: Session) -> None:
    """Worker hook: explain new incidents automatically (when enabled), at most `auto_per_hour` per hour."""
    from .models import Incident
    from .monitoring import format_alert, queue_event, target_of
    cfg = load(db)
    if not (cfg["auto_explain"] and is_ready(cfg)):
        return
    now = datetime.now(timezone.utc)
    done = db.scalar(select(func_count()).select_from(Incident).where(Incident.ai_generated_at >= now - timedelta(hours=1))) or 0
    budget = max(0, int(cfg["auto_per_hour"]) - done)
    if not provider_spec(cfg).tools:   # the free tier answers about once per 45 s: one per worker run keeps the worker moving
        budget = min(budget, 1)
    for incident in db.scalars(select(Incident).where(Incident.resolved_at.is_(None), Incident.ai_generated_at.is_(None), Incident.started_at <= now - timedelta(minutes=2),
                                                       Incident.started_at >= now - timedelta(hours=2)).order_by(Incident.started_at).limit(budget)).all():
        try:
            analysis = explain_incident(db, incident)
        except AiError as error:
            incident.ai_generated_at, incident.ai_analysis = now, json.dumps({"error": str(error)})
            db.commit()
            continue
        if cfg["post_explanations"]:
            target = target_of(db, incident.target_type, incident.target_id)
            if target is not None:
                causes = [f"{c['cause']} ({c['confidence']})" for c in analysis["likely_causes"][:3]]
                queue_event(db, incident.target_type, target, "info", format_alert("AI", "ai_note", incident.target_name, [analysis["summary"], *("Likely: " + c for c in causes), *analysis["next_checks"][:3]]), deliver=True, state="ai_note")
                db.commit()


def func_count():
    from sqlalchemy import func
    return func.count()


# ------------------------------------------------------------------------------------------------ logs
class LogGroup(BaseModel):
    title: str = Field(description="Short name of this kind of message, e.g. 'Database connection refused'")
    severity: Literal["error", "warning", "info"]

    @field_validator("severity", mode="before")
    @classmethod
    def _lower(cls, v):   # smaller models often answer "High" or "Error"
        return v.strip().lower() if isinstance(v, str) else v
    occurrences: int = Field(description="Roughly how many lines belong to it")
    example: str = Field(description="One representative line, shortened")
    meaning: str = Field(description="What it means, in plain words")
    fix: str = Field(description="What to do about it; empty when nothing is needed")


class LogAnalysis(BaseModel):
    summary: str = Field(description="The overall picture in two or three sentences")
    health: Literal["healthy", "degraded", "failing"]
    groups: list[LogGroup] = Field(description="The important kinds of messages, most serious first; at most 8")
    next_steps: list[str] = Field(description="What the operator should do next, most useful first; at most 5")

    @field_validator("health", mode="before")
    @classmethod
    def _lower(cls, v):
        return v.strip().lower() if isinstance(v, str) else v


LOG_SYSTEM = """You are an experienced site reliability engineer reading application and system logs for an operator.
Group similar lines, explain what matters in plain words, and suggest concrete fixes. Ignore routine noise unless it hides a problem.
Values replaced with *** were masked on purpose. Say so when the excerpt is too short to judge."""


def analyze_logs(db: Session, text: str, source: str) -> dict:
    cfg = _ready(db)
    if not cfg["allow_logs"]:
        raise AiError("An admin has not allowed sending logs to the AI (AI → Settings).")
    lines = text.splitlines()
    excerpt = "\n".join(lines[-3000:])[-150_000:]
    content = f"Log source: {source}\nLines in this excerpt: {min(len(lines), 3000)} (newest last)\n\n{mask(excerpt)}"
    analysis, model = _parse(db, LOG_SYSTEM, content, LogAnalysis)
    db.commit()
    return {**analysis.model_dump(), "model": model, "lines_sent": min(len(lines), 3000)}


# ------------------------------------------------------------------------------------------------ ask your infrastructure
ASK_SYSTEM = """You answer questions about the infrastructure monitored by SM-Watch for {company}: servers, services (websites and APIs), Kubernetes clusters, API tests, domains, cron jobs, incidents, alerts, SLOs and security findings.
Use the tools to look things up; never invent values. If a tool returns nothing, say the data is not available. Prefer short answers with the numbers that matter; use a small markdown table when comparing several items.
The person asking may see only some monitors: the tools return only those. Current time: {now} UTC."""


SNAPSHOT_SYSTEM = """You answer questions about the infrastructure monitored by SM-Watch for {company}: servers, services (websites and APIs), Kubernetes clusters, API tests, domains, cron jobs, incidents, alerts, SLOs and security findings.
Answer only from the data snapshot below; never invent values. If the snapshot does not contain what is asked, say so and suggest where in SM-Watch to look.
Prefer short answers with the numbers that matter; use a small markdown table when comparing several items. Current time: {now} UTC.

# Data snapshot (JSON, collected just now; the person asking may see only some monitors)
{snapshot}"""
# What a provider without multi-step tool use gets up front, in one request: (tool, arguments)
SNAPSHOT_TOOLS = (("list_monitors", {}), ("incidents", {"hours": 72}), ("recent_alerts", {"hours": 24}), ("slo_status", {}), ("anomalies", {"hours": 72}), ("security_summary", {}))
SNAPSHOT_CHARS = 40_000


def ask(db: Session, user: dict, messages: list[dict]) -> dict:
    from .config import get_settings
    from .security import can_see
    cfg = _ready(db)
    provider = _provider(cfg)
    used: list[dict] = []
    tools_impl = Toolbox(db, user, can_see)

    def track(name):
        fn = getattr(tools_impl, name)

        def inner(*a, **k):
            used.append({"tool": name, "input": k})
            try:
                return fn(*a, **k)
            except Exception as error:   # noqa: BLE001  (a tool failure is reported to the model, not raised)
                return json.dumps({"error": str(error)[:200]})
        inner.__name__, inner.__doc__, inner.__annotations__ = fn.__name__, fn.__doc__, dict(fn.__annotations__)
        inner.__signature__ = __import__("inspect").signature(fn)
        return inner

    now, company = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M"), get_settings().company_name
    if provider.spec.tools:
        reply = provider.chat(ASK_SYSTEM.format(company=company, now=now), messages, [track(name) for name in Toolbox.NAMES], max_iterations=10)
    else:
        parts, budget = [], SNAPSHOT_CHARS
        for name, args in SNAPSHOT_TOOLS:
            data = track(name)(**args)[: max(0, budget)]
            budget -= len(data)
            parts.append(f"## {name} {json.dumps(args) if args else ''}\n{data}")
        reply = provider.chat(SNAPSHOT_SYSTEM.format(company=company, now=now, snapshot="\n".join(parts)), messages[-6:], [])
    _record_usage(db, reply.usage)
    db.commit()
    if reply.refused:
        return {"answer": "The model declined to answer this question.", "tools": used, "model": reply.model}
    return {"answer": reply.text or "(no answer)", "tools": used, "model": reply.model}


class Toolbox:
    """Read-only tools for the assistant. Every one respects the asking person's access (limited users see only their monitors)."""
    NAMES = ("list_monitors", "uptime", "incidents", "server_metrics", "service_response_times", "recent_alerts", "slo_status", "security_summary", "anomalies")

    def __init__(self, db: Session, user: dict, can_see):
        self.db, self.user, self.can_see = db, user, can_see

    def _visible(self, kind: str, target_id: int) -> bool:
        if kind in ("server", "service", "cluster"):
            return self.can_see(self.user, kind, target_id)
        return self.user.get("scope") is None

    def _all(self) -> list[tuple[str, object]]:
        from .models import ApiTest, Cluster, DnsMonitor, Heartbeat, Server, Service
        out = []
        for kind, model in (("server", Server), ("service", Service), ("cluster", Cluster), ("test", ApiTest), ("dns", DnsMonitor), ("heartbeat", Heartbeat)):
            out += [(kind, m) for m in self.db.scalars(select(model)).all() if self._visible(kind, m.id)]
        return out

    def _find(self, name: str, kind: str | None = None):
        needle = name.strip().lower()
        candidates = [(k, m) for k, m in self._all() if (not kind or k == kind)]
        for k, m in candidates:
            if m.name.lower() == needle:
                return k, m
        for k, m in candidates:
            if needle in m.name.lower():
                return k, m
        raise ValueError(f"No monitor named '{name}'" + (f" of kind {kind}" if kind else ""))

    def list_monitors(self, kind: str = "", status: str = "") -> str:
        """List monitors with their current status.

        Args:
            kind: Optional filter: server, service, cluster, test, dns or heartbeat. Empty for all.
            status: Optional filter: up, down, alert or unknown. Empty for all.
        """
        rows = []
        for k, m in self._all():
            st = getattr(m, "last_status", None) or getattr(m, "status", "unknown")
            if (kind and k != kind) or (status and st != status):
                continue
            rows.append({"kind": k, "name": m.name, "status": st, "problem": (getattr(m, "last_error", None) or "")[:160] or None})
        return json.dumps(rows[:200])

    def uptime(self, monitor: str, hours: int = 24) -> str:
        """Availability of one monitor over the last N hours (1 to 2160).

        Args:
            monitor: The monitor's name (or part of it).
            hours: The window in hours.
        """
        from .stats import totals_by_target
        k, m = self._find(monitor)
        total, ok = totals_by_target(self.db, max(1, min(2160, int(hours)))).get((k, m.id), (0, 0))
        return json.dumps({"monitor": m.name, "kind": k, "hours": hours, "checks": total, "failed_checks": total - ok, "availability_pct": round(100 * ok / total, 3) if total else None})

    def incidents(self, hours: int = 24, open_only: bool = False, monitor: str = "") -> str:
        """Incidents (outages and alerts) that started in the last N hours.

        Args:
            hours: How far back to look (1 to 720).
            open_only: Only incidents that are still open.
            monitor: Optional monitor name to filter on.
        """
        from .models import Incident
        from .stats import aware
        since = datetime.now(timezone.utc) - timedelta(hours=max(1, min(720, int(hours))))
        q = select(Incident).where(Incident.started_at >= since).order_by(desc(Incident.started_at)).limit(200)
        if open_only:
            q = q.where(Incident.resolved_at.is_(None))
        target = self._find(monitor) if monitor else None
        rows = []
        for i in self.db.scalars(q).all():
            if not self._visible(i.target_type, i.target_id) or (target and (i.target_type, i.target_id) != (target[0], target[1].id)):
                continue
            end = aware(i.resolved_at) if i.resolved_at else datetime.now(timezone.utc)
            rows.append({"monitor": i.target_name, "kind": i.target_type, "title": i.title, "started": aware(i.started_at).strftime("%Y-%m-%d %H:%M"), "open": i.resolved_at is None,
                         "minutes": round((end - aware(i.started_at)).total_seconds() / 60), "detail": mask(i.detail or "")[:200]})
        return json.dumps(rows[:60])

    def server_metrics(self, server: str, hours: int = 6) -> str:
        """CPU, memory, disk, load and network of one server: latest values and averages / peaks over the last N hours (1 to 336).

        Args:
            server: The server's name (or part of it).
            hours: The window in hours.
        """
        from .stats import server_history
        _, m = self._find(server, "server")
        hist = server_history(self.db, m.id, max(1, min(336, int(hours))))
        pts = hist["points"]
        summary = {}
        for key in ("cpu", "memory", "disk", "load", "net_rx_bps", "net_tx_bps"):
            vals = [p[key] for p in pts if p.get(key) is not None]
            peaks = [p.get(f"{key}_max", p[key]) for p in pts if p.get(key) is not None]
            if vals:
                summary[key] = {"avg": round(sum(vals) / len(vals), 2), "max": round(max(peaks), 2), "latest": vals[-1]}
        latest = json.loads(m.last_metrics or "{}") if m.last_metrics else {}
        return json.dumps({"server": m.name, "status": m.last_status, "hours": hours, "samples": hist["samples"], "metrics": summary,
                           "top_processes": [{"name": p.get("name"), "cpu": p.get("cpu"), "memory": p.get("memory")} for p in (latest.get("processes") or [])[:5]],
                           "os": latest.get("os"), "disk_note": "disk is % used"})

    def service_response_times(self, service: str, hours: int = 24) -> str:
        """Response times (avg, p50, p95, p99, max in ms) and failed checks of one website or API over the last N hours (1 to 720).

        Args:
            service: The service's name (or part of it).
            hours: The window in hours.
        """
        from .stats import latency_stats, totals_by_target
        _, m = self._find(service, "service")
        since = datetime.now(timezone.utc) - timedelta(hours=max(1, min(720, int(hours))))
        stats = latency_stats(self.db, since, "service", m.id).get(("service", m.id)) or {}
        total, ok = totals_by_target(self.db, int(hours)).get(("service", m.id), (0, 0))
        return json.dumps({"service": m.name, "status": m.last_status, "hours": hours, **stats, "failed_checks": total - ok, "last_error": m.last_error})

    def recent_alerts(self, hours: int = 24, monitor: str = "") -> str:
        """Alerts SM-Watch generated in the last N hours (1 to 168), newest first.

        Args:
            hours: How far back to look.
            monitor: Optional monitor name to filter on.
        """
        from .models import AlertEvent
        from .stats import aware
        since = datetime.now(timezone.utc) - timedelta(hours=max(1, min(168, int(hours))))
        target = self._find(monitor) if monitor else None
        rows = []
        for a in self.db.scalars(select(AlertEvent).where(AlertEvent.created_at >= since).order_by(desc(AlertEvent.id)).limit(300)).all():
            if not self._visible(a.target_type, a.target_id) or (target and (a.target_type, a.target_id) != (target[0], target[1].id)):
                continue
            text = re.sub(r"<[^>]+>", "", a.message)
            rows.append({"at": aware(a.created_at).strftime("%m-%d %H:%M"), "kind": a.target_type, "state": a.state, "message": mask(text)[:240], "delivered": a.sent})
        return json.dumps(rows[:60])

    def slo_status(self) -> str:
        """Every SLO: objective, current availability, error budget left and burn rate."""
        from . import devops
        from .models import Slo
        rows = []
        for s in self.db.scalars(select(Slo)).all():
            if self._visible(s.target_type, s.target_id):
                r = devops.evaluate(self.db, s)
                rows.append({"slo": s.name, "objective": s.objective, "window_days": s.window_days, **{k: r[k] for k in ("sli", "budget_remaining_pct", "state", "burn_1h", "burn_6h")}})
        return json.dumps(rows)

    def security_summary(self) -> str:
        """Security picture: failed SSH logins (24 h), pending security updates, risky open ports and TLS grades."""
        from . import secscan
        from .models import Server
        from .routes_security import latest_scans
        servers = [s for s in self.db.scalars(select(Server)).all() if self._visible("server", s.id)]
        ssh = secscan.ssh_summary(self.db, 24, [s.id for s in servers])
        ports = latest_scans(self.db, "ports", "server")
        out = []
        for s in servers:
            u = (json.loads(s.last_metrics or "{}") if s.last_metrics else {}).get("updates") or {}
            scan = json.loads(ports[s.id].results) if s.id in ports else {}
            out.append({"server": s.name, "ssh_failures_24h": ssh["per_server"].get(s.id, {}).get("total", 0), "security_updates": u.get("security"), "reboot_required": u.get("reboot_required"),
                        "risky_open_ports": [f"{p['port']} {p['service']}" for p in scan.get("open", []) if p["risk"] in ("critical", "high")], "exposure_grade": ports[s.id].grade if s.id in ports else None})
        return json.dumps({"servers": out, "top_attackers": ssh["top_ips"][:5]})

    def anomalies(self, hours: int = 24) -> str:
        """Unusual metric behaviour detected in the last N hours (1 to 168): what, where, how far from normal, and whether it is still going on.

        Args:
            hours: How far back to look.
        """
        from .anomaly import describe
        from .models import Anomaly
        from .stats import aware
        since = datetime.now(timezone.utc) - timedelta(hours=max(1, min(168, int(hours))))
        rows = [{"monitor": a.target_name, "metric": a.metric, "description": describe(a), "started": aware(a.started_at).strftime("%m-%d %H:%M"), "ongoing": a.resolved_at is None}
                for a in self.db.scalars(select(Anomaly).where(Anomaly.started_at >= since).order_by(desc(Anomaly.started_at)).limit(100)).all() if self._visible(a.target_type, a.target_id)]
        return json.dumps(rows)
