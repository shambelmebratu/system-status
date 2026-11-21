"""Data retention and purging.

What the control plane stores is small and bounded, and an admin decides how long each kind is kept:

  checks      uptime history: one row per check (the biggest table over time)
  metrics     CPU/memory/disk/network samples of servers and Kubernetes clusters
  alerts      the alert messages that were sent (and their delivery state)
  incidents   RESOLVED incidents (open incidents are never purged)
  audit       the audit log (kept at least 30 days)
  links       expired / revoked agent install links

Fetched logs are never archived at all: they are deleted 15 minutes after they were read ("transient").
A purge runs automatically on the configured schedule and can be started by hand, for everything or for chosen kinds."""
import json
from datetime import datetime, time as dtime, timedelta, timezone

from sqlalchemy import delete, func, select, text
from sqlalchemy.orm import Session

from .config import get_settings
from .models import ClusterFinding, SecurityFinding, SshFailureSample, SshLoginEvent, TrafficSample, AlertEvent, AppSetting, AuditEvent, CheckResult, ClusterSample, Enrollment, Incident, K8sRequest, LogRequest, MetricSample

KEY = "retention"
CATEGORIES = {
    "checks": "Uptime history (checks)",
    "metrics": "Server, cluster & traffic metrics",
    "alerts": "Alert messages",
    "incidents": "Resolved incidents",
    "audit": "Audit log",
    "links": "Expired install links",
    "transient": "Fetched logs (temporary)",
}
def audit_min_days() -> int:
    return get_settings().audit_min_retention_days


FREQUENCIES = ("hourly", "daily", "weekly")


def defaults() -> dict:
    s = get_settings()
    return {
        "days": {"checks": s.check_retention_days, "metrics": s.metric_retention_days, "alerts": s.alert_retention_days, "incidents": s.incident_retention_days, "audit": max(audit_min_days(), s.audit_retention_days), "links": s.link_retention_days},
        "auto": True,
        "frequency": "hourly",
        "time": "03:00",        # UTC, for daily and weekly runs
        "weekday": 0,           # Monday = 0, for weekly runs
        "last_run_at": None,
        "last_result": None,
    }


def load(db: Session) -> dict:
    cfg = defaults()
    row = db.get(AppSetting, KEY)
    if row:
        try:
            saved = json.loads(row.value)
        except ValueError:
            saved = {}
        for key in ("auto", "frequency", "time", "weekday", "last_run_at", "last_result"):
            if key in saved:
                cfg[key] = saved[key]
        cfg["days"].update({k: v for k, v in (saved.get("days") or {}).items() if k in CATEGORIES and isinstance(v, int)})
    return cfg


def save(db: Session, cfg: dict, user: str | None) -> None:
    row = db.get(AppSetting, KEY)
    if row is None:
        row = AppSetting(key=KEY)
        db.add(row)
    row.value, row.updated_by = json.dumps(cfg), user


def _delete_older(db: Session, category: str, cutoff: datetime | None) -> int:
    """cutoff None = everything of that kind."""
    def older(column):
        return [] if cutoff is None else [column < cutoff]

    if category == "checks":
        from .stats import forget_days
        forget_days(db, before=cutoff.date() if cutoff else None)      # purged history: its daily uptime goes too
        stmt = delete(CheckResult).where(*older(CheckResult.checked_at))
    elif category == "metrics":
        n = db.execute(delete(MetricSample).where(*older(MetricSample.ts))).rowcount or 0
        n += db.execute(delete(TrafficSample).where(*older(TrafficSample.ts))).rowcount or 0
        n += db.execute(delete(SshFailureSample).where(*older(SshFailureSample.ts))).rowcount or 0
        return n + (db.execute(delete(ClusterSample).where(*older(ClusterSample.ts))).rowcount or 0)
    elif category == "alerts":
        stmt = delete(AlertEvent).where(*older(AlertEvent.created_at))
    elif category == "incidents":
        n = db.execute(delete(SecurityFinding).where(SecurityFinding.resolved_at.is_not(None), *older(SecurityFinding.resolved_at))).rowcount or 0
        n += db.execute(delete(ClusterFinding).where(ClusterFinding.resolved_at.is_not(None), *older(ClusterFinding.resolved_at))).rowcount or 0
        n += db.execute(delete(SshLoginEvent).where(*older(SshLoginEvent.ts))).rowcount or 0
        return n + (db.execute(delete(Incident).where(Incident.resolved_at.is_not(None), *older(Incident.resolved_at))).rowcount or 0)
    elif category == "audit":
        stmt = delete(AuditEvent).where(*older(AuditEvent.ts))
    elif category == "links":
        now = datetime.now(timezone.utc)
        inactive = (Enrollment.revoked.is_(True)) | (Enrollment.expires_at.is_not(None) & (Enrollment.expires_at < now))
        stmt = delete(Enrollment).where(inactive, *older(Enrollment.created_at))
    elif category == "transient":
        n = db.execute(delete(LogRequest).where(*older(LogRequest.created_at))).rowcount or 0
        return n + (db.execute(delete(K8sRequest).where(*older(K8sRequest.created_at))).rowcount or 0)
    else:
        raise ValueError(category)
    return db.execute(stmt).rowcount or 0


def purge(db: Session, categories: list[str], older_than_days: dict[str, int] | int | None) -> dict[str, int]:
    """Deletes rows. `older_than_days`: one number for all, a per-category map, or None/0 to delete everything of that kind."""
    now = datetime.now(timezone.utc)
    result = {}
    for category in categories:
        days = older_than_days.get(category) if isinstance(older_than_days, dict) else older_than_days
        cutoff = now - timedelta(days=days) if days else None
        if category == "audit" and (cutoff is None or days < audit_min_days()):
            raise ValueError(f"The audit log can only be purged for entries older than {audit_min_days()} days")
        result[category] = _delete_older(db, category, cutoff)
    return result


def due(cfg: dict, now: datetime | None = None) -> bool:
    if not cfg["auto"]:
        return False
    now = now or datetime.now(timezone.utc)
    last = datetime.fromisoformat(cfg["last_run_at"]) if cfg.get("last_run_at") else None
    if cfg["frequency"] == "hourly":
        return last is None or now - last >= timedelta(hours=1)
    hh, mm = (int(x) for x in cfg["time"].split(":"))
    slot = datetime.combine(now.date(), dtime(hh, mm), tzinfo=timezone.utc)
    if cfg["frequency"] == "weekly":
        slot -= timedelta(days=(now.weekday() - int(cfg["weekday"])) % 7)
    elif slot > now:
        slot -= timedelta(days=1)
    return slot <= now and (last is None or last < slot)


def summarize(result: dict[str, int]) -> str:
    parts = [f"{k}={v}" for k, v in result.items() if v]
    return "deleted " + ", ".join(parts) if parts else "nothing to delete"


def run_scheduled(db: Session) -> dict | None:
    """Worker hook: purges by the configured retention when the schedule says it is time. Returns what was deleted."""
    cfg = load(db)
    # Fetched logs are transient whatever the schedule says.
    db.execute(delete(LogRequest).where(LogRequest.created_at < datetime.now(timezone.utc) - timedelta(minutes=get_settings().log_result_ttl_minutes)))
    db.execute(delete(K8sRequest).where(K8sRequest.created_at < datetime.now(timezone.utc) - timedelta(minutes=get_settings().log_result_ttl_minutes)))
    if not due(cfg):
        db.commit()
        return None
    result = purge(db, [c for c in CATEGORIES if c != "transient"], cfg["days"])
    cfg["last_run_at"] = datetime.now(timezone.utc).isoformat()
    cfg["last_result"] = {"by": "schedule", "deleted": result, "at": cfg["last_run_at"]}
    save(db, cfg, "schedule")
    db.add(AuditEvent(actor="system", action="purge.scheduled", detail=summarize(result)))
    db.commit()
    return result


def stats(db: Session) -> dict:
    """Row counts (large PostgreSQL tables: the planner's estimate), oldest entry and (on PostgreSQL) disk size for each kind."""
    spec = {
        "checks": [(CheckResult, CheckResult.checked_at)],
        "metrics": [(MetricSample, MetricSample.ts), (TrafficSample, TrafficSample.ts), (ClusterSample, ClusterSample.ts), (SshFailureSample, SshFailureSample.ts)],
        "alerts": [(AlertEvent, AlertEvent.created_at)],
        "incidents": [(Incident, Incident.started_at), (SecurityFinding, SecurityFinding.first_seen), (ClusterFinding, ClusterFinding.first_seen), (SshLoginEvent, SshLoginEvent.ts)],
        "audit": [(AuditEvent, AuditEvent.ts)],
        "links": [(Enrollment, Enrollment.created_at)],
        "transient": [(LogRequest, LogRequest.created_at), (K8sRequest, K8sRequest.created_at)],
    }
    out = {}
    pg = db.bind.dialect.name == "postgresql"
    for key, parts in spec.items():
        rows, oldest, size = 0, None, 0
        for model, column in parts:
            estimate = None
            if pg:   # counting millions of rows takes seconds; PostgreSQL's own statistics are close enough for a size overview
                try:
                    estimate = db.scalar(text("select reltuples::bigint from pg_class where relname = :t"), {"t": model.__tablename__})
                except Exception:
                    db.rollback()
            rows += int(estimate) if estimate is not None and estimate > 100_000 else (db.scalar(select(func.count()).select_from(model)) or 0)
            first = db.scalar(select(func.min(column)))
            if first is not None and (oldest is None or first < oldest):
                oldest = first
            if pg:
                try:
                    size += db.scalar(text("select pg_total_relation_size(:t)"), {"t": model.__tablename__}) or 0
                except Exception:
                    db.rollback()
        out[key] = {"label": CATEGORIES[key], "rows": rows, "oldest": (oldest if oldest is None or oldest.tzinfo else oldest.replace(tzinfo=timezone.utc)).isoformat() if oldest else None, "bytes": size if pg else None}
    return out
