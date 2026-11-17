"""DevOps: maintenance windows, heartbeat (cron job) monitors, SLOs and error budgets."""
from __future__ import annotations

import json
import time
from datetime import datetime, timedelta, timezone

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from .models import Heartbeat, HeartbeatPing, Maintenance, Slo
from .stats import aware, clear_cache, daily_uptime, live_totals, totals_by_target, ttl_cached


# ------------------------------------------------------------------------------------------------ maintenance
def active_windows(db: Session, now: datetime | None = None) -> list[Maintenance]:
    now = now or datetime.now(timezone.utc)
    return list(db.scalars(select(Maintenance).where(Maintenance.starts_at <= now, Maintenance.ends_at > now)).all())


def covers(window: Maintenance, target_type: str, target_id: int) -> bool:
    if not window.targets:
        return True
    return f"{target_type}:{target_id}" in json.loads(window.targets)


def in_maintenance(db: Session, target_type: str, target_id: int) -> str | None:
    """Title of an active maintenance window that holds back alerts for this monitor, or None. (Cached 10 s; cleared on every change.)"""
    windows = ttl_cached(("maintenance",), 10, lambda: [(w.title, w.targets) for w in active_windows(db) if w.suppress_alerts])
    for title, targets in windows:
        if not targets or f"{target_type}:{target_id}" in json.loads(targets):
            return title
    return None


def changed() -> None:
    clear_cache()


# ------------------------------------------------------------------------------------------------ heartbeats
PING_KINDS = ("success", "start", "fail")


def clean_message(text: str) -> str | None:
    text = "".join(ch if ch.isprintable() or ch in "\n\t" else " " for ch in (text or ""))[-4000:].strip()
    return text or None


def record_ping(db: Session, hb: Heartbeat, kind: str, message: str | None, ip: str | None) -> None:
    from .monitoring import format_alert, outage_seconds, queue_event, record_result, sync_incident
    now = datetime.now(timezone.utc)
    duration = None
    if kind == "start":
        hb.last_start_at = now
    else:
        started = aware(hb.last_start_at) if hb.last_start_at else None
        if started and now - started <= timedelta(seconds=hb.period_seconds + hb.grace_seconds):
            duration = round((now - started).total_seconds() * 1000, 1)
            hb.last_start_at = None
    db.add(HeartbeatPing(heartbeat_id=hb.id, ts=now, kind=kind, duration_ms=duration, message=clean_message(message or ""), ip=ip))
    if kind == "start":
        db.commit()
        return
    previous = hb.last_status
    hb.last_ping_at = now
    hb.last_duration_ms = duration if duration is not None else hb.last_duration_ms
    status = "up" if kind == "success" else "down"
    detail = None if status == "up" else ("The job reported a failure" + (f": {clean_message(message or '')[:300]}" if clean_message(message or "") else ""))
    hb.last_status, hb.last_error, hb.fail_count, hb.last_checked_at = status, detail, 0, now
    record_result(db, "heartbeat", hb.id, status, duration, None, detail)
    resolved = sync_incident(db, "heartbeat", hb, status, detail)
    if status == "down" and previous != "down":
        queue_event(db, "heartbeat", hb, "critical", format_alert("Job", "down", hb.name, detail, at=now), deliver=True, state="down")
    elif status == "up" and previous == "down":
        queue_event(db, "heartbeat", hb, "info", format_alert("Job", "recovered", hb.name, "The job ran successfully" + (f" in {duration / 1000:.1f} s" if duration else ""), at=now, duration=outage_seconds(resolved)), deliver=True, state="recovered")
    db.commit()


def human(seconds: float) -> str:
    seconds = int(seconds)
    if seconds < 120:
        return f"{seconds} s"
    if seconds < 7200:
        return f"{seconds // 60} min"
    if seconds < 172800:
        return f"{seconds // 3600} h"
    return f"{seconds // 86400} days"


def check_heartbeats(db: Session) -> None:
    """Once a minute: a heartbeat whose next ping is overdue (period + grace) is down. Also records an uptime sample."""
    from .monitoring import format_alert, is_due, queue_event, record_result, should_notify_again, reminder_minutes, sync_incident
    now = datetime.now(timezone.utc)
    for hb in db.scalars(select(Heartbeat).where(Heartbeat.enabled.is_(True))).all():
        if not is_due(hb.last_checked_at, 60):
            continue
        hb.last_checked_at = now
        if hb.last_ping_at is None and hb.last_status == "unknown" and now - aware(hb.created_at) < timedelta(seconds=hb.period_seconds + hb.grace_seconds):
            continue   # waiting for the first ping
        since = aware(hb.last_ping_at or hb.created_at)
        late = (now - since).total_seconds() > hb.period_seconds + hb.grace_seconds
        if hb.last_status == "down" and not late:
            record_result(db, "heartbeat", hb.id, "down", None, None, hb.last_error)   # an explicit failure stays down until the next success
            continue
        status = "down" if late else "up"
        detail = (f"No ping for {human((now - since).total_seconds())} (expected every {human(hb.period_seconds)}, {human(hb.grace_seconds)} grace)"
                  if hb.last_ping_at else f"No ping received yet (expected every {human(hb.period_seconds)})") if late else None
        record_result(db, "heartbeat", hb.id, status, None, None, detail)
        if status == "down":
            previous = hb.last_status
            hb.last_status, hb.last_error = "down", detail
            sync_incident(db, "heartbeat", hb, "down", detail)
            if previous != "down" or should_notify_again(db, "heartbeat", hb.id, reminder_minutes(hb)):
                state = "down" if previous != "down" else "still_down"
                queue_event(db, "heartbeat", hb, "critical", format_alert("Job", state, hb.name, detail, at=now), deliver=True, state=state)
    db.execute(delete(HeartbeatPing).where(HeartbeatPing.ts < now - timedelta(days=90)))
    db.commit()


# ------------------------------------------------------------------------------------------------ SLOs
FAST, SLOW = 14.4, 6.0     # burn-rate thresholds (Google SRE workbook: 2 % of a 30-day budget in 1 h, 5 % in 6 h)


def burn(db: Session, slo: Slo, minutes: int) -> float | None:
    now = datetime.now(timezone.utc)
    total, ok = live_totals(db, now - timedelta(minutes=minutes), now, slo.target_type, [slo.target_id]).get((slo.target_type, slo.target_id), (0, 0))
    if not total:
        return None
    allowed = 1 - slo.objective / 100
    return round(((total - ok) / total) / allowed, 2) if allowed > 0 else None


def evaluate(db: Session, slo: Slo, with_daily: bool = False) -> dict:
    total, ok = totals_by_target(db, slo.window_days * 24).get((slo.target_type, slo.target_id), (0, 0))
    allowed = 1 - slo.objective / 100
    sli = 100.0 * ok / total if total else None
    bad = (total - ok) / total if total else 0.0
    remaining = (1 - bad / allowed) if allowed > 0 and total else None
    window_minutes = slo.window_days * 1440
    rates = {f"burn_{label}": burn(db, slo, m) for label, m in (("5m", 5), ("30m", 30), ("1h", 60), ("6h", 360))}
    gt = lambda a, b: a is not None and a > b   # noqa: E731
    if remaining is not None and remaining <= 0:
        state = "exhausted"
    elif gt(rates["burn_1h"], FAST) and gt(rates["burn_5m"], FAST):
        state = "fast"
    elif gt(rates["burn_6h"], SLOW) and gt(rates["burn_30m"], SLOW):
        state = "slow"
    else:
        state = "ok"
    out = {"sli": round(sli, 4) if sli is not None else None, "checks": total, "failed": total - ok, "budget_remaining_pct": round(remaining * 100, 1) if remaining is not None else None,
           "allowed_downtime_minutes": round(window_minutes * allowed, 1), "used_downtime_minutes": round(window_minutes * allowed * (1 - remaining), 1) if remaining is not None else 0.0,
           "state": state, **rates}
    if out["budget_remaining_pct"] is not None and out["burn_6h"]:
        hours_left = (remaining * slo.window_days * 24) / out["burn_6h"] if out["burn_6h"] > 0 and remaining > 0 else None
        out["budget_gone_in_hours"] = round(hours_left, 1) if hours_left is not None and hours_left < slo.window_days * 24 else None
    if with_daily:
        out["daily"] = daily_uptime(db, slo.target_type, [slo.target_id], min(slo.window_days, 90)).get(slo.target_id, [])
    return out


RANK = {"ok": 0, "slow": 1, "fast": 2, "exhausted": 3}
_last_eval = {"at": 0.0}


def check_slos(db: Session, force: bool = False) -> None:
    """Every 5 minutes: alert when an SLO starts burning (slow -> fast -> exhausted), and once when it is back to normal."""
    if not force and time.monotonic() - _last_eval["at"] < 300:
        return
    _last_eval["at"] = time.monotonic()
    from .monitoring import format_alert, queue_event, target_of
    now = datetime.now(timezone.utc)
    for slo in db.scalars(select(Slo).where(Slo.burn_alerts.is_(True))).all():
        target = target_of(db, slo.target_type, slo.target_id)
        if target is None:
            continue
        r = evaluate(db, slo)
        previous = slo.alert_state or "ok"
        if RANK[r["state"]] > RANK[previous]:
            lines = [f"Objective {slo.objective}% over {slo.window_days} days; now {r['sli']}%" if r["sli"] is not None else f"Objective {slo.objective}%",
                     f"Error budget left: {r['budget_remaining_pct']}%" if r["budget_remaining_pct"] is not None else "",
                     f"Burn rate {r['burn_1h']}× (1 h), {r['burn_6h']}× (6 h)" if r["state"] != "exhausted" else "Every further failure breaks the objective.",
                     f"At this rate the budget is gone in {r['budget_gone_in_hours']} h" if r.get("budget_gone_in_hours") else ""]
            state = f"slo_{r['state']}"
            queue_event(db, slo.target_type, target, "critical" if r["state"] in ("fast", "exhausted") else "warning",
                        format_alert("SLO", state, f"{slo.name} ({target.name})", [x for x in lines if x], at=now), deliver=True, state=state)
            slo.alert_state, slo.alert_state_at = r["state"], now
        elif r["state"] == "ok" and previous != "ok":
            queue_event(db, slo.target_type, target, "info", format_alert("SLO", "recovered", f"{slo.name} ({target.name})", f"Burn rate is back to normal; {r['budget_remaining_pct']}% of the error budget left", at=now), deliver=True, state="recovered")
            slo.alert_state, slo.alert_state_at = "ok", now
        elif RANK[r["state"]] < RANK[previous] and r["state"] != "ok":
            slo.alert_state = r["state"]   # calmer, but not normal yet: remember it so a new escalation alerts again
    db.commit()
