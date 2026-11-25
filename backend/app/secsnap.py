"""Security over time: an hourly snapshot of each server's security state, and the comparison of two periods (this hour with the
previous hour, today with yesterday, this week with last week, this month with last month).

Two kinds of numbers are compared:
* state at a moment (open threats, weak settings, missing updates, risky ports, unreviewed changes, verified or not): now, measured
  live, against the snapshot taken one period ago;
* events during a period (new threats, resolved, reviewed, failed and successful SSH logins, new login addresses, alerts, sign-ins
  and changes in SM-Watch): counted from the event tables for this period and the one before.
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

PERIODS = {"hour": timedelta(hours=1), "day": timedelta(days=1), "week": timedelta(days=7), "month": timedelta(days=30)}
SERIES = {"hour": 24, "day": 14, "week": 12, "month": 12}       # how many periods the trend chart shows
STATE_KEYS = ("critical", "high", "unreviewed", "hardening_failed", "updates", "risky_ports", "verified", "untrusted")
HOURLY_DAYS, DAILY_DAYS = 35, 400


def _aware(v):
    from .stats import aware
    return aware(v) if v else None


def measure(db: Session, servers: list, now: datetime) -> dict[int, dict]:
    """The security state of these servers right now (what a snapshot stores)."""
    from . import zerotrust
    from .models import SecurityFinding
    from .routes_security import latest_scans, metrics_of
    ids = [s.id for s in servers]
    findings = db.scalars(select(SecurityFinding).where(SecurityFinding.server_id.in_(ids or [0]), SecurityFinding.resolved_at.is_(None))).all()
    by: dict[int, list] = {}
    for f in findings:
        by.setdefault(f.server_id, []).append(f)
    ports = latest_scans(db, "ports", "server")
    queue_ids = {f.id for f in zerotrust.review_queue(db, ids)}
    out = {}
    for s in servers:
        mine = by.get(s.id, [])
        m = metrics_of(s)
        sec = m.get("security") or {}
        v = zerotrust.verify_server(db, s, m, mine, ports.get(s.id), now)
        out[s.id] = {
            "critical": sum(1 for f in mine if f.severity == "critical" and f.acknowledged_at is None),
            "high": sum(1 for f in mine if f.severity == "high" and f.acknowledged_at is None),
            "unreviewed": sum(1 for f in mine if f.id in queue_ids),
            "hardening_failed": sum(1 for c in sec.get("hardening") or [] if c.get("ok") is False),
            "updates": (m.get("updates") or {}).get("security") or 0,
            "risky_ports": v.get("risky_ports", 0),
            "verified": 1 if v["status"] == "verified" else 0,
            "untrusted": 1 if v["status"] in ("untrusted", "unverified") else 0,
        }
    return out


def take(db: Session, now: datetime | None = None, force: bool = False) -> bool:
    """Records a snapshot when the last one is about an hour old (or force). Also drops old ones. Returns True when one was taken."""
    from .models import SecuritySnapshot, Server
    now = now or datetime.now(timezone.utc)
    last = db.scalar(select(func.max(SecuritySnapshot.ts)))
    if not force and last is not None and now - _aware(last) < timedelta(minutes=55):
        return False
    servers = db.scalars(select(Server).where(Server.enabled.is_(True))).all()
    db.add(SecuritySnapshot(ts=now, data=json.dumps({"servers": {str(k): v for k, v in measure(db, servers, now).items()}})))
    prune(db, now)
    db.commit()
    return True


def prune(db: Session, now: datetime) -> None:
    from .models import SecuritySnapshot
    db.execute(delete(SecuritySnapshot).where(SecuritySnapshot.ts < now - timedelta(days=DAILY_DAYS)))
    old = db.execute(select(SecuritySnapshot.id, SecuritySnapshot.ts).where(SecuritySnapshot.ts < now - timedelta(days=HOURLY_DAYS)).order_by(SecuritySnapshot.ts)).all()
    keep, drop = set(), []
    for sid, ts in old:                              # beyond 35 days: only the first snapshot of each day stays
        day = _aware(ts).date()
        if day in keep:
            drop.append(sid)
        else:
            keep.add(day)
    if drop:
        db.execute(delete(SecuritySnapshot).where(SecuritySnapshot.id.in_(drop)))


def _snapshot_at(db: Session, t: datetime, tolerance: timedelta):
    """The snapshot closest to `t` (before it, else just after), within `tolerance`."""
    from .models import SecuritySnapshot
    before = db.scalar(select(SecuritySnapshot).where(SecuritySnapshot.ts <= t).order_by(SecuritySnapshot.ts.desc()).limit(1))
    after = db.scalar(select(SecuritySnapshot).where(SecuritySnapshot.ts > t).order_by(SecuritySnapshot.ts).limit(1))
    best = min((x for x in (before, after) if x is not None), key=lambda x: abs((_aware(x.ts) - t).total_seconds()), default=None)
    return best if best is not None and abs(_aware(best.ts) - t) <= tolerance else None


def _sum(per_server: dict, ids: set[int]) -> dict:
    total = {k: 0 for k in STATE_KEYS}
    for sid, row in per_server.items():
        if int(sid) in ids:
            for k in STATE_KEYS:
                total[k] += int(row.get(k) or 0)
    return total


def _events(db: Session, ids: list[int], start: datetime, end: datetime, smwatch: bool) -> dict:
    """What happened between start and end."""
    from . import secalerts
    from .models import AlertEvent, AuditEvent, SecurityFinding, SshFailureSample, SshLoginEvent
    sid = ids or [0]
    f = SecurityFinding

    def count(q):
        return int(db.scalar(q) or 0)

    out = {
        "new_critical": count(select(func.count()).select_from(f).where(f.server_id.in_(sid), f.first_seen >= start, f.first_seen < end, f.severity == "critical")),
        "new_high": count(select(func.count()).select_from(f).where(f.server_id.in_(sid), f.first_seen >= start, f.first_seen < end, f.severity == "high")),
        "new_other": count(select(func.count()).select_from(f).where(f.server_id.in_(sid), f.first_seen >= start, f.first_seen < end, f.severity.in_(("medium", "low")))),
        "resolved": count(select(func.count()).select_from(f).where(f.server_id.in_(sid), f.resolved_at >= start, f.resolved_at < end)),
        "reviewed": count(select(func.count()).select_from(f).where(f.server_id.in_(sid), f.acknowledged_at >= start, f.acknowledged_at < end)),
        "ssh_failed": count(select(func.coalesce(func.sum(SshFailureSample.total), 0)).where(SshFailureSample.server_id.in_(sid), SshFailureSample.ts >= start, SshFailureSample.ts < end)),
        "ssh_logins": count(select(func.count()).select_from(SshLoginEvent).where(SshLoginEvent.server_id.in_(sid), SshLoginEvent.ts >= start, SshLoginEvent.ts < end, SshLoginEvent.kind != "sftp")),
        "ssh_new_sources": count(select(func.count()).select_from(SshLoginEvent).where(SshLoginEvent.server_id.in_(sid), SshLoginEvent.ts >= start, SshLoginEvent.ts < end, SshLoginEvent.new_source.is_(True))),
        "alerts": count(select(func.count()).select_from(AlertEvent).where(AlertEvent.state.in_(secalerts.SECURITY_STATES), AlertEvent.created_at >= start, AlertEvent.created_at < end,
                                                                           (AlertEvent.target_type != "server") | AlertEvent.target_id.in_(sid)) if smwatch else
                        select(func.count()).select_from(AlertEvent).where(AlertEvent.state.in_(secalerts.SECURITY_STATES), AlertEvent.created_at >= start, AlertEvent.created_at < end,
                                                                           AlertEvent.target_type == "server", AlertEvent.target_id.in_(sid))),
    }
    if smwatch:
        a = AuditEvent
        out["signins"] = count(select(func.count()).select_from(a).where(a.action == "auth.login", a.success.is_(True), a.ts >= start, a.ts < end))
        out["signins_failed"] = count(select(func.count()).select_from(a).where(a.action == "auth.login", a.success.is_(False), a.ts >= start, a.ts < end))
        from .zerotrust import ADMIN_ACTIONS, GUARD_ACTIONS
        out["smwatch_changes"] = count(select(func.count()).select_from(a).where(a.action.in_(list(ADMIN_ACTIONS) + list(GUARD_ACTIONS)), a.success.is_(True), a.ts >= start, a.ts < end))
    return out


def _series(db: Session, ids: list[int], period: str, now: datetime) -> list[dict]:
    """One point per period for the trend chart: events counted in SQL per bucket, state from the snapshot nearest each bucket's end."""
    from . import secalerts
    from .models import AlertEvent, SecurityFinding, SecuritySnapshot, SshFailureSample, SshLoginEvent
    from .stats import bucket_of
    width = PERIODS[period].total_seconds()
    n = SERIES[period]
    since = now - PERIODS[period] * n
    sid = ids or [0]
    points = [{"t": (since + timedelta(seconds=width * (i + 1))).isoformat(), "new_threats": 0, "ssh_failed": 0, "ssh_logins": 0, "alerts": 0, "resolved": 0} for i in range(n)]

    def fill(key, column, q):
        b = bucket_of(db, column, since, width).label("b")
        for val, idx in db.execute(q.add_columns(b).group_by(b)).all():   # (the aggregate, then the bucket)
            i = int(idx)
            if 0 <= i < n:
                points[i][key] += int(val or 0)

    f = SecurityFinding
    fill("new_threats", f.first_seen, select(func.count()).select_from(f).where(f.server_id.in_(sid), f.first_seen >= since, f.severity.in_(("critical", "high"))))
    fill("resolved", f.resolved_at, select(func.count()).select_from(f).where(f.server_id.in_(sid), f.resolved_at >= since))
    fill("ssh_failed", SshFailureSample.ts, select(func.coalesce(func.sum(SshFailureSample.total), 0)).where(SshFailureSample.server_id.in_(sid), SshFailureSample.ts >= since))
    fill("ssh_logins", SshLoginEvent.ts, select(func.count()).select_from(SshLoginEvent).where(SshLoginEvent.server_id.in_(sid), SshLoginEvent.ts >= since, SshLoginEvent.kind != "sftp"))
    fill("alerts", AlertEvent.created_at, select(func.count()).select_from(AlertEvent).where(AlertEvent.state.in_(secalerts.SECURITY_STATES), AlertEvent.created_at >= since,
                                                                                           AlertEvent.target_type == "server", AlertEvent.target_id.in_(sid)))
    ids_set = set(ids)
    snaps = db.scalars(select(SecuritySnapshot).where(SecuritySnapshot.ts >= since - PERIODS[period]).order_by(SecuritySnapshot.ts)).all()
    for p in points:
        end = datetime.fromisoformat(p["t"])
        last = None
        for s in snaps:                                   # the last snapshot taken before this period ended
            if _aware(s.ts) <= end:
                last = s
            else:
                break
        if last is not None and end - _aware(last.ts) <= max(PERIODS[period], timedelta(hours=2)):
            p.update(_sum(json.loads(last.data).get("servers") or {}, ids_set))
    return points


def compare(db: Session, servers: list, period: str, smwatch: bool, now: datetime | None = None) -> dict:
    now = now or datetime.now(timezone.utc)
    delta = PERIODS[period]
    ids = [s.id for s in servers]
    current_state = measure(db, servers, now)
    snap = _snapshot_at(db, now - delta, max(delta / 4, timedelta(minutes=40)))
    then = json.loads(snap.data).get("servers") or {} if snap else None
    names = {s.id: s.name for s in servers}
    per_server = []
    for s in servers:
        nowv = current_state.get(s.id) or {}
        before = (then or {}).get(str(s.id))
        per_server.append({"id": s.id, "name": names[s.id], "now": nowv, "then": before})
    from .models import SecuritySnapshot
    oldest = db.scalar(select(func.min(SecuritySnapshot.ts)))
    return {
        "period": period, "generated_at": now.isoformat(),
        "current": {"start": (now - delta).isoformat(), "end": now.isoformat(), "events": _events(db, ids, now - delta, now, smwatch), "state": _sum({str(k): v for k, v in current_state.items()}, set(ids))},
        "previous": {"start": (now - 2 * delta).isoformat(), "end": (now - delta).isoformat(), "events": _events(db, ids, now - 2 * delta, now - delta, smwatch),
                     "state": _sum(then, set(ids)) if then is not None else None, "snapshot_at": _aware(snap.ts).isoformat() if snap else None},
        "servers": per_server,
        "series": _series(db, ids, period, now),
        "history_since": _aware(oldest).isoformat() if oldest else None,
    }
