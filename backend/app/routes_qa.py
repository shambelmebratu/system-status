"""QA: API tests (multi-step, with run history) and DNS / domain monitors."""
import json
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.concurrency import run_in_threadpool
from pydantic import BaseModel, Field, ValidationError, field_validator
from sqlalchemy import case, desc, func, select
from sqlalchemy.orm import Session

from . import dnsmon, qa
from .audit import audit
from .database import get_db
from .models import ApiTest, Channel, DnsMonitor, TestRun
from .monitoring import alert_columns
from .schemas import AlertPrefs
from .security import require_operator, require_unrestricted
from .stats import aware, uptime_by_target

router = APIRouter(prefix="/api", tags=["qa"])
iso = lambda d: aware(d).isoformat() if d else None   # noqa: E731


def _channels_ok(db: Session, ids: list[int]) -> None:
    if ids and set(db.scalars(select(Channel.id).where(Channel.id.in_(ids))).all()) != set(ids):
        raise HTTPException(422, "One of the chosen notification channels does not exist")


# ------------------------------------------------------------------------------------------------ API tests
class TestIn(AlertPrefs):
    name: str = Field(min_length=1, max_length=100)
    description: str = Field(default="", max_length=500)
    enabled: bool = True
    interval_seconds: int = Field(default=300, ge=60, le=86400)
    definition: qa.TestDefinition


def serialize_test(t: ApiTest, uptime: dict | None = None, full: bool = False) -> dict:
    out = {"id": t.id, "name": t.name, "description": t.description, "enabled": t.enabled, "interval_seconds": t.interval_seconds, "last_status": t.last_status,
           "last_run_at": iso(t.last_run_at), "last_duration_ms": t.last_duration_ms, "last_error": t.last_error, "created_by": t.created_by,
           "alert_events": [v for v in (t.alert_events or "").split(",") if v], "alert_channels": [int(v) for v in (t.alert_channels or "").split(",") if v.isdigit()],
           "alert_reminder_minutes": t.alert_reminder_minutes}
    definition = json.loads(t.steps)
    out["step_count"] = len(definition.get("steps", []))
    if uptime is not None:
        out["pass_rate_7d"] = uptime.get(("test", t.id))
    if full:
        out["definition"] = definition
    return out


def _store(t: ApiTest, payload: TestIn, db: Session) -> None:
    values = alert_columns(payload.model_dump(include={"alert_events", "alert_channels", "alert_reminder_minutes"}), "test")
    _channels_ok(db, payload.alert_channels)
    t.name, t.description, t.enabled, t.interval_seconds = payload.name.strip(), payload.description.strip(), payload.enabled, payload.interval_seconds
    t.alert_events, t.alert_channels, t.alert_reminder_minutes = values["alert_events"], values["alert_channels"], values["alert_reminder_minutes"]
    t.steps = payload.definition.model_dump_json()


@router.get("/tests")
def list_tests(_: dict = Depends(require_unrestricted), db: Session = Depends(get_db)) -> list[dict]:
    uptime = uptime_by_target(db, 168)
    return [serialize_test(t, uptime) for t in db.scalars(select(ApiTest).order_by(ApiTest.name)).all()]


@router.get("/tests/{tid}")
def read_test(tid: int, _: dict = Depends(require_unrestricted), db: Session = Depends(get_db)) -> dict:
    t = db.get(ApiTest, tid)
    if not t:
        raise HTTPException(404, "Test not found")
    return serialize_test(t, uptime_by_target(db, 168), full=True)


@router.post("/tests")
def create_test(payload: TestIn, request: Request, user: dict = Depends(require_unrestricted), db: Session = Depends(get_db)) -> dict:
    t = ApiTest(created_by=user["email"])
    _store(t, payload, db)
    db.add(t); db.flush()
    audit(db, request, "qa.test_create", user=user, target=f"test:{t.id}", detail=f"{t.name}: {len(payload.definition.steps)} steps")
    db.commit(); db.refresh(t)
    return serialize_test(t, full=True)


@router.put("/tests/{tid}")
def update_test(tid: int, payload: TestIn, request: Request, user: dict = Depends(require_unrestricted), db: Session = Depends(get_db)) -> dict:
    t = db.get(ApiTest, tid)
    if not t:
        raise HTTPException(404, "Test not found")
    _store(t, payload, db)
    audit(db, request, "qa.test_update", user=user, target=f"test:{t.id}", detail=t.name)
    db.commit(); db.refresh(t)
    return serialize_test(t, full=True)


@router.delete("/tests/{tid}")
def delete_test(tid: int, request: Request, user: dict = Depends(require_unrestricted), db: Session = Depends(get_db)) -> dict:
    t = db.get(ApiTest, tid)
    if t:
        from .main import purge_history
        audit(db, request, "qa.test_delete", user=user, target=f"test:{t.id}", detail=t.name)
        purge_history(db, "test", t.id)
        db.delete(t); db.commit()
    return {"deleted": True}


@router.post("/tests/try")
async def try_test(definition: qa.TestDefinition, _: dict = Depends(require_unrestricted)) -> dict:
    """Runs a definition once without saving anything (the editor's Run button before the first save)."""
    return await run_in_threadpool(qa.run_test, definition.model_dump())


@router.post("/tests/{tid}/run")
async def run_now(tid: int, request: Request, user: dict = Depends(require_unrestricted)) -> dict:
    from .database import SessionLocal
    with SessionLocal() as db:
        t = db.get(ApiTest, tid)
        if not t:
            raise HTTPException(404, "Test not found")
        definition = json.loads(t.steps)
    result = await run_in_threadpool(qa.run_test, definition)
    with SessionLocal() as db:
        t = db.get(ApiTest, tid)
        qa.apply_test_result(db, t, result, trigger=f"manual: {user['email']}")
        run = db.scalar(select(TestRun).where(TestRun.test_id == tid).order_by(desc(TestRun.id)).limit(1))
        return {**result, "run_id": run.id if run else None}


def serialize_run(r: TestRun, full: bool = False) -> dict:
    out = {"id": r.id, "test_id": r.test_id, "started_at": iso(r.started_at), "duration_ms": r.duration_ms, "status": r.status, "trigger": r.trigger, "error": r.error}
    if full:
        out["steps"] = json.loads(r.results)
    return out


@router.get("/tests/{tid}/runs")
def runs(tid: int, limit: int = Query(50, ge=1, le=500), _: dict = Depends(require_unrestricted), db: Session = Depends(get_db)) -> dict:
    items = db.scalars(select(TestRun).where(TestRun.test_id == tid).order_by(desc(TestRun.started_at)).limit(limit)).all()
    since = datetime.now(timezone.utc) - timedelta(days=7)
    total, passed, avg = db.execute(select(func.count(), func.sum(case((TestRun.status == "passed", 1), else_=0)), func.avg(TestRun.duration_ms))
                                    .where(TestRun.test_id == tid, TestRun.started_at >= since)).one()
    return {"runs": [serialize_run(r) for r in items], "summary_7d": {"runs": int(total or 0), "passed": int(passed or 0), "avg_ms": round(float(avg), 1) if avg else None}}


@router.get("/test-runs/{rid}")
def run_detail(rid: int, _: dict = Depends(require_unrestricted), db: Session = Depends(get_db)) -> dict:
    r = db.get(TestRun, rid)
    if not r:
        raise HTTPException(404, "Run not found")
    t = db.get(ApiTest, r.test_id)
    return {**serialize_run(r, full=True), "test_name": t.name if t else ""}


# ------------------------------------------------------------------------------------------------ DNS / domains
class DnsIn(AlertPrefs):
    name: str = Field(min_length=1, max_length=100)
    domain: str = Field(min_length=3, max_length=253)
    record_types: list[str] = Field(default_factory=lambda: ["A", "AAAA", "MX", "NS", "TXT"], min_length=1, max_length=8)
    interval_seconds: int = Field(default=3600, ge=300, le=86400)
    enabled: bool = True
    check_expiry: bool = True
    expiry_alert_days: list[int] = Field(default_factory=list, max_length=8)

    @field_validator("domain")
    @classmethod
    def valid_domain(cls, v: str) -> str:
        v = dnsmon.normalise(v)
        if not dnsmon.DOMAIN_RE.match(v):
            raise ValueError("Enter a domain name such as example.com (no https:// or paths)")
        return v

    @field_validator("record_types")
    @classmethod
    def valid_types(cls, v: list[str]) -> list[str]:
        v = [t.upper() for t in v]
        if any(t not in dnsmon.RECORD_TYPES for t in v):
            raise ValueError(f"Record types: {', '.join(dnsmon.RECORD_TYPES)}")
        return list(dict.fromkeys(v))

    @field_validator("expiry_alert_days")
    @classmethod
    def valid_days(cls, v: list[int]) -> list[int]:
        if any(d < 1 or d > 365 for d in v):
            raise ValueError("Alert days must be between 1 and 365")
        return sorted(set(v), reverse=True)


def serialize_dns(m: DnsMonitor) -> dict:
    baseline, current = json.loads(m.baseline) if m.baseline else None, json.loads(m.current) if m.current else None
    return {"id": m.id, "name": m.name, "domain": m.domain, "record_types": [t for t in m.record_types.split(",") if t], "interval_seconds": m.interval_seconds,
            "enabled": m.enabled, "check_expiry": m.check_expiry, "expiry_alert_days": [int(d) for d in (m.expiry_alert_days or "").split(",") if d.isdigit()],
            "expiry_alert_days_effective": dnsmon.thresholds(m), "domain_expires_at": iso(m.domain_expires_at), "registrar": m.registrar, "expiry_error": m.expiry_error,
            "baseline": baseline, "current": current, "changes": dnsmon.diff(baseline, current) if baseline is not None and current is not None else [],
            "changed_at": iso(m.changed_at), "last_status": m.last_status, "last_checked_at": iso(m.last_checked_at), "last_error": m.last_error,
            "alert_events": [v for v in (m.alert_events or "").split(",") if v], "alert_channels": [int(v) for v in (m.alert_channels or "").split(",") if v.isdigit()],
            "alert_reminder_minutes": m.alert_reminder_minutes}


def _store_dns(m: DnsMonitor, payload: DnsIn, db: Session) -> None:
    values = alert_columns(payload.model_dump(include={"alert_events", "alert_channels", "alert_reminder_minutes"}), "dns")
    _channels_ok(db, payload.alert_channels)
    if m.domain and m.domain != payload.domain or (m.record_types and m.record_types != ",".join(payload.record_types)):
        m.baseline = m.current = None   # another domain or other record types: learn the records again
        m.domain_expires_at = m.registrar = m.expiry_checked_at = m.expiry_alerted = None
    m.name, m.domain, m.record_types, m.interval_seconds, m.enabled = payload.name.strip(), payload.domain, ",".join(payload.record_types), payload.interval_seconds, payload.enabled
    m.check_expiry, m.expiry_alert_days = payload.check_expiry, ",".join(str(d) for d in payload.expiry_alert_days) or None
    m.alert_events, m.alert_channels, m.alert_reminder_minutes = values["alert_events"], values["alert_channels"], values["alert_reminder_minutes"]


@router.get("/dns")
def list_dns(_: dict = Depends(require_unrestricted), db: Session = Depends(get_db)) -> list[dict]:
    return [serialize_dns(m) for m in db.scalars(select(DnsMonitor).order_by(DnsMonitor.name)).all()]


async def _check_now(mid: int, force: bool = True) -> dict:
    from .database import SessionLocal
    with SessionLocal() as db:
        m = db.get(DnsMonitor, mid)
        if not m:
            raise HTTPException(404, "DNS monitor not found")
    result = await run_in_threadpool(dnsmon.check, m, force)
    with SessionLocal() as db:
        m = db.get(DnsMonitor, mid)
        dnsmon.apply_result(db, m, result)
        db.refresh(m)
        return serialize_dns(m)


@router.post("/dns")
async def create_dns(payload: DnsIn, request: Request, user: dict = Depends(require_unrestricted), db: Session = Depends(get_db)) -> dict:
    m = DnsMonitor()
    _store_dns(m, payload, db)
    db.add(m); db.flush()
    audit(db, request, "qa.dns_create", user=user, target=f"dns:{m.id}", detail=f"{m.name}: {m.domain}")
    db.commit()
    return await _check_now(m.id)   # the first check learns the current records as the accepted set


@router.put("/dns/{mid}")
def update_dns(mid: int, payload: DnsIn, request: Request, user: dict = Depends(require_unrestricted), db: Session = Depends(get_db)) -> dict:
    m = db.get(DnsMonitor, mid)
    if not m:
        raise HTTPException(404, "DNS monitor not found")
    _store_dns(m, payload, db)
    audit(db, request, "qa.dns_update", user=user, target=f"dns:{m.id}", detail=f"{m.name}: {m.domain}")
    db.commit(); db.refresh(m)
    return serialize_dns(m)


@router.delete("/dns/{mid}")
def delete_dns(mid: int, request: Request, user: dict = Depends(require_unrestricted), db: Session = Depends(get_db)) -> dict:
    m = db.get(DnsMonitor, mid)
    if m:
        from .main import purge_history
        audit(db, request, "qa.dns_delete", user=user, target=f"dns:{m.id}", detail=m.domain)
        purge_history(db, "dns", m.id)
        db.delete(m); db.commit()
    return {"deleted": True}


@router.post("/dns/{mid}/check")
async def check_dns(mid: int, _: dict = Depends(require_operator)) -> dict:
    return await _check_now(mid)


@router.post("/dns/{mid}/accept")
def accept_dns(mid: int, request: Request, user: dict = Depends(require_unrestricted), db: Session = Depends(get_db)) -> dict:
    """The current records are intended: they become the accepted set and the alert clears at the next check (now)."""
    from .monitoring import format_alert, queue_event, sync_incident
    m = db.get(DnsMonitor, mid)
    if not m:
        raise HTTPException(404, "DNS monitor not found")
    if m.current:
        changes = dnsmon.diff(json.loads(m.baseline or "{}"), json.loads(m.current))
        m.baseline = m.current
        if m.last_status == "alert":
            m.last_status, m.last_error, m.fail_count = "up", None, 0
            sync_incident(db, "dns", m, "up", None)
            queue_event(db, "dns", m, "info", format_alert("DNS", "recovered", m.name, f"New records accepted by {user['email']}"), deliver=True, state="recovered")
        audit(db, request, "qa.dns_accept", user=user, target=f"dns:{m.id}", detail=f"{m.domain}: " + ("; ".join(changes) or "no changes")[:800])
    db.commit(); db.refresh(m)
    return serialize_dns(m)
