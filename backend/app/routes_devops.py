"""DevOps: heartbeat monitors (with their public ping URLs), maintenance windows, SLOs."""
import json
import secrets
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field, model_validator
from sqlalchemy import desc, select
from sqlalchemy.orm import Session

from . import devops
from .audit import audit
from .database import get_db
from .models import Channel, Heartbeat, HeartbeatPing, Maintenance, Server, Service, Slo
from .monitoring import alert_columns, target_of
from .routes_agent import hash_token
from .schemas import AlertPrefs
from .security import agent_gate, client_ip, login_limiter, require_operator, require_unrestricted, require_user
from .stats import aware

router = APIRouter(prefix="/api", tags=["devops"])
iso = lambda d: aware(d).isoformat() if d else None   # noqa: E731


def _channels_ok(db: Session, ids: list[int]) -> None:
    if ids and set(db.scalars(select(Channel.id).where(Channel.id.in_(ids))).all()) != set(ids):
        raise HTTPException(422, "One of the chosen notification channels does not exist")


# ------------------------------------------------------------------------------------------------ heartbeats
class HeartbeatIn(AlertPrefs):
    name: str = Field(min_length=1, max_length=100)
    description: str = Field(default="", max_length=500)
    period_seconds: int = Field(default=86400, ge=60, le=31 * 86400)
    grace_seconds: int = Field(default=3600, ge=30, le=7 * 86400)
    enabled: bool = True


def serialize_hb(h: Heartbeat, request: Request | None = None) -> dict:
    from .routes_enroll import control_plane_url
    base = control_plane_url(request) if request is not None else ""
    now = datetime.now(timezone.utc)
    due = aware(h.last_ping_at) + timedelta(seconds=h.period_seconds) if h.last_ping_at else None
    return {"id": h.id, "name": h.name, "description": h.description, "period_seconds": h.period_seconds, "grace_seconds": h.grace_seconds, "enabled": h.enabled,
            "ping_url": f"{base}/api/ping/{h.token}", "last_ping_at": iso(h.last_ping_at), "next_due_at": iso(due), "overdue": bool(due and now > due + timedelta(seconds=h.grace_seconds)),
            "running_since": iso(h.last_start_at), "last_duration_ms": h.last_duration_ms, "last_status": h.last_status, "last_error": h.last_error,
            "alert_events": [v for v in (h.alert_events or "").split(",") if v], "alert_channels": [int(v) for v in (h.alert_channels or "").split(",") if v.isdigit()],
            "alert_reminder_minutes": h.alert_reminder_minutes}


def _store_hb(h: Heartbeat, payload: HeartbeatIn, db: Session) -> None:
    values = alert_columns(payload.model_dump(include={"alert_events", "alert_channels", "alert_reminder_minutes"}), "heartbeat")
    _channels_ok(db, payload.alert_channels)
    h.name, h.description, h.period_seconds, h.grace_seconds, h.enabled = payload.name.strip(), payload.description.strip(), payload.period_seconds, payload.grace_seconds, payload.enabled
    h.alert_events, h.alert_channels, h.alert_reminder_minutes = values["alert_events"], values["alert_channels"], values["alert_reminder_minutes"]


def _new_token(h: Heartbeat) -> None:
    token = "hb_" + secrets.token_urlsafe(18)
    h.token, h.token_hash = token, hash_token(token)


@router.get("/heartbeats")
def list_heartbeats(request: Request, _: dict = Depends(require_unrestricted), db: Session = Depends(get_db)) -> list[dict]:
    return [serialize_hb(h, request) for h in db.scalars(select(Heartbeat).order_by(Heartbeat.name)).all()]


@router.post("/heartbeats")
def create_heartbeat(payload: HeartbeatIn, request: Request, user: dict = Depends(require_unrestricted), db: Session = Depends(get_db)) -> dict:
    h = Heartbeat()
    _store_hb(h, payload, db)
    _new_token(h)
    db.add(h); db.flush()
    audit(db, request, "devops.heartbeat_create", user=user, target=f"heartbeat:{h.id}", detail=h.name)
    db.commit(); db.refresh(h)
    return serialize_hb(h, request)


@router.put("/heartbeats/{hid}")
def update_heartbeat(hid: int, payload: HeartbeatIn, request: Request, user: dict = Depends(require_unrestricted), db: Session = Depends(get_db)) -> dict:
    h = db.get(Heartbeat, hid)
    if not h:
        raise HTTPException(404, "Heartbeat not found")
    _store_hb(h, payload, db)
    audit(db, request, "devops.heartbeat_update", user=user, target=f"heartbeat:{h.id}", detail=h.name)
    db.commit(); db.refresh(h)
    return serialize_hb(h, request)


@router.post("/heartbeats/{hid}/new-url")
def new_url(hid: int, request: Request, user: dict = Depends(require_unrestricted), db: Session = Depends(get_db)) -> dict:
    """Replaces the ping URL (if it leaked): the old one stops working at once."""
    h = db.get(Heartbeat, hid)
    if not h:
        raise HTTPException(404, "Heartbeat not found")
    _new_token(h)
    audit(db, request, "devops.heartbeat_new_url", user=user, target=f"heartbeat:{h.id}", detail=h.name)
    db.commit(); db.refresh(h)
    return serialize_hb(h, request)


@router.delete("/heartbeats/{hid}")
def delete_heartbeat(hid: int, request: Request, user: dict = Depends(require_unrestricted), db: Session = Depends(get_db)) -> dict:
    h = db.get(Heartbeat, hid)
    if h:
        from .main import purge_history
        audit(db, request, "devops.heartbeat_delete", user=user, target=f"heartbeat:{h.id}", detail=h.name)
        purge_history(db, "heartbeat", h.id)
        db.delete(h); db.commit()
    return {"deleted": True}


@router.get("/heartbeats/{hid}/pings")
def pings(hid: int, limit: int = Query(100, ge=1, le=500), _: dict = Depends(require_unrestricted), db: Session = Depends(get_db)) -> list[dict]:
    return [{"ts": iso(p.ts), "kind": p.kind, "duration_ms": p.duration_ms, "message": p.message, "ip": p.ip}
            for p in db.scalars(select(HeartbeatPing).where(HeartbeatPing.heartbeat_id == hid).order_by(desc(HeartbeatPing.ts)).limit(limit)).all()]


async def _ping(token: str, kind: str, request: Request, db: Session) -> PlainTextResponse:
    gate = agent_gate(request, "ping")
    h = db.scalar(select(Heartbeat).where(Heartbeat.token_hash == hash_token(token))) if token.startswith("hb_") and len(token) < 80 else None
    if h is None:
        login_limiter.fail_unique(gate, token)
        raise HTTPException(404, "Unknown ping URL")
    if not h.enabled:
        return PlainTextResponse("paused\n")
    recent = db.scalar(select(HeartbeatPing.ts).where(HeartbeatPing.heartbeat_id == h.id, HeartbeatPing.kind == kind).order_by(desc(HeartbeatPing.ts)).limit(1))
    if recent and datetime.now(timezone.utc) - aware(recent) < timedelta(seconds=1):   # the same signal more than once a second: a loop, not a job
        raise HTTPException(429, "Too many pings", headers={"Retry-After": "1"})
    message = ""
    if request.method == "POST":
        message = (await request.body())[:10_000].decode("utf-8", "replace")
    devops.record_ping(db, h, kind, message, client_ip(request))
    return PlainTextResponse("ok\n")


for _kind, _suffix in (("success", ""), ("start", "/start"), ("fail", "/fail")):
    def _make(kind):
        async def endpoint(token: str, request: Request, db: Session = Depends(get_db)) -> PlainTextResponse:
            return await _ping(token, kind, request, db)
        endpoint.__name__ = f"ping_{kind}"
        return endpoint
    router.add_api_route(f"/ping/{{token}}{_suffix}", _make(_kind), methods=["GET", "POST", "HEAD"], response_class=PlainTextResponse)


# ------------------------------------------------------------------------------------------------ maintenance
class MaintenanceIn(BaseModel):
    title: str = Field(min_length=1, max_length=150)
    description: str = Field(default="", max_length=2000)
    starts_at: datetime
    ends_at: datetime
    targets: list[str] = Field(default_factory=list, max_length=500)       # "server:1"; empty = everything
    suppress_alerts: bool = True
    show_on_status: bool = True

    @model_validator(mode="after")
    def check(self):
        import re
        if self.starts_at.tzinfo is None or self.ends_at.tzinfo is None:
            raise ValueError("Times need a time zone")
        if self.ends_at <= self.starts_at:
            raise ValueError("The window must end after it starts")
        if self.ends_at - self.starts_at > timedelta(days=31):
            raise ValueError("A maintenance window can last at most 31 days")
        if any(not re.fullmatch(r"(server|service|cluster|test|dns|heartbeat):\d{1,9}", t) for t in self.targets):
            raise ValueError("Unknown monitor in the list")
        return self


def serialize_mw(w: Maintenance) -> dict:
    now = datetime.now(timezone.utc)
    state = "active" if aware(w.starts_at) <= now < aware(w.ends_at) else "upcoming" if aware(w.starts_at) > now else "done"
    return {"id": w.id, "title": w.title, "description": w.description, "starts_at": iso(w.starts_at), "ends_at": iso(w.ends_at), "targets": json.loads(w.targets) if w.targets else [],
            "suppress_alerts": w.suppress_alerts, "show_on_status": w.show_on_status, "state": state, "created_by": w.created_by}


@router.get("/maintenance")
def list_maintenance(_: dict = Depends(require_user), db: Session = Depends(get_db)) -> list[dict]:
    since = datetime.now(timezone.utc) - timedelta(days=30)
    return [serialize_mw(w) for w in db.scalars(select(Maintenance).where(Maintenance.ends_at >= since).order_by(Maintenance.starts_at)).all()]


@router.post("/maintenance")
def create_maintenance(payload: MaintenanceIn, request: Request, user: dict = Depends(require_unrestricted), db: Session = Depends(get_db)) -> dict:
    w = Maintenance(title=payload.title.strip(), description=payload.description.strip(), starts_at=payload.starts_at, ends_at=payload.ends_at,
                    targets=json.dumps(sorted(set(payload.targets))) if payload.targets else None, suppress_alerts=payload.suppress_alerts, show_on_status=payload.show_on_status, created_by=user["email"])
    db.add(w); db.flush()
    audit(db, request, "devops.maintenance_create", user=user, target=f"maintenance:{w.id}", detail=f"{w.title}: {payload.starts_at:%Y-%m-%d %H:%M} – {payload.ends_at:%Y-%m-%d %H:%M} UTC, {len(payload.targets) or 'all'} monitors")
    db.commit(); devops.changed()
    return serialize_mw(w)


@router.put("/maintenance/{wid}")
def update_maintenance(wid: int, payload: MaintenanceIn, request: Request, user: dict = Depends(require_unrestricted), db: Session = Depends(get_db)) -> dict:
    w = db.get(Maintenance, wid)
    if not w:
        raise HTTPException(404, "Maintenance window not found")
    w.title, w.description, w.starts_at, w.ends_at = payload.title.strip(), payload.description.strip(), payload.starts_at, payload.ends_at
    w.targets = json.dumps(sorted(set(payload.targets))) if payload.targets else None
    w.suppress_alerts, w.show_on_status = payload.suppress_alerts, payload.show_on_status
    audit(db, request, "devops.maintenance_update", user=user, target=f"maintenance:{w.id}", detail=w.title)
    db.commit(); devops.changed()
    return serialize_mw(w)


@router.post("/maintenance/{wid}/end")
def end_maintenance(wid: int, request: Request, user: dict = Depends(require_unrestricted), db: Session = Depends(get_db)) -> dict:
    w = db.get(Maintenance, wid)
    if not w:
        raise HTTPException(404, "Maintenance window not found")
    now = datetime.now(timezone.utc)
    if aware(w.ends_at) > now:
        w.ends_at = max(now, aware(w.starts_at) + timedelta(seconds=1))
    audit(db, request, "devops.maintenance_end", user=user, target=f"maintenance:{w.id}", detail=w.title)
    db.commit(); devops.changed()
    return serialize_mw(w)


@router.delete("/maintenance/{wid}")
def delete_maintenance(wid: int, request: Request, user: dict = Depends(require_unrestricted), db: Session = Depends(get_db)) -> dict:
    w = db.get(Maintenance, wid)
    if w:
        audit(db, request, "devops.maintenance_delete", user=user, target=f"maintenance:{w.id}", detail=w.title)
        db.delete(w); db.commit(); devops.changed()
    return {"deleted": True}


def public_maintenance(db: Session, public_keys: set[str]) -> list[dict]:
    """Active and upcoming (7 days) windows that touch a public monitor (or everything), for the status page. No internal detail."""
    now = datetime.now(timezone.utc)
    out = []
    for w in db.scalars(select(Maintenance).where(Maintenance.show_on_status.is_(True), Maintenance.ends_at > now, Maintenance.starts_at < now + timedelta(days=7)).order_by(Maintenance.starts_at)).all():
        targets = json.loads(w.targets) if w.targets else None
        if targets is None or set(targets) & public_keys:
            out.append({"title": w.title, "description": w.description, "starts_at": iso(w.starts_at), "ends_at": iso(w.ends_at), "active": aware(w.starts_at) <= now})
    return out


# ------------------------------------------------------------------------------------------------ SLOs
class SloIn(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    target: str = Field(pattern=r"^(server|service|test|dns|heartbeat|cluster):\d{1,9}$")
    objective: float = Field(ge=50, le=99.999)
    window_days: int = Field(default=30, ge=1, le=90)
    burn_alerts: bool = True


def serialize_slo(db: Session, s: Slo, daily: bool = False) -> dict:
    target = target_of(db, s.target_type, s.target_id)
    return {"id": s.id, "name": s.name, "target": f"{s.target_type}:{s.target_id}", "target_type": s.target_type, "target_id": s.target_id, "target_name": target.name if target else "(deleted)",
            "objective": s.objective, "window_days": s.window_days, "burn_alerts": s.burn_alerts, **devops.evaluate(db, s, with_daily=daily)}


@router.get("/slos")
def list_slos(user: dict = Depends(require_user), db: Session = Depends(get_db)) -> list[dict]:
    from .security import can_see
    return [serialize_slo(db, s, daily=True) for s in db.scalars(select(Slo).order_by(Slo.name)).all() if can_see(user, s.target_type, s.target_id) or s.target_type not in ("server", "service", "cluster") and user.get("scope") is None]


def _store_slo(s: Slo, payload: SloIn, db: Session) -> None:
    kind, tid = payload.target.split(":")
    if target_of(db, kind, int(tid)) is None:
        raise HTTPException(422, "That monitor does not exist")
    if (s.target_type, s.target_id, s.objective, s.window_days) != (kind, int(tid), payload.objective, payload.window_days):
        s.alert_state = None
    s.name, s.target_type, s.target_id, s.objective, s.window_days, s.burn_alerts = payload.name.strip(), kind, int(tid), payload.objective, payload.window_days, payload.burn_alerts


@router.post("/slos")
def create_slo(payload: SloIn, request: Request, user: dict = Depends(require_unrestricted), db: Session = Depends(get_db)) -> dict:
    s = Slo(created_by=user["email"])
    _store_slo(s, payload, db)
    db.add(s); db.flush()
    audit(db, request, "devops.slo_create", user=user, target=f"slo:{s.id}", detail=f"{s.name}: {s.objective}% over {s.window_days} days for {payload.target}")
    db.commit()
    return serialize_slo(db, s, daily=True)


@router.put("/slos/{sid}")
def update_slo(sid: int, payload: SloIn, request: Request, user: dict = Depends(require_unrestricted), db: Session = Depends(get_db)) -> dict:
    s = db.get(Slo, sid)
    if not s:
        raise HTTPException(404, "SLO not found")
    _store_slo(s, payload, db)
    audit(db, request, "devops.slo_update", user=user, target=f"slo:{s.id}", detail=f"{s.name}: {s.objective}% over {s.window_days} days")
    db.commit()
    return serialize_slo(db, s, daily=True)


@router.delete("/slos/{sid}")
def delete_slo(sid: int, request: Request, user: dict = Depends(require_unrestricted), db: Session = Depends(get_db)) -> dict:
    s = db.get(Slo, sid)
    if s:
        audit(db, request, "devops.slo_delete", user=user, target=f"slo:{s.id}", detail=s.name)
        db.delete(s); db.commit()
    return {"deleted": True}


@router.get("/monitors")
def monitors(user: dict = Depends(require_operator), db: Session = Depends(get_db)) -> list[dict]:
    """Every monitor of every kind (for pickers: maintenance windows, SLOs)."""
    from .models import ApiTest, Cluster, DnsMonitor
    from .security import can_see
    out = []
    for kind, model in (("server", Server), ("service", Service), ("cluster", Cluster), ("test", ApiTest), ("dns", DnsMonitor), ("heartbeat", Heartbeat)):
        for item in db.scalars(select(model).order_by(model.name)).all():
            if kind in ("server", "service", "cluster") and not can_see(user, kind, item.id) or kind not in ("server", "service", "cluster") and user.get("scope") is not None:
                continue
            out.append({"key": f"{kind}:{item.id}", "kind": kind, "id": item.id, "name": item.name, "status": getattr(item, "last_status", getattr(item, "status", "unknown"))})
    return out
