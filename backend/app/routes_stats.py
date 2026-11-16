"""Authenticated analytics endpoints and the unauthenticated public status page."""
import json
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import desc, select
from sqlalchemy.orm import Session

from .config import get_settings
from .database import get_db
from .models import Cluster, Incident, Server, Service
from .security import can_see, ensure_access, require_user
from .stats import AVAILABILITY_RANGES, aware, availability, daily_uptime, server_history, service_history, ttl_cached, uptime_by_target

router = APIRouter(prefix="/api", tags=["stats"])
RANGES = {"1h": 1, "6h": 6, "24h": 24, "7d": 168, "30d": 720}


def hours_for(range_: str, retention_days: int) -> int:
    return min(RANGES[range_], retention_days * 24)


def public_ranges() -> list[int]:
    """The time frames the public status page offers (PUBLIC_STATUS_RANGES, days). Bad values fall back to 7, 30 and 90."""
    try:
        values = sorted({int(x) for x in get_settings().public_status_ranges.split(",") if x.strip()})
        if values and all(1 <= v <= 365 for v in values):
            return values[:8]
    except ValueError:
        pass
    return [7, 30, 90]


def serialize_incident(item: Incident) -> dict:
    started, resolved = aware(item.started_at), aware(item.resolved_at) if item.resolved_at else None
    return {
        "id": item.id, "target_type": item.target_type, "target_id": item.target_id, "target_name": item.target_name,
        "severity": item.severity, "title": item.title, "detail": item.detail,
        "started_at": started.isoformat(), "resolved_at": resolved.isoformat() if resolved else None,
        "duration_seconds": int(((resolved or datetime.now(timezone.utc)) - started).total_seconds()),
    }


@router.get("/servers/{item_id}/history")
def server_history_endpoint(item_id: int, range: str = Query("24h", pattern="^(1h|6h|24h|7d|30d)$"), user: dict = Depends(require_user), db: Session = Depends(get_db)) -> dict:
    ensure_access(user, "server", item_id)
    if not db.get(Server, item_id):
        raise HTTPException(404, "Server not found")
    result = server_history(db, item_id, hours_for(range, get_settings().metric_retention_days))
    result["daily"] = daily_uptime(db, "server", [item_id], 90)[item_id]
    return result


@router.get("/services/{item_id}/history")
def service_history_endpoint(item_id: int, range: str = Query("24h", pattern="^(1h|6h|24h|7d|30d)$"), user: dict = Depends(require_user), db: Session = Depends(get_db)) -> dict:
    ensure_access(user, "service", item_id)
    if not db.get(Service, item_id):
        raise HTTPException(404, "Service monitor not found")
    result = service_history(db, item_id, hours_for(range, get_settings().check_retention_days))
    result["daily"] = daily_uptime(db, "service", [item_id], 90)[item_id]
    return result


@router.get("/{kind}/{item_id}/availability")
def availability_endpoint(kind: str, item_id: int, range: str = Query("1d", pattern="^(1m|5m|15m|30m|1h|4h|12h|1d|1mo|3mo|1y)$"), user: dict = Depends(require_user), db: Session = Depends(get_db)) -> dict:
    """Status-bar data for one server or service over a selectable window (1 minute to 1 year)."""
    model = {"servers": Server, "services": Service, "clusters": Cluster}.get(kind)
    if model is None:
        raise HTTPException(404, "Unknown target type")
    ensure_access(user, kind[:-1], item_id)
    if not db.get(model, item_id):
        raise HTTPException(404, "Target not found")
    return availability(db, kind[:-1], item_id, range)


@router.get("/uptime")
def uptime_summary(user: dict = Depends(require_user), db: Session = Depends(get_db)) -> dict:
    """Availability per target for 24h / 7d / 30d, keyed 'server:ID' and 'service:ID'."""
    windows = {"24h": 24, "7d": 168, "30d": 720}
    result: dict[str, dict[str, float | None]] = {}
    for label, hours in windows.items():
        for (kind, target_id), pct in uptime_by_target(db, hours).items():
            if not can_see(user, kind, target_id):
                continue
            result.setdefault(f"{kind}:{target_id}", {})[label] = pct
    return result


@router.get("/incidents")
def incidents(state: str = Query("all", pattern="^(all|open|resolved)$"), limit: int = Query(100, ge=1, le=500), target_type: str = Query("", pattern="^(|server|service|cluster)$"),
              target_id: int | None = None, user: dict = Depends(require_user), db: Session = Depends(get_db)) -> list[dict]:
    restricted = user.get("scope") is not None
    query = select(Incident).order_by(desc(Incident.started_at)).limit(5000 if restricted else limit)   # limited access: filter first, then cut
    if target_type and target_id is not None:   # one monitor's incidents (uses the per-target index)
        query = query.where(Incident.target_type == target_type, Incident.target_id == target_id)
    if state == "open":
        query = query.where(Incident.resolved_at.is_(None))
    elif state == "resolved":
        query = query.where(Incident.resolved_at.is_not(None))
    items = [item for item in db.scalars(query).all() if can_see(user, item.target_type, item.target_id)]
    return [serialize_incident(item) for item in items[:limit]]


@router.get("/public/status")
def public_status(days: int | None = Query(None, ge=1, le=365), db: Session = Depends(get_db)) -> dict:
    """Unauthenticated status page data. Only items flagged `public` appear; URLs/hosts are never exposed."""
    settings = get_settings()
    if not settings.public_status_enabled:
        raise HTTPException(404, "Status page is disabled")
    services = db.scalars(select(Service).where(Service.public.is_(True), Service.enabled.is_(True)).order_by(Service.name)).all()
    servers = db.scalars(select(Server).where(Server.public.is_(True), Server.enabled.is_(True)).order_by(Server.name)).all()
    ranges = public_ranges()
    days = days if days is not None else (settings.public_status_default_days if settings.public_status_default_days in ranges else ranges[0])
    if days not in ranges:
        raise HTTPException(422, f"Choose one of: {', '.join(str(r) for r in ranges)} days")
    return ttl_cached(("public-status", days, tuple(i.id for i in services), tuple(i.id for i in servers)), 30, lambda: _public_page(db, settings, services, servers, days, ranges))


def _public_page(db: Session, settings, services, servers, days: int, ranges: list[int]) -> dict:
    """Unauthenticated and cached for 30 s: a busy (or abusive) visitor cannot make the database recount history."""
    uptime = uptime_by_target(db, 24 * days)
    since = datetime.now(timezone.utc) - timedelta(days=days)
    daily = {"service": daily_uptime(db, "service", [i.id for i in services], days), "server": daily_uptime(db, "server", [i.id for i in servers], days)}

    def row(kind: str, item, latency) -> dict:
        return {"id": f"{kind}-{item.id}", "kind": kind, "name": item.name, "status": item.last_status, "latency_ms": latency, "uptime": uptime.get((kind, item.id)), "daily": daily[kind][item.id]}

    items = [row("service", i, i.last_latency_ms) for i in services] + [row("server", i, (json.loads(i.last_metrics).get("latency_ms") if i.last_metrics else None)) for i in servers]
    items.sort(key=lambda r: r["name"].lower())
    incidents = []
    for kind, ids in (("service", [i.id for i in services]), ("server", [i.id for i in servers])):
        if ids:
            incidents += [serialize_incident(i) for i in db.scalars(select(Incident).where(Incident.target_type == kind, Incident.target_id.in_(ids), Incident.started_at >= since)).all()]
    incidents.sort(key=lambda i: i["started_at"], reverse=True)
    for item in incidents:  # internal error text stays private
        item["detail"] = None
    statuses = [r["status"] for r in items]
    overall = "down" if "down" in statuses else ("alert" if "alert" in statuses else ("unknown" if not statuses or all(s == "unknown" for s in statuses) else "up"))
    return {"company_name": settings.company_name, "overall": overall, "days": days, "ranges": ranges, "services": items, "incidents": incidents[:50], "updated_at": datetime.now(timezone.utc).isoformat()}
