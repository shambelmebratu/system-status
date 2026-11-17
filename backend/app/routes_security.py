"""Security dashboard: SSH attacks, pending updates, exposure scans, TLS audits, two-factor adoption."""
import json
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.concurrency import run_in_threadpool
from sqlalchemy import desc, func, select
from sqlalchemy.orm import Session

from . import secscan
from .audit import audit
from .database import SessionLocal, get_db
from .models import SecurityScan, Server, Service, User
from .security import can_see, ensure_access, require_operator
from .stats import aware

router = APIRouter(prefix="/api/security", tags=["security"])
_last_manual: dict[tuple, float] = {}


def latest_scans(db: Session, kind: str, target_type: str) -> dict[int, SecurityScan]:
    newest = select(SecurityScan.target_id, func.max(SecurityScan.id).label("id")).where(SecurityScan.kind == kind, SecurityScan.target_type == target_type).group_by(SecurityScan.target_id).subquery()
    return {s.target_id: s for s in db.scalars(select(SecurityScan).join(newest, SecurityScan.id == newest.c.id)).all()}


def scan_view(s: SecurityScan | None) -> dict | None:
    if s is None:
        return None
    return {"id": s.id, "kind": s.kind, "address": s.address, "started_at": aware(s.started_at).isoformat(), "grade": s.grade, "findings": s.findings, "error": s.error, "results": json.loads(s.results)}


@router.get("/overview")
def overview(user: dict = Depends(require_operator), db: Session = Depends(get_db)) -> dict:
    servers = [s for s in db.scalars(select(Server).order_by(Server.name)).all() if can_see(user, "server", s.id)]
    services = [s for s in db.scalars(select(Service).order_by(Service.name)).all() if can_see(user, "service", s.id) and s.url.lower().startswith("https://")]
    ssh = secscan.ssh_summary(db, 24, [s.id for s in servers])
    ports, tls = latest_scans(db, "ports", "server"), latest_scans(db, "tls", "service")
    server_rows = []
    for s in servers:
        metrics = json.loads(s.last_metrics or "{}") if s.last_metrics else {}
        address, reason = secscan.server_address(s)
        server_rows.append({"id": s.id, "name": s.name, "status": s.last_status, "updates": metrics.get("updates"), "agent_version": metrics.get("agent_version"),
                            "ssh_24h": ssh["per_server"].get(s.id, {"total": 0, "distinct_ips": 0, "top_ips": []}), "scan": scan_view(ports.get(s.id)),
                            "scan_address": address, "scan_unavailable": reason or None, "push": s.monitor_mode == "push"})
    out = {"servers": server_rows, "services": [{"id": s.id, "name": s.name, "url": s.url, "tls": scan_view(tls.get(s.id))} for s in services],
           "ssh": {k: ssh[k] for k in ("total", "top_ips", "top_users", "hourly")}}
    if user["role"] == "admin":
        from .mfa import policy
        users = db.scalars(select(User).where(User.active.is_(True))).all()
        out["two_factor"] = {"policy": policy(db), "enabled": sum(1 for u in users if u.totp_enabled), "total": len(users),
                             "without": [{"id": u.id, "email": u.email, "role": u.role} for u in users if not u.totp_enabled][:50]}
    return out


@router.get("/ssh")
def ssh(hours: int = Query(24, ge=1, le=168), user: dict = Depends(require_operator), db: Session = Depends(get_db)) -> dict:
    ids = [s.id for s in db.scalars(select(Server)).all() if can_see(user, "server", s.id)]
    data = secscan.ssh_summary(db, hours, ids)
    names = {s.id: s.name for s in db.scalars(select(Server).where(Server.id.in_(list(data["per_server"]) or [0]))).all()}
    data["per_server"] = [{"id": sid, "name": names.get(sid, f"server {sid}"), **v} for sid, v in sorted(data["per_server"].items(), key=lambda kv: -kv[1]["total"])]
    return data


@router.post("/scan/{target_type}/{target_id}")
async def scan_now(target_type: str, target_id: int, request: Request, user: dict = Depends(require_operator)) -> dict:
    if target_type not in ("server", "service"):
        raise HTTPException(404, "Unknown target")
    ensure_access(user, target_type, target_id)
    import time
    key = (target_type, target_id)
    if time.monotonic() - _last_manual.get(key, -1e9) < 120:
        raise HTTPException(429, "This target was scanned less than 2 minutes ago")
    _last_manual[key] = time.monotonic()
    with SessionLocal() as db:
        target = db.get(Server if target_type == "server" else Service, target_id)
        if target is None:
            raise HTTPException(404, "Not found")
        db.expunge(target)
    started = datetime.now(timezone.utc)
    result = await run_in_threadpool(secscan.run_server_scan if target_type == "server" else secscan.run_service_scan, target)
    with SessionLocal() as db:
        target = db.get(Server if target_type == "server" else Service, target_id)
        kind = "ports" if target_type == "server" else "tls"
        secscan.store(db, kind, target, target_type, result, started)
        audit(db, request, "security.scan", user=user, target=f"{target_type}:{target_id}", detail=f"{kind} scan of {target.name}: " + (result.get("error") or f"grade {result.get('grade')}, {result.get('findings', 0)} findings"))
        db.commit()
        return scan_view(db.scalar(select(SecurityScan).where(SecurityScan.kind == kind, SecurityScan.target_type == target_type, SecurityScan.target_id == target_id).order_by(desc(SecurityScan.id)).limit(1)))


@router.get("/scans/{target_type}/{target_id}")
def scan_history(target_type: str, target_id: int, limit: int = Query(10, ge=1, le=50), user: dict = Depends(require_operator), db: Session = Depends(get_db)) -> list[dict]:
    ensure_access(user, target_type, target_id)
    return [scan_view(s) for s in db.scalars(select(SecurityScan).where(SecurityScan.target_type == target_type, SecurityScan.target_id == target_id).order_by(desc(SecurityScan.id)).limit(limit)).all()]
