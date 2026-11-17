"""Security dashboard: SSH attacks and logins, threats (malware, persistence, new keys), pending updates, hardening, exposure scans,
TLS audits, two-factor adoption, and report data. Every list can be narrowed to one server (?server=<id, host name or IP>) and every
item says which server it belongs to (name, host name, public and private addresses)."""
import json
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.concurrency import run_in_threadpool
from pydantic import BaseModel, Field
from sqlalchemy import desc, func, select
from sqlalchemy.orm import Session

from . import secscan
from .audit import audit
from .database import SessionLocal, get_db
from .models import SecurityFinding, SecurityScan, Server, Service, SshLoginEvent, User
from .security import can_see, ensure_access, require_admin, require_operator
from .stats import aware
from .threats import SEVERITY_ORDER, finding_view

router = APIRouter(prefix="/api/security", tags=["security"])
_last_manual: dict[tuple, float] = {}


def latest_scans(db: Session, kind: str, target_type: str) -> dict[int, SecurityScan]:
    newest = select(SecurityScan.target_id, func.max(SecurityScan.id).label("id")).where(SecurityScan.kind == kind, SecurityScan.target_type == target_type).group_by(SecurityScan.target_id).subquery()
    return {s.target_id: s for s in db.scalars(select(SecurityScan).join(newest, SecurityScan.id == newest.c.id)).all()}


def scan_view(s: SecurityScan | None) -> dict | None:
    if s is None:
        return None
    return {"id": s.id, "kind": s.kind, "address": s.address, "started_at": aware(s.started_at).isoformat(), "grade": s.grade, "findings": s.findings, "error": s.error, "results": json.loads(s.results)}


def metrics_of(s: Server) -> dict:
    try:
        return json.loads(s.last_metrics or "{}") or {}
    except ValueError:
        return {}


def server_info(s: Server) -> dict:
    """Who a server is: what people search by (id, name, host name, addresses)."""
    from .monitoring import server_addresses
    m = metrics_of(s)
    addr = server_addresses(s)
    return {"id": s.id, "name": s.name, "hostname": m.get("hostname") or None, "public_ip": addr.get("public_ip"), "private_ips": addr.get("private_ips") or [],
            "host": s.host or None, "os": m.get("os") or None}


def matches(info: dict, needle: str) -> bool:
    n = needle.strip().lower()
    if not n:
        return True
    if n.lstrip("#").isdigit() and int(n.lstrip("#")) == info["id"]:
        return True
    hay = [info["name"], info.get("hostname"), info.get("public_ip"), info.get("host"), *info.get("private_ips", [])]
    return any(h and n in str(h).lower() for h in hay)


def visible_servers(db: Session, user: dict, server: str | None) -> list[Server]:
    """The servers this person may see, narrowed by ?server= (an id, a name, a host name or an address; exact id wins)."""
    servers = [s for s in db.scalars(select(Server).order_by(Server.name)).all() if can_see(user, "server", s.id)]
    if not server:
        return servers
    exact = [s for s in servers if server.strip().lstrip("#").isdigit() and s.id == int(server.strip().lstrip("#"))]
    return exact or [s for s in servers if matches(server_info(s), server)]


def open_counts(db: Session, ids: list[int]) -> dict[int, dict]:
    out: dict[int, dict] = {}
    rows = db.execute(select(SecurityFinding.server_id, SecurityFinding.severity, SecurityFinding.acknowledged_at.is_(None), func.count())
                      .where(SecurityFinding.server_id.in_(ids or [0]), SecurityFinding.resolved_at.is_(None))
                      .group_by(SecurityFinding.server_id, SecurityFinding.severity, SecurityFinding.acknowledged_at.is_(None))).all()
    for sid, severity, unacked, n in rows:
        entry = out.setdefault(sid, {"critical": 0, "high": 0, "medium": 0, "low": 0, "acknowledged": 0})
        if unacked:
            entry[severity] = entry.get(severity, 0) + n
        else:
            entry["acknowledged"] += n
    return out


@router.get("/overview")
def overview(server: str | None = Query(None, max_length=200), user: dict = Depends(require_operator), db: Session = Depends(get_db)) -> dict:
    servers = visible_servers(db, user, server)
    ids = [s.id for s in servers]
    services = [s for s in db.scalars(select(Service).order_by(Service.name)).all() if can_see(user, "service", s.id) and s.url.lower().startswith("https://")]
    if server:   # narrowed to servers: keep the https services that run on them (same host or address)
        hosts = {h for s in servers for h in (server_info(s).get("hostname"), server_info(s).get("public_ip"), s.host) if h}
        services = [s for s in services if s.server_id in ids or any(h and h in s.url for h in hosts)]
    ssh = secscan.ssh_summary(db, 24, ids)
    ports, tls = latest_scans(db, "ports", "server"), latest_scans(db, "tls", "service")
    counts = open_counts(db, ids)
    server_rows = []
    for s in servers:
        m = metrics_of(s)
        address, reason = secscan.server_address(s)
        sec = m.get("security") or {}
        checks = sec.get("hardening") or []
        server_rows.append({**server_info(s), "status": s.last_status, "updates": m.get("updates"), "agent_version": m.get("agent_version"),
                            "ssh_24h": ssh["per_server"].get(s.id, {"total": 0, "distinct_ips": 0, "top_ips": []}), "scan": scan_view(ports.get(s.id)),
                            "scan_address": address, "scan_unavailable": reason or None, "push": s.monitor_mode == "push",
                            "threats": counts.get(s.id, {"critical": 0, "high": 0, "medium": 0, "low": 0, "acknowledged": 0}),
                            "threat_scan_at": sec.get("checked_at"), "threat_scan": bool(sec),
                            "hardening": {"passed": sum(1 for c in checks if c.get("ok") is True), "failed": sum(1 for c in checks if c.get("ok") is False), "total": len(checks)}})
    out = {"servers": server_rows, "services": [{"id": s.id, "name": s.name, "url": s.url, "server_id": s.server_id, "tls": scan_view(tls.get(s.id))} for s in services],
           "ssh": {k: ssh[k] for k in ("total", "top_ips", "top_users", "hourly")}, "filter": server or None}
    if user["role"] == "admin" and not server:
        from .mfa import policy
        users = db.scalars(select(User).where(User.active.is_(True))).all()
        out["two_factor"] = {"policy": policy(db), "enabled": sum(1 for u in users if u.totp_enabled), "total": len(users),
                             "without": [{"id": u.id, "email": u.email, "role": u.role} for u in users if not u.totp_enabled][:50]}
    return out


@router.get("/servers")
def servers_list(user: dict = Depends(require_operator), db: Session = Depends(get_db)) -> list[dict]:
    """The server picker: every visible server with what people search by."""
    return [server_info(s) for s in visible_servers(db, user, None)]


@router.get("/ssh")
def ssh(hours: int = Query(24, ge=1, le=168), server: str | None = Query(None, max_length=200), user: dict = Depends(require_operator), db: Session = Depends(get_db)) -> dict:
    servers = visible_servers(db, user, server)
    infos = {s.id: server_info(s) for s in servers}
    data = secscan.ssh_summary(db, hours, list(infos))
    data["per_server"] = [{**infos.get(sid, {"id": sid, "name": f"server {sid}"}), **v} for sid, v in sorted(data["per_server"].items(), key=lambda kv: -kv[1]["total"])]
    # which servers each attacking address went after (by name, not just a count)
    since = datetime.now(timezone.utc) - timedelta(hours=hours)
    from .models import SshFailureSample
    targets: dict[str, dict[int, int]] = {}
    for sid, raw in db.execute(select(SshFailureSample.server_id, SshFailureSample.ips).where(SshFailureSample.ts >= since, SshFailureSample.server_id.in_(list(infos) or [0]))).all():
        for ip, n in json.loads(raw or "{}").items():
            targets.setdefault(ip, {})[sid] = targets.setdefault(ip, {}).get(sid, 0) + n
    for row in data["top_ips"]:
        row["targets"] = [{"id": sid, "name": infos[sid]["name"], "attempts": n} for sid, n in sorted(targets.get(row["ip"], {}).items(), key=lambda kv: -kv[1]) if sid in infos]
    logins = db.scalars(select(SshLoginEvent).where(SshLoginEvent.ts >= since, SshLoginEvent.server_id.in_(list(infos) or [0])).order_by(desc(SshLoginEvent.ts)).limit(300)).all()
    data["logins"] = [{"id": e.id, "server": {k: infos[e.server_id][k] for k in ("id", "name", "hostname", "public_ip")}, "ts": aware(e.ts).isoformat(), "ip": e.ip, "user": e.user,
                       "method": e.method, "failures_before": e.failures_before, "new_source": e.new_source,
                       "verdict": "breach" if e.failures_before >= _breach_threshold() else "new" if e.new_source else "ok"} for e in logins]
    data["logins_supported"] = any(version_at_least(metrics_of(s).get("agent_version"), (2, 15)) for s in servers)
    return data


def version_at_least(version: str | None, wanted: tuple[int, int]) -> bool:
    try:
        return tuple(int(x) for x in str(version or "0").split(".")[:2]) >= wanted
    except ValueError:
        return False


def _breach_threshold() -> int:
    from .config import get_settings
    return get_settings().ssh_success_after_failures


@router.get("/findings")
def findings(server: str | None = Query(None, max_length=200), status: str = Query("open", pattern="^(open|attention|acknowledged|resolved|all)$"),
             severity: str | None = Query(None, pattern="^(critical|high|medium|low)$"), limit: int = Query(300, ge=1, le=1000),
             user: dict = Depends(require_operator), db: Session = Depends(get_db)) -> list[dict]:
    servers = visible_servers(db, user, server)
    infos = {s.id: server_info(s) for s in servers}
    q = select(SecurityFinding).where(SecurityFinding.server_id.in_(list(infos) or [0]))
    if status in ("open", "attention", "acknowledged"):
        q = q.where(SecurityFinding.resolved_at.is_(None))
    if status == "attention":
        q = q.where(SecurityFinding.acknowledged_at.is_(None))
    elif status == "acknowledged":
        q = q.where(SecurityFinding.acknowledged_at.is_not(None))
    elif status == "resolved":
        q = q.where(SecurityFinding.resolved_at.is_not(None))
    if severity:
        q = q.where(SecurityFinding.severity == severity)
    rows = db.scalars(q.order_by(desc(SecurityFinding.last_seen)).limit(limit)).all()
    out = [finding_view(f, infos[f.server_id]) for f in rows]
    out.sort(key=lambda f: (f["resolved_at"] is not None, f["acknowledged_at"] is not None, SEVERITY_ORDER.get(f["severity"], 9), f["last_seen"]))
    return out


class AckIn(BaseModel):
    note: str = Field(default="", max_length=500)


@router.post("/findings/{finding_id}/acknowledge")
def acknowledge(finding_id: int, payload: AckIn, request: Request, user: dict = Depends(require_operator), db: Session = Depends(get_db)) -> dict:
    f = db.get(SecurityFinding, finding_id)
    if not f:
        raise HTTPException(404, "Finding not found")
    ensure_access(user, "server", f.server_id)
    now = datetime.now(timezone.utc)
    f.acknowledged_by, f.acknowledged_at, f.note = user["email"], now, payload.note.strip()
    if f.source == "smwatch":           # an event (login, new key): acknowledging closes it. Agent findings close when the agent stops seeing them.
        f.resolved_at = f.resolved_at or now
    server = db.get(Server, f.server_id)
    audit(db, request, "security.acknowledge", user=user, target=f"server:{f.server_id}", detail=f"{server.name if server else f.server_id}: {f.title}" + (f" ({payload.note.strip()[:200]})" if payload.note.strip() else ""))
    db.commit()
    return finding_view(f, server_info(server) if server else None)


@router.get("/hardening")
def hardening(server: str | None = Query(None, max_length=200), user: dict = Depends(require_operator), db: Session = Depends(get_db)) -> list[dict]:
    out = []
    for s in visible_servers(db, user, server):
        m = metrics_of(s)
        sec = m.get("security")
        out.append({"server": server_info(s), "agent_version": m.get("agent_version"), "push": s.monitor_mode == "push", "checked_at": (sec or {}).get("checked_at"),
                    "checks": (sec or {}).get("hardening") or [], "listening": (sec or {}).get("listening") or [], "authorized_keys": (sec or {}).get("authorized_keys") or [],
                    "foreign_packages": (sec or {}).get("foreign_packages"), "supported": sec is not None})
    return out


@router.get("/report")
def report(request: Request, server: str | None = Query(None, max_length=200), days: int = Query(7, ge=1, le=90), user: dict = Depends(require_operator), db: Session = Depends(get_db)) -> dict:
    """Everything a security report needs, for the chosen servers and period. The page lays it out by template."""
    servers = visible_servers(db, user, server)
    infos = {s.id: server_info(s) for s in servers}
    ids = list(infos)
    since = datetime.now(timezone.utc) - timedelta(days=days)
    ssh_data = secscan.ssh_summary(db, days * 24, ids)
    found = db.scalars(select(SecurityFinding).where(SecurityFinding.server_id.in_(ids or [0]), (SecurityFinding.resolved_at.is_(None)) | (SecurityFinding.last_seen >= since))
                       .order_by(desc(SecurityFinding.last_seen)).limit(1000)).all()
    logins = db.scalars(select(SshLoginEvent).where(SshLoginEvent.server_id.in_(ids or [0]), SshLoginEvent.ts >= since).order_by(desc(SshLoginEvent.ts)).limit(1000)).all()
    ports = latest_scans(db, "ports", "server")
    rows = []
    for s in servers:
        m = metrics_of(s)
        sec = m.get("security") or {}
        mine = [f for f in found if f.server_id == s.id]
        my_logins = [e for e in logins if e.server_id == s.id]
        rows.append({"server": infos[s.id], "status": s.last_status, "agent_version": m.get("agent_version"), "updates": m.get("updates"),
                     "ssh_failures": ssh_data["per_server"].get(s.id, {"total": 0, "distinct_ips": 0, "top_ips": []}),
                     "logins": {"total": len(my_logins), "suspicious": sum(1 for e in my_logins if e.failures_before >= _breach_threshold()), "new_sources": sum(1 for e in my_logins if e.new_source),
                                "users": sorted({e.user for e in my_logins})[:20], "sources": sorted({e.ip for e in my_logins})[:30]},
                     "findings": [finding_view(f, None) for f in mine], "hardening": sec.get("hardening") or [], "listening": sec.get("listening") or [],
                     "authorized_keys": len(sec.get("authorized_keys") or []), "foreign_packages": sec.get("foreign_packages"), "exposure": scan_view(ports.get(s.id)),
                     "threat_scan_at": sec.get("checked_at")})
    audit(db, request, "security.report", user=user, detail=f"{days} days; servers: {', '.join(i['name'] for i in infos.values())[:600] or 'none'}", commit=True)
    return {"generated_at": datetime.now(timezone.utc).isoformat(), "days": days, "since": since.isoformat(), "filter": server or None, "servers": rows,
            "ssh": {"total": ssh_data["total"], "top_ips": ssh_data["top_ips"][:15], "top_users": ssh_data["top_users"][:10]}}


class ScheduleIn(BaseModel):
    scan_hours: int = Field(ge=0, le=720)          # 0 = only when someone presses Scan now
    threat_minutes: int = Field(ge=2, le=1440)
    updates_hours: int = Field(ge=1, le=168)


def schedule_view(db: Session) -> dict:
    cfg = secscan.schedule(db)
    last = db.scalar(select(func.max(SecurityScan.started_at)))
    return {k: cfg.get(k) for k in ("scan_hours", "threat_minutes", "updates_hours", "updated_by", "updated_at")} | {"last_scan_at": aware(last).isoformat() if last else None, "job": dict(secscan.JOB)}


@router.get("/schedule")
def get_schedule(_: dict = Depends(require_operator), db: Session = Depends(get_db)) -> dict:
    return schedule_view(db)


@router.put("/schedule")
def put_schedule(payload: ScheduleIn, request: Request, user: dict = Depends(require_admin), db: Session = Depends(get_db)) -> dict:
    cfg = secscan.schedule(db)
    changes = [f"{k} {cfg.get(k)} -> {getattr(payload, k)}" for k in ("scan_hours", "threat_minutes", "updates_hours") if cfg.get(k) != getattr(payload, k)]
    cfg.update(payload.model_dump(), updated_by=user["email"], updated_at=datetime.now(timezone.utc).isoformat())
    secscan.save_schedule(db, cfg)
    audit(db, request, "security.schedule", user=user, detail="; ".join(changes) or "no changes")
    db.commit()
    return schedule_view(db)


class ScanAllIn(BaseModel):
    server: str | None = Field(default=None, max_length=200)    # the page's server filter, if any


@router.post("/scan-all")
def scan_all(payload: ScanAllIn, request: Request, user: dict = Depends(require_operator), db: Session = Depends(get_db)) -> dict:
    """Scan now: exposure scans + TLS audits from SM-Watch (in the background), and asks every agent to run its threat scan and
    update check at its next report. Covers the servers this person can see (narrowed by the page's server filter)."""
    import threading
    import time
    if secscan.JOB["running"]:
        raise HTTPException(409, "A scan of everything is already running")
    finished = secscan.JOB.get("finished_at")
    if finished and time.time() - datetime.fromisoformat(finished).timestamp() < 120:
        raise HTTPException(429, "Everything was scanned less than 2 minutes ago")
    servers = visible_servers(db, user, payload.server)
    ids = [s.id for s in servers]
    services = [s for s in db.scalars(select(Service).where(Service.enabled.is_(True))).all() if can_see(user, "service", s.id) and s.url.lower().startswith("https://")]
    if payload.server:
        hosts = {h for s in servers for h in (server_info(s).get("hostname"), server_info(s).get("public_ip"), s.host) if h}
        services = [s for s in services if s.server_id in ids or any(h in s.url for h in hosts)]
    targets = [("server", s.id) for s in servers if s.enabled and secscan.server_address(s)[0]] + [("service", s.id) for s in services]
    agents = [s.id for s in servers if s.monitor_mode == "push"]
    secscan.request_agent_rescan(db, agents, user["email"])
    audit(db, request, "security.scan_all", user=user, detail=f"{len(targets)} exposure/TLS scans; {len(agents)} agents asked to re-check" + (f"; filter {payload.server}" if payload.server else ""))
    db.commit()
    secscan.JOB.update(running=True, total=len(targets), done=0, failed=0)       # visible at once, before the thread starts
    threading.Thread(target=secscan.scan_all, args=(targets, user["email"]), daemon=True, name="security-scan-all").start()
    return {"scans": len(targets), "agents": len(agents), "job": dict(secscan.JOB)}


_last_recheck: dict[int, float] = {}


class RecheckIn(BaseModel):
    server: str | None = Field(default=None, max_length=200)    # several servers: the page's filter (empty = all visible)


@router.post("/recheck")
def recheck(payload: RecheckIn, request: Request, user: dict = Depends(require_operator), db: Session = Depends(get_db)) -> dict:
    """Asks agents to run their threat scan, hardening checks and update check at their next report (no port scan)."""
    import time
    servers = [s for s in visible_servers(db, user, payload.server) if s.monitor_mode == "push" and s.enabled]
    now = time.monotonic()
    fresh = [s for s in servers if now - _last_recheck.get(s.id, -1e9) >= 30]
    if servers and not fresh:
        raise HTTPException(429, "Already requested less than 30 seconds ago; the agent re-checks at its next report")
    for s in fresh:
        _last_recheck[s.id] = now
    secscan.request_agent_rescan(db, [s.id for s in fresh], user["email"])
    audit(db, request, "security.recheck", user=user, detail=f"{len(fresh)} agent(s): {', '.join(s.name for s in fresh)[:500]}")
    db.commit()
    return {"agents": len(fresh), "interval_seconds": max((s.check_interval_seconds or 30) for s in fresh) if fresh else 0}


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
