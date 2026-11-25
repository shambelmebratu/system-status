"""Security dashboard: SSH attacks and logins, threats (malware, persistence, new keys), pending updates, hardening, exposure scans,
TLS audits, two-factor adoption, and report data. Every list can be narrowed to one server (?server=<id, host name or IP>) and every
item says which server it belongs to (name, host name, public and private addresses)."""
import json
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.concurrency import run_in_threadpool
from pydantic import BaseModel, Field
from sqlalchemy import desc, func, or_, select
from sqlalchemy.orm import Session

from . import secalerts, secscan
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
    if not server:
        out["kubernetes"] = kubernetes_counts(db, user)
        cluster_ports = latest_scans(db, "ports", "cluster")
        rows = []
        for c in visible_clusters(db, user):
            try:
                summary = json.loads(c.summary or "{}") or {}
            except ValueError:
                summary = {}
            targets, reason = secscan.cluster_targets(c)
            rows.append({"id": c.id, "name": c.name, "agent_version": c.agent_version, "scan": scan_view(cluster_ports.get(c.id)), "scannable": bool(targets),
                         "scan_unavailable": reason or None, "exposed": summary.get("exposed") or [], "nodes": len(summary.get("node_addresses") or [])})
        out["clusters"] = rows
    if user["role"] == "admin" and not server:
        from .mfa import policy
        users = db.scalars(select(User).where(User.active.is_(True))).all()
        out["two_factor"] = {"policy": policy(db), "enabled": sum(1 for u in users if u.totp_enabled), "total": len(users),
                             "without": [{"id": u.id, "email": u.email, "role": u.role} for u in users if not u.totp_enabled][:50]}
    return out


ACTION_TITLES = {"security.alerts": "Security alert settings changed", "security.alerts_test": "Test security alert sent", "security.scan_all": "Scan of everything started",
                 "security.scan": "Scan run by hand", "security.recheck": "Agents asked to re-check", "security.schedule": "Scan schedule changed",
                 "security.acknowledge": "Finding acknowledged", "security.report": "Security report created", "security.policy": "Two-factor policy changed"}


ACTIVITY_CATEGORIES = ("access", "changes", "threats", "scans", "alerts", "smwatch", "agents")
ACCESS_KINDS = {"ssh_login_new_source", "ssh_login_after_failures", "ssh_key_added", "ssh_many_logins", "file_transfer"}
QUIET_ACTIONS = ("auth.logout",)       # recorded in the audit log, too routine for the timeline


def _category_of_finding(kind: str, source: str) -> str:
    return "access" if kind in ACCESS_KINDS else "changes" if source == "smwatch" else "threats"


def _category_of_action(action: str) -> str:
    return "access" if action.startswith("auth.") else "agents" if action.startswith(("agent.", "k8s.register")) else "smwatch"


@router.get("/activity")
def activity(days: int = Query(7, ge=1, le=90), server: str | None = Query(None, max_length=200), limit: int = Query(300, ge=1, le=1000),
             category: str | None = Query(None, pattern="^(access|changes|threats|scans|alerts|smwatch|agents)$"),
             user: dict = Depends(require_operator), db: Session = Depends(get_db)) -> list[dict]:
    """Everything that happened, newest first, each with who, what, where and when: SSH logins and file transfers, sign-ins to SM-Watch
    (and failed ones), what people changed or looked at in SM-Watch, agent identity events, findings opened / acknowledged / resolved,
    port and TLS scans, and every security alert with its delivery state. Only the servers this person can see; SM-Watch's own events
    (sign-ins, settings) are shown to admins."""
    from .models import AlertEvent, AuditEvent
    since = datetime.now(timezone.utc) - timedelta(days=days)
    servers = visible_servers(db, user, server)
    who = {s.id: {"id": s.id, "name": s.name} for s in servers}
    ids = list(who) or [0]
    out: list[dict] = []
    for f in db.scalars(select(SecurityFinding).where(SecurityFinding.server_id.in_(ids), or_(SecurityFinding.first_seen >= since, SecurityFinding.resolved_at >= since,
                                                                                               SecurityFinding.acknowledged_at >= since))).all():
        base = {"server": who.get(f.server_id), "finding_id": f.id, "kind": f.kind, "severity": f.severity, "title": f.title}
        if aware(f.first_seen) >= since:
            out.append({**base, "at": aware(f.first_seen).isoformat(), "type": "found", "detail": f.detail[:300]})
        if f.acknowledged_at and aware(f.acknowledged_at) >= since:
            out.append({**base, "at": aware(f.acknowledged_at).isoformat(), "type": "acknowledged", "actor": f.acknowledged_by, "detail": f.note or ""})
        if f.resolved_at and aware(f.resolved_at) >= since:
            out.append({**base, "at": aware(f.resolved_at).isoformat(), "type": "resolved", "detail": ""})
    scan_q = select(SecurityScan).where(SecurityScan.started_at >= since)
    if server:
        scan_q = scan_q.where(SecurityScan.target_type == "server", SecurityScan.target_id.in_(ids))
    from .models import Cluster
    names = {("service", s.id): s.name for s in db.scalars(select(Service)).all()} | {("cluster", c.id): f"cluster {c.name}" for c in db.scalars(select(Cluster)).all()}
    for sc in db.scalars(scan_q.order_by(desc(SecurityScan.id)).limit(200)).all():
        if sc.target_type == "server" and sc.target_id not in who:
            continue
        if sc.target_type in ("service", "cluster") and not can_see(user, sc.target_type, sc.target_id):
            continue
        target = who.get(sc.target_id) if sc.target_type == "server" else None
        label = target["name"] if target else names.get((sc.target_type, sc.target_id)) or f"{sc.target_type} #{sc.target_id}"
        out.append({"at": aware(sc.started_at).isoformat(), "type": "scan", "server": target, "target": {"type": sc.target_type, "id": sc.target_id}, "severity": "high" if (sc.findings or 0) else "low",
                    "title": f"{'Port scan' if sc.kind == 'ports' else 'TLS audit'} of {label}: " + (f"failed ({sc.error[:120]})" if sc.error else f"grade {sc.grade or '–'}, {sc.findings or 0} risky"),
                    "detail": sc.address or "", "kind": sc.kind})
    alert_q = select(AlertEvent).where(AlertEvent.state.in_(secalerts.SECURITY_STATES), AlertEvent.created_at >= since)
    for e in db.scalars(alert_q.order_by(desc(AlertEvent.id)).limit(300)).all():
        if e.target_type == "server" and e.target_id not in who:
            continue
        if server and e.target_type != "server":
            continue
        if e.target_type == "system" and user["role"] != "admin":     # SM-Watch's own sign-ins and settings: admins only
            continue
        lines = [ln for ln in (e.message or "").replace("<b>", "").replace("</b>", "").splitlines() if ln.strip()]
        out.append({"at": aware(e.created_at).isoformat(), "type": "alert", "server": who.get(e.target_id) if e.target_type == "server" else None, "target": {"type": e.target_type, "id": e.target_id},
                    "severity": "critical" if e.severity == "critical" else "medium", "title": lines[1][:200] if len(lines) > 1 else (lines[0][:200] if lines else "Security alert"),
                    "detail": "sent" if e.sent else (e.delivery_error or "not sent yet"), "sent": bool(e.sent), "kind": secalerts.category_of(e.state, e.target_type)})
    for row in out:
        if row["type"] in ("found", "acknowledged", "resolved"):
            row["category"] = _category_of_finding(row.get("kind") or "", "smwatch" if row.get("kind") in ZT_CHANGE_KINDS else "agent")
        else:
            row["category"] = {"scan": "scans", "alert": "alerts"}.get(row["type"], "smwatch")
    # SSH logins and file transfers: every one, with the key and whether the address is new
    if category in (None, "access"):
        for e in db.scalars(select(SshLoginEvent).where(SshLoginEvent.server_id.in_(ids), SshLoginEvent.ts >= since).order_by(desc(SshLoginEvent.ts)).limit(600)).all():
            what = "file transfer (SFTP/scp)" if e.kind == "sftp" else f"SSH login ({e.method or 'unknown method'})"
            flags = (["new address"] if e.new_source else []) + ([f"after {e.failures_before} failed attempts"] if (e.failures_before or 0) > 0 else [])
            out.append({"at": aware(e.ts).isoformat(), "type": "login", "category": "access", "server": who.get(e.server_id), "severity": "medium" if flags else "low",
                        "title": f"{e.user or '?'} · {what} from {e.ip}" + (f" · {', '.join(flags)}" if flags else ""), "actor": e.user or None, "ip": e.ip,
                        "detail": f"key {e.key_name or e.fingerprint}" if (e.key_name or e.fingerprint) else "", "kind": e.kind})
    # SM-Watch itself: sign-ins, what people changed or read, agent identity events (admins; not narrowed to a server)
    if not server and user["role"] == "admin" and category in (None, "access", "smwatch", "agents"):
        from .zerotrust import ACTION_TITLES as ZT_TITLES
        q = select(AuditEvent).where(AuditEvent.ts >= since, AuditEvent.action.not_in(QUIET_ACTIONS)).order_by(desc(AuditEvent.id)).limit(600)
        for a in db.scalars(q).all():
            cat = _category_of_action(a.action)
            if category and cat != category:
                continue
            title = ZT_TITLES.get(a.action) or ACTION_TITLES.get(a.action) or a.action.replace(".", ": ").replace("_", " ")
            out.append({"at": aware(a.ts).isoformat(), "type": "action", "category": cat, "server": None, "severity": "medium" if not a.success else "low",
                        "title": title + ("" if a.success else " (refused)"), "detail": (a.detail or "")[:300], "actor": a.actor, "ip": a.ip, "target_ref": a.target or None,
                        "kind": a.action, "success": a.success})
    if category:
        out = [r for r in out if r.get("category") == category]
    out.sort(key=lambda r: r["at"], reverse=True)
    return out[:limit]


ZT_CHANGE_KINDS = {"user_added", "admin_granted", "critical_file_changed", "system_program_changed", "kernel_module_loaded", "hardening_weakened", "port_opened",
                   "ssh_login_new_source", "ssh_login_after_failures", "ssh_key_added", "ssh_many_logins", "file_transfer"}


@router.get("/trust")
def trust(server: str | None = Query(None, max_length=200), user: dict = Depends(require_operator), db: Session = Depends(get_db)) -> dict:
    """Zero trust: is every server verified right now (and why not), who can get in (SM-Watch accounts and SSH identities, with
    what is new), and what is waiting for a person to review."""
    from . import zerotrust
    now = datetime.now(timezone.utc)
    servers = visible_servers(db, user, server)
    ids = [s.id for s in servers]
    findings = db.scalars(select(SecurityFinding).where(SecurityFinding.server_id.in_(ids or [0]), SecurityFinding.resolved_at.is_(None))).all()
    by_server: dict[int, list] = {}
    for f in findings:
        by_server.setdefault(f.server_id, []).append(f)
    ports = latest_scans(db, "ports", "server")
    devices = []
    for s in servers:
        v = zerotrust.verify_server(db, s, metrics_of(s), by_server.get(s.id, []), ports.get(s.id), now)
        devices.append({"server": server_info(s), "status": s.last_status, **v})
    order = {"untrusted": 0, "unverified": 1, "review": 2, "verified": 3}
    devices.sort(key=lambda d: (order[d["status"]], d["server"]["name"].lower()))
    who = {s.id: server_info(s) for s in servers}
    queue = zerotrust.review_queue(db, ids)
    ident = zerotrust.identities(db, ids, now, include_users=user["role"] == "admin" and not server)
    users = ident["users"] or []
    return {
        "generated_at": now.isoformat(),
        "devices": devices,
        "identities": ident,
        "review": [finding_view(f, who.get(f.server_id)) for f in queue[:200]],
        "summary": {
            "devices": {"total": len(devices), "verified": sum(1 for d in devices if d["status"] == "verified"), "review": sum(1 for d in devices if d["status"] == "review"),
                        "untrusted": sum(1 for d in devices if d["status"] in ("untrusted", "unverified"))},
            "people": None if ident["users"] is None else {"total": len(users), "verified": sum(1 for u in users if u["verified"]), "without_mfa": sum(1 for u in users if not u["mfa"] and u["active"])},
            "ssh": {"identities": len(ident["ssh"]), "new_sources": sum(len(g["new_sources"]) for g in ident["ssh"]), "root": sum(1 for g in ident["ssh"] if g["root"])},
            "unreviewed": len(queue),
            "alerts_locked": sorted(secalerts.LOCKED),
        },
    }


@router.get("/servers")
def servers_list(user: dict = Depends(require_operator), db: Session = Depends(get_db)) -> list[dict]:
    """The server picker: every visible server with what people search by."""
    return [server_info(s) for s in visible_servers(db, user, None)]


@router.get("/ssh")
def ssh(hours: int = Query(24, ge=1, le=168), server: str | None = Query(None, max_length=200),
        start: str | None = Query(None, pattern=r"^\d{4}-\d{2}-\d{2}$"), end: str | None = Query(None, pattern=r"^\d{4}-\d{2}-\d{2}$"),
        user: dict = Depends(require_operator), db: Session = Depends(get_db)) -> dict:
    """Failed and successful SSH logins: the last `hours`, or the days from `start` to `end` (inclusive, UTC dates, at most 90 days)."""
    until = datetime.now(timezone.utc)
    if start or end:
        try:
            first = datetime.fromisoformat(start or end).replace(tzinfo=timezone.utc)
            last = datetime.fromisoformat(end or start).replace(tzinfo=timezone.utc)
        except ValueError as error:
            raise HTTPException(422, "Dates must look like 2026-11-20") from error
        if last < first:
            first, last = last, first
        until = min(last + timedelta(days=1), datetime.now(timezone.utc) + timedelta(minutes=1))
        hours = max(1, int((until - first).total_seconds() // 3600) + (1 if (until - first).total_seconds() % 3600 else 0))
        if hours > 90 * 24:
            raise HTTPException(422, "Choose at most 90 days")
    servers = visible_servers(db, user, server)
    infos = {s.id: server_info(s) for s in servers}
    data = secscan.ssh_summary(db, hours, list(infos), until)
    data["per_server"] = [{**infos.get(sid, {"id": sid, "name": f"server {sid}"}), **v} for sid, v in sorted(data["per_server"].items(), key=lambda kv: -kv[1]["total"])]
    # which servers each attacking address went after (by name, not just a count)
    since = until - timedelta(hours=hours)
    data["since"], data["until"] = since.isoformat(), until.isoformat()
    from .models import SshFailureSample
    targets: dict[str, dict[int, int]] = {}
    for sid, raw in db.execute(select(SshFailureSample.server_id, SshFailureSample.ips).where(SshFailureSample.ts >= since, SshFailureSample.ts < until, SshFailureSample.server_id.in_(list(infos) or [0]))).all():
        for ip, n in json.loads(raw or "{}").items():
            targets.setdefault(ip, {})[sid] = targets.setdefault(ip, {}).get(sid, 0) + n
    for row in data["top_ips"]:
        row["targets"] = [{"id": sid, "name": infos[sid]["name"], "attempts": n} for sid, n in sorted(targets.get(row["ip"], {}).items(), key=lambda kv: -kv[1]) if sid in infos]
    logins = db.scalars(select(SshLoginEvent).where(SshLoginEvent.ts >= since, SshLoginEvent.ts < until, SshLoginEvent.server_id.in_(list(infos) or [0])).order_by(desc(SshLoginEvent.ts)).limit(1000)).all()
    data["logins"] = [{"id": e.id, "server": {k: infos[e.server_id][k] for k in ("id", "name", "hostname", "public_ip")}, "ts": aware(e.ts).isoformat(), "ip": e.ip, "user": e.user,
                       "method": e.method, "failures_before": e.failures_before, "new_source": e.new_source, "kind": e.kind or "login",
                       "key_type": e.key_type or None, "fingerprint": e.fingerprint or None, "key_name": e.key_name or None,
                       "verdict": "transfer" if e.kind == "sftp" else "breach" if e.failures_before >= _breach_threshold(db) else "new" if e.new_source else "ok"} for e in logins]
    # how many SSH logins each server had today, against the daily limit
    day = datetime.now(timezone.utc).date()
    start = datetime(day.year, day.month, day.day, tzinfo=timezone.utc)
    today = dict(db.execute(select(SshLoginEvent.server_id, func.count()).where(SshLoginEvent.server_id.in_(list(infos) or [0]), SshLoginEvent.kind == "login",
                                                                               SshLoginEvent.ts >= start).group_by(SshLoginEvent.server_id)).all())
    data["daily_limit"] = int(secscan.schedule(db).get("daily_login_alert") or 0)
    data["today"] = [{"id": sid, "name": infos[sid]["name"], "logins": n} for sid, n in sorted(today.items(), key=lambda kv: -kv[1])]
    data["logins_supported"] = any(version_at_least(metrics_of(s).get("agent_version"), (2, 15)) for s in servers)
    return data


def version_at_least(version: str | None, wanted: tuple[int, int]) -> bool:
    try:
        return tuple(int(x) for x in str(version or "0").split(".")[:2]) >= wanted
    except ValueError:
        return False


def _breach_threshold(db: Session | None = None) -> int:
    from .config import get_settings
    if db is not None:
        from .secalerts import config
        return config(db)["ssh_success_after_failures"]
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


@router.get("/findings/{finding_id}")
def finding_detail(finding_id: int, user: dict = Depends(require_operator), db: Session = Depends(get_db)) -> dict:
    f = db.get(SecurityFinding, finding_id)
    if f is None or not can_see(user, "server", f.server_id):
        raise HTTPException(404, "Finding not found")
    server = db.get(Server, f.server_id)
    return finding_view(f, server_info(server) if server else None)


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
                     "logins": {"total": sum(1 for e in my_logins if e.kind != "sftp"), "transfers": sum(1 for e in my_logins if e.kind == "sftp"),
                                "keys": sorted({e.key_name or e.fingerprint for e in my_logins if e.fingerprint})[:20], "suspicious": sum(1 for e in my_logins if e.failures_before >= _breach_threshold(db)), "new_sources": sum(1 for e in my_logins if e.new_source),
                                "users": sorted({e.user for e in my_logins})[:20], "sources": sorted({e.ip for e in my_logins})[:30]},
                     "findings": [finding_view(f, None) for f in mine], "hardening": sec.get("hardening") or [], "listening": sec.get("listening") or [],
                     "authorized_keys": len(sec.get("authorized_keys") or []), "foreign_packages": sec.get("foreign_packages"), "exposure": scan_view(ports.get(s.id)),
                     "threat_scan_at": sec.get("checked_at")})
    zero = trust(server=server, user=user, db=db)                  # verification, identities and the review queue, as of now
    smwatch = None
    if user["role"] == "admin" and not server:                     # what happened in SM-Watch itself during the period
        from .models import AuditEvent
        from .zerotrust import ACTION_TITLES as ZT_TITLES
        events = db.scalars(select(AuditEvent).where(AuditEvent.ts >= since, AuditEvent.action.not_in(QUIET_ACTIONS)).order_by(desc(AuditEvent.id)).limit(2000)).all()
        signins = [a for a in events if a.action == "auth.login"]
        smwatch = {"sign_ins": sum(1 for a in signins if a.success), "failed_sign_ins": sum(1 for a in signins if not a.success),
                   "addresses": sorted({a.ip for a in signins if a.success and a.ip})[:40],
                   "changes": [{"at": aware(a.ts).isoformat(), "actor": a.actor, "ip": a.ip, "action": a.action, "title": ZT_TITLES.get(a.action) or ACTION_TITLES.get(a.action) or a.action,
                                "detail": (a.detail or "")[:200], "success": a.success} for a in events if not a.action.startswith(("auth.login", "logs.", "process.", "ai.", "db.query", "db.slow"))][:300],
                   "data_access": sum(1 for a in events if a.action.startswith(("logs.", "process.", "db.query", "ai.")))}
    audit(db, request, "security.report", user=user, detail=f"{days} days; servers: {', '.join(i['name'] for i in infos.values())[:600] or 'none'}", commit=True)
    return {"generated_at": datetime.now(timezone.utc).isoformat(), "days": days, "since": since.isoformat(), "filter": server or None, "servers": rows,
            "ssh": {"total": ssh_data["total"], "top_ips": ssh_data["top_ips"][:15], "top_users": ssh_data["top_users"][:10]},
            "zero_trust": {"summary": zero["summary"], "devices": zero["devices"], "identities": zero["identities"], "review": zero["review"][:100]}, "smwatch": smwatch}


class ScheduleIn(BaseModel):
    scan_hours: int = Field(ge=0, le=720)          # 0 = only when someone presses Scan now
    threat_minutes: int = Field(ge=2, le=1440)
    updates_hours: int = Field(ge=1, le=168)
    daily_login_alert: int | None = Field(default=None, ge=0, le=1000)   # SSH logins per server per day before an alert (0 = off)


def schedule_view(db: Session) -> dict:
    cfg = secscan.schedule(db)
    last = db.scalar(select(func.max(SecurityScan.started_at)))
    return {k: cfg.get(k) for k in ("scan_hours", "threat_minutes", "updates_hours", "daily_login_alert", "updated_by", "updated_at")} | {"last_scan_at": aware(last).isoformat() if last else None, "job": secscan.job_state(db)}


@router.get("/schedule")
def get_schedule(_: dict = Depends(require_operator), db: Session = Depends(get_db)) -> dict:
    return schedule_view(db)


@router.put("/schedule")
def put_schedule(payload: ScheduleIn, request: Request, user: dict = Depends(require_admin), db: Session = Depends(get_db)) -> dict:
    cfg = secscan.schedule(db)
    data = payload.model_dump(exclude_none=True)
    changes = [f"{k} {cfg.get(k)} -> {v}" for k, v in data.items() if cfg.get(k) != v]
    cfg.update(data, updated_by=user["email"], updated_at=datetime.now(timezone.utc).isoformat())
    secscan.save_schedule(db, cfg)
    audit(db, request, "security.schedule", user=user, detail="; ".join(changes) or "no changes")
    db.commit()
    secalerts.forget()
    return schedule_view(db)


# ------------------------------------------------------------------------------------------------ alert settings (Security → Alerts)
class SecurityAlertsIn(BaseModel):
    enabled: bool = True
    categories: dict[str, bool] = Field(default_factory=dict)
    channels: list[int] = Field(default_factory=list, max_length=50)
    threat_severity: str = Field(default="high", pattern="^(critical|high|medium|off)$")
    ssh_attack_threshold: int = Field(default=30, ge=0, le=100000)          # 0 = no attack alerts
    ssh_success_after_failures: int = Field(default=5, ge=1, le=10000)
    daily_login_alert: int = Field(default=4, ge=0, le=10000)                # 0 = off


def alerts_view(db: Session) -> dict:
    from .models import AlertEvent, Channel
    cfg = secalerts.config(db, fresh=True)
    recent = db.scalars(select(AlertEvent).where(AlertEvent.state.in_(secalerts.SECURITY_STATES)).order_by(AlertEvent.id.desc()).limit(25)).all()
    names = {"server": {s.id: s.name for s in db.scalars(select(Server)).all()}}
    week = datetime.now(timezone.utc) - timedelta(days=7)
    counts = {k: 0 for k in secalerts.CATEGORIES}
    for state, target_type, n in db.execute(select(AlertEvent.state, AlertEvent.target_type, func.count()).where(AlertEvent.state.in_(secalerts.SECURITY_STATES), AlertEvent.created_at >= week)
                                            .group_by(AlertEvent.state, AlertEvent.target_type)).all():
        cat = secalerts.category_of(state, target_type)
        if cat:
            counts[cat] += n
    return {**cfg, "kinds": [{"id": k, "label": l, "description": d, "last_7_days": counts[k], "locked": k in secalerts.LOCKED} for k, (l, d, _) in secalerts.CATEGORIES.items()],
            "available_channels": [{"id": c.id, "name": c.name, "type": c.type, "enabled": c.enabled} for c in db.scalars(select(Channel).order_by(Channel.name)).all()],
            "recent": [{"id": e.id, "at": aware(e.created_at).isoformat(), "kind": secalerts.category_of(e.state, e.target_type), "severity": e.severity,
                        "target": names.get(e.target_type, {}).get(e.target_id) or f"{e.target_type} #{e.target_id}",
                        "summary": next((line for line in (e.message or "").replace("<b>", "").replace("</b>", "").splitlines() if line.strip() and not line.startswith(("🚨", "🛡", "🔑", "🔁"))), "")[:200],
                        "sent": bool(e.sent), "error": e.delivery_error} for e in recent]}


@router.get("/alerts")
def get_alerts(_: dict = Depends(require_operator), db: Session = Depends(get_db)) -> dict:
    return alerts_view(db)


@router.put("/alerts")
def put_alerts(payload: SecurityAlertsIn, request: Request, user: dict = Depends(require_admin), db: Session = Depends(get_db)) -> dict:
    from .models import Channel
    known = {c for c in db.scalars(select(Channel.id)).all()}
    if any(c not in known for c in payload.channels):
        raise HTTPException(422, "Unknown channel")
    unknown = [k for k in payload.categories if k not in secalerts.CATEGORIES]
    if unknown:
        raise HTTPException(422, f"Unknown alert kind '{unknown[0]}'")
    before = secalerts.config(db, fresh=True)
    data = payload.model_dump()
    data["categories"] = {**before["categories"], **payload.categories}
    changes = [f"{k} {before.get(k)} -> {data[k]}" for k in ("enabled", "channels", "threat_severity", "ssh_attack_threshold", "ssh_success_after_failures", "daily_login_alert") if before.get(k) != data[k]]
    changes += [f"{k} {'on' if v else 'off'}" for k, v in data["categories"].items() if before["categories"].get(k) != v]
    secalerts.save(db, data, user["email"])
    audit(db, request, "security.alerts", user=user, detail="; ".join(changes) or "no changes")
    db.commit()
    return alerts_view(db)


@router.post("/alerts/test")
def test_alerts(request: Request, user: dict = Depends(require_admin), db: Session = Depends(get_db)) -> dict:
    """Sends a test message to the channels security alerts go to."""
    from .monitoring import format_alert, send_alert
    cfg = secalerts.config(db, fresh=True)
    message = format_alert("Security", "security_finding", "SM-Watch", ["This is a test of your security alerts.", f"Sent by {user['email']} from Security → Alerts."])
    sent, error = send_alert(message, db, None, None, set(cfg["channels"]) if cfg["channels"] else None)
    audit(db, request, "security.alerts_test", user=user, detail="sent" if sent else (error or "not sent")[:200], success=bool(sent))
    db.commit()
    return {"sent": bool(sent), "error": error}


class ScanAllIn(BaseModel):
    server: str | None = Field(default=None, max_length=200)    # the page's server filter, if any


@router.post("/scan-all")
def scan_all(payload: ScanAllIn, request: Request, user: dict = Depends(require_operator), db: Session = Depends(get_db)) -> dict:
    """Scan now: exposure scans + TLS audits from SM-Watch (in the background), and asks every agent to run its threat scan and
    update check at its next report. Covers the servers this person can see (narrowed by the page's server filter)."""
    import threading
    import time
    job = secscan.job_state(db)
    if job["running"]:
        raise HTTPException(409, "A scan of everything is already running")
    finished = job.get("finished_at")
    if finished and time.time() - datetime.fromisoformat(finished).timestamp() < 120:
        raise HTTPException(429, "Everything was scanned less than 2 minutes ago")
    servers = visible_servers(db, user, payload.server)
    ids = [s.id for s in servers]
    services = [s for s in db.scalars(select(Service).where(Service.enabled.is_(True))).all() if can_see(user, "service", s.id) and s.url.lower().startswith("https://")]
    if payload.server:
        hosts = {h for s in servers for h in (server_info(s).get("hostname"), server_info(s).get("public_ip"), s.host) if h}
        services = [s for s in services if s.server_id in ids or any(h in s.url for h in hosts)]
    targets = [("server", s.id) for s in servers if s.enabled and secscan.server_address(s)[0]] + [("service", s.id) for s in services]
    if not payload.server:
        targets += [("cluster", c.id) for c in visible_clusters(db, user) if c.enabled and secscan.cluster_targets(c)[0]]
    agents = [s.id for s in servers if s.monitor_mode == "push"]
    secscan.request_agent_rescan(db, agents, user["email"])
    audit(db, request, "security.scan_all", user=user, detail=f"{len(targets)} exposure/TLS scans; {len(agents)} agents asked to re-check" + (f"; filter {payload.server}" if payload.server else ""))
    db.commit()
    job = secscan.job_save(running=True, total=len(targets), done=0, failed=0, finished_at=None, started_by=user["email"])   # visible at once
    threading.Thread(target=secscan.scan_all, args=(targets, user["email"]), daemon=True, name="security-scan-all").start()
    return {"scans": len(targets), "agents": len(agents), "job": job}


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
    if target_type not in ("server", "service", "cluster"):
        raise HTTPException(404, "Unknown target")
    from .models import Cluster
    model = {"server": Server, "service": Service, "cluster": Cluster}[target_type]
    runner = {"server": secscan.run_server_scan, "service": secscan.run_service_scan, "cluster": secscan.run_cluster_scan}[target_type]
    ensure_access(user, target_type, target_id)
    import time
    key = (target_type, target_id)
    if time.monotonic() - _last_manual.get(key, -1e9) < 120:
        raise HTTPException(429, "This target was scanned less than 2 minutes ago")
    _last_manual[key] = time.monotonic()
    with SessionLocal() as db:
        target = db.get(model, target_id)
        if target is None:
            raise HTTPException(404, "Not found")
        db.expunge(target)
    started = datetime.now(timezone.utc)
    result = await run_in_threadpool(runner, target)
    with SessionLocal() as db:
        target = db.get(model, target_id)
        kind = "tls" if target_type == "service" else "ports"
        secscan.store(db, kind, target, target_type, result, started)
        audit(db, request, "security.scan", user=user, target=f"{target_type}:{target_id}", detail=f"{kind} scan of {target.name}: " + (result.get("error") or f"grade {result.get('grade')}, {result.get('findings', 0)} findings"))
        db.commit()
        return scan_view(db.scalar(select(SecurityScan).where(SecurityScan.kind == kind, SecurityScan.target_type == target_type, SecurityScan.target_id == target_id).order_by(desc(SecurityScan.id)).limit(1)))


@router.get("/scans/{target_type}/{target_id}")
def scan_history(target_type: str, target_id: int, limit: int = Query(10, ge=1, le=50), user: dict = Depends(require_operator), db: Session = Depends(get_db)) -> list[dict]:
    ensure_access(user, target_type, target_id)
    return [scan_view(s) for s in db.scalars(select(SecurityScan).where(SecurityScan.target_type == target_type, SecurityScan.target_id == target_id).order_by(desc(SecurityScan.id)).limit(limit)).all()]


# ------------------------------------------------------------------------------------------------ Kubernetes
def visible_clusters(db: Session, user: dict, cluster: str | None = None) -> list:
    from .models import Cluster
    clusters = [c for c in db.scalars(select(Cluster).order_by(Cluster.name)).all() if can_see(user, "cluster", c.id)]
    if cluster:
        needle = cluster.strip().lower()
        clusters = [c for c in clusters if (needle.isdigit() and c.id == int(needle)) or needle in c.name.lower()]
    return clusters


def cluster_scan(c) -> dict:
    try:
        summary = json.loads(c.summary or "{}") or {}
    except ValueError:
        summary = {}
    return {"id": c.id, "name": c.name, "agent_version": c.agent_version, "last_seen_at": aware(c.last_seen_at).isoformat() if c.last_seen_at else None,
            "scan": summary.get("security_scan"), "supported": "security_scan" in summary}


def kubernetes_counts(db: Session, user: dict) -> dict:
    from .models import ClusterFinding
    clusters = visible_clusters(db, user)
    ids = [c.id for c in clusters] or [0]
    rows = db.execute(select(ClusterFinding.severity, ClusterFinding.acknowledged_at.is_(None), func.count()).where(ClusterFinding.cluster_id.in_(ids), ClusterFinding.resolved_at.is_(None))
                      .group_by(ClusterFinding.severity, ClusterFinding.acknowledged_at.is_(None))).all()
    out = {"clusters": len(clusters), "scanned": sum(1 for c in clusters if cluster_scan(c)["supported"]), "critical": 0, "high": 0, "medium": 0, "low": 0, "acknowledged": 0}
    for severity, unacked, n in rows:
        if unacked:
            out[severity] = out.get(severity, 0) + n
        else:
            out["acknowledged"] += n
    return out


@router.get("/kubernetes")
def kubernetes_findings(cluster: str | None = Query(None, max_length=200), status: str = Query("open", pattern="^(open|attention|acknowledged|resolved|all)$"),
                        severity: str | None = Query(None, pattern="^(critical|high|medium|low)$"), limit: int = Query(500, ge=1, le=2000),
                        user: dict = Depends(require_operator), db: Session = Depends(get_db)) -> dict:
    """Security findings from the Kubernetes agents (1.3+), with each cluster's scan status."""
    from .k8s_security import finding_view as k8s_view
    from .models import ClusterFinding
    clusters = visible_clusters(db, user, cluster)
    infos = {c.id: {"id": c.id, "name": c.name} for c in clusters}
    q = select(ClusterFinding).where(ClusterFinding.cluster_id.in_(list(infos) or [0]))
    if status in ("open", "attention", "acknowledged"):
        q = q.where(ClusterFinding.resolved_at.is_(None))
    if status == "attention":
        q = q.where(ClusterFinding.acknowledged_at.is_(None))
    elif status == "acknowledged":
        q = q.where(ClusterFinding.acknowledged_at.is_not(None))
    elif status == "resolved":
        q = q.where(ClusterFinding.resolved_at.is_not(None))
    if severity:
        q = q.where(ClusterFinding.severity == severity)
    rows = db.scalars(q.order_by(desc(ClusterFinding.last_seen)).limit(limit)).all()
    findings = [k8s_view(f, infos[f.cluster_id]) for f in rows]
    findings.sort(key=lambda f: (f["resolved_at"] is not None, f["acknowledged_at"] is not None, SEVERITY_ORDER.get(f["severity"], 9), f["namespace"], f["object"]))
    return {"clusters": [cluster_scan(c) for c in clusters], "findings": findings}


@router.post("/kubernetes/{finding_id}/acknowledge")
def acknowledge_k8s(finding_id: int, payload: AckIn, request: Request, user: dict = Depends(require_operator), db: Session = Depends(get_db)) -> dict:
    """Marks a Kubernetes finding as known (it stays listed until the agent stops seeing it)."""
    from .k8s_security import finding_view as k8s_view
    from .models import Cluster, ClusterFinding
    f = db.get(ClusterFinding, finding_id)
    if not f:
        raise HTTPException(404, "Finding not found")
    ensure_access(user, "cluster", f.cluster_id)
    f.acknowledged_by, f.acknowledged_at, f.note = user["email"], datetime.now(timezone.utc), payload.note.strip()
    cluster = db.get(Cluster, f.cluster_id)
    audit(db, request, "security.acknowledge", user=user, target=f"cluster:{f.cluster_id}", detail=f"{cluster.name if cluster else f.cluster_id}: {f.title}" + (f" ({payload.note.strip()[:200]})" if payload.note.strip() else ""))
    db.commit()
    return k8s_view(f, {"id": cluster.id, "name": cluster.name} if cluster else None)

