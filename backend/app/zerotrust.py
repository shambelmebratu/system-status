"""Zero trust: nothing is trusted because it was trusted yesterday. Every server is verified continuously, every identity is known,
and every change is either reviewed by a person or shown as unreviewed.

* verify_server(): the checks a server must pass right now to count as verified, each with the reason it passed or failed.
* identities(): everyone who can sign in to SM-Watch and everyone who logged in to a server over SSH, with what is new.
* review_queue(): open findings that need a human decision (changes, new access, threats nobody looked at).
* on_audit(): turns audited events into alerts: sign-ins from new addresses, failed sign-in bursts, two-factor turned off,
  changes to users / channels / alert settings / monitors, and agent identity events. Changes that could hide an attack
  (alerts turned off, channels removed, maintenance windows, pauses) always alert: that kind cannot be turned off.
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .config import get_settings

logger = logging.getLogger("smwatch.zerotrust")

# --------------------------------------------------------------------------------------------------------------- audit -> alerts
# Changes that could be used to hide an attack. Always alerted (secalerts treats this state as locked on).
GUARD_ACTIONS = {
    "security.alerts": "Security alert settings changed", "security.policy": "Two-factor sign-in policy changed", "security.schedule": "Security scan schedule changed",
    "channel.delete": "Alert channel removed", "channel.update": "Alert channel changed", "purge.settings": "Data retention changed", "purge.manual": "Data deleted by hand",
    "devops.maintenance_create": "Maintenance window created (alerts are muted during it)", "devops.maintenance_update": "Maintenance window changed",
    "server.pause": "Server monitoring paused", "service.pause": "Service monitoring paused", "server.log_policy": "Server log access changed", "k8s.log_policy": "Cluster log access changed",
    "auth.2fa_disable": "Two-factor sign-in turned off",
}
# Changes people make in SM-Watch that are worth knowing about (alerted unless "Changes in SM-Watch" is turned off).
ADMIN_ACTIONS = {
    "user.create": "User added", "user.update": "User changed", "user.delete": "User removed", "channel.create": "Alert channel added",
    "server.delete": "Server removed", "service.delete": "Service removed", "server.token_revoke": "Server agent token revoked", "server.token_rotate": "Server agent token rotated",
    "k8s.cluster_delete": "Cluster removed", "k8s.token_revoke": "Cluster agent token revoked", "k8s.token_rotate": "Cluster agent token rotated",
    "enroll.link_create": "Agent join token created (anyone holding it can add servers)", "ai.settings": "AI settings changed", "auth.email_change": "Sign-in email changed",
    "auth.password_change": "Password changed",
}
AGENT_ACTIONS = {"agent.ip_changed": "Agent reports from a new address", "agent.enroll": "New server joined", "k8s.register": "New cluster joined",
                 "agent.auth_failed": "An agent used a wrong or revoked token"}
ACTION_TITLES = {**GUARD_ACTIONS, **ADMIN_ACTIONS, **AGENT_ACTIONS, "auth.login": "Signed in to SM-Watch", "auth.logout": "Signed out", "auth.2fa_enable": "Two-factor sign-in turned on",
                 "server.create": "Server added", "server.update": "Server settings changed", "service.create": "Service added", "service.update": "Service settings changed",
                 "server.resume": "Server monitoring resumed", "service.resume": "Service monitoring resumed", "channel.test": "Test alert sent", "enroll.link_revoke": "Agent join token revoked",
                 "agent.token_rotated": "Agent switched to its new token", "agent.token_shared": "Agent token delivered", "k8s.cluster_update": "Cluster settings changed",
                 "process.inspect": "Process inspected", "logs.denied": "Log access refused", "db.query": "Database queried", "ai.ask": "Asked the AI assistant",
                 "devops.maintenance_end": "Maintenance window ended", "devops.maintenance_delete": "Maintenance window removed"}


def _queue(db: Session, state: str, title: str, lines: list[str], severity: str = "warning") -> None:
    from .monitoring import format_alert
    from .models import AlertEvent
    db.add(AlertEvent(target_type="system", target_id=0, severity=severity, message=format_alert("Security", state, "SM-Watch", [title, *lines]), state=state))
    from .monitoring import _alert_wake
    _alert_wake.set()


def _recent_alert(db: Session, state: str, needle: str, minutes: int) -> bool:
    from .models import AlertEvent
    since = datetime.now(timezone.utc) - timedelta(minutes=minutes)
    return bool(db.scalar(select(func.count()).select_from(AlertEvent).where(AlertEvent.state == state, AlertEvent.created_at >= since, AlertEvent.message.contains(needle))))


def on_audit(db: Session, *, action: str, actor: str, target: str, detail: str | None, ip: str | None, success: bool) -> None:
    """Called for every audit event (before it is committed with the caller's transaction). Never raises."""
    try:
        _on_audit(db, action, actor, target, detail or "", ip, success)
    except Exception:          # an alert must never break the action that was audited
        logger.exception("zero-trust alert for %s failed", action)


def _on_audit(db: Session, action: str, actor: str, target: str, detail: str, ip: str | None, success: bool) -> None:
    from .models import AuditEvent
    s = get_settings()
    where = f"from {ip}" if ip else ""
    by = f"By {actor} {where}".strip()
    if action == "auth.login":
        if success:
            if not ip:
                return
            since = datetime.now(timezone.utc) - timedelta(days=s.zt_known_address_days)
            known = db.scalar(select(func.count()).select_from(AuditEvent).where(AuditEvent.action == "auth.login", AuditEvent.success.is_(True), AuditEvent.actor == actor,
                                                                                AuditEvent.ip == ip, AuditEvent.ts >= since))
            history = db.scalar(select(func.count()).select_from(AuditEvent).where(AuditEvent.action == "auth.login", AuditEvent.success.is_(True), AuditEvent.actor == actor))
            if not known and history:              # the very first sign-in of an account sets its baseline
                _queue(db, "zt_signin", f"{actor} signed in from a new address: {ip}", [f"No sign-in from this address in the last {s.zt_known_address_days} days.",
                                                                                      "If this was not them, reset their password and two-factor sign-in now."])
            return
        limit = s.zt_failed_signin_alert
        if limit <= 0:
            return
        since = datetime.now(timezone.utc) - timedelta(minutes=10)
        by_ip = db.scalar(select(func.count()).select_from(AuditEvent).where(AuditEvent.action == "auth.login", AuditEvent.success.is_(False), AuditEvent.ip == ip, AuditEvent.ts >= since)) if ip else 0
        by_actor = db.scalar(select(func.count()).select_from(AuditEvent).where(AuditEvent.action == "auth.login", AuditEvent.success.is_(False), AuditEvent.actor == actor, AuditEvent.ts >= since))
        n = max(by_ip or 0, by_actor or 0) + 1      # this event is not flushed yet
        key = f"Failed sign-ins: {actor}"
        if n >= limit and not _recent_alert(db, "zt_signin", key, 30):
            _queue(db, "zt_signin", f"{key} ({n} in 10 minutes)", [f"Last attempt {where or 'from an unknown address'}: {detail or 'refused'}.",
                                                                      "Someone may be guessing a password. Accounts are locked for a while after repeated failures."])
        return
    if action in GUARD_ACTIONS and success:
        _queue(db, "zt_guard", GUARD_ACTIONS[action], [by, detail[:300]] if detail else [by], "critical" if action in ("security.alerts", "auth.2fa_disable", "purge.manual") else "warning")
        return
    if action == "user.update" and success and ("two-factor sign-in reset" in detail or "-> admin" in detail or "→ admin" in detail):
        _queue(db, "zt_guard", "Two-factor sign-in reset for a user" if "two-factor" in detail else "User given admin rights", [by, detail[:300]], "critical")
        return
    if action in ADMIN_ACTIONS and success:
        _queue(db, "zt_admin", ADMIN_ACTIONS[action], [by, f"Target: {target}" if target else "", detail[:300]])
        return
    if action in AGENT_ACTIONS:
        if action == "agent.auth_failed":
            if _recent_alert(db, "zt_agent", f"wrong or revoked token ({target or ip})", 60):
                return
            _queue(db, "zt_agent", f"An agent used a wrong or revoked token ({target or ip})", [where, detail[:300], "A stolen or old token, or a server that was reinstalled."])
            return
        _queue(db, "zt_agent", AGENT_ACTIONS[action], [actor if actor.startswith("agent:") else by, f"Target: {target}" if target else "", detail[:300]])


# --------------------------------------------------------------------------------------------------------------- devices
def _aware(v):
    from .stats import aware
    return aware(v) if v else None


def verify_server(db: Session, s, metrics: dict, open_findings: list, port_scan, now: datetime) -> dict:
    """The checks a server must pass right now. ok: True (passed), False (failed) or None (cannot be checked)."""
    from .agent_versions import is_outdated, latest_server_agent
    from .monitoring import heartbeat_grace
    from .secscan import schedule
    cfg = schedule(db)
    st = get_settings()
    checks: list[dict] = []

    def add(cid: str, label: str, ok, detail: str, weight: str = "review") -> None:
        checks.append({"id": cid, "label": label, "ok": ok, "detail": detail, "weight": weight})

    if s.monitor_mode != "push":
        add("agent", "Agent installed", False, "Monitored by ping or pull only: SM-Watch cannot see what runs on it, so it cannot be verified.", "untrusted")
        return {"status": "unverified", "checks": checks, "passed": 0, "total": 1}
    seen = _aware(s.last_seen_at)
    silent = (now - seen).total_seconds() if seen else None
    add("reporting", "Agent reporting now", silent is not None and silent <= heartbeat_grace(s.check_interval_seconds),
        "never reported" if silent is None else f"last report {int(silent)} s ago (every {s.check_interval_seconds} s)", "untrusted")
    version, latest = metrics.get("agent_version"), latest_server_agent()
    add("agent_version", "Agent up to date", None if not version else not is_outdated(version, latest), f"{version or 'unknown'} (latest {latest})")
    issued = _aware(s.token_issued_at) or _aware(s.created_at)
    age = (now - issued).days if issued else None
    add("token", "Agent token rotated recently", None if age is None else age <= st.zt_token_max_days,
        "unknown" if age is None else f"issued {age} days ago (rotate at least every {st.zt_token_max_days} days)")
    sec = metrics.get("security") or {}
    scanned = None
    try:
        scanned = datetime.fromisoformat(sec["checked_at"]) if sec.get("checked_at") else None
    except ValueError:
        pass
    fresh_limit = max(30, int(cfg.get("threat_minutes") or 10) * 3)
    add("threat_scan", "Threat scan is recent", None if metrics.get("capabilities") is not None and "process" not in (metrics.get("capabilities") or []) else
        (scanned is not None and (now - _aware(scanned)).total_seconds() <= fresh_limit * 60), f"last scan {_ago(scanned, now)}" if scanned else "no threat scan received yet")
    add("baseline", "Integrity baseline recorded", bool(sec.get("baseline")) if sec else None,
        "accounts, admin groups, security files and system programs are fingerprinted" if sec.get("baseline") else "not recorded yet (agent 2.17+)")
    threats = [f for f in open_findings if f.source == "agent" and f.acknowledged_at is None and f.severity in ("critical", "high")]
    add("threats", "No unreviewed threats", not threats, f"{len(threats)} critical/high: " + "; ".join(f.title for f in threats[:3]) if threats else "none open", "untrusted" if any(f.severity == "critical" for f in threats) else "review")
    changes = [f for f in open_findings if f.source == "smwatch" and f.acknowledged_at is None]
    add("changes", "Every change reviewed", not changes, f"{len(changes)} unreviewed: " + "; ".join(f.title for f in changes[:3]) if changes else "nothing waiting for review",
        "untrusted" if any(f.severity == "critical" for f in changes) else "review")
    hard = [c for c in sec.get("hardening") or [] if c.get("ok") is False and c.get("severity") in ("critical", "high")]
    add("hardening", "No serious weak settings", None if not sec.get("hardening") else not hard, f"{len(hard)} failing: " + ", ".join(c.get("title", c.get("id", "")) for c in hard[:3]) if hard else "high-risk checks pass")
    updates = (metrics.get("updates") or {}).get("security")
    add("updates", "Security updates installed", None if updates is None else updates == 0, "unknown" if updates is None else f"{updates} waiting")
    risky = []
    if port_scan is not None and not port_scan.error:
        try:
            risky = [p for p in (json.loads(port_scan.results).get("open") or []) if p.get("risk") in ("critical", "high")]
        except ValueError:
            risky = []
    add("exposure", "No risky ports reachable", None if port_scan is None else not risky, "not scanned yet" if port_scan is None else (f"{len(risky)} reachable: " + ", ".join(str(p.get("port")) for p in risky[:5]) if risky else "nothing risky reachable"))
    failed = [c for c in checks if c["ok"] is False]
    status = "untrusted" if any(c["weight"] == "untrusted" for c in failed) else "review" if failed else "verified"
    return {"status": status, "checks": checks, "passed": sum(1 for c in checks if c["ok"] is True), "total": sum(1 for c in checks if c["ok"] is not None), "risky_ports": len(risky)}


def _ago(t, now) -> str:
    if not t:
        return "never"
    s = int((now - _aware(t)).total_seconds())
    return f"{s} s ago" if s < 90 else f"{s // 60} min ago" if s < 5400 else f"{s // 3600} h ago" if s < 172800 else f"{s // 86400} days ago"


# --------------------------------------------------------------------------------------------------------------- identities
def identities(db: Session, server_ids: list[int], now: datetime, include_users: bool) -> dict:
    """Dashboard accounts (admins only) and SSH identities seen on the servers in the last 7 days."""
    from .models import AuditEvent, SshLoginEvent, User
    week = now - timedelta(days=7)
    out: dict = {"users": None, "ssh": []}
    if include_users:
        rows = []
        for u in db.scalars(select(User).order_by(User.email)).all():
            last = db.scalar(select(AuditEvent).where(AuditEvent.action == "auth.login", AuditEvent.success.is_(True), AuditEvent.actor == u.email).order_by(AuditEvent.id.desc()).limit(1))
            ips = db.scalars(select(AuditEvent.ip).where(AuditEvent.action == "auth.login", AuditEvent.success.is_(True), AuditEvent.actor == u.email, AuditEvent.ts >= week).distinct()).all()
            failed = db.scalar(select(func.count()).select_from(AuditEvent).where(AuditEvent.action == "auth.login", AuditEvent.success.is_(False), AuditEvent.actor == u.email,
                                                                                 AuditEvent.ts >= now - timedelta(hours=24)))
            issues = ([] if u.totp_enabled else ["no two-factor sign-in"]) + ([f"{failed} failed sign-ins in 24 h"] if failed else []) + ([] if u.active else ["disabled"])
            rows.append({"id": u.id, "email": u.email, "name": u.name, "role": u.role, "active": u.active, "mfa": bool(u.totp_enabled),
                         "last_sign_in": _aware(last.ts).isoformat() if last else None, "last_ip": last.ip if last else None, "addresses_7d": [i for i in ips if i][:10],
                         "failed_24h": failed or 0, "issues": issues, "verified": bool(u.totp_enabled) and u.active and not failed})
        out["users"] = rows
    if server_ids:
        from .models import Server
        names = {s.id: s.name for s in db.scalars(select(Server).where(Server.id.in_(server_ids))).all()}
        groups: dict[tuple, dict] = {}
        for e in db.scalars(select(SshLoginEvent).where(SshLoginEvent.server_id.in_(server_ids), SshLoginEvent.ts >= week).order_by(SshLoginEvent.ts.desc()).limit(5000)).all():
            g = groups.setdefault((e.server_id, e.user), {"server": {"id": e.server_id, "name": names.get(e.server_id)}, "user": e.user, "logins": 0, "transfers": 0, "sources": set(),
                                                         "keys": set(), "new_sources": set(), "suspicious": 0, "last": None})
            if e.kind == "sftp":
                g["transfers"] += 1
            else:
                g["logins"] += 1
            g["sources"].add(e.ip)
            if e.key_name or e.fingerprint:
                g["keys"].add(e.key_name or e.fingerprint)
            if e.new_source:
                g["new_sources"].add(e.ip)
            if (e.failures_before or 0) > 0:
                g["suspicious"] += 1
            g["last"] = g["last"] or _aware(e.ts).isoformat()
        out["ssh"] = sorted(({**g, "sources": sorted(g["sources"])[:12], "keys": sorted(g["keys"])[:8], "new_sources": sorted(g["new_sources"])[:12],
                              "root": g["user"] == "root"} for g in groups.values()), key=lambda g: (-len(g["new_sources"]), -g["logins"]))[:200]
    return out


# --------------------------------------------------------------------------------------------------------------- review queue
REVIEW_KINDS = ("ssh_login_new_source", "ssh_login_after_failures", "ssh_key_added", "user_added", "admin_granted", "critical_file_changed", "system_program_changed",
                "kernel_module_loaded", "hardening_weakened", "port_opened", "file_transfer", "ssh_many_logins")


def review_queue(db: Session, server_ids: list[int]) -> list:
    """Open findings nobody has looked at yet: every change and every new kind of access, plus serious threats."""
    from .models import SecurityFinding
    rows = db.scalars(select(SecurityFinding).where(SecurityFinding.server_id.in_(server_ids or [0]), SecurityFinding.resolved_at.is_(None), SecurityFinding.acknowledged_at.is_(None))
                      .order_by(SecurityFinding.last_seen.desc()).limit(500)).all()
    return [f for f in rows if f.kind in REVIEW_KINDS or f.source == "smwatch" or f.severity in ("critical", "high")]
