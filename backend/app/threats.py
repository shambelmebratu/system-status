"""Signs of compromise: suspicious successful SSH logins, the agent's threat findings (malware, persistence, web shells ...), newly authorized
SSH keys, and changes since the previous scan (new accounts and administrators, changed security files and system programs, weakened
protections, newly exposed ports, kernel modules).

Findings are kept per server with a stable key, so the same problem seen in every report stays ONE finding (first seen / last seen).
Agent findings resolve themselves when the agent stops seeing them. Findings SM-Watch derives itself (a login after failed attempts,
a login from a new address, a new SSH key) are events: they stay open until someone acknowledges them."""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .config import get_settings

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def aware(ts: datetime | None) -> datetime | None:
    return ts if ts is None or ts.tzinfo else ts.replace(tzinfo=timezone.utc)


def _alert(db: Session, server, state: str, lines: list[str], severity: str = "warning") -> None:
    from .monitoring import format_alert, queue_event, server_where
    queue_event(db, "server", server, severity, format_alert("Security", state, server.name, lines, where=server_where(server)), deliver=False, state=state)


def open_finding(db: Session, server, key: str, *, kind: str, severity: str, title: str, detail: str, evidence: dict, source: str, now: datetime):
    """Creates the finding, or refreshes the open one with the same key. Returns (finding, is_new)."""
    from .models import SecurityFinding
    row = db.scalar(select(SecurityFinding).where(SecurityFinding.server_id == server.id, SecurityFinding.key == key, SecurityFinding.resolved_at.is_(None)))
    if row:
        row.last_seen, row.severity, row.title, row.detail = now, severity, title[:200], detail[:1000]
        row.evidence = json.dumps(evidence)
        return row, False
    row = SecurityFinding(server_id=server.id, key=key[:200], kind=kind, severity=severity, title=title[:200], detail=detail[:1000], evidence=json.dumps(evidence),
                          source=source, first_seen=now, last_seen=now)
    db.add(row)
    db.flush()
    return row, True


# ------------------------------------------------------------------------------------------------ successful SSH logins
def record_logins(db: Session, server, accepted: list[dict], now: datetime) -> None:
    """Stores successful logins and raises a finding (and an alert) for the suspicious ones:
    * after N failed attempts from the same address in the previous 24 h (on any server): a likely successful brute force;
    * from an address this server has never had a login from (only once SM-Watch has a day of login history for it)."""
    from .models import SshFailureSample, SshLoginEvent
    settings = get_settings()
    since = now - timedelta(hours=24)
    failures: dict[str, int] = {}
    for raw in db.scalars(select(SshFailureSample.ips).where(SshFailureSample.ts >= since)).all():
        for ip, n in json.loads(raw or "{}").items():
            failures[ip] = failures.get(ip, 0) + int(n)
    first = db.scalar(select(func.min(SshLoginEvent.ts)).where(SshLoginEvent.server_id == server.id))
    has_baseline = first is not None and now - aware(first) >= timedelta(hours=24)
    for login in accepted[:60]:
        ip, user, method = login["ip"], login.get("user") or "", login.get("method") or ""
        try:
            ts = datetime.fromisoformat(login.get("ts") or "")
            ts = aware(ts) if abs((aware(ts) - now).total_seconds()) < 7 * 86400 else now
        except ValueError:
            ts = now
        seen_before = db.scalar(select(func.count()).select_from(SshLoginEvent).where(SshLoginEvent.server_id == server.id, SshLoginEvent.ip == ip)) or 0
        tried = failures.get(ip, 0)
        new_source = has_baseline and not seen_before
        key = {k: (login.get(k) or "")[:80] for k in ("key_type", "fingerprint", "key_name")}
        db.add(SshLoginEvent(server_id=server.id, ts=ts, ip=ip, user=user, method=method, failures_before=tried, new_source=new_source, kind="login", **key))
        db.flush()
        evidence = {"ip": ip, "user": user, "method": method, "failed_attempts_24h": tried, "at": ts.isoformat(), **{k: v for k, v in key.items() if v}}
        from .secalerts import config as alert_config
        if tried >= alert_config(db)["ssh_success_after_failures"]:
            finding, is_new = open_finding(db, server, f"login_breach:{ip}:{user}", kind="ssh_login_after_failures", severity="critical", source="smwatch", now=now,
                                           title=f"SSH login by {user or '?'} from {ip} after {tried} failed attempts",
                                           detail=(f"{user or 'Someone'} logged in over SSH ({method or 'unknown method'}) from {ip}, an address that failed to log in {tried} times "
                                                   "in the previous 24 hours. If this was not you, treat the server as compromised: disconnect it, rotate keys and passwords, and investigate."),
                                           evidence=evidence)
            if is_new:
                _alert(db, server, "ssh_login_breach", [f"User {user or '?'} logged in from {ip} ({method})", f"{tried} failed attempts from that address in the last 24 h",
                                                        "If this was not you, treat the server as compromised."], "critical")
        elif new_source and settings.ssh_new_source_alerts:
            finding, is_new = open_finding(db, server, f"login_new:{ip}:{user}", kind="ssh_login_new_source", severity="medium", source="smwatch", now=now,
                                           title=f"SSH login by {user or '?'} from a new address ({ip})",
                                           detail=f"First SSH login on this server from {ip}. Acknowledge it if it was you or a colleague.", evidence=evidence)
            if is_new:
                _alert(db, server, "ssh_login_new", [f"User {user or '?'} logged in from {ip} ({method})", "No login came from this address before."])


def check_daily_logins(db: Session, server, now: datetime) -> None:
    """More SSH logins on one server today than the configured limit (even legitimate ones): one finding and one alert per day."""
    from .models import SshLoginEvent
    from .secscan import schedule
    limit = int(schedule(db).get("daily_login_alert") or 0)
    if limit <= 0:
        return
    day = now.astimezone(timezone.utc).date()
    start = datetime(day.year, day.month, day.day, tzinfo=timezone.utc)
    rows = db.execute(select(SshLoginEvent.user, SshLoginEvent.ip, SshLoginEvent.key_name).where(
        SshLoginEvent.server_id == server.id, SshLoginEvent.kind == "login", SshLoginEvent.ts >= start)).all()
    if len(rows) <= limit:
        return
    who: dict[str, int] = {}
    for user, ip, key_name in rows:
        label = f"{user or '?'} from {ip}" + (f" ({key_name})" if key_name else "")
        who[label] = who.get(label, 0) + 1
    top = sorted(who.items(), key=lambda kv: -kv[1])
    detail = f"{len(rows)} SSH logins today (UTC), more than the limit of {limit}: " + ", ".join(f"{k} ×{n}" for k, n in top[:8]) + ". Even if they are legitimate, check they are expected."
    finding, is_new = open_finding(db, server, f"many_logins:{day.isoformat()}", kind="ssh_many_logins", severity="medium", source="smwatch", now=now,
                                   title=f"{len(rows)} SSH logins today (limit {limit})", detail=detail, evidence={"count": len(rows), "limit": limit, "by": dict(top[:20])})
    if is_new:
        _alert(db, server, "ssh_login_many", [f"{len(rows)} SSH logins today, more than the limit of {limit}"] + [f"{k}: {n}" for k, n in top[:5]])


def record_transfers(db: Session, server, transfers: list[dict], now: datetime) -> None:
    """File-transfer (SFTP / scp) sessions: stored like logins, and one finding per user and address per day, counting the sessions."""
    from .models import SshLoginEvent
    for t in transfers[:60]:
        try:
            ts = aware(datetime.fromisoformat(t.get("ts") or ""))
            ts = ts if abs((ts - now).total_seconds()) < 7 * 86400 else now
        except ValueError:
            ts = now
        ip, user = t.get("ip") or "", t.get("user") or ""
        db.add(SshLoginEvent(server_id=server.id, ts=ts, ip=ip or "?", user=user, method=t.get("kind") or "sftp", kind="sftp"))
        day = ts.date().isoformat()
        row, is_new = open_finding(db, server, f"transfer:{day}:{user}:{ip}", kind="file_transfer", severity="low", source="smwatch", now=now,
                                   title=f"File transfer session by {user or '?'}" + (f" from {ip}" if ip else ""),
                                   detail=f"{user or 'Someone'} opened an SFTP/scp file-transfer session" + (f" from {ip}" if ip else "") + " (files sent to or taken from this server). Acknowledge it if expected.",
                                   evidence={"user": user, "ip": ip, "sessions": 1, "day": day})
        if not is_new:
            ev = json.loads(row.evidence or "{}")
            ev["sessions"] = int(ev.get("sessions", 1)) + 1
            row.evidence = json.dumps(ev)
            row.detail = f"{user or 'Someone'} opened {ev['sessions']} SFTP/scp file-transfer sessions" + (f" from {ip}" if ip else "") + f" on {day}. Acknowledge them if expected."
    db.flush()


# ------------------------------------------------------------------------------------------------ agent threat scan
def _alert_level(db: Session | None = None) -> int:
    from .database import SessionLocal
    from .secalerts import config
    if db is None:
        with SessionLocal() as own:
            level = config(own)["threat_severity"]
    else:
        level = config(db)["threat_severity"]
    return -1 if level == "off" else SEVERITY_ORDER.get(level, 1)


def sync_threats(db: Session, server, report: dict, previous: dict | None, now: datetime) -> None:
    """Applies one threat-scan result: opens new findings (alerting on serious ones), refreshes those still present, resolves agent
    findings that are gone, and turns SSH keys that appeared since the previous scan into findings."""
    from .models import SecurityFinding
    if previous and previous.get("checked_at") == report.get("checked_at"):
        return                                                  # the same cached scan, re-sent with the next report: nothing new
    level = _alert_level(db)
    present = set()
    for f in report.get("findings") or []:
        key = f"agent:{f['key']}"
        present.add(key)
        evidence = {k: f[k] for k in ("pid", "process", "user", "path", "command", "remote", "packages") if f.get(k)}
        row, is_new = open_finding(db, server, key, kind=f["kind"], severity=f["severity"], title=f["title"], detail=f.get("detail") or "", evidence=evidence, source="agent", now=now)
        if is_new and SEVERITY_ORDER[f["severity"]] <= level:
            lines = [f["title"], f.get("detail") or ""]
            if f.get("path"):
                lines.append(f"Path: {f['path']}")
            _alert(db, server, "threat", lines, "critical" if f["severity"] == "critical" else "warning")
    for row in db.scalars(select(SecurityFinding).where(SecurityFinding.server_id == server.id, SecurityFinding.source == "agent", SecurityFinding.resolved_at.is_(None))).all():
        if row.key not in present:
            row.resolved_at = now
    if previous and previous.get("hardening") is not None:
        hardening_weakened(db, server, report.get("hardening") or [], previous.get("hardening") or [], now, level)
    if previous and previous.get("listening") is not None:
        ports_opened(db, server, report.get("listening") or [], previous.get("listening") or [], now, level)
    if previous and previous.get("baseline") and report.get("baseline"):
        compare_baseline(db, server, report["baseline"], previous["baseline"], previous.get("checked_at"), now, level)
    # SSH keys: compare with the previous scan (the first scan only sets the baseline)
    if previous and previous.get("authorized_keys") is not None:
        before = {(k["user"], k["fingerprint"]) for k in previous.get("authorized_keys") or []}
        for k in report.get("authorized_keys") or []:
            if (k["user"], k["fingerprint"]) not in before:
                row, is_new = open_finding(db, server, f"sshkey:{k['user']}:{k['fingerprint']}", kind="ssh_key_added", severity="high", source="smwatch", now=now,
                                           title=f"New SSH key authorized for {k['user']}",
                                           detail=(f"A {k['type']} key ({k['fingerprint']}{', comment ' + repr(k['comment']) if k['comment'] else ''}) was added to {k['file'] or 'authorized_keys'}. "
                                                   "Attackers add keys to keep access. Acknowledge it if someone on your team added it."),
                                           evidence={"user": k["user"], "fingerprint": k["fingerprint"], "type": k["type"], "comment": k["comment"], "path": k["file"]})
                if is_new:
                    _alert(db, server, "ssh_key_added", [f"User {k['user']}: {k['type']} {k['fingerprint']}" + (f" ({k['comment']})" if k["comment"] else ""), "Acknowledge it in Security → Threats if it was expected."])


def finding_view(f, server_info: dict | None = None) -> dict:
    return {"id": f.id, "server_id": f.server_id, "server": server_info, "key": f.key, "source": f.source, "kind": f.kind, "severity": f.severity, "title": f.title,
            "detail": f.detail, "evidence": json.loads(f.evidence or "{}"), "first_seen": aware(f.first_seen).isoformat(), "last_seen": aware(f.last_seen).isoformat(),
            "resolved_at": aware(f.resolved_at).isoformat() if f.resolved_at else None, "acknowledged_by": f.acknowledged_by,
            "acknowledged_at": aware(f.acknowledged_at).isoformat() if f.acknowledged_at else None, "note": f.note}


# ------------------------------------------------------------------------------------------------ changes since the previous scan (agent 2.17+)
# Like new SSH keys these are events: they stay open until acknowledged. The first scan of a server only records the baseline.
def _change(db: Session, server, key: str, kind: str, severity: str, title: str, detail: str, evidence: dict, now: datetime, level: int) -> None:
    _, is_new = open_finding(db, server, key, kind=kind, severity=severity, title=title, detail=detail, evidence=evidence, source="smwatch", now=now)
    if is_new and SEVERITY_ORDER[severity] <= level:
        _alert(db, server, "security_change", [title, detail], "critical" if severity == "critical" else "warning")


def hardening_weakened(db: Session, server, current: list[dict], previous: list[dict], now: datetime, level: int) -> None:
    """A protection that passed in the previous scan and fails now, e.g. someone turned SSH password logins back on."""
    before = {c["id"]: c for c in previous}
    for c in current:
        old = before.get(c["id"])
        if old and old.get("ok") is True and c.get("ok") is False:
            _change(db, server, f"weakened:{c['id']}:{now.date().isoformat()}", "hardening_weakened", c.get("severity") or "medium",
                    f"Protection turned off: {c['title']}", f"This passed in the previous check and fails now. {c.get('detail') or ''} If nobody on your team changed it, investigate.",
                    {"check": c["id"]}, now, level)


def ports_opened(db: Session, server, current: list[dict], previous: list[dict], now: datetime, level: int) -> None:
    """A service that started accepting connections from every network since the previous scan."""
    from .secscan import PORTS
    before = {p["port"] for p in previous if p.get("all_interfaces")}       # also catches a port moved from localhost to every network
    for p in current:
        if not p.get("all_interfaces") or p["port"] in before:
            continue
        label, risk, advice = PORTS.get(p["port"], (None, "medium", ""))
        severity = "high" if risk == "critical" else "medium"
        what = f"{label} ({p['port']})" if label else f"port {p['port']}"
        _change(db, server, f"port_opened:{p['port']}:{p.get('process') or ''}", "port_opened", severity, f"New service open to every network: {what}",
                f"{p.get('process') or 'A program'} started accepting connections on {what} from any address. {advice} Acknowledge it if you opened it on purpose.",
                {"port": p["port"], "process": p.get("process") or ""}, now, level)


SENSITIVE_FILES = ("/etc/sudoers", "/etc/sudoers.d/", "/etc/pam.d/", "/etc/ld.so.preload")
LOGIN_FILES = ("/etc/ssh/sshd_config", "/etc/passwd", "/etc/shadow", "/etc/group")


def compare_baseline(db: Session, server, current: dict, previous: dict, previous_at: str | None, now: datetime, level: int) -> None:
    """New accounts and administrators, changed critical files and system programs, newly loaded kernel modules."""
    updated = False                                            # were packages installed between the two scans? (programs legitimately change then)
    try:
        if current.get("packages_changed_at") and previous_at:
            updated = datetime.fromisoformat(current["packages_changed_at"]) >= datetime.fromisoformat(previous_at) - timedelta(minutes=1)
    except ValueError:
        updated = True
    old_users = {a["user"] for a in previous.get("accounts") or []}
    for a in current.get("accounts") or []:
        if a["user"] not in old_users:
            root = a.get("uid") == 0
            _change(db, server, f"user_added:{a['user']}", "user_added", "critical" if root else "high", f"New account that can log in: {a['user']}" + (" (root rights)" if root else ""),
                    f"The account {a['user']} (uid {a.get('uid')}, shell {a.get('shell') or '?'}) was created since the previous check. Attackers create accounts to come back. "
                    "Acknowledge it if someone on your team added it.", {"user": a["user"], "uid": a.get("uid"), "shell": a.get("shell")}, now, level)
    old_admins = previous.get("admins") or {}
    for group, members in (current.get("admins") or {}).items():
        for user in set(members) - set(old_admins.get(group) or []):
            what = "can control Docker (equivalent to root)" if group in ("docker", "lxd") else "can now run commands as root"
            _change(db, server, f"admin_granted:{group}:{user}", "admin_granted", "high", f"{user} was added to the {group} group",
                    f"{user} {what}. If you did not grant this, someone with access may be preparing to keep root rights.", {"user": user, "group": group}, now, level)
    old_files = previous.get("files") or {}
    for path, fp in (current.get("files") or {}).items():
        if path not in old_files and not path.startswith(("/etc/sudoers.d/", "/etc/ld.so.preload")):
            continue                                           # a file that just was not readable before; new sudoers rules or a preload file always count
        if old_files.get(path) == fp:
            continue
        severity = "high" if path.startswith(SENSITIVE_FILES) else "medium" if path.startswith(LOGIN_FILES) else "low"
        if updated and severity != "high":
            severity = "low"
        _change(db, server, f"file_changed:{path}:{fp}", "critical_file_changed", severity, f"Security file changed: {path}",
                f"{path} " + ("was created" if path not in old_files else "was changed") + " since the previous check"
                + (" (packages were also updated, which can explain it)" if updated else "") + ". It controls who can log in or become root; check the change was yours.",
                {"path": path}, now, level)
    old_programs = previous.get("programs") or {}
    if not updated:
        for path, fp in (current.get("programs") or {}).items():
            if old_programs.get(path) and old_programs[path] != fp:
                _change(db, server, f"program_changed:{path}:{fp}", "system_program_changed", "critical", f"System program replaced: {path}",
                        f"{path} changed but no package was installed or updated. Rootkits replace programs like ps, ls, ssh or sudo to hide themselves or steal passwords. "
                        "Compare it with the package (debsums / rpm -V) before trusting this server.", {"path": path}, now, level)
    new_modules = sorted(set(current.get("modules") or []) - set(previous.get("modules") or []))
    if previous.get("modules") and new_modules:
        _change(db, server, f"kmod:{','.join(new_modules[:10])}"[:200], "kernel_module_loaded", "medium", f"Kernel module loaded: {', '.join(new_modules[:5])}",
                "New code was loaded into the kernel since the previous check (" + ", ".join(new_modules[:20]) + "). Usually a driver or Docker networking; rootkits load modules too.",
                {"modules": new_modules[:40]}, now, level)
