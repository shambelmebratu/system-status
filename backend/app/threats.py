"""Signs of compromise: suspicious successful SSH logins, the agent's threat findings (malware, persistence), and newly authorized SSH keys.

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
        db.add(SshLoginEvent(server_id=server.id, ts=ts, ip=ip, user=user, method=method, failures_before=tried, new_source=new_source))
        db.flush()
        evidence = {"ip": ip, "user": user, "method": method, "failed_attempts_24h": tried, "at": ts.isoformat()}
        if tried >= settings.ssh_success_after_failures:
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


# ------------------------------------------------------------------------------------------------ agent threat scan
def _alert_level() -> int:
    level = get_settings().threat_alert_severity.lower()
    return -1 if level == "off" else SEVERITY_ORDER.get(level, 1)


def sync_threats(db: Session, server, report: dict, previous: dict | None, now: datetime) -> None:
    """Applies one threat-scan result: opens new findings (alerting on serious ones), refreshes those still present, resolves agent
    findings that are gone, and turns SSH keys that appeared since the previous scan into findings."""
    from .models import SecurityFinding
    if previous and previous.get("checked_at") == report.get("checked_at"):
        return                                                  # the same cached scan, re-sent with the next report: nothing new
    level = _alert_level()
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
