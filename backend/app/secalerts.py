"""Security alert settings, editable by admins in Security → Alerts (defaults from .env): which kinds of security alerts are sent,
to which channels, and the limits behind them (threat severity, SSH attack threshold, break-in rule, logins per day).

Every security alert is still recorded in the delivery log; a kind that is turned off is marked "not sent" and never retried."""
from __future__ import annotations

import json
import threading
import time
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from .config import get_settings

KEY = "security_alerts"
# category -> (label, description, alert states). Kubernetes threats share the "threat" state but come from a cluster.
CATEGORIES: dict[str, tuple[str, str, tuple[str, ...]]] = {
    "threat": ("Signs of compromise", "Malware, miners, reverse shells, web shells, back doors, attacks on other machines (agent threat scan).", ("threat",)),
    "changes": ("System changes", "New accounts and administrators, edited sudoers / PAM / SSH files, replaced system programs, weakened protections, newly exposed ports.", ("security_change",)),
    "ssh_breach": ("Possible break-in", "An SSH login from an address that failed to log in many times before.", ("ssh_login_breach",)),
    "ssh_attack": ("SSH brute-force attacks", "Many failed SSH logins on one server within 10 minutes.", ("ssh_attack",)),
    "ssh_key": ("New SSH key", "A key added to authorized_keys since the previous scan.", ("ssh_key_added",)),
    "ssh_new": ("Login from a new address", "The first SSH login on a server from an address never seen there.", ("ssh_login_new",)),
    "ssh_many": ("Many logins in a day", "More SSH logins on a server in one day than the limit, even legitimate ones.", ("ssh_login_many",)),
    "exposure": ("Exposed ports and TLS problems", "New risky ports reachable from SM-Watch, and new TLS problems on https services.", ("security_finding",)),
    "kubernetes": ("Kubernetes threats", "Risky pods, privileged containers and RBAC findings in your clusters.", ("threat",)),
}
SECURITY_STATES = {state for _, _, states in CATEGORIES.values() for state in states}
SEVERITIES = ("critical", "high", "medium", "off")
_cache: dict = {"at": 0.0, "value": None}
_lock = threading.Lock()


def category_of(state: str | None, target_type: str | None) -> str | None:
    if state == "threat":
        return "kubernetes" if target_type == "cluster" else "threat"
    for key, (_, _, states) in CATEGORIES.items():
        if state in states:
            return key
    return None


def defaults(db: Session) -> dict:
    from .secscan import schedule
    s = get_settings()
    return {"enabled": True, "categories": {k: True for k in CATEGORIES}, "channels": [], "threat_severity": s.threat_alert_severity.lower(),
            "ssh_attack_threshold": s.ssh_attack_threshold, "ssh_success_after_failures": s.ssh_success_after_failures,
            "daily_login_alert": schedule(db)["daily_login_alert"], "updated_by": None, "updated_at": None}


def config(db: Session, fresh: bool = False) -> dict:
    """The effective settings: what an admin saved, else the .env defaults. Cached for 10 s (cleared on save)."""
    with _lock:
        if not fresh and _cache["value"] is not None and time.monotonic() - _cache["at"] < 10:
            return _cache["value"]
    from .models import AppSetting
    out = defaults(db)
    row = db.get(AppSetting, KEY)
    if row and row.value:
        try:
            saved = json.loads(row.value)
            out.update({k: saved[k] for k in ("enabled", "channels", "threat_severity", "ssh_attack_threshold", "ssh_success_after_failures", "updated_by", "updated_at") if k in saved})
            out["categories"] = {**out["categories"], **{k: bool(v) for k, v in (saved.get("categories") or {}).items() if k in CATEGORIES}}
        except ValueError:
            pass
    with _lock:
        _cache.update(at=time.monotonic(), value=out)
    return out


def save(db: Session, data: dict, user: str) -> dict:
    from .models import AppSetting
    from .secscan import save_schedule, schedule
    row = db.get(AppSetting, KEY) or AppSetting(key=KEY)
    stored = {k: data[k] for k in ("enabled", "categories", "channels", "threat_severity", "ssh_attack_threshold", "ssh_success_after_failures")}
    stored.update(updated_by=user, updated_at=datetime.now(timezone.utc).isoformat())
    row.value = json.dumps(stored)
    db.add(row)
    cfg = schedule(db)                                   # the daily login limit lives with the scan schedule (the agents' side)
    if cfg.get("daily_login_alert") != data["daily_login_alert"]:
        cfg["daily_login_alert"] = data["daily_login_alert"]
        save_schedule(db, cfg)
    db.flush()
    with _lock:
        _cache.update(at=0.0, value=None)
    return config(db, fresh=True)


def forget() -> None:
    with _lock:
        _cache.update(at=0.0, value=None)


def blocked(db: Session, state: str | None, target_type: str | None) -> str | None:
    """Why this security alert must not be sent (a choice in Security → Alerts), or None."""
    category = category_of(state, target_type)
    if category is None:
        return None
    cfg = config(db)
    if not cfg["enabled"]:
        return "Not sent: security alerts are turned off (Security → Alerts)"
    if not cfg["categories"].get(category, True):
        return f"Not sent: \"{CATEGORIES[category][0]}\" alerts are turned off (Security → Alerts)"
    return None


def channels_for(db: Session, state: str | None, target_type: str | None) -> set[int] | None:
    """The channels chosen for security alerts (None = the usual channels)."""
    if category_of(state, target_type) is None:
        return None
    chosen = config(db)["channels"]
    return set(chosen) if chosen else None
