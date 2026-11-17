"""QA: DNS records and domain registration.

- Records (A, AAAA, CNAME, MX, NS, TXT, CAA, SOA) are looked up every interval and compared with the accepted set ("baseline").
  A change raises an alert and keeps the monitor in "alert" until someone accepts the new records (or they change back).
  A domain that no longer resolves (NXDOMAIN) is "down".
- The registration's expiry date comes from RDAP (the registries' JSON successor of WHOIS, via rdap.org). Alerts at each threshold
  (default 30 / 14 / 7 days), and when it has expired. Some country domains have no RDAP service: then only records are watched.
"""
from __future__ import annotations

import json
import re
import urllib.request
from datetime import datetime, timedelta, timezone

from .config import get_settings
from .netguard import safe_urlopen

RECORD_TYPES = ("A", "AAAA", "CNAME", "MX", "NS", "TXT", "CAA", "SOA")
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?!-)([A-Za-z0-9-]{1,63}(?<!-)\.)+[A-Za-z]{2,63}\.?$")


def normalise(domain: str) -> str:
    return domain.strip().lower().rstrip(".")


def lookup(domain: str, types: list[str]) -> tuple[dict[str, list[str]], str | None, bool]:
    """({type: sorted values}, error, missing_domain)."""
    import dns.exception
    import dns.resolver
    resolver = dns.resolver.Resolver()
    servers = [s.strip() for s in get_settings().dns_resolvers.split(",") if s.strip()]
    if servers:
        resolver.nameservers = servers
    resolver.lifetime = 6
    out: dict[str, list[str]] = {}
    errors = []
    for kind in types:
        try:
            answer = resolver.resolve(domain, kind, raise_on_no_answer=False)
            values = []
            for r in answer:
                if kind == "MX":
                    values.append(f"{r.preference} {str(r.exchange).rstrip('.').lower()}")
                elif kind in ("NS", "CNAME"):
                    values.append(str(r.target).rstrip(".").lower())
                elif kind == "TXT":
                    values.append(b"".join(r.strings).decode("utf-8", "replace"))
                elif kind == "SOA":   # the serial changes with every edit: watch only who is authoritative
                    values.append(f"{str(r.mname).rstrip('.').lower()} {str(r.rname).rstrip('.').lower()}")
                else:
                    values.append(r.to_text().lower())
            out[kind] = sorted(set(values))
        except dns.resolver.NXDOMAIN:
            return {}, f"{domain} does not exist (NXDOMAIN)", True
        except (dns.resolver.NoNameservers, dns.exception.Timeout) as error:
            errors.append(f"{kind}: {error.__class__.__name__}")
        except dns.exception.DNSException as error:
            errors.append(f"{kind}: {str(error)[:100]}")
    return out, ("; ".join(errors) or None), False


def diff(old: dict[str, list[str]], new: dict[str, list[str]]) -> list[str]:
    lines = []
    for kind in sorted(set(old) | set(new)):
        a, b = set(old.get(kind, [])), set(new.get(kind, []))
        for v in sorted(b - a):
            lines.append(f"{kind} added: {v}")
        for v in sorted(a - b):
            lines.append(f"{kind} removed: {v}")
    return lines


def rdap(domain: str) -> dict:
    """Registration data for the registrable part of `domain` (tries shorter names until a registry answers)."""
    labels = normalise(domain).split(".")
    last_error = "no RDAP service for this domain"
    for start in range(0, max(1, len(labels) - 1)):
        name = ".".join(labels[start:])
        if name.count(".") < 1:
            break
        request = urllib.request.Request(f"https://rdap.org/domain/{name}", headers={"Accept": "application/rdap+json", "User-Agent": "SM-Watch/1.0"})
        try:
            with safe_urlopen(request, timeout=10) as response:
                data = json.loads(response.read(500_000))
        except urllib.error.HTTPError as error:
            last_error = f"RDAP answered HTTP {error.code}" if error.code != 404 else "no RDAP record (the registry may not offer RDAP)"
            continue
        except Exception as error:   # noqa: BLE001
            last_error = str(getattr(error, "reason", error))[:200]
            continue
        expires = None
        for event in data.get("events") or []:
            if event.get("eventAction") in ("expiration", "registration expiration") and event.get("eventDate"):
                expires = datetime.fromisoformat(event["eventDate"].replace("Z", "+00:00"))
        registrar = None
        for entity in data.get("entities") or []:
            if "registrar" in (entity.get("roles") or []):
                for item in ((entity.get("vcardArray") or [None, []])[1] or []):
                    if isinstance(item, list) and item and item[0] == "fn":
                        registrar = str(item[3])[:200]
        if expires is None:
            return {"name": name, "error": "the registry does not publish an expiry date", "registrar": registrar}
        return {"name": name, "expires_at": expires, "registrar": registrar}
    return {"error": last_error}


def check(monitor, force_expiry: bool = False) -> dict:
    """Pure network I/O (safe in a worker thread)."""
    types = [t for t in (monitor.record_types or "").split(",") if t in RECORD_TYPES] or ["A"]
    records, error, missing = lookup(normalise(monitor.domain), types)
    result = {"records": records, "error": error, "missing": missing}
    checked = monitor.expiry_checked_at
    if checked is not None and checked.tzinfo is None:
        checked = checked.replace(tzinfo=timezone.utc)
    if monitor.check_expiry and (force_expiry or checked is None or datetime.now(timezone.utc) - checked > timedelta(hours=12)):
        result["expiry"] = rdap(monitor.domain)
    return result


def thresholds(monitor) -> list[int]:
    raw = monitor.expiry_alert_days or get_settings().cert_alert_days
    try:
        return sorted({int(d) for d in raw.split(",") if d.strip()}, reverse=True) or [30, 14, 7]
    except ValueError:
        return [30, 14, 7]


def apply_result(session, monitor, result: dict) -> None:
    from .monitoring import format_alert, outage_seconds, queue_event, record_result, reminder_minutes, settle_status, should_notify_again, sync_incident
    now = datetime.now(timezone.utc)
    previous = monitor.last_status
    monitor.last_checked_at = now
    records = result["records"]
    host = monitor.domain
    # ---- expiry
    expiry = result.get("expiry")
    if expiry is not None:
        monitor.expiry_checked_at = now
        if expiry.get("expires_at"):
            old = monitor.domain_expires_at.replace(tzinfo=timezone.utc) if monitor.domain_expires_at and not monitor.domain_expires_at.tzinfo else monitor.domain_expires_at
            monitor.domain_expires_at, monitor.registrar, monitor.expiry_error = expiry["expires_at"], expiry.get("registrar"), None
            if old and expiry["expires_at"] > old + timedelta(days=1):
                if monitor.expiry_alerted is not None:
                    queue_event(session, "dns", monitor, "info", format_alert("Domain", "domain_renewed", monitor.name, [f"{expiry.get('name', host)} is now registered until {expiry['expires_at']:%d %b %Y}"], at=now), deliver=True, state="domain_renewed")
                monitor.expiry_alerted = None
            days_left = (expiry["expires_at"] - now).total_seconds() / 86400
            level = -1 if days_left < 0 else min([d for d in thresholds(monitor) if days_left <= d], default=None)
            if level is not None and (monitor.expiry_alerted is None or level < monitor.expiry_alerted):
                monitor.expiry_alerted = level
                if level == -1:
                    queue_event(session, "dns", monitor, "critical", format_alert("Domain", "domain_expired", monitor.name, [f"{expiry.get('name', host)} expired on {expiry['expires_at']:%d %b %Y}", "Renew it with the registrar now: the website and email stop working."], at=now), deliver=True, state="domain_expired")
                else:
                    queue_event(session, "dns", monitor, "warning", format_alert("Domain", "domain", monitor.name, [f"{expiry.get('name', host)} expires in {int(days_left)} days ({expiry['expires_at']:%d %b %Y})"] + ([f"Registrar: {monitor.registrar}"] if monitor.registrar else []), at=now), deliver=True, state="domain")
        else:
            monitor.expiry_error = expiry.get("error")
    # ---- records
    if result["missing"]:
        raw, detail = "down", result["error"]
    elif not records and result["error"]:
        raw, detail = "down", f"DNS lookup failed: {result['error']}"
    else:
        current = json.dumps(records, sort_keys=True)
        if monitor.baseline is None:
            monitor.baseline = current
        if current != (monitor.current or monitor.baseline):
            monitor.changed_at = now
        monitor.current = current
        changes = diff(json.loads(monitor.baseline), records)
        expired = monitor.domain_expires_at is not None and (monitor.domain_expires_at if monitor.domain_expires_at.tzinfo else monitor.domain_expires_at.replace(tzinfo=timezone.utc)) < now
        raw = "down" if expired else ("alert" if changes else "up")
        detail = "The domain registration has expired" if expired else ("; ".join(changes)[:900] if changes else None)
    record_result(session, "dns", monitor.id, raw, None, None, detail)
    status = settle_status(monitor, raw)
    if status == previous and raw == "down" and previous != "down":
        session.commit()
        return
    monitor.last_status, monitor.last_error = status, detail
    resolved = sync_incident(session, "dns", monitor, status, detail, alert_title=f"DNS records of {monitor.domain} changed")
    if status in ("down", "alert") and (previous != status or should_notify_again(session, "dns", monitor.id, reminder_minutes(monitor))):
        state = status if previous != status else f"still_{status}"
        if status == "alert":
            lines = [f"DNS records of {monitor.domain} no longer match the accepted set:"] + (detail or "").split("; ")[:8] + ["If this change was intended, press Accept in SM-Watch."]
            queue_event(session, "dns", monitor, "warning", format_alert("DNS", "dns_changed" if state == "alert" else state, monitor.name, lines, at=now), deliver=True, state=state)
        else:
            queue_event(session, "dns", monitor, "critical", format_alert("DNS", state, monitor.name, detail, at=now), deliver=True, state=state)
    elif status == "up" and previous in ("down", "alert"):
        queue_event(session, "dns", monitor, "info", format_alert("DNS", "recovered", monitor.name, "Records match the accepted set again", at=now, duration=outage_seconds(resolved)), deliver=True, state="recovered")
    session.commit()
