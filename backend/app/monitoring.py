import html
import json
import logging
import os
import re
import shutil
import socket
import subprocess
import struct
import time
import urllib.parse
import urllib.request
from urllib.error import HTTPError
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

from sqlalchemy import delete, select

from .config import get_settings
from .database import SessionLocal
from .models import AlertEvent, AuditEvent, Channel, CheckResult, ClusterSample, Incident, K8sRequest, LogRequest, MetricSample, Server, Service
from .netguard import fetch_certificate, safe_urlopen, validate_host

logger = logging.getLogger(__name__)


def icmp_checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    total = (total >> 16) + (total & 0xFFFF)
    total += total >> 16
    return (~total) & 0xFFFF


def ping_host(host: str, attempts: int = 3) -> float | None:
    """Round-trip time in ms when the host answers, None when it does not. Retries so a single dropped
    packet is not reported as an outage."""
    validate_host(host)
    for attempt in range(attempts):
        latency = _ping_once(host)
        if latency is not None:
            return latency
        if attempt < attempts - 1:
            time.sleep(0.5)
    return None


def _ping_once(host: str) -> float | None:
    ping = shutil.which("ping")
    if ping:
        started = time.perf_counter()
        result = subprocess.run([ping, "-c", "1", "-W", "2", "--", host], capture_output=True, timeout=5)
        if result.returncode != 0:
            return None
        match = re.search(rb"time[=<]([0-9.]+)", result.stdout)
        return float(match.group(1)) if match else round((time.perf_counter() - started) * 1000, 1)

    # Minimal IPv4 ICMP echo fallback for slim containers without iputils.
    # The worker container needs CAP_NET_RAW for this socket.
    try:
        destination = socket.gethostbyname(host)
        identifier = (os.getpid() ^ int(time.time() * 1000)) & 0xFFFF
        sequence = 1
        started = time.perf_counter()
        payload = b"sm-watch-ping"
        header = struct.pack("!BBHHH", 8, 0, 0, identifier, sequence)
        checksum = icmp_checksum(header + payload)
        packet = struct.pack("!BBHHH", 8, 0, checksum, identifier, sequence) + payload
        with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP) as sock:
            sock.settimeout(2.0)
            sock.sendto(packet, (destination, 1))
            while True:
                reply, _ = sock.recvfrom(2048)
                ip_header_length = (reply[0] & 0x0F) * 4
                icmp_type, _, _, reply_id, reply_sequence = struct.unpack("!BBHHH", reply[ip_header_length:ip_header_length + 8])
                if icmp_type == 0 and reply_id == identifier and reply_sequence == sequence:
                    return round((time.perf_counter() - started) * 1000, 1)
    except socket.timeout:
        return None
    except PermissionError as error:
        raise RuntimeError("ICMP ping requires NET_RAW capability on the worker container") from error


def evaluate_metrics(server: Server, metrics: dict) -> tuple[str, list[str]]:
    """Compares a metrics payload to the server's thresholds. Shared by pull checks and push reports."""
    required_metrics = ("cpu", "memory", "disk", "load", "swap")
    missing_metrics = [name for name in required_metrics if name not in metrics]
    if missing_metrics:
        raise ValueError(f"Agent response is missing required metrics: {', '.join(missing_metrics)}")
    checks = [("CPU", metrics["cpu"], server.cpu_threshold, "%"), ("Memory", metrics["memory"], server.memory_threshold, "%"), ("Disk", metrics["disk"], server.disk_threshold, "%"), ("Load", metrics["load"], server.load_threshold, ""), ("Swap", metrics["swap"], server.swap_threshold, "%")]
    failures = [f"{name} {value}{unit} >= {threshold}{unit}" for name, value, threshold, unit in checks if value >= threshold]
    configured_processes = {name.strip().lower() for name in server.process_names.split(",") if name.strip()}
    process_failures = [item for item in metrics.get("processes", []) if item["cpu"] >= server.process_threshold and (not configured_processes or item["name"].lower() in configured_processes)]
    failures.extend(f"Process {item['name']} PID {item['pid']} CPU {item['cpu']}% >= {server.process_threshold}%" for item in process_failures)
    return ("alert" if failures else "up", failures)


def check_server(server: Server) -> tuple[str, list[str], dict]:
    """Pull-mode poll (ping, or ping + agent /metrics). Pure network I/O; safe to run in a worker thread."""
    latency = ping_host(server.host)
    if latency is None:
        raise ConnectionError(f"Ping failed for {server.host}")
    if server.monitor_mode == "ping":
        return "up", [], {"hostname": server.host, "reachability": "reachable", "latency_ms": latency}
    request = urllib.request.Request(server.endpoint.rstrip("/") + "/metrics")
    if server.agent_token:
        request.add_header("Authorization", f"Bearer {server.agent_token}")
    with safe_urlopen(request, timeout=8) as response:
        raw = response.read(1_000_001)   # a metrics answer is a few KB: never buffer an endless response
    if len(raw) > 1_000_000:
        raise ValueError("Agent response is too large")
    metrics = json.loads(raw.decode())
    status, failures = evaluate_metrics(server, metrics)
    metrics["latency_ms"] = latency
    return status, failures, metrics


def redact(text: str, channel: Channel) -> str:
    """Strip channel secrets (e.g. the Telegram bot token embedded in the API URL) from error text."""
    for secret in (channel.token, channel.endpoint):
        if secret:
            text = text.replace(secret, "***")
    return re.sub(r"/bot\d+:[A-Za-z0-9_-]+", "/bot***", text)


# ------------------------------------------------------------------------------------------------ alert message format
# Alerts are stored with a tiny markup (<b>..</b>, everything else HTML-escaped) and rendered per channel:
# Telegram gets real bold text, Slack gets *bold*, webhooks and WhatsApp get plain text.
_STATE = {"anomaly": ("📈", "UNUSUAL BEHAVIOUR"), "ai_note": ("🤖", "AI ANALYSIS"),
          "ssh_attack": ("🛡", "SSH BRUTE-FORCE ATTACK"), "security_finding": ("🛡", "SECURITY FINDING"),
          "ssh_login_breach": ("🚨", "POSSIBLE BREAK-IN: SSH LOGIN AFTER FAILED ATTEMPTS"), "ssh_login_new": ("🔑", "SSH LOGIN FROM A NEW ADDRESS"),
          "threat": ("🚨", "POSSIBLE COMPROMISE"), "ssh_login_many": ("🔁", "MANY SSH LOGINS TODAY"), "ssh_key_added": ("🔑", "NEW SSH KEY AUTHORIZED"), "security_change": ("🛡", "SECURITY CHANGE"),
          "slo_fast": ("🔥", "ERROR BUDGET BURNING FAST"), "slo_slow": ("🟠", "ERROR BUDGET BURNING"), "slo_exhausted": ("⛔", "ERROR BUDGET EXHAUSTED"),
          "dns_changed": ("🧭", "DNS CHANGED"), "domain": ("🌐", "DOMAIN EXPIRES SOON"), "domain_expired": ("⛔", "DOMAIN EXPIRED"), "domain_renewed": ("✅", "DOMAIN RENEWED"),
          "cert": ("🔐", "CERTIFICATE EXPIRES SOON"), "cert_expired": ("⛔", "CERTIFICATE EXPIRED"), "cert_renewed": ("✅", "CERTIFICATE RENEWED"),
          "down": ("🔴", "DOWN"), "still_down": ("🔴", "STILL DOWN"), "alert": ("🟠", "ALERT"), "still_alert": ("🟠", "STILL IN ALERT"), "recovered": ("✅", "RECOVERED")}


def esc(value) -> str:
    return html.escape(str(value), quote=False)


def human_duration(seconds: float) -> str:
    seconds = max(0, int(seconds))
    days, rest = divmod(seconds, 86400)
    hours, rest = divmod(rest, 3600)
    minutes, secs = divmod(rest, 60)
    parts = [f"{days}d" if days else "", f"{hours}h" if hours else "", f"{minutes}m" if minutes else "", f"{secs}s" if secs and not days and not hours else ""]
    return " ".join(p for p in parts if p) or "0s"


def tidy_reason(line: str) -> str:
    line = re.sub(r"\bPID (\d+)", r"(PID \1)", str(line))
    return line.replace(" >= ", " ≥ ")


def format_alert(kind: str, state: str, name: str, lines: list[str] | str | None = None, *, at: datetime | None = None, link: str | None = None, duration: float | None = None, where: str | None = None) -> str:
    """kind: Server / Service / Cluster. state: down, still_down, alert, still_alert, recovered."""
    icon, label = _STATE[state]
    when = (at or datetime.now(timezone.utc)).astimezone(timezone.utc).strftime("%d %b %Y, %H:%M UTC")
    out = [f"{icon} <b>{label}</b> · {esc(kind)}", f"<b>{esc(name)}</b>"]
    if where and where != name:
        out.append(f"🖥 {esc(where)}")
    items = [lines] if isinstance(lines, str) else [x for x in (lines or []) if x]
    if len(items) == 1:
        out.append(esc(tidy_reason(items[0])))
    elif items:
        out.extend(f"• {esc(tidy_reason(x))}" for x in items[:8])
        if len(items) > 8:
            out.append(f"• … and {len(items) - 8} more")
    if duration is not None:
        out.append(f"⏱ Was affected for {human_duration(duration)}")
    out.append(f"🕒 {when}")
    if link:
        out.append(f"🔗 {esc(link)}")
    return "\n".join(out)


def server_addresses(server) -> dict:
    """{"public_ip": str|None, "private_ips": [str]}. The public address is the one the control plane sees the agent connect from
    (when it is publicly routable), or the one an admin configured on the agent; private ones are the agent's own LAN addresses."""
    import ipaddress
    try:
        metrics = json.loads(server.last_metrics) if server.last_metrics else {}
    except ValueError:
        metrics = {}

    from .netinfo import control_plane_public_ip, in_container_network, is_public

    def is_global(value) -> bool:
        return is_public(value)

    reported = []
    for entry in metrics.get("ips") or []:
        ip = entry.get("ip") if isinstance(entry, dict) else None
        if ip and ip not in reported:
            reported.append(ip)
    # An address on the machine's own interface that is publicly routable IS its public address (typical for a VPS), not a private one.
    on_interface_public = [ip for ip in reported if ipaddress.ip_address(ip).is_global]
    private = [ip for ip in reported if ip not in on_interface_public]
    seen = (server.last_agent_ip or "").strip()
    colocated = metrics.get("install") == "bundled" or in_container_network(seen)   # runs next to the control plane (shares its Docker network)
    configured = metrics.get("public_ip") if is_global(metrics.get("public_ip")) else None
    public = configured or (on_interface_public[0] if on_interface_public else None) or next((c for c in (seen, (server.host or "").strip()) if c and is_global(c)), None)
    if not public and colocated:   # then its public address is the control plane's own
        public = control_plane_public_ip() or None
    if not private and seen and not colocated:   # an older agent that reports no addresses: the LAN address it connects from
        try:
            ip = ipaddress.ip_address(seen)
            if ip.is_private and not ip.is_loopback and ip not in ipaddress.ip_network("172.16.0.0/12"):   # (container-network noise)
                private.append(seen)
        except ValueError:
            pass
    rank = lambda ip: 0 if ipaddress.ip_address(ip).is_private and not ipaddress.ip_address(ip) in ipaddress.ip_network("100.64.0.0/10") else 1  # noqa: E731
    private = sorted(dict.fromkeys(private), key=rank)
    return {"public_ip": public, "private_ips": [p for p in private if p != public]}


def server_where(server) -> str | None:
    """Where a server is, for alerts: its host name and its public address (its private one only when it has no public one)."""
    try:
        metrics = json.loads(server.last_metrics) if server.last_metrics else {}
    except ValueError:
        metrics = {}
    addr = server_addresses(server)
    parts = [str(metrics.get("hostname") or "").strip(), addr["public_ip"] or (addr["private_ips"][0] if addr["private_ips"] else "")]
    unique = []
    for part in parts:
        if part and part not in unique and part.lower() != str(server.name).lower():
            unique.append(part)
    return " · ".join(unique) or None


def plain_text(message: str) -> str:
    return html.unescape(re.sub(r"</?b>", "", message))


def slack_text(message: str) -> str:
    return html.unescape(re.sub(r"</?b>", "*", message))


ALERT_KINDS = ("server", "service", "cluster", "test", "dns", "heartbeat")
ALERT_EVENTS = ("down", "alert", "recovered", "reminder")


def event_category(state: str | None) -> str | None:
    """down / alert / recovered / reminder (a repeat while something is still failing). None for events from before routing existed."""
    if not state:
        return None
    if state.startswith(("cert", "domain", "dns_", "slo_", "ssh_attack", "ssh_login", "ssh_key", "threat", "security_", "anomaly", "ai_")):   # certificate / domain / DNS warnings travel with "over a limit" alerts; renewals with recoveries
        return "recovered" if state.endswith("_renewed") else "alert"
    return "reminder" if state.startswith("still_") else state


def channel_wants(channel: Channel, target_type: str | None, state: str | None) -> bool:
    """A channel with no selection receives everything; otherwise only the kinds and events ticked for it."""
    kinds = [k for k in (channel.notify_kinds or "").split(",") if k]
    events = [e for e in (channel.notify_events or "").split(",") if e]
    category = event_category(state)
    if kinds and target_type and target_type not in kinds:
        return False
    if events and category and category not in events:
        return False
    return True


NOT_ROUTED = "Not sent: no channel is set to receive this kind of alert"
MONITOR_MUTED = "Not sent: this monitor is set not to send this kind of alert"

# Which alert types each kind of monitor can produce (a service has no "over a limit"; a ping-only host cannot go over a limit either).
APPLICABLE_EVENTS = {kind: ("down", "alert", "recovered", "reminder") for kind in ALERT_KINDS}


def csv_list(value: str | None) -> list[str]:
    return [v for v in (value or "").split(",") if v]


def alert_columns(values: dict, target_type: str) -> dict:
    """alert_events / alert_channels travel as lists and are stored comma-separated. Selecting everything (or nothing) is stored as
    NULL = inherit, so a later new channel or alert type is picked up automatically."""
    events = values.get("alert_events") or []
    everything = APPLICABLE_EVENTS[target_type]
    values["alert_events"] = ",".join(e for e in events if e in everything) if events and set(everything) - set(events) else None
    values["alert_events"] = values["alert_events"] or None
    channels = values.get("alert_channels") or []
    values["alert_channels"] = ",".join(str(c) for c in channels) if channels else None
    return values


def reminder_minutes(target) -> int:
    """How long to wait before repeating an alert for this monitor: its own setting, else REMINDER_MINUTES. 0 = never repeat."""
    own = getattr(target, "alert_reminder_minutes", None)
    return get_settings().reminder_minutes if own is None else own


def target_allows(target, state: str | None) -> bool:
    events = csv_list(getattr(target, "alert_events", None))
    category = event_category(state)
    return not (events and category and category not in events)


def target_channel_ids(target) -> set[int] | None:
    ids = {int(c) for c in csv_list(getattr(target, "alert_channels", None)) if c.isdigit()}
    return ids or None


def target_of(session, target_type: str, target_id: int):
    from .models import ApiTest, Cluster, DnsMonitor, Heartbeat
    model = {"server": Server, "service": Service, "cluster": Cluster, "test": ApiTest, "dns": DnsMonitor, "heartbeat": Heartbeat}.get(target_type)
    return session.get(model, target_id) if model else None


def send_alert(message: str, session, target_type: str | None = None, state: str | None = None, only_channels: set[int] | None = None) -> tuple[bool, str | None]:
    channels = session.scalars(select(Channel).where(Channel.enabled.is_(True))).all()
    if not channels:
        return False, "No enabled notification channels are configured"
    if only_channels:   # this monitor sends to specific channels only
        channels = [c for c in channels if c.id in only_channels]
        if not channels:
            return False, "Not sent: none of the channels chosen for this monitor is enabled"
    channels = [c for c in channels if channel_wants(c, target_type, state)]
    if not channels:
        return False, NOT_ROUTED

    errors = []
    sent = False
    for channel in channels:
        try:
            delivered, detail = deliver_channel(channel, message, rich=True)
            if delivered:
                sent = True
            else:
                errors.append(f"{channel.name}: {redact(str(detail), channel)}")
        except Exception as error:
            errors.append(f"{channel.name}: {redact(str(error), channel)[:250]}")
    return sent, ("; ".join(errors)[:1000] if errors and not sent else None)


def post_json(url: str, payload: dict, token: str = "") -> tuple[bool, str]:
    headers = {"Content-Type": "application/json", "User-Agent": "SM-Watch-Monitor/1.0"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(url, data=json.dumps(payload).encode(), headers=headers, method="POST")
    try:
        with safe_urlopen(request, timeout=10) as response:
            body = response.read(2048).decode(errors="replace").strip()
            if not 200 <= response.status < 300:
                return False, f"HTTP {response.status}: {body[:200]}"
            if body and body.lower() not in ("ok", "ok."):
                try:
                    result = json.loads(body)
                    if result.get("ok") is False or result.get("success") is False:
                        return False, str(result.get("error") or result.get("message") or body)[:250]
                except ValueError:
                    pass
            return True, "Delivered"
    except HTTPError as error:
        detail = error.read(1024).decode(errors="replace")
        return False, f"HTTP {error.code}: {detail[:200]}"


def send_whatsapp(channel: Channel, text: str) -> tuple[bool, str]:
    if not channel.token or not channel.phone_number_id or not channel.chat_id or not channel.template_name:
        return False, "WhatsApp needs access token, phone number ID, recipient, and approved template name"
    url = f"https://graph.facebook.com/v23.0/{channel.phone_number_id}/messages"
    payload = {
        "messaging_product": "whatsapp",
        "to": channel.chat_id,
        "type": "template",
        "template": {
            "name": channel.template_name,
            "language": {"code": channel.template_language or "en_US"},
            "components": [{"type": "body", "parameters": [{"type": "text", "text": re.sub(r"\s*[\r\n\t]+\s*", " | ", text)[:900]}]}],
        },
    }
    return post_json(url, payload, channel.token)


def telegram_hint(description: str) -> str:
    lowered = description.lower()
    if "chat not found" in lowered:
        return description + ". The bot cannot see this chat: add the bot to the group (as an admin for channels), send a message in it, then use “Find chat ID” to get the right ID."
    if "unauthorized" in lowered:
        return description + ". The bot token is wrong or was revoked."
    if "kicked" in lowered or "not a member" in lowered or "forbidden" in lowered:
        return description + ". The bot was removed from, or blocked in, this chat."
    return description


def discover_telegram_chats(token: str) -> dict:
    """Lists chats the bot has recently seen (read-only; does not consume updates)."""
    def call(method: str) -> dict:
        try:
            with safe_urlopen(urllib.request.Request(f"https://api.telegram.org/bot{token}/{method}"), timeout=10) as response:
                return json.loads(response.read().decode())
        except HTTPError as error:
            try:
                return json.loads(error.read().decode())
            except (ValueError, OSError):
                return {"ok": False, "description": f"HTTP {error.code}"}
    me = call("getMe")
    if not me.get("ok"):
        raise ValueError(telegram_hint(me.get("description", "Telegram rejected the token")))
    chats: dict[int, dict] = {}
    for update in call("getUpdates").get("result", []):
        for key in ("message", "edited_message", "channel_post", "my_chat_member"):
            chat = (update.get(key) or {}).get("chat")
            if chat:
                chats[chat["id"]] = {"id": chat["id"], "type": chat.get("type"), "title": chat.get("title") or chat.get("username") or chat.get("first_name") or str(chat["id"])}
    return {"bot": me["result"].get("username"), "chats": list(chats.values())}


def deliver_channel(channel: Channel, text: str, rich: bool = False) -> tuple[bool, str]:
    """rich=True: `text` carries the alert markup (<b>, escaped HTML) and is rendered for the channel; otherwise it is plain text."""
    if channel.type == "telegram":
        if not channel.token or not channel.chat_id:
            return False, "missing bot token or chat/group ID"
        fields = {"chat_id": channel.chat_id, "text": text, "disable_web_page_preview": "true"}
        if rich:
            fields["parse_mode"] = "HTML"
        request = urllib.request.Request(f"https://api.telegram.org/bot{channel.token}/sendMessage", data=urllib.parse.urlencode(fields).encode(), method="POST")
        try:
            with safe_urlopen(request, timeout=8) as response:
                result = json.loads(response.read().decode())
        except HTTPError as error:
            try:
                result = json.loads(error.read().decode())
            except (ValueError, OSError):
                return False, f"HTTP {error.code}"
            if rich and "parse entities" in str(result.get("description", "")).lower():
                return deliver_channel(channel, plain_text(text))     # an old stored message with unescaped markup: send it as plain text
            return False, telegram_hint(result.get("description", f"HTTP {error.code}"))
        if result.get("ok"):
            return True, "Delivered"
        return False, telegram_hint(result.get("description", "Telegram rejected the alert"))
    if channel.type == "slack":
        if not channel.endpoint:
            return False, "Slack Incoming Webhook URL is missing"
        return post_json(channel.endpoint, {"text": slack_text(text) if rich else text})
    if channel.type == "webhook":
        if not channel.endpoint:
            return False, "Webhook URL is missing"
        payload = {"source": "SM-Watch", "text": plain_text(text) if rich else text, "sent_at": datetime.now(timezone.utc).isoformat()}
        return post_json(channel.endpoint, payload, channel.token or "")
    if channel.type == "whatsapp":
        return send_whatsapp(channel, plain_text(text) if rich else text)
    return False, f"Unsupported notification type: {channel.type}"


def deliver_event(event: AlertEvent, session) -> None:
    event.delivery_attempts = (event.delivery_attempts or 0) + 1
    event.last_attempt_at = datetime.now(timezone.utc)
    target = target_of(session, event.target_type, event.target_id)
    if target is not None and not target_allows(target, event.state):
        event.sent, event.delivery_error, event.delivery_attempts = False, MONITOR_MUTED, 10   # a choice made on the monitor, never retried
        return
    paused = pause_state(target) if target is not None else None
    if paused:   # someone paused this monitor: recorded, never sent or retried
        event.sent, event.delivery_error, event.delivery_attempts = False, "Not sent: the monitor is paused" + (f" by {target.paused_by}" if target.paused_by else ""), 10
        return
    from . import secalerts
    off = secalerts.blocked(session, event.state, event.target_type)
    if off:      # this kind of security alert is turned off in Security → Alerts
        event.sent, event.delivery_error, event.delivery_attempts = False, off, 10
        return
    from .devops import in_maintenance
    window = in_maintenance(session, event.target_type, event.target_id)
    if window is not None:   # planned work: the alert is recorded but not sent
        event.sent, event.delivery_error, event.delivery_attempts = False, f"Not sent: maintenance window \"{window}\"", 10
        return
    channels = secalerts.channels_for(session, event.state, event.target_type)
    if channels is None:
        channels = target_channel_ids(target) if target is not None else None
    event.sent, event.delivery_error = send_alert(event.message, session, event.target_type, event.state, channels)
    if (event.delivery_error or "").startswith("Not sent:"):
        event.delivery_attempts = 10   # a deliberate choice, not a failure: never retried
        return
    if event.sent:
        logger.info("alert delivered event_id=%s target=%s:%s attempt=%s", event.id, event.target_type, event.target_id, event.delivery_attempts)
    else:
        logger.error("alert delivery failed event_id=%s target=%s:%s attempt=%s reason=%s", event.id, event.target_type, event.target_id, event.delivery_attempts, event.delivery_error)


def send_channel_test(channel: Channel) -> tuple[bool, str]:
    message = f"SM-Watch test notification · {channel.name}"
    try:
        delivered, detail = deliver_channel(channel, message)
    except Exception as error:
        return False, redact(str(error), channel)[:300]
    if not delivered:
        return False, redact(str(detail), channel)
    labels = {"telegram": "Telegram", "webhook": "Webhook", "slack": "Slack", "whatsapp": "WhatsApp"}
    return True, f"{labels.get(channel.type, channel.type)} test notification delivered"


def service_timeout(service: Service) -> float:
    """Seconds (fractions allowed): the service's own limit in milliseconds, else the older whole-second one, else SERVICE_TIMEOUT_SECONDS."""
    if getattr(service, "timeout_ms", None):
        return service.timeout_ms / 1000
    return float(service.timeout_seconds or get_settings().service_timeout_seconds)


def fmt_limit(seconds: float) -> str:
    return f"{round(seconds * 1000)} ms" if seconds < 10 else f"{seconds:g} s"


# ------------------------------------------------------------------------------------------------ pause
def pause_state(target, now: datetime | None = None) -> str | None:
    """"monitor" (no checks, no alerts) or "alerts" (checked, alerts muted) while a pause is active, else None."""
    mode = getattr(target, "pause_mode", None)
    if not mode:
        return None
    until = target.paused_until
    if until is not None:
        until = until if until.tzinfo else until.replace(tzinfo=timezone.utc)
        if until <= (now or datetime.now(timezone.utc)):
            return None
    return mode


def resume(target, now: datetime | None = None) -> None:
    """Ends a pause. A monitor that was not checked starts again as "unknown", so its first check cannot raise a stale alert."""
    was_monitor = target.pause_mode == "monitor"
    target.pause_mode = target.paused_until = target.paused_by = target.pause_reason = None
    if was_monitor:
        target.last_status, target.fail_count, target.last_checked_at = "unknown", 0, None
        if getattr(target, "monitor_mode", None) == "push":
            target.last_seen_at = now or datetime.now(timezone.utc)      # a fresh grace period before "no heartbeat" counts


def expire_pauses(session) -> None:
    """Worker: resumes monitors whose pause has run out (and writes it to the audit log)."""
    from .audit import audit
    now = datetime.now(timezone.utc)
    for model, kind in ((Server, "server"), (Service, "service")):
        for item in session.scalars(select(model).where(model.pause_mode.is_not(None), model.paused_until.is_not(None), model.paused_until <= now)).all():
            resume(item, now)
            audit(session, None, f"{kind}.resume", actor="system", target=f"{kind}:{item.id}", detail=f"{item.name}: pause ended")


def cert_thresholds(service: Service) -> list[int]:
    raw = service.cert_alert_days or get_settings().cert_alert_days
    try:
        days = sorted({int(d) for d in str(raw).split(",") if d.strip()}, reverse=True)
        return [d for d in days if 1 <= d <= 365] or [30, 14, 7]
    except ValueError:
        return [30, 14, 7]


def cert_due(service: Service, force: bool = False) -> bool:
    if not service.cert_check or not service.url.lower().startswith("https://"):
        return False
    if force or service.cert_checked_at is None:
        return True
    checked = service.cert_checked_at if service.cert_checked_at.tzinfo else service.cert_checked_at.replace(tzinfo=timezone.utc)
    return datetime.now(timezone.utc) - checked >= timedelta(hours=max(1, get_settings().cert_check_hours))


def probe_service(service: Service, force_cert: bool = False) -> dict:
    """HTTP probe (plus, every few hours, the certificate). Pure network I/O; safe to run in a worker thread.
    A response that takes longer than the service's timeout is a failed check, even if it eventually arrives."""
    limit = service_timeout(service)
    started = time.perf_counter()
    http_status = None
    error_message = None
    status = "down"
    body = ""
    try:
        request = urllib.request.Request(service.url, headers={"User-Agent": "SM-Watch-Uptime/1.0"})
        try:
            with safe_urlopen(request, timeout=limit) as response:
                http_status = response.status
                body = response.read(1_000_000).decode("utf-8", "replace") if service.keyword else ""
        except HTTPError as response_error:
            http_status = response_error.code
            response_error.close()
        status = "up" if http_status == service.expected_status else "down"
        if status == "down":
            error_message = f"Expected HTTP {service.expected_status}; received HTTP {http_status}"
        elif service.keyword:   # content check: the page must (or must not) contain this text, case-insensitive
            found = service.keyword.lower() in body.lower()
            if service.keyword_mode == "absent" and found:
                status, error_message = "down", f"The page contains \"{service.keyword}\", which it must not"
            elif service.keyword_mode != "absent" and not found:
                status, error_message = "down", f"Expected text \"{service.keyword}\" was not found on the page"
    except Exception as error:
        reason = getattr(error, "reason", error)
        timed_out = isinstance(reason, (TimeoutError, socket.timeout)) or "timed out" in str(error).lower()
        error_message = f"Timed out: no response within {fmt_limit(limit)}" if timed_out else str(error)[:500]
    elapsed = time.perf_counter() - started
    if status == "up" and elapsed > limit:     # a socket timeout applies per read; the whole answer must also be in time
        status, error_message = "down", f"Timed out: the response took {fmt_limit(elapsed)}, longer than the {fmt_limit(limit)} limit"
    result = {"status": status, "http_status": http_status, "latency_ms": round(elapsed * 1000, 1), "error": error_message}
    if cert_due(service, force_cert):
        try:
            result["cert"] = fetch_certificate(service.url, timeout=min(max(limit, 5), 15))
        except Exception as error:   # noqa: BLE001
            result["cert_error"] = str(error)[:300] or error.__class__.__name__
    return result


def apply_certificate(session, service: Service, result: dict) -> None:
    """Stores what the certificate check found and sends at most one alert per threshold (30 / 14 / 7 days ...) per certificate,
    one when it has expired, and one when a renewed certificate replaces one that was alerted about."""
    if "cert" not in result and "cert_error" not in result:
        return
    now = datetime.now(timezone.utc)
    service.cert_checked_at = now
    if "cert_error" in result:
        service.cert_error = result["cert_error"]
        return
    cert = result["cert"]
    expires = cert["expires_at"]
    previous = service.cert_expires_at.replace(tzinfo=timezone.utc) if service.cert_expires_at and not service.cert_expires_at.tzinfo else service.cert_expires_at
    service.cert_error = None if cert.get("host_matches", True) else f"The certificate does not cover this host name (it is for {', '.join(cert.get('names') or [cert['subject']])[:200]})"
    service.cert_issuer, service.cert_subject = cert["issuer"], cert["subject"]
    service.cert_expires_at = expires
    host = urllib.parse.urlsplit(service.url).hostname or service.url
    if previous and expires > previous + timedelta(days=1):            # renewed
        if service.cert_alerted is not None:
            queue_event(session, "service", service, "info", format_alert("Service", "cert_renewed", service.name, [f"New certificate for {host} is valid until {expires:%d %b %Y}", f"Issuer: {cert['issuer']}"], at=now, link=service.url), deliver=True, state="cert_renewed")
        service.cert_alerted = None
    days_left = (expires - now).total_seconds() / 86400
    if days_left < 0:
        level = -1
    else:
        crossed = [d for d in cert_thresholds(service) if days_left <= d]
        level = min(crossed) if crossed else None
    if level is None or (service.cert_alerted is not None and level >= service.cert_alerted):
        return
    service.cert_alerted = level
    if level == -1:
        lines = [f"The certificate for {host} expired on {expires:%d %b %Y, %H:%M UTC}", "Visitors now see a security warning. Renew it now.", f"Issuer: {cert['issuer']}"]
        queue_event(session, "service", service, "critical", format_alert("Service", "cert_expired", service.name, lines, at=now, link=service.url), deliver=True, state="cert_expired")
    else:
        whole = int(days_left)
        lines = [f"The certificate for {host} expires in {whole} day{'s' if whole != 1 else ''} ({expires:%d %b %Y})", f"Issuer: {cert['issuer']}"]
        queue_event(session, "service", service, "warning", format_alert("Service", "cert", service.name, lines, at=now, link=service.url), deliver=True, state="cert")


def record_result(session, target_type: str, target_id: int, status: str, latency_ms=None, http_status=None, error=None) -> None:
    session.add(CheckResult(target_type=target_type, target_id=target_id, status=status, latency_ms=latency_ms, http_status=http_status, error=(error or None) and error[:1000]))


def sync_incident(session, target_type: str, target, status: str, detail: str | None, alert_title: str | None = None):
    """Keeps exactly one open incident per target while it is failing; resolves it on recovery."""
    open_incident = session.scalar(
        select(Incident).where(Incident.target_type == target_type, Incident.target_id == target.id, Incident.resolved_at.is_(None))
    )
    if status in ("down", "alert"):
        severity = "critical" if status == "down" else "warning"
        noun = "service" if target_type == "service" else "server"
        title = f"{target.name} is down" if status == "down" else (alert_title or f"{target.name} is over its resource thresholds")
        if open_incident is None:
            session.add(Incident(target_type=target_type, target_id=target.id, target_name=target.name, severity=severity, title=title, detail=(detail or "")[:1000], started_at=datetime.now(timezone.utc)))
        else:
            open_incident.severity, open_incident.title, open_incident.detail = severity, title, (detail or "")[:1000]
    elif open_incident is not None:
        open_incident.resolved_at = datetime.now(timezone.utc)
        return open_incident
    return None


def outage_seconds(incident) -> float | None:
    if incident is None:
        return None
    started = incident.started_at if incident.started_at.tzinfo else incident.started_at.replace(tzinfo=timezone.utc)
    return (incident.resolved_at - started).total_seconds()


def queue_event(session, target_type: str, target, severity: str, message: str, deliver: bool, state: str | None = None) -> None:
    event = AlertEvent(target_type=target_type, target_id=target.id, severity=severity, message=message, state=state)
    session.add(event)
    session.flush()
    if deliver:
        deliver_event(event, session)


def confirm_checks(target) -> int:
    """Failed checks in a row needed before an alert: the monitor's own setting, else ALERT_AFTER_FAILURES (1 = alert at once)."""
    own = getattr(target, "confirm_checks", None)
    return max(1, int(own if own else get_settings().alert_after_failures))


def settle_status(target, raw_status: str, confirm_alerts: bool = False, from_unknown: bool = False) -> str:
    """Debounce: a healthy target must fail `confirm_checks` checks in a row before it is published as down, or (servers, with
    confirm_alerts) as over a threshold. from_unknown: also when its state is not known yet (new, or just edited), so saving a
    monitor's settings never turns the next single failure into an alert. History keeps every check; recovery is published at once."""
    bad = ("down", "alert") if confirm_alerts else ("down",)
    if raw_status not in bad:
        target.fail_count = 0
        return raw_status
    target.fail_count = (target.fail_count or 0) + 1
    holdable = (("up",) if confirm_alerts else ("up", "alert")) + (("unknown",) if from_unknown else ())
    if target.last_status in holdable and target.fail_count < confirm_checks(target):
        return target.last_status
    if raw_status == "down" and target.last_status == "alert" and target.fail_count < confirm_checks(target):
        return "alert"
    return raw_status


def should_notify_again(session, target_type: str, target_id: int, minutes: int | None = None) -> bool:
    """Repeat alerts for a still-failing target at most once per reminder window (the monitor's own, else REMINDER_MINUTES; 0 = never)."""
    minutes = get_settings().reminder_minutes if minutes is None else minutes
    latest = session.scalar(
        select(AlertEvent.created_at).where(AlertEvent.target_type == target_type, AlertEvent.target_id == target_id, AlertEvent.severity == "critical").order_by(AlertEvent.id.desc()).limit(1)
    )
    if latest is None:
        return True
    if minutes <= 0:
        return False
    latest = latest if latest.tzinfo else latest.replace(tzinfo=timezone.utc)
    return datetime.now(timezone.utc) - latest >= timedelta(minutes=minutes)


def apply_service_result(session, service: Service, result: dict) -> dict:
    previous_status = service.last_status
    raw_status = result["status"]
    now = datetime.now(timezone.utc)
    record_result(session, "service", service.id, raw_status, result["latency_ms"], result["http_status"], result["error"])
    service.last_checked_at = now
    try:
        apply_certificate(session, service, result)
    except Exception:   # a certificate problem must never stop the uptime result from being recorded
        logger.exception("certificate check failed for service id=%s", service.id)
    status = settle_status(service, raw_status, from_unknown=True)
    if status == previous_status and raw_status == "down" and previous_status != "down":
        # Failure absorbed by the debounce: history keeps it, but no state change, incident or alert yet.
        session.commit()
        return _service_payload(service, raw_status, result, now, held=True)
    service.last_latency_ms = result["latency_ms"]
    service.last_http_status = result["http_status"]
    service.last_status = status
    service.last_error = result["error"]
    if status == "up" and service.perf_threshold_ms:   # healthy, but is it fast enough? (the service's own response-time target)
        from .performance import breach_text, measure_service
        session.flush()
        slow = measure_service(session, service)
        if slow and slow["breaching"]:
            status, service.last_status, service.last_error = "alert", "alert", breach_text(slow, "responses")
    resolved = sync_incident(session, "service", service, status, service.last_error, alert_title=f"{service.name} is slow")
    if status == "alert":
        if previous_status != "alert" or should_notify_again(session, "service", service.id, reminder_minutes(service)):
            queue_event(session, "service", service, "critical", format_alert("Service", "alert" if previous_status != "alert" else "still_alert", service.name, service.last_error, at=now, link=service.url), deliver=True, state="alert" if previous_status != "alert" else "still_alert")
    elif status == "down":
        if previous_status != "down" or should_notify_again(session, "service", service.id, reminder_minutes(service)):
            queue_event(session, "service", service, "critical", format_alert("Service", "down" if previous_status != "down" else "still_down", service.name, service.last_error, at=now, link=service.url), deliver=True, state="down" if previous_status != "down" else "still_down")
    elif previous_status in ("down", "alert"):
        queue_event(session, "service", service, "info", format_alert("Service", "recovered", service.name, f"Responding again: HTTP {service.last_http_status} in {round(service.last_latency_ms or 0)} ms", at=now, link=service.url, duration=outage_seconds(resolved)), deliver=True, state="recovered")
    session.commit()
    return _service_payload(service, status, result, now)


def _service_payload(service: Service, status: str, result: dict, now: datetime, held: bool = False) -> dict:
    return {"id": service.id, "name": service.name, "url": service.url, "status": result["status"] if held else status, "http_status": result["http_status"], "expected_status": service.expected_status, "latency_ms": result["latency_ms"], "error": result["error"], "checked_at": now.isoformat(), "held": held}


def check_service(service: Service, session) -> dict:
    return apply_service_result(session, service, probe_service(service, force_cert=True))


def apply_server_result(session, server: Server, status: str, failures: list[str] | None = None, metrics: dict | None = None, error: str | None = None, deliver: bool = True, debounce: bool = True) -> None:
    """Single place where a server's state, history, incidents and alerts are updated.

    deliver=False queues the alert for the worker's retry loop (used by the API's agent ingest so a
    slow notification provider can never delay an agent report).
    """
    failures = failures or []
    previous = server.last_status
    now = datetime.now(timezone.utc)
    raw_status = status
    detail = error or "; ".join(failures) or None
    record_result(session, "server", server.id, raw_status, (metrics or {}).get("latency_ms"), None, detail)
    server.last_checked_at = now
    status = settle_status(server, raw_status, confirm_alerts=True, from_unknown=True) if debounce else raw_status
    if debounce is False and raw_status in ("down", "alert"):
        server.fail_count = (server.fail_count or 0) + 1
    if metrics is not None:   # graphs and the server page always get the latest numbers, also while a problem is being confirmed
        server.last_metrics = json.dumps(metrics)
        if all(key in metrics for key in ("cpu", "memory", "disk", "load", "swap")):  # ping-only checks carry no resource metrics
            session.add(MetricSample(server_id=server.id, ts=now, cpu=metrics["cpu"], cpu_peak=metrics.get("cpu_peak"), memory=metrics["memory"], disk=metrics["disk"], load=metrics["load"], swap=metrics["swap"], net_rx_bps=metrics.get("net_rx_bps"), net_tx_bps=metrics.get("net_tx_bps")))
    if status == previous and raw_status in ("down", "alert") and previous not in ("down", "alert"):
        return  # a problem not confirmed yet (fewer failed checks in a row than the monitor needs): history only, no alert
    server.last_status = status
    server.last_error = error
    resolved = sync_incident(session, "server", server, status, detail)
    if status == "down":
        if previous != "down" or should_notify_again(session, "server", server.id, reminder_minutes(server)):
            queue_event(session, "server", server, "critical", format_alert("Server", "down" if previous != "down" else "still_down", server.name, error, at=now, where=server_where(server)), deliver, state="down" if previous != "down" else "still_down")
    elif status == "alert":
        if previous != "alert" or should_notify_again(session, "server", server.id, reminder_minutes(server)):
            queue_event(session, "server", server, "critical", format_alert("Server", "alert" if previous != "alert" else "still_alert", server.name, failures, at=now, where=server_where(server)), deliver, state="alert" if previous != "alert" else "still_alert")
    elif previous in ("down", "alert"):
        queue_event(session, "server", server, "info", format_alert("Server", "recovered", server.name, "Host reachable and all resource checks are within their thresholds.", at=now, duration=outage_seconds(resolved), where=server_where(server)), deliver, state="recovered")


def is_due(last_checked_at, interval_seconds: int) -> bool:
    if last_checked_at is None:
        return True
    checked_at = last_checked_at
    if checked_at.tzinfo is None:
        checked_at = checked_at.replace(tzinfo=timezone.utc)
    return (datetime.now(timezone.utc) - checked_at).total_seconds() >= interval_seconds


def _probe_server(server: Server):
    try:
        return "ok", check_server(server)
    except Exception as error:
        return "error", error


_pool: ThreadPoolExecutor | None = None


def get_pool() -> ThreadPoolExecutor:
    global _pool
    if _pool is None:
        _pool = ThreadPoolExecutor(max_workers=max(1, get_settings().worker_concurrency), thread_name_prefix="probe")
    return _pool


def _defer(session, target) -> None:
    """After an internal error, push the next check out by one interval instead of retrying every second."""
    try:
        target.last_checked_at = datetime.now(timezone.utc)
        session.commit()
    except Exception:
        session.rollback()


def heartbeat_grace(interval_seconds: int) -> int:
    s = get_settings()
    return max(s.heartbeat_min_grace_seconds, interval_seconds * s.heartbeat_missed_reports)


def run_once() -> None:
    """One scheduler tick: probe everything that is due concurrently, then apply results serially."""
    session = SessionLocal()
    try:
        expire_pauses(session)
        session.commit()
        servers = [s for s in session.scalars(select(Server).where(Server.enabled.is_(True))).all() if pause_state(s) != "monitor"]
        pull_servers = [s for s in servers if s.monitor_mode != "push" and is_due(s.last_checked_at, s.check_interval_seconds)]
        services = [s for s in session.scalars(select(Service).where(Service.enabled.is_(True))).all() if pause_state(s) != "monitor" and is_due(s.last_checked_at, s.interval_seconds)]
        from . import dnsmon, qa
        from .models import ApiTest, DnsMonitor
        tests = [t for t in session.scalars(select(ApiTest).where(ApiTest.enabled.is_(True))).all() if is_due(t.last_checked_at, t.interval_seconds)]
        dns_monitors = [m for m in session.scalars(select(DnsMonitor).where(DnsMonitor.enabled.is_(True))).all() if is_due(m.last_checked_at, m.interval_seconds)]

        pool = get_pool()
        server_futures = [(s, pool.submit(_probe_server, s)) for s in pull_servers]
        service_futures = [(s, pool.submit(probe_service, s)) for s in services]
        test_futures = [(t, pool.submit(qa.run_test, json.loads(t.steps))) for t in tests]
        dns_futures = [(m, pool.submit(dnsmon.check, m)) for m in dns_monitors]

        # One bad target must never abort the cycle for the others (and a crash must not leave it re-probed every second).
        for server, future in server_futures:
            try:
                kind, value = future.result()
                if kind == "ok":
                    status, failures, metrics = value
                    apply_server_result(session, server, status, failures, metrics)
                else:
                    apply_server_result(session, server, "down", error=str(value)[:500])
                session.commit()
            except Exception:
                session.rollback()
                logger.exception("failed to record result for server id=%s", server.id)
                _defer(session, server)
        for service, future in service_futures:
            try:
                apply_service_result(session, service, future.result())
            except Exception:
                session.rollback()
                logger.exception("failed to record result for service id=%s", service.id)
                _defer(session, service)
        for kind, futures, apply in (("test", test_futures, qa.apply_test_result), ("dns", dns_futures, dnsmon.apply_result)):
            for target, future in futures:
                try:
                    apply(session, target, future.result())
                except Exception:
                    session.rollback()
                    logger.exception("failed to record result for %s id=%s", kind, target.id)
                    _defer(session, target)

        # Push-mode agents: the agent reports on its own; the worker only detects silence.
        now = datetime.now(timezone.utc)
        for server in servers:
            if server.monitor_mode != "push" or server.last_seen_at is None:
                continue
            seen = server.last_seen_at if server.last_seen_at.tzinfo else server.last_seen_at.replace(tzinfo=timezone.utc)
            silent_for = (now - seen).total_seconds()
            if silent_for > heartbeat_grace(server.check_interval_seconds) and is_due(server.last_checked_at, server.check_interval_seconds):
                apply_server_result(session, server, "down", error=f"No agent heartbeat for {int(silent_for)}s", debounce=False)
        session.commit()
        from .routes_k8s import check_cluster_heartbeats
        check_cluster_heartbeats(session)
        session.commit()
        from . import devops
        devops.check_heartbeats(session)
        devops.check_slos(session)
        retry_pending_alerts(session)
        session.commit()
        from .scheduler import run_due_schedules
        run_due_schedules(session)
    finally:
        session.close()


def prune_history() -> None:
    """Applies the admin-configured retention when the purge schedule is due (see retention.py)."""
    from .retention import run_scheduled
    from .qa import prune_runs
    session = SessionLocal()
    try:
        prune_runs(session, get_settings().test_run_retention_days)
        session.commit()
        run_scheduled(session)
    except Exception:
        session.rollback()
        logger.exception("scheduled purge failed")
    finally:
        session.close()


def retry_pending_alerts(session) -> None:
    # Re-arm pre-retry-era events only when the corresponding target is still
    # actively down and the event was never actually attempted. Historical
    # events for recovered targets are not replayed.
    active_targets = [
        ("service", Service, ("down",)),
        ("server", Server, ("down", "alert")),
    ]
    for target_type, model, statuses in active_targets:
        for target in session.scalars(select(model).where(model.last_status.in_(statuses))):
            event = session.scalar(
                select(AlertEvent)
                .where(
                    AlertEvent.target_type == target_type,
                    AlertEvent.target_id == target.id,
                    AlertEvent.severity == "critical",
                )
                .order_by(AlertEvent.id.desc())
                .limit(1)
            )
            if event and not event.sent and event.delivery_attempts >= 10 and event.last_attempt_at is None:
                event.delivery_attempts = 0
                event.delivery_error = None
                logger.info("re-arming active-down alert event_id=%s target=%s:%s", event.id, target_type, target.id)

    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(minutes=get_settings().alert_retry_minutes)
    for stale in session.scalars(select(AlertEvent).where(AlertEvent.sent.is_(False), AlertEvent.delivery_attempts < 10, AlertEvent.created_at < cutoff)).all():
        stale.delivery_attempts = 10  # stop retrying: a delayed "down" message hours later is just noise
        stale.delivery_error = ((stale.delivery_error or "") + " [expired, not retried]").strip()
    pending = session.scalars(select(AlertEvent).where(AlertEvent.sent.is_(False), AlertEvent.delivery_attempts < 10)).all()
    for event in pending:
        if event.last_attempt_at is not None:
            last_attempt = event.last_attempt_at
            if last_attempt.tzinfo is None:
                last_attempt = last_attempt.replace(tzinfo=timezone.utc)
            delay = min(300, 10 * (2 ** max(0, event.delivery_attempts - 1)))
            if (now - last_attempt).total_seconds() < delay:
                continue
        deliver_event(event, session)


def _security_loop() -> None:
    """Slow background work on its own thread, so it never delays the regular checks: storing yesterday's (and older) uptime per
    day, scheduled exposure scans and TLS audits, anomaly detection, and (when enabled) AI explanations of new incidents."""
    from . import ai, anomaly
    from .secscan import scans_due
    while True:
        from .stats import backfill_days
        for name, job in (("uptime per day", lambda s: backfill_days(s, 60)), ("security scan", scans_due), ("anomaly detection", lambda s: anomaly.run(s, ai.load(s)["anomaly_alerts"])), ("AI explanation", lambda s: get_settings().ai_enabled and ai.auto_explain(s))):
            session = SessionLocal()
            try:
                job(session)
            except Exception:
                session.rollback()
                logger.exception("%s failed", name)
            finally:
                session.close()
        time.sleep(60)


def run_forever() -> None:
    logger.info("monitor worker started scheduler_poll_seconds=1 concurrency=%s", get_settings().worker_concurrency)
    import threading
    threading.Thread(target=_security_loop, name="security-scans", daemon=True).start()
    last_prune = 0.0
    while True:
        try:
            run_once()
            if time.monotonic() - last_prune > 60:
                prune_history()
                last_prune = time.monotonic()
        except Exception:
            logger.exception("monitor cycle failed")
        time.sleep(1)
