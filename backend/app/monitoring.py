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
from .models import AlertEvent, Channel, CheckResult, Incident, LogRequest, MetricSample, Server, Service
from .netguard import safe_urlopen, validate_host

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
        metrics = json.loads(response.read().decode())
    status, failures = evaluate_metrics(server, metrics)
    metrics["latency_ms"] = latency
    return status, failures, metrics


def redact(text: str, channel: Channel) -> str:
    """Strip channel secrets (e.g. the Telegram bot token embedded in the API URL) from error text."""
    for secret in (channel.token, channel.endpoint):
        if secret:
            text = text.replace(secret, "***")
    return re.sub(r"/bot\d+:[A-Za-z0-9_-]+", "/bot***", text)


def send_alert(message: str, session) -> tuple[bool, str | None]:
    channels = session.scalars(select(Channel).where(Channel.enabled.is_(True))).all()
    if not channels:
        return False, "No enabled notification channels are configured"

    text = re.sub(r"</?b>", "", message)
    errors = []
    sent = False
    for channel in channels:
        try:
            delivered, detail = deliver_channel(channel, text)
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


def deliver_channel(channel: Channel, text: str) -> tuple[bool, str]:
    if channel.type == "telegram":
        if not channel.token or not channel.chat_id:
            return False, "missing bot token or chat/group ID"
        body = urllib.parse.urlencode({"chat_id": channel.chat_id, "text": text}).encode()
        request = urllib.request.Request(f"https://api.telegram.org/bot{channel.token}/sendMessage", data=body, method="POST")
        try:
            with safe_urlopen(request, timeout=8) as response:
                result = json.loads(response.read().decode())
        except HTTPError as error:
            try:
                result = json.loads(error.read().decode())
                return False, telegram_hint(result.get("description", f"HTTP {error.code}"))
            except (ValueError, OSError):
                return False, f"HTTP {error.code}"
        if result.get("ok"):
            return True, "Delivered"
        return False, telegram_hint(result.get("description", "Telegram rejected the alert"))
    if channel.type == "slack":
        if not channel.endpoint:
            return False, "Slack Incoming Webhook URL is missing"
        return post_json(channel.endpoint, {"text": text})
    if channel.type == "webhook":
        if not channel.endpoint:
            return False, "Webhook URL is missing"
        payload = {"source": "SM-Watch", "text": text, "sent_at": datetime.now(timezone.utc).isoformat()}
        return post_json(channel.endpoint, payload, channel.token or "")
    if channel.type == "whatsapp":
        return send_whatsapp(channel, text)
    return False, f"Unsupported notification type: {channel.type}"


def deliver_event(event: AlertEvent, session) -> None:
    event.delivery_attempts = (event.delivery_attempts or 0) + 1
    event.last_attempt_at = datetime.now(timezone.utc)
    event.sent, event.delivery_error = send_alert(event.message, session)
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


def probe_service(service: Service) -> dict:
    """HTTP probe. Pure network I/O; safe to run in a worker thread."""
    started = time.perf_counter()
    http_status = None
    error_message = None
    status = "down"
    try:
        request = urllib.request.Request(service.url, headers={"User-Agent": "SM-Watch-Uptime/1.0"})
        try:
            with safe_urlopen(request, timeout=10) as response:
                http_status = response.status
        except HTTPError as response_error:
            http_status = response_error.code
            response_error.close()
        status = "up" if http_status == service.expected_status else "down"
        if status == "down":
            error_message = f"Expected HTTP {service.expected_status}; received HTTP {http_status}"
    except Exception as error:
        error_message = str(error)[:500]
    return {"status": status, "http_status": http_status, "latency_ms": round((time.perf_counter() - started) * 1000, 1), "error": error_message}


def record_result(session, target_type: str, target_id: int, status: str, latency_ms=None, http_status=None, error=None) -> None:
    session.add(CheckResult(target_type=target_type, target_id=target_id, status=status, latency_ms=latency_ms, http_status=http_status, error=(error or None) and error[:1000]))


def sync_incident(session, target_type: str, target, status: str, detail: str | None) -> None:
    """Keeps exactly one open incident per target while it is failing; resolves it on recovery."""
    open_incident = session.scalar(
        select(Incident).where(Incident.target_type == target_type, Incident.target_id == target.id, Incident.resolved_at.is_(None))
    )
    if status in ("down", "alert"):
        severity = "critical" if status == "down" else "warning"
        noun = "service" if target_type == "service" else "server"
        title = f"{target.name} is down" if status == "down" else f"{target.name} is over its resource thresholds"
        if open_incident is None:
            session.add(Incident(target_type=target_type, target_id=target.id, target_name=target.name, severity=severity, title=title, detail=(detail or "")[:1000], started_at=datetime.now(timezone.utc)))
        else:
            open_incident.severity, open_incident.title, open_incident.detail = severity, title, (detail or "")[:1000]
    elif open_incident is not None:
        open_incident.resolved_at = datetime.now(timezone.utc)


def queue_event(session, target_type: str, target, severity: str, message: str, deliver: bool) -> None:
    event = AlertEvent(target_type=target_type, target_id=target.id, severity=severity, message=message)
    session.add(event)
    session.flush()
    if deliver:
        deliver_event(event, session)


def settle_status(target, raw_status: str) -> str:
    """Debounce: a healthy target must fail `alert_after_failures` checks in a row before it is published as down."""
    if raw_status != "down":
        target.fail_count = 0
        return raw_status
    target.fail_count = (target.fail_count or 0) + 1
    if target.fail_count < get_settings().alert_after_failures and target.last_status in ("up", "alert"):
        return target.last_status
    return "down"


def should_notify_again(session, target_type: str, target_id: int) -> bool:
    """Repeat alerts for a still-failing target at most once per reminder window."""
    latest = session.scalar(
        select(AlertEvent.created_at).where(AlertEvent.target_type == target_type, AlertEvent.target_id == target_id, AlertEvent.severity == "critical").order_by(AlertEvent.id.desc()).limit(1)
    )
    if latest is None:
        return True
    latest = latest if latest.tzinfo else latest.replace(tzinfo=timezone.utc)
    return datetime.now(timezone.utc) - latest >= timedelta(minutes=get_settings().reminder_minutes)


def apply_service_result(session, service: Service, result: dict) -> dict:
    previous_status = service.last_status
    raw_status = result["status"]
    now = datetime.now(timezone.utc)
    record_result(session, "service", service.id, raw_status, result["latency_ms"], result["http_status"], result["error"])
    service.last_checked_at = now
    status = settle_status(service, raw_status)
    if status == previous_status and raw_status == "down" and previous_status != "down":
        # Failure absorbed by the debounce: history keeps it, but no state change, incident or alert yet.
        session.commit()
        return _service_payload(service, raw_status, result, now, held=True)
    service.last_latency_ms = result["latency_ms"]
    service.last_http_status = result["http_status"]
    service.last_status = status
    service.last_error = result["error"]
    sync_incident(session, "service", service, status, service.last_error)
    if status == "down":
        if previous_status != "down" or should_notify_again(session, "service", service.id):
            heading = "Service down" if previous_status != "down" else "Service still down"
            queue_event(session, "service", service, "critical", f"<b>{heading}: {service.name}</b>\n{service.last_error}\nChecked at {now.isoformat()}\n{service.url}", deliver=True)
    elif previous_status == "down":
        queue_event(session, "service", service, "info", f"<b>Service recovered: {service.name}</b>\nHTTP {service.last_http_status} in {service.last_latency_ms} ms\n{service.url}", deliver=True)
    session.commit()
    return _service_payload(service, status, result, now)


def _service_payload(service: Service, status: str, result: dict, now: datetime, held: bool = False) -> dict:
    return {"id": service.id, "name": service.name, "url": service.url, "status": result["status"] if held else status, "http_status": result["http_status"], "expected_status": service.expected_status, "latency_ms": result["latency_ms"], "error": result["error"], "checked_at": now.isoformat(), "held": held}


def check_service(service: Service, session) -> dict:
    return apply_service_result(session, service, probe_service(service))


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
    status = settle_status(server, raw_status) if debounce else raw_status
    if debounce is False and raw_status == "down":
        server.fail_count = (server.fail_count or 0) + 1
    if status == previous and raw_status == "down" and previous != "down":
        return  # failure absorbed by the debounce; recorded in history only
    server.last_status = status
    server.last_error = error
    if metrics is not None:
        server.last_metrics = json.dumps(metrics)
        if all(key in metrics for key in ("cpu", "memory", "disk", "load", "swap")):  # ping-only checks carry no resource metrics
            session.add(MetricSample(server_id=server.id, ts=now, cpu=metrics["cpu"], memory=metrics["memory"], disk=metrics["disk"], load=metrics["load"], swap=metrics["swap"], net_rx_bps=metrics.get("net_rx_bps"), net_tx_bps=metrics.get("net_tx_bps")))
    sync_incident(session, "server", server, status, detail)
    stamp = f"\nChecked at {now.isoformat()}"
    if status == "down":
        if previous != "down" or should_notify_again(session, "server", server.id):
            heading = "Server down" if previous != "down" else "Server still down"
            queue_event(session, "server", server, "critical", f"<b>{heading}: {server.name}</b>\n{error}{stamp}", deliver)
    elif status == "alert":
        if previous != "alert" or should_notify_again(session, "server", server.id):
            heading = "Server alert" if previous != "alert" else "Server still in alert"
            queue_event(session, "server", server, "critical", f"<b>{heading}: {server.name}</b>\n" + "\n".join(failures) + stamp, deliver)
    elif previous in ("down", "alert"):
        queue_event(session, "server", server, "info", f"<b>Server recovered: {server.name}</b>\nHost reachable and resource checks are within configured thresholds.", deliver)


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
    return max(30, interval_seconds * 3)


def run_once() -> None:
    """One scheduler tick: probe everything that is due concurrently, then apply results serially."""
    session = SessionLocal()
    try:
        servers = session.scalars(select(Server).where(Server.enabled.is_(True))).all()
        pull_servers = [s for s in servers if s.monitor_mode != "push" and is_due(s.last_checked_at, s.check_interval_seconds)]
        services = [s for s in session.scalars(select(Service).where(Service.enabled.is_(True))).all() if is_due(s.last_checked_at, s.interval_seconds)]

        pool = get_pool()
        server_futures = [(s, pool.submit(_probe_server, s)) for s in pull_servers]
        service_futures = [(s, pool.submit(probe_service, s)) for s in services]

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
        retry_pending_alerts(session)
        session.commit()
        from .scheduler import run_due_schedules
        run_due_schedules(session)
    finally:
        session.close()


def prune_history() -> None:
    settings = get_settings()
    now = datetime.now(timezone.utc)
    session = SessionLocal()
    try:
        session.execute(delete(CheckResult).where(CheckResult.checked_at < now - timedelta(days=settings.check_retention_days)))
        session.execute(delete(MetricSample).where(MetricSample.ts < now - timedelta(days=settings.metric_retention_days)))
        session.execute(delete(LogRequest).where(LogRequest.created_at < now - timedelta(minutes=15)))  # fetched logs are never archived
        session.commit()
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


def run_forever() -> None:
    logger.info("monitor worker started scheduler_poll_seconds=1 concurrency=%s", get_settings().worker_concurrency)
    last_prune = 0.0
    while True:
        try:
            run_once()
            if time.monotonic() - last_prune > 3600:
                prune_history()
                last_prune = time.monotonic()
        except Exception:
            logger.exception("monitor cycle failed")
        time.sleep(1)
