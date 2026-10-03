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
from datetime import datetime, timezone

from sqlalchemy import select

from .config import get_settings
from .database import SessionLocal
from .models import AlertEvent, Channel, Server, Service

logger = logging.getLogger(__name__)


def icmp_checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    total = (total >> 16) + (total & 0xFFFF)
    total += total >> 16
    return (~total) & 0xFFFF


def ping_host(host: str) -> bool:
    ping = shutil.which("ping")
    if ping:
        result = subprocess.run([ping, "-c", "1", "-W", "2", host], capture_output=True, timeout=5)
        return result.returncode == 0

    # Minimal IPv4 ICMP echo fallback for slim containers without iputils.
    # The worker container needs CAP_NET_RAW for this socket.
    try:
        destination = socket.gethostbyname(host)
        identifier = (os.getpid() ^ int(time.time() * 1000)) & 0xFFFF
        sequence = 1
        payload = b"northstar-ping"
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
                    return True
    except socket.timeout:
        return False
    except PermissionError as error:
        raise RuntimeError("ICMP ping requires NET_RAW capability on the worker container") from error


def check_server(server: Server) -> tuple[str, list[str], dict]:
    if not ping_host(server.host):
        raise ConnectionError(f"Ping failed for {server.host}")
    if server.monitor_mode == "ping":
        return "up", [], {"hostname": server.host, "reachability": "reachable"}
    request = urllib.request.Request(server.endpoint.rstrip("/") + "/metrics")
    if server.agent_token:
        request.add_header("Authorization", f"Bearer {server.agent_token}")
    with urllib.request.urlopen(request, timeout=8) as response:
        metrics = json.loads(response.read().decode())
    required_metrics = ("cpu", "memory", "disk", "load", "swap")
    missing_metrics = [name for name in required_metrics if name not in metrics]
    if missing_metrics:
        raise ValueError(f"Agent response is missing required metrics: {', '.join(missing_metrics)}")
    checks = [("CPU", metrics.get("cpu", 0), server.cpu_threshold, "%"), ("Memory", metrics.get("memory", 0), server.memory_threshold, "%"), ("Disk", metrics.get("disk", 0), server.disk_threshold, "%"), ("Load", metrics.get("load", 0), server.load_threshold, ""), ("Swap", metrics.get("swap", 0), server.swap_threshold, "%")]
    failures = [f"{name} {value}{unit} >= {threshold}{unit}" for name, value, threshold, unit in checks if value >= threshold]
    configured_processes = {name.strip().lower() for name in server.process_names.split(",") if name.strip()}
    process_failures = [item for item in metrics.get("processes", []) if item["cpu"] >= server.process_threshold and (not configured_processes or item["name"].lower() in configured_processes)]
    failures.extend(f"Process {item['name']} PID {item['pid']} CPU {item['cpu']}% >= {server.process_threshold}%" for item in process_failures)
    return ("alert" if failures else "up", failures, metrics)


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
                errors.append(f"{channel.name}: {detail}")
        except Exception as error:
            errors.append(f"{channel.name}: {str(error)[:250]}")
    return sent, ("; ".join(errors)[:1000] if errors and not sent else None)


def post_json(url: str, payload: dict, token: str = "") -> tuple[bool, str]:
    headers = {"Content-Type": "application/json", "User-Agent": "Northstar-Monitor/1.0"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(url, data=json.dumps(payload).encode(), headers=headers, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
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
            "components": [{"type": "body", "parameters": [{"type": "text", "text": text[:900]}]}],
        },
    }
    return post_json(url, payload, channel.token)


def deliver_channel(channel: Channel, text: str) -> tuple[bool, str]:
    if channel.type == "telegram":
        if not channel.token or not channel.chat_id:
            return False, "missing bot token or chat/group ID"
        body = urllib.parse.urlencode({"chat_id": channel.chat_id, "text": text}).encode()
        request = urllib.request.Request(f"https://api.telegram.org/bot{channel.token}/sendMessage", data=body, method="POST")
        try:
            with urllib.request.urlopen(request, timeout=8) as response:
                result = json.loads(response.read().decode())
        except HTTPError as error:
            try:
                result = json.loads(error.read().decode())
                return False, result.get("description", f"HTTP {error.code}")
            except (ValueError, OSError):
                return False, f"HTTP {error.code}"
        if result.get("ok"):
            return True, "Delivered"
        return False, result.get("description", "Telegram rejected the alert")
    if channel.type == "slack":
        if not channel.endpoint:
            return False, "Slack Incoming Webhook URL is missing"
        return post_json(channel.endpoint, {"text": text})
    if channel.type == "webhook":
        if not channel.endpoint:
            return False, "Webhook URL is missing"
        payload = {"source": "Northstar Operations", "text": text, "sent_at": datetime.now(timezone.utc).isoformat()}
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
    message = f"Northstar test notification · {channel.name}"
    try:
        delivered, detail = deliver_channel(channel, message)
    except Exception as error:
        return False, str(error)[:300]
    if not delivered:
        return False, detail
    labels = {"telegram": "Telegram", "webhook": "Webhook", "slack": "Slack", "whatsapp": "WhatsApp"}
    return True, f"{labels.get(channel.type, channel.type)} test notification delivered"


def check_service(service: Service, session) -> dict:
    previous_status = service.last_status
    started = time.perf_counter()
    http_status = None
    error_message = None
    try:
        request = urllib.request.Request(service.url, headers={"User-Agent": "Northstar-Uptime/1.0"})
        try:
            with urllib.request.urlopen(request, timeout=10) as response:
                http_status = response.status
        except HTTPError as response_error:
            http_status = response_error.code
            response_error.close()
        service.last_latency_ms = round((time.perf_counter() - started) * 1000, 1)
        service.last_http_status = http_status
        service.last_status = "up" if http_status == service.expected_status else "down"
        if service.last_status == "down":
            error_message = f"Expected HTTP {service.expected_status}; received HTTP {http_status}"
    except Exception as error:
        service.last_latency_ms = round((time.perf_counter() - started) * 1000, 1)
        service.last_http_status = None
        service.last_status = "down"
        error_message = str(error)[:500]

    service.last_error = error_message
    service.last_checked_at = datetime.now(timezone.utc)
    if service.last_status == "down":
        heading = "Service down" if previous_status != "down" else "Service still down"
        message = f"<b>{heading}: {service.name}</b>\n{error_message}\nChecked at {service.last_checked_at.isoformat()}\n{service.url}"
        event = AlertEvent(target_type="service", target_id=service.id, severity="critical", message=message)
        session.add(event)
        session.flush()
        deliver_event(event, session)
    elif service.last_status == "up" and previous_status == "down":
        message = f"<b>Service recovered: {service.name}</b>\nHTTP {http_status} in {service.last_latency_ms} ms\n{service.url}"
        event = AlertEvent(target_type="service", target_id=service.id, severity="info", message=message)
        session.add(event)
        session.flush()
        deliver_event(event, session)
    session.commit()
    return {"id": service.id, "name": service.name, "url": service.url, "status": service.last_status, "http_status": service.last_http_status, "expected_status": service.expected_status, "latency_ms": service.last_latency_ms, "error": service.last_error, "checked_at": service.last_checked_at.isoformat()}


def is_due(last_checked_at, interval_seconds: int) -> bool:
    if last_checked_at is None:
        return True
    checked_at = last_checked_at
    if checked_at.tzinfo is None:
        checked_at = checked_at.replace(tzinfo=timezone.utc)
    return (datetime.now(timezone.utc) - checked_at).total_seconds() >= interval_seconds


def run_once() -> None:
    session = SessionLocal()
    try:
        for server in session.scalars(select(Server).where(Server.enabled.is_(True))):
            if not is_due(server.last_checked_at, server.check_interval_seconds):
                continue
            previous = server.last_status
            try:
                status, failures, metrics = check_server(server)
                server.last_status = status
                server.last_error = None
                server.last_metrics = json.dumps(metrics)
                server.last_checked_at = datetime.now(timezone.utc)
                if failures:
                    heading = "Server alert" if previous != "alert" else "Server still in alert"
                    message = f"<b>{heading}: {server.name}</b>\n" + "\n".join(failures)
                    message += f"\nChecked at {server.last_checked_at.isoformat()}"
                    event = AlertEvent(target_type="server", target_id=server.id, severity="critical", message=message)
                    session.add(event)
                    session.flush()
                    deliver_event(event, session)
                elif not failures and previous in ("down", "alert"):
                    message = f"<b>Server recovered: {server.name}</b>\nHost reachable and resource checks are within configured thresholds."
                    event = AlertEvent(target_type="server", target_id=server.id, severity="info", message=message)
                    session.add(event)
                    session.flush()
                    deliver_event(event, session)
            except Exception as error:
                server.last_status = "down"
                server.last_error = str(error)[:500]
                server.last_checked_at = datetime.now(timezone.utc)
                heading = "Server down" if previous != "down" else "Server still down"
                message = f"<b>{heading}: {server.name}</b>\n{server.last_error}\nChecked at {server.last_checked_at.isoformat()}"
                event = AlertEvent(target_type="server", target_id=server.id, severity="critical", message=message)
                session.add(event)
                session.flush()
                deliver_event(event, session)
        for service in session.scalars(select(Service).where(Service.enabled.is_(True))):
            if is_due(service.last_checked_at, service.interval_seconds):
                check_service(service, session)
        retry_pending_alerts(session)
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

    pending = session.scalars(select(AlertEvent).where(AlertEvent.sent.is_(False), AlertEvent.delivery_attempts < 10)).all()
    now = datetime.now(timezone.utc)
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
    logger.info("monitor worker started scheduler_poll_seconds=1")
    while True:
        try:
            run_once()
        except Exception:
            logger.exception("monitor cycle failed")
        time.sleep(1)
