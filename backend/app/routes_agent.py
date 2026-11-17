"""Endpoints used by installed agents: report ingest, installer script, agent source."""
import hashlib
from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from fastapi.responses import PlainTextResponse, Response
from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from .database import get_db
import json

from .models import Server, TrafficSample
from .performance import breach_text, measure_server_traffic, traffic_bounds
from .monitoring import apply_server_result, evaluate_metrics
from .schemas import AgentReport
from . import log_policy as policy_lib
from .audit import audit
from .config import get_settings
from .security import agent_gate, client_ip, login_limiter

router = APIRouter(prefix="/api/agent", tags=["agent"])
ROOT = Path(__file__).resolve().parent.parent


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


@router.post("/report")
def report(payload: AgentReport, request: Request, authorization: str | None = Header(default=None), db: Session = Depends(get_db)) -> dict:
    gate = agent_gate(request, "agent")   # throttles token guessing; valid agents never increment it
    token = authorization[7:] if authorization and authorization.startswith("Bearer ") else ""
    digest = hash_token(token) if token else None
    server = db.scalar(select(Server).where(or_(Server.token_hash == digest, Server.pending_token_hash == digest), Server.monitor_mode == "push")) if digest else None
    if server is None:
        if login_limiter.fail_unique(gate, digest or ""):   # one audit line per wrong token, not one per request (no log flooding)
            audit(db, request, "agent.auth_failed", actor="agent:unknown", detail="report with an unknown token", success=False, commit=True)
        raise HTTPException(401, "Invalid agent token")
    if not server.enabled:
        raise HTTPException(403, "This server monitor is disabled")
    now = datetime.now(timezone.utc)
    if server.last_seen_at and (now - (server.last_seen_at if server.last_seen_at.tzinfo else server.last_seen_at.replace(tzinfo=timezone.utc))).total_seconds() < get_settings().agent_min_report_seconds:
        raise HTTPException(429, "Reporting too frequently", headers={"Retry-After": "2"})   # a compromised agent must not be able to flood the database

    reply: dict = {"ok": True}
    # --- token rotation: the new token wins the moment the agent proves it has it; until then the agent is told about it
    if server.pending_token_hash and digest == server.pending_token_hash:
        server.agent_token, server.token_hash, server.token_issued_at = server.pending_token, server.pending_token_hash, now
        server.pending_token = server.pending_token_hash = server.pending_token_at = None
        audit(db, request, "agent.token_rotated", actor=f"agent:{server.name}", target=f"server:{server.id}", detail="agent switched to the new token; the old one is now invalid")
    elif server.pending_token_hash:
        reply["rotate_token"] = server.pending_token

    # --- where is this token being used from? A change is worth a look (a stolen token would show up from a new address)
    ip = client_ip(request)
    if server.last_agent_ip and server.last_agent_ip != ip:
        audit(db, request, "agent.ip_changed", actor=f"agent:{server.name}", target=f"server:{server.id}", detail=f"{server.last_agent_ip} -> {ip}")
    server.last_agent_ip = ip

    metrics = payload.model_dump()
    traffic = metrics.pop("traffic", None)   # stored in its own table, not in the host metrics JSON
    failures_seen = metrics.pop("ssh_failures", None)
    previous_security = None
    try:
        previous_security = (json.loads(server.last_metrics or "{}") or {}).get("security")
    except ValueError:
        pass
    metrics["received_at"] = now.isoformat()
    try:
        status, failures = evaluate_metrics(server, metrics)
    except ValueError as error:
        raise HTTPException(422, str(error)) from error
    server.last_seen_at = now
    if traffic and traffic["requests"] > 0:
        db.add(TrafficSample(server_id=server.id, ts=now, bounds=json.dumps(traffic["bounds"]), counts=json.dumps(traffic["counts"]),
                             **{k: traffic[k] for k in ("window_seconds", "requests", "errors_5xx", "errors_4xx", "sum_ms", "max_ms", "upstream_sum_ms", "upstream_count")}))
        db.flush()
    if failures_seen and failures_seen["total"]:
        from .secscan import record_ssh_failures
        record_ssh_failures(db, server, failures_seen, now)
    if failures_seen and failures_seen.get("accepted"):
        from .threats import record_logins
        record_logins(db, server, failures_seen["accepted"], now)
    if metrics.get("security"):
        from .threats import sync_threats
        sync_threats(db, server, metrics["security"], previous_security, now)
    slow = measure_server_traffic(db, server) if server.perf_threshold_ms else None   # this server's response-time target (real traffic)
    if slow and slow["breaching"]:
        failures = [*failures, breach_text(slow, "responses")]
        status = "alert"
    # deliver=False: alerts are queued and sent by the worker so ingest stays fast.
    apply_server_result(db, server, status, failures, metrics, deliver=False)
    db.commit()
    reply["traffic_buckets_ms"] = traffic_bounds()
    from .secscan import agent_config
    reply["security"] = agent_config(db, server.id)   # how often to run the threat scan / update check, and "scan now" requests   # the agent uses these histogram boundaries from its next report on
    reply["log_policy"] = policy_lib.compile_for_agent(policy_lib.parse(server.log_policy))   # the agent enforces this too
    return {**reply, "status": status, "interval_seconds": server.check_interval_seconds}


@router.get("/install.sh", response_class=PlainTextResponse)
def install_script() -> str:
    return (ROOT / "agent_install.sh").read_text()


@router.get("/agent.py")
def agent_source() -> Response:
    return Response(content=(ROOT / "agent.py").read_bytes(), media_type="text/plain; charset=utf-8")   # exact bytes: the installer checks their SHA-256
