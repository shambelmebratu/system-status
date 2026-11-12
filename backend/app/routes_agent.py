"""Endpoints used by installed agents: report ingest, installer script, agent source."""
import hashlib
from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from fastapi.responses import PlainTextResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from .database import get_db
from .models import Server
from .monitoring import apply_server_result, evaluate_metrics
from .schemas import AgentReport
from .security import login_limiter

router = APIRouter(prefix="/api/agent", tags=["agent"])
ROOT = Path(__file__).resolve().parent.parent


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


@router.post("/report")
def report(payload: AgentReport, request: Request, authorization: str | None = Header(default=None), db: Session = Depends(get_db)) -> dict:
    client = f"agent:{request.client.host if request.client else 'unknown'}"
    login_limiter.check(client)  # throttles token guessing; valid agents never increment it
    token = authorization[7:] if authorization and authorization.startswith("Bearer ") else ""
    server = db.scalar(select(Server).where(Server.token_hash == hash_token(token), Server.monitor_mode == "push")) if token else None
    if server is None:
        login_limiter.fail(client)
        raise HTTPException(401, "Invalid agent token")
    if not server.enabled:
        raise HTTPException(403, "This server monitor is disabled")
    metrics = payload.model_dump()
    metrics["received_at"] = datetime.now(timezone.utc).isoformat()
    try:
        status, failures = evaluate_metrics(server, metrics)
    except ValueError as error:
        raise HTTPException(422, str(error)) from error
    server.last_seen_at = datetime.now(timezone.utc)
    # deliver=False: alerts are queued and sent by the worker so ingest stays fast.
    apply_server_result(db, server, status, failures, metrics, deliver=False)
    db.commit()
    return {"ok": True, "status": status, "interval_seconds": server.check_interval_seconds}


@router.get("/install.sh", response_class=PlainTextResponse)
def install_script() -> str:
    return (ROOT / "agent_install.sh").read_text()


@router.get("/agent.py", response_class=PlainTextResponse)
def agent_source() -> str:
    return (ROOT / "agent.py").read_text()
