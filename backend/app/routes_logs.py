"""On-demand logs. The agent only ever dials out, so the dashboard queues a request, the agent polls for it
(every few seconds), runs it against its fixed allow-list of log sources, and posts the result back."""
import json
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, Header, HTTPException
from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from .database import get_db
from .models import LogRequest, Server
from .routes_agent import hash_token
from .schemas import LogQuery, LogResult
from .security import require_user
from .stats import aware

router = APIRouter(tags=["logs"])
MAX_PENDING_PER_SERVER = 5
REQUEST_TTL = timedelta(minutes=15)   # results are transient: nothing is archived on the control plane
PICKUP_TIMEOUT = timedelta(seconds=45)


def agent_server(authorization: str | None, db: Session) -> Server:
    token = authorization[7:] if authorization and authorization.startswith("Bearer ") else ""
    server = db.scalar(select(Server).where(Server.token_hash == hash_token(token), Server.monitor_mode == "push")) if token else None
    if server is None:
        raise HTTPException(401, "Invalid agent token")
    return server


def supports_logs(server: Server) -> bool:
    try:
        return "logs" in (json.loads(server.last_metrics or "{}").get("capabilities") or [])
    except ValueError:
        return False


# ------------------------------------------------------------------ dashboard side
@router.post("/api/servers/{server_id}/logs")
def request_logs(server_id: int, payload: LogQuery, _: dict = Depends(require_user), db: Session = Depends(get_db)) -> dict:
    server = db.get(Server, server_id)
    if not server:
        raise HTTPException(404, "Server not found")
    if server.monitor_mode != "push":
        raise HTTPException(422, "Logs need the installed agent (this server is monitored by ping or pull)")
    if not supports_logs(server):
        raise HTTPException(422, "This server's agent has log access turned off or is too old. Re-run the install command to update it.")
    if payload.source != "inventory" and not payload.target:
        raise HTTPException(422, "Choose what to read (a container, a unit or a file)")
    now = datetime.now(timezone.utc)
    db.execute(delete(LogRequest).where(LogRequest.created_at < now - REQUEST_TTL))
    pending = db.scalar(select(func.count()).select_from(LogRequest).where(LogRequest.server_id == server_id, LogRequest.status.in_(("pending", "running")), LogRequest.created_at >= now - PICKUP_TIMEOUT)) or 0
    if pending >= MAX_PENDING_PER_SERVER:
        raise HTTPException(429, "Too many log requests are already waiting for this server")
    item = LogRequest(server_id=server_id, query=payload.model_dump_json())
    db.add(item); db.commit(); db.refresh(item)
    return {"id": item.id, "status": item.status}


@router.get("/api/servers/{server_id}/logs/{request_id}")
def read_logs(server_id: int, request_id: int, _: dict = Depends(require_user), db: Session = Depends(get_db)) -> dict:
    item = db.get(LogRequest, request_id)
    if not item or item.server_id != server_id:
        raise HTTPException(404, "Log request not found (results are kept for 15 minutes)")
    status = item.status
    error = item.error
    if status in ("pending", "running") and datetime.now(timezone.utc) - aware(item.created_at) > PICKUP_TIMEOUT:
        status, error = "error", "The agent did not answer in time. Is the server online and the agent running?"
    return {"id": item.id, "status": status, "output": item.output or "", "error": error, "truncated": item.truncated, "query": json.loads(item.query)}


# ------------------------------------------------------------------ agent side
@router.get("/api/agent/tasks")
def agent_tasks(authorization: str | None = Header(default=None), db: Session = Depends(get_db)) -> dict:
    """Polled by agents. Hands out each pending request exactly once."""
    server = agent_server(authorization, db)
    fresh = datetime.now(timezone.utc) - PICKUP_TIMEOUT
    items = db.scalars(select(LogRequest).where(LogRequest.server_id == server.id, LogRequest.status == "pending", LogRequest.created_at >= fresh).order_by(LogRequest.id).limit(MAX_PENDING_PER_SERVER)).all()
    tasks = []
    for item in items:
        item.status = "running"
        tasks.append({"id": item.id, **json.loads(item.query)})
    if tasks:
        db.commit()
    return {"tasks": tasks}


@router.post("/api/agent/tasks/{request_id}/result")
def agent_task_result(request_id: int, payload: LogResult, authorization: str | None = Header(default=None), db: Session = Depends(get_db)) -> dict:
    server = agent_server(authorization, db)
    item = db.get(LogRequest, request_id)
    if not item or item.server_id != server.id or item.status != "running":   # an agent can only answer its own, handed-out requests
        raise HTTPException(404, "Unknown task")
    item.status = "done" if payload.ok else "error"
    item.output, item.error, item.truncated = payload.output, payload.error or None, payload.truncated
    item.completed_at = datetime.now(timezone.utc)
    db.commit()
    return {"ok": True}
