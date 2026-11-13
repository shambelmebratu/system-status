"""On-demand logs. The agent only ever dials out, so the dashboard queues a request, the agent polls for it
(every few seconds), runs it against its fixed allow-list of log sources, and posts the result back."""
import asyncio
import json
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, Header, HTTPException, Query
from fastapi.concurrency import run_in_threadpool
from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from .database import SessionLocal, get_db
from .models import LogRequest, Server
from .routes_agent import hash_token
from .schemas import LogQuery, LogResult
from .security import require_operator
from .stats import aware

router = APIRouter(tags=["logs"])
MAX_PENDING_PER_SERVER = 5
REQUEST_TTL = timedelta(minutes=15)   # results are transient: nothing is archived on the control plane
PICKUP_TIMEOUT = timedelta(seconds=45)


# --- instant wake-ups --------------------------------------------------------------------------------------------
# Agents long-poll for work and the dashboard long-polls for results. Each waiting request registers its own event
# (together with the loop it runs on); queueing a request or posting a result sets the matching events. This is a
# latency optimisation only: every wait also re-checks the database every couple of seconds, so a missed notification
# (or a second API process) just costs a little latency, never correctness.
_task_waiters: dict[int, list[tuple[asyncio.AbstractEventLoop, asyncio.Event]]] = {}      # server id  -> agents waiting for work
_result_waiters: dict[int, list[tuple[asyncio.AbstractEventLoop, asyncio.Event]]] = {}    # request id -> dashboards waiting for a result


def _wake(table: dict, key: int) -> None:
    for loop, event in list(table.get(key, [])):
        try:
            loop.call_soon_threadsafe(event.set)
        except RuntimeError:   # that loop is already closed: its waiter is gone
            pass


class _Waiter:
    """Registers an event for the duration of a long-poll."""

    def __init__(self, table: dict, key: int):
        self.table, self.key = table, key
        self.entry = (asyncio.get_running_loop(), asyncio.Event())
        self.event = self.entry[1]

    def __enter__(self):
        self.table.setdefault(self.key, []).append(self.entry)
        return self.event

    def __exit__(self, *exc):
        waiters = self.table.get(self.key, [])
        if self.entry in waiters:
            waiters.remove(self.entry)
        if not waiters:
            self.table.pop(self.key, None)


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
def request_logs(server_id: int, payload: LogQuery, _: dict = Depends(require_operator), db: Session = Depends(get_db)) -> dict:
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
    _wake(_task_waiters, server_id)   # the agent's open long-poll returns immediately
    return {"id": item.id, "status": item.status}


def _read(server_id: int, request_id: int) -> dict:
    with SessionLocal() as db:   # short-lived session: never held while waiting
        item = db.get(LogRequest, request_id)
        if not item or item.server_id != server_id:
            raise HTTPException(404, "Log request not found (results are kept for 15 minutes)")
        status, error = item.status, item.error
        if status in ("pending", "running") and datetime.now(timezone.utc) - aware(item.created_at) > PICKUP_TIMEOUT:
            status, error = "error", "The agent did not answer in time. Is the server online and the agent running?"
        return {"id": item.id, "status": status, "output": item.output or "", "error": error, "truncated": item.truncated, "query": json.loads(item.query)}


@router.get("/api/servers/{server_id}/logs/{request_id}")
async def read_logs(server_id: int, request_id: int, wait: int = Query(0, ge=0, le=20), _: dict = Depends(require_operator)) -> dict:
    """Result of a log request. With ?wait=N the call returns as soon as the agent has answered (up to N seconds)."""
    loop = asyncio.get_running_loop()
    deadline = loop.time() + wait
    with _Waiter(_result_waiters, request_id) as event:
        while True:
            event.clear()                                   # clear BEFORE checking so a wake-up in between is not lost
            result = await run_in_threadpool(_read, server_id, request_id)
            remaining = deadline - loop.time()
            if result["status"] in ("done", "error") or remaining <= 0:
                return result
            try:
                await asyncio.wait_for(event.wait(), timeout=min(remaining, 2.0))
            except asyncio.TimeoutError:
                pass


# ------------------------------------------------------------------ agent side
def _claim(authorization: str | None) -> tuple[int, list[dict]]:
    """Authenticates the agent and hands out each pending request exactly once (own short DB session)."""
    with SessionLocal() as db:
        server = agent_server(authorization, db)
        fresh = datetime.now(timezone.utc) - PICKUP_TIMEOUT
        items = db.scalars(select(LogRequest).where(LogRequest.server_id == server.id, LogRequest.status == "pending", LogRequest.created_at >= fresh).order_by(LogRequest.id).limit(MAX_PENDING_PER_SERVER)).all()
        tasks = []
        for item in items:
            item.status = "running"
            tasks.append({"id": item.id, **json.loads(item.query)})
        if tasks:
            db.commit()
        return server.id, tasks


@router.get("/api/agent/tasks")
async def agent_tasks(wait: int = Query(0, ge=0, le=25), authorization: str | None = Header(default=None)) -> dict:
    """Polled by agents. With ?wait=N the request is held open (no DB connection is held) until work arrives or N seconds pass."""
    loop = asyncio.get_running_loop()
    deadline = loop.time() + wait
    server_id, tasks = await run_in_threadpool(_claim, authorization)        # raises 401 for a bad token
    if tasks or wait == 0:
        return {"tasks": tasks}
    with _Waiter(_task_waiters, server_id) as event:
        while not tasks and loop.time() < deadline:
            event.clear()                                                    # clear BEFORE checking so a wake-up in between is not lost
            _, tasks = await run_in_threadpool(_claim, authorization)
            if tasks:
                break
            try:
                await asyncio.wait_for(event.wait(), timeout=min(max(deadline - loop.time(), 0.01), 2.0))
            except asyncio.TimeoutError:
                pass
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
    _wake(_result_waiters, request_id)   # the dashboard's open long-poll returns immediately
    return {"ok": True}
