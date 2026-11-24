"""On-demand logs. The agent only ever dials out, so the dashboard queues a request, the agent polls for it
(every few seconds), runs it against its fixed allow-list of log sources, and posts the result back."""
import asyncio
import json
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request
from fastapi.concurrency import run_in_threadpool
from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from . import log_policy as policy_lib
from .audit import audit
from .config import get_settings
from .database import SessionLocal, get_db
from .models import LogRequest, Server
from .routes_agent import hash_token
from .schemas import LogQuery, LogResult
from .security import agent_gate, ensure_access, login_limiter, require_admin, require_operator, require_user
from .stats import aware

router = APIRouter(tags=["logs"])
# Limits come from .env (LOG_* settings). Fetched logs are transient: nothing is archived on the control plane.
def request_ttl() -> timedelta:
    return timedelta(minutes=get_settings().log_result_ttl_minutes)


def pickup_timeout() -> timedelta:
    return timedelta(seconds=get_settings().log_pickup_timeout_seconds)


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


def agent_server(authorization: str | None, db: Session, request: Request | None = None) -> Server:
    from .routes_agent import server_for_token
    token = authorization[7:] if authorization and authorization.startswith("Bearer ") else ""
    server = server_for_token(db, request, hash_token(token), pending=False) if token else None
    if server is None:
        raise HTTPException(401, "Invalid agent token")
    if not server.enabled:
        raise HTTPException(403, "This server monitor is disabled")   # a disabled server's agent gets no work and cannot post results
    return server


def capabilities(server: Server) -> list[str]:
    try:
        return list(json.loads(server.last_metrics or "{}").get("capabilities") or [])
    except (ValueError, AttributeError):
        return []


def supports_logs(server: Server) -> bool:
    return "logs" in capabilities(server)


# ------------------------------------------------------------------ dashboard side
@router.post("/api/servers/{server_id}/logs")
def request_logs(server_id: int, payload: LogQuery, request: Request, user: dict = Depends(require_operator), db: Session = Depends(get_db)) -> dict:
    ensure_access(user, "server", server_id)
    server = db.get(Server, server_id)
    if not server:
        raise HTTPException(404, "Server not found")
    if server.monitor_mode != "push":
        raise HTTPException(422, "Logs need the installed agent (this server is monitored by ping or pull)")
    if payload.source == "ssh":
        caps = capabilities(server)
        if payload.target not in ("sessions", "history"):
            raise HTTPException(422, "Choose sessions or history")
        if "ssh" not in caps:
            raise HTTPException(422, "This server's agent does not report SSH activity: it is older than 2.13 or has AGENT_SSH=off. Update the agent to enable it.")
        if payload.target == "history" and "ssh_history" not in caps:
            raise HTTPException(422, "Command history is turned off in this server's agent (AGENT_SSH=nohistory).")
    elif not supports_logs(server):
        raise HTTPException(422, "This server's agent has log access turned off or is too old. Re-run the install command to update it.")
    if payload.source != "inventory" and not payload.target:
        raise HTTPException(422, "Choose what to read (a container, a unit or a file)")
    compiled = policy_lib.compile_for_agent(policy_lib.parse(server.log_policy))
    if not policy_lib.query_allowed(compiled, payload.source, payload.target):
        audit(db, request, "logs.denied", user=user, target=f"server:{server_id}", success=False, detail=f"{payload.source}:{payload.target} blocked by the server's log policy", commit=True)
        raise HTTPException(403, f"This server's log policy does not allow reading {payload.source} '{payload.target}'. An admin can change it under Server page → Log access.")
    now = datetime.now(timezone.utc)
    db.execute(delete(LogRequest).where(LogRequest.created_at < now - request_ttl()))
    pending = db.scalar(select(func.count()).select_from(LogRequest).where(LogRequest.server_id == server_id, LogRequest.status.in_(("pending", "running")), LogRequest.created_at >= now - pickup_timeout())) or 0
    if pending >= get_settings().log_max_pending_per_server:
        raise HTTPException(429, "Too many log requests are already waiting for this server")
    item = LogRequest(server_id=server_id, query=payload.model_dump_json())
    db.add(item)
    # Logs can contain secrets: record who looked at what (never the content itself).
    action = {"history": "logs.ssh_history", "sessions": "logs.ssh_sessions"}.get(payload.target, "logs.read") if payload.source == "ssh" else "logs.read"
    audit(db, request, action, user=user, target=f"server:{server_id}", detail=f"{payload.source}:{payload.target or '-'} lines={payload.lines}" + (f" filter={payload.grep!r}" if payload.grep else ""))
    db.commit(); db.refresh(item)
    _wake(_task_waiters, server_id)   # the agent's open long-poll returns immediately
    return {"id": item.id, "status": item.status}


@router.post("/api/servers/{server_id}/processes/{pid}")
def inspect_process(server_id: int, pid: int, request: Request, user: dict = Depends(require_operator), db: Session = Depends(get_db)) -> dict:
    """Queues an on-demand look at one process (like ps -o ..., /proc/PID/{cmdline,cwd,exe,status,cgroup}). Read the answer with
    GET /api/servers/{id}/logs/{request id}. Environment values are never sent, only their names."""
    ensure_access(user, "server", server_id)
    server = db.get(Server, server_id)
    if not server:
        raise HTTPException(404, "Server not found")
    if server.monitor_mode != "push":
        raise HTTPException(422, "Process details need the installed agent")
    if "process" not in capabilities(server):
        raise HTTPException(422, "This server's agent cannot show process details: it is older than 2.15 or has AGENT_SECURITY=off. Re-run the install command to update it.")
    if not 0 < pid < 2**31:
        raise HTTPException(422, "Invalid process id")
    now = datetime.now(timezone.utc)
    pending = db.scalar(select(func.count()).select_from(LogRequest).where(LogRequest.server_id == server_id, LogRequest.status.in_(("pending", "running")), LogRequest.created_at >= now - pickup_timeout())) or 0
    if pending >= get_settings().log_max_pending_per_server:
        raise HTTPException(429, "Too many requests are already waiting for this server")
    item = LogRequest(server_id=server_id, query=json.dumps({"source": "process", "target": str(pid), "lines": 1}))
    db.add(item)
    audit(db, request, "process.inspect", user=user, target=f"server:{server_id}", detail=f"{server.name}: PID {pid}")
    db.commit(); db.refresh(item)
    _wake(_task_waiters, server_id)
    return {"id": item.id, "status": item.status}


SYNC_MIN_SECONDS = 5


@router.post("/api/servers/{server_id}/sync")
def sync_now(server_id: int, request: Request, user: dict = Depends(require_user), db: Session = Depends(get_db)) -> dict:
    """"Sync now": asks the agent for a live one-second measurement (CPU and where it goes, memory, disk, load, the busiest processes).
    The agent answers within seconds over its open task channel; the answer replaces the server's latest metrics (graphs keep the
    regular reports). Read it with GET /api/servers/{id}/logs/{request id}."""
    ensure_access(user, "server", server_id)
    server = db.get(Server, server_id)
    if not server:
        raise HTTPException(404, "Server not found")
    if server.monitor_mode != "push":
        raise HTTPException(422, "Sync now needs the installed agent (this server is monitored by ping or pull)")
    if not server.enabled:
        raise HTTPException(422, "This server monitor is disabled")
    if "sync" not in capabilities(server):
        raise HTTPException(422, "This server's agent is older than 2.16 and cannot measure on demand. Update the agent (Servers → this server → Update agent) to use Sync now.")
    now = datetime.now(timezone.utc)
    recent = db.scalar(select(LogRequest).where(LogRequest.server_id == server_id, LogRequest.created_at >= now - timedelta(seconds=SYNC_MIN_SECONDS),
                                              LogRequest.query.like('%"source": "snapshot"%')).order_by(LogRequest.id.desc()).limit(1))
    if recent is not None:   # several people pressing the button at once share one measurement
        return {"id": recent.id, "status": recent.status}
    pending = db.scalar(select(func.count()).select_from(LogRequest).where(LogRequest.server_id == server_id, LogRequest.status.in_(("pending", "running")), LogRequest.created_at >= now - pickup_timeout())) or 0
    if pending >= get_settings().log_max_pending_per_server:
        raise HTTPException(429, "Too many requests are already waiting for this server")
    item = LogRequest(server_id=server_id, query=json.dumps({"source": "snapshot", "target": "", "lines": 1, "seconds": 1}))
    db.add(item)
    # "Sync now" refreshes security too: the agent also re-runs its threat scan (so a stopped process is resolved, a new one found)
    # and the update check at its next report. At most every 30 s per server, shared with Security → "Re-check".
    import time as _time
    from .routes_security import _last_recheck
    from .secscan import request_agent_rescan
    recheck = user["role"] in ("operator", "admin") and _time.monotonic() - _last_recheck.get(server_id, -1e9) >= 30   # a security re-scan is operator work, like Security → Re-check
    if recheck:
        _last_recheck[server_id] = _time.monotonic()
        request_agent_rescan(db, [server_id], user["email"])
        audit(db, request, "security.recheck", user=user, target=f"server:{server_id}", detail="with Sync now")
    db.commit(); db.refresh(item)
    _wake(_task_waiters, server_id)
    return {"id": item.id, "status": item.status, "security_recheck": recheck}


def apply_snapshot(db: Session, server: Server, output: str, now: datetime) -> str | None:
    """Validates a live snapshot from the agent and makes it the server's latest metrics. Returns an error text, or None."""
    from pydantic import ValidationError
    from .schemas import LiveSnapshot
    try:
        snap = LiveSnapshot.model_validate_json(output)
    except (ValidationError, ValueError):
        return "The agent's measurement was not in the expected format"
    try:
        metrics = json.loads(server.last_metrics or "{}") or {}
    except ValueError:
        metrics = {}
    for key in ("cpu_breakdown", "process_cpu_total", "process_count", "forks_per_sec", "procs_running", "procs_blocked"):
        metrics.pop(key, None)                  # never mix an old breakdown with the new figures
    metrics.update({k: v for k, v in snap.model_dump().items() if v is not None and k != "sample_seconds"})
    metrics["cpu_peak"] = None                  # a one-second measurement has no separate peak
    metrics["synced_at"], metrics["sync_sample_seconds"] = now.isoformat(), snap.sample_seconds
    server.last_metrics = json.dumps(metrics)
    return None


def _source_of(server_id: int, request_id: int) -> str | None:
    with SessionLocal() as db:
        item = db.get(LogRequest, request_id)
        return json.loads(item.query).get("source") if item and item.server_id == server_id else None


def _read(server_id: int, request_id: int) -> dict:
    with SessionLocal() as db:   # short-lived session: never held while waiting
        item = db.get(LogRequest, request_id)
        if not item or item.server_id != server_id:
            raise HTTPException(404, "Log request not found (results are kept for 15 minutes)")
        status, error = item.status, item.error
        if status in ("pending", "running") and datetime.now(timezone.utc) - aware(item.created_at) > pickup_timeout():
            status, error = "error", "The agent did not answer in time. Is the server online and the agent running?"
        query = json.loads(item.query)
        output = item.output or ""
        if query.get("source") == "inventory" and status == "done":   # never show what the policy forbids, even if the agent listed it
            server = db.get(Server, server_id)
            output = policy_lib.filter_inventory(output, policy_lib.compile_for_agent(policy_lib.parse(server.log_policy if server else None)))
        return {"id": item.id, "status": status, "output": output, "error": error, "truncated": item.truncated, "query": query}


@router.get("/api/servers/{server_id}/logs/{request_id}")
async def read_logs(server_id: int, request_id: int, wait: int = Query(0, ge=0, le=20), user: dict = Depends(require_user)) -> dict:
    """Result of a log request. With ?wait=N the call returns as soon as the agent has answered (up to N seconds).
    Viewers may read only "Sync now" measurements; logs, SSH activity and process details need the operator role."""
    ensure_access(user, "server", server_id)
    if user["role"] not in ("admin", "operator"):
        source = await run_in_threadpool(_source_of, server_id, request_id)
        if source != "snapshot":
            raise HTTPException(403, "Operator role required")
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


# ------------------------------------------------------------------ log access policy (what an agent may expose)
@router.get("/api/log-policy/catalog")
def policy_catalog(_: dict = Depends(require_operator)) -> dict:
    return {"file_categories": [{"id": k, "label": v["label"], "hint": v["hint"]} for k, v in policy_lib.FILE_CATEGORIES.items()]}


@router.get("/api/servers/{server_id}/log-policy")
def get_policy(server_id: int, user: dict = Depends(require_operator), db: Session = Depends(get_db)) -> dict:
    ensure_access(user, "server", server_id)
    server = db.get(Server, server_id)
    if not server:
        raise HTTPException(404, "Server not found")
    policy = policy_lib.parse(server.log_policy)
    return {"policy": policy.model_dump(), "restricted": policy_lib.is_restricted(policy_lib.compile_for_agent(policy))}


@router.put("/api/servers/{server_id}/log-policy")
def set_policy(server_id: int, policy: policy_lib.LogPolicy, request: Request, user: dict = Depends(require_admin), db: Session = Depends(get_db)) -> dict:
    """Which logs this server's agent may expose. Admin only: it is security configuration. Takes effect at the agent's next report."""
    server = db.get(Server, server_id)
    if not server:
        raise HTTPException(404, "Server not found")
    compiled = policy_lib.compile_for_agent(policy)
    server.log_policy = None if not policy_lib.is_restricted(compiled) else policy.model_dump_json()
    d, j, f = policy.docker, policy.journal, policy.files
    summary = (f"ssh {'off' if not policy.ssh.enabled else 'on' + ('' if policy.ssh.history else ', no command history')}; "
               f"docker {'off' if not d.enabled else ','.join(d.include)}{' except ' + ','.join(d.exclude) if d.exclude else ''}; "
               f"journal {'off' if not j.enabled else ','.join(j.units)}; files {'off' if not f.enabled else f.mode + (':' + ','.join(f.categories) if f.mode == 'selected' else '')}")
    audit(db, request, "server.log_policy", user=user, target=f"server:{server.id}", detail=f"{server.name}: {summary}")
    db.commit()
    return {"policy": policy.model_dump(), "restricted": policy_lib.is_restricted(compiled)}


# ------------------------------------------------------------------ agent side
def _claim(authorization: str | None) -> tuple[int, list[dict]]:
    """Authenticates the agent and hands out each pending request exactly once (own short DB session)."""
    with SessionLocal() as db:
        server = agent_server(authorization, db)
        fresh = datetime.now(timezone.utc) - pickup_timeout()
        items = db.scalars(select(LogRequest).where(LogRequest.server_id == server.id, LogRequest.status == "pending", LogRequest.created_at >= fresh).order_by(LogRequest.id).limit(get_settings().log_max_pending_per_server)).all()
        tasks = []
        for item in items:
            item.status = "running"
            tasks.append({"id": item.id, **json.loads(item.query)})
        if tasks:
            db.commit()
        return server.id, tasks


@router.get("/api/agent/tasks")
async def agent_tasks(request: Request, wait: int = Query(0, ge=0, le=25), authorization: str | None = Header(default=None)) -> dict:
    """Polled by agents. With ?wait=N the request is held open (no DB connection is held) until work arrives or N seconds pass."""
    gate = agent_gate(request, "agent")                                       # refuse callers that keep presenting wrong tokens
    loop = asyncio.get_running_loop()
    deadline = loop.time() + wait
    try:
        server_id, tasks = await run_in_threadpool(_claim, authorization)    # raises 401 for a bad token
    except HTTPException as error:
        if error.status_code == 401:
            login_limiter.fail_unique(gate, authorization or "")
        raise
    if tasks or wait == 0:
        return {"tasks": tasks}
    if len(_task_waiters.get(server_id, ())) >= get_settings().agent_max_open_polls:   # one agent holds one poll open; a stolen token must not tie up connections
        raise HTTPException(429, "Too many open task polls for this agent", headers={"Retry-After": "5"})
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
def agent_task_result(request_id: int, payload: LogResult, request: Request, authorization: str | None = Header(default=None), db: Session = Depends(get_db)) -> dict:
    gate = agent_gate(request, "agent")
    try:
        server = agent_server(authorization, db)
    except HTTPException:
        login_limiter.fail_unique(gate, authorization or "")
        raise
    item = db.get(LogRequest, request_id)
    if not item or item.server_id != server.id or item.status != "running":   # an agent can only answer its own, handed-out requests
        raise HTTPException(404, "Unknown task")
    item.status = "done" if payload.ok else "error"
    item.output, item.error, item.truncated = payload.output, payload.error or None, payload.truncated
    item.completed_at = datetime.now(timezone.utc)
    if payload.ok and json.loads(item.query).get("source") == "snapshot":
        problem = apply_snapshot(db, server, payload.output, item.completed_at)
        if problem:
            item.status, item.error = "error", problem
    db.commit()
    _wake(_result_waiters, request_id)   # the dashboard's open long-poll returns immediately
    return {"ok": True}
