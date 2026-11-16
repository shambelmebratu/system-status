import json
import logging
import os
import re
import secrets
from contextlib import asynccontextmanager
from datetime import datetime, timezone

from pydantic import ValidationError
from fastapi import BackgroundTasks, Depends, FastAPI, HTTPException, Query, Request, Response
from sqlalchemy import delete, desc, func, select
from sqlalchemy.orm import Session

from .config import get_settings
from .database import Base, engine, get_db
from .models import AlertEvent, Channel, CheckResult, Incident, Server, Service, User
from .bodylimit import BodyLimitMiddleware
from .agent_versions import latest_k8s_agent, latest_server_agent
from .monitoring import alert_columns, server_addresses, check_service, discover_telegram_chats, run_once, send_channel_test
from .routes_agent import hash_token, router as agent_router
from .routes_audit import router as audit_router
from .routes_db import router as db_router
from .routes_enroll import router as enroll_router
from .routes_k8s import router as k8s_router
from .routes_logs import router as logs_router
from .performance import router as performance_router
from .routes_retention import router as retention_router
from .routes_schedule import router as schedule_router
from .routes_stats import router as stats_router
from .schemas import ChannelCreate, ChannelUpdate, LoginRequest, PasswordChange, ProfileUpdate, TokenBody, ServerCreate, ServiceCreate
from .stats import uptime_by_target
from .netguard import BlockedTargetError, insecure_pull_problem, validate_host, validate_url
from .routes_users import router as users_router, serialize_user
from .audit import audit
from .security import COOKIE_NAME, can_see, client_ip, create_token, ensure_access, hash_password, login_limiter, needs_rehash, require_operator, require_unrestricted, require_user, scope_ids, verify_password

settings = get_settings()


HOST_AGENT_ID = "control-plane-host"


def ensure_host_agent(session: Session) -> None:
    """Provisions the dashboard entry and token for the stack's own `host-agent` service (the machine running SM-Watch)."""
    path = settings.host_agent_token_file
    if not path:
        return
    try:
        server = session.scalar(select(Server).where(Server.machine_id == HOST_AGENT_ID))
        try:
            with open(path) as handle:
                current = handle.read().strip()
        except OSError:
            current = ""
        if server and current and server.token_hash == hash_token(current):
            return
        token = secrets.token_urlsafe(32)
        if server is None:
            server = Server(name="This server (control plane)", host="", monitor_mode="push", check_interval_seconds=settings.check_interval_seconds, machine_id=HOST_AGENT_ID)
            session.add(server)
        server.monitor_mode = "push"
        set_token(server, token)
        session.commit()
        with open(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "w") as handle:
            handle.write(token)
    except Exception:  # never block API startup on this convenience feature
        session.rollback()
        logging.getLogger(__name__).exception("could not provision the host agent")


@asynccontextmanager
async def lifespan(_: FastAPI):
    with Session(engine) as session:
        if not session.scalar(select(User).limit(1)):
            session.add(User(email=settings.admin_email.lower(), password_hash=hash_password(settings.admin_password), role="admin", name="Administrator"))
            session.commit()
        ensure_host_agent(session)
    yield


def same_machine_groups(servers: list) -> dict[int, list[dict]]:
    """Servers that are really ONE machine reporting through two agents (for example the bundled agent and a separately installed
    one). Each entry has its own limits and alerts, which is confusing: the dashboard points it out.
    Same machine = same machine fingerprint (agent 2.9+), or the same host name booted at the same moment (older agents)."""
    facts = []
    for server in servers:
        if server.monitor_mode != "push" or not server.last_metrics:
            continue
        try:
            m = json.loads(server.last_metrics)
        except ValueError:
            continue
        boot = None
        try:
            if m.get("uptime_seconds") is not None and m.get("received_at"):
                boot = datetime.fromisoformat(m["received_at"]).timestamp() - float(m["uptime_seconds"])
        except (ValueError, TypeError):
            boot = None
        facts.append((server, m.get("machine") or "", (m.get("hostname") or "").lower(), boot))
    result: dict[int, list[dict]] = {}
    for i, (a, a_machine, a_host, a_boot) in enumerate(facts):
        for b, b_machine, b_host, b_boot in facts[i + 1:]:
            same = bool(a_machine and a_machine == b_machine) or bool(a_host and a_host == b_host and a_boot is not None and b_boot is not None and abs(a_boot - b_boot) < 180)
            if same:
                result.setdefault(a.id, []).append({"id": b.id, "name": b.name})
                result.setdefault(b.id, []).append({"id": a.id, "name": a.name})
    return result


def cookie_secure() -> bool:
    """Session cookies are HTTPS-only whenever the dashboard is served over HTTPS (COOKIE_SECURE=true, or an https:// PUBLIC_URL)."""
    return settings.cookie_secure or settings.public_url.lower().startswith("https://")


_dev = settings.environment.lower() in ("development", "dev", "test")
# The interactive API docs describe every endpoint: only served for local development.
app = FastAPI(title=settings.app_name, version="4.0.0", lifespan=lifespan, docs_url="/docs" if _dev else None, redoc_url=None, openapi_url="/openapi.json" if _dev else None)
from starlette.middleware.gzip import GZipMiddleware
app.add_middleware(GZipMiddleware, minimum_size=1024, compresslevel=5)   # dashboards and graphs are JSON: typically 5-10x smaller on the wire
app.add_middleware(BodyLimitMiddleware)   # outermost: oversized bodies are refused before anything reads them
app.include_router(agent_router)
app.include_router(enroll_router)
app.include_router(schedule_router)
app.include_router(logs_router)
app.include_router(k8s_router)
app.include_router(retention_router)
app.include_router(performance_router)
app.include_router(users_router)
app.include_router(audit_router)
app.include_router(db_router)
app.include_router(stats_router)


def purge_history(db: Session, kind: str, target_id: int) -> None:
    db.execute(delete(CheckResult).where(CheckResult.target_type == kind, CheckResult.target_id == target_id))
    db.execute(delete(Incident).where(Incident.target_type == kind, Incident.target_id == target_id))
    from .stats import clear_cache
    clear_cache()


def set_token(item: Server, token: str | None) -> None:
    changed = (token or None) != item.agent_token
    item.agent_token = token or None
    item.token_hash = hash_token(token) if token else None
    if changed:
        item.token_issued_at = datetime.now(timezone.utc) if token else None
        item.pending_token = item.pending_token_hash = item.pending_token_at = None   # any staged rotation is now moot


def guard_target(check, value: str, label: str) -> None:
    try:
        check(value)
    except BlockedTargetError as error:
        raise HTTPException(422, f"{label}: {error}") from error


def serialize(item):
    result = {column.name: getattr(item, column.name) for column in item.__table__.columns}
    for key in ("created_at", "last_checked_at", "last_seen_at", "cert_expires_at", "cert_checked_at"):
        if result.get(key): result[key] = (result[key] if result[key].tzinfo else result[key].replace(tzinfo=timezone.utc)).isoformat()
    if "cert_alert_days" in result:   # services: the effective certificate alert schedule and timeout
        from .monitoring import cert_thresholds, service_timeout
        result["cert_alert_days"] = [int(d) for d in (result["cert_alert_days"] or "").split(",") if d.strip().isdigit()]
        result["cert_alert_days_effective"] = cert_thresholds(item)
        result["timeout_seconds_effective"] = service_timeout(item)
        result.pop("cert_alerted", None)
    result.pop("token_hash", None)
    if "last_agent_ip" in result and "monitor_mode" in result:   # servers: public and private addresses, resolved on the server
        result.update(server_addresses(item))
    if "pending_token_hash" in result:   # never expose a staged token; just whether a rotation is waiting for the agent
        result["token_rotation_pending"] = bool(result.pop("pending_token_hash"))
        result.pop("pending_token", None)
        if result.get("pending_token_at"):
            result["pending_token_at"] = result["pending_token_at"].isoformat()
        if result.get("token_issued_at"):
            result["token_issued_at"] = result["token_issued_at"].isoformat()
    for key in ("notify_kinds", "notify_events", "alert_events"):
        if key in result:
            result[key] = [v for v in (result[key] or "").split(",") if v]
    if "alert_channels" in result:
        result["alert_channels"] = [int(v) for v in (result["alert_channels"] or "").split(",") if v.isdigit()]
    for secret in ("agent_token", "token"):
        if secret in result: result[secret] = "configured" if result[secret] else ""
    if "endpoint" in result and result.get("type") in ("slack", "webhook"):
        result["endpoint"] = "configured" if result["endpoint"] else ""
    if result.get("last_metrics"):
        result["last_metrics"] = json.loads(result["last_metrics"])
    return result


@app.get("/api/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "api"}


@app.get("/api/branding")
def branding() -> dict[str, str]:
    def safe_color(value: str, default: str) -> str:
        return value if re.fullmatch(r"#[0-9a-fA-F]{6}", value) else default

    return {
        "company_name": settings.company_name,
        "primary_color": safe_color(settings.brand_primary_color, "#c9f36b"),
        "accent_color": safe_color(settings.brand_accent_color, "#68d5e8"),
        "public_url": settings.public_url.rstrip("/"),
    }


_DUMMY_HASH: str | None = None


def dummy_hash() -> str:
    """Checked when the email is unknown, so an unknown user costs the same time as a wrong password (no account enumeration by timing)."""
    global _DUMMY_HASH
    if _DUMMY_HASH is None:
        _DUMMY_HASH = hash_password("not-a-real-password")
    return _DUMMY_HASH


@app.post("/api/auth/login")
def login(payload: LoginRequest, request: Request, response: Response, db: Session = Depends(get_db)) -> dict[str, str]:
    email = payload.email.lower()
    keys = (f"ip:{client_ip(request)}", f"email:{email}")
    try:
        login_limiter.check(keys[0])                                                                                            # this address: 5 misses / 5 min
        login_limiter.check(keys[1], limit=settings.login_account_max_attempts, window=settings.login_account_window_seconds)  # this account: 20 / 15 min
    except HTTPException:
        if login_limiter.first_time(f"blocked:{keys[0]}:{email}"):   # one line per lock-out, not one per blocked request
            audit(db, request, "auth.login", actor=email, success=False, detail="blocked: too many failed attempts", commit=True)
        raise
    user = db.scalar(select(User).where(User.email == email))
    password_ok = verify_password(payload.password, user.password_hash if user else dummy_hash())
    if not user or not password_ok or not user.active:
        login_limiter.fail(*keys)   # the same message and counting for every reason: nothing reveals which accounts exist
        audit(db, request, "auth.login", actor=email, success=False, detail="unknown user" if not user else "wrong password" if not password_ok else "account disabled", commit=True)
        raise HTTPException(401, "Invalid email or password")
    login_limiter.reset(*keys)
    user.last_login_at = datetime.now(timezone.utc)
    if needs_rehash(user.password_hash):   # silently upgrade an older, weaker hash now that we hold the password
        user.password_hash = hash_password(payload.password)
    audit(db, request, "auth.login", actor=user.email, user={"email": user.email, "role": user.role}, target=f"user:{user.id}")
    db.commit()
    response.set_cookie(
        COOKIE_NAME,
        create_token(user.id, user.email, user.token_version),
        max_age=settings.session_hours * 3600,
        httponly=True,
        secure=cookie_secure(),
        samesite="strict",
        path="/api",
    )
    return {"email": user.email}


@app.post("/api/auth/logout")
def logout(request: Request, response: Response, claims: dict = Depends(require_user), db: Session = Depends(get_db)) -> dict[str, bool]:
    """Revokes every session for this user (bumps the token version) and clears the cookie."""
    account = db.get(User, int(claims["sub"]))
    if account:
        account.token_version += 1
        audit(db, request, "auth.logout", user=claims, target=f"user:{account.id}")
        db.commit()
    response.delete_cookie(COOKIE_NAME, path="/api")
    return {"ok": True}


@app.post("/api/auth/password")
def change_password(payload: PasswordChange, request: Request, response: Response, claims: dict = Depends(require_user), db: Session = Depends(get_db)) -> dict[str, bool]:
    account = db.get(User, int(claims["sub"]))
    key = f"pw:{account.id}"
    login_limiter.check(key)   # a stolen session must not be usable to guess the current password
    if not verify_password(payload.current_password, account.password_hash):
        login_limiter.fail(key)
        audit(db, request, "auth.password_change", user=claims, target=f"user:{account.id}", success=False, detail="wrong current password", commit=True)
        raise HTTPException(403, "Current password is incorrect")
    if verify_password(payload.new_password, account.password_hash):
        raise HTTPException(422, "Choose a password different from the current one")
    account.password_hash = hash_password(payload.new_password)
    account.must_change_password = False
    account.token_version += 1  # signs out every other session
    audit(db, request, "auth.password_change", user=claims, target=f"user:{account.id}")
    db.commit()
    response.set_cookie(COOKIE_NAME, create_token(account.id, account.email, account.token_version), max_age=settings.session_hours * 3600, httponly=True, secure=cookie_secure(), samesite="strict", path="/api")
    return {"ok": True}


@app.get("/api/auth/me")
def me(user: dict = Depends(require_user), db: Session = Depends(get_db)) -> dict:
    account = db.get(User, user["uid"])  # require_user guarantees it exists and is active
    return {**serialize_user(account)}


@app.put("/api/auth/profile")
def update_profile(payload: ProfileUpdate, request: Request, user: dict = Depends(require_user), db: Session = Depends(get_db)) -> dict:
    """Edit your own name and email. Changing the email needs the current password."""
    account = db.get(User, user["uid"])
    account.name = payload.name.strip()
    if payload.email and payload.email.strip().lower() != account.email:
        key = f"profile:{account.id}"
        login_limiter.check(key)
        if not verify_password(payload.current_password, account.password_hash):
            login_limiter.fail(key)
            audit(db, request, "auth.email_change", user=user, target=f"user:{account.id}", success=False, detail="wrong current password", commit=True)
            raise HTTPException(403, "Enter your current password to change your email")
        email = payload.email.strip().lower()
        if db.scalar(select(User.id).where(User.email == email, User.id != account.id)) is not None:
            raise HTTPException(409, "That email is already in use")
        audit(db, request, "auth.email_change", user=user, target=f"user:{account.id}", detail=f"{account.email} -> {email}")
        account.email = email
    db.commit(); db.refresh(account)
    return serialize_user(account)


@app.get("/api/dashboard")
def dashboard(user: dict = Depends(require_user), db: Session = Depends(get_db)) -> dict:
    servers = [s for s in db.scalars(select(Server).order_by(Server.name)).all() if can_see(user, "server", s.id)]
    services = [s for s in db.scalars(select(Service).order_by(Service.name)).all() if can_see(user, "service", s.id)]
    restricted = user.get("scope") is not None
    events = db.scalars(select(AlertEvent).order_by(desc(AlertEvent.created_at)).limit(200 if restricted else 10)).all()
    events = [e for e in events if e.target_type in ("server", "service", "cluster") and can_see(user, e.target_type, e.target_id)][:10] if restricted else events
    statuses = [item.last_status for item in [*servers, *services]]
    uptime = uptime_by_target(db, 24)

    def with_uptime(kind: str, item) -> dict:
        return {**serialize(item), "uptime_24h": uptime.get((kind, item.id))}

    if restricted:
        open_incidents = sum(1 for i in db.scalars(select(Incident).where(Incident.resolved_at.is_(None))).all() if i.target_type in ("server", "service", "cluster") and can_see(user, i.target_type, i.target_id))
    else:
        open_incidents = db.scalar(select(func.count()).select_from(Incident).where(Incident.resolved_at.is_(None))) or 0
    server_rows = [with_uptime("server", item) for item in servers]
    twins = same_machine_groups(servers)
    for row in server_rows:
        row["same_machine_as"] = twins.get(row["id"], [])
    return {
        "servers": server_rows,
        "services": [with_uptime("service", item) for item in services],
        "events": [serialize(item) for item in events],
        "threshold_defaults": {
            "cpu": settings.cpu_threshold,
            "memory": settings.memory_threshold,
            "disk": settings.disk_threshold,
            "load": settings.load_threshold,
            "swap": settings.swap_threshold,
            "process": settings.process_threshold,
            "server_interval_seconds": settings.check_interval_seconds,
        },
        "agents": {"latest": latest_server_agent(), "latest_k8s": latest_k8s_agent()},
        "limits": {
            "reminder_minutes": settings.reminder_minutes, "usage_warn_percent": settings.usage_warn_percent, "usage_bad_percent": settings.usage_bad_percent, "k8s_offline_seconds": settings.k8s_offline_seconds,
            "service_timeout_seconds": settings.service_timeout_seconds, "cert_alert_days": settings.cert_alert_days, "cert_check_hours": settings.cert_check_hours,
            "enrollment_default_minutes": settings.enrollment_default_minutes, "enrollment_max_minutes": settings.enrollment_max_minutes, "log_result_ttl_minutes": settings.log_result_ttl_minutes,
        },
        "summary": {"servers": len(servers), "services": len(services), "up": statuses.count("up"), "alerts": sum(value in ("alert", "down", "degraded") for value in statuses), "open_incidents": open_incidents},
    }


def alert_settings(values: dict, target_type: str, db: Session) -> dict:
    """Validates and converts the per-monitor alert settings of a server / service payload."""
    wanted = values.get("alert_channels") or []
    if wanted:
        known = set(db.scalars(select(Channel.id).where(Channel.id.in_(wanted))).all())
        if known != set(wanted):
            raise HTTPException(422, "One of the chosen notification channels does not exist")
    return alert_columns(values, target_type)


def routing_columns(values: dict) -> dict:
    """notify_kinds / notify_events travel as lists and are stored comma-separated (NULL = everything, also when all are ticked)."""
    for key, everything in (("notify_kinds", 3), ("notify_events", 4)):
        chosen = values.get(key) or []
        values[key] = ",".join(chosen) if chosen and len(chosen) < everything else None
    return values


@app.get("/api/channels")
def channels(user: dict = Depends(require_user), db: Session = Depends(get_db)) -> list[dict]:
    items = [serialize(item) for item in db.scalars(select(Channel).order_by(Channel.name)).all()]
    if user["role"] == "viewer" or user.get("scope") is not None:   # viewers (and people limited to selected monitors) see that channels exist, not how they are configured
        return [{"id": i["id"], "name": i["name"], "type": i["type"], "enabled": i["enabled"]} for i in items]
    return items


@app.post("/api/channels/telegram/discover")
def telegram_discover(payload: TokenBody, _: dict = Depends(require_unrestricted)) -> dict:
    """Helps users find the right chat ID: lists chats the bot has seen recently."""
    try:
        return discover_telegram_chats(payload.token)
    except (ValueError, OSError) as error:
        raise HTTPException(422, re.sub(r"\d{6,}:[A-Za-z0-9_-]{20,}", "***", str(error))) from error


@app.post("/api/channels")
def create_channel(payload: ChannelCreate, request: Request, user: dict = Depends(require_unrestricted), db: Session = Depends(get_db)) -> dict:
    if payload.type in ("slack", "webhook"):
        guard_target(validate_url, payload.endpoint, "Endpoint")
    item = Channel(**routing_columns(payload.model_dump())); db.add(item); db.flush()
    audit(db, request, "channel.create", user=user, target=f"channel:{item.id}", detail=f"{item.name} ({item.type})")
    db.commit(); db.refresh(item); return serialize(item)


@app.put("/api/channels/{item_id}")
def update_channel(item_id: int, payload: ChannelUpdate, request: Request, user: dict = Depends(require_unrestricted), db: Session = Depends(get_db)) -> dict:
    item = db.get(Channel, item_id)
    if not item:
        raise HTTPException(404, "Notification channel not found")
    values = payload.model_dump()
    same_type = values["type"] == item.type
    for secret in ("token", "endpoint"):  # blank = keep the stored secret (never round-tripped to the browser)
        if not values[secret] and same_type:
            values[secret] = getattr(item, secret) or ""
    try:
        ChannelCreate(**values)  # same provider validation as creation
    except ValidationError as error:
        raise HTTPException(422, "; ".join(e["msg"].removeprefix("Value error, ") for e in error.errors())) from error
    if values["type"] in ("slack", "webhook"):
        guard_target(validate_url, values["endpoint"], "Endpoint")
    for key, value in routing_columns(values).items():
        setattr(item, key, value)
    audit(db, request, "channel.update", user=user, target=f"channel:{item.id}", detail=item.name)
    db.commit(); db.refresh(item)
    return serialize(item)


@app.post("/api/channels/{item_id}/test")
def test_channel(item_id: int, request: Request, user: dict = Depends(require_unrestricted), db: Session = Depends(get_db)) -> dict[str, str | bool]:
    item = db.get(Channel, item_id)
    if not item:
        raise HTTPException(404, "Notification channel not found")
    delivered, detail = send_channel_test(item)
    audit(db, request, "channel.test", user=user, target=f"channel:{item.id}", detail=item.name, success=delivered, commit=True)
    if not delivered:
        raise HTTPException(502, detail)
    return {"ok": True, "detail": detail}


@app.delete("/api/channels/{item_id}")
def delete_channel(item_id: int, request: Request, user: dict = Depends(require_unrestricted), db: Session = Depends(get_db)) -> dict[str, bool]:
    item = db.get(Channel, item_id)
    if item:
        audit(db, request, "channel.delete", user=user, target=f"channel:{item.id}", detail=item.name)
        db.delete(item); db.commit()
    return {"deleted": True}


def validate_server_targets(payload: ServerCreate) -> None:
    if payload.monitor_mode in ("ping", "agent"):
        guard_target(validate_host, payload.host, "Host")
    elif payload.host:
        guard_target(validate_host, payload.host, "Host")
    if payload.monitor_mode == "agent":
        guard_target(validate_url, payload.endpoint, "Agent endpoint")
        problem = insecure_pull_problem(payload.endpoint)
        if problem:
            raise HTTPException(422, f"Agent endpoint: {problem}")


@app.post("/api/servers")
def create_server(payload: ServerCreate, request: Request, user: dict = Depends(require_unrestricted), db: Session = Depends(get_db)) -> dict:
    values = payload.model_dump()
    token = values.pop("agent_token")
    if payload.monitor_mode == "push":
        token = token or secrets.token_urlsafe(32)  # shown once in this response
        values["endpoint"] = ""
    if payload.monitor_mode in ("agent", "push") and len(token) < 32:
        raise HTTPException(422, "Agent token must be at least 32 characters")
    validate_server_targets(payload)
    item = Server(**alert_settings(values, "server", db))
    set_token(item, token if payload.monitor_mode != "ping" else None)
    db.add(item); db.flush()
    audit(db, request, "server.create", user=user, target=f"server:{item.id}", detail=f"{item.name} ({item.monitor_mode})")
    db.commit(); db.refresh(item)
    result = serialize(item)
    if payload.monitor_mode == "push":
        result["install_token"] = token
    return result


@app.put("/api/servers/{item_id}")
def update_server(item_id: int, payload: ServerCreate, request: Request, user: dict = Depends(require_operator), db: Session = Depends(get_db)) -> dict:
    ensure_access(user, "server", item_id)
    item = db.get(Server, item_id)
    if not item:
        raise HTTPException(404, "Server not found")
    values = payload.model_dump()
    token = values.pop("agent_token") or item.agent_token
    validate_server_targets(payload)
    if values["monitor_mode"] == "ping":
        values["endpoint"] = ""
        token = None
    elif values["monitor_mode"] == "push":
        values["endpoint"] = ""
    if values["monitor_mode"] in ("agent", "push") and len(token or "") < 32:
        raise HTTPException(422, "Agent token must be at least 32 characters")
    for key, value in alert_settings(values, "server", db).items():
        setattr(item, key, value)
    set_token(item, token)
    item.last_checked_at = None
    item.last_seen_at = None
    item.last_status = "unknown"
    item.last_error = None
    audit(db, request, "server.update", user=user, target=f"server:{item.id}", detail=f"{item.name} ({item.monitor_mode})")
    db.commit()
    db.refresh(item)
    return serialize(item)


@app.post("/api/servers/{item_id}/rotate-token")
def rotate_server_token(item_id: int, request: Request, immediate: bool = Query(False), user: dict = Depends(require_operator), db: Session = Depends(get_db)) -> dict:
    ensure_access(user, "server", item_id)
    """Replaces the server's agent token.

    Default (agents that have connected): the new token is staged and delivered to the agent over its own authenticated
    connection at its next report; the old token stays valid only until the agent has switched, so nothing is interrupted.
    immediate=true (a token is stolen/leaked): the old token stops working NOW and the new one is returned once, to be
    installed by hand. Pull/never-connected agents always use the immediate form."""
    item = db.get(Server, item_id)
    if not item:
        raise HTTPException(404, "Server not found")
    if item.monitor_mode == "ping":
        raise HTTPException(422, "Ping-only monitors do not use an agent token")
    token = secrets.token_urlsafe(32)
    if item.monitor_mode == "push" and item.last_seen_at and not immediate:
        item.pending_token, item.pending_token_hash, item.pending_token_at = token, hash_token(token), datetime.now(timezone.utc)
        audit(db, request, "server.token_rotate", user=user, target=f"server:{item.id}", detail=f"{item.name}: staged for delivery to the agent")
        db.commit()
        return {"mode": "managed", "detail": "The new token will be delivered to the agent at its next report. Nothing needs to be installed."}
    set_token(item, token)
    audit(db, request, "server.token_revoke", user=user, target=f"server:{item.id}", detail=f"{item.name}: old token invalidated immediately")
    db.commit()
    return {"mode": "immediate", "install_token": token}


@app.delete("/api/servers/{item_id}")
def delete_server(item_id: int, request: Request, user: dict = Depends(require_unrestricted), db: Session = Depends(get_db)) -> dict[str, bool]:
    item = db.get(Server, item_id)
    if item:
        audit(db, request, "server.delete", user=user, target=f"server:{item.id}", detail=item.name)
        purge_history(db, "server", item.id)
        db.delete(item); db.commit()
    return {"deleted": True}


def service_values(payload: ServiceCreate) -> dict:
    values = payload.model_dump()
    values["cert_alert_days"] = ",".join(str(d) for d in values["cert_alert_days"]) or None
    return values


@app.post("/api/services")
def create_service(payload: ServiceCreate, request: Request, user: dict = Depends(require_unrestricted), db: Session = Depends(get_db)) -> dict:
    guard_target(validate_url, payload.url, "URL")
    if payload.server_id is not None and not db.get(Server, payload.server_id): raise HTTPException(404, "Server not found")
    item = Service(**alert_settings(service_values(payload), "service", db)); db.add(item); db.flush()
    audit(db, request, "service.create", user=user, target=f"service:{item.id}", detail=item.name)
    db.commit(); db.refresh(item); return serialize(item)


@app.put("/api/services/{item_id}")
def update_service(item_id: int, payload: ServiceCreate, request: Request, user: dict = Depends(require_operator), db: Session = Depends(get_db)) -> dict:
    ensure_access(user, "service", item_id)
    item = db.get(Service, item_id)
    if not item:
        raise HTTPException(404, "Service monitor not found")
    values = service_values(payload)
    guard_target(validate_url, payload.url, "URL")
    if values["url"] != item.url or not values["cert_check"]:   # another address: forget the old certificate and its alerts
        item.cert_expires_at = item.cert_issuer = item.cert_subject = item.cert_checked_at = item.cert_error = item.cert_alerted = None
    if values["cert_alert_days"] != item.cert_alert_days:
        item.cert_alerted = None
    if values["server_id"] is not None and (not db.get(Server, values["server_id"]) or not can_see(user, "server", values["server_id"])):
        raise HTTPException(404, "Server not found")
    for key, value in alert_settings(values, "service", db).items():
        setattr(item, key, value)
    item.last_checked_at = None
    item.last_status = "unknown"
    item.last_error = None
    item.last_http_status = None
    audit(db, request, "service.update", user=user, target=f"service:{item.id}", detail=item.name)
    db.commit()
    db.refresh(item)
    return serialize(item)


@app.delete("/api/services/{item_id}")
def delete_service(item_id: int, request: Request, user: dict = Depends(require_unrestricted), db: Session = Depends(get_db)) -> dict[str, bool]:
    item = db.get(Service, item_id)
    if item:
        audit(db, request, "service.delete", user=user, target=f"service:{item.id}", detail=item.name)
        purge_history(db, "service", item.id)
        db.delete(item); db.commit()
    return {"deleted": True}


@app.post("/api/services/{item_id}/check")
def check_service_now(item_id: int, user: dict = Depends(require_operator), db: Session = Depends(get_db)) -> dict:
    ensure_access(user, "service", item_id)
    item = db.get(Service, item_id)
    if not item:
        raise HTTPException(404, "Service monitor not found")
    try:
        return check_service(item, db)
    except Exception as error:
        db.rollback()
        raise HTTPException(502, f"Service check failed: {error}") from error


@app.post("/api/monitor/run")
def run_monitor(background_tasks: BackgroundTasks, _: dict = Depends(require_unrestricted)) -> dict[str, str]:
    background_tasks.add_task(run_once)
    return {"status": "queued"}
