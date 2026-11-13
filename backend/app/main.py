import json
import logging
import os
import re
import secrets
from contextlib import asynccontextmanager
from datetime import datetime, timezone

from pydantic import ValidationError
from fastapi import BackgroundTasks, Depends, FastAPI, HTTPException, Request, Response
from sqlalchemy import delete, desc, func, select
from sqlalchemy.orm import Session

from .config import get_settings
from .database import Base, engine, get_db
from .models import AlertEvent, Channel, CheckResult, Incident, Server, Service, User
from .monitoring import check_service, discover_telegram_chats, run_once, send_channel_test
from .routes_agent import hash_token, router as agent_router
from .routes_enroll import router as enroll_router
from .routes_logs import router as logs_router
from .routes_schedule import router as schedule_router
from .routes_stats import router as stats_router
from .schemas import ChannelCreate, ChannelUpdate, LoginRequest, PasswordChange, ProfileUpdate, TokenBody, ServerCreate, ServiceCreate
from .stats import uptime_by_target
from .netguard import BlockedTargetError, validate_host, validate_url
from .routes_users import router as users_router, serialize_user
from .security import COOKIE_NAME, create_token, hash_password, login_limiter, require_operator, require_user, verify_password

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


app = FastAPI(title=settings.app_name, version="4.0.0", lifespan=lifespan)
app.include_router(agent_router)
app.include_router(enroll_router)
app.include_router(schedule_router)
app.include_router(logs_router)
app.include_router(users_router)
app.include_router(stats_router)


def purge_history(db: Session, kind: str, target_id: int) -> None:
    db.execute(delete(CheckResult).where(CheckResult.target_type == kind, CheckResult.target_id == target_id))
    db.execute(delete(Incident).where(Incident.target_type == kind, Incident.target_id == target_id))


def set_token(item: Server, token: str | None) -> None:
    item.agent_token = token or None
    item.token_hash = hash_token(token) if token else None


def guard_target(check, value: str, label: str) -> None:
    try:
        check(value)
    except BlockedTargetError as error:
        raise HTTPException(422, f"{label}: {error}") from error


def serialize(item):
    result = {column.name: getattr(item, column.name) for column in item.__table__.columns}
    for key in ("created_at", "last_checked_at", "last_seen_at"):
        if result.get(key): result[key] = result[key].isoformat()
    result.pop("token_hash", None)
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


@app.post("/api/auth/login")
def login(payload: LoginRequest, request: Request, response: Response, db: Session = Depends(get_db)) -> dict[str, str]:
    email = payload.email.lower()
    keys = (f"ip:{request.client.host if request.client else 'unknown'}", f"email:{email}")
    login_limiter.check(*keys)
    user = db.scalar(select(User).where(User.email == email))
    if not user or not verify_password(payload.password, user.password_hash):
        login_limiter.fail(*keys)
        raise HTTPException(401, "Invalid email or password")
    if not user.active:   # same message and same failure counting as a wrong password: do not reveal which accounts exist
        login_limiter.fail(*keys)
        raise HTTPException(401, "Invalid email or password")
    login_limiter.reset(*keys)
    user.last_login_at = datetime.now(timezone.utc)
    db.commit()
    response.set_cookie(
        COOKIE_NAME,
        create_token(user.id, user.email, user.token_version),
        max_age=settings.session_hours * 3600,
        httponly=True,
        secure=settings.cookie_secure,
        samesite="strict",
        path="/api",
    )
    return {"email": user.email}


@app.post("/api/auth/logout")
def logout(response: Response, claims: dict = Depends(require_user), db: Session = Depends(get_db)) -> dict[str, bool]:
    """Revokes every session for this user (bumps the token version) and clears the cookie."""
    account = db.get(User, int(claims["sub"]))
    if account:
        account.token_version += 1
        db.commit()
    response.delete_cookie(COOKIE_NAME, path="/api")
    return {"ok": True}


@app.post("/api/auth/password")
def change_password(payload: PasswordChange, response: Response, claims: dict = Depends(require_user), db: Session = Depends(get_db)) -> dict[str, bool]:
    account = db.get(User, int(claims["sub"]))
    if not verify_password(payload.current_password, account.password_hash):
        raise HTTPException(403, "Current password is incorrect")
    if verify_password(payload.new_password, account.password_hash):
        raise HTTPException(422, "Choose a password different from the current one")
    account.password_hash = hash_password(payload.new_password)
    account.must_change_password = False
    account.token_version += 1  # signs out every other session
    db.commit()
    response.set_cookie(COOKIE_NAME, create_token(account.id, account.email, account.token_version), max_age=settings.session_hours * 3600, httponly=True, secure=settings.cookie_secure, samesite="strict", path="/api")
    return {"ok": True}


@app.get("/api/auth/me")
def me(user: dict = Depends(require_user), db: Session = Depends(get_db)) -> dict:
    account = db.get(User, user["uid"])  # require_user guarantees it exists and is active
    return {**serialize_user(account)}


@app.put("/api/auth/profile")
def update_profile(payload: ProfileUpdate, user: dict = Depends(require_user), db: Session = Depends(get_db)) -> dict:
    """Edit your own name and email. Changing the email needs the current password."""
    account = db.get(User, user["uid"])
    account.name = payload.name.strip()
    if payload.email and payload.email.strip().lower() != account.email:
        key = f"profile:{account.id}"
        login_limiter.check(key)
        if not verify_password(payload.current_password, account.password_hash):
            login_limiter.fail(key)
            raise HTTPException(403, "Enter your current password to change your email")
        email = payload.email.strip().lower()
        if db.scalar(select(User.id).where(User.email == email, User.id != account.id)) is not None:
            raise HTTPException(409, "That email is already in use")
        account.email = email
    db.commit(); db.refresh(account)
    return serialize_user(account)


@app.get("/api/dashboard")
def dashboard(_: dict = Depends(require_user), db: Session = Depends(get_db)) -> dict:
    servers = db.scalars(select(Server).order_by(Server.name)).all()
    services = db.scalars(select(Service).order_by(Service.name)).all()
    events = db.scalars(select(AlertEvent).order_by(desc(AlertEvent.created_at)).limit(10)).all()
    statuses = [item.last_status for item in [*servers, *services]]
    uptime = uptime_by_target(db, 24)

    def with_uptime(kind: str, item) -> dict:
        return {**serialize(item), "uptime_24h": uptime.get((kind, item.id))}

    open_incidents = db.scalar(select(func.count()).select_from(Incident).where(Incident.resolved_at.is_(None))) or 0
    return {
        "servers": [with_uptime("server", item) for item in servers],
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
        "summary": {"servers": len(servers), "services": len(services), "up": statuses.count("up"), "alerts": sum(value in ("alert", "down", "degraded") for value in statuses), "open_incidents": open_incidents},
    }


@app.get("/api/channels")
def channels(user: dict = Depends(require_user), db: Session = Depends(get_db)) -> list[dict]:
    items = [serialize(item) for item in db.scalars(select(Channel).order_by(Channel.name)).all()]
    if user["role"] == "viewer":   # viewers may see that channels exist, not how they are configured
        return [{"id": i["id"], "name": i["name"], "type": i["type"], "enabled": i["enabled"]} for i in items]
    return items


@app.post("/api/channels/telegram/discover")
def telegram_discover(payload: TokenBody, _: dict = Depends(require_operator)) -> dict:
    """Helps users find the right chat ID: lists chats the bot has seen recently."""
    try:
        return discover_telegram_chats(payload.token)
    except (ValueError, OSError) as error:
        raise HTTPException(422, re.sub(r"\d{6,}:[A-Za-z0-9_-]{20,}", "***", str(error))) from error


@app.post("/api/channels")
def create_channel(payload: ChannelCreate, _: dict = Depends(require_operator), db: Session = Depends(get_db)) -> dict:
    if payload.type in ("slack", "webhook"):
        guard_target(validate_url, payload.endpoint, "Endpoint")
    item = Channel(**payload.model_dump()); db.add(item); db.commit(); db.refresh(item); return serialize(item)


@app.put("/api/channels/{item_id}")
def update_channel(item_id: int, payload: ChannelUpdate, _: dict = Depends(require_operator), db: Session = Depends(get_db)) -> dict:
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
    for key, value in values.items():
        setattr(item, key, value)
    db.commit(); db.refresh(item)
    return serialize(item)


@app.post("/api/channels/{item_id}/test")
def test_channel(item_id: int, _: dict = Depends(require_operator), db: Session = Depends(get_db)) -> dict[str, str | bool]:
    item = db.get(Channel, item_id)
    if not item:
        raise HTTPException(404, "Notification channel not found")
    delivered, detail = send_channel_test(item)
    if not delivered:
        raise HTTPException(502, detail)
    return {"ok": True, "detail": detail}


@app.delete("/api/channels/{item_id}")
def delete_channel(item_id: int, _: dict = Depends(require_operator), db: Session = Depends(get_db)) -> dict[str, bool]:
    item = db.get(Channel, item_id)
    if item: db.delete(item); db.commit()
    return {"deleted": True}


def validate_server_targets(payload: ServerCreate) -> None:
    if payload.monitor_mode in ("ping", "agent"):
        guard_target(validate_host, payload.host, "Host")
    elif payload.host:
        guard_target(validate_host, payload.host, "Host")
    if payload.monitor_mode == "agent":
        guard_target(validate_url, payload.endpoint, "Agent endpoint")


@app.post("/api/servers")
def create_server(payload: ServerCreate, _: dict = Depends(require_operator), db: Session = Depends(get_db)) -> dict:
    values = payload.model_dump()
    token = values.pop("agent_token")
    if payload.monitor_mode == "push":
        token = token or secrets.token_urlsafe(32)  # shown once in this response
        values["endpoint"] = ""
    if payload.monitor_mode in ("agent", "push") and len(token) < 32:
        raise HTTPException(422, "Agent token must be at least 32 characters")
    validate_server_targets(payload)
    item = Server(**values)
    set_token(item, token if payload.monitor_mode != "ping" else None)
    db.add(item); db.commit(); db.refresh(item)
    result = serialize(item)
    if payload.monitor_mode == "push":
        result["install_token"] = token
    return result


@app.put("/api/servers/{item_id}")
def update_server(item_id: int, payload: ServerCreate, _: dict = Depends(require_operator), db: Session = Depends(get_db)) -> dict:
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
    for key, value in values.items():
        setattr(item, key, value)
    set_token(item, token)
    item.last_checked_at = None
    item.last_seen_at = None
    item.last_status = "unknown"
    item.last_error = None
    db.commit()
    db.refresh(item)
    return serialize(item)


@app.post("/api/servers/{item_id}/rotate-token")
def rotate_server_token(item_id: int, _: dict = Depends(require_operator), db: Session = Depends(get_db)) -> dict:
    """Issues a new agent token (shown once). The old token stops working immediately."""
    item = db.get(Server, item_id)
    if not item:
        raise HTTPException(404, "Server not found")
    if item.monitor_mode == "ping":
        raise HTTPException(422, "Ping-only monitors do not use an agent token")
    token = secrets.token_urlsafe(32)
    set_token(item, token)
    db.commit()
    return {"install_token": token}


@app.delete("/api/servers/{item_id}")
def delete_server(item_id: int, _: dict = Depends(require_operator), db: Session = Depends(get_db)) -> dict[str, bool]:
    item = db.get(Server, item_id)
    if item:
        purge_history(db, "server", item.id)
        db.delete(item); db.commit()
    return {"deleted": True}


@app.post("/api/services")
def create_service(payload: ServiceCreate, _: dict = Depends(require_operator), db: Session = Depends(get_db)) -> dict:
    guard_target(validate_url, payload.url, "URL")
    if payload.server_id is not None and not db.get(Server, payload.server_id): raise HTTPException(404, "Server not found")
    item = Service(**payload.model_dump()); db.add(item); db.commit(); db.refresh(item); return serialize(item)


@app.put("/api/services/{item_id}")
def update_service(item_id: int, payload: ServiceCreate, _: dict = Depends(require_operator), db: Session = Depends(get_db)) -> dict:
    item = db.get(Service, item_id)
    if not item:
        raise HTTPException(404, "Service monitor not found")
    values = payload.model_dump()
    guard_target(validate_url, payload.url, "URL")
    if values["server_id"] is not None and not db.get(Server, values["server_id"]):
        raise HTTPException(404, "Server not found")
    for key, value in values.items():
        setattr(item, key, value)
    item.last_checked_at = None
    item.last_status = "unknown"
    item.last_error = None
    item.last_http_status = None
    db.commit()
    db.refresh(item)
    return serialize(item)


@app.delete("/api/services/{item_id}")
def delete_service(item_id: int, _: dict = Depends(require_operator), db: Session = Depends(get_db)) -> dict[str, bool]:
    item = db.get(Service, item_id)
    if item:
        purge_history(db, "service", item.id)
        db.delete(item); db.commit()
    return {"deleted": True}


@app.post("/api/services/{item_id}/check")
def check_service_now(item_id: int, _: dict = Depends(require_operator), db: Session = Depends(get_db)) -> dict:
    item = db.get(Service, item_id)
    if not item:
        raise HTTPException(404, "Service monitor not found")
    try:
        return check_service(item, db)
    except Exception as error:
        db.rollback()
        raise HTTPException(502, f"Service check failed: {error}") from error


@app.post("/api/monitor/run")
def run_monitor(background_tasks: BackgroundTasks, _: dict = Depends(require_operator)) -> dict[str, str]:
    background_tasks.add_task(run_once)
    return {"status": "queued"}
