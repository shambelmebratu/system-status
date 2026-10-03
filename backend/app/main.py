import json
import re

from fastapi import BackgroundTasks, Depends, FastAPI, HTTPException
from sqlalchemy import desc, select
from sqlalchemy.orm import Session

from .config import get_settings
from .database import Base, engine, get_db
from .models import AlertEvent, Channel, Server, Service, User
from .monitoring import check_service, run_once, send_channel_test
from .schemas import ChannelCreate, LoginRequest, ServerCreate, ServiceCreate
from .security import create_token, hash_password, require_user, verify_password

settings = get_settings()
app = FastAPI(title=settings.app_name, version="3.0.0")


def serialize(item):
    result = {column.name: getattr(item, column.name) for column in item.__table__.columns}
    for key in ("created_at", "last_checked_at"):
        if result.get(key): result[key] = result[key].isoformat()
    for secret in ("agent_token", "token"):
        if secret in result: result[secret] = "configured" if result[secret] else ""
    if "endpoint" in result and result.get("type") in ("slack", "webhook"):
        result["endpoint"] = "configured" if result["endpoint"] else ""
    if result.get("last_metrics"):
        result["last_metrics"] = json.loads(result["last_metrics"])
    return result


@app.on_event("startup")
def startup() -> None:
    with Session(engine) as session:
        if not session.scalar(select(User).limit(1)):
            session.add(User(email=settings.admin_email.lower(), password_hash=hash_password(settings.admin_password)))
            session.commit()


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
    }


@app.post("/api/auth/login")
def login(payload: LoginRequest, db: Session = Depends(get_db)) -> dict[str, str]:
    user = db.scalar(select(User).where(User.email == payload.email.lower()))
    if not user or not verify_password(payload.password, user.password_hash):
        raise HTTPException(401, "Invalid email or password")
    return {"token": create_token(user.id, user.email), "email": user.email}


@app.get("/api/auth/me")
def me(user: dict = Depends(require_user), db: Session = Depends(get_db)) -> dict:
    account = db.get(User, int(user["sub"]))
    return {"id": account.id, "email": account.email, "role": account.role}


@app.get("/api/dashboard")
def dashboard(_: dict = Depends(require_user), db: Session = Depends(get_db)) -> dict:
    servers = db.scalars(select(Server).order_by(Server.name)).all()
    services = db.scalars(select(Service).order_by(Service.name)).all()
    events = db.scalars(select(AlertEvent).order_by(desc(AlertEvent.created_at)).limit(10)).all()
    statuses = [item.last_status for item in [*servers, *services]]
    return {
        "servers": [serialize(item) for item in servers],
        "services": [serialize(item) for item in services],
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
        "summary": {"servers": len(servers), "services": len(services), "up": statuses.count("up"), "alerts": sum(value in ("alert", "down", "degraded") for value in statuses)},
    }


@app.get("/api/channels")
def channels(_: dict = Depends(require_user), db: Session = Depends(get_db)) -> list[dict]:
    return [serialize(item) for item in db.scalars(select(Channel).order_by(Channel.name)).all()]


@app.post("/api/channels")
def create_channel(payload: ChannelCreate, _: dict = Depends(require_user), db: Session = Depends(get_db)) -> dict:
    item = Channel(**payload.model_dump()); db.add(item); db.commit(); db.refresh(item); return serialize(item)


@app.post("/api/channels/{item_id}/test")
def test_channel(item_id: int, _: dict = Depends(require_user), db: Session = Depends(get_db)) -> dict[str, str | bool]:
    item = db.get(Channel, item_id)
    if not item:
        raise HTTPException(404, "Notification channel not found")
    delivered, detail = send_channel_test(item)
    if not delivered:
        raise HTTPException(502, detail)
    return {"ok": True, "detail": detail}


@app.delete("/api/channels/{item_id}")
def delete_channel(item_id: int, _: dict = Depends(require_user), db: Session = Depends(get_db)) -> dict[str, bool]:
    item = db.get(Channel, item_id)
    if item: db.delete(item); db.commit()
    return {"deleted": True}


@app.post("/api/servers")
def create_server(payload: ServerCreate, _: dict = Depends(require_user), db: Session = Depends(get_db)) -> dict:
    if payload.monitor_mode == "agent" and len(payload.agent_token) < 32:
        raise HTTPException(422, "Agent token must be at least 32 characters")
    item = Server(**payload.model_dump()); db.add(item); db.commit(); db.refresh(item); return serialize(item)


@app.put("/api/servers/{item_id}")
def update_server(item_id: int, payload: ServerCreate, _: dict = Depends(require_user), db: Session = Depends(get_db)) -> dict:
    item = db.get(Server, item_id)
    if not item:
        raise HTTPException(404, "Server not found")
    values = payload.model_dump()
    if values["monitor_mode"] == "ping":
        values["endpoint"] = ""
        values["agent_token"] = None
    elif not values["agent_token"]:
        values["agent_token"] = item.agent_token
    if values["monitor_mode"] == "agent" and len(values["agent_token"] or "") < 32:
        raise HTTPException(422, "Agent token must be at least 32 characters")
    for key, value in values.items():
        setattr(item, key, value)
    item.last_checked_at = None
    item.last_status = "unknown"
    item.last_error = None
    db.commit()
    db.refresh(item)
    return serialize(item)


@app.delete("/api/servers/{item_id}")
def delete_server(item_id: int, _: dict = Depends(require_user), db: Session = Depends(get_db)) -> dict[str, bool]:
    item = db.get(Server, item_id)
    if item: db.delete(item); db.commit()
    return {"deleted": True}


@app.post("/api/services")
def create_service(payload: ServiceCreate, _: dict = Depends(require_user), db: Session = Depends(get_db)) -> dict:
    if payload.server_id is not None and not db.get(Server, payload.server_id): raise HTTPException(404, "Server not found")
    item = Service(**payload.model_dump()); db.add(item); db.commit(); db.refresh(item); return serialize(item)


@app.put("/api/services/{item_id}")
def update_service(item_id: int, payload: ServiceCreate, _: dict = Depends(require_user), db: Session = Depends(get_db)) -> dict:
    item = db.get(Service, item_id)
    if not item:
        raise HTTPException(404, "Service monitor not found")
    values = payload.model_dump()
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
def delete_service(item_id: int, _: dict = Depends(require_user), db: Session = Depends(get_db)) -> dict[str, bool]:
    item = db.get(Service, item_id)
    if item: db.delete(item); db.commit()
    return {"deleted": True}


@app.post("/api/services/{item_id}/check")
def check_service_now(item_id: int, _: dict = Depends(require_user), db: Session = Depends(get_db)) -> dict:
    item = db.get(Service, item_id)
    if not item:
        raise HTTPException(404, "Service monitor not found")
    try:
        return check_service(item, db)
    except Exception as error:
        db.rollback()
        raise HTTPException(502, f"Service check failed: {error}") from error


@app.post("/api/monitor/run")
def run_monitor(background_tasks: BackgroundTasks, _: dict = Depends(require_user)) -> dict[str, str]:
    background_tasks.add_task(run_once)
    return {"status": "queued"}
