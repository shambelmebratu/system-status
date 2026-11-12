"""Agent self-registration: admin-issued join tokens, the enroll endpoint, and personalised install scripts."""
import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import PlainTextResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from .config import get_settings
from .database import get_db
from .models import Enrollment, Server
from .routes_agent import hash_token
from .schemas import EnrollmentCreate, EnrollRequest
from .security import login_limiter, require_user
from .stats import aware

router = APIRouter(tags=["enrollment"])
ROOT = Path(__file__).resolve().parent.parent


def serialize_enrollment(item: Enrollment) -> dict:
    now = datetime.now(timezone.utc)
    expired = bool(item.expires_at and aware(item.expires_at) < now)
    exhausted = item.max_uses is not None and item.uses >= item.max_uses
    return {
        "id": item.id, "label": item.label, "token": item.token, "uses": item.uses, "max_uses": item.max_uses,
        "created_at": aware(item.created_at).isoformat(), "expires_at": aware(item.expires_at).isoformat() if item.expires_at else None,
        "last_used_at": aware(item.last_used_at).isoformat() if item.last_used_at else None,
        "revoked": item.revoked, "active": not (item.revoked or expired or exhausted),
        "state": "revoked" if item.revoked else "expired" if expired else "used up" if exhausted else "active",
    }


@router.get("/api/enrollments")
def list_enrollments(_: dict = Depends(require_user), db: Session = Depends(get_db)) -> list[dict]:
    return [serialize_enrollment(i) for i in db.scalars(select(Enrollment).order_by(Enrollment.id.desc()).limit(100)).all()]


@router.post("/api/enrollments")
def create_enrollment(payload: EnrollmentCreate, _: dict = Depends(require_user), db: Session = Depends(get_db)) -> dict:
    token = "smwj_" + secrets.token_urlsafe(24)  # 192 bits from the OS CSPRNG: unguessable, never reused
    item = Enrollment(
        label=payload.label, token=token, token_hash=hash_token(token), max_uses=payload.max_uses,
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=payload.expires_minutes),
    )
    db.add(item); db.commit(); db.refresh(item)
    return serialize_enrollment(item)


@router.delete("/api/enrollments/{item_id}")
def revoke_enrollment(item_id: int, _: dict = Depends(require_user), db: Session = Depends(get_db)) -> dict[str, bool]:
    """Revokes the join token. Servers that already joined keep working (they have their own tokens)."""
    item = db.get(Enrollment, item_id)
    if item:
        item.revoked = True
        db.commit()
    return {"revoked": True}


def find_enrollment(db: Session, token: str) -> Enrollment | None:
    item = db.scalar(select(Enrollment).where(Enrollment.token_hash == hash_token(token))) if token else None
    if item is None or item.revoked or (item.expires_at and aware(item.expires_at) < datetime.now(timezone.utc)):
        return None
    return item


def unique_name(db: Session, hostname: str) -> str:
    base = hostname.strip()[:90] or "server"
    name, n = base, 1
    while db.scalar(select(Server.id).where(Server.name == name).limit(1)) is not None:
        n += 1
        name = f"{base}-{n}"
    return name


@router.post("/api/agent/enroll")
def enroll(payload: EnrollRequest, request: Request, db: Session = Depends(get_db)) -> dict:
    """An agent presents a join token and receives its own per-server token. Re-enrolling the same machine reuses its server."""
    client = f"enroll:{request.client.host if request.client else 'unknown'}"
    login_limiter.check(client)
    auth = request.headers.get("authorization", "")
    item = find_enrollment(db, auth[7:] if auth.startswith("Bearer ") else "")
    if item is None:
        login_limiter.fail(client)
        raise HTTPException(401, "Join token is invalid, expired or revoked")
    machine = hashlib.sha256(("smwatch:" + payload.machine_id).encode()).hexdigest() if payload.machine_id else None
    server = db.scalar(select(Server).where(Server.machine_id == machine, Server.monitor_mode == "push")) if machine else None
    if server is None:
        if item.max_uses is not None and item.uses >= item.max_uses:
            raise HTTPException(403, "This join token has reached its maximum number of uses")
        settings = get_settings()
        server = Server(
            name=unique_name(db, payload.hostname), host="", monitor_mode="push", check_interval_seconds=settings.check_interval_seconds,
            cpu_threshold=settings.cpu_threshold, memory_threshold=settings.memory_threshold, disk_threshold=settings.disk_threshold,
            load_threshold=settings.load_threshold, swap_threshold=settings.swap_threshold, process_threshold=settings.process_threshold,
            machine_id=machine,
        )
        db.add(server)
        item.uses += 1
    token = secrets.token_urlsafe(32)
    server.agent_token, server.token_hash, server.enabled = token, hash_token(token), True  # a re-install rotates the server's token
    item.last_used_at = datetime.now(timezone.utc)
    db.commit(); db.refresh(server)
    return {"server_id": server.id, "name": server.name, "agent_token": token, "interval_seconds": server.check_interval_seconds}


def control_plane_url(request: Request) -> str:
    configured = get_settings().public_url.rstrip("/")
    if configured:
        return configured
    host = request.headers.get("x-forwarded-host") or request.headers.get("host") or "localhost"
    scheme = request.headers.get("x-forwarded-proto") or request.url.scheme
    return f"{scheme}://{host}"


def shell_quote(value: str) -> str:
    return "'" + value.replace("'", "'\"'\"'") + "'"


def render(request: Request, token: str, db: Session, template: str) -> str:
    if find_enrollment(db, token) is None:
        return "#!/usr/bin/env bash\necho 'This join link is invalid, expired or revoked. Ask a dashboard admin for a new command.' >&2\nexit 1\n"
    body = (ROOT / template).read_text()
    body = "\n".join(line for i, line in enumerate(body.splitlines()) if not (i == 0 and line.startswith("#!")))
    return f"#!/usr/bin/env bash\nexport SMWATCH_URL={shell_quote(control_plane_url(request))} SMWATCH_JOIN={shell_quote(token)}\n{body}\n"


@router.get("/api/agent/join/{token}", response_class=PlainTextResponse)
def join_script(token: str, request: Request, db: Session = Depends(get_db)) -> str:
    """Personalised installer: `curl -fsSL <url>/api/agent/join/<token> | sudo bash`."""
    return render(request, token, db, "agent_install.sh")


@router.get("/api/agent/join/{token}/docker", response_class=PlainTextResponse)
def join_docker_script(token: str, request: Request, db: Session = Depends(get_db)) -> str:
    """Docker variant: `curl -fsSL <url>/api/agent/join/<token>/docker | sudo bash`."""
    return render(request, token, db, "agent_install_docker.sh")
