"""Agent self-registration: admin-issued join tokens, the enroll endpoint, and personalised install scripts."""
import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import PlainTextResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from .audit import audit
from .config import get_settings, resolved_agent_image
from .database import get_db
from .models import Enrollment, Server
from .routes_agent import hash_token
from .schemas import EnrollmentCreate, EnrollRequest
from .security import agent_gate, client_ip, login_limiter, require_unrestricted
from .stats import aware

router = APIRouter(tags=["enrollment"])
ROOT = Path(__file__).resolve().parent.parent


def serialize_enrollment(item: Enrollment) -> dict:
    now = datetime.now(timezone.utc)
    expired = bool(item.expires_at and aware(item.expires_at) < now)
    exhausted = item.max_uses is not None and item.uses >= item.max_uses
    return {
        "id": item.id, "label": item.label, "token": item.token, "uses": item.uses, "max_uses": item.max_uses,
        "created_by": item.created_by, "created_at": aware(item.created_at).isoformat(), "expires_at": aware(item.expires_at).isoformat() if item.expires_at else None,
        "last_used_at": aware(item.last_used_at).isoformat() if item.last_used_at else None,
        "revoked": item.revoked, "active": not (item.revoked or expired or exhausted),
        "state": "revoked" if item.revoked else "expired" if expired else "used up" if exhausted else "active",
    }


@router.get("/api/enrollments")
def list_enrollments(_: dict = Depends(require_unrestricted), db: Session = Depends(get_db)) -> list[dict]:
    return [serialize_enrollment(i) for i in db.scalars(select(Enrollment).order_by(Enrollment.id.desc()).limit(100)).all()]


@router.post("/api/enrollments")
def create_enrollment(payload: EnrollmentCreate, request: Request, user: dict = Depends(require_unrestricted), db: Session = Depends(get_db)) -> dict:
    limit = get_settings().enrollment_max_minutes
    if payload.expires_minutes > limit:
        raise HTTPException(422, f"Install links can be valid for at most {limit} minutes")
    token = "smwj_" + secrets.token_urlsafe(24)  # 192 bits from the OS CSPRNG: unguessable, never reused
    item = Enrollment(
        label=payload.label, token=token, token_hash=hash_token(token), max_uses=payload.max_uses, created_by=user["email"],
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=payload.expires_minutes),
    )
    db.add(item); db.flush()
    audit(db, request, "enroll.link_create", user=user, target=f"enrollment:{item.id}", detail=f"{item.label or 'unnamed'}: {payload.expires_minutes} min, max uses {payload.max_uses or 'unlimited'}")
    db.commit(); db.refresh(item)
    return serialize_enrollment(item)


@router.delete("/api/enrollments/{item_id}")
def revoke_enrollment(item_id: int, request: Request, user: dict = Depends(require_unrestricted), db: Session = Depends(get_db)) -> dict[str, bool]:
    """Revokes the join token. Servers that already joined keep working (they have their own tokens)."""
    item = db.get(Enrollment, item_id)
    if item:
        item.revoked = True
        audit(db, request, "enroll.link_revoke", user=user, target=f"enrollment:{item.id}", detail=item.label or "unnamed")
        db.commit()
    return {"revoked": True}


def find_enrollment(db: Session, token: str) -> Enrollment | None:
    item = db.scalar(select(Enrollment).where(Enrollment.token_hash == hash_token(token))) if token else None
    if item is None or item.revoked or (item.expires_at and aware(item.expires_at) < datetime.now(timezone.utc)):
        return None
    return item


def clean_name(value: str) -> str:
    """Host names come from the machine being registered: keep printable characters only (no control characters or line breaks
    that could disguise text in the dashboard, audit log or alerts)."""
    cleaned = "".join(ch if ch.isprintable() else " " for ch in value)
    return " ".join(cleaned.split())[:90] or "server"


def is_live(server: Server) -> bool:
    from .monitoring import heartbeat_grace
    if not server.last_seen_at:
        return False
    return (datetime.now(timezone.utc) - aware(server.last_seen_at)).total_seconds() <= heartbeat_grace(server.check_interval_seconds)


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
    client = agent_gate(request, "enroll")
    auth = request.headers.get("authorization", "")
    item = find_enrollment(db, auth[7:] if auth.startswith("Bearer ") else "")
    if item is None:
        if login_limiter.fail_unique(client, auth):   # one audit line per wrong link, not one per request
            audit(db, request, "agent.enroll", actor=f"agent:{clean_name(payload.hostname)[:80]}", success=False, detail="invalid, expired or revoked join link", commit=True)
        raise HTTPException(401, "Join token is invalid, expired or revoked")
    machine = hashlib.sha256(("smwatch:" + payload.machine_id).encode()).hexdigest() if payload.machine_id else None
    server = db.scalar(select(Server).where(Server.machine_id == machine, Server.monitor_mode == "push")) if machine else None
    if server is None:
        if item.max_uses is not None and item.uses >= item.max_uses:
            if login_limiter.first_time(f"used-up:{item.id}:{client_ip(request)}"):
                audit(db, request, "agent.enroll", actor=f"agent:{clean_name(payload.hostname)[:80]}", target=f"enrollment:{item.id}", success=False, detail="join link used up", commit=True)
            raise HTTPException(403, "This join token has reached its maximum number of uses")
        settings = get_settings()
        server = Server(
            name=unique_name(db, clean_name(payload.hostname)), host="", monitor_mode="push", check_interval_seconds=settings.check_interval_seconds,
            cpu_threshold=settings.cpu_threshold, memory_threshold=settings.memory_threshold, disk_threshold=settings.disk_threshold,
            load_threshold=settings.load_threshold, swap_threshold=settings.swap_threshold, process_threshold=settings.process_threshold,
            machine_id=machine,
        )
        db.add(server)
        item.uses += 1
    elif is_live(server) and server.last_agent_ip and server.last_agent_ip != client_ip(request):
        # Re-registering re-issues the server's token and cuts the running agent off. A machine id is not a secret, so a join link
        # alone must not be enough to take over a server that is online: a genuine re-install comes from the server's own address.
        if login_limiter.first_time(f"takeover:{server.id}:{client_ip(request)}"):
            audit(db, request, "agent.enroll", actor=f"agent:{clean_name(payload.hostname)[:80]}", target=f"server:{server.id}", success=False,
                  detail=f"refused: {server.name} is online from {server.last_agent_ip}; re-registration attempted from another address", commit=True)
        raise HTTPException(409, "This machine is already registered and currently online from a different address. Run the command on that server itself, or remove the server in the dashboard first.")
    token = secrets.token_urlsafe(32)
    server.agent_token, server.token_hash, server.enabled = token, hash_token(token), True  # a re-install rotates the server's token
    server.token_issued_at = datetime.now(timezone.utc)
    server.pending_token = server.pending_token_hash = server.pending_token_at = None
    item.last_used_at = datetime.now(timezone.utc)
    db.flush()
    audit(db, request, "agent.enroll", actor=f"agent:{server.name}", target=f"server:{server.id}", detail=f"registered via link {item.id} ({item.label or 'unnamed'}); platform {payload.platform[:60]}")
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
    gate = agent_gate(request, "join")                # someone guessing links is throttled
    if find_enrollment(db, token) is None:
        login_limiter.fail_unique(gate, token)
        return "#!/usr/bin/env bash\necho 'This join link is invalid, expired or revoked. Ask a dashboard admin for a new command.' >&2\nexit 1\n"
    body = (ROOT / template).read_text()
    body = "\n".join(line for i, line in enumerate(body.splitlines()) if not (i == 0 and line.startswith("#!")))
    exports = f"SMWATCH_URL={shell_quote(control_plane_url(request))} SMWATCH_JOIN={shell_quote(token)}"
    if template == "agent_install.sh":
        # The installer verifies the agent file it downloads against this hash.
        exports += f" SMWATCH_AGENT_SHA256={hashlib.sha256((ROOT / 'agent.py').read_bytes()).hexdigest()}"
    else:
        # Docker: run the published image (the agent code is inside it). Nothing is downloaded when the container starts.
        exports += f" SMWATCH_AGENT_IMAGE={shell_quote(resolved_agent_image(get_settings()))}"
    return f"#!/usr/bin/env bash\nexport {exports}\n{body}\n"


@router.get("/api/agent/join/{token}", response_class=PlainTextResponse)
def join_script(token: str, request: Request, db: Session = Depends(get_db)) -> str:
    """Personalised installer: `curl -fsSL <url>/api/agent/join/<token> | sudo bash`."""
    return render(request, token, db, "agent_install.sh")


@router.get("/api/agent/join/{token}/docker", response_class=PlainTextResponse)
def join_docker_script(token: str, request: Request, db: Session = Depends(get_db)) -> str:
    """Docker variant: `curl -fsSL <url>/api/agent/join/<token>/docker | sudo bash`."""
    return render(request, token, db, "agent_install_docker.sh")


@router.get("/api/agent/docker-update.sh", response_class=PlainTextResponse)
def docker_update_script(request: Request) -> str:
    """`curl -fsSL <url>/api/agent/docker-update.sh | sudo bash`: updates a Docker agent in place, no link or token needed.
    The script contains only the public image name; the agent's own settings are read from its local container."""
    body = (ROOT / "agent_update_docker.sh").read_text()
    body = "\n".join(line for i, line in enumerate(body.splitlines()) if not (i == 0 and line.startswith("#!")))
    return f"#!/usr/bin/env bash\nexport SMWATCH_AGENT_IMAGE={shell_quote(resolved_agent_image(get_settings()))}\n{body}\n"
