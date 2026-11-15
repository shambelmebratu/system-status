"""User administration (admin only). Roles: admin (everything), operator (manage monitoring), viewer (read-only)."""
import json
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .audit import audit
from .database import get_db
from .models import Cluster, Server, Service, User
from .schemas import AccessScope, UserCreate, UserUpdate
from .security import SCOPE_KINDS, hash_password, parse_scope, require_admin
from .stats import aware

router = APIRouter(prefix="/api/users", tags=["users"])


def serialize_user(user: User) -> dict:
    return {
        "id": user.id, "email": user.email, "name": user.name, "role": user.role, "active": user.active,
        "must_change_password": user.must_change_password,
        "access": ({k: sorted(v) for k, v in scope.items()} if (scope := parse_scope(user.access_scope, user.role)) is not None else None),
        "last_login_at": aware(user.last_login_at).isoformat() if user.last_login_at else None,
        "created_at": aware(user.created_at).isoformat() if user.created_at else None,
    }


def stored_scope(db: Session, access: AccessScope | None, role: str) -> tuple[str | None, str]:
    """(value for users.access_scope, text for the audit log). Admins always see everything; ids that do not exist are dropped."""
    if access is None or role == "admin":
        return None, "access: everything"
    known = {"servers": Server, "services": Service, "clusters": Cluster}
    clean = {kind: sorted(set(db.scalars(select(known[kind].id).where(known[kind].id.in_(getattr(access, kind) or [0]))).all())) for kind in SCOPE_KINDS}
    return json.dumps(clean), "access limited to " + ", ".join(f"{len(clean[k])} {k}" for k in SCOPE_KINDS)


def other_active_admins(db: Session, user: User) -> int:
    return db.scalar(select(func.count()).select_from(User).where(User.role == "admin", User.active.is_(True), User.id != user.id)) or 0


@router.get("")
def list_users(_: dict = Depends(require_admin), db: Session = Depends(get_db)) -> list[dict]:
    return [serialize_user(u) for u in db.scalars(select(User).order_by(User.id)).all()]


@router.post("")
def create_user(payload: UserCreate, request: Request, me: dict = Depends(require_admin), db: Session = Depends(get_db)) -> dict:
    email = payload.email.strip().lower()
    if db.scalar(select(User.id).where(User.email == email)) is not None:
        raise HTTPException(409, "A user with that email already exists")
    scope, scope_text = stored_scope(db, payload.access, payload.role)
    user = User(email=email, name=payload.name.strip(), role=payload.role, password_hash=hash_password(payload.password), must_change_password=True, access_scope=scope)
    db.add(user); db.flush()
    audit(db, request, "user.create", user=me, target=f"user:{user.id}", detail=f"{user.email} as {user.role}; {scope_text}")
    db.commit(); db.refresh(user)
    return serialize_user(user)


@router.put("/{user_id}")
def update_user(user_id: int, payload: UserUpdate, request: Request, me: dict = Depends(require_admin), db: Session = Depends(get_db)) -> dict:
    user = db.get(User, user_id)
    if not user:
        raise HTTPException(404, "User not found")
    is_self = user.id == me["uid"]
    if is_self and ((payload.role is not None and payload.role != user.role) or payload.active is False):
        raise HTTPException(409, "You cannot change your own role or disable your own account. Ask another admin.")
    if is_self and payload.password:
        # Otherwise a stolen admin session could set a new password without knowing the current one (and keep every session alive).
        raise HTTPException(409, "Change your own password under Profile: it needs your current password.")
    losing_admin = user.role == "admin" and ((payload.role is not None and payload.role != "admin") or payload.active is False)
    if losing_admin and other_active_admins(db, user) == 0:
        raise HTTPException(409, "There must always be at least one active admin")
    revoke = False
    changes = []
    if payload.name is not None:
        user.name = payload.name.strip()
    if payload.role is not None and payload.role != user.role:
        changes.append(f"role {user.role} -> {payload.role}")
        user.role, revoke = payload.role, True
    if payload.active is not None and payload.active != user.active:
        changes.append("enabled" if payload.active else "disabled")
        user.active, revoke = payload.active, True
    if payload.access_set or (user.role == "admin" and user.access_scope):
        scope, scope_text = stored_scope(db, payload.access if payload.access_set else None, user.role)   # promoted to admin: any limit is dropped
        if scope != user.access_scope:
            changes.append(scope_text)
            user.access_scope = scope
    if payload.password:
        changes.append("password reset")
        user.password_hash = hash_password(payload.password)
        user.must_change_password = True             # a reset by an admin is temporary; the person picks their own
        revoke = True
    if revoke and not is_self:
        user.token_version += 1                      # sign the person out everywhere so the change applies at once
    if changes:
        audit(db, request, "user.update", user=me, target=f"user:{user.id}", detail=f"{user.email}: " + ", ".join(changes))
    db.commit(); db.refresh(user)
    return serialize_user(user)


@router.delete("/{user_id}")
def delete_user(user_id: int, request: Request, me: dict = Depends(require_admin), db: Session = Depends(get_db)) -> dict[str, bool]:
    user = db.get(User, user_id)
    if not user:
        return {"deleted": True}
    if user.id == me["uid"]:
        raise HTTPException(409, "You cannot delete your own account")
    if user.role == "admin" and user.active and other_active_admins(db, user) == 0:
        raise HTTPException(409, "There must always be at least one active admin")
    audit(db, request, "user.delete", user=me, target=f"user:{user.id}", detail=user.email)
    db.delete(user); db.commit()
    return {"deleted": True}
