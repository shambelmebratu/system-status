"""User administration (admin only). Roles: admin (everything), operator (manage monitoring), viewer (read-only)."""
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .database import get_db
from .models import User
from .schemas import UserCreate, UserUpdate
from .security import hash_password, require_admin
from .stats import aware

router = APIRouter(prefix="/api/users", tags=["users"])


def serialize_user(user: User) -> dict:
    return {
        "id": user.id, "email": user.email, "name": user.name, "role": user.role, "active": user.active,
        "must_change_password": user.must_change_password,
        "last_login_at": aware(user.last_login_at).isoformat() if user.last_login_at else None,
        "created_at": aware(user.created_at).isoformat() if user.created_at else None,
    }


def other_active_admins(db: Session, user: User) -> int:
    return db.scalar(select(func.count()).select_from(User).where(User.role == "admin", User.active.is_(True), User.id != user.id)) or 0


@router.get("")
def list_users(_: dict = Depends(require_admin), db: Session = Depends(get_db)) -> list[dict]:
    return [serialize_user(u) for u in db.scalars(select(User).order_by(User.id)).all()]


@router.post("")
def create_user(payload: UserCreate, _: dict = Depends(require_admin), db: Session = Depends(get_db)) -> dict:
    email = payload.email.strip().lower()
    if db.scalar(select(User.id).where(User.email == email)) is not None:
        raise HTTPException(409, "A user with that email already exists")
    user = User(email=email, name=payload.name.strip(), role=payload.role, password_hash=hash_password(payload.password), must_change_password=True)
    db.add(user); db.commit(); db.refresh(user)
    return serialize_user(user)


@router.put("/{user_id}")
def update_user(user_id: int, payload: UserUpdate, me: dict = Depends(require_admin), db: Session = Depends(get_db)) -> dict:
    user = db.get(User, user_id)
    if not user:
        raise HTTPException(404, "User not found")
    is_self = user.id == me["uid"]
    if is_self and ((payload.role is not None and payload.role != user.role) or payload.active is False):
        raise HTTPException(409, "You cannot change your own role or disable your own account. Ask another admin.")
    losing_admin = user.role == "admin" and ((payload.role is not None and payload.role != "admin") or payload.active is False)
    if losing_admin and other_active_admins(db, user) == 0:
        raise HTTPException(409, "There must always be at least one active admin")
    revoke = False
    if payload.name is not None:
        user.name = payload.name.strip()
    if payload.role is not None and payload.role != user.role:
        user.role, revoke = payload.role, True
    if payload.active is not None and payload.active != user.active:
        user.active, revoke = payload.active, True
    if payload.password:
        user.password_hash = hash_password(payload.password)
        user.must_change_password = not is_self      # a reset by an admin is temporary; the person picks their own
        revoke = True
    if revoke and not is_self:
        user.token_version += 1                      # sign the person out everywhere so the change applies at once
    db.commit(); db.refresh(user)
    return serialize_user(user)


@router.delete("/{user_id}")
def delete_user(user_id: int, me: dict = Depends(require_admin), db: Session = Depends(get_db)) -> dict[str, bool]:
    user = db.get(User, user_id)
    if not user:
        return {"deleted": True}
    if user.id == me["uid"]:
        raise HTTPException(409, "You cannot delete your own account")
    if user.role == "admin" and user.active and other_active_admins(db, user) == 0:
        raise HTTPException(409, "There must always be at least one active admin")
    db.delete(user); db.commit()
    return {"deleted": True}
