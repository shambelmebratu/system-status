"""Audit trail. Every security-relevant action is recorded with who, what, from where and whether it succeeded.

Never put secrets in `detail`: only identifiers and short descriptions."""
from fastapi import Request
from sqlalchemy.orm import Session

from .models import AuditEvent
from .security import client_ip


def audit(db: Session, request: Request | None, action: str, *, user: dict | None = None, actor: str | None = None, target: str = "",
          detail: str | None = None, success: bool = True, commit: bool = False) -> None:
    """Adds an event to the session (committed with the caller's transaction, or immediately with commit=True)."""
    who = actor if actor is not None else (user["email"] if user else "system")
    db.add(AuditEvent(
        actor=who[:320], actor_role=(user or {}).get("role"), action=action[:60], target=str(target)[:200],
        detail=(detail or None) and detail[:1000], ip=client_ip(request) if request is not None else None, success=success,
    ))
    from .zerotrust import on_audit
    on_audit(db, action=action, actor=who, target=str(target), detail=detail, ip=client_ip(request) if request is not None else None, success=success)
    if commit:
        db.commit()
