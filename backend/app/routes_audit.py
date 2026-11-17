"""Read access to the audit trail (admins only). The trail is append-only: there is no way to edit or delete events through the API."""
from fastapi import APIRouter, Depends, Query
from sqlalchemy import desc, or_, select
from sqlalchemy.orm import Session

from .database import get_db
from .models import AuditEvent
from .security import require_admin
from .stats import aware

router = APIRouter(prefix="/api/audit", tags=["audit"])


@router.get("")
def list_events(
    limit: int = Query(200, ge=1, le=1000), category: str = Query("", pattern="^(|auth|user|server|service|schedule|agent|enroll|logs|channel|k8s|purge|db|qa|devops|security|ai)$"),
    failures: bool = False, q: str = Query("", max_length=100), _: dict = Depends(require_admin), db: Session = Depends(get_db),
) -> list[dict]:
    query = select(AuditEvent).order_by(desc(AuditEvent.id)).limit(limit)
    if category:
        query = query.where(AuditEvent.action.like(f"{category}.%"))
    if failures:
        query = query.where(AuditEvent.success.is_(False))
    if q:
        like = f"%{q}%"
        query = query.where(or_(AuditEvent.actor.ilike(like), AuditEvent.target.ilike(like), AuditEvent.detail.ilike(like), AuditEvent.ip.ilike(like), AuditEvent.action.ilike(like)))
    return [
        {"id": e.id, "ts": aware(e.ts).isoformat(), "actor": e.actor, "actor_role": e.actor_role, "action": e.action, "target": e.target,
         "detail": e.detail, "ip": e.ip, "success": e.success}
        for e in db.scalars(query).all()
    ]
