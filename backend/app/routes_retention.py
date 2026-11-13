"""Admin controls for data retention: how long things are kept, the automatic purge schedule, and manual purges."""
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from . import retention
from .audit import audit
from .database import get_db
from .security import require_admin

router = APIRouter(prefix="/api/retention", tags=["retention"])


class RetentionUpdate(BaseModel):
    days: dict[str, int] = Field(default_factory=dict)
    auto: bool | None = None
    frequency: str | None = Field(default=None, pattern="^(hourly|daily|weekly)$")
    time: str | None = Field(default=None, pattern=r"^([01]\d|2[0-3]):[0-5]\d$")
    weekday: int | None = Field(default=None, ge=0, le=6)


class PurgeRequest(BaseModel):
    categories: list[str] = Field(min_length=1, max_length=len(retention.CATEGORIES))
    older_than_days: int = Field(default=0, ge=0, le=3650, description="0 = everything of that kind")


def view(db: Session) -> dict:
    cfg = retention.load(db)
    return {"settings": cfg, "stats": retention.stats(db), "audit_min_days": retention.AUDIT_MIN_DAYS, "now": datetime.now(timezone.utc).isoformat()}


@router.get("")
def read(_: dict = Depends(require_admin), db: Session = Depends(get_db)) -> dict:
    return view(db)


@router.put("")
def update(payload: RetentionUpdate, request: Request, user: dict = Depends(require_admin), db: Session = Depends(get_db)) -> dict:
    cfg = retention.load(db)
    changes = []
    for key, days in payload.days.items():
        if key not in retention.CATEGORIES or key == "transient":
            raise HTTPException(422, f"Unknown data kind '{key}'")
        if not 1 <= days <= 3650:
            raise HTTPException(422, "Retention must be between 1 and 3650 days")
        if key == "audit" and days < retention.AUDIT_MIN_DAYS:
            raise HTTPException(422, f"The audit log must be kept at least {retention.AUDIT_MIN_DAYS} days")
        if cfg["days"].get(key) != days:
            changes.append(f"{key}={days}d")
            cfg["days"][key] = days
    for key in ("auto", "frequency", "time", "weekday"):
        value = getattr(payload, key)
        if value is not None and cfg[key] != value:
            changes.append(f"{key}={value}")
            cfg[key] = value
    if changes:
        retention.save(db, cfg, user["email"])
        audit(db, request, "purge.settings", user=user, detail=", ".join(changes))
        db.commit()
    return view(db)


@router.post("/purge")
def purge_now(payload: PurgeRequest, request: Request, user: dict = Depends(require_admin), db: Session = Depends(get_db)) -> dict:
    unknown = [c for c in payload.categories if c not in retention.CATEGORIES]
    if unknown:
        raise HTTPException(422, f"Unknown data kind '{unknown[0]}'")
    try:
        deleted = retention.purge(db, list(dict.fromkeys(payload.categories)), payload.older_than_days)
    except ValueError as error:
        db.rollback()
        raise HTTPException(422, str(error))
    cfg = retention.load(db)
    now = datetime.now(timezone.utc).isoformat()
    cfg["last_result"] = {"by": user["email"], "deleted": deleted, "at": now}
    retention.save(db, cfg, user["email"])
    scope = "everything" if not payload.older_than_days else f"older than {payload.older_than_days} days"
    audit(db, request, "purge.manual", user=user, detail=f"{scope}: {retention.summarize(deleted)}")
    db.commit()
    return {"deleted": deleted, **view(db)}
