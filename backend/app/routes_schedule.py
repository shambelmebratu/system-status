"""CRUD for scheduled messages and an on-demand 'send now'."""
import json
from datetime import datetime, timezone

from fastapi import Request, APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from .audit import audit
from .database import get_db
from .models import Channel, ScheduledMessage
from .schemas import ScheduledMessageIn
from .scheduler import channel_list, compute_next_run, get_zone, parse_days, render_text, send_scheduled
from .security import require_operator
from .stats import aware

router = APIRouter(prefix="/api/scheduled-messages", tags=["scheduled"])


def serialize(item: ScheduledMessage, preview: bool = True) -> dict:
    iso = lambda v: aware(v).isoformat() if v else None  # noqa: E731
    return {
        "id": item.id, "name": item.name, "text": item.text, "channel_ids": channel_list(item.channel_ids), "repeat": item.repeat,
        "time_of_day": item.time_of_day, "days_of_week": parse_days(item.days_of_week), "run_at": iso(item.run_at), "timezone": item.timezone,
        "enabled": item.enabled, "next_run_at": iso(item.next_run_at), "last_run_at": iso(item.last_run_at), "last_status": item.last_status,
        "last_error": item.last_error, "created_at": iso(item.created_at),
        "preview": render_text(item, item.next_run_at or datetime.now(timezone.utc)) if preview else None,
    }


def apply(item: ScheduledMessage, payload: ScheduledMessageIn, db: Session) -> None:
    try:
        get_zone(payload.timezone)
    except ValueError as error:
        raise HTTPException(422, str(error)) from error
    found = {c for c in db.scalars(select(Channel.id).where(Channel.id.in_(payload.channel_ids))).all()}
    missing = sorted(set(payload.channel_ids) - found)
    if missing:
        raise HTTPException(422, f"Unknown notification channel id(s): {missing}")
    if any(d < 1 or d > 7 for d in payload.days_of_week):
        raise HTTPException(422, "days_of_week must contain numbers 1 (Mon) to 7 (Sun)")
    if payload.repeat == "weekly" and not payload.days_of_week:
        raise HTTPException(422, "Pick at least one weekday for a weekly schedule")
    now = datetime.now(timezone.utc)
    if payload.repeat == "once" and (payload.run_at is None or aware(payload.run_at) <= now):
        raise HTTPException(422, "Choose a date and time in the future for a one-time message")
    item.name, item.text, item.repeat, item.time_of_day, item.timezone, item.enabled = payload.name, payload.text, payload.repeat, payload.time_of_day, payload.timezone, payload.enabled
    item.channel_ids = json.dumps(sorted(set(payload.channel_ids)))
    item.days_of_week = ",".join(str(d) for d in sorted(set(payload.days_of_week)))
    item.run_at = aware(payload.run_at) if payload.run_at else None
    item.attempts, item.pending_channel_ids = 0, None
    item.next_run_at = compute_next_run(item, now) if item.enabled else None


@router.get("")
def list_messages(_: dict = Depends(require_operator), db: Session = Depends(get_db)) -> list[dict]:
    return [serialize(i) for i in db.scalars(select(ScheduledMessage).order_by(ScheduledMessage.name)).all()]


@router.post("")
def create_message(payload: ScheduledMessageIn, request: Request, user: dict = Depends(require_operator), db: Session = Depends(get_db)) -> dict:
    item = ScheduledMessage()
    apply(item, payload, db)
    db.add(item); db.flush()
    audit(db, request, "schedule.create", user=user, target=f"schedule:{item.id}", detail=item.name)
    db.commit(); db.refresh(item)
    return serialize(item)


@router.put("/{item_id}")
def update_message(item_id: int, payload: ScheduledMessageIn, request: Request, user: dict = Depends(require_operator), db: Session = Depends(get_db)) -> dict:
    item = db.get(ScheduledMessage, item_id)
    if not item:
        raise HTTPException(404, "Scheduled message not found")
    apply(item, payload, db)
    audit(db, request, "schedule.update", user=user, target=f"schedule:{item.id}", detail=item.name)
    db.commit(); db.refresh(item)
    return serialize(item)


@router.delete("/{item_id}")
def delete_message(item_id: int, request: Request, user: dict = Depends(require_operator), db: Session = Depends(get_db)) -> dict[str, bool]:
    item = db.get(ScheduledMessage, item_id)
    if item:
        audit(db, request, "schedule.delete", user=user, target=f"schedule:{item.id}", detail=item.name)
        db.delete(item); db.commit()
    return {"deleted": True}


@router.post("/{item_id}/send")
def send_now(item_id: int, request: Request, user: dict = Depends(require_operator), db: Session = Depends(get_db)) -> dict:
    """Sends the message immediately to its channels without affecting the schedule."""
    item = db.get(ScheduledMessage, item_id)
    if not item:
        raise HTTPException(404, "Scheduled message not found")
    failed, errors = send_scheduled(db, item)
    audit(db, request, "schedule.send_now", user=user, target=f"schedule:{item.id}", detail=item.name, success=not (failed or errors), commit=True)
    if failed or errors:
        raise HTTPException(502, "; ".join(errors) or "Delivery failed")
    return {"ok": True, "detail": f"Sent to {len(channel_list(item.channel_ids))} channel(s)"}
