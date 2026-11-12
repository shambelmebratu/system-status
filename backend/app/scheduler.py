"""Scheduled messages: compute the next run in the schedule's own time zone, send to the chosen channels, retry failures."""
import json
import logging
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from sqlalchemy import select

from .models import Channel, ScheduledMessage

logger = logging.getLogger(__name__)
MAX_ATTEMPTS = 3          # per run: first try + 2 retries, one minute apart
RETRY_DELAY = timedelta(minutes=1)
MISSED_AFTER = timedelta(minutes=15)  # a reminder delivered much later than planned is just noise: skip it


def get_zone(name: str) -> ZoneInfo:
    try:
        return ZoneInfo(name)
    except (ZoneInfoNotFoundError, ValueError) as error:
        raise ValueError(f"Unknown time zone '{name}' (use an IANA name such as Africa/Addis_Ababa)") from error


def parse_days(value: str) -> list[int]:
    return sorted({int(d) for d in value.split(",") if d.strip().isdigit() and 1 <= int(d) <= 7})


def compute_next_run(item: ScheduledMessage, after: datetime) -> datetime | None:
    """First run strictly after `after` (UTC-aware), or None when a one-time schedule has passed."""
    if item.repeat == "once":
        if item.run_at is None:
            return None
        run_at = item.run_at if item.run_at.tzinfo else item.run_at.replace(tzinfo=timezone.utc)
        return run_at if run_at > after else None
    zone = get_zone(item.timezone)
    hour, minute = (int(part) for part in item.time_of_day.split(":"))
    days = parse_days(item.days_of_week) if item.repeat == "weekly" or item.days_of_week else []
    local_after = after.astimezone(zone)
    for offset in range(0, 9):
        day = (local_after + timedelta(days=offset)).date()
        if days and day.isoweekday() not in days:
            continue
        candidate = datetime(day.year, day.month, day.day, hour, minute, tzinfo=zone)
        if candidate.astimezone(timezone.utc) > after:
            return candidate.astimezone(timezone.utc)
    return None


def render_text(item: ScheduledMessage, when: datetime) -> str:
    """Fills {date}, {time}, {weekday} using the schedule's time zone."""
    local = when.astimezone(get_zone(item.timezone))
    return item.text.replace("{date}", local.strftime("%Y-%m-%d")).replace("{time}", local.strftime("%H:%M")).replace("{weekday}", local.strftime("%A"))


def channel_list(raw: str | None) -> list[int]:
    try:
        return [int(x) for x in json.loads(raw or "[]")]
    except (ValueError, TypeError):
        return []


def send_scheduled(session, item: ScheduledMessage, only_ids: list[int] | None = None, now: datetime | None = None) -> tuple[list[int], list[str]]:
    """Delivers to the given channels. Returns (channel ids that failed, human-readable errors)."""
    from .monitoring import deliver_channel, redact  # late import: monitoring imports nothing from here

    now = now or datetime.now(timezone.utc)
    ids = only_ids if only_ids is not None else channel_list(item.channel_ids)
    text = render_text(item, now)
    failed, errors = [], []
    channels = {c.id: c for c in session.scalars(select(Channel).where(Channel.id.in_(ids))).all()} if ids else {}
    for channel_id in ids:
        channel = channels.get(channel_id)
        if channel is None:
            errors.append(f"channel {channel_id} no longer exists")
            continue  # deleted channel: nothing to retry
        if not channel.enabled:
            errors.append(f"{channel.name}: channel is disabled")
            continue
        try:
            delivered, detail = deliver_channel(channel, text)
        except Exception as error:
            delivered, detail = False, str(error)
        if not delivered:
            failed.append(channel_id)
            errors.append(f"{channel.name}: {redact(str(detail), channel)[:250]}")
    return failed, errors


def schedule_next(item: ScheduledMessage, after: datetime) -> None:
    item.next_run_at = compute_next_run(item, after)
    item.attempts, item.pending_channel_ids = 0, None
    if item.next_run_at is None and item.repeat == "once":
        item.enabled = False  # one-time message done


def run_due_schedules(session) -> None:
    now = datetime.now(timezone.utc)
    due = session.scalars(select(ScheduledMessage).where(ScheduledMessage.enabled.is_(True), ScheduledMessage.next_run_at <= now)).all()
    for item in due:
        try:
            planned = item.next_run_at if item.next_run_at.tzinfo else item.next_run_at.replace(tzinfo=timezone.utc)
            if item.attempts == 0 and now - planned > MISSED_AFTER:
                item.last_status, item.last_error, item.last_run_at = "missed", f"Skipped: worker was not running at {planned.isoformat()}", now
                schedule_next(item, now)
                continue
            only = channel_list(item.pending_channel_ids) if item.attempts else None
            failed, errors = send_scheduled(session, item, only, now=planned if item.attempts == 0 else now)
            item.attempts += 1
            item.last_run_at = now
            total = len(channel_list(item.channel_ids))
            if not failed:
                item.last_status = "sent" if not errors else "partial"
                item.last_error = "; ".join(errors)[:1000] or None
                logger.info("scheduled message sent id=%s name=%s", item.id, item.name)
                schedule_next(item, now)
            elif item.attempts >= MAX_ATTEMPTS:
                item.last_status = "failed" if len(failed) >= total else "partial"
                item.last_error = "; ".join(errors)[:1000]
                logger.error("scheduled message failed id=%s errors=%s", item.id, item.last_error)
                schedule_next(item, now)
            else:
                item.pending_channel_ids = json.dumps(failed)
                item.last_status, item.last_error = "failed", "; ".join(errors)[:1000] + f" (retrying, attempt {item.attempts}/{MAX_ATTEMPTS})"
                item.next_run_at = now + RETRY_DELAY
            session.commit()
        except Exception:
            session.rollback()
            logger.exception("scheduled message crashed id=%s", item.id)
            item.next_run_at = now + RETRY_DELAY * 5  # never let one bad schedule spin every second
            session.commit()
