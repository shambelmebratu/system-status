"""Read-side aggregations over check history and metric samples."""
import threading
import time
from datetime import date, datetime, timedelta, timezone

from sqlalchemy import Integer, case, func, select
from sqlalchemy.orm import Session

from .models import CheckResult, MetricSample, TrafficSample

METRIC_KEYS = ("cpu", "memory", "disk", "load", "swap", "net_rx_bps", "net_tx_bps")


def aware(value: datetime) -> datetime:
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def available(status_column):
    """A target counts as available unless it is fully down (resource 'alert' is still reachable)."""
    return case((status_column != "down", 1), else_=0)


def percentile(values: list[float], fraction: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    return round(ordered[min(len(ordered) - 1, int(len(ordered) * fraction))], 1)


def bucketize(rows: list[tuple[datetime, dict]], since: datetime, until: datetime, buckets: int = 120, with_max: bool = False) -> list[dict]:
    """Averages (timestamp, {key: value}) rows into at most `buckets` evenly spaced points. With with_max, every key also gets
    `<key>_max`: the highest value in the bucket (an average alone flattens the spikes that matter)."""
    width = max(1.0, (until - since).total_seconds() / buckets)
    grouped: dict[int, dict[str, list[float]]] = {}
    for ts, values in rows:
        index = int((aware(ts) - since).total_seconds() // width)
        slot = grouped.setdefault(index, {})
        for key, value in values.items():
            if value is not None:
                slot.setdefault(key, []).append(value)
    points = []
    for index in sorted(grouped):
        point = {"t": (since + timedelta(seconds=index * width + width / 2)).isoformat()}
        for key, values in grouped[index].items():
            point[key] = round(sum(values) / len(values), 2)
            if with_max:
                point[f"{key}_max"] = round(max(values), 2)
        points.append(point)
    return points


# ------------------------------------------------------------------------------------------------ fast aggregation helpers
# Graphs are aggregated INSIDE the database (one row per chart point instead of one per sample), percentiles too on PostgreSQL.
# Uptime per finished day never changes, so each past day is counted once and kept in memory; only "today" (and the partial
# first day of a rolling window) is counted live. Results are exact; they are just not recomputed from millions of rows each time.
CHART_POINTS = 120
_lock = threading.Lock()
_day_cache: dict[date, dict[tuple[str, int], tuple[int, int]]] = {}     # finished UTC day -> {(kind, id): (checks, available)}
_ttl_cache: dict[tuple, tuple[float, object]] = {}


def clear_cache() -> None:
    """Forget cached uptime (after history is deleted or purged)."""
    with _lock:
        _day_cache.clear()
        _ttl_cache.clear()


def ttl_cached(key: tuple, seconds: float, compute):
    now = time.monotonic()
    with _lock:
        hit = _ttl_cache.get(key)
        if hit and now - hit[0] < seconds:
            return hit[1]
    value = compute()
    with _lock:
        if len(_ttl_cache) > 500:
            _ttl_cache.clear()
        _ttl_cache[key] = (now, value)
    return value


def is_pg(db: Session) -> bool:
    return db.get_bind().dialect.name == "postgresql"


def _naive_utc(value: datetime) -> str:
    return aware(value).astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")


def bucket_of(db: Session, column, since: datetime, width: float):
    """The chart-point index of a timestamp column (0 = the first `width` seconds after `since`)."""
    if is_pg(db):
        return func.floor((func.extract("epoch", column) - aware(since).timestamp()) / width)
    return func.cast((func.julianday(column) - func.julianday(_naive_utc(since))) * 86400.0 / width, Integer)


def day_of(db: Session, column):
    return func.date(func.timezone("UTC", column)) if is_pg(db) else func.date(column)


def _as_date(value) -> date:
    return value if isinstance(value, date) and not isinstance(value, datetime) else date.fromisoformat(str(value)[:10])


def midnight(day: date) -> datetime:
    return datetime.combine(day, datetime.min.time(), tzinfo=timezone.utc)


def live_totals(db: Session, start: datetime, end: datetime, kind: str | None = None, ids: list[int] | None = None) -> dict[tuple[str, int], tuple[int, int]]:
    query = select(CheckResult.target_type, CheckResult.target_id, func.count(), func.sum(available(CheckResult.status))).where(CheckResult.checked_at >= start, CheckResult.checked_at < end)
    if kind:
        query = query.where(CheckResult.target_type == kind)
    if ids is not None:
        query = query.where(CheckResult.target_id.in_(ids or [0]))
    return {(k, i): (int(total), int(ok or 0)) for k, i, total, ok in db.execute(query.group_by(CheckResult.target_type, CheckResult.target_id)).all()}


def ensure_days(db: Session, first: date, last: date) -> None:
    """Counts every finished day in [first, last] that is not cached yet, in ONE grouped query."""
    today = datetime.now(timezone.utc).date()
    last = min(last, today - timedelta(days=1))
    with _lock:
        missing = [first + timedelta(days=n) for n in range((last - first).days + 1) if first + timedelta(days=n) not in _day_cache]
    if not missing:
        return
    lo, hi = min(missing), max(missing)
    day = day_of(db, CheckResult.checked_at)
    rows = db.execute(select(day, CheckResult.target_type, CheckResult.target_id, func.count(), func.sum(available(CheckResult.status)))
                      .where(CheckResult.checked_at >= midnight(lo), CheckResult.checked_at < midnight(hi + timedelta(days=1)))
                      .group_by(day, CheckResult.target_type, CheckResult.target_id)).all()
    filled: dict[date, dict] = {d: {} for d in missing}
    for when, kind, target_id, total, ok in rows:
        d = _as_date(when)
        if d in filled:
            filled[d][(kind, target_id)] = (int(total), int(ok or 0))
    with _lock:
        _day_cache.update(filled)
        if len(_day_cache) > 800:
            for old in sorted(_day_cache)[: len(_day_cache) - 800]:
                del _day_cache[old]


def day_totals(day: date) -> dict[tuple[str, int], tuple[int, int]]:
    with _lock:
        return _day_cache.get(day, {})


def uptime_by_target(db: Session, hours: int) -> dict[tuple[str, int], float]:
    """Availability % per target over the last `hours`. Short windows are counted live (cached 15 s); long ones from cached days."""
    def compute():
        now = datetime.now(timezone.utc)
        since = now - timedelta(hours=hours)
        if hours <= 48:
            totals = live_totals(db, since, now)
        else:
            first_full, today = since.date() + timedelta(days=1), now.date()
            totals = live_totals(db, since, midnight(first_full))
            ensure_days(db, first_full, today - timedelta(days=1))
            for n in range((today - first_full).days):
                for key, (t, o) in day_totals(first_full + timedelta(days=n)).items():
                    prev = totals.get(key, (0, 0)); totals[key] = (prev[0] + t, prev[1] + o)
            for key, (t, o) in live_totals(db, midnight(today), now).items():
                prev = totals.get(key, (0, 0)); totals[key] = (prev[0] + t, prev[1] + o)
        return {key: round(100.0 * ok / total, 3) for key, (total, ok) in totals.items() if total}
    return ttl_cached(("uptime", hours), 15 if hours <= 48 else 60, compute)


def uptime_for(db: Session, kind: str, target_id: int, hours: int) -> float | None:
    """One target's availability (uses the per-target index; never scans other targets)."""
    if hours > 48:
        return uptime_by_target(db, hours).get((kind, target_id))
    now = datetime.now(timezone.utc)
    total, ok = live_totals(db, now - timedelta(hours=hours), now, kind, [target_id]).get((kind, target_id), (0, 0))
    return round(100.0 * ok / total, 3) if total else None


def latency_stats(db: Session, since: datetime, kind: str | None = None, target_id: int | None = None, until: datetime | None = None) -> dict[tuple[str, int], dict]:
    """checks, avg, max, p50, p95, p99 of non-failed probes per target (percentiles in SQL on PostgreSQL)."""
    where = [CheckResult.checked_at >= since, CheckResult.status != "down", CheckResult.latency_ms.is_not(None)]
    if until is not None:
        where.append(CheckResult.checked_at < until)
    if kind:
        where.append(CheckResult.target_type == kind)
    if target_id is not None:
        where.append(CheckResult.target_id == target_id)
    out: dict[tuple[str, int], dict] = {}
    if is_pg(db):
        lat = CheckResult.latency_ms
        rows = db.execute(select(CheckResult.target_type, CheckResult.target_id, func.count(), func.avg(lat), func.max(lat),
                                 *[func.percentile_disc(f).within_group(lat) for f in (0.5, 0.95, 0.99)]).where(*where)
                          .group_by(CheckResult.target_type, CheckResult.target_id)).all()
        for k, i, n, avg, mx, p50, p95, p99 in rows:
            out[(k, i)] = {"checks": int(n), "avg": round(float(avg), 1), "max": round(float(mx), 1), "p50": round(float(p50), 1), "p95": round(float(p95), 1), "p99": round(float(p99), 1)}
        return out
    grouped: dict[tuple[str, int], list[float]] = {}
    for k, i, v in db.execute(select(CheckResult.target_type, CheckResult.target_id, CheckResult.latency_ms).where(*where)).all():
        grouped.setdefault((k, i), []).append(v)
    for key, values in grouped.items():
        out[key] = {"checks": len(values), "avg": round(sum(values) / len(values), 1), "max": round(max(values), 1),
                    "p50": percentile(values, 0.5), "p95": percentile(values, 0.95), "p99": percentile(values, 0.99)}
    return out


def _point_time(since: datetime, index: int, width: float) -> str:
    return (since + timedelta(seconds=index * width + width / 2)).isoformat()


def server_history(db: Session, server_id: int, hours: int) -> dict:
    until = datetime.now(timezone.utc)
    since = until - timedelta(hours=hours)
    width = max(1.0, (until - since).total_seconds() / CHART_POINTS)
    b = bucket_of(db, MetricSample.ts, since, width).label("b")
    columns = [b, func.count()]
    for key in METRIC_KEYS:
        column = getattr(MetricSample, key)
        columns += [func.avg(column), func.max(column)]
    columns.append(func.max(func.coalesce(MetricSample.cpu_peak, MetricSample.cpu)))
    rows = db.execute(select(*columns).where(MetricSample.server_id == server_id, MetricSample.ts >= since).group_by(b).order_by(b)).all()
    points, samples = [], 0
    for row in rows:
        samples += int(row[1])
        point: dict = {"t": _point_time(since, int(row[0]), width)}
        for n, key in enumerate(METRIC_KEYS):
            avg, peak = row[2 + 2 * n], row[3 + 2 * n]
            if avg is not None:
                point[key], point[f"{key}_max"] = round(float(avg), 2), round(float(peak), 2)
        if "cpu" in point:   # the real CPU peak is the highest reported peak (agent 2.12+), or the highest average where there is none
            point["cpu_max"] = round(max(float(row[-1] or 0), point.get("cpu_max", 0)), 2)
        points.append(point)
    lb = bucket_of(db, CheckResult.checked_at, since, width).label("b")
    target = (CheckResult.target_type == "server", CheckResult.target_id == server_id, CheckResult.checked_at >= since)
    latency_rows = db.execute(select(lb, func.avg(CheckResult.latency_ms), func.max(CheckResult.latency_ms)).where(*target, CheckResult.latency_ms.is_not(None)).group_by(lb).order_by(lb)).all()
    stats = latency_stats(db, since, "server", server_id).get(("server", server_id))
    return {
        "hours": hours, "points": points, "samples": samples, "uptime_pct": uptime_for(db, "server", server_id, hours),
        "latency_points": [{"t": _point_time(since, int(i), width), "latency": round(float(a), 2), "latency_max": round(float(m), 2)} for i, a, m in latency_rows],
        "latency_avg": stats["avg"] if stats else None, "latency_p95": stats["p95"] if stats else None, "latency_max": stats["max"] if stats else None,
    }


def service_history(db: Session, service_id: int, hours: int) -> dict:
    until = datetime.now(timezone.utc)
    since = until - timedelta(hours=hours)
    width = max(1.0, (until - since).total_seconds() / CHART_POINTS)
    b = bucket_of(db, CheckResult.checked_at, since, width).label("b")
    down = case((CheckResult.status == "down", 1.0), else_=0.0)
    target = (CheckResult.target_type == "service", CheckResult.target_id == service_id, CheckResult.checked_at >= since)
    rows = db.execute(select(b, func.count(), func.avg(CheckResult.latency_ms), func.max(CheckResult.latency_ms), func.avg(down), func.max(down)).where(*target).group_by(b).order_by(b)).all()
    points, checks = [], 0
    for i, n, avg, mx, d_avg, d_max in rows:
        checks += int(n)
        point: dict = {"t": _point_time(since, int(i), width), "down": round(float(d_avg), 2), "down_max": round(float(d_max), 2)}
        if avg is not None:
            point["latency"], point["latency_max"] = round(float(avg), 2), round(float(mx), 2)
        points.append(point)
    failures = db.execute(select(CheckResult.checked_at, CheckResult.error, CheckResult.http_status).where(*target, CheckResult.status == "down").order_by(CheckResult.checked_at.desc()).limit(20)).all()
    stats = latency_stats(db, since, "service", service_id).get(("service", service_id))
    return {
        "hours": hours, "points": points, "checks": checks, "uptime_pct": uptime_for(db, "service", service_id, hours),
        "latency_avg": stats["avg"] if stats else None, "latency_p95": stats["p95"] if stats else None, "latency_max": stats["max"] if stats else None,
        "recent_failures": [{"t": aware(t).isoformat(), "error": e, "http_status": h} for t, e, h in reversed(failures)],
    }


def daily_uptime(db: Session, target_type: str, target_ids: list[int], days: int = 90) -> dict[int, list[dict]]:
    """Per-day availability for the last `days` days (UTC). Days without data have pct=None. Finished days come from the cache."""
    if not target_ids:
        return {}
    today = datetime.now(timezone.utc).date()
    first = today - timedelta(days=days - 1)
    ensure_days(db, first, today - timedelta(days=1))
    live = live_totals(db, midnight(today), datetime.now(timezone.utc), target_type, target_ids)
    result: dict[int, list[dict]] = {}
    for target_id in target_ids:
        series = []
        for offset in range(days):
            when = first + timedelta(days=offset)
            total, ok = (live if when == today else day_totals(when)).get((target_type, target_id), (0, 0))
            series.append({"date": when.isoformat(), "pct": round(100.0 * ok / total, 2) if total else None})
        result[target_id] = series
    return result


# range -> (window seconds, bucket seconds). Buckets >= 1 day are computed in SQL; shorter ones in Python.
DAY = 86400
AVAILABILITY_RANGES: dict[str, tuple[int, int]] = {
    "1m": (60, 5), "5m": (300, 10), "15m": (900, 30), "30m": (1800, 60), "1h": (3600, 60),
    "4h": (4 * 3600, 300), "12h": (12 * 3600, 900), "1d": (DAY, 1800),
    "1mo": (30 * DAY, DAY), "3mo": (90 * DAY, DAY), "1y": (364 * DAY, 7 * DAY),
}


def availability(db: Session, kind: str, target_id: int, range_: str) -> dict:
    """Availability split into equal time buckets for the status bar. Empty buckets have pct=None."""
    window, bucket = AVAILABILITY_RANGES[range_]
    count = window // bucket
    now = datetime.now(timezone.utc)
    if bucket >= DAY:
        # Align to UTC days: the last bucket ends today.
        today = now.date()
        days = window // DAY
        first = today - timedelta(days=days - 1)
        ensure_days(db, first, today - timedelta(days=1))
        live = live_totals(db, midnight(today), now, kind, [target_id])
        per_day: dict[date, tuple[int, int]] = {}
        for n in range(days):
            d = first + timedelta(days=n)
            per_day[d] = (live if d == today else day_totals(d)).get((kind, target_id), (0, 0))
        step = bucket // DAY
        buckets = []
        for index in range(count):
            start = first + timedelta(days=index * step)
            total = ok = 0
            for offset in range(step):
                t, o = per_day.get(start + timedelta(days=offset), (0, 0))
                total, ok = total + t, ok + o
            buckets.append({"t": datetime.combine(start, datetime.min.time(), tzinfo=timezone.utc).isoformat(), "pct": round(100.0 * ok / total, 2) if total else None, "checks": total, "down": total - ok})
        total_checks = sum(b["checks"] for b in buckets)
        total_ok = sum(b["checks"] - b["down"] for b in buckets)
    else:
        since = now - timedelta(seconds=window)
        rows = db.execute(
            select(CheckResult.checked_at, CheckResult.status)
            .where(CheckResult.target_type == kind, CheckResult.target_id == target_id, CheckResult.checked_at >= since)
        ).all()
        totals = [[0, 0] for _ in range(count)]
        for checked_at, status in rows:
            index = min(count - 1, int((aware(checked_at) - since).total_seconds() // bucket))
            if index >= 0:
                totals[index][0] += 1
                totals[index][1] += 1 if status != "down" else 0
        buckets = [{"t": (since + timedelta(seconds=i * bucket)).isoformat(), "pct": round(100.0 * ok / total, 2) if total else None, "checks": total, "down": total - ok} for i, (total, ok) in enumerate(totals)]
        total_checks = sum(t for t, _ in totals)
        total_ok = sum(o for _, o in totals)
    return {"range": range_, "bucket_seconds": bucket, "buckets": buckets, "checks": total_checks, "uptime_pct": round(100.0 * total_ok / total_checks, 3) if total_checks else None}
