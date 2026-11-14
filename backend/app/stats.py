"""Read-side aggregations over check history and metric samples."""
from datetime import date, datetime, timedelta, timezone

from sqlalchemy import case, func, select
from sqlalchemy.orm import Session

from .models import CheckResult, MetricSample, TrafficSample

METRIC_KEYS = ("cpu", "memory", "disk", "load", "swap", "net_rx_bps", "net_tx_bps")


def aware(value: datetime) -> datetime:
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def available(status_column):
    """A target counts as available unless it is fully down (resource 'alert' is still reachable)."""
    return case((status_column != "down", 1), else_=0)


def uptime_by_target(db: Session, hours: int) -> dict[tuple[str, int], float]:
    since = datetime.now(timezone.utc) - timedelta(hours=hours)
    rows = db.execute(
        select(CheckResult.target_type, CheckResult.target_id, func.count(), func.sum(available(CheckResult.status)))
        .where(CheckResult.checked_at >= since)
        .group_by(CheckResult.target_type, CheckResult.target_id)
    ).all()
    return {(kind, target_id): round(100.0 * (ok or 0) / total, 3) for kind, target_id, total, ok in rows if total}


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


def server_history(db: Session, server_id: int, hours: int) -> dict:
    until = datetime.now(timezone.utc)
    since = until - timedelta(hours=hours)
    samples = db.execute(select(MetricSample).where(MetricSample.server_id == server_id, MetricSample.ts >= since).order_by(MetricSample.ts)).scalars().all()
    points = bucketize([(m.ts, {**{key: getattr(m, key) for key in METRIC_KEYS}, "cpu_hi": m.cpu_peak if m.cpu_peak is not None else m.cpu}) for m in samples], since, until, with_max=True)
    for point in points:   # the real CPU peak is the highest reported peak (agent 2.12+), or the highest average where there is none
        point["cpu_max"] = max(point.pop("cpu_hi_max", point.get("cpu", 0)), point.get("cpu_max", 0))
        point.pop("cpu_hi", None)
    uptime = uptime_by_target(db, hours).get(("server", server_id))
    results = db.execute(select(CheckResult).where(CheckResult.target_type == "server", CheckResult.target_id == server_id, CheckResult.checked_at >= since, CheckResult.latency_ms.is_not(None)).order_by(CheckResult.checked_at)).scalars().all()
    latencies = [r.latency_ms for r in results]
    return {
        "hours": hours, "points": points, "samples": len(samples), "uptime_pct": uptime,
        "latency_points": bucketize([(r.checked_at, {"latency": r.latency_ms}) for r in results], since, until, with_max=True),
        "latency_avg": round(sum(latencies) / len(latencies), 1) if latencies else None,
        "latency_p95": percentile(latencies, 0.95),
        "latency_max": round(max(latencies), 1) if latencies else None,
    }


def service_history(db: Session, service_id: int, hours: int) -> dict:
    until = datetime.now(timezone.utc)
    since = until - timedelta(hours=hours)
    results = db.execute(select(CheckResult).where(CheckResult.target_type == "service", CheckResult.target_id == service_id, CheckResult.checked_at >= since).order_by(CheckResult.checked_at)).scalars().all()
    rows = [(r.checked_at, {"latency": r.latency_ms, "down": 1.0 if r.status == "down" else 0.0}) for r in results]
    latencies = [r.latency_ms for r in results if r.latency_ms is not None and r.status != "down"]
    failures = [{"t": aware(r.checked_at).isoformat(), "error": r.error, "http_status": r.http_status} for r in results if r.status == "down"][-20:]
    return {
        "hours": hours,
        "points": bucketize(rows, since, until, with_max=True),
        "checks": len(results),
        "uptime_pct": uptime_by_target(db, hours).get(("service", service_id)),
        "latency_avg": round(sum(latencies) / len(latencies), 1) if latencies else None,
        "latency_p95": percentile(latencies, 0.95),
        "latency_max": round(max(latencies), 1) if latencies else None,
        "recent_failures": failures,
    }


def daily_uptime(db: Session, target_type: str, target_ids: list[int], days: int = 90) -> dict[int, list[dict]]:
    """Per-day availability for the last `days` days (UTC). Days without data have pct=None."""
    if not target_ids:
        return {}
    today = datetime.now(timezone.utc).date()
    first = today - timedelta(days=days - 1)
    day = func.date(CheckResult.checked_at)
    rows = db.execute(
        select(CheckResult.target_id, day, func.count(), func.sum(available(CheckResult.status)))
        .where(CheckResult.target_type == target_type, CheckResult.target_id.in_(target_ids), CheckResult.checked_at >= datetime.combine(first, datetime.min.time(), tzinfo=timezone.utc))
        .group_by(CheckResult.target_id, day)
    ).all()
    lookup: dict[tuple[int, date], tuple[int, int]] = {}
    for target_id, when, total, ok in rows:
        when = when if isinstance(when, date) and not isinstance(when, datetime) else date.fromisoformat(str(when)[:10])
        lookup[(target_id, when)] = (total, ok or 0)
    result: dict[int, list[dict]] = {}
    for target_id in target_ids:
        series = []
        for offset in range(days):
            when = first + timedelta(days=offset)
            total, ok = lookup.get((target_id, when), (0, 0))
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
        day = func.date(CheckResult.checked_at)
        rows = db.execute(
            select(day, func.count(), func.sum(available(CheckResult.status)))
            .where(CheckResult.target_type == kind, CheckResult.target_id == target_id, CheckResult.checked_at >= datetime.combine(first, datetime.min.time(), tzinfo=timezone.utc))
            .group_by(day)
        ).all()
        per_day: dict[date, tuple[int, int]] = {}
        for when, total, ok in rows:
            when = when if isinstance(when, date) and not isinstance(when, datetime) else date.fromisoformat(str(when)[:10])
            per_day[when] = (total, ok or 0)
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
