"""Response-time dashboard data: p50 / p95 / p99.

Two sources, shown side by side:
  * real traffic: summarised by agents from the load balancer / web server access log (the time a request spent from the moment
    it reached the load balancer until the last byte left it), kept as histograms so percentiles can be merged across windows;
  * synthetic checks: the probes SM-Watch itself runs against services (and pings of servers).
"""
import json
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .config import get_settings
from .database import get_db
from .models import CheckResult, Server, Service, TrafficSample
from .audit import audit
from .security import require_operator, require_user, can_see, ensure_access
from .stats import aware, bucket_of, is_pg, latency_stats, ttl_cached

router = APIRouter(prefix="/api/performance", tags=["performance"])
RANGES = {"1h": 1, "6h": 6, "24h": 24, "7d": 168, "30d": 720}
FRACTIONS = {"p50": 0.50, "p95": 0.95, "p99": 0.99}


def traffic_bounds() -> list[float]:
    """Histogram boundaries (ms) agents use. From .env (TRAFFIC_BUCKETS_MS); invalid values fall back to a safe set."""
    try:
        values = sorted({float(x) for x in get_settings().traffic_buckets_ms.split(",") if x.strip()})
        if 1 <= len(values) <= 40 and all(v > 0 for v in values):
            return values
    except ValueError:
        pass
    return [5, 10, 25, 50, 75, 100, 150, 200, 300, 500, 750, 1000, 1500, 2000, 3000, 5000, 10000]


# ------------------------------------------------------------------------------------------------------------ histograms
def merge(histograms: list[tuple[list[float], list[int]]]) -> tuple[list[float], list[int]]:
    """Adds histograms that may use different boundaries: counts are attributed to each bucket's upper bound (the open-ended last
    bucket to 2x the largest bound). Exact when the boundaries agree, which is the normal case."""
    pooled: dict[float, int] = {}
    for bounds, counts in histograms:
        top = (bounds[-1] * 2) if bounds else 1.0
        for index, count in enumerate(counts):
            if count:
                edge = bounds[index] if index < len(bounds) else top
                pooled[edge] = pooled.get(edge, 0) + count
    edges = sorted(pooled)
    return edges, [pooled[e] for e in edges]


def histogram_percentile(bounds: list[float], counts: list[int], fraction: float, max_ms: float | None = None) -> float | None:
    """The value below which `fraction` of requests fell, interpolated inside the bucket that contains it. `bounds` are bucket upper
    edges and counts[i] belongs to (bounds[i-1], bounds[i]]; a trailing extra count is the open-ended top bucket."""
    total = sum(counts)
    if not total:
        return None
    target = max(1.0, fraction * total)
    seen = 0
    for index, count in enumerate(counts):
        if seen + count >= target and count:
            lower = bounds[index - 1] if index > 0 else 0.0
            if index < len(bounds):
                upper = bounds[index]
            else:   # open-ended top bucket: the slowest request we saw, or twice the last bound
                upper = max(max_ms or 0.0, lower * 2 if lower else 1.0)
            value = lower + (upper - lower) * ((target - seen) / count)
            return round(min(value, max_ms) if max_ms else value, 1)
        seen += count
    return None


def sample_hist(sample: TrafficSample) -> tuple[list[float], list[int]]:
    return json.loads(sample.bounds), json.loads(sample.counts)


def summarise(samples: list[TrafficSample]) -> dict:
    requests = sum(s.requests for s in samples)
    seconds = sum(s.window_seconds for s in samples)
    bounds, counts = merge([sample_hist(s) for s in samples]) if samples else ([], [])
    peak = max((s.max_ms for s in samples), default=0.0)
    upstream_count = sum(s.upstream_count for s in samples)
    return {
        "requests": requests, "rps": round(requests / seconds, 2) if seconds else None,
        "p50": histogram_percentile(bounds, counts, 0.50, peak), "p95": histogram_percentile(bounds, counts, 0.95, peak), "p99": histogram_percentile(bounds, counts, 0.99, peak),
        "avg": round(sum(s.sum_ms for s in samples) / requests, 1) if requests else None, "max": round(peak, 1) if requests else None,
        "upstream_avg": round(sum(s.upstream_sum_ms for s in samples) / upstream_count, 1) if upstream_count else None,
        "errors_5xx": sum(s.errors_5xx for s in samples), "errors_4xx": sum(s.errors_4xx for s in samples),
        "error_rate_5xx": round(100.0 * sum(s.errors_5xx for s in samples) / requests, 3) if requests else None,
    }


def series(samples: list[TrafficSample], since: datetime, until: datetime, buckets: int = 60) -> list[dict]:
    width = max(60.0, (until - since).total_seconds() / buckets)
    grouped: dict[int, list[TrafficSample]] = {}
    for s in samples:
        grouped.setdefault(int((aware(s.ts) - since).total_seconds() // width), []).append(s)
    points = []
    for index in sorted(grouped):
        part = summarise(grouped[index])
        seconds = sum(s.window_seconds for s in grouped[index]) or width
        points.append({"t": (since + timedelta(seconds=index * width + width / 2)).isoformat(), "p50": part["p50"], "p95": part["p95"], "p99": part["p99"],
                       "avg": part["avg"], "rpm": round(part["requests"] * 60 / seconds, 1), "errors": round(part["error_rate_5xx"] or 0, 2)})
    return points


def window(range_: str) -> tuple[datetime, datetime]:
    until = datetime.now(timezone.utc)
    return until - timedelta(hours=RANGES[range_]), until


# ------------------------------------------------------------------------------------------------------------ targets
def target_info(target) -> dict | None:
    if not getattr(target, "perf_threshold_ms", None):
        return None
    return {"percentile": target.perf_percentile or "p95", "threshold_ms": target.perf_threshold_ms, "window_minutes": target.perf_window_minutes or get_settings().perf_default_window_minutes}


def measure_service(db: Session, service: Service) -> dict | None:
    """The percentile a service's target is about, over its window, from SM-Watch's own probes. None = not enough data to judge."""
    info = target_info(service)
    if not info:
        return None
    since = datetime.now(timezone.utc) - timedelta(minutes=info["window_minutes"])
    values = [r.latency_ms for r in _check_rows(db, "service", service.id, since) if r.status != "down"]
    if len(values) < get_settings().perf_min_check_samples:
        return {**info, "value": None, "samples": len(values), "breaching": False}
    value = _percentiles(values)[info["percentile"]]
    return {**info, "value": value, "samples": len(values), "breaching": value is not None and value > info["threshold_ms"]}


def measure_server_traffic(db: Session, server: Server) -> dict | None:
    """Same for the real traffic of a server (load balancer), from its reported histograms."""
    info = target_info(server)
    if not info:
        return None
    since = datetime.now(timezone.utc) - timedelta(minutes=info["window_minutes"])
    samples = db.scalars(select(TrafficSample).where(TrafficSample.server_id == server.id, TrafficSample.ts >= since)).all()
    part = summarise(samples) if samples else {"requests": 0}
    if part["requests"] < get_settings().perf_min_requests:
        return {**info, "value": None, "samples": part["requests"], "breaching": False}
    value = part[info["percentile"]]
    return {**info, "value": value, "samples": part["requests"], "breaching": value is not None and value > info["threshold_ms"]}


def breach_text(m: dict, what: str) -> str:
    fmt = lambda v: f"{v / 1000:.2f} s" if v >= 1000 else f"{round(v)} ms"  # noqa: E731
    return f"Slow {what}: {m['percentile']} is {fmt(m['value'])} over the last {m['window_minutes']} min (target {fmt(m['threshold_ms'])} or faster, {m['samples']:,} samples)"


class TargetBody(BaseModel):
    percentile: str = Field(default="p95", pattern="^(p50|p95|p99)$")
    threshold_ms: int | None = Field(default=None, ge=1, le=600_000)      # None removes the target
    window_minutes: int | None = Field(default=None, ge=1, le=1440)


# ------------------------------------------------------------------------------------------------------------ endpoints
@router.get("/traffic")
def traffic(range: str = Query("24h", pattern="^(1h|6h|24h|7d|30d)$"), user: dict = Depends(require_user), db: Session = Depends(get_db)) -> dict:
    """Real-traffic response times per server whose agent reads a web server / load balancer access log."""
    since, until = window(range)
    rows = [r for r in db.scalars(select(TrafficSample).where(TrafficSample.ts >= since).order_by(TrafficSample.ts)).all() if can_see(user, "server", r.server_id)]
    by_server: dict[int, list[TrafficSample]] = {}
    for sample in rows:
        by_server.setdefault(sample.server_id, []).append(sample)
    names = {s.id: s.name for s in db.scalars(select(Server).where(Server.id.in_(list(by_server) or [0]))).all()}
    objs = {s.id: s for s in db.scalars(select(Server).where(Server.id.in_(list(by_server) or [0]))).all()}
    servers = [{"server_id": sid, "name": names.get(sid, f"server {sid}"), **summarise(samples), "series": series(samples, since, until),
                "last_data_at": aware(samples[-1].ts).isoformat(), "target": measure_server_traffic(db, objs[sid]) if sid in objs else None}
               for sid, samples in by_server.items()]
    servers.sort(key=lambda s: s["requests"], reverse=True)
    everything = summarise(rows) if rows else None
    return {"range": range, "servers": servers, "total": everything, "bounds_ms": traffic_bounds()}


def _percentiles(values: list[float]) -> dict:
    ordered = sorted(values)
    pick = lambda f: round(ordered[min(len(ordered) - 1, int(len(ordered) * f))], 1) if ordered else None  # noqa: E731
    return {"p50": pick(0.50), "p95": pick(0.95), "p99": pick(0.99), "avg": round(sum(ordered) / len(ordered), 1) if ordered else None, "max": round(ordered[-1], 1) if ordered else None}


def _check_rows(db: Session, kind: str, target_id: int, since: datetime):
    return db.execute(select(CheckResult.checked_at, CheckResult.latency_ms, CheckResult.status).where(CheckResult.target_type == kind, CheckResult.target_id == target_id, CheckResult.checked_at >= since, CheckResult.latency_ms.is_not(None)).order_by(CheckResult.checked_at)).all()


@router.get("/checks")
def checks(range: str = Query("24h", pattern="^(1h|6h|24h|7d|30d)$"), user: dict = Depends(require_user), db: Session = Depends(get_db)) -> dict:
    """p50 / p95 / p99 of SM-Watch's own probes: services (HTTP) and servers (ping). One grouped query for every target."""
    since, _until = window(range)
    stats = ttl_cached(("perf-checks", range), 20, lambda: latency_stats(db, since))
    items = []
    services = db.scalars(select(Service).order_by(Service.name)).all()
    targets = [("service", s.id, s.name, s) for s in services] + [("server", s.id, s.name, None) for s in db.scalars(select(Server).where(Server.monitor_mode != "push").order_by(Server.name)).all()]
    for kind, target_id, name, service in targets:
        found = stats.get((kind, target_id))
        if found and can_see(user, kind, target_id):
            items.append({"kind": kind, "id": target_id, "name": name, **found, "target": measure_service(db, service) if service is not None else None})
    items.sort(key=lambda i: i["p95"] or 0, reverse=True)
    return {"range": range, "items": items}


@router.get("/checks/{kind}/{target_id}")
def check_series(kind: str, target_id: int, range: str = Query("24h", pattern="^(1h|6h|24h|7d|30d)$"), buckets: int = Query(60, ge=10, le=240), user: dict = Depends(require_user), db: Session = Depends(get_db)) -> dict:
    if kind not in ("service", "server"):
        raise HTTPException(404, "Unknown target type")
    ensure_access(user, kind, target_id)
    since, until = window(range)
    width = max(30.0, (until - since).total_seconds() / buckets)
    where = (CheckResult.target_type == kind, CheckResult.target_id == target_id, CheckResult.checked_at >= since, CheckResult.status != "down", CheckResult.latency_ms.is_not(None))
    b = bucket_of(db, CheckResult.checked_at, since, width).label("b")
    points = []
    if is_pg(db):
        lat = CheckResult.latency_ms
        for i, p50, p95, p99 in db.execute(select(b, *[func.percentile_disc(f).within_group(lat) for f in (0.5, 0.95, 0.99)]).where(*where).group_by(b).order_by(b)).all():
            points.append({"t": (since + timedelta(seconds=int(i) * width + width / 2)).isoformat(), "p50": round(float(p50), 1), "p95": round(float(p95), 1), "p99": round(float(p99), 1)})
    else:
        grouped: dict[int, list[float]] = {}
        for i, v in db.execute(select(b, CheckResult.latency_ms).where(*where)).all():
            grouped.setdefault(int(i), []).append(v)
        points = [{"t": (since + timedelta(seconds=i * width + width / 2)).isoformat(), **{k: v for k, v in _percentiles(vals).items() if k in ("p50", "p95", "p99")}} for i, vals in sorted(grouped.items())]
    overall = latency_stats(db, since, kind, target_id).get((kind, target_id)) or {"checks": 0, "p50": None, "p95": None, "p99": None, "avg": None, "max": None}
    return {"range": range, **overall, "points": points}


@router.put("/targets/{kind}/{target_id}")
def set_target(kind: str, target_id: int, payload: TargetBody, request: Request, user: dict = Depends(require_operator), db: Session = Depends(get_db)) -> dict:
    """A response-time target: alert when the chosen percentile over the window is slower than the threshold. threshold_ms=null removes it."""
    model = {"service": Service, "server": Server}.get(kind)
    item = db.get(model, target_id) if model and can_see(user, kind, target_id) else None
    if item is None:
        raise HTTPException(404, "Monitor not found")
    if payload.threshold_ms is None:
        item.perf_percentile = item.perf_threshold_ms = item.perf_window_minutes = None
        detail = "response-time target removed"
    else:
        item.perf_percentile, item.perf_threshold_ms, item.perf_window_minutes = payload.percentile, payload.threshold_ms, payload.window_minutes
        detail = f"target: {payload.percentile} <= {payload.threshold_ms} ms over {payload.window_minutes or get_settings().perf_default_window_minutes} min"
    audit(db, request, "perf.target", user=user, target=f"{kind}:{item.id}", detail=f"{item.name}: {detail}")
    db.commit()
    return {"target": target_info(item)}
