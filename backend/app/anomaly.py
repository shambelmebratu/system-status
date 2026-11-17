"""Anomaly detection: statistics, no AI and no API key.

Every 5 minutes, each metric's last 15 minutes is compared with the same metric's 15-minute averages over the previous 7 days.
"Normal" is the median, and the spread is the median absolute deviation (MAD x 1.4826 = a standard deviation that ignores outliers),
so last week's incidents do not make the baseline look noisier than it is. A value is anomalous when it is SCORE spreads away AND the
change is large in absolute terms (a CPU going from 0.2 % to 0.9 % is "6 spreads" but nobody cares). It must hold for two runs in a
row (10 minutes) before an anomaly opens, and ends when the score stays below RESOLVE for two runs."""
from __future__ import annotations

import statistics
import time
from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .models import Anomaly, CheckResult, MetricSample, Server, Service
from .stats import bucket_of

SCORE, RESOLVE = 6.0, 3.0
WINDOW_MIN, BASELINE_DAYS, MIN_POINTS = 15, 7, 96          # at least a day of 15-minute points before judging
# metric: (label, unit, directions watched, minimum absolute change, minimum relative change)
METRICS = {
    "cpu": ("CPU", "%", ("up",), 15.0, 0.0), "memory": ("Memory", "%", ("up",), 15.0, 0.0), "load": ("Load", "", ("up",), 1.0, 0.5),
    "net_rx_bps": ("Network in", "B/s", ("up", "down"), 50_000.0, 2.0), "net_tx_bps": ("Network out", "B/s", ("up", "down"), 50_000.0, 2.0),
    "latency": ("Response time", "ms", ("up",), 80.0, 0.5),
}
_pending: dict[tuple, int] = {}
_calm: dict[tuple, int] = {}
_last = {"at": 0.0}


def robust(values: list[float]) -> tuple[float, float]:
    median = statistics.median(values)
    mad = statistics.median([abs(v - median) for v in values])
    return median, max(mad * 1.4826, 1e-9)


def judge(metric: str, current: float, history: list[float]) -> tuple[str, float, float, float] | None:
    """(direction, score, baseline, spread) when `current` is anomalous for this metric, else None."""
    if len(history) < MIN_POINTS:
        return None
    _, _, directions, min_abs, min_rel = METRICS[metric]
    baseline, spread = robust(history)
    spread = max(spread, min_abs / 4)                    # a perfectly flat history must not make any wobble "infinitely" unusual
    score = (current - baseline) / spread
    delta = current - baseline
    if "up" in directions and score >= SCORE and delta >= min_abs and (not min_rel or current >= baseline * (1 + min_rel)):
        return "up", score, baseline, spread
    if "down" in directions and score <= -SCORE and -delta >= min_abs and (not min_rel or current <= baseline / (1 + min_rel)):
        return "down", score, baseline, spread
    return ("calm", score, baseline, spread) if abs(score) < RESOLVE else ("between", score, baseline, spread)


def _series(db: Session, model, ts_col, where: list, columns: dict, now: datetime) -> dict[str, tuple[float | None, list[float]]]:
    since = now - timedelta(days=BASELINE_DAYS)
    width = WINDOW_MIN * 60
    b = bucket_of(db, ts_col, since, width).label("b")
    rows = db.execute(select(b, *[func.avg(c) for c in columns.values()]).where(*where, ts_col >= since).group_by(b).order_by(b)).all()
    last_index = int((now - since).total_seconds() // width)
    out = {}
    for n, key in enumerate(columns):
        points = {int(r[0]): float(r[n + 1]) for r in rows if r[n + 1] is not None}
        current = points.get(last_index) if last_index in points else points.get(last_index - 1)
        history = [v for i, v in points.items() if i < last_index - 4]     # leave out the last hour: an anomaly must not raise its own baseline
        out[key] = (current, history)
    return out


def detect(db: Session, force: bool = False) -> list[dict]:
    """Runs one detection pass (every 5 minutes unless forced). Returns the anomalies that opened in this pass."""
    if not force and time.monotonic() - _last["at"] < 300:
        return []
    _last["at"] = time.monotonic()
    now = datetime.now(timezone.utc)
    targets = []
    for server in db.scalars(select(Server).where(Server.enabled.is_(True), Server.monitor_mode == "push")).all():
        cols = {k: getattr(MetricSample, k) for k in ("cpu", "memory", "load", "net_rx_bps", "net_tx_bps")}
        targets.append(("server", server, _series(db, MetricSample, MetricSample.ts, [MetricSample.server_id == server.id], cols, now)))
    for service in db.scalars(select(Service).where(Service.enabled.is_(True))).all():
        where = [CheckResult.target_type == "service", CheckResult.target_id == service.id, CheckResult.status != "down"]
        targets.append(("service", service, _series(db, CheckResult, CheckResult.checked_at, where, {"latency": CheckResult.latency_ms}, now)))
    opened = []
    for kind, target, series in targets:
        for metric, (current, history) in series.items():
            key = (kind, target.id, metric)
            open_row = db.scalar(select(Anomaly).where(Anomaly.target_type == kind, Anomaly.target_id == target.id, Anomaly.metric == metric, Anomaly.resolved_at.is_(None)))
            verdict = judge(metric, current, history) if current is not None else None
            if verdict and verdict[0] in ("up", "down"):
                direction, score, baseline, spread = verdict
                _calm.pop(key, None)
                if open_row:
                    open_row.last_seen_at, open_row.value = now, current
                    open_row.peak = max(open_row.peak, current) if direction == "up" else min(open_row.peak, current)
                    open_row.score = max(open_row.score, score) if direction == "up" else min(open_row.score, score)
                    continue
                _pending[key] = _pending.get(key, 0) + 1
                if _pending[key] >= 2:
                    _pending.pop(key, None)
                    row = Anomaly(target_type=kind, target_id=target.id, target_name=target.name, metric=metric, direction=direction, value=current, peak=current,
                                  baseline=baseline, spread=spread, score=score, started_at=now - timedelta(minutes=5), last_seen_at=now)
                    db.add(row)
                    opened.append({"row": row, "target": target, "kind": kind})
            else:
                _pending.pop(key, None)
                if open_row and (verdict is None or verdict[0] == "calm"):
                    _calm[key] = _calm.get(key, 0) + 1
                    if _calm[key] >= 2:
                        open_row.resolved_at = now
                        _calm.pop(key, None)
    db.flush()
    return opened


def describe(row: Anomaly) -> str:
    label, unit, *_ = METRICS[row.metric]
    fmt = lambda v: (f"{v / 1e6:.1f} MB/s" if v >= 1e6 else f"{v / 1e3:.0f} kB/s") if unit == "B/s" else f"{v:.0f} ms" if unit == "ms" else f"{v:.1f}{unit}"   # noqa: E731
    return f"{label} is {fmt(row.value)}, usually {fmt(row.baseline)} (± {fmt(row.spread)}): {abs(row.score):.0f}× its normal variation {'above' if row.direction == 'up' else 'below'}"


def run(db: Session, alerts: bool) -> None:
    """Worker hook: detect, and (when enabled) send one alert per new anomaly."""
    from .monitoring import format_alert, queue_event
    for item in detect(db):
        row, target = item["row"], item["target"]
        if alerts:
            queue_event(db, item["kind"], target, "warning", format_alert("Anomaly", "anomaly", target.name, [describe(row), "Nothing is necessarily broken yet: this is unusual compared with the last 7 days."]), deliver=True, state="anomaly")
            row.alerted = True
    db.commit()
