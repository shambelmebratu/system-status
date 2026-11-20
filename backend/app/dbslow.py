"""Slowest queries, from the statistics each database keeps itself (read-only; nothing is enabled or changed by SM-Watch):

* PostgreSQL: pg_stat_statements (needs the extension), plus the queries running right now (pg_stat_activity).
* MySQL / MariaDB: performance_schema statement digests, plus the process list.
* MongoDB: the profiler (system.profile, when profiling is on), plus current operations.

Statement statistics hold normalised text ($1 / ? placeholders), so no values. For queries running right now the text is
literal, so string and number literals are masked before anything is shown."""
from __future__ import annotations

import json
import re

from .dbinspect import DbError, Inspector, _clean, _reset

SORTS = ("mean", "total", "max", "calls")
_STRING = re.compile(r"'(?:[^']|'')*'")
_NUMBER = re.compile(r"(?<![\w$.])-?\d+(?:\.\d+)?(?![\w.])")


def mask_literals(sql: str) -> str:
    return _NUMBER.sub("?", _STRING.sub("'?'", sql or ""))


def _tidy(sql: str, limit: int = 4000) -> str:
    return _clean(" ".join((sql or "").split()), limit)


def _filter(rows: list[dict], search: str, min_ms: float, sort: str, limit: int) -> list[dict]:
    needle = search.strip().lower()
    rows = [r for r in rows if (not needle or needle in r["query"].lower() or needle in (r.get("database") or "").lower()) and r["mean_ms"] >= min_ms]
    key = {"mean": "mean_ms", "total": "total_ms", "max": "max_ms", "calls": "calls"}[sort]
    rows.sort(key=lambda r: -(r.get(key) or 0))
    total = sum(r["total_ms"] for r in rows) or 1
    for r in rows:
        r["share_pct"] = round(100 * r["total_ms"] / total, 1)
    return rows[:limit]


def slow_queries(insp: Inspector, search: str = "", min_ms: float = 0, sort: str = "mean", limit: int = 50) -> dict:
    sort = sort if sort in SORTS else "mean"
    if insp.engine == "postgresql":
        return _postgres(insp, search, min_ms, sort, limit)
    if insp.engine == "mysql":
        return _mysql(insp, search, min_ms, sort, limit)
    if insp.engine == "mongodb":
        return _mongo(insp, search, min_ms, sort, limit)
    raise DbError(f"Not available for {insp.engine}")


# ------------------------------------------------------------------------------------------------ PostgreSQL
def _postgres(insp, search, min_ms, sort, limit) -> dict:
    out: dict = {"engine": "postgresql", "source": "pg_stat_statements", "available": False, "note": "", "statements": [], "running": []}
    try:
        has = insp.rows("SELECT 1 FROM pg_extension WHERE extname = 'pg_stat_statements'")
    except Exception:   # noqa: BLE001
        _reset(insp); has = []
    if not has:
        out["note"] = ("pg_stat_statements is not enabled in this database. To see the slowest queries, a DBA adds it to shared_preload_libraries "
                       "in postgresql.conf, restarts PostgreSQL, and runs CREATE EXTENSION pg_stat_statements; (in this database).")
    else:
        version = int(insp.rows("SHOW server_version_num")[0][0])
        t = "exec_time" if version >= 130000 else "time"           # renamed in PostgreSQL 13
        try:
            rows = insp.rows(f"""SELECT s.query, s.calls, s.total_{t}, s.mean_{t}, s.max_{t}, s.rows, d.datname, r.rolname
                                 FROM pg_stat_statements s LEFT JOIN pg_database d ON d.oid = s.dbid LEFT JOIN pg_roles r ON r.oid = s.userid
                                 WHERE s.calls > 0 ORDER BY s.mean_{t} DESC LIMIT 2000""")
            out["available"] = True
            out["statements"] = _filter([{"query": _tidy(q), "calls": int(c), "total_ms": round(float(tot), 2), "mean_ms": round(float(mean), 2), "max_ms": round(float(mx), 2),
                                          "rows": int(n or 0), "database": db or "", "user": role or ""}
                                         for q, c, tot, mean, mx, n, db, role in rows if q and not q.startswith("<insufficient")], search, min_ms, sort, limit)
            hidden = sum(1 for r in rows if (r[0] or "").startswith("<insufficient"))
            if hidden:
                out["note"] = f"{hidden} statements of other users are hidden: grant pg_read_all_stats to the SM-Watch database user to see them."
        except Exception as error:   # noqa: BLE001
            _reset(insp)
            out["note"] = f"pg_stat_statements could not be read: {_clean(str(error).splitlines()[0], 200)}"
    try:
        running = insp.rows("""SELECT pid, datname, usename, state, EXTRACT(EPOCH FROM (now() - query_start)) * 1000, wait_event_type, query
                               FROM pg_stat_activity WHERE state <> 'idle' AND pid <> pg_backend_pid() AND query <> '' AND backend_type = 'client backend'
                               ORDER BY query_start LIMIT 50""")
        out["running"] = [{"id": str(pid), "database": db or "", "user": user or "", "state": state or "", "running_ms": round(float(ms or 0)), "waiting": wait or "",
                           "query": _tidy(mask_literals(q), 2000)} for pid, db, user, state, ms, wait, q in running]
    except Exception:   # noqa: BLE001
        _reset(insp)
    return out


# ------------------------------------------------------------------------------------------------ MySQL / MariaDB
def _mysql(insp, search, min_ms, sort, limit) -> dict:
    out: dict = {"engine": "mysql", "source": "performance_schema", "available": False, "note": "", "statements": [], "running": []}
    try:
        rows = insp.rows("""SELECT DIGEST_TEXT, COUNT_STAR, SUM_TIMER_WAIT / 1e9, AVG_TIMER_WAIT / 1e9, MAX_TIMER_WAIT / 1e9, SUM_ROWS_SENT, SUM_ROWS_EXAMINED, SCHEMA_NAME
                            FROM performance_schema.events_statements_summary_by_digest WHERE DIGEST_TEXT IS NOT NULL AND COUNT_STAR > 0
                            ORDER BY AVG_TIMER_WAIT DESC LIMIT 2000""")
        out["available"] = True
        out["statements"] = _filter([{"query": _tidy(q), "calls": int(c), "total_ms": round(float(tot or 0), 2), "mean_ms": round(float(mean or 0), 2), "max_ms": round(float(mx or 0), 2),
                                      "rows": int(sent or 0), "rows_examined": int(examined or 0), "database": db or ""}
                                     for q, c, tot, mean, mx, sent, examined, db in rows], search, min_ms, sort, limit)
        if not rows:
            out["note"] = "performance_schema has no statement statistics yet (it may be turned off: performance_schema=ON in my.cnf)."
    except Exception as error:   # noqa: BLE001
        _reset(insp)
        out["note"] = ("Statement statistics need performance_schema (performance_schema=ON) and SELECT on performance_schema for the SM-Watch user. "
                       f"({_clean(str(error), 160)})")
    try:
        running = insp.rows("""SELECT ID, DB, USER, STATE, TIME * 1000, INFO FROM information_schema.PROCESSLIST
                               WHERE COMMAND NOT IN ('Sleep', 'Daemon', 'Binlog Dump') AND INFO IS NOT NULL AND ID <> CONNECTION_ID() ORDER BY TIME DESC LIMIT 50""")
        out["running"] = [{"id": str(pid), "database": db or "", "user": user or "", "state": state or "", "running_ms": round(float(ms or 0)), "waiting": "",
                           "query": _tidy(mask_literals(q), 2000)} for pid, db, user, state, ms, q in running]
    except Exception:   # noqa: BLE001
        _reset(insp)
    return out


# ------------------------------------------------------------------------------------------------ MongoDB
def _shape(value, depth: int = 0):
    """A query filter with its values replaced by '?', e.g. {"status": "?", "total": {"$gt": "?"}}."""
    if depth > 6:
        return "?"
    if isinstance(value, dict):
        return {k: _shape(v, depth + 1) for k, v in list(value.items())[:30]}
    if isinstance(value, list):
        return [_shape(v, depth + 1) for v in value[:5]]
    return "?"


def _mongo(insp, search, min_ms, sort, limit) -> dict:
    from .dbinspect import STATEMENT_TIMEOUT_MS
    out: dict = {"engine": "mongodb", "source": "system.profile", "available": False, "note": "", "statements": [], "running": []}
    try:
        status = insp.db.command("profile", -1)
        level = int(status.get("was", 0))
    except Exception:   # noqa: BLE001
        level = -1
    groups: dict[str, dict] = {}
    try:
        for doc in insp.db["system.profile"].find({}, {"op": 1, "ns": 1, "command": 1, "millis": 1, "nreturned": 1, "docsExamined": 1}).sort("ts", -1).limit(5000).max_time_ms(STATEMENT_TIMEOUT_MS):
            cmd = doc.get("command") or {}
            shape = {"op": doc.get("op"), "ns": doc.get("ns"), "filter": _shape(cmd.get("filter") or cmd.get("q") or cmd.get("pipeline") or {})}
            key = json.dumps(shape, sort_keys=True, default=str)
            g = groups.setdefault(key, {"query": f"{doc.get('op')} {doc.get('ns')} {json.dumps(shape['filter'], default=str)}"[:4000], "calls": 0, "total_ms": 0.0, "max_ms": 0.0,
                                        "rows": 0, "rows_examined": 0, "database": (doc.get("ns") or "").split(".")[0]})
            ms = float(doc.get("millis") or 0)
            g["calls"] += 1; g["total_ms"] += ms; g["max_ms"] = max(g["max_ms"], ms)
            g["rows"] += int(doc.get("nreturned") or 0); g["rows_examined"] += int(doc.get("docsExamined") or 0)
        for g in groups.values():
            g["mean_ms"] = round(g["total_ms"] / g["calls"], 2); g["total_ms"] = round(g["total_ms"], 2)
        out["available"] = bool(groups)
        out["statements"] = _filter(list(groups.values()), search, min_ms, sort, limit)
    except Exception:   # noqa: BLE001
        pass
    if not groups:
        out["note"] = ("The MongoDB profiler is off for this database" if level == 0 else "The profiler has recorded nothing yet") + \
                      ". A DBA can record slow operations with db.setProfilingLevel(1, { slowms: 100 }) in this database."
    try:
        ops = insp.client.admin.command("currentOp", {"active": True, "secs_running": {"$gte": 0}}).get("inprog", [])
        out["running"] = [{"id": str(op.get("opid")), "database": (op.get("ns") or "").split(".")[0], "user": ((op.get("effectiveUsers") or [{}])[0] or {}).get("user", ""),
                           "state": op.get("op") or "", "running_ms": int(op.get("microsecs_running", 0)) // 1000, "waiting": "lock" if op.get("waitingForLock") else "",
                           "query": f"{op.get('op')} {op.get('ns')} {json.dumps(_shape((op.get('command') or {}).get('filter') or {}), default=str)}"[:2000]}
                          for op in ops if op.get("ns") and not str(op.get("ns", "")).startswith(("admin.", "local.", "config."))][:50]
    except Exception:   # noqa: BLE001
        pass
    return out
