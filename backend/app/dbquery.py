"""Quick queries: COUNT / COUNT DISTINCT / SUM / AVG / MIN / MAX, optionally grouped (by a column, or a date by hour/day/month/year)
and filtered, built from a form instead of typed SQL.

Same safety rules as the reports (see dbinspect): read-only session with a time limit; table and column names come only from the
database's catalog and are quoted; filter values are always bound parameters (MongoDB: plain values in a $match, never operators
from the request); columns with sensitive names can be counted but never grouped, filtered, summed, or shown as min/max."""
from __future__ import annotations

import json
import re
import time

from .dbinspect import NUMERIC, SENSITIVE, TEMPORAL, Column, DbError, Inspector, Table, _clean, _display, _reset

FUNCTIONS = ("count", "count_distinct", "sum", "avg", "min", "max")
OPS = ("eq", "ne", "gt", "gte", "lt", "lte", "contains", "starts", "in", "is_null", "not_null")
BUCKETS = ("hour", "day", "month", "year")
MAX_ROWS = 500


def _column(table: Table, name: str | None, what: str) -> Column:
    for c in table.columns:
        if c.name == name:
            return c
    raise DbError(f"Unknown {what}: {_clean(name, 80)}")


def _label(fn: str, col: str | None) -> str:
    return {"count": "count", "count_distinct": "distinct"}.get(fn, fn) + (f"({col})" if col else "(*)" if fn == "count" else "")


def validate(table: Table, spec: dict) -> dict:
    """Checks the request against the catalog and the sensitive-column rule. Returns a normalised spec."""
    measures = []
    for m in spec.get("measures") or [{"fn": "count"}]:
        fn, col = m.get("fn"), m.get("column") or None
        if fn not in FUNCTIONS:
            raise DbError(f"Unknown function: {_clean(fn, 30)}")
        c = _column(table, col, "column") if col else None
        if c is None and fn != "count":
            raise DbError(f"Choose a column for {fn.upper().replace('_', ' ')}")
        if c is not None and SENSITIVE.search(c.name) and fn not in ("count", "count_distinct"):
            raise DbError(f"{c.name} looks sensitive: it can only be counted")
        if fn in ("sum", "avg") and c is not None and not NUMERIC.search(c.type) and table.kind != "collection":
            raise DbError(f"{fn.upper()} needs a number column; {c.name} is {c.type}")
        measures.append({"fn": fn, "column": c.name if c else None, "label": _label(fn, c.name if c else None)})
    groups = []
    for g in (spec.get("group_by") or [])[:2]:
        c = _column(table, g.get("column"), "column to group by")
        if SENSITIVE.search(c.name):
            raise DbError(f"{c.name} looks sensitive: it cannot be grouped by")
        bucket = g.get("bucket") or None
        if bucket and bucket not in BUCKETS:
            raise DbError("Unknown date grouping")
        if bucket and table.kind != "collection" and not TEMPORAL.search(c.type):
            raise DbError(f"{c.name} is not a date, so it cannot be grouped by {bucket}")
        groups.append({"column": c.name, "bucket": bucket, "label": c.name + (f" ({bucket})" if bucket else "")})
    filters = []
    for f in (spec.get("filters") or [])[:8]:
        c = _column(table, f.get("column"), "column to filter on")
        if SENSITIVE.search(c.name) and f.get("op") not in ("is_null", "not_null"):
            raise DbError(f"{c.name} looks sensitive: you can only filter on whether it is empty")
        if f.get("op") not in OPS:
            raise DbError("Unknown filter")
        value = str(f.get("value") or "")[:500]
        if table.kind != "collection" and f["op"] in ("eq", "ne", "gt", "gte", "lt", "lte", "in"):
            for part in (value.split(",") if f["op"] == "in" else [value]):
                _coerce(part.strip(), c.type)             # "abc" for a number column: say so before running anything
        filters.append({"column": c.name, "op": f["op"], "value": value, "type": c.type})
    order = spec.get("order") or "measure_desc"
    if order not in ("measure_desc", "measure_asc", "group_asc", "group_desc"):
        raise DbError("Unknown order")
    return {"measures": measures, "group_by": groups, "filters": filters, "order": order, "limit": max(1, min(MAX_ROWS, int(spec.get("limit") or 50)))}


def _coerce(value: str, col_type: str):
    if NUMERIC.search(col_type):
        try:
            return int(value) if re.fullmatch(r"-?\d+", value.strip()) else float(value)
        except ValueError:
            raise DbError(f"'{_clean(value, 40)}' is not a number") from None
    return value


# ------------------------------------------------------------------------------------------------ SQL
def _bucket_sql(insp: Inspector, col: str, bucket: str) -> str:
    if insp.engine == "postgresql":
        fmt = {"hour": "YYYY-MM-DD HH24:00", "day": "YYYY-MM-DD", "month": "YYYY-MM", "year": "YYYY"}[bucket]
        return f"to_char({col}, '{fmt}')"
    fmt = {"hour": "%Y-%m-%d %H:00", "day": "%Y-%m-%d", "month": "%Y-%m", "year": "%Y"}[bucket]
    return f"DATE_FORMAT({col}, '{fmt.replace('%', '%%')}')"      # %% : pymysql formats the statement with the parameters


def build_sql(insp: Inspector, table: Table, spec: dict) -> tuple[str, list, str]:
    """(statement with %s placeholders, parameters, the same statement with values inlined, for display only)."""
    q = insp.q
    select, group_exprs = [], []
    for n, g in enumerate(spec["group_by"]):
        expr = _bucket_sql(insp, q(g["column"]), g["bucket"]) if g["bucket"] else q(g["column"])
        group_exprs.append(expr)
        select.append(f"{expr} AS g{n}")
    for n, m in enumerate(spec["measures"]):
        col = q(m["column"]) if m["column"] else None
        expr = {"count": f"COUNT({col or '*'})", "count_distinct": f"COUNT(DISTINCT {col})", "sum": f"SUM({col})", "avg": f"AVG({col})",
                "min": f"MIN({col})", "max": f"MAX({col})"}[m["fn"]]
        select.append(f"{expr} AS m{n}")
    where, params = [], []
    for f in spec["filters"]:
        col, op, raw = q(f["column"]), f["op"], f["value"]
        if op == "is_null":
            where.append(f"{col} IS NULL")
        elif op == "not_null":
            where.append(f"{col} IS NOT NULL")
        elif op in ("contains", "starts"):
            escaped = raw.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
            where.append(f"{insp.text_expr(col)} LIKE %s")
            params.append(("%" if op == "contains" else "") + escaped + "%")
        elif op == "in":
            values = [_coerce(v.strip(), f["type"]) for v in raw.split(",") if v.strip()][:50]
            if not values:
                raise DbError("Give at least one value for 'is one of'")
            where.append(f"{col} IN ({', '.join(['%s'] * len(values))})")
            params += values
        else:
            where.append(f"{col} {({'eq': '=', 'ne': '<>', 'gt': '>', 'gte': '>=', 'lt': '<', 'lte': '<='})[op]} %s")
            params.append(_coerce(raw, f["type"]))
    sql = f"SELECT {', '.join(select)} FROM {insp.qualified(table)}"
    if where:
        sql += " WHERE " + " AND ".join(where)
    if group_exprs:
        sql += " GROUP BY " + ", ".join(group_exprs)
        direction = "DESC" if spec["order"].endswith("desc") else "ASC"
        sql += f" ORDER BY {'m0' if spec['order'].startswith('measure') else 'g0'} {direction}"
    sql += f" LIMIT {spec['limit']}"
    shown = sql
    for p in params:
        shown = shown.replace("%s", repr(p) if isinstance(p, str) else str(p), 1)
    return sql, params, shown.replace("%%", "%")


def run(insp: Inspector, table: Table, raw_spec: dict) -> dict:
    spec = validate(table, raw_spec)
    started = time.monotonic()
    if insp.engine == "mongodb":
        rows, shown = _run_mongo(insp, table, spec)
    else:
        sql, params, shown = build_sql(insp, table, spec)
        try:
            rows = insp.rows(sql, tuple(params))
        except DbError:
            raise
        except Exception as error:   # noqa: BLE001
            _reset(insp)
            text = str(error).splitlines()[0] if str(error) else error.__class__.__name__
            raise DbError(_clean(("The query took too long (over 15 s). Add a filter or group by fewer values." if "timeout" in text.lower() or "cancel" in text.lower() else text), 300)) from error
    columns = [g["label"] for g in spec["group_by"]] + [m["label"] for m in spec["measures"]]
    out_rows = [[_display(v, 120) for v in r] for r in rows]
    return {"table": table.key, "columns": columns, "groups": len(spec["group_by"]), "rows": out_rows, "query": shown, "language": "mongodb" if insp.engine == "mongodb" else "sql",
            "truncated": len(out_rows) >= spec["limit"] and bool(spec["group_by"]), "seconds": round(time.monotonic() - started, 3)}


# ------------------------------------------------------------------------------------------------ MongoDB
def _run_mongo(insp, table: Table, spec: dict) -> tuple[list[list], str]:
    import re as _re
    from .dbinspect import STATEMENT_TIMEOUT_MS
    from .dbmongo import MISSING, _value

    def path(name: str) -> str:
        return name.replace("[]", "")

    def coerce(value: str, col_type: str):
        v = value.strip()
        if any(t in col_type for t in ("int", "long")) and _re.fullmatch(r"-?\d+", v):
            return int(v)
        if any(t in col_type for t in ("double", "decimal")) or (_re.fullmatch(r"-?\d+(\.\d+)?", v) and "string" not in col_type):
            try:
                return float(v) if "." in v else int(v)
            except ValueError:
                return v
        if "bool" in col_type and v.lower() in ("true", "false"):
            return v.lower() == "true"
        if "objectId" in col_type and _re.fullmatch(r"[0-9a-f]{24}", v):
            from bson import ObjectId
            return ObjectId(v)
        return v

    match: dict = {}
    for f in spec["filters"]:
        p, op, raw = path(f["column"]), f["op"], f["value"]
        cond: object
        if op == "is_null":
            cond = None
        elif op == "not_null":
            cond = {"$ne": None}
        elif op == "contains":
            cond = {"$regex": _re.escape(raw), "$options": "i"}
        elif op == "starts":
            cond = {"$regex": "^" + _re.escape(raw)}
        elif op == "in":
            cond = {"$in": [coerce(v, f["type"]) for v in raw.split(",") if v.strip()][:50]}
        elif op == "eq":
            cond = coerce(raw, f["type"])
        else:
            cond = {f"${op}": coerce(raw, f["type"])}
        if p in match and isinstance(match[p], dict) and isinstance(cond, dict):
            match[p].update(cond)
        else:
            match[p] = cond
    group_id: dict | None = {}
    for n, g in enumerate(spec["group_by"]):
        p = "$" + path(g["column"])
        group_id[f"g{n}"] = {"$dateToString": {"format": {"hour": "%Y-%m-%d %H:00", "day": "%Y-%m-%d", "month": "%Y-%m", "year": "%Y"}[g["bucket"]], "date": p}} if g["bucket"] else p
    group: dict = {"_id": group_id or None}
    project: dict = {"_id": 0, **{f"g{n}": f"$_id.g{n}" for n in range(len(spec["group_by"]))}}
    for n, m in enumerate(spec["measures"]):
        p = "$" + path(m["column"]) if m["column"] else None
        if m["fn"] == "count":
            group[f"m{n}"] = {"$sum": 1} if not p else {"$sum": {"$cond": [{"$eq": [{"$ifNull": [p, MISSING]}, MISSING]}, 0, 1]}}
            project[f"m{n}"] = 1
        elif m["fn"] == "count_distinct":
            group[f"m{n}"] = {"$addToSet": p}
            project[f"m{n}"] = {"$size": {"$filter": {"input": f"$m{n}", "cond": {"$ne": ["$$this", None]}}}}
        else:
            group[f"m{n}"] = {f"${m['fn']}": p}
            project[f"m{n}"] = 1
    pipeline: list[dict] = ([{"$match": match}] if match else []) + [{"$group": group}, {"$project": project}]
    if spec["group_by"]:
        key = "m0" if spec["order"].startswith("measure") else "g0"
        pipeline.append({"$sort": {key: -1 if spec["order"].endswith("desc") else 1}})
    pipeline.append({"$limit": spec["limit"]})
    try:
        docs = list(insp.db[table.name].aggregate(pipeline, maxTimeMS=STATEMENT_TIMEOUT_MS, allowDiskUse=False))
    except Exception as error:   # noqa: BLE001
        text = str(error).split(", full error")[0]
        raise DbError(_clean("The query took too long (over 15 s). Add a filter." if "time limit" in text.lower() or "exceeded" in text.lower() else text, 300)) from error
    keys = [f"g{n}" for n in range(len(spec["group_by"]))] + [f"m{n}" for n in range(len(spec["measures"]))]
    rows = [[_value(d.get(k), 120) for k in keys] for d in docs]
    shown = f"db.{table.name}.aggregate({json.dumps(pipeline, default=str)})"
    return rows, shown
