"""MongoDB for the Database section: collections, inferred fields and relations, and data-profile reports.

MongoDB has no schema and no foreign keys, so both are inferred from a sample of documents:
- fields: every path seen in up to SCHEMA_SAMPLE documents (nested objects as a.b, arrays as a[]), with their types and how often
  they are present;
- relations: an ObjectId (or id-like) field whose sampled values exist as _id in another collection (e.g. orders.customer_id ->
  customers._id). They are marked as inferred.

Read-only: only find / count / aggregate (never $out or $merge) and listCollections are issued, every one with a time limit.
Use a user that has only the built-in "read" role as well.
"""
from __future__ import annotations

import json
import re
from datetime import datetime

from .dbinspect import (CONNECT_TIMEOUT_S, PROFILE_SAMPLE_ROWS, SENSITIVE, STATEMENT_TIMEOUT_MS, Column, DbError, Inspector, Relation, Table, _clean,
                        _display, resolve_checked)

SCHEMA_SAMPLE = 300          # documents read per collection to infer its fields
MAX_FIELDS = 120             # fields shown per collection
MAX_DEPTH = 4                # how deep nested objects are flattened
RELATION_PROBE = 25          # sampled values checked against a candidate collection
MISSING = "\u0000smw-missing\u0000"   # a value no real document holds


def _type_name(value) -> str:
    from bson import DBRef, Decimal128, ObjectId
    if isinstance(value, DBRef):
        return "dbref"
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "bool"
    if isinstance(value, int):
        return "int"
    if isinstance(value, float):
        return "double"
    if isinstance(value, Decimal128):
        return "decimal"
    if isinstance(value, str):
        return "string"
    if isinstance(value, ObjectId):
        return "objectId"
    if isinstance(value, datetime):
        return "date"
    if isinstance(value, (bytes, bytearray)):
        return "binary"
    if isinstance(value, dict):
        return "object"
    if isinstance(value, list):
        return "array"
    return type(value).__name__


ID_NAME = re.compile(r"(_id|Id|_ids|Ids)$")


def _walk(doc: dict, prefix: str, depth: int, seen: dict[str, dict], counted: set[str], ids: dict[str, list] | None = None) -> None:
    """Records every field path with its types; collects id-like values (ObjectIds, *_id fields) per path in `ids`."""
    from bson import ObjectId
    for key, value in doc.items():
        if not isinstance(key, str) or key.startswith("$"):
            continue
        path = f"{prefix}{key}"
        entry = seen.setdefault(path, {"types": {}, "docs": 0, "ref": None})
        if path not in counted:
            entry["docs"] += 1
            counted.add(path)
        kind = _type_name(value)
        entry["types"][kind] = entry["types"].get(kind, 0) + 1
        if ids is not None and path != "_id" and len(ids.get(path, ())) < 40 and (isinstance(value, ObjectId) or (isinstance(value, (str, int)) and not isinstance(value, bool) and ID_NAME.search(key))):
            ids.setdefault(path, []).append(value)
        if kind == "dbref":
            entry["ref"] = str(value.collection)
        elif kind == "object":
            if "$ref" in value and "$id" in value:
                entry["ref"] = str(value.get("$ref"))
            elif depth < MAX_DEPTH:
                _walk(value, f"{path}.", depth + 1, seen, counted, ids)
        elif kind == "array" and value:
            items = {_type_name(v) for v in value[:20]}
            entry["types"]["array"] -= 1
            if not entry["types"]["array"]:
                del entry["types"]["array"]
            for item in items:
                entry["types"][f"{item}[]"] = entry["types"].get(f"{item}[]", 0) + 1
            if ids is not None and isinstance(value[0], ObjectId) and len(ids.get(f"{path}[]", ())) < 40:
                ids.setdefault(f"{path}[]", []).extend(v for v in value[:3] if isinstance(v, ObjectId))
            for item in [v for v in value[:3] if isinstance(v, dict)][:1] if depth < MAX_DEPTH else []:
                _walk(item, f"{path}[].", depth + 1, seen, counted, ids)


def _candidates(field: str, names: list[str]) -> list[str]:
    """Collections a field such as customer_id / customerId / customer probably points to."""
    base = re.sub(r"(_id|Id|_ids|Ids|_ref|Ref)$", "", field.split(".")[-1].replace("[]", ""))
    base = base.lower()
    if not base or base == "_id":
        return []
    wanted = {base, base + "s", base + "es", base[:-1] + "ies" if base.endswith("y") else base + "s"}
    return [n for n in names if n.lower() in wanted or n.lower().replace("_", "") in wanted]


class MongoInspector(Inspector):
    engine = "mongodb"

    def __init__(self, host: str, port: int, database: str, user: str, password: str, ssl_mode: str = "prefer", schemas: list[str] | None = None,
                 connect_host: str | None = None, auth_source: str | None = None):
        from pymongo import MongoClient
        from pymongo.errors import PyMongoError
        if not database:
            raise DbError("Enter the database name")
        tls = ssl_mode in ("require", "verify-full")
        address = host if tls else (connect_host or resolve_checked(host))   # TLS needs the name for its certificate; it was checked too
        if tls:
            resolve_checked(host)
        try:
            self.client = MongoClient(host=address, port=port, username=user or None, password=password or None, authSource=auth_source or database,
                                      tls=tls, tlsAllowInvalidCertificates=ssl_mode == "require", directConnection=True, appname="sm-watch-report",
                                      serverSelectionTimeoutMS=CONNECT_TIMEOUT_S * 1000, connectTimeoutMS=CONNECT_TIMEOUT_S * 1000,
                                      socketTimeoutMS=STATEMENT_TIMEOUT_MS + 5000, readPreference="secondaryPreferred")
            self.client.admin.command("ping")
            self.db = self.client[database]
            self._version = str(self.client.server_info().get("version", ""))
        except PyMongoError as error:
            raise DbError(_clean(str(error).split(", full error")[0], 300)) from error
        self.database = database
        self.conn = self.client           # Inspector.close() closes it

    # never SQL: the SQL helpers of the base class must not be used
    def rows(self, sql: str, params: tuple = ()):
        raise DbError("Not available for MongoDB")

    def server_version(self) -> str:
        return self._version[:60]

    def _collections(self) -> list[dict]:
        out = []
        for info in self.db.list_collections():
            name = info.get("name", "")
            if name.startswith("system.") or info.get("type") not in (None, "collection", "view", "timeseries"):
                continue
            out.append({"name": name, "kind": "view" if info.get("type") == "view" else "collection"})
        return sorted(out, key=lambda c: c["name"])[:2000]

    def schema(self) -> tuple[list[Table], list[Relation]]:
        from bson import ObjectId
        tables: list[Table] = []
        samples: dict[str, dict[str, list]] = {}
        names = [c["name"] for c in self._collections()]
        for coll in self._collections():
            c = self.db[coll["name"]]
            est = size = None
            if coll["kind"] == "collection":
                try:
                    est = int(c.estimated_document_count(maxTimeMS=STATEMENT_TIMEOUT_MS))
                    stats = self.db.command("collStats", coll["name"], maxTimeMS=STATEMENT_TIMEOUT_MS)
                    size = int(stats.get("storageSize", 0) + stats.get("totalIndexSize", 0))
                except Exception:   # noqa: BLE001  (collStats needs a permission some read-only users lack)
                    pass
            seen: dict[str, dict] = {}
            docs = 0
            values: dict[str, list] = {}       # id-like values per field path, to infer relations
            try:
                cursor = c.aggregate([{"$sample": {"size": SCHEMA_SAMPLE}}], maxTimeMS=STATEMENT_TIMEOUT_MS) if coll["kind"] == "collection" else c.find({}, limit=SCHEMA_SAMPLE, max_time_ms=STATEMENT_TIMEOUT_MS)
                for doc in cursor:
                    docs += 1
                    _walk(doc, "", 0, seen, set(), values)
            except Exception as error:   # noqa: BLE001
                seen = {"_id": {"types": {"objectId": 1}, "docs": 1, "ref": None}}
                tables.append(Table(self.database, coll["name"], coll["kind"], [Column("_id", "objectId", False, pk=True)], est, size, comment=f"Could not read documents: {_clean(error, 120)}"))
                continue
            columns = []
            ordered = sorted(seen.items(), key=lambda kv: (kv[0] != "_id", -kv[1]["docs"], kv[0]))[:MAX_FIELDS]
            for path, info in ordered:
                types = sorted(info["types"], key=lambda t: -info["types"][t])
                if any(t.endswith("[]") for t in types):
                    types = [t for t in types if t != "array"]   # empty arrays: the element type is already known
                type_text = " | ".join(t for t in types if t != "null") or "null"
                presence = info["docs"] / docs if docs else 0
                comment = f"in {round(100 * presence)}% of sampled documents" if presence < 1 else ""
                columns.append(Column(path, type_text[:60], presence < 1 or "null" in types, pk=path == "_id", comment=comment))
            tables.append(Table(self.database, coll["name"], coll["kind"], columns, est, size, comment="" if docs else "Empty collection"))
            samples[coll["name"]] = {"values": values, "refs": {p: i["ref"] for p, i in seen.items() if i["ref"]}}
        relations: list[Relation] = []
        checks = 0
        for t in tables:
            info = samples.get(t.name, {"values": {}, "refs": {}})
            for path, target in info["refs"].items():
                if target in names:
                    relations.append(Relation(f"{t.name}.{path}", t.key, [path], f"{self.database}.{target}", ["_id"], inferred=False))
            for field, vals in info["values"].items():
                probe = list(dict.fromkeys(vals))[:RELATION_PROBE]
                candidates = _candidates(field, [n for n in names if n != t.name])
                if not candidates and probe and isinstance(probe[0], ObjectId):
                    candidates = [n for n in names if n != t.name][:20]       # an ObjectId with an unhelpful name: try the others
                for target in candidates:
                    if checks > 300:
                        break
                    checks += 1
                    try:
                        found = self.db[target].count_documents({"_id": {"$in": probe}}, maxTimeMS=STATEMENT_TIMEOUT_MS)
                    except Exception:   # noqa: BLE001
                        continue
                    if probe and found / len(probe) >= 0.6:
                        relations.append(Relation(f"{t.name}.{field}", t.key, [field], f"{self.database}.{target}", ["_id"], inferred=True))
                        break
        return tables, relations

    # ---------------------------------------------------------------- reports
    def profile(self, table: Table, columns: list[Column], sample_rows: int) -> dict:
        import time
        started = time.monotonic()
        c = self.db[table.name]
        notes: list[str] = []
        try:
            total, exact = int(c.count_documents({}, maxTimeMS=STATEMENT_TIMEOUT_MS)), True
        except Exception:   # noqa: BLE001
            total, exact = table.rows_estimate or 0, False
            notes.append("Counting every document took too long, so the count is MongoDB's own estimate.")
        profiled = min(total, PROFILE_SAMPLE_ROWS)
        stats = []
        for col in columns:
            path = col.name.replace("[]", "")
            sensitive = bool(SENSITIVE.search(col.name))
            entry: dict = {"name": col.name, "type": col.type, "nullable": col.nullable, "pk": col.pk, "sensitive": sensitive, "comment": col.comment}
            v = "$v"                      # the field, after the $project step below
            # $ifNull treats a missing field and null alike (documented), so this counts documents that really have a value
            present = {"$cond": [{"$eq": [{"$ifNull": [v, MISSING]}, MISSING]}, 0, 1]}
            group = {"_id": None, "present": {"$sum": present}}
            numeric = any(t in col.type for t in ("int", "double", "decimal", "long"))
            temporal = "date" in col.type
            if (numeric or temporal) and not sensitive:
                group.update(min={"$min": v}, max={"$max": v})
            if numeric and not sensitive:
                group["avg"] = {"$avg": v}
            pipeline = [{"$limit": PROFILE_SAMPLE_ROWS}, {"$project": {"_id": 0, "v": f"${path}"}} if path != "_id" else {"$project": {"v": "$_id"}},
                        {"$facet": {"stats": [{"$group": group}],
                                    "distinct": [{"$group": {"_id": "$v"}}, {"$count": "n"}],
                                    "top": [{"$match": {"v": {"$ne": None}}}, {"$group": {"_id": "$v", "n": {"$sum": 1}}}, {"$sort": {"n": -1}}, {"$limit": 6}]}}]
            try:
                result = next(c.aggregate(pipeline, maxTimeMS=STATEMENT_TIMEOUT_MS, allowDiskUse=False))
                s = (result.get("stats") or [{}])[0]
                non_null = int(s.get("present", 0))
                distinct = int((result.get("distinct") or [{"n": 0}])[0]["n"]) - (1 if non_null < profiled else 0)
                distinct = max(distinct, 0)
                entry.update(non_null=non_null, nulls=max(0, profiled - non_null), null_pct=round(100 * (1 - non_null / profiled), 1) if profiled else 0.0,
                             distinct=distinct, unique=bool(non_null) and distinct == non_null)
                if "min" in s:
                    entry["min"], entry["max"] = _value(s.get("min")), _value(s.get("max"))
                if "avg" in s and s.get("avg") is not None:
                    entry["avg"] = _display(float(s["avg"]))
                if col.type == "string":   # own query: a server without $strLenCP only loses this one figure
                    try:
                        length = next(c.aggregate([{"$limit": PROFILE_SAMPLE_ROWS}, {"$project": {"_id": 0, "v": f"${path}"}}, {"$match": {"v": {"$type": "string"}}},
                                                   {"$group": {"_id": None, "len": {"$avg": {"$strLenCP": "$v"}}}}], maxTimeMS=STATEMENT_TIMEOUT_MS), {})
                        if length.get("len") is not None:
                            entry["avg_length"] = round(float(length["len"]), 1)
                    except Exception:   # noqa: BLE001
                        pass
                top = result.get("top") or []
                if not sensitive and 0 < distinct <= 30 and non_null:
                    entry["top"] = [{"value": _value(t["_id"], 60), "count": int(t["n"]), "pct": round(100 * int(t["n"]) / non_null, 1)} for t in top[:5]]
            except Exception as error:   # noqa: BLE001
                entry["error"] = _clean(str(error).split(", full error")[0], 200)
            stats.append(entry)
        rows = []
        if sample_rows:
            try:
                for doc in c.find({}, limit=int(sample_rows), max_time_ms=STATEMENT_TIMEOUT_MS):
                    rows.append(["•••" if SENSITIVE.search(col.name) and _get(doc, col.name) is not None else _value(_get(doc, col.name)) for col in columns])
            except Exception:   # noqa: BLE001
                pass
        if total > PROFILE_SAMPLE_ROWS:
            notes.append(f"Field statistics are based on the first {PROFILE_SAMPLE_ROWS:,} documents.")
        if any(c.comment for c in columns):
            notes.append("Fields were discovered from a sample of documents; a field that appears in only a few documents may be missing from the list.")
        return {"rows": total, "rows_exact": exact, "columns": stats, "sample": rows, "notes": notes, "seconds": round(time.monotonic() - started, 2)}


def _get(doc, path: str):
    value = doc
    for part in path.replace("[]", "").split("."):
        if isinstance(value, list):
            value = value[0] if value else None
        if not isinstance(value, dict):
            return None
        value = value.get(part)
    return value


def _value(value, limit: int = 80):
    from bson import DBRef, Decimal128, ObjectId
    if isinstance(value, DBRef):
        return f"{value.collection}/{value.id}"
    if isinstance(value, ObjectId):
        return str(value)
    if isinstance(value, Decimal128):
        return _display(float(value.to_decimal()))
    if isinstance(value, (dict, list)):
        try:
            text = json.dumps(value, default=str, separators=(",", ":"))
        except (TypeError, ValueError):
            text = str(value)
        return text if len(text) <= limit else text[: limit - 1] + "…"
    return _display(value, limit)
