"""Read-only database inspection: the schema (tables, columns, keys, relations) and data-profile reports.

Safety rules, all enforced here:
- Every session is read-only (PostgreSQL: default_transaction_read_only; MySQL: SESSION TRANSACTION READ ONLY) and has a statement
  time limit, so a report can never change data and never run for long. Use a database user with read-only grants as well.
- Table and column names in generated SQL come ONLY from the database's own catalog (never from the request as-is) and are quoted.
- The host goes through the same network guard as every other outbound connection (no loopback, metadata or internal services),
  and the connection is made to the address that was checked.
- Values from columns whose names look sensitive (password, token, secret, card ...) are never shown, only counted.
"""
from __future__ import annotations

import ipaddress
import re
import socket
import time
from dataclasses import dataclass, field
from datetime import date, datetime
from decimal import Decimal

from .netguard import BlockedTargetError, validate_host

STATEMENT_TIMEOUT_MS = 15_000
CONNECT_TIMEOUT_S = 10
PROFILE_SAMPLE_ROWS = 100_000          # column statistics of bigger tables are computed on this many rows
MAX_TABLES_PER_REPORT = 60
MAX_COLUMNS_PER_TABLE = 80
SENSITIVE = re.compile(r"pass(word|wd)?|secret|token|api_?key|private|salt|hash|otp|pin\b|cvv|cvc|card_?(no|num)|iban|ssn|social_sec|credit", re.I)
NUMERIC = re.compile(r"int|numeric|decimal|real|double|float|money|serial", re.I)
TEMPORAL = re.compile(r"date|time", re.I)
TEXTUAL = re.compile(r"char|text|uuid|enum|citext|json", re.I)


class DbError(Exception):
    """A problem worth showing to the admin as-is (never contains the password)."""


@dataclass
class Column:
    name: str
    type: str
    nullable: bool
    default: str | None = None
    pk: bool = False
    comment: str = ""


@dataclass
class Table:
    schema: str
    name: str
    kind: str = "table"            # table | view
    columns: list[Column] = field(default_factory=list)
    rows_estimate: int | None = None
    size_bytes: int | None = None
    comment: str = ""

    @property
    def key(self) -> str:
        return f"{self.schema}.{self.name}"


@dataclass
class Relation:
    name: str
    from_table: str                # schema.table
    from_columns: list[str]
    to_table: str
    to_columns: list[str]
    inferred: bool = False         # MongoDB: found by matching ids, not declared by the database


def _clean(value, limit: int = 300) -> str:
    return "".join(ch if ch.isprintable() else " " for ch in str(value or ""))[:limit]


# ------------------------------------------------------------------------------------------------ connections
def resolve_checked(host: str) -> str:
    """The address to connect to, after the network guard approved the name and every address it resolves to."""
    validate_host(host)
    try:
        return str(ipaddress.ip_address(host.strip("[]")))
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except socket.gaierror as error:
        raise DbError(f"Cannot resolve {host}: {error.strerror or error}") from error
    if not infos:
        raise DbError(f"Cannot resolve {host}")
    return infos[0][4][0]


class Inspector:
    """One read-only session. Use as a context manager."""
    quote_char = '"'
    engine = ""

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    def close(self) -> None:
        try:
            self.conn.close()
        except Exception:   # noqa: BLE001
            pass

    def q(self, name: str) -> str:
        return self.quote_char + name.replace(self.quote_char, self.quote_char * 2) + self.quote_char

    def qualified(self, table: Table) -> str:
        return f"{self.q(table.schema)}.{self.q(table.name)}"

    def rows(self, sql: str, params: tuple = ()) -> list[tuple]:
        cur = self.conn.cursor()
        try:
            cur.execute(sql, params)
            return list(cur.fetchall())
        finally:
            cur.close()

    # dialect bits overridden below
    def sample_from(self, table: Table, columns: list[str], limit: int) -> str:
        cols = ", ".join(self.q(c) for c in columns)
        return f"(SELECT {cols} FROM {self.qualified(table)} LIMIT {int(limit)}) AS s"

    def length_expr(self, col: str) -> str:
        return f"LENGTH(CAST({col} AS CHAR))"

    def profile(self, table: "Table", columns: list["Column"], sample_rows: int) -> dict:
        return profile_table(self, table, columns, sample_rows)

    def text_expr(self, col: str) -> str:
        return f"CAST({col} AS CHAR)"


class PostgresInspector(Inspector):
    engine = "postgresql"

    def __init__(self, host: str, port: int, database: str, user: str, password: str, ssl_mode: str = "prefer", schemas: list[str] | None = None, connect_host: str | None = None):
        import psycopg
        self.schemas = schemas or []
        try:
            self.conn = psycopg.connect(
                host=host, hostaddr=connect_host or resolve_checked(host), port=port, dbname=database, user=user, password=password,
                sslmode=ssl_mode, connect_timeout=CONNECT_TIMEOUT_S, application_name="sm-watch-report",
                options=f"-c default_transaction_read_only=on -c statement_timeout={STATEMENT_TIMEOUT_MS} -c idle_in_transaction_session_timeout=60000",
                autocommit=True,
            )
        except psycopg.Error as error:
            raise DbError(_pg_message(error)) from error

    def length_expr(self, col: str) -> str:
        return f"LENGTH({col}::text)"

    def text_expr(self, col: str) -> str:
        return f"{col}::text"

    def server_version(self) -> str:
        return _clean(self.rows("SHOW server_version")[0][0], 60)

    def schema(self) -> tuple[list[Table], list[Relation]]:
        skip = ("pg_catalog", "information_schema", "pg_toast")
        where = "n.nspname = ANY(%s)" if self.schemas else "n.nspname <> ALL(%s) AND n.nspname NOT LIKE 'pg_temp%%' AND n.nspname NOT LIKE 'pg_toast%%'"
        arg = (list(self.schemas) if self.schemas else list(skip),)
        tables: dict[str, Table] = {}
        for schema, name, relkind, est, size, comment in self.rows(
            f"""SELECT n.nspname, c.relname, c.relkind, c.reltuples::bigint,
                       CASE WHEN c.relkind IN ('r','p','m') THEN pg_total_relation_size(c.oid) END, obj_description(c.oid, 'pg_class')
                FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
                WHERE c.relkind IN ('r','p','v','m') AND NOT c.relispartition AND {where}
                ORDER BY n.nspname, c.relname LIMIT 2000""", arg):
            t = Table(schema, name, "view" if relkind in ("v", "m") else "table", rows_estimate=int(est) if est is not None and est >= 0 else None, size_bytes=size, comment=_clean(comment))
            tables[t.key] = t
        for schema, table, column, dtype, nullable, default, comment in self.rows(
            f"""SELECT n.nspname, c.relname, a.attname, format_type(a.atttypid, a.atttypmod), NOT a.attnotnull, pg_get_expr(d.adbin, d.adrelid), col_description(c.oid, a.attnum)
                FROM pg_attribute a JOIN pg_class c ON c.oid = a.attrelid JOIN pg_namespace n ON n.oid = c.relnamespace
                LEFT JOIN pg_attrdef d ON d.adrelid = a.attrelid AND d.adnum = a.attnum
                WHERE a.attnum > 0 AND NOT a.attisdropped AND c.relkind IN ('r','p','v','m') AND {where}
                ORDER BY n.nspname, c.relname, a.attnum""", arg):
            t = tables.get(f"{schema}.{table}")
            if t:
                t.columns.append(Column(column, _clean(dtype, 60), bool(nullable), _clean(default, 120) or None, comment=_clean(comment)))
        relations = []
        for conname, contype, schema, table, cols, fschema, ftable, fcols in self.rows(
            f"""SELECT c.conname, c.contype, n.nspname, t.relname,
                       ARRAY(SELECT a.attname FROM unnest(c.conkey) WITH ORDINALITY k(num, ord) JOIN pg_attribute a ON a.attrelid = c.conrelid AND a.attnum = k.num ORDER BY k.ord)::text[],
                       fn.nspname, ft.relname,
                       ARRAY(SELECT a.attname FROM unnest(c.confkey) WITH ORDINALITY k(num, ord) JOIN pg_attribute a ON a.attrelid = c.confrelid AND a.attnum = k.num ORDER BY k.ord)::text[]
                FROM pg_constraint c JOIN pg_class t ON t.oid = c.conrelid JOIN pg_namespace n ON n.oid = t.relnamespace
                LEFT JOIN pg_class ft ON ft.oid = c.confrelid LEFT JOIN pg_namespace fn ON fn.oid = ft.relnamespace
                WHERE c.contype IN ('p', 'f') AND {where}""", arg):
            t = tables.get(f"{schema}.{table}")
            if contype == "p" and t:
                for col in t.columns:
                    col.pk = col.pk or col.name in (cols or [])
            elif contype == "f":
                relations.append(Relation(conname, f"{schema}.{table}", list(cols or []), f"{fschema}.{ftable}", list(fcols or [])))
        return list(tables.values()), relations


def _pg_message(error) -> str:
    text = str(error).strip().splitlines()[0] if str(error).strip() else error.__class__.__name__
    return re.sub(r"password=\S+", "password=***", text)[:300]


class MySqlInspector(Inspector):
    engine = "mysql"
    quote_char = "`"

    def __init__(self, host: str, port: int, database: str, user: str, password: str, ssl_mode: str = "prefer", schemas: list[str] | None = None, connect_host: str | None = None):
        import pymysql
        import ssl
        self.schemas = schemas or [database]
        ssl_ctx = None
        if ssl_mode in ("prefer", "require", "verify-full"):
            ssl_ctx = ssl.create_default_context()
            if ssl_mode != "verify-full":
                ssl_ctx.check_hostname = False
                ssl_ctx.verify_mode = ssl.CERT_NONE
        address = connect_host or resolve_checked(host)
        kwargs = dict(host=address, port=port, user=user, password=password, database=database or None, connect_timeout=CONNECT_TIMEOUT_S,
                      read_timeout=STATEMENT_TIMEOUT_MS // 1000 + 5, autocommit=True, charset="utf8mb4")
        try:
            try:
                self.conn = pymysql.connect(ssl=ssl_ctx, **kwargs)
            except pymysql.MySQLError:
                if ssl_mode != "prefer":
                    raise
                self.conn = pymysql.connect(**kwargs)          # "prefer": the server does not offer TLS
            cur = self.conn.cursor()
            cur.execute("SET SESSION TRANSACTION READ ONLY")
            try:
                cur.execute(f"SET SESSION MAX_EXECUTION_TIME={STATEMENT_TIMEOUT_MS}")       # MySQL 5.7+
            except pymysql.MySQLError:
                cur.execute(f"SET SESSION max_statement_time={STATEMENT_TIMEOUT_MS / 1000}")  # MariaDB
            cur.close()
        except pymysql.MySQLError as error:
            raise DbError(_clean(error.args[1] if len(error.args) > 1 else error, 300)) from error

    def server_version(self) -> str:
        return _clean(self.rows("SELECT VERSION()")[0][0], 60)

    def schema(self) -> tuple[list[Table], list[Relation]]:
        marks = ",".join(["%s"] * len(self.schemas))
        args = tuple(self.schemas)
        tables: dict[str, Table] = {}
        for schema, name, ttype, est, size, comment in self.rows(
            f"SELECT TABLE_SCHEMA, TABLE_NAME, TABLE_TYPE, TABLE_ROWS, DATA_LENGTH + INDEX_LENGTH, TABLE_COMMENT FROM information_schema.TABLES "
            f"WHERE TABLE_SCHEMA IN ({marks}) ORDER BY TABLE_SCHEMA, TABLE_NAME LIMIT 2000", args):
            t = Table(schema, name, "view" if "VIEW" in (ttype or "") else "table", rows_estimate=int(est) if est is not None else None, size_bytes=int(size) if size is not None else None, comment=_clean(comment))
            tables[t.key] = t
        for schema, table, column, dtype, nullable, default, key, comment in self.rows(
            f"SELECT TABLE_SCHEMA, TABLE_NAME, COLUMN_NAME, COLUMN_TYPE, IS_NULLABLE, COLUMN_DEFAULT, COLUMN_KEY, COLUMN_COMMENT FROM information_schema.COLUMNS "
            f"WHERE TABLE_SCHEMA IN ({marks}) ORDER BY TABLE_SCHEMA, TABLE_NAME, ORDINAL_POSITION", args):
            t = tables.get(f"{schema}.{table}")
            if t:
                t.columns.append(Column(column, _clean(dtype, 60), nullable == "YES", _clean(default, 120) or None, pk=key == "PRI", comment=_clean(comment)))
        grouped: dict[tuple, Relation] = {}
        for name, schema, table, column, rschema, rtable, rcolumn in self.rows(
            f"SELECT CONSTRAINT_NAME, TABLE_SCHEMA, TABLE_NAME, COLUMN_NAME, REFERENCED_TABLE_SCHEMA, REFERENCED_TABLE_NAME, REFERENCED_COLUMN_NAME "
            f"FROM information_schema.KEY_COLUMN_USAGE WHERE TABLE_SCHEMA IN ({marks}) AND REFERENCED_TABLE_NAME IS NOT NULL ORDER BY CONSTRAINT_NAME, ORDINAL_POSITION", args):
            rel = grouped.setdefault((schema, table, name), Relation(name, f"{schema}.{table}", [], f"{rschema}.{rtable}", []))
            rel.from_columns.append(column)
            rel.to_columns.append(rcolumn)
        return list(tables.values()), list(grouped.values())


def _mongo(*args, **kwargs):
    from .dbmongo import MongoInspector
    return MongoInspector(*args, **kwargs)


ENGINES = {"postgresql": PostgresInspector, "mysql": MySqlInspector, "mongodb": _mongo}
DEFAULT_PORTS = {"postgresql": 5432, "mysql": 3306, "mongodb": 27017}


def open_inspector(conn) -> Inspector:
    """`conn` is a DbConnection row (password decrypted by the column type)."""
    cls = ENGINES.get(conn.engine)
    if cls is None:
        raise DbError(f"Unsupported engine: {conn.engine}")
    schemas = [s.strip() for s in (conn.schemas or "").split(",") if s.strip()]
    try:
        extra = {"auth_source": getattr(conn, "auth_source", None)} if conn.engine == "mongodb" else {}
        return cls(conn.host, conn.port, conn.database, conn.username, conn.password or "", conn.ssl_mode or "prefer", schemas, **extra)
    except BlockedTargetError as error:
        raise DbError(str(error)) from error


# ------------------------------------------------------------------------------------------------ schema as JSON
def schema_json(tables: list[Table], relations: list[Relation]) -> dict:
    fk_cols = {(r.from_table, c) for r in relations for c in r.from_columns}
    return {
        "tables": [{"key": t.key, "schema": t.schema, "name": t.name, "kind": t.kind, "rows_estimate": t.rows_estimate, "size_bytes": t.size_bytes, "comment": t.comment,
                    "columns": [{"name": c.name, "type": c.type, "nullable": c.nullable, "default": c.default, "pk": c.pk, "fk": (t.key, c.name) in fk_cols, "comment": c.comment,
                                 "sensitive": bool(SENSITIVE.search(c.name))} for c in t.columns]} for t in tables],
        "relations": [{"name": r.name, "from": r.from_table, "from_columns": r.from_columns, "to": r.to_table, "to_columns": r.to_columns, "inferred": r.inferred} for r in relations],
    }


# ------------------------------------------------------------------------------------------------ reports
def _display(value, limit: int = 80):
    if value is None:
        return None
    if isinstance(value, (datetime, date)):
        return value.isoformat(sep=" ") if isinstance(value, datetime) else value.isoformat()
    if isinstance(value, Decimal):
        value = float(value)
    if isinstance(value, float):
        return round(value, 4)
    if isinstance(value, int):
        return value
    if isinstance(value, (bytes, bytearray, memoryview)):
        return f"<{len(bytes(value))} bytes>"
    text = _clean(value, 2000)
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _plural(n: int | None, word: str) -> str:
    n = n or 0
    return f"{n:,} {word}{'' if n == 1 else 's'}"


def _humanize(name: str) -> str:
    return re.sub(r"_+", " ", name).strip()


def _singular(name: str) -> str:
    """orders -> order, categories -> category, addresses -> address (good enough for sentences; never used in SQL)."""
    word = _humanize(name)
    low = word.lower()
    if low.endswith("ies") and len(word) > 4:
        return word[:-3] + "y"
    if low.endswith(("sses", "xes", "ches", "shes")):
        return word[:-2]
    if low.endswith("s") and not low.endswith(("ss", "us", "is")):
        return word[:-1]
    return word


def profile_table(insp: Inspector, table: Table, columns: list[Column], sample_rows: int) -> dict:
    started = time.monotonic()
    notes: list[str] = []
    try:
        total = int(insp.rows(f"SELECT COUNT(*) FROM {insp.qualified(table)}")[0][0])
        exact = True
    except Exception:   # noqa: BLE001  (timeout on a huge table: use the planner's estimate)
        _reset(insp)
        total, exact = table.rows_estimate or 0, False
        notes.append("Counting every row took too long, so the row count is the database's own estimate.")
    sampled = total > PROFILE_SAMPLE_ROWS
    base = insp.sample_from(table, [c.name for c in columns], PROFILE_SAMPLE_ROWS)
    profiled = min(total, PROFILE_SAMPLE_ROWS) if exact else None
    stats = []
    for col in columns:
        c = insp.q(col.name)
        sensitive = bool(SENSITIVE.search(col.name))
        entry: dict = {"name": col.name, "type": col.type, "nullable": col.nullable, "pk": col.pk, "sensitive": sensitive, "comment": col.comment}
        try:
            numeric, temporal, textual = bool(NUMERIC.search(col.type)), bool(TEMPORAL.search(col.type)), bool(TEXTUAL.search(col.type))
            parts = [f"COUNT({c})", f"COUNT(DISTINCT {c})"]
            if (numeric or temporal) and not sensitive:
                parts += [f"MIN({c})", f"MAX({c})"]
            if numeric and not sensitive and "serial" not in col.type.lower():
                parts.append(f"AVG({c})")
            if textual and "json" not in col.type.lower():
                parts.append(f"AVG({insp.length_expr(c)})")
            row = insp.rows(f"SELECT {', '.join(parts)} FROM {base}")[0]
            non_null, distinct = int(row[0] or 0), int(row[1] or 0)
            n = profiled if profiled is not None else non_null
            entry.update(non_null=non_null, nulls=max(0, (n or 0) - non_null), null_pct=round(100 * (1 - non_null / n), 1) if n else 0.0, distinct=distinct,
                         unique=bool(non_null) and distinct == non_null)
            i = 2
            if (numeric or temporal) and not sensitive:
                entry["min"], entry["max"] = _display(row[i]), _display(row[i + 1]); i += 2
            if numeric and not sensitive and "serial" not in col.type.lower():
                entry["avg"] = _display(row[i]); i += 1
            if textual and "json" not in col.type.lower():
                entry["avg_length"] = round(float(row[i]), 1) if row[i] is not None else None
            if not sensitive and 0 < distinct <= 30 and non_null:
                top = insp.rows(f"SELECT {insp.text_expr(c)} AS v, COUNT(*) AS n FROM {base} WHERE {c} IS NOT NULL GROUP BY {insp.text_expr(c)} ORDER BY n DESC LIMIT 5")
                entry["top"] = [{"value": _display(v, 60), "count": int(k), "pct": round(100 * int(k) / non_null, 1)} for v, k in top]
        except Exception as error:   # noqa: BLE001  (one odd column type must not sink the whole report)
            _reset(insp)
            entry["error"] = _clean(str(error).splitlines()[0] if str(error) else error.__class__.__name__, 200)
        stats.append(entry)
    rows = []
    if sample_rows:
        try:
            cols = ", ".join(insp.q(c.name) for c in columns)
            for r in insp.rows(f"SELECT {cols} FROM {insp.qualified(table)} LIMIT {int(sample_rows)}"):
                rows.append(["•••" if SENSITIVE.search(col.name) and v is not None else _display(v) for col, v in zip(columns, r)])
        except Exception:   # noqa: BLE001
            _reset(insp)
    if sampled:
        notes.append(f"Column statistics are based on the first {PROFILE_SAMPLE_ROWS:,} rows.")
    return {"rows": total, "rows_exact": exact, "columns": stats, "sample": rows, "notes": notes, "seconds": round(time.monotonic() - started, 2)}


def _reset(insp: Inspector) -> None:
    try:
        insp.conn.rollback()
    except Exception:   # noqa: BLE001
        pass


def build_report(insp: Inspector, tables: list[Table], relations: list[Relation], selection: list[dict], sample_rows: int = 0, title: str = "") -> dict:
    """selection: [{"table": "schema.name", "columns": ["a", "b"] or []}] (empty = every column). Names are matched against the catalog."""
    by_key = {t.key: t for t in tables}
    chosen: list[tuple[Table, list[Column]]] = []
    for item in selection[:MAX_TABLES_PER_REPORT]:
        t = by_key.get(str(item.get("table", "")))
        if t is None:
            raise DbError(f"Unknown table: {_clean(item.get('table'), 120)}")
        wanted = [str(c) for c in item.get("columns") or []]
        known = {c.name: c for c in t.columns}
        unknown = [c for c in wanted if c not in known]
        if unknown:
            raise DbError(f"Unknown column in {t.key}: {_clean(unknown[0], 80)}")
        cols = [known[c] for c in wanted] if wanted else list(t.columns)
        chosen.append((t, cols[:MAX_COLUMNS_PER_TABLE]))
    if not chosen:
        raise DbError("Choose at least one table")
    keys = {t.key for t, _ in chosen}
    sections = []
    for t, cols in chosen:
        profile = insp.profile(t, cols, max(0, min(20, sample_rows)))
        outgoing = [r for r in relations if r.from_table == t.key]
        incoming = [r for r in relations if r.to_table == t.key]
        quality = quality_notes(t, cols, profile, outgoing)
        sections.append({"table": t.key, "schema": t.schema, "name": t.name, "kind": t.kind, "comment": t.comment, "size_bytes": t.size_bytes,
                         "summary": table_sentence(t, profile, outgoing, incoming), "profile": profile, "quality": quality,
                         "references": [relation_sentence(r, by_key, "out") for r in outgoing], "referenced_by": [relation_sentence(r, by_key, "in") for r in incoming],
                         "primary_key": [c.name for c in t.columns if c.pk]})
    inside = [r for r in relations if r.from_table in keys and r.to_table in keys]
    total_rows = sum(s["profile"]["rows"] for s in sections)
    biggest = max(sections, key=lambda s: s["profile"]["rows"])
    mongo = insp.engine == "mongodb"
    table_word, row_word = ("collection", "document") if mongo else ("table", "row")
    overview = (f"This report covers {_plural(len(sections), table_word)} with {_plural(total_rows, row_word)} in total. "
                f"The largest is {biggest['name']} ({_plural(biggest['profile']['rows'], row_word)}). "
                + (f"{_plural(len(inside), 'relationship')} connect the selected {table_word}s." if inside else f"None of the selected {table_word}s reference each other."))
    issues = sum(len(s["quality"]) for s in sections)
    return {"title": title or f"Data report: {', '.join(s['name'] for s in sections[:4])}{' …' if len(sections) > 4 else ''}", "engine": insp.engine,
            "generated_at": datetime.utcnow().replace(microsecond=0).isoformat() + "Z", "overview": overview, "issues": issues,
            "relations": [relation_sentence(r, by_key, "out") for r in inside], "tables": sections}


def table_sentence(t: Table, profile: dict, outgoing: list[Relation], incoming: list[Relation]) -> str:
    kind = "view" if t.kind == "view" else t.kind if t.kind == "collection" else "table"
    row, col = ("document", "field") if t.kind == "collection" else ("row", "column")
    parts = [f"{t.name} is a {kind} with {_plural(profile['rows'], row)}{'' if profile['rows_exact'] else ' (estimated)'} and {_plural(len(t.columns), col)}."]
    pk = [c.name for c in t.columns if c.pk]
    if pk:
        parts.append(f"Each {row} is identified by {' + '.join(pk)}.")
    if outgoing:
        parts.append(f"It points to {', '.join(sorted({r.to_table.split('.')[-1] for r in outgoing}))}.")
    if incoming:
        parts.append(f"It is referenced by {', '.join(sorted({r.from_table.split('.')[-1] for r in incoming}))}.")
    return " ".join(parts)


def relation_sentence(r: Relation, by_key: dict, direction: str) -> dict:
    src, dst = r.from_table.split(".")[-1], r.to_table.split(".")[-1]
    src_cols, dst_cols = ", ".join(r.from_columns), ", ".join(r.to_columns)
    child = by_key.get(r.from_table)
    optional = child is not None and any(c.nullable for c in child.columns if c.name in r.from_columns)
    one, parent = _singular(src), _singular(dst)
    text = (f"Each {one} {'may belong' if optional else 'belongs'} to one {parent} ({src}.{src_cols} → {dst}.{dst_cols}). "
            f"{'An' if parent[:1].lower() in 'aeiou' else 'A'} {parent} can have many {_humanize(src)}.")
    if r.inferred:
        text += " (Found by matching ids: MongoDB does not declare relations.)"
    return {"name": r.name, "from": r.from_table, "from_columns": r.from_columns, "to": r.to_table, "to_columns": r.to_columns, "optional": optional, "text": text, "inferred": r.inferred}


def quality_notes(t: Table, cols: list[Column], profile: dict, outgoing: list[Relation]) -> list[str]:
    notes = []
    if t.kind == "table" and not any(c.pk for c in t.columns):
        notes.append("This table has no primary key, so rows cannot be told apart reliably.")
    if profile["rows"] == 0:
        notes.append("The collection is empty." if row == "document" else "The table is empty.")
        return notes
    fk_cols = {c for r in outgoing for c in r.from_columns}
    row = "document" if t.kind == "collection" else "row"
    complex_type = re.compile(r"object|array|\[\]|json|dbref", re.I)
    for s in profile["columns"]:
        if "error" in s:
            continue
        if s.get("non_null", 0) == 0 and profile["rows"]:
            notes.append(f"{s['name']} is always empty.")
        elif s.get("null_pct", 0) >= 50:
            notes.append(f"{s['name']} is empty in {s['null_pct']}% of {row}s.")
        if s["name"] in fk_cols and s.get("nulls"):
            notes.append(f"{s['name']} links to another {'collection' if row == 'document' else 'table'} but is missing in {_plural(s['nulls'], row)}.")
        if s.get("distinct") == 1 and s.get("non_null", 0) > 1:
            notes.append(f"{s['name']} has the same value in every {row}{' that has it' if s.get('nulls') else ''}.")
        if (s.get("unique") and not s.get("pk") and not s.get("sensitive") and not s.get("nullable") and s.get("non_null", 0) > 10 and s["name"] not in fk_cols
                and not TEMPORAL.search(s.get("type", "")) and not NUMERIC.search(s.get("type", "")) and not complex_type.search(s.get("type", ""))) and s.get("null_pct", 0) == 0:
            notes.append(f"{s['name']} is unique in every {row}: it could serve as a key.")
    return notes[:12]
