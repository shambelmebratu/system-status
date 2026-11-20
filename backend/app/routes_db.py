"""Database section (admins only): read-only connections, the schema graph, and data reports.

Credentials are stored encrypted and never returned. Every session is read-only with a statement time limit (see dbinspect)."""
import json
import threading
import time
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import select
from sqlalchemy.orm import Session

from . import dbinspect
from .audit import audit
from .database import get_db
from .models import DbConnection, DbReport
from .netguard import BlockedTargetError, validate_host
from .security import require_admin

router = APIRouter(prefix="/api", tags=["databases"])
NAME = r"^[A-Za-z0-9_.$\-]{1,128}$"
_cache: dict[int, tuple[float, dict]] = {}
_busy = threading.BoundedSemaphore(3)          # at most three reports/schema reads at once (they can be heavy)
CACHE_SECONDS = 120


class ConnectionIn(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    engine: str = Field(pattern="^(postgresql|mysql|mongodb)$")
    auth_source: str = Field(default="", max_length=64, pattern=NAME.replace("{1,128}", "{0,64}"))
    host: str = Field(min_length=1, max_length=255)
    port: int | None = Field(default=None, ge=1, le=65535)
    database: str = Field(default="", max_length=128)
    username: str = Field(min_length=1, max_length=128)
    password: str = Field(default="", max_length=500)             # blank on edit = keep the stored one
    ssl_mode: str = Field(default="prefer", pattern="^(disable|prefer|require|verify-full)$")
    schemas: list[str] = Field(default_factory=list, max_length=30)

    @field_validator("database", "username")
    @classmethod
    def no_control(cls, v: str) -> str:
        if any(not ch.isprintable() for ch in v):
            raise ValueError("Only printable characters are allowed")
        return v.strip()

    @field_validator("schemas")
    @classmethod
    def valid_schemas(cls, v: list[str]) -> list[str]:
        import re
        v = [s.strip() for s in v if s.strip()]
        if any(not re.match(NAME, s) for s in v):
            raise ValueError("Schema names may contain letters, digits and _ . $ - only")
        return v


class TestIn(ConnectionIn):
    id: int | None = None          # testing an existing connection with a blank password uses the stored one


class Selection(BaseModel):
    table: str = Field(max_length=300)
    columns: list[str] = Field(default_factory=list, max_length=dbinspect.MAX_COLUMNS_PER_TABLE)


class ReportIn(BaseModel):
    selection: list[Selection] = Field(min_length=1, max_length=dbinspect.MAX_TABLES_PER_REPORT)
    sample_rows: int = Field(default=0, ge=0, le=20)
    title: str = Field(default="", max_length=120)


class SavedReportIn(ReportIn):
    name: str = Field(min_length=1, max_length=120)


def serialize(c: DbConnection) -> dict:
    iso = lambda d: (d if d.tzinfo else d.replace(tzinfo=timezone.utc)).isoformat() if d else None   # noqa: E731
    return {"id": c.id, "name": c.name, "engine": c.engine, "host": c.host, "port": c.port, "database": c.database, "username": c.username,
            "has_password": bool(c.password), "ssl_mode": c.ssl_mode, "auth_source": c.auth_source or "", "schemas": [s for s in (c.schemas or "").split(",") if s],
            "created_by": c.created_by, "created_at": iso(c.created_at), "last_ok_at": iso(c.last_ok_at), "last_error": c.last_error, "server_version": c.server_version}


def get_conn(db: Session, cid: int) -> DbConnection:
    c = db.get(DbConnection, cid)
    if not c:
        raise HTTPException(404, "Database connection not found")
    return c


def apply(c: DbConnection, payload: ConnectionIn) -> None:
    try:
        validate_host(payload.host, resolve=False)
    except BlockedTargetError as error:
        raise HTTPException(422, f"Host: {error}") from error
    c.name, c.engine, c.host = payload.name.strip(), payload.engine, payload.host.strip()
    c.port = payload.port or dbinspect.DEFAULT_PORTS[payload.engine]
    c.database, c.username, c.ssl_mode = payload.database, payload.username, payload.ssl_mode
    c.schemas = ",".join(payload.schemas) or None
    c.auth_source = payload.auth_source.strip() or None if payload.engine == "mongodb" else None
    if payload.password:
        c.password = payload.password
    if payload.engine in ("postgresql", "mongodb") and not c.database:
        raise HTTPException(422, "Enter the database name")


def with_session(c: DbConnection, work):
    if not _busy.acquire(timeout=20):
        raise HTTPException(429, "Other database reports are running. Try again in a moment.")
    try:
        with dbinspect.open_inspector(c) as insp:
            return insp, work(insp)
    except dbinspect.DbError as error:
        raise HTTPException(502, str(error)) from error
    finally:
        _busy.release()


def load_schema(c: DbConnection, db: Session, refresh: bool = False) -> tuple[dict, list, list]:
    hit = _cache.get(c.id)
    if hit and not refresh and time.monotonic() - hit[0] < CACHE_SECONDS and hit[1].get("_sig") == signature(c):
        return hit[1]["json"], hit[1]["tables"], hit[1]["relations"]
    try:
        insp, (version, (tables, relations)) = with_session(c, lambda i: (i.server_version(), i.schema()))
    except HTTPException as error:
        c.last_error = str(error.detail)[:500]
        db.commit()
        raise
    c.last_ok_at, c.last_error, c.server_version = datetime.now(timezone.utc), None, version
    db.commit()
    data = dbinspect.schema_json(tables, relations)
    _cache[c.id] = (time.monotonic(), {"_sig": signature(c), "json": data, "tables": tables, "relations": relations})
    return data, tables, relations


def signature(c: DbConnection) -> str:
    return f"{c.engine}|{c.host}|{c.port}|{c.database}|{c.username}|{c.schemas}|{c.auth_source}"


# ------------------------------------------------------------------------------------------------ connections
@router.get("/databases")
def list_connections(_: dict = Depends(require_admin), db: Session = Depends(get_db)) -> list[dict]:
    return [serialize(c) for c in db.scalars(select(DbConnection).order_by(DbConnection.name)).all()]


@router.post("/databases/test")
def test_connection(payload: TestIn, _: dict = Depends(require_admin), db: Session = Depends(get_db)) -> dict:
    c = DbConnection()
    if payload.id is not None:
        existing = get_conn(db, payload.id)
        c.password = existing.password
    apply(c, payload)
    started = time.monotonic()
    _, (version, (tables, relations)) = with_session(c, lambda i: (i.server_version(), i.schema()))
    return {"ok": True, "version": version, "tables": len(tables), "relations": len(relations), "ms": round((time.monotonic() - started) * 1000)}


@router.post("/databases")
def create_connection(payload: ConnectionIn, request: Request, user: dict = Depends(require_admin), db: Session = Depends(get_db)) -> dict:
    c = DbConnection(created_by=user["email"])
    apply(c, payload)
    db.add(c); db.flush()
    audit(db, request, "db.connection_create", user=user, target=f"database:{c.id}", detail=f"{c.name}: {c.engine} {c.host}:{c.port}/{c.database} as {c.username}")
    db.commit(); db.refresh(c)
    return serialize(c)


@router.put("/databases/{cid}")
def update_connection(cid: int, payload: ConnectionIn, request: Request, user: dict = Depends(require_admin), db: Session = Depends(get_db)) -> dict:
    c = get_conn(db, cid)
    apply(c, payload)
    _cache.pop(cid, None)
    audit(db, request, "db.connection_update", user=user, target=f"database:{c.id}", detail=f"{c.name}: {c.engine} {c.host}:{c.port}/{c.database} as {c.username}" + ("; password changed" if payload.password else ""))
    db.commit(); db.refresh(c)
    return serialize(c)


@router.delete("/databases/{cid}")
def delete_connection(cid: int, request: Request, user: dict = Depends(require_admin), db: Session = Depends(get_db)) -> dict:
    c = db.get(DbConnection, cid)
    if c:
        _cache.pop(cid, None)
        audit(db, request, "db.connection_delete", user=user, target=f"database:{c.id}", detail=c.name)
        for r in db.scalars(select(DbReport).where(DbReport.connection_id == cid)).all():
            db.delete(r)
        db.delete(c); db.commit()
    return {"deleted": True}


# ------------------------------------------------------------------------------------------------ schema + reports
@router.get("/databases/{cid}/schema")
def schema(cid: int, refresh: bool = Query(False), _: dict = Depends(require_admin), db: Session = Depends(get_db)) -> dict:
    c = get_conn(db, cid)
    data, _t, _r = load_schema(c, db, refresh)
    return {**data, "server_version": c.server_version, "read_at": datetime.now(timezone.utc).isoformat()}


def run_report(c: DbConnection, db: Session, payload: ReportIn) -> dict:
    _data, tables, relations = load_schema(c, db)
    selection = [s.model_dump() for s in payload.selection]
    try:
        _, report = with_session(c, lambda i: dbinspect.build_report(i, tables, relations, selection, payload.sample_rows, payload.title))
    except dbinspect.DbError as error:
        raise HTTPException(422, str(error)) from error
    report["database"] = {"name": c.name, "engine": c.engine, "database": c.database, "server_version": c.server_version}
    return report


class Measure(BaseModel):
    fn: str = Field(pattern="^(count|count_distinct|sum|avg|min|max)$")
    column: str | None = Field(default=None, max_length=300)


class GroupBy(BaseModel):
    column: str = Field(max_length=300)
    bucket: str | None = Field(default=None, pattern="^(hour|day|month|year)$")


class Filter(BaseModel):
    column: str = Field(max_length=300)
    op: str = Field(pattern="^(eq|ne|gt|gte|lt|lte|contains|starts|in|is_null|not_null)$")
    value: str = Field(default="", max_length=500)


class QueryIn(BaseModel):
    table: str = Field(max_length=300)
    measures: list[Measure] = Field(default_factory=lambda: [Measure(fn="count")], min_length=1, max_length=6)
    group_by: list[GroupBy] = Field(default_factory=list, max_length=2)
    filters: list[Filter] = Field(default_factory=list, max_length=8)
    order: str = Field(default="measure_desc", pattern="^(measure_desc|measure_asc|group_asc|group_desc)$")
    limit: int = Field(default=50, ge=1, le=500)


@router.get("/databases/{cid}/slow-queries")
def slow_queries(cid: int, request: Request, search: str = Query("", max_length=200), min_ms: float = Query(0, ge=0, le=3_600_000),
                 sort: str = Query("mean", pattern="^(mean|total|max|calls)$"), limit: int = Query(50, ge=1, le=500),
                 user: dict = Depends(require_admin), db: Session = Depends(get_db)) -> dict:
    """The slowest statements (from the database's own statistics) and the queries running now. Read-only."""
    from . import dbslow
    c = get_conn(db, cid)
    _, result = with_session(c, lambda i: dbslow.slow_queries(i, search, min_ms, sort, limit))
    audit(db, request, "db.slow_queries", user=user, target=f"database:{c.id}", detail=f"{c.name}" + (f"; filter {search!r}" if search else ""), commit=True)
    return result


@router.post("/databases/{cid}/query")
def quick_query(cid: int, payload: QueryIn, request: Request, user: dict = Depends(require_admin), db: Session = Depends(get_db)) -> dict:
    """COUNT / SUM / AVG / MIN / MAX ... built from a form (no typed SQL), read-only, with a time limit."""
    from . import dbquery
    c = get_conn(db, cid)
    _data, tables, _relations = load_schema(c, db)
    table = next((t for t in tables if t.key == payload.table), None)
    if table is None:
        raise HTTPException(422, "Unknown table")
    spec = payload.model_dump()
    try:
        dbquery.validate(table, spec)                      # a wrong choice in the form is the user's to fix (422), before connecting
    except dbinspect.DbError as error:
        raise HTTPException(422, str(error)) from error
    _, result = with_session(c, lambda i: dbquery.run(i, table, spec))
    audit(db, request, "db.query", user=user, target=f"database:{c.id}", detail=f"{c.name}: {result['query'][:700]}", commit=True)
    return result


@router.post("/databases/{cid}/report")
def report(cid: int, payload: ReportIn, request: Request, user: dict = Depends(require_admin), db: Session = Depends(get_db)) -> dict:
    c = get_conn(db, cid)
    result = run_report(c, db, payload)
    audit(db, request, "db.report", user=user, target=f"database:{c.id}", detail=f"{c.name}: {', '.join(s.table for s in payload.selection)[:600]}" + (f"; {payload.sample_rows} sample rows" if payload.sample_rows else ""), commit=True)
    return result


@router.get("/databases/{cid}/reports")
def saved_reports(cid: int, _: dict = Depends(require_admin), db: Session = Depends(get_db)) -> list[dict]:
    get_conn(db, cid)
    return [{"id": r.id, "name": r.name, "selection": json.loads(r.selection), "sample_rows": r.sample_rows, "created_by": r.created_by,
             "updated_at": (r.updated_at if r.updated_at.tzinfo else r.updated_at.replace(tzinfo=timezone.utc)).isoformat()}
            for r in db.scalars(select(DbReport).where(DbReport.connection_id == cid).order_by(DbReport.name)).all()]


@router.post("/databases/{cid}/reports")
def save_report(cid: int, payload: SavedReportIn, request: Request, user: dict = Depends(require_admin), db: Session = Depends(get_db)) -> dict:
    get_conn(db, cid)
    r = DbReport(connection_id=cid, name=payload.name.strip(), selection=json.dumps([s.model_dump() for s in payload.selection]), sample_rows=payload.sample_rows, created_by=user["email"])
    db.add(r); db.flush()
    audit(db, request, "db.report_save", user=user, target=f"database:{cid}", detail=r.name)
    db.commit()
    return {"id": r.id}


@router.put("/db-reports/{rid}")
def update_saved(rid: int, payload: SavedReportIn, request: Request, user: dict = Depends(require_admin), db: Session = Depends(get_db)) -> dict:
    r = db.get(DbReport, rid)
    if not r:
        raise HTTPException(404, "Report not found")
    r.name, r.selection, r.sample_rows = payload.name.strip(), json.dumps([s.model_dump() for s in payload.selection]), payload.sample_rows
    audit(db, request, "db.report_save", user=user, target=f"database:{r.connection_id}", detail=r.name)
    db.commit()
    return {"id": r.id}


@router.delete("/db-reports/{rid}")
def delete_saved(rid: int, request: Request, user: dict = Depends(require_admin), db: Session = Depends(get_db)) -> dict:
    r = db.get(DbReport, rid)
    if r:
        audit(db, request, "db.report_delete", user=user, target=f"database:{r.connection_id}", detail=r.name)
        db.delete(r); db.commit()
    return {"deleted": True}
