"""AI: settings, incident explanations, log analysis, the infrastructure assistant, and anomalies."""
import json
import time
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.concurrency import run_in_threadpool
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import desc, select
from sqlalchemy.orm import Session

from . import ai
from .audit import audit
from .database import SessionLocal, get_db
from .models import Anomaly, Incident
from .security import can_see, ensure_access, require_admin, require_operator, require_user
from .stats import aware

router = APIRouter(prefix="/api", tags=["ai"])
_calls: dict[tuple[int, str], list[float]] = {}


def _rate(user: dict, what: str, per_hour: int) -> None:
    now = time.monotonic()
    hits = [t for t in _calls.get((user["uid"], what), []) if now - t < 3600]
    if len(hits) >= per_hour:
        raise HTTPException(429, f"You reached the limit of {per_hour} AI requests of this kind per hour")
    _calls[(user["uid"], what)] = hits + [now]


class AiSettingsIn(BaseModel):
    enabled: bool
    model: str = Field(default=ai.DEFAULT_MODEL, pattern=r"^claude-[a-z0-9.-]{3,60}$")
    auto_explain: bool = False
    post_explanations: bool = False
    allow_logs: bool = True
    anomaly_alerts: bool = True
    auto_per_hour: int = Field(default=6, ge=1, le=60)
    api_key: str = Field(default="", max_length=300)     # blank = keep
    clear_key: bool = False

    @field_validator("api_key")
    @classmethod
    def key_shape(cls, v: str) -> str:
        v = v.strip()
        if v and not v.startswith("sk-ant-"):
            raise ValueError("That does not look like an Anthropic API key (it starts with sk-ant-)")
        return v


@router.get("/ai/settings")
def get_settings_ai(_: dict = Depends(require_user), db: Session = Depends(get_db)) -> dict:
    return ai.public_settings(db)


@router.put("/ai/settings")
def put_settings_ai(payload: AiSettingsIn, request: Request, user: dict = Depends(require_admin), db: Session = Depends(get_db)) -> dict:
    from .crypto import encrypt
    cfg = ai.load(db)
    changes = [f"{k} {cfg.get(k)} -> {getattr(payload, k)}" for k in ai.DEFAULTS if cfg.get(k) != getattr(payload, k)]
    for k in ai.DEFAULTS:
        cfg[k] = getattr(payload, k)
    if payload.clear_key:
        cfg.pop("api_key", None); changes.append("API key removed")
    elif payload.api_key:
        cfg["api_key"] = encrypt(payload.api_key); changes.append("API key set")
    ai.save(db, cfg, user["email"])
    audit(db, request, "ai.settings", user=user, detail="; ".join(changes)[:900] or "no changes")
    db.commit()
    return ai.public_settings(db)


@router.post("/ai/test")
async def test_ai(request: Request, user: dict = Depends(require_admin)) -> dict:
    """A tiny request that proves the key and model work (costs a few tokens)."""
    def run():
        with SessionLocal() as db:
            cfg = ai._ready(db)
            client = ai._client(cfg)
            import anthropic
            try:
                r = client.messages.create(model=cfg["model"], max_tokens=200, messages=[{"role": "user", "content": "Reply with the single word: ready"}])
            except anthropic.APIError as error:
                raise ai._api_error(error) from error
            ai._record_usage(db, r.usage); db.commit()
            return {"ok": True, "model": r.model, "reply": "".join(b.text for b in r.content if b.type == "text")[:50]}
    try:
        return await run_in_threadpool(run)
    except ai.AiError as error:
        raise HTTPException(422, str(error)) from error


@router.post("/incidents/{incident_id}/explain")
async def explain(incident_id: int, request: Request, user: dict = Depends(require_operator)) -> dict:
    with SessionLocal() as db:
        incident = db.get(Incident, incident_id)
        if not incident:
            raise HTTPException(404, "Incident not found")
        if incident.target_type in ("server", "service", "cluster"):
            ensure_access(user, incident.target_type, incident.target_id)
    _rate(user, "explain", 30)

    def run():
        with SessionLocal() as db:
            incident = db.get(Incident, incident_id)
            result = ai.explain_incident(db, incident)
            audit(db, request, "ai.explain", user=user, target=f"incident:{incident_id}", detail=incident.title[:200], commit=True)
            return {"analysis": result, "model": incident.ai_model, "generated_at": aware(incident.ai_generated_at).isoformat()}
    try:
        return await run_in_threadpool(run)
    except ai.AiError as error:
        raise HTTPException(422, str(error)) from error


class LogsIn(BaseModel):
    text: str = Field(min_length=1, max_length=400_000)
    source: str = Field(default="", max_length=200)


@router.post("/ai/logs")
async def analyze_logs(payload: LogsIn, request: Request, user: dict = Depends(require_operator)) -> dict:
    _rate(user, "logs", 30)

    def run():
        with SessionLocal() as db:
            result = ai.analyze_logs(db, payload.text, payload.source)
            audit(db, request, "ai.logs", user=user, detail=f"{payload.source[:120]}: {result['lines_sent']} lines analysed", commit=True)
            return result
    try:
        return await run_in_threadpool(run)
    except ai.AiError as error:
        raise HTTPException(422, str(error)) from error


class ChatMessage(BaseModel):
    role: str = Field(pattern="^(user|assistant)$")
    content: str = Field(min_length=1, max_length=8000)


class AskIn(BaseModel):
    messages: list[ChatMessage] = Field(min_length=1, max_length=30)

    @field_validator("messages")
    @classmethod
    def ends_with_question(cls, v: list[ChatMessage]) -> list[ChatMessage]:
        if v[0].role != "user" or v[-1].role != "user":
            raise ValueError("The conversation must start and end with a question")
        return v


@router.post("/ai/ask")
async def ask(payload: AskIn, request: Request, user: dict = Depends(require_user)) -> dict:
    _rate(user, "ask", 40)

    def run():
        with SessionLocal() as db:
            result = ai.ask(db, user, [m.model_dump() for m in payload.messages])
            audit(db, request, "ai.ask", user=user, detail=payload.messages[-1].content[:300], commit=True)
            return result
    try:
        return await run_in_threadpool(run)
    except ai.AiError as error:
        raise HTTPException(422, str(error)) from error


@router.get("/anomalies")
def anomalies(hours: int = Query(168, ge=1, le=720), user: dict = Depends(require_user), db: Session = Depends(get_db)) -> list[dict]:
    from .anomaly import METRICS, describe
    since = datetime.now(timezone.utc) - timedelta(hours=hours)
    rows = db.scalars(select(Anomaly).where((Anomaly.resolved_at.is_(None)) | (Anomaly.started_at >= since)).order_by(desc(Anomaly.started_at)).limit(300)).all()
    return [{"id": a.id, "target_type": a.target_type, "target_id": a.target_id, "target_name": a.target_name, "metric": a.metric, "label": METRICS[a.metric][0], "unit": METRICS[a.metric][1],
             "direction": a.direction, "value": a.value, "peak": a.peak, "baseline": a.baseline, "spread": a.spread, "score": round(a.score, 1), "description": describe(a),
             "started_at": aware(a.started_at).isoformat(), "last_seen_at": aware(a.last_seen_at).isoformat(), "resolved_at": aware(a.resolved_at).isoformat() if a.resolved_at else None, "alerted": a.alerted}
            for a in rows if can_see(user, a.target_type, a.target_id)]
