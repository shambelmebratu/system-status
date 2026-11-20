"""AI: settings, incident explanations, log analysis, the infrastructure assistant, and anomalies."""
import json
import re
import time
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.concurrency import run_in_threadpool
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import desc, select
from sqlalchemy.orm import Session

from . import ai, llm
from .audit import audit
from .database import SessionLocal, get_db
from .models import Anomaly, Incident
from .security import can_see, ensure_access, require_admin, require_operator, require_user
from .stats import aware

router = APIRouter(prefix="/api", tags=["ai"])
_calls: dict[tuple[int, str], list[float]] = {}


def require_ai() -> None:
    from .config import get_settings
    if not get_settings().ai_enabled:
        raise HTTPException(404, "AI features are turned off on this installation (AI_ENABLED=false)")


def _rate(user: dict, what: str, per_hour: int) -> None:
    now = time.monotonic()
    hits = [t for t in _calls.get((user["uid"], what), []) if now - t < 3600]
    if len(hits) >= per_hour:
        raise HTTPException(429, f"You reached the limit of {per_hour} AI requests of this kind per hour")
    _calls[(user["uid"], what)] = hits + [now]


class TierIn(BaseModel):
    """One tier's provider. Omitted fields keep their saved value."""
    enabled: bool | None = None
    provider: str | None = Field(default=None, max_length=30)
    model: str | None = Field(default=None, max_length=120)         # "" = the provider's default
    base_url: str | None = Field(default=None, max_length=300)      # only for providers with an editable address (Ollama, custom)
    zdr_confirmed: bool | None = None                               # Confidential tier: the admin confirms the account's no-retention terms

    @field_validator("provider")
    @classmethod
    def known_provider(cls, v: str | None) -> str | None:
        if v is not None and v not in llm.PROVIDERS:
            raise ValueError(f"Unknown provider. Choose one of: {', '.join(llm.PROVIDERS)}")
        return v

    @field_validator("model")
    @classmethod
    def model_shape(cls, v: str | None) -> str | None:
        if v is not None and (v := v.strip()) and not re.fullmatch(r"[A-Za-z0-9._:/@+-]{1,120}", v):
            raise ValueError("A model name may contain only letters, digits and . _ : / @ + -")
        return v

    @field_validator("base_url")
    @classmethod
    def url_shape(cls, v: str | None) -> str | None:
        if v is not None and (v := v.strip()) and not re.fullmatch(r"https?://[^\s]+", v):
            raise ValueError("The base URL must start with http:// or https://, for example http://ollama:11434/v1")
        return v


class AiSettingsIn(BaseModel):
    """Every field is optional: what is omitted keeps its saved value."""
    tiers: dict[str, TierIn] = Field(default_factory=dict)
    features: dict[str, str] = Field(default_factory=dict)          # feature -> confidential | dev | off
    acknowledge_shared: bool = False                                # required to move a feature (or security data) to the Development tier
    security_on_dev: bool | None = None
    auto_explain: bool | None = None
    post_explanations: bool | None = None
    allow_logs: bool | None = None
    anomaly_alerts: bool | None = None
    auto_per_hour: int | None = Field(default=None, ge=1, le=60)
    keys: dict[str, str] = Field(default_factory=dict, max_length=12)       # provider -> new API key (stored encrypted)
    clear_keys: list[str] = Field(default_factory=list, max_length=12)

    @field_validator("tiers")
    @classmethod
    def known_tiers(cls, v: dict) -> dict:
        if set(v) - set(ai.TIERS):
            raise ValueError("Tiers are 'dev' and 'confidential'")
        return v

    @field_validator("features")
    @classmethod
    def known_features(cls, v: dict) -> dict:
        for f, t in v.items():
            if f not in ai.FEATURES or t not in ("confidential", "dev", "off"):
                raise ValueError(f"Features are {', '.join(ai.FEATURES)}; each uses 'confidential', 'dev' or 'off'")
        return v

    @field_validator("keys", "clear_keys")
    @classmethod
    def known_key_providers(cls, v):
        for p in v:
            if p not in llm.PROVIDERS:
                raise ValueError(f"Unknown provider '{p}'")
        return {p: k.strip() for p, k in v.items()} if isinstance(v, dict) else v


@router.get("/ai/settings", dependencies=[Depends(require_ai)])
def get_settings_ai(_: dict = Depends(require_user), db: Session = Depends(get_db)) -> dict:
    return ai.public_settings(db)


@router.put("/ai/settings", dependencies=[Depends(require_ai)])
def put_settings_ai(payload: AiSettingsIn, request: Request, user: dict = Depends(require_admin), db: Session = Depends(get_db)) -> dict:
    """Saves the two tiers, which tier each feature uses, and the shared options. The privacy rules are enforced here, not only in the page:
    the Confidential tier never runs on a provider whose terms allow data reuse, needs a recorded confirmation of the account's
    no-retention terms (except a local Ollama), and features move to the Development tier only with an explicit acknowledgement."""
    from .crypto import encrypt
    cfg = ai.load(db)
    before = json.loads(json.dumps({k: cfg[k] for k in ("tiers", "features", *ai.DEFAULTS)}))
    now = datetime.now(timezone.utc).isoformat()
    changes: list[str] = []
    for tier, t in payload.tiers.items():
        cur = cfg["tiers"][tier]
        new_provider = t.provider if t.provider is not None else cur["provider"]
        spec = llm.PROVIDERS[new_provider]
        if new_provider != cur["provider"]:
            cur["provider"] = new_provider
            cur["model"] = t.model if t.model is not None else ""          # a model name rarely carries over between providers
            cur["base_url"] = ""
            if tier == "confidential":
                cur["zdr_confirmed_by"] = cur["zdr_confirmed_at"] = None   # a confirmation belongs to one provider account
        if t.model is not None:
            cur["model"] = t.model
        if t.base_url is not None:
            cur["base_url"] = t.base_url if spec.base_url_editable else ""
        if tier == "confidential":
            if spec.privacy == "shared" and (t.provider is not None or t.enabled):
                raise HTTPException(422, f"{spec.label} cannot be used in the Confidential tier: {spec.policy} Use it in the Development tier, or choose a local Ollama "
                                         "or a provider that offers zero data retention.")
            if t.zdr_confirmed is True and spec.privacy == "zdr_possible" and not cur.get("zdr_confirmed_at"):
                cur["zdr_confirmed_by"], cur["zdr_confirmed_at"] = user["email"], now
                changes.append(f"confirmed zero data retention / no training for {spec.label}")
            elif t.zdr_confirmed is False and cur.get("zdr_confirmed_at"):
                cur["zdr_confirmed_by"] = cur["zdr_confirmed_at"] = None
                changes.append(f"withdrew the zero-retention confirmation for {spec.label}")
            if t.enabled and spec.privacy == "zdr_possible" and not cur.get("zdr_confirmed_at"):
                raise HTTPException(422, f"Before the Confidential tier can use {spec.label}, confirm that your account has zero data retention / no training on your data "
                                         f"(a paid or enterprise plan, or a signed agreement). SM-Watch cannot check this from the key. {spec.policy}")
        if t.enabled is not None:
            cur["enabled"] = t.enabled
    newly_shared = [f for f, t in payload.features.items() if t == "dev" and cfg["features"][f] != "dev"]
    if payload.security_on_dev and not cfg["security_on_dev"]:
        newly_shared.append("security findings for the assistant")
    if newly_shared and not payload.acknowledge_shared:
        raise HTTPException(422, f"Moving {', '.join(ai.FEATURES.get(f, f) for f in newly_shared)} to the Development tier sends production data to a provider that may log, "
                                 "retain or train on it. Confirm that you accept this (acknowledge_shared) to continue.")
    cfg["features"].update(payload.features)
    for k in ai.DEFAULTS:
        if getattr(payload, k) is not None:
            cfg[k] = getattr(payload, k)
    if newly_shared:
        cfg["shared_ack"] = {"by": user["email"], "at": now, "what": newly_shared}
        changes.append(f"accepted shared-data processing for {', '.join(newly_shared)}")
    keys = dict(cfg.get("api_keys") or {})
    for provider in payload.clear_keys:
        if keys.pop(provider, None):
            changes.append(f"{llm.PROVIDERS[provider].label} API key removed")
    for provider, key in payload.keys.items():
        if not key:
            continue
        problem = llm.check_key_shape(provider, key)
        if problem:
            raise HTTPException(422, problem)
        keys[provider] = encrypt(key); changes.append(f"{llm.PROVIDERS[provider].label} API key set")
    cfg["api_keys"] = keys
    after = {k: cfg[k] for k in ("tiers", "features", *ai.DEFAULTS)}
    for tier in ai.TIERS:
        for k in ai.TIER_FIELDS:
            if before["tiers"][tier][k] != after["tiers"][tier][k]:
                changes.append(f"{tier}.{k} {before['tiers'][tier][k]!r} -> {after['tiers'][tier][k]!r}")
    changes += [f"{f} tier {before['features'][f]} -> {after['features'][f]}" for f in ai.FEATURES if before["features"][f] != after["features"][f]]
    changes += [f"{k} {before[k]!r} -> {after[k]!r}" for k in ai.DEFAULTS if before[k] != after[k]]
    ai.save(db, cfg, user["email"])
    audit(db, request, "ai.settings", user=user, detail="; ".join(changes)[:900] or "no changes")
    db.commit()
    return ai.public_settings(db)


@router.get("/ai/models")
async def ai_models(tier: str = Query("confidential", pattern="^(dev|confidential)$"), user: dict = Depends(require_admin)) -> dict:
    """The models a tier's saved provider offers to the saved key."""
    def run():
        with SessionLocal() as db:
            return ai.list_models(db, tier)
    try:
        return await run_in_threadpool(run)
    except ai.AiError as error:
        raise HTTPException(422, str(error)) from error


@router.post("/ai/test")
async def test_ai(request: Request, tier: str = Query("confidential", pattern="^(dev|confidential)$"), user: dict = Depends(require_admin)) -> dict:
    """A tiny request that proves a tier's provider, key and model work (costs a few tokens)."""
    def run():
        with SessionLocal() as db:
            return ai.test_connection(db, tier)
    try:
        return await run_in_threadpool(run)
    except ai.AiError as error:
        raise HTTPException(422, str(error)) from error


@router.post("/incidents/{incident_id}/explain", dependencies=[Depends(require_ai)])
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


@router.post("/ai/logs", dependencies=[Depends(require_ai)])
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


class LogLineIn(BaseModel):
    line: str = Field(min_length=1, max_length=8000)
    before: list[str] = Field(default_factory=list, max_length=20)
    after: list[str] = Field(default_factory=list, max_length=10)
    source: str = Field(default="", max_length=200)


@router.post("/ai/log-line")
async def explain_log_line(payload: LogLineIn, request: Request, user: dict = Depends(require_operator)) -> dict:
    """Explains one log line (with a few surrounding lines as context). Secrets are masked before anything is sent."""
    _rate(user, "log-line", 120)

    def run():
        with SessionLocal() as db:
            result = ai.explain_log_line(db, payload.line, payload.before, payload.after, payload.source)
            audit(db, request, "ai.log_line", user=user, detail=f"{payload.source[:120]}: {ai.mask(payload.line)[:200]}", commit=True)
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


@router.post("/ai/ask", dependencies=[Depends(require_ai)])
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
