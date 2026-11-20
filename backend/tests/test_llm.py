"""Provider-independent AI: the free keyless default, OpenAI-compatible providers (tool use, JSON answers), legacy settings, and error messages.
Every HTTP call goes to an httpx.MockTransport: no network, no cost."""
import json
import os
import sys
from datetime import datetime, timedelta, timezone

os.environ.setdefault("ENVIRONMENT", "test"); os.environ.setdefault("JWT_SECRET", "x" * 40); os.environ.setdefault("DATABASE_URL", "sqlite://")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import httpx
import pytest

from test_api_auth import CSRF, client, fresh_stats_cache, main, sign_in  # noqa: F401
from app import ai, database, llm
from app.models import AppSetting, Incident

LOG_JSON = {"summary": "Database connections are refused.", "health": "Failing",
            "groups": [{"title": "Connection refused", "severity": "ERROR", "occurrences": 40, "example": "ECONNREFUSED", "meaning": "Postgres is down", "fix": "Restart it"}],
            "next_steps": ["Check postgres"]}


class Server:
    """A scripted OpenAI-compatible server: answers each request with the next queued response, and records requests."""
    def __init__(self, *responses):
        self.queue, self.requests = list(responses), []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append({"url": str(request.url), "method": request.method, "auth": request.headers.get("authorization"),
                              "body": json.loads(request.content) if request.content else None})
        status, body = self.queue.pop(0)
        return httpx.Response(status, json=body)


def ok(content=None, tool_calls=None, model="m-1"):
    return 200, {"model": model, "choices": [{"message": {"role": "assistant", "content": content, "tool_calls": tool_calls}, "finish_reason": "tool_calls" if tool_calls else "stop"}],
                 "usage": {"prompt_tokens": 100, "completion_tokens": 20}}


@pytest.fixture()
def server(monkeypatch):
    holder = {}

    def install(*responses):
        holder["s"] = Server(*responses)
        monkeypatch.setattr(llm.OpenAICompatProvider, "transport", httpx.MockTransport(holder["s"]))
        return holder["s"]
    for s in llm.PROVIDERS.values():
        if s.key_env:
            monkeypatch.delenv(s.key_env, raising=False)
    yield install


def _clear(names=("llm-svc",)):
    with database.SessionLocal() as db:
        row = db.get(AppSetting, "ai")
        if row:
            db.delete(row)
        q = db.query(Incident).filter(Incident.resolved_at.is_(None))
        for i in (q.all() if names is None else q.filter(Incident.target_name.in_(names)).all()):
            i.resolved_at = datetime.now(timezone.utc)
        db.commit()


@pytest.fixture()
def reset(client):
    sign_in(client)
    _clear(names=None)   # start from no AI settings and no open incidents, whatever earlier test files left behind
    yield
    _clear()


def put(client, body):
    return client.put("/api/ai/settings", headers=CSRF, json=body)


def dev(client, provider="free", key=None, **tier):
    """A provider on the Development tier, with every feature explicitly moved to it."""
    body = {"tiers": {"dev": {"enabled": True, "provider": provider, **tier}}, "features": {f: "dev" for f in ai.FEATURES}, "acknowledge_shared": True}
    if key:
        body["keys"] = {provider: key}
    return put(client, body)


def conf(client, provider, key=None, confirm=True, **tier):
    """A provider on the Confidential tier (zero-retention terms confirmed unless it runs locally)."""
    t = {"enabled": True, "provider": provider, **tier}
    if llm.PROVIDERS[provider].privacy == "zdr_possible":
        t["zdr_confirmed"] = confirm
    body = {"tiers": {"confidential": t}}
    if key:
        body["keys"] = {provider: key}
    return put(client, body)


def test_defaults_put_every_feature_on_the_confidential_tier(client, reset, server):
    s = client.get("/api/ai/settings").json()
    assert s["tiers"]["dev"]["provider"] == "free" and s["tiers"]["confidential"]["provider"] == "ollama"
    assert not s["tiers"]["dev"]["enabled"] and not s["tiers"]["confidential"]["enabled"] and not s["ready"]
    assert {f: v["tier"] for f, v in s["features"].items()} == {"incidents": "confidential", "logs": "confidential", "assistant": "confidential"}
    providers = {p["id"]: p for p in s["providers"]}
    assert providers["free"]["privacy"] == "shared" and providers["deepseek"]["privacy"] == "shared" and providers["ollama"]["privacy"] == "local"
    assert providers["anthropic"]["privacy"] == "zdr_possible" and providers["gemini"]["policy_url"].startswith("https://") and "training" in providers["gemini"]["policy"]
    # turning on only the Development tier does not make sensitive features use it
    s = put(client, {"tiers": {"dev": {"enabled": True}}}).json()
    assert s["tiers"]["dev"]["ready"] and not s["features"]["logs"]["ready"] and "Confidential tier" in s["features"]["logs"]["problem"]
    r = client.post("/api/ai/logs", headers=CSRF, json={"text": "ERROR x"})
    assert r.status_code == 422 and "Log analysis uses the Confidential tier" in r.json()["detail"] and "explicitly allow the Development tier" in r.json()["detail"]
    srv = server(ok("ready", model="gpt-oss-20b"))
    r = client.post("/api/ai/test?tier=dev", headers=CSRF)                       # each tier is tested on its own
    assert r.status_code == 200 and r.json() == {"ok": True, "tier": "dev", "provider": "free", "model": "gpt-oss-20b", "reply": "ready"}
    assert srv.requests[0]["url"] == "https://text.pollinations.ai/openai" and srv.requests[0]["auth"] is None
    r = put(client, {"keys": {"free": "sk-something-1234567890"}})
    assert r.status_code == 422 and "does not use an API key" in r.json()["detail"]


def test_shared_data_providers_never_serve_the_confidential_tier(client, reset):
    for provider in ("free", "deepseek"):
        r = put(client, {"tiers": {"confidential": {"enabled": True, "provider": provider}}})
        assert r.status_code == 422 and "cannot be used in the Confidential tier" in r.json()["detail"]
    with database.SessionLocal() as db:        # even if one got into the database some other way, nothing is sent
        cfg = ai.load(db)
        cfg["tiers"]["confidential"].update(enabled=True, provider="deepseek")
        assert "cannot serve the Confidential tier" in ai.tier_problem(cfg, "confidential")
        with pytest.raises(ai.AiError, match="cannot serve the Confidential tier"):
            ai._provider(cfg, "confidential")


def test_confidential_tier_needs_a_recorded_zero_retention_confirmation(client, reset, server):
    r = conf(client, "groq", key="gsk_test_1234567890abcdef", confirm=False)
    assert r.status_code == 422 and "confirm that your account has zero data retention" in r.json()["detail"]
    s = conf(client, "groq", key="gsk_test_1234567890abcdef").json()
    t = s["tiers"]["confidential"]
    assert t["ready"] and t["zdr_confirmed_by"] == "admin@example.com" and t["zdr_confirmed_at"] and s["features"]["logs"]["ready"]
    assert any("confirmed zero data retention / no training for Groq" in e["detail"] for e in client.get("/api/audit?category=ai").json())
    s = put(client, {"tiers": {"confidential": {"provider": "openai"}}}).json()   # the confirmation belongs to one provider account
    assert s["tiers"]["confidential"]["zdr_confirmed_at"] is None and not s["tiers"]["confidential"]["ready"] and "has not confirmed" in s["tiers"]["confidential"]["problem"]
    s = conf(client, "ollama").json()                                              # local: nothing leaves the network, nothing to confirm
    assert s["tiers"]["confidential"]["ready"] and s["tiers"]["confidential"]["zdr_confirmed_at"] is None


def test_moving_a_feature_to_the_development_tier_takes_an_explicit_acknowledgement(client, reset, server):
    put(client, {"tiers": {"dev": {"enabled": True}}})
    r = put(client, {"features": {"logs": "dev"}})
    assert r.status_code == 422 and "may log, retain or train on it" in r.json()["detail"]
    s = put(client, {"features": {"logs": "dev"}, "acknowledge_shared": True}).json()
    assert s["features"]["logs"]["tier"] == "dev" and s["features"]["logs"]["ready"] and s["shared_ack"]["by"] == "admin@example.com" and s["shared_ack"]["what"] == ["logs"]
    assert s["features"]["incidents"]["tier"] == "confidential"                      # only what was asked moved
    assert put(client, {"features": {"assistant": "off"}}).json()["features"]["assistant"]["problem"].endswith("turned off (AI → Settings).")
    assert put(client, {"security_on_dev": True}).status_code == 422               # security data for the assistant needs its own acknowledgement


def test_free_provider_logs_and_assistant_snapshot_without_security_data(client, reset, server):
    dev(client)
    srv = server(ok("Here you go:\n```json\n" + json.dumps(LOG_JSON) + "\n```"))   # fenced JSON with odd casing still parses
    r = client.post("/api/ai/logs", headers=CSRF, json={"text": "ERROR x\nDB_PASSWORD=s3cr3t\n", "source": "app"})
    assert r.status_code == 200, r.text
    assert r.json()["health"] == "failing" and r.json()["groups"][0]["severity"] == "error" and r.json()["tier"] == "dev"
    body = srv.requests[0]["body"]
    assert body["response_format"] == {"type": "json_object"} and "JSON schema" in body["messages"][0]["content"] and "s3cr3t" not in json.dumps(body)
    client.post("/api/services", headers=CSRF, json={"name": "llm-svc", "url": "https://llm.example.com"})
    srv = server(ok("One service is monitored."))
    r = client.post("/api/ai/ask", headers=CSRF, json={"messages": [{"role": "user", "content": "What do we monitor?"}]})
    assert r.status_code == 200 and r.json()["answer"] == "One service is monitored." and r.json()["tier"] == "dev"
    assert len(srv.requests) == 1 and "tools" not in srv.requests[0]["body"]                  # one request: the free provider is rate limited
    system = srv.requests[0]["body"]["messages"][0]["content"]
    assert "Data snapshot" in system and "llm-svc" in system and "## security_summary" not in system and "Security findings are not available" in system
    assert "security_summary" not in [t["tool"] for t in r.json()["tools"]]
    put(client, {"security_on_dev": True, "acknowledge_shared": True})               # an admin explicitly allows it
    srv = server(ok("ok"))
    client.post("/api/ai/ask", headers=CSRF, json={"messages": [{"role": "user", "content": "security?"}]})
    assert "## security_summary" in srv.requests[0]["body"]["messages"][0]["content"]


def test_free_provider_busy_gives_a_helpful_message(client, reset, server):
    dev(client)
    server((402, {"error": {"code": "FREE_LIMIT", "message": "Free limit reached: 1 reply every 45 seconds per IP. Retry after 120s"}}))
    r = client.post("/api/ai/test?tier=dev", headers=CSRF)
    assert r.status_code == 422 and "45 seconds" in r.json()["detail"] and "own key" in r.json()["detail"]


def test_confidential_tier_uses_tools_and_asks_providers_not_to_keep_data(client, reset, server):
    s = conf(client, "groq", key="gsk_test_1234567890abcdef").json()
    assert s["tiers"]["confidential"]["model"] == "llama-3.3-70b-versatile" and s["tiers"]["confidential"]["key_source"] == "dashboard"
    with database.SessionLocal() as db:
        assert "gsk_test" not in db.get(AppSetting, "ai").value                                 # stored encrypted
    client.post("/api/services", headers=CSRF, json={"name": "llm-svc", "url": "https://llm.example.com"})
    call = {"id": "c1", "type": "function", "function": {"name": "list_monitors", "arguments": json.dumps({"kind": "service", "bogus": 1})}}
    call2 = {"id": "c2", "type": "function", "function": {"name": "incidents", "arguments": "{\"hours\": \"48\", \"open_only\": \"false\"}"}}
    srv = server(ok(None, [call, call2]), ok("You monitor llm-svc."))
    r = client.post("/api/ai/ask", headers=CSRF, json={"messages": [{"role": "user", "content": "What do we monitor?"}]})
    assert r.status_code == 200, r.text
    assert r.json()["answer"] == "You monitor llm-svc." and r.json()["tier"] == "confidential" and [t["tool"] for t in r.json()["tools"]] == ["list_monitors", "incidents"]
    first, second = srv.requests
    assert first["url"] == "https://api.groq.com/openai/v1/chat/completions" and first["auth"] == "Bearer gsk_test_1234567890abcdef"
    names = {t["function"]["name"]: t["function"] for t in first["body"]["tools"]}
    assert set(names) == set(ai.Toolbox.NAMES) and names["uptime"]["parameters"]["required"] == ["monitor"]   # security data allowed here
    assert names["uptime"]["parameters"]["properties"]["hours"] == {"type": "integer", "description": "The window in hours."}
    tool_msgs = [m for m in second["body"]["messages"] if m["role"] == "tool"]
    assert [m["tool_call_id"] for m in tool_msgs] == ["c1", "c2"] and "llm-svc" in tool_msgs[0]["content"] and not tool_msgs[1]["content"].startswith('{"error"')
    s = client.get("/api/ai/settings").json()
    assert s["usage"]["input_tokens"] >= 200 and s["tiers"]["confidential"]["usage"]["requests"] == 1 and s["tiers"]["dev"]["usage"]["requests"] == 0
    # OpenRouter is told to use only hosts that do not collect data; OpenAI not to store completions; never on the Development tier
    conf(client, "openrouter", key="sk-or-test-1234567890")
    srv = server(ok("ready"))
    client.post("/api/ai/test?tier=confidential", headers=CSRF)
    assert srv.requests[0]["body"]["provider"] == {"data_collection": "deny"}
    conf(client, "openai", key="sk-test-1234567890")
    srv = server(ok("ready"))
    client.post("/api/ai/test", headers=CSRF)
    assert srv.requests[0]["body"]["store"] is False
    dev(client, "openrouter")
    srv = server(ok("ready"))
    client.post("/api/ai/test?tier=dev", headers=CSRF)
    assert "provider" not in srv.requests[0]["body"]


def test_switching_provider_keeps_each_key_and_resets_the_model(client, reset, server):
    dev(client, "groq", key="gsk_one_1234567890")
    s = conf(client, "ollama", base_url="http://localhost:11434/v1/").json()
    t = s["tiers"]["confidential"]
    assert t["model"] == "llama3.2" and t["ready"] and t["base_url"] == "http://localhost:11434/v1/"
    srv = server(ok("ready"))
    assert client.post("/api/ai/test?tier=confidential", headers=CSRF).status_code == 200 and srv.requests[0]["url"] == "http://localhost:11434/v1/chat/completions"
    s = put(client, {"tiers": {"dev": {"model": "openai/gpt-oss-120b"}}}).json()
    assert s["tiers"]["dev"]["model"] == "openai/gpt-oss-120b" and s["tiers"]["dev"]["provider"] == "groq" and s["tiers"]["dev"]["key_source"] == "dashboard"
    s = put(client, {"tiers": {"dev": {"provider": "mistral"}}}).json()
    assert s["tiers"]["dev"]["model"] == "mistral-small-latest" and next(p for p in s["providers"] if p["id"] == "groq")["key_saved"]   # the Groq key is kept
    assert put(client, {"tiers": {"dev": {"provider": "nope"}}}).status_code == 422
    assert put(client, {"tiers": {"dev": {"model": "bad model; rm"}}}).status_code == 422
    assert put(client, {"tiers": {"prod": {"enabled": True}}}).status_code == 422
    assert next(p for p in put(client, {"clear_keys": ["groq"]}).json()["providers"] if p["id"] == "groq")["key_saved"] is False


@pytest.mark.parametrize("provider,key,status,body,expect", [
    ("groq", None, None, None, "No API key is set for Groq"),
    ("openai", "sk-test-1234567890", 401, {"error": {"message": "Incorrect API key provided"}}, "OpenAI API key was rejected"),
    ("gemini", "AIzaTest1234567890", 400, {"error": {"message": "API key not valid. Please pass a valid API key."}}, "Google Gemini API key was rejected"),
    ("openrouter", "sk-or-test-1234567890", 404, {"error": {"message": "No endpoints found"}}, "does not know the model"),
    ("mistral", "abc1234567890", 429, {"message": "Requests rate limit exceeded"}, "rate limit or quota"),
    ("deepseek", "sk-test-1234567890", 503, {"error": "overloaded"}, "server error (503)"),
])
def test_clear_errors_for_each_provider(client, reset, server, provider, key, status, body, expect):
    s = dev(client, provider, key=key)
    assert s.status_code == 200, s.text
    if status:
        server((status, body), (status, body), (status, body))
    r = client.post("/api/ai/test?tier=dev", headers=CSRF)
    assert r.status_code == 422 and expect in r.json()["detail"], r.json()


GEMINI_MODELS = {"object": "list", "data": [{"id": f"models/{m}", "object": "model"} for m in
                 ("gemini-3.8-flash", "gemini-3.5-flash-lite", "gemini-3.8-pro", "gemini-embedding-001", "imagen-4.0-generate-001", "gemini-3.9-flash-preview")]}


def test_retired_model_404_suggests_available_models(client, reset, server):
    conf(client, "gemini", key="AQ.Ab8RN6Ktest_key", model="gemini-2.5-flash")
    srv = server((404, [{"error": {"code": 404, "message": "models/gemini-2.5-flash is not found for API version v1main", "status": "NOT_FOUND"}}]), (200, GEMINI_MODELS))
    r = client.post("/api/ai/test", headers=CSRF)
    detail = r.json()["detail"]
    assert r.status_code == 422 and "does not offer the model 'gemini-2.5-flash'" in detail and "retired" in detail
    assert "gemini-3.8-flash" in detail and "embedding" not in detail and "imagen" not in detail
    assert detail.index("gemini-3.8-flash") < detail.index("gemini-3.8-pro")                    # same family ("flash") first
    assert srv.requests[1] == {"url": "https://generativelanguage.googleapis.com/v1beta/openai/models", "method": "GET", "auth": "Bearer AQ.Ab8RN6Ktest_key", "body": None}
    server((200, GEMINI_MODELS))
    r = client.get("/api/ai/models?tier=confidential")
    assert r.status_code == 200 and r.json() == {"tier": "confidential", "provider": "gemini", "models": ["gemini-3.5-flash-lite", "gemini-3.8-flash", "gemini-3.8-pro", "gemini-3.9-flash-preview"]}
    server((400, [{"error": {"code": 400, "message": "API key not valid. Please pass a valid API key."}}]))
    r = client.get("/api/ai/models")
    assert r.status_code == 422 and "key was rejected" in r.json()["detail"]


def test_key_shape_hints(client, reset):
    r = put(client, {"keys": {"groq": "sk-ant-abc1234567890"}})
    assert r.status_code == 422 and "looks like a Anthropic (Claude) key" in r.json()["detail"]
    r = put(client, {"keys": {"openrouter": "sk-ant x"}})
    assert r.status_code == 422 and "spaces" in r.json()["detail"]
    for provider, key in (("gemini", "AQ.Ab8RN6Ktest-key_1234567890"), ("gemini", "AIzaSyTest1234567890"), ("openai", "sk-proj-abc1234567890"),
                          ("mistral", "abc1234567890"), ("openrouter", "sk-or-v1-abc1234567890")):   # unfamiliar or new key formats are accepted
        r = put(client, {"keys": {provider: key}})
        assert r.status_code == 200, (provider, key, r.text)


def test_unreachable_ollama(client, reset, monkeypatch):
    def refuse(request):
        raise httpx.ConnectError("refused")
    monkeypatch.setattr(llm.OpenAICompatProvider, "transport", httpx.MockTransport(refuse))
    conf(client, "ollama")
    r = client.post("/api/ai/test", headers=CSRF)
    assert r.status_code == 422 and "Could not reach Ollama" in r.json()["detail"] and "Is Ollama running" in r.json()["detail"]


def test_settings_from_before_tiers_are_migrated_safely(client, reset, monkeypatch):
    from app.crypto import encrypt
    with database.SessionLocal() as db:   # an Anthropic setup from before providers existed: becomes the Confidential tier, waiting for a confirmation
        db.add(AppSetting(key="ai", value=json.dumps({"enabled": True, "model": "claude-sonnet-5-5", "api_key": encrypt("sk-ant-legacy-123456"), "allow_logs": True})))
        db.commit()
        cfg = ai.load(db)
    c = cfg["tiers"]["confidential"]
    assert c["provider"] == "anthropic" and c["model"] == "claude-sonnet-5-5" and c["enabled"] and not cfg["tiers"]["dev"]["enabled"]
    assert cfg["features"]["logs"] == "confidential" and "has not confirmed" in ai.feature_problem(cfg, "logs")
    seen = {}
    monkeypatch.setattr(llm, "anthropic_client", lambda key: seen.setdefault("key", key))
    with database.SessionLocal() as db:
        provider = ai._provider(ai.load(db), "confidential")
    assert isinstance(provider, llm.AnthropicProvider) and seen["key"] == "sk-ant-legacy-123456"
    s = put(client, {"tiers": {"confidential": {"zdr_confirmed": True}}}).json()    # one confirmation and it works again
    assert s["features"]["logs"]["ready"] and s["tiers"]["confidential"]["key_source"] == "dashboard"
    with database.SessionLocal() as db:
        assert '"api_key"' not in db.get(AppSetting, "ai").value and '"tiers"' in db.get(AppSetting, "ai").value
        db.delete(db.get(AppSetting, "ai")); db.commit()
        db.add(AppSetting(key="ai", value=json.dumps({"enabled": True, "provider": "free", "model": ""})))   # a free-provider setup: the Development tier
        db.commit()
        cfg = ai.load(db)
    assert cfg["tiers"]["dev"]["enabled"] and cfg["tiers"]["dev"]["provider"] == "free" and not cfg["tiers"]["confidential"]["enabled"] and cfg["features"]["assistant"] == "confidential"


def test_env_key_selects_the_confidential_provider_when_nothing_is_saved(client, reset, monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "AIzaFromEnv")
    for name in ("ANTHROPIC_API_KEY", "OPENAI_API_KEY"):
        monkeypatch.delenv(name, raising=False)
    s = client.get("/api/ai/settings").json()
    assert s["tiers"]["confidential"]["provider"] == "gemini" and s["tiers"]["confidential"]["key_source"] == "env"


def test_auto_explain_with_free_provider_does_one_per_run(client, reset, server):
    dev(client)
    put(client, {"auto_explain": True})
    sid = client.post("/api/services", headers=CSRF, json={"name": "llm-svc", "url": "https://llm.example.com"}).json()["id"]
    now = datetime.now(timezone.utc)
    with database.SessionLocal() as db:
        for _ in range(2):
            db.add(Incident(target_type="service", target_id=sid, target_name="llm-svc", severity="critical", title="llm-svc is down", started_at=now - timedelta(minutes=5)))
        db.commit()
    analysis = {"summary": "It went down.", "impact": "Users", "likely_causes": [{"cause": "Deploy", "evidence": "timing", "confidence": "High"}], "next_checks": ["look"], "related": []}
    srv = server(ok(json.dumps(analysis), model="gpt-oss-20b"))
    with database.SessionLocal() as db:
        ai.auto_explain(db)
        done = db.query(Incident).filter(Incident.target_name == "llm-svc", Incident.ai_generated_at.isnot(None)).all()
    assert len(srv.requests) == 1 and len(done) == 1 and done[0].ai_model == "gpt-oss-20b"
    assert json.loads(done[0].ai_analysis)["likely_causes"][0]["confidence"] == "high"


def test_tool_schema_and_call_tool():
    def sample(name: str, hours: int = 24, open_only: bool = False) -> str:
        """Do a thing.

        Args:
            name: The name.
            hours: How long.
            open_only: Only open ones.
        """
        return json.dumps([name, hours, open_only])
    schema = llm.tool_schema(sample)["function"]
    assert schema["description"] == "Do a thing." and schema["parameters"]["required"] == ["name"]
    assert schema["parameters"]["properties"]["open_only"] == {"type": "boolean", "description": "Only open ones."}
    assert json.loads(llm.call_tool(sample, '{"name": 5, "hours": "12.0", "open_only": "true", "x": 1}')) == ["5", 12, True]
    assert "not valid JSON" in llm.call_tool(sample, "{oops")
    assert "error" in llm.call_tool(sample, "{}")            # missing required argument is reported, not raised
    assert llm.extract_json("<think>hmm</think> sure: {\"a\": 1} done") == {"a": 1}


def test_explain_one_log_line_masks_secrets_and_uses_context(client, reset, server):
    dev(client)
    answer = {"summary": "Postgres refused the connection.", "severity": "Error", "meaning": "The app could not open a TCP connection to the database.",
              "likely_causes": ["Postgres is down"], "fix": ["systemctl status postgresql"], "needs_attention": True}
    srv = server(ok(json.dumps(answer), model="gpt-oss-20b"))
    r = client.post("/api/ai/log-line", headers=CSRF, json={"line": "ERROR connect ECONNREFUSED 10.0.0.5:5432 password=hunter2", "before": ["INFO start", "DB_PASSWORD=s3cr3t"],
                                                            "after": ["WARN retrying"], "source": "container api on web-01"})
    assert r.status_code == 200, r.text
    assert r.json()["severity"] == "error" and r.json()["needs_attention"] and r.json()["context_lines"] == 3 and r.json()["model"] == "gpt-oss-20b"
    sent = json.dumps(srv.requests[0]["body"])
    assert "hunter2" not in sent and "s3cr3t" not in sent and "ECONNREFUSED" in sent and "WARN retrying" in sent and "container api on web-01" in sent
    assert client.post("/api/ai/log-line", headers=CSRF, json={"line": ""}).status_code == 422
    put(client, {"allow_logs": False})
    assert "not allowed" in client.post("/api/ai/log-line", headers=CSRF, json={"line": "x"}).json()["detail"]


def _cut(content, model="m-1"):
    return 200, {"model": model, "choices": [{"message": {"role": "assistant", "content": content}, "finish_reason": "length"}], "usage": {"prompt_tokens": 10, "completion_tokens": 10}}


def test_answers_are_not_cut_off(server, monkeypatch):
    """The output limit is always sent; a chat answer that hits it is continued; a server that rejects the limit still works."""
    monkeypatch.setenv("AI_MAX_OUTPUT_TOKENS", "3000")
    groq = llm.OpenAICompatProvider(llm.PROVIDERS["groq"], "m-1", "k", "https://api.example/v1/chat/completions")
    srv = server(_cut("The disk is full because "), _cut("the log rotation stopped "), ok("on Monday. Run logrotate -f."))
    reply = groq.chat("sys", [{"role": "user", "content": "why?"}], [])
    assert reply.text == "The disk is full because the log rotation stopped on Monday. Run logrotate -f."
    assert srv.requests[0]["body"]["max_tokens"] == 3000 and srv.requests[1]["body"]["messages"][-1]["content"].startswith("Continue exactly")
    openai = llm.OpenAICompatProvider(llm.PROVIDERS["openai"], "gpt-x", "k", "https://api.example/v1/chat/completions")
    srv = server(ok("hi"))
    openai.chat("sys", [{"role": "user", "content": "x"}], [])
    assert "max_completion_tokens" in srv.requests[0]["body"] and "max_tokens" not in srv.requests[0]["body"]   # OpenAI's newer name
    srv = server((400, {"error": {"message": "Unsupported parameter: 'max_tokens'"}}), ok("fine"))
    assert groq.chat("sys", [{"role": "user", "content": "x"}], []).text == "fine" and "max_tokens" not in srv.requests[1]["body"]
    srv = server(_cut("a"), _cut("b"), _cut("c"))
    assert groq.chat("sys", [{"role": "user", "content": "x"}], []).text.endswith("cut off by the model's output limit.)*")   # said, never silent
