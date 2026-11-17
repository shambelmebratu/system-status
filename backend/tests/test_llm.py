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
        self.requests.append({"url": str(request.url), "auth": request.headers.get("authorization"), "body": json.loads(request.content)})
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


def test_free_provider_is_the_default_and_needs_no_key(client, reset, server):
    s = client.get("/api/ai/settings").json()
    assert s["provider"] == "free" and s["model"] == "openai" and not s["ready"] and not s["enabled"]
    free = next(p for p in s["providers"] if p["id"] == "free")
    assert free["needs_key"] is False and "Pollinations" in free["destination"]
    assert {p["id"] for p in s["providers"]} >= {"free", "anthropic", "openai", "gemini", "groq", "openrouter", "mistral", "deepseek", "ollama", "custom"}
    s = client.put("/api/ai/settings", headers=CSRF, json={"enabled": True}).json()
    assert s["ready"] and s["key_source"] is None
    srv = server(ok("ready", model="gpt-oss-20b"))
    r = client.post("/api/ai/test", headers=CSRF)
    assert r.status_code == 200 and r.json() == {"ok": True, "provider": "free", "model": "gpt-oss-20b", "reply": "ready"}
    assert srv.requests[0]["url"] == "https://text.pollinations.ai/openai" and srv.requests[0]["auth"] is None
    # a key typed for the free provider is refused with a clear reason
    r = client.put("/api/ai/settings", headers=CSRF, json={"enabled": True, "api_key": "sk-something-1234567890"})
    assert r.status_code == 422 and "does not use an API key" in r.json()["detail"]


def test_free_provider_logs_and_assistant_snapshot(client, reset, server):
    client.put("/api/ai/settings", headers=CSRF, json={"enabled": True, "provider": "free"})
    srv = server(ok("Here you go:\n```json\n" + json.dumps(LOG_JSON) + "\n```"))   # fenced JSON with odd casing still parses
    r = client.post("/api/ai/logs", headers=CSRF, json={"text": "ERROR x\nDB_PASSWORD=s3cr3t\n", "source": "app"})
    assert r.status_code == 200, r.text
    assert r.json()["health"] == "failing" and r.json()["groups"][0]["severity"] == "error"
    body = srv.requests[0]["body"]
    assert body["response_format"] == {"type": "json_object"} and "JSON schema" in body["messages"][0]["content"] and "s3cr3t" not in json.dumps(body)
    client.post("/api/services", headers=CSRF, json={"name": "llm-svc", "url": "https://llm.example.com"})
    srv = server(ok("One service is monitored."))
    r = client.post("/api/ai/ask", headers=CSRF, json={"messages": [{"role": "user", "content": "What do we monitor?"}]})
    assert r.status_code == 200 and r.json()["answer"] == "One service is monitored."
    assert len(srv.requests) == 1 and "tools" not in srv.requests[0]["body"]                  # one request: the free tier is rate limited
    system = srv.requests[0]["body"]["messages"][0]["content"]
    assert "Data snapshot" in system and "llm-svc" in system
    assert [t["tool"] for t in r.json()["tools"]][:2] == ["list_monitors", "incidents"]


def test_free_provider_busy_gives_a_helpful_message(client, reset, server):
    client.put("/api/ai/settings", headers=CSRF, json={"enabled": True, "provider": "free"})
    server((402, {"error": {"code": "FREE_LIMIT", "message": "Free limit reached: 1 reply every 45 seconds per IP. Retry after 120s"}}))
    r = client.post("/api/ai/test", headers=CSRF)
    assert r.status_code == 422 and "45 seconds" in r.json()["detail"] and "own key" in r.json()["detail"]


def test_openai_compatible_provider_uses_tools(client, reset, server):
    s = client.put("/api/ai/settings", headers=CSRF, json={"enabled": True, "provider": "groq", "api_key": "gsk_test_1234567890abcdef"}).json()
    assert s["ready"] and s["provider"] == "groq" and s["model"] == "llama-3.3-70b-versatile" and s["key_source"] == "dashboard"
    with database.SessionLocal() as db:
        assert "gsk_test" not in db.get(AppSetting, "ai").value                                 # stored encrypted
    client.post("/api/services", headers=CSRF, json={"name": "llm-svc", "url": "https://llm.example.com"})
    call = {"id": "c1", "type": "function", "function": {"name": "list_monitors", "arguments": json.dumps({"kind": "service", "bogus": 1})}}
    call2 = {"id": "c2", "type": "function", "function": {"name": "incidents", "arguments": "{\"hours\": \"48\", \"open_only\": \"false\"}"}}
    srv = server(ok(None, [call, call2]), ok("You monitor llm-svc."))
    r = client.post("/api/ai/ask", headers=CSRF, json={"messages": [{"role": "user", "content": "What do we monitor?"}]})
    assert r.status_code == 200, r.text
    assert r.json()["answer"] == "You monitor llm-svc." and [t["tool"] for t in r.json()["tools"]] == ["list_monitors", "incidents"]
    first, second = srv.requests
    assert first["url"] == "https://api.groq.com/openai/v1/chat/completions" and first["auth"] == "Bearer gsk_test_1234567890abcdef"
    names = {t["function"]["name"]: t["function"] for t in first["body"]["tools"]}
    assert set(names) == set(ai.Toolbox.NAMES) and names["uptime"]["parameters"]["required"] == ["monitor"]
    assert names["uptime"]["parameters"]["properties"]["hours"] == {"type": "integer", "description": "The window in hours."}
    tool_msgs = [m for m in second["body"]["messages"] if m["role"] == "tool"]
    assert [m["tool_call_id"] for m in tool_msgs] == ["c1", "c2"] and "llm-svc" in tool_msgs[0]["content"] and not tool_msgs[1]["content"].startswith('{"error"')
    assert client.get("/api/ai/settings").json()["usage"]["input_tokens"] >= 200


def test_switching_provider_keeps_each_key_and_resets_the_model(client, reset, server):
    client.put("/api/ai/settings", headers=CSRF, json={"enabled": True, "provider": "groq", "api_key": "gsk_one_1234567890"})
    s = client.put("/api/ai/settings", headers=CSRF, json={"enabled": True, "provider": "ollama", "base_url": "http://localhost:11434/v1/"}).json()
    assert s["model"] == "llama3.2" and s["ready"] and s["base_url"] == "http://localhost:11434/v1/"
    srv = server(ok("ready"))
    assert client.post("/api/ai/test", headers=CSRF).status_code == 200 and srv.requests[0]["url"] == "http://localhost:11434/v1/chat/completions"
    s = client.put("/api/ai/settings", headers=CSRF, json={"enabled": True, "provider": "groq"}).json()
    assert s["key_source"] == "dashboard" and s["base_url"] == "" and next(p for p in s["providers"] if p["id"] == "groq")["key_saved"]
    s = client.put("/api/ai/settings", headers=CSRF, json={"enabled": True, "model": "openai/gpt-oss-120b"}).json()
    assert s["model"] == "openai/gpt-oss-120b" and s["provider"] == "groq"
    assert client.put("/api/ai/settings", headers=CSRF, json={"enabled": True, "provider": "nope"}).status_code == 422
    assert client.put("/api/ai/settings", headers=CSRF, json={"enabled": True, "model": "bad model; rm"}).status_code == 422


@pytest.mark.parametrize("provider,payload,status,body,expect", [
    ("groq", {}, None, None, "No API key is set for Groq. Add GROQ_API_KEY to .env"),
    ("openai", {"api_key": "sk-test-1234567890"}, 401, {"error": {"message": "Incorrect API key provided"}}, "OpenAI API key was rejected"),
    ("gemini", {"api_key": "AIzaTest1234567890"}, 400, {"error": {"message": "API key not valid. Please pass a valid API key."}}, "Google Gemini API key was rejected"),
    ("openrouter", {"api_key": "sk-or-test-1234567890"}, 404, {"error": {"message": "No endpoints found"}}, "does not know the model"),
    ("mistral", {"api_key": "abc1234567890"}, 429, {"message": "Requests rate limit exceeded"}, "rate limit or quota"),
    ("deepseek", {"api_key": "sk-test-1234567890"}, 503, {"error": "overloaded"}, "server error (503)"),
])
def test_clear_errors_for_each_provider(client, reset, server, provider, payload, status, body, expect):
    s = client.put("/api/ai/settings", headers=CSRF, json={"enabled": True, "provider": provider, **payload})
    assert s.status_code == 200, s.text
    if status:
        server((status, body), (status, body), (status, body))
    r = client.post("/api/ai/test", headers=CSRF)
    assert r.status_code == 422 and expect in r.json()["detail"], r.json()


def test_key_shape_hints(client, reset):
    r = client.put("/api/ai/settings", headers=CSRF, json={"enabled": True, "provider": "groq", "api_key": "sk-ant-abc1234567890"})
    assert r.status_code == 422 and "looks like a Anthropic (Claude) key" in r.json()["detail"]
    r = client.put("/api/ai/settings", headers=CSRF, json={"enabled": True, "provider": "openrouter", "api_key": "foo1234567890"})
    assert r.status_code == 422 and "starts with sk-or-" in r.json()["detail"]


def test_unreachable_ollama(client, reset, monkeypatch):
    def refuse(request):
        raise httpx.ConnectError("refused")
    monkeypatch.setattr(llm.OpenAICompatProvider, "transport", httpx.MockTransport(refuse))
    client.put("/api/ai/settings", headers=CSRF, json={"enabled": True, "provider": "ollama"})
    r = client.post("/api/ai/test", headers=CSRF)
    assert r.status_code == 422 and "Could not reach Ollama" in r.json()["detail"] and "Is Ollama running" in r.json()["detail"]


def test_legacy_anthropic_settings_still_work(client, reset, monkeypatch):
    from app.crypto import encrypt
    with database.SessionLocal() as db:
        db.add(AppSetting(key="ai", value=json.dumps({"enabled": True, "model": "claude-sonnet-5-5", "api_key": encrypt("sk-ant-legacy-123456"), "allow_logs": True})))
        db.commit()
        cfg = ai.load(db)
    assert cfg["provider"] == "anthropic" and cfg["model"] == "claude-sonnet-5-5"
    seen = {}
    monkeypatch.setattr(llm, "anthropic_client", lambda key: seen.setdefault("key", key))
    with database.SessionLocal() as db:
        provider = ai._provider(ai.load(db))
    assert isinstance(provider, llm.AnthropicProvider) and seen["key"] == "sk-ant-legacy-123456"
    s = client.put("/api/ai/settings", headers=CSRF, json={"enabled": True}).json()            # saving rewrites it in the new shape
    assert s["provider"] == "anthropic" and s["key_source"] == "dashboard"
    with database.SessionLocal() as db:
        assert '"api_key"' not in db.get(AppSetting, "ai").value


def test_env_key_selects_a_provider_when_nothing_is_saved(client, reset, monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "AIzaFromEnv")
    for name in ("ANTHROPIC_API_KEY", "OPENAI_API_KEY"):
        monkeypatch.delenv(name, raising=False)
    s = client.get("/api/ai/settings").json()
    assert s["provider"] == "gemini" and s["key_source"] == "env"


def test_auto_explain_with_free_provider_does_one_per_run(client, reset, server):
    client.put("/api/ai/settings", headers=CSRF, json={"enabled": True, "provider": "free", "auto_explain": True})
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
