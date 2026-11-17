"""AI features with a fake Anthropic client (the Anthropic provider) (no network, no cost), and statistical anomaly detection."""
import json
import os
import sys
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

os.environ.setdefault("ENVIRONMENT", "test"); os.environ.setdefault("JWT_SECRET", "x" * 40); os.environ.setdefault("DATABASE_URL", "sqlite://")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import pytest
from fastapi.testclient import TestClient

from test_api_auth import CSRF, PW, client, fresh_stats_cache, main, make_user, session_for, sign_in  # noqa: F401
from app import ai, anomaly, database, llm
from app.models import AuditEvent, CheckResult, Incident, MetricSample, Server, Service


class FakeClient:
    """Records what would have been sent to the Anthropic API and answers like it."""
    def __init__(self, stop_reason="end_turn"):
        self.sent, self.stop_reason = [], stop_reason
        self.beta = SimpleNamespace(messages=SimpleNamespace(parse=self.parse, tool_runner=self.tool_runner))

    def _usage(self):
        return SimpleNamespace(input_tokens=1200, output_tokens=300, cache_read_input_tokens=0, cache_creation_input_tokens=0)

    def parse(self, **kw):
        self.sent.append(kw)
        schema = kw["output_format"]
        if schema is ai.IncidentAnalysis:
            out = ai.IncidentAnalysis(summary="The checkout service stopped answering after a deploy.", impact="Customers cannot pay.",
                                      likely_causes=[ai.Cause(cause="Bad deploy", evidence="Timeout changed 4 minutes before", confidence="high")],
                                      next_checks=["kubectl -n shop rollout history deploy/checkout"], related=["api-gateway also failed"])
        else:
            out = ai.LogAnalysis(summary="Database connections are refused.", health="failing",
                                 groups=[ai.LogGroup(title="Connection refused", severity="error", occurrences=40, example="connect ECONNREFUSED 10.0.0.5:5432", meaning="Postgres is down", fix="Restart postgres")],
                                 next_steps=["Check postgres"])
        return SimpleNamespace(parsed_output=None if self.stop_reason == "refusal" else out, stop_reason=self.stop_reason, model=kw["model"], usage=self._usage())

    def tool_runner(self, **kw):
        self.sent.append(kw)
        tools = {t.to_dict()["name"]: t for t in kw["tools"]}
        results = {name: json.loads(tools[name].call(args)) for name, args in (("list_monitors", {"kind": "service"}), ("incidents", {"hours": 48}), ("uptime", {"monitor": "checkout", "hours": 24}))}
        self.tool_results = results
        final = SimpleNamespace(stop_reason="end_turn", model=kw["model"], usage=self._usage(), content=[SimpleNamespace(type="text", text=f"{len(results['list_monitors'])} services are monitored.")])
        return SimpleNamespace(until_done=lambda: final)


@pytest.fixture()
def fake(monkeypatch):
    f = FakeClient()
    monkeypatch.setattr(llm, "anthropic_client", lambda key: f)
    return f


def _enable(client, **extra):
    r = client.put("/api/ai/settings", headers=CSRF, json={"enabled": True, "provider": "anthropic", "api_key": "sk-ant-test-key-1234567890", **extra})
    assert r.status_code == 200, r.text
    return r.json()


def test_settings_are_admin_only_and_the_key_stays_secret(client):
    sign_in(client)
    assert client.get("/api/ai/settings").json()["enabled"] is False
    assert client.put("/api/ai/settings", headers=CSRF, json={"enabled": True, "provider": "anthropic", "api_key": "not-a-key"}).status_code == 422
    s = _enable(client)
    assert s["ready"] and s["key_source"] == "dashboard" and s["model"] == "claude-opus-5-5" and "sk-ant-test" not in json.dumps(s)
    with database.SessionLocal() as db:
        raw = db.get(ai.AppSetting, "ai").value
    assert "sk-ant-test-key" not in raw                                                             # stored encrypted
    make_user(client, "ai-op@example.com", "operator")
    op = session_for("ai-op@example.com", new_password="ai-operator-pass-1")
    assert op.put("/api/ai/settings", headers=CSRF, json={"enabled": False}).status_code == 403
    assert any(e["action"] == "ai.settings" and "API key set" in e["detail"] for e in client.get("/api/audit?category=ai").json())
    client.put("/api/ai/settings", headers=CSRF, json={"enabled": False, "clear_key": True})


def test_explain_incident_with_context(client, fake):
    sign_in(client)
    _enable(client)
    try:
        sid = client.post("/api/services", headers=CSRF, json={"name": "checkout", "url": "https://shop.example.com/pay", "timeout_seconds": 3}).json()["id"]
        other = client.post("/api/services", headers=CSRF, json={"name": "api-gateway", "url": "https://api.example.com"}).json()["id"]
        now = datetime.now(timezone.utc)
        with database.SessionLocal() as db:
            for i in range(10):
                db.add(CheckResult(target_type="service", target_id=sid, status="up" if i < 6 else "down", latency_ms=120, http_status=200 if i < 6 else None,
                                   error=None if i < 6 else "Timed out: password=hunter2 in url", checked_at=now - timedelta(minutes=10 - i)))
            inc = Incident(target_type="service", target_id=sid, target_name="checkout", severity="critical", title="checkout is down", detail="Timed out", started_at=now - timedelta(minutes=4))
            db.add(inc)
            db.add(Incident(target_type="service", target_id=other, target_name="api-gateway", severity="critical", title="api-gateway is down", started_at=now - timedelta(minutes=3)))
            db.add(AuditEvent(actor="admin@example.com", action="service.update", target=f"service:{sid}", detail="checkout", success=True, ts=now - timedelta(minutes=8)))
            db.commit(); iid = inc.id
        r = client.post(f"/api/incidents/{iid}/explain", headers=CSRF)
        assert r.status_code == 200, r.text
        assert r.json()["analysis"]["likely_causes"][0]["confidence"] == "high" and r.json()["model"] == "claude-opus-5-5"
        sent = fake.sent[-1]
        context = sent["messages"][0]["content"]
        assert "api-gateway is down" in context and "service.update" in context and "url host: shop.example.com" in context
        assert "hunter2" not in context and "password=***" in context                                                # masked before sending
        assert sent["betas"] == ["server-side-fallback-2026-07-01"] and sent["fallbacks"] == "default" and sent["output_config"] == {"effort": "medium"}
        listed = next(i for i in client.get("/api/incidents").json() if i["id"] == iid)
        assert listed["ai_analysis"]["summary"].startswith("The checkout service")
        assert client.get("/api/ai/settings").json()["usage"]["requests"] >= 1
    finally:
        client.put("/api/ai/settings", headers=CSRF, json={"enabled": False, "clear_key": True})
        with database.SessionLocal() as db:   # leave no open incidents behind for other tests
            for i in db.query(Incident).filter(Incident.resolved_at.is_(None), Incident.target_name.in_(["checkout", "api-gateway"])).all():
                i.resolved_at = datetime.now(timezone.utc)
            db.commit()


def test_logs_are_masked_and_refusals_handled(client, fake, monkeypatch):
    sign_in(client)
    _enable(client)
    try:
        text = "INFO start\nERROR connect ECONNREFUSED 10.0.0.5:5432\nDB_PASSWORD=s3cr3t\nAuthorization: Bearer abcdefghijklmnopqrstuvwxyz\npostgres://app:pw123@db:5432/x\n"
        r = client.post("/api/ai/logs", headers=CSRF, json={"text": text, "source": "container api on web-01"})
        assert r.status_code == 200 and r.json()["health"] == "failing" and r.json()["lines_sent"] == 5
        sent = fake.sent[-1]["messages"][0]["content"]
        assert "s3cr3t" not in sent and "abcdefghijklmnop" not in sent and "pw123" not in sent and "ECONNREFUSED" in sent
        client.put("/api/ai/settings", headers=CSRF, json={"enabled": True, "allow_logs": False})
        assert "not allowed" in client.post("/api/ai/logs", headers=CSRF, json={"text": "x"}).json()["detail"]
        refusing = FakeClient(stop_reason="refusal")
        monkeypatch.setattr(llm, "anthropic_client", lambda key: refusing)
        client.put("/api/ai/settings", headers=CSRF, json={"enabled": True, "allow_logs": True})
        assert "declined" in client.post("/api/ai/logs", headers=CSRF, json={"text": "x"}).json()["detail"]
    finally:
        client.put("/api/ai/settings", headers=CSRF, json={"enabled": False, "clear_key": True})


def test_assistant_tools_respect_access(client, fake):
    sign_in(client)
    _enable(client)
    try:
        a = client.post("/api/services", headers=CSRF, json={"name": "checkout", "url": "https://shop.example.com"}).json()["id"]
        client.post("/api/services", headers=CSRF, json={"name": "secret-internal", "url": "https://internal.example.com"})
        r = client.post("/api/ai/ask", headers=CSRF, json={"messages": [{"role": "user", "content": "How many services do we monitor?"}]})
        assert r.status_code == 200 and [t["tool"] for t in r.json()["tools"]] == ["list_monitors", "incidents", "uptime"]
        assert any(m["name"] == "secret-internal" for m in fake.tool_results["list_monitors"])
        make_user(client, "ai-limited@example.com", "viewer")
        uid = next(u["id"] for u in client.get("/api/users").json() if u["email"] == "ai-limited@example.com")
        client.put(f"/api/users/{uid}", headers=CSRF, json={"access_set": True, "access": {"services": [a]}})
        v = session_for("ai-limited@example.com", new_password="ai-viewer-pass-12")
        assert v.post("/api/ai/ask", headers=CSRF, json={"messages": [{"role": "user", "content": "list services"}]}).status_code == 200
        names = [m["name"] for m in fake.tool_results["list_monitors"]]
        assert "checkout" in names and "secret-internal" not in names                                   # the assistant sees only what the person may see
        assert client.post("/api/ai/ask", headers=CSRF, json={"messages": [{"role": "assistant", "content": "hi"}]}).status_code == 422
        assert any(e["action"] == "ai.ask" and "list services" in e["detail"] for e in client.get("/api/audit?category=ai").json())
    finally:
        client.put("/api/ai/settings", headers=CSRF, json={"enabled": False, "clear_key": True})


def test_ai_off_by_default_gives_a_clear_message(client):
    sign_in(client)
    r = client.post("/api/ai/ask", headers=CSRF, json={"messages": [{"role": "user", "content": "hi"}]})
    assert r.status_code == 422 and "turned off" in r.json()["detail"]


def test_mask():
    text = "AWS key AKIAABCDEFGHIJKLMNOP and token=abc123secret and eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
    out = ai.mask(text)
    assert "ABCDEFGHIJKLMNOP" not in out and "abc123secret" not in out and "*** JWT ***" in out


def test_anomaly_detection(client):
    sign_in(client)
    import random
    random.seed(7)
    anon = TestClient(main.app)
    tok = client.post("/api/enrollments", headers=CSRF, json={}).json()["token"]
    sid = anon.post("/api/agent/enroll", headers={"Authorization": f"Bearer {tok}"}, json={"hostname": "anomaly-box", "machine_id": "anom1"}).json()["server_id"]
    now = datetime.now(timezone.utc)
    with database.SessionLocal() as db:   # 3 days of a quiet server (CPU ~10 % +- 2), then the last 20 minutes at 70 %
        rows = [MetricSample(server_id=sid, ts=now - timedelta(minutes=m), cpu=(70.0 if m < 20 else 10 + random.uniform(-2, 2)), memory=40 + random.uniform(-1, 1), disk=50, load=0.5, swap=0,
                             net_rx_bps=200_000 + random.uniform(-20_000, 20_000), net_tx_bps=50_000) for m in range(0, 3 * 1440, 5)]
        db.add_all(rows); db.commit()
        assert anomaly.detect(db, force=True) == []                       # first sighting: wait for confirmation
        opened = anomaly.detect(db, force=True)
        db.commit()
        assert [(o["kind"], o["row"].metric, o["row"].direction) for o in opened] == [("server", "cpu", "up")]
        assert anomaly.describe(opened[0]["row"]).startswith("CPU is 70.0%, usually 10.") and "above" in anomaly.describe(opened[0]["row"])
    listed = client.get("/api/anomalies").json()
    assert listed[0]["target_name"] == "anomaly-box" and listed[0]["resolved_at"] is None
    # judge(): a flat metric must not alert on a tiny wobble, and needs enough history
    flat = [10.0] * 200
    assert anomaly.judge("cpu", 12.0, flat)[0] == "calm" and anomaly.judge("cpu", 60.0, flat)[0] == "up" and anomaly.judge("cpu", 60.0, flat[:10]) is None
