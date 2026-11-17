"""QA: multi-step API tests, content checks and DNS monitors (a local test API; DNS answers are simulated)."""
import http.server
import json
import os
import sys
import threading

os.environ.setdefault("ENVIRONMENT", "test"); os.environ.setdefault("JWT_SECRET", "x" * 40); os.environ.setdefault("DATABASE_URL", "sqlite://")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import pytest

from test_api_auth import CSRF, client, fresh_stats_cache, sign_in  # noqa: F401  (fixtures)
from app import database, dnsmon, netguard, qa


class Api(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a): pass

    def _send(self, code, body, headers=None):
        data = json.dumps(body).encode() if not isinstance(body, bytes) else body
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers(); self.wfile.write(data)

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))) or b"{}")
        if self.path == "/login" and body.get("password") == "s3cret-pass":
            return self._send(200, {"token": "tok-abcdef-123456", "user": {"id": 7, "roles": ["admin"]}}, {"X-Request-Id": "r1"})
        self._send(401, {"error": "bad credentials"})

    def do_GET(self):
        if self.path == "/me":
            if self.headers.get("Authorization") == "Bearer tok-abcdef-123456":
                return self._send(200, {"id": 7, "items": [{"sku": "A"}, {"sku": "B"}], "total": 2})
            return self._send(401, {"error": "no token"})
        if self.path == "/page":
            return self._send(200, b"<html><h1>Welcome to the Checkout</h1></html>")
        self._send(404, {"error": "nope"})


@pytest.fixture()
def api(monkeypatch):
    monkeypatch.setattr(netguard, "_ip_blocked", lambda ip: None)   # the test API runs on loopback
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Api)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{server.server_port}"
    server.shutdown()


def definition(base, password="{{password}}"):
    return {"variables": {"password": "s3cret-pass"}, "secret_variables": ["password"], "steps": [
        {"name": "Log in", "method": "POST", "url": f"{base}/login", "body": json.dumps({"user": "qa", "password": password}),
         "assertions": [{"kind": "status", "op": "eq", "value": "200"}, {"kind": "json", "path": "user.roles", "op": "contains", "value": "admin"}, {"kind": "time", "op": "lt", "value": "5000"}],
         "extract": [{"var": "token", "source": "json", "path": "token"}]},
        {"name": "Profile", "method": "GET", "url": f"{base}/me", "headers": {"Authorization": "Bearer {{token}}"},
         "assertions": [{"kind": "json", "path": "items[1].sku", "op": "eq", "value": "B"}, {"kind": "json", "path": "total", "op": "gte", "value": "2"},
                        {"kind": "json", "path": "missing", "op": "not_exists"}, {"kind": "header", "path": "content-type", "op": "contains", "value": "json"}]},
    ]}


def test_multi_step_test_passes_and_masks_secrets(api):
    r = qa.run_test(definition(api))
    assert r["status"] == "passed" and [s["status"] for s in r["steps"]] == ["passed", "passed"], r
    text = json.dumps(r)
    assert "s3cret-pass" not in text and "tok-abcdef-123456" not in text                     # password and extracted token never stored
    assert r["steps"][1]["request_headers"]["Authorization"] == "***"


def test_failure_stops_and_explains(api):
    r = qa.run_test(definition(api, password="wrong"))
    assert r["status"] == "failed" and [s["status"] for s in r["steps"]] == ["failed", "skipped"]
    assert "Log in: Status code equals 200 (got 401)" in r["error"]


def test_internal_addresses_are_blocked():
    blocked = qa.run_test({"steps": [{"url": "http://169.254.169.254/latest/meta-data"}, {"url": "http://127.0.0.1:5432/"}]})
    assert blocked["status"] == "failed" and "Blocked" in blocked["steps"][0]["error"] and blocked["steps"][1]["status"] == "skipped"


def test_json_path_and_compare():
    data = {"a": {"b": [{"c": 1}, {"c": "x"}]}, "n": None}
    assert qa.json_path(data, "a.b[1].c") == "x" and qa.json_path(data, "$.a.b[-1].c") == "x" and qa.json_path(data, "a.z") is qa._MISSING
    assert qa.compare(5, "gt", "4") and qa.compare("abc", "matches", "^a") and qa.compare(None, "type", "null") and qa.compare(201, "in", "200,201")
    assert not qa.compare(qa._MISSING, "eq", "1") and qa.compare(qa._MISSING, "not_exists", "")


def test_tests_api_runs_and_records(client, api):
    sign_in(client)
    body = {"name": "Checkout API", "interval_seconds": 300, "definition": definition(api)}
    t = client.post("/api/tests", headers=CSRF, json=body).json()
    assert t["step_count"] == 2 and "s3cret-pass" not in json.dumps(client.get("/api/tests").json())
    run = client.post(f"/api/tests/{t['id']}/run", headers=CSRF).json()
    assert run["status"] == "passed" and run["run_id"]
    detail = client.get(f"/api/test-runs/{run['run_id']}").json()
    assert detail["test_name"] == "Checkout API" and len(detail["steps"]) == 2 and detail["trigger"].startswith("manual: admin@")
    runs = client.get(f"/api/tests/{t['id']}/runs").json()
    assert runs["summary_7d"]["runs"] == 1 and runs["summary_7d"]["passed"] == 1
    tried = client.post("/api/tests/try", headers=CSRF, json=definition(api, "nope")).json()
    assert tried["status"] == "failed" and len(client.get(f"/api/tests/{t['id']}/runs").json()["runs"]) == 1   # a try is not stored
    bad = client.post("/api/tests", headers=CSRF, json={**body, "definition": {"steps": [{"url": "x", "headers": {"Bad Header": "1"}}]}})
    assert bad.status_code == 422
    assert any(e["action"] == "qa.test_create" for e in client.get("/api/audit?category=qa").json())


def test_keyword_check(client, api, monkeypatch):
    from app import monitoring as m
    s = m.Service(name="page", url=f"{api}/page", expected_status=200, keyword="checkout", keyword_mode="contains", cert_check=False)
    assert m.probe_service(s)["status"] == "up"
    s.keyword = "Out of stock"
    r = m.probe_service(s); assert r["status"] == "down" and "was not found" in r["error"]
    s.keyword, s.keyword_mode = "Welcome", "absent"
    r = m.probe_service(s); assert r["status"] == "down" and "must not" in r["error"]


def test_dns_change_detection_and_accept(client, monkeypatch):
    sign_in(client)
    answers = {"A": ["203.0.113.10"], "MX": ["10 mail.example.com"]}
    monkeypatch.setattr(dnsmon, "lookup", lambda domain, types: ({k: v for k, v in answers.items() if k in types}, None, False))
    monkeypatch.setattr(dnsmon, "rdap", lambda domain: {"name": "example.com", "expires_at": __import__("datetime").datetime(2030, 1, 1, tzinfo=__import__("datetime").timezone.utc), "registrar": "Example Registrar"})
    from app import monitoring
    sent = []
    monkeypatch.setattr(monitoring, "queue_event", lambda s, kind, target, sev, msg, deliver, state=None: sent.append((state, msg)))
    m = client.post("/api/dns", headers=CSRF, json={"name": "Main domain", "domain": "Example.COM.", "record_types": ["A", "MX"]}).json()
    assert m["domain"] == "example.com" and m["last_status"] == "up" and m["baseline"] == answers and m["registrar"] == "Example Registrar"
    answers["A"] = ["198.51.100.99"]
    m = client.post(f"/api/dns/{m['id']}/check", headers=CSRF).json()
    assert m["last_status"] == "alert" and m["changes"] == ["A added: 198.51.100.99", "A removed: 203.0.113.10"] and sent[-1][0] == "alert"
    m = client.post(f"/api/dns/{m['id']}/accept", headers=CSRF).json()
    assert m["last_status"] == "up" and m["baseline"]["A"] == ["198.51.100.99"] and sent[-1][0] == "recovered"
    assert client.post("/api/dns", headers=CSRF, json={"name": "x", "domain": "https://bad/path"}).status_code == 422


def test_real_dns_lookup():
    records, error, missing = dnsmon.lookup("example.com", ["A", "NS"])
    if error and not records:
        pytest.skip("no DNS available")
    assert records.get("A") and records.get("NS") and not missing
    assert dnsmon.lookup("no-such-name-sm-watch.invalid", ["A"])[2] is True
