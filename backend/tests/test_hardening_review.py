"""Security review before production: each test is an attack that must fail."""
import os
import sys
import time

os.environ.setdefault("ENVIRONMENT", "test"); os.environ.setdefault("JWT_SECRET", "x" * 40); os.environ.setdefault("DATABASE_URL", "sqlite://")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from fastapi.testclient import TestClient

from test_api_auth import CSRF, client, fresh_stats_cache, main, make_user, session_for, sign_in  # noqa: F401
from app import mfa


def test_mfa_ticket_is_not_a_session(client):
    """The ticket handed out after the password step must not work as a session (that would skip the second factor)."""
    sign_in(client)
    make_user(client, "mfa-bypass@example.com", "admin")
    u = session_for("mfa-bypass@example.com", new_password="mfa-bypass-pass-123")
    secret = u.post("/api/auth/2fa/setup", headers=CSRF).json()["secret"]
    u.post("/api/auth/2fa/enable", headers=CSRF, json={"code": mfa._code(secret, int(time.time()) // 30)})
    attacker = TestClient(main.app)                                          # knows the password, not the authenticator
    ticket = attacker.post("/api/auth/login", json={"email": "mfa-bypass@example.com", "password": "mfa-bypass-pass-123"}).json()["mfa_token"]
    bearer = {"Authorization": f"Bearer {ticket}"}
    assert attacker.get("/api/dashboard", headers=bearer).status_code == 401
    assert attacker.get("/api/users", headers=bearer).status_code == 401
    attacker.cookies.set("smwatch_session", ticket, path="/api")
    assert attacker.get("/api/auth/me").status_code == 401


def _routes():
    """Every API route, including those in included routers."""
    def walk(routes, prefix=""):
        for r in routes:
            if type(r).__name__ == "_IncludedRouter":
                yield from walk((getattr(r, "router", None) or r.original_router).routes, prefix + (getattr(r, "prefix", "") or ""))
            elif hasattr(r, "dependant"):
                yield prefix + r.path, r
    return list(walk(main.app.routes))


def test_people_limited_to_monitors_cannot_reach_others(client):
    """Sweep: every route with a server / service / cluster id, asked by someone limited to A about B, must refuse."""
    import re
    from app import database
    from app.models import Cluster, Server, Service
    sign_in(client)
    with database.SessionLocal() as db:
        a = Server(name="scope-a", host="203.0.113.71", monitor_mode="push"); b = Server(name="scope-b", host="203.0.113.72", monitor_mode="push")
        sa = Service(name="scope-sa", url="https://a.example.com"); sb = Service(name="scope-sb", url="https://b.example.com")
        ca = Cluster(name="scope-ca", enabled=True); cb = Cluster(name="scope-cb", enabled=True)
        db.add_all([a, b, sa, sb, ca, cb]); db.commit()
        ids = dict(a=a.id, b=b.id, sa=sa.id, sb=sb.id, ca=ca.id, cb=cb.id)
    r = client.post("/api/users", headers=CSRF, json={"email": "scope-sweep@example.com", "role": "operator", "password": "scope-sweep-pass-1",
                                                       "access": {"servers": [ids["a"]], "services": [ids["sa"]], "clusters": [ids["ca"]]}})
    assert r.status_code == 200, r.text
    u = session_for("scope-sweep@example.com", password="scope-sweep-pass-1", new_password="scope-sweep-pass-2")
    checked, answered = 0, []
    for path, route in _routes():
        if "agent" in path or not re.search(r"\{(server_id|item_id|target_id|cluster_id|kind|target_type)\}", path):
            continue
        if "{kind}" in path or "{target_type}" in path:
            urls = [path.replace("{kind}", k).replace("{target_type}", k).replace("{item_id}", str(ids[x])).replace("{target_id}", str(ids[x]))
                    for k, x in (("servers", "b"), ("services", "sb"), ("server", "b"), ("service", "sb"), ("cluster", "cb"), ("clusters", "cb"))]
        elif "cluster" in path:
            urls = [re.sub(r"\{(cluster_id|item_id)\}", str(ids["cb"]), path)]
        elif "service" in path:
            urls = [re.sub(r"\{(item_id|target_id)\}", str(ids["sb"]), path)]
        else:
            urls = [re.sub(r"\{(server_id|item_id|target_id)\}", str(ids["b"]), path)]
        for url in urls:
            url = re.sub(r"\{[a-z_]+\}", "1", url)
            for method in sorted(route.methods - {"HEAD"}):
                if method != "GET":
                    continue                                    # writes are covered in test_access_limited_to_selected_monitors
                checked += 1
                resp = u.get(url)
                if resp.status_code < 400:
                    answered.append((url, resp.status_code))
    assert checked > 20 and answered == [], answered


def test_secret_urls_are_masked_in_the_access_log():
    import logging
    f = [x for x in logging.getLogger("uvicorn.access").filters if type(x).__name__ == "_RedactSecretPaths"][0]
    rec = logging.LogRecord("uvicorn.access", logging.INFO, "", 0, '%s - "%s %s HTTP/%s" %d', ("10.0.0.1:5", "GET", "/api/agent/join/smwj_SECRETVALUE/docker", "1.1", 200), None)
    f.filter(rec)
    assert "SECRETVALUE" not in rec.getMessage() and "/api/agent/join/[token]/docker" in rec.getMessage()
    for path in ("/api/ping/hb_SECRET123", "/api/agent/k8s/smwj_SECRET?name=prod"):
        rec = logging.LogRecord("uvicorn.access", logging.INFO, "", 0, '%s %s', ("GET", path), None)
        f.filter(rec)
        assert "SECRET" not in rec.getMessage()


def test_unreadable_token_file_never_locks_out_the_bundled_agent(tmp_path, monkeypatch):
    """The token is written to the shared file BEFORE it is stored: if the file cannot be written, the old token stays valid."""
    from app import database
    from app.main import HOST_AGENT_ID, ensure_host_agent, settings
    from app.models import Server
    from app.routes_agent import hash_token
    path = tmp_path / "agent.token"
    monkeypatch.setattr(settings, "host_agent_token_file", str(path))
    with database.SessionLocal() as db:
        ensure_host_agent(db)
    first = path.read_text()
    with database.SessionLocal() as db:
        assert db.query(Server).filter_by(machine_id=HOST_AGENT_ID).one().token_hash == hash_token(first)
    path.write_text("stale-token-the-agent-does-not-have")    # forces a renewal ...
    os.chmod(path, 0o400)                                     # ... into a file that cannot be written
    with database.SessionLocal() as db:
        ensure_host_agent(db)
    with database.SessionLocal() as db:
        assert db.query(Server).filter_by(machine_id=HOST_AGENT_ID).one().token_hash == hash_token(first)   # unchanged: nothing locked out
