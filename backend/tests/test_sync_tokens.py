"""Sync now (live measurement over the agent's task channel), unique agent tokens, and what viewers may read."""
import json
import os
import sys

os.environ.setdefault("ENVIRONMENT", "test"); os.environ.setdefault("JWT_SECRET", "x" * 40); os.environ.setdefault("DATABASE_URL", "sqlite://")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from fastapi.testclient import TestClient

from test_api_auth import CSRF, client, fresh_stats_cache, main, make_user, report, session_for, sign_in  # noqa: F401
from app import database
from app.models import Server

SNAP = {"cpu": 91.5, "memory": 41.0, "disk": 50.0, "load": 3.9, "swap": 0.0, "cpu_count": 4, "uptime_seconds": 1000, "sample_seconds": 1.0,
        "cpu_breakdown": {"user": 4.0, "nice": 0.0, "system": 3.0, "idle": 8.5, "iowait": 0.0, "irq": 0.0, "softirq": 1.5, "steal": 83.0},
        "process_cpu_total": 7.1, "process_count": 212, "forks_per_sec": 0.4, "procs_running": 2, "procs_blocked": 0,
        "processes": [{"pid": 10, "name": "nginx", "user": "www", "cpu": 12.0, "memory": 1.0}]}


def _push_server(client, name, caps=("logs", "sync")):
    created = client.post("/api/servers", headers=CSRF, json={"name": name, "monitor_mode": "push", "check_interval_seconds": 30}).json()
    token = created["install_token"]
    agent = TestClient(main.app)
    agent.headers["Authorization"] = f"Bearer {token}"
    assert agent.post("/api/agent/report", json=report(capabilities=list(caps))).status_code == 200
    return created["id"], token, agent


def test_sync_now_measures_live_and_replaces_latest_metrics(client):
    sign_in(client)
    sid, _, agent = _push_server(client, "sync-box")
    r = client.post(f"/api/servers/{sid}/sync", headers=CSRF)
    assert r.status_code == 200
    rid = r.json()["id"]
    assert client.post(f"/api/servers/{sid}/sync", headers=CSRF).json()["id"] == rid             # pressed twice: one measurement
    tasks = agent.get("/api/agent/tasks").json()["tasks"]
    assert tasks == [{"id": rid, "source": "snapshot", "target": "", "lines": 1, "seconds": 1}]
    assert agent.post(f"/api/agent/tasks/{rid}/result", json={"ok": True, "output": json.dumps(SNAP)}).status_code == 200
    done = client.get(f"/api/servers/{sid}/logs/{rid}").json()
    assert done["status"] == "done" and json.loads(done["output"])["cpu"] == 91.5
    m = next(s for s in client.get("/api/dashboard").json()["servers"] if s["id"] == sid)["last_metrics"]
    assert m["cpu"] == 91.5 and m["cpu_breakdown"]["steal"] == 83.0 and m["process_cpu_total"] == 7.1 and m["synced_at"] and m["cpu_peak"] is None
    assert m["processes"][0]["name"] == "nginx" and m["hostname"] == "box"                              # the rest of the last report is kept
    # a viewer may press the button and read the measurement, but not logs
    make_user(client, "sync-viewer@example.com", "viewer")
    v = session_for("sync-viewer@example.com", new_password="sync-viewer-pass-1")
    assert v.get(f"/api/servers/{sid}/logs/{rid}").status_code == 200
    log_id = client.post(f"/api/servers/{sid}/logs", headers=CSRF, json={"source": "inventory"}).json()["id"]
    assert v.get(f"/api/servers/{sid}/logs/{log_id}").status_code == 403


def test_sync_rejects_bad_answers_and_old_agents(client):
    sign_in(client)
    sid, _, agent = _push_server(client, "sync-bad")
    rid = client.post(f"/api/servers/{sid}/sync", headers=CSRF).json()["id"]
    agent.get("/api/agent/tasks")
    agent.post(f"/api/agent/tasks/{rid}/result", json={"ok": True, "output": json.dumps({**SNAP, "cpu": 900})})
    assert client.get(f"/api/servers/{sid}/logs/{rid}").json()["status"] == "error"
    old, _, _ = _push_server(client, "sync-old", caps=("logs",))
    r = client.post(f"/api/servers/{old}/sync", headers=CSRF)
    assert r.status_code == 422 and "2.16" in r.json()["detail"]


def test_every_agent_token_is_unique(client):
    sign_in(client)
    shared = "s" * 40
    a = client.post("/api/servers", headers=CSRF, json={"name": "tok-a", "monitor_mode": "push", "agent_token": shared})
    assert a.status_code == 200
    b = client.post("/api/servers", headers=CSRF, json={"name": "tok-b", "monitor_mode": "push", "agent_token": shared})
    assert b.status_code == 409 and "tok-a" in b.json()["detail"] and "own token" in b.json()["detail"]
    pull = client.post("/api/servers", headers=CSRF, json={"name": "tok-c", "monitor_mode": "agent", "host": "10.0.0.9", "endpoint": "http://10.0.0.9:9100", "agent_token": shared})
    assert pull.status_code == 409
    other = client.post("/api/servers", headers=CSRF, json={"name": "tok-d", "monitor_mode": "push"}).json()
    r = client.put(f"/api/servers/{other['id']}", headers=CSRF, json={"name": "tok-d", "monitor_mode": "push", "agent_token": shared})
    assert r.status_code == 409
    keep = client.put(f"/api/servers/{a.json()['id']}", headers=CSRF, json={"name": "tok-a2", "monitor_mode": "push"})   # editing keeps its own token
    assert keep.status_code == 200


def test_a_token_found_on_two_servers_is_refused_not_guessed(client):
    sign_in(client)
    sid, token, agent = _push_server(client, "dup-1")
    from app.routes_agent import hash_token
    with database.SessionLocal() as db:   # what an old database could contain: one hand-typed token on two servers
        twin = Server(name="dup-2", host="", monitor_mode="push", check_interval_seconds=30, agent_token=token, token_hash=hash_token(token))
        db.add(twin); db.commit()
    r = agent.post("/api/agent/report", json=report())
    assert r.status_code == 409 and "dup-1" in r.json()["detail"] and "dup-2" in r.json()["detail"]
    assert agent.get("/api/agent/tasks").status_code == 409
    assert any(e["action"] == "agent.token_shared" for e in client.get("/api/audit?category=agent").json())


def test_viewers_do_not_get_security_details_from_the_dashboard(client):
    sign_in(client)
    sid, _, agent = _push_server(client, "leak-box")
    security = {"checked_at": "2026-11-18T10:00:00Z", "findings": [], "hardening": [], "listening": [], "authorized_keys": [{"user": "root", "fingerprint": "SHA256:abc", "type": "ssh-ed25519", "comment": "laptop", "file": "/root/.ssh/authorized_keys"}]}
    updates = {"manager": "apt", "total": 1, "security": 1, "packages": [{"name": "openssl", "version": "3.0.1", "security": True}], "reboot_required": False}
    import time; time.sleep(1.1)
    r = agent.post("/api/agent/report", json=report(security=security, updates=updates))
    assert r.status_code == 200, r.text
    admin_view = next(s for s in client.get("/api/dashboard").json()["servers"] if s["id"] == sid)["last_metrics"]
    assert "security" not in admin_view and admin_view["updates"]["packages"]
    make_user(client, "leak-viewer@example.com", "viewer")
    v = session_for("leak-viewer@example.com", new_password="leak-viewer-pass-1")
    view = next(s for s in v.get("/api/dashboard").json()["servers"] if s["id"] == sid)["last_metrics"]
    assert "security" not in view and "packages" not in view["updates"] and view["updates"]["security"] == 1 and "SHA256:abc" not in json.dumps(view)
