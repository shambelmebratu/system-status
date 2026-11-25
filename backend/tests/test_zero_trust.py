"""Zero trust: every server verified with reasons, every identity known, every change reviewed or shown as unreviewed, and alerts for
sign-ins, changes in SM-Watch, agent identity and anything that could hide an attack (which cannot be turned off)."""
import json
from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient

from test_api_auth import CSRF, client, main, make_user, session_for, sign_in  # noqa: F401
from app import database, secalerts, zerotrust
from app.models import AlertEvent, AuditEvent, SecurityFinding, Server, SshLoginEvent


def _alerts(state):
    with database.SessionLocal() as db:
        return [e.message for e in db.query(AlertEvent).filter(AlertEvent.state == state).order_by(AlertEvent.id)]


def _enroll(client, name):
    tok = client.post("/api/enrollments", headers=CSRF, json={}).json()["token"]
    r = TestClient(main.app).post("/api/agent/enroll", headers={"Authorization": f"Bearer {tok}"}, json={"hostname": name, "machine_id": f"zt-{name}"}).json()
    return r["server_id"], {"Authorization": f"Bearer {r['agent_token']}"}


def test_sign_in_from_a_new_address_and_failed_bursts_alert():
    with database.SessionLocal() as db:
        db.add(AuditEvent(actor="ops@zt.example", action="auth.login", ip="198.51.100.1", success=True))
        db.commit()
        zerotrust.on_audit(db, action="auth.login", actor="ops@zt.example", target="", detail=None, ip="198.51.100.1", success=True)   # known address
        zerotrust.on_audit(db, action="auth.login", actor="ops@zt.example", target="", detail=None, ip="203.0.113.77", success=True)   # new address
        db.commit()
        for n in range(7):                                       # one burst: one alert, not seven
            db.add(AuditEvent(actor="victim@zt.example", action="auth.login", ip="203.0.113.9", success=False))
            zerotrust.on_audit(db, action="auth.login", actor="victim@zt.example", target="", detail="wrong password", ip="203.0.113.9", success=False)
            db.commit()
    msgs = _alerts("zt_signin")
    assert sum("ops@zt.example signed in from a new address: 203.0.113.77" in m for m in msgs) == 1
    assert not any("198.51.100.1" in m and "new address" in m for m in msgs)
    assert sum("Failed sign-ins: victim@zt.example" in m for m in msgs) == 1


def test_protection_changes_always_alert_even_with_alerts_off(client):
    sign_in(client)
    cur = client.get("/api/security/alerts").json()
    assert {k["id"]: k["locked"] for k in cur["kinds"]}["guard"] is True
    body = {k: cur[k] for k in ("channels", "threat_severity", "ssh_attack_threshold", "ssh_success_after_failures", "daily_login_alert")}
    r = client.put("/api/security/alerts", headers=CSRF, json={**body, "enabled": False, "categories": {"guard": False, "admin": False}})
    assert r.status_code == 200 and r.json()["categories"]["guard"] is True          # cannot be turned off
    try:
        assert any("Security alert settings changed" in m and "admin@example.com" in m for m in _alerts("zt_guard"))
        with database.SessionLocal() as db:
            assert secalerts.blocked(db, "zt_guard", "system") is None                 # still delivered
            assert secalerts.blocked(db, "zt_admin", "system") is not None              # everything else respects the switch
    finally:
        client.put("/api/security/alerts", headers=CSRF, json={**body, "enabled": True, "categories": {"admin": True}})


def test_changes_in_smwatch_alert_with_who_and_from_where(client):
    sign_in(client)
    make_user(client, "zt-new@example.com", "viewer")
    assert any("User added" in m and "admin@example.com" in m for m in _alerts("zt_admin"))


def test_trust_verifies_each_server_and_lists_identities_and_reviews(client):
    sign_in(client)
    sid, auth = _enroll(client, "zt-box")
    anon = TestClient(main.app)
    assert anon.post("/api/agent/report", headers=auth, json={"cpu": 1, "memory": 1, "disk": 1, "load": 0, "swap": 0, "agent_version": "2.18.1", "capabilities": ["process"]}).status_code == 200
    ping = client.post("/api/servers", headers=CSRF, json={"name": "zt-ping", "host": "192.0.2.10", "monitor_mode": "ping"}).json()["id"]
    now = datetime.now(timezone.utc)
    with database.SessionLocal() as db:
        db.add(SecurityFinding(server_id=sid, key="user_added:mallory", kind="user_added", severity="critical", title="New account that can log in: mallory", detail="x",
                               evidence="{}", source="smwatch", first_seen=now, last_seen=now))
        db.add(SshLoginEvent(server_id=sid, ts=now - timedelta(minutes=5), ip="203.0.113.50", user="root", method="publickey", kind="login", new_source=True, failures_before=0, key_name="laptop"))
        db.commit()
    t = client.get("/api/security/trust").json()
    dev = {d["server"]["id"]: d for d in t["devices"]}
    assert dev[ping]["status"] == "unverified"
    box = dev[sid]
    checks = {c["id"]: c for c in box["checks"]}
    assert checks["reporting"]["ok"] is True and checks["changes"]["ok"] is False and "mallory" in checks["changes"]["detail"]
    assert box["status"] == "untrusted"                                                # an unreviewed critical change
    assert any(f["title"].startswith("New account that can log in") for f in t["review"])
    assert any(u["email"] == "admin@example.com" and "mfa" in u for u in t["identities"]["users"])
    ssh = [g for g in t["identities"]["ssh"] if g["server"]["id"] == sid]
    assert ssh and ssh[0]["user"] == "root" and ssh[0]["new_sources"] == ["203.0.113.50"] and ssh[0]["keys"] == ["laptop"]
    assert t["summary"]["devices"]["untrusted"] >= 2 and t["summary"]["unreviewed"] >= 1


def test_activity_shows_logins_sign_ins_and_changes_by_category(client):
    sign_in(client)
    sid, _ = _enroll(client, "zt-act")
    with database.SessionLocal() as db:
        db.add(SshLoginEvent(server_id=sid, ts=datetime.now(timezone.utc), ip="198.51.100.20", user="deploy", method="publickey", kind="login", new_source=False, failures_before=0))
        db.commit()
    access = client.get("/api/security/activity?category=access").json()
    assert any(r["type"] == "login" and r["actor"] == "deploy" and r["ip"] == "198.51.100.20" for r in access)
    assert any(r["type"] == "action" and r["kind"] == "auth.login" for r in access)              # sign-ins to SM-Watch
    assert all(r["category"] == "access" for r in access)
    agents = client.get("/api/security/activity?category=agents").json()
    assert any(r["kind"] == "agent.enroll" for r in agents)
    make_user(client, "zt-op@example.com", "operator")
    op = session_for("zt-op@example.com", new_password="zt-operator-pass-1")
    assert not any(r.get("target", {}) and r.get("target", {}).get("type") == "system" for r in op.get("/api/security/activity").json())   # admins only


def test_report_includes_zero_trust_and_what_happened_in_smwatch(client):
    sign_in(client)
    r = client.get("/api/security/report?days=7").json()
    assert {"summary", "devices", "identities", "review"} <= set(r["zero_trust"])
    assert r["smwatch"]["sign_ins"] >= 1 and isinstance(r["smwatch"]["changes"], list)
