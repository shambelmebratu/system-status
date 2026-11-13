import json
from datetime import datetime, timezone
import os

os.environ.update(ENVIRONMENT="test", JWT_SECRET="x" * 40, ADMIN_PASSWORD="correct-horse-battery", DATABASE_URL="sqlite://", AGENT_MIN_REPORT_SECONDS="0")

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.pool import StaticPool
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app import database

# Single shared in-memory DB for the whole process.
engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
database.engine = engine
database.SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)

from app import main  # noqa: E402

main.engine = engine
main.get_db.__globals__["SessionLocal"] = database.SessionLocal
database.Base.metadata.create_all(engine)

CSRF = {"X-Requested-With": "smwatch"}


@pytest.fixture()
def client():
    from app.security import login_limiter
    login_limiter._hits.clear()
    with TestClient(main.app) as c:
        yield c


def sign_in(client):
    r = client.post("/api/auth/login", json={"email": "admin@example.com", "password": "correct-horse-battery"})
    assert r.status_code == 200
    assert "token" not in r.json()
    assert "httponly" in r.headers["set-cookie"].lower() and "samesite=strict" in r.headers["set-cookie"].lower()


def test_requires_auth(client):
    assert client.get("/api/dashboard").status_code == 401


def test_cookie_session_csrf_and_logout(client):
    sign_in(client)
    assert client.get("/api/auth/me").json()["email"] == "admin@example.com"
    assert client.post("/api/servers", json={}).status_code == 403  # no CSRF header
    stale = client.cookies.get("smwatch_session")
    assert client.post("/api/auth/logout", headers=CSRF).status_code == 200
    client.cookies.set("smwatch_session", stale, path="/api")
    assert client.get("/api/auth/me").status_code == 401  # revoked


def test_ssrf_rejected(client):
    sign_in(client)
    r = client.post("/api/services", headers=CSRF, json={"name": "x", "url": "http://169.254.169.254/latest"})
    assert r.status_code == 422
    r = client.post("/api/servers", headers=CSRF, json={"name": "x", "host": "-f", "monitor_mode": "ping"})
    assert r.status_code == 422


def test_login_rate_limit(client):
    for _ in range(5):
        assert client.post("/api/auth/login", json={"email": "admin@example.com", "password": "bad"}).status_code == 401
    assert client.post("/api/auth/login", json={"email": "admin@example.com", "password": "correct-horse-battery"}).status_code == 429


# ---------------------------------------------------------------- push agents, history, incidents, status page
from app.models import Incident, Server  # noqa: E402


def report(cpu=10.0, **extra):
    body = {"cpu": cpu, "memory": 40, "disk": 50, "load": 0.5, "swap": 0, "hostname": "box", "net_rx_bps": 1200.0, "net_tx_bps": 300.0,
            "processes": [{"pid": 1, "name": "init", "cpu": 1.0, "memory": 0.1}]}
    body.update(extra)
    return body


def test_push_agent_lifecycle(client):
    sign_in(client)
    created = client.post("/api/servers", headers=CSRF, json={"name": "edge-1", "monitor_mode": "push", "check_interval_seconds": 30}).json()
    token = created["install_token"]
    assert len(token) >= 32 and created["agent_token"] == "configured" and "token_hash" not in created
    sid = created["id"]

    anon = TestClient(main.app)
    assert anon.post("/api/agent/report", json=report()).status_code == 401
    assert anon.post("/api/agent/report", json=report(), headers={"Authorization": "Bearer nope"}).status_code == 401
    auth = {"Authorization": f"Bearer {token}"}
    assert anon.post("/api/agent/report", json=report(cpu=500), headers=auth).status_code == 422  # validated
    ok = anon.post("/api/agent/report", json=report(), headers=auth)
    assert ok.status_code == 200 and ok.json()["interval_seconds"] == 30 and ok.json()["status"] == "up"

    # threshold breach -> alert status + open incident; queued (not delivered inline)
    assert anon.post("/api/agent/report", json=report(cpu=99), headers=auth).json()["status"] == "alert"
    incidents = client.get("/api/incidents?state=open").json()
    assert [i["target_name"] for i in incidents] == ["edge-1"] and incidents[0]["severity"] == "warning"
    # recovery resolves it
    anon.post("/api/agent/report", json=report(cpu=5), headers=auth)
    assert client.get("/api/incidents?state=open").json() == []
    assert client.get("/api/incidents?state=resolved").json()[0]["resolved_at"]

    history = client.get(f"/api/servers/{sid}/history?range=1h").json()
    assert history["samples"] == 3 and history["points"] and history["uptime_pct"] == 100.0
    dash = client.get("/api/dashboard").json()
    srv = next(s for s in dash["servers"] if s["id"] == sid)
    assert srv["last_status"] == "up" and srv["last_metrics"]["hostname"] == "box" and srv["uptime_24h"] == 100.0

    # rotating invalidates the old token
    new = client.post(f"/api/servers/{sid}/rotate-token?immediate=true", headers=CSRF).json()["install_token"]
    assert anon.post("/api/agent/report", json=report(), headers=auth).status_code == 401
    assert anon.post("/api/agent/report", json=report(), headers={"Authorization": f"Bearer {new}"}).status_code == 200


def test_heartbeat_timeout_marks_down(client):
    from datetime import datetime, timedelta, timezone
    from app import monitoring
    from app.models import Server

    monitoring.SessionLocal = database.SessionLocal
    sign_in(client)
    created = client.post("/api/servers", headers=CSRF, json={"name": "silent", "monitor_mode": "push", "check_interval_seconds": 30}).json()
    with database.SessionLocal() as db:
        s = db.get(Server, created["id"])
        s.last_seen_at = s.last_checked_at = datetime.now(timezone.utc) - timedelta(minutes=10)
        s.last_status = "up"
        db.commit()
    monitoring.deliver_event = lambda event, session: None  # no notification channels in tests
    monitoring.run_once()
    srv = next(s for s in client.get("/api/dashboard").json()["servers"] if s["id"] == created["id"])
    assert srv["last_status"] == "down" and "heartbeat" in srv["last_error"]
    assert any(i["target_name"] == "silent" and i["severity"] == "critical" for i in client.get("/api/incidents?state=open").json())


def test_public_status_and_install_assets(client):
    from app import monitoring
    from app.models import Service
    sign_in(client)
    a = client.post("/api/services", headers=CSRF, json={"name": "Website", "url": "https://example.com", "public": True}).json()
    client.post("/api/services", headers=CSRF, json={"name": "Internal", "url": "https://example.org"})
    with database.SessionLocal() as db:
        svc = db.get(Service, a["id"])
        monitoring.deliver_event = lambda event, session: None
        monitoring.apply_service_result(db, svc, {"status": "up", "http_status": 200, "latency_ms": 42.0, "error": None})
    page = TestClient(main.app).get("/api/public/status").json()
    assert [s["name"] for s in page["services"]] == ["Website"]          # private service hidden
    assert page["overall"] == "up" and len(page["services"][0]["daily"]) == 90 and "url" not in page["services"][0]
    assert page["services"][0]["daily"][-1]["pct"] == 100.0
    hist = client.get(f"/api/services/{a['id']}/history?range=24h").json()
    assert hist["checks"] == 1 and hist["latency_avg"] == 42.0
    anon = TestClient(main.app)
    assert anon.get("/api/agent/install.sh").text.startswith("#!/usr/bin/env bash")
    assert "def push_loop" in anon.get("/api/agent/agent.py").text


def test_change_password_revokes_other_sessions(client):
    sign_in(client)
    stale = client.cookies.get("smwatch_session")
    assert client.post("/api/auth/password", headers=CSRF, json={"current_password": "wrong", "new_password": "another-long-password"}).status_code == 403
    assert client.post("/api/auth/password", headers=CSRF, json={"current_password": "correct-horse-battery", "new_password": "another-long-password"}).status_code == 200
    assert client.get("/api/auth/me").status_code == 200  # fresh cookie issued
    other = TestClient(main.app)
    other.cookies.set("smwatch_session", stale, path="/api")
    assert other.get("/api/auth/me").status_code == 401
    assert client.post("/api/auth/password", headers=CSRF, json={"current_password": "another-long-password", "new_password": "correct-horse-battery"}).status_code == 200


# ---------------------------------------------------------------- regressions: ping-only crash, debounce, reminders, telegram
def _setup_monitoring():
    from app import monitoring
    monitoring.SessionLocal = database.SessionLocal
    monitoring.deliver_event = lambda event, session: None
    return monitoring


def test_ping_only_success_does_not_crash_and_recovers(client):
    """Regression: ping results carry no cpu/memory; recording them used to raise KeyError and leave the server 'down'."""
    from app.models import Server
    monitoring = _setup_monitoring()
    sign_in(client)
    created = client.post("/api/servers", headers=CSRF, json={"name": "ping-box", "host": "93.184.216.34", "monitor_mode": "ping", "check_interval_seconds": 5}).json()
    with database.SessionLocal() as db:
        server = db.get(Server, created["id"]); server.last_status = "down"; db.commit()
        monitoring.apply_server_result(db, server, "up", [], {"hostname": "93.184.216.34", "reachability": "reachable", "latency_ms": 230.0})
        db.commit()
        assert server.last_status == "up"
    hist = client.get(f"/api/servers/{created['id']}/history?range=1h").json()
    assert hist["samples"] == 0 and hist["uptime_pct"] is not None  # no resource samples, but availability is recorded


def test_single_failure_is_debounced_and_reminders_throttled(client):
    from app.models import AlertEvent, Server
    monitoring = _setup_monitoring()
    sign_in(client)
    created = client.post("/api/servers", headers=CSRF, json={"name": "flaky", "host": "93.184.216.35", "monitor_mode": "ping"}).json()
    with database.SessionLocal() as db:
        server = db.get(Server, created["id"])
        monitoring.apply_server_result(db, server, "up", [], {"latency_ms": 10.0}); db.commit()
        monitoring.apply_server_result(db, server, "down", error="Ping failed"); db.commit()
        assert server.last_status == "up", "one dropped check must not flip the server to down"
        monitoring.apply_server_result(db, server, "up", [], {"latency_ms": 10.0}); db.commit()
        assert server.fail_count == 0
        monitoring.apply_server_result(db, server, "down", error="Ping failed"); db.commit()
        monitoring.apply_server_result(db, server, "down", error="Ping failed"); db.commit()
        assert server.last_status == "down"
        for _ in range(5):  # still down: reminders throttled to one per window
            monitoring.apply_server_result(db, server, "down", error="Ping failed"); db.commit()
        events = db.query(AlertEvent).filter(AlertEvent.target_id == server.id, AlertEvent.severity == "critical").count()
        assert events == 1
        monitoring.apply_server_result(db, server, "up", [], {"latency_ms": 10.0}); db.commit()
        assert server.last_status == "up"


def test_stale_undelivered_alerts_expire(client):
    from datetime import datetime, timedelta, timezone
    from app.models import AlertEvent
    monitoring = _setup_monitoring()
    with database.SessionLocal() as db:
        old = AlertEvent(target_type="server", target_id=999, severity="info", message="old", created_at=datetime.now(timezone.utc) - timedelta(hours=5))
        db.add(old); db.commit()
        monitoring.retry_pending_alerts(db); db.commit()
        assert old.delivery_attempts == 10 and "expired" in old.delivery_error


def test_telegram_hint_and_discover(client, monkeypatch):
    from app import main, monitoring
    assert "Find chat ID" in monitoring.telegram_hint("Bad Request: chat not found")
    sign_in(client)
    monkeypatch.setattr(main, "discover_telegram_chats", lambda token: {"bot": "b", "chats": [{"id": -100, "type": "supergroup", "title": "Ops"}]})
    r = client.post("/api/channels/telegram/discover", headers=CSRF, json={"token": "1234567890:abcdefghijklmnopqrstuvwxyz"})
    assert r.status_code == 200 and r.json()["chats"][0]["title"] == "Ops"


def test_edit_channel_keeps_secrets_and_validates(client):
    from app.models import Channel
    sign_in(client)
    c = client.post("/api/channels", headers=CSRF, json={"name": "ops", "type": "telegram", "token": "1234567890:abcdefghijklmnopqrstuv", "chat_id": "-100111"}).json()
    r = client.put(f"/api/channels/{c['id']}", headers=CSRF, json={"name": "ops-renamed", "type": "telegram", "chat_id": "-100222", "enabled": False})
    assert r.status_code == 200 and r.json()["name"] == "ops-renamed" and r.json()["chat_id"] == "-100222" and r.json()["enabled"] is False and r.json()["token"] == "configured"
    with database.SessionLocal() as db:
        assert db.get(Channel, c["id"]).token == "1234567890:abcdefghijklmnopqrstuv"   # unchanged
    assert client.put(f"/api/channels/{c['id']}", headers=CSRF, json={"name": "x", "type": "telegram", "token": "short", "chat_id": "1"}).status_code == 422
    assert client.put(f"/api/channels/{c['id']}", headers=CSRF, json={"name": "x", "type": "slack", "endpoint": "https://hooks.slack.com/services/a/b/c"}).json()["type"] == "slack"
    assert client.put("/api/channels/9999", headers=CSRF, json={"name": "x"}).status_code == 404


def test_public_status_includes_public_servers(client):
    monitoring = _setup_monitoring()
    from app.models import Server
    sign_in(client)
    s = client.post("/api/servers", headers=CSRF, json={"name": "Dedicated", "host": "93.184.216.36", "monitor_mode": "ping", "public": True}).json()
    client.post("/api/servers", headers=CSRF, json={"name": "Hidden", "host": "93.184.216.37", "monitor_mode": "ping"})
    with database.SessionLocal() as db:
        monitoring.apply_server_result(db, db.get(Server, s["id"]), "up", [], {"latency_ms": 12.0}); db.commit()
    page = TestClient(main.app).get("/api/public/status").json()
    names = [i["name"] for i in page["services"]]
    assert "Dedicated" in names and "Hidden" not in names
    item = next(i for i in page["services"] if i["name"] == "Dedicated")
    assert item["kind"] == "server" and item["status"] == "up" and item["latency_ms"] == 12.0 and "host" not in item
    hist = client.get(f"/api/servers/{s['id']}/history?range=1h").json()
    assert hist["latency_avg"] == 12.0 and hist["latency_points"]


def test_availability_ranges(client):
    from datetime import datetime, timedelta, timezone
    from app.models import CheckResult
    from app.stats import AVAILABILITY_RANGES
    sign_in(client)
    svc = client.post("/api/services", headers=CSRF, json={"name": "bars", "url": "https://example.net"}).json()["id"]
    now = datetime.now(timezone.utc)
    with database.SessionLocal() as db:
        # 10 ok checks 40s..3s ago, 2 failures among them; plus one ok check 3 days ago and one 200 days ago
        for i, status in enumerate(["up"] * 8 + ["down", "down"]):
            db.add(CheckResult(target_type="service", target_id=svc, status=status, latency_ms=10.0, checked_at=now - timedelta(seconds=40 - i * 4)))
        db.add(CheckResult(target_type="service", target_id=svc, status="up", checked_at=now - timedelta(days=3)))
        db.add(CheckResult(target_type="service", target_id=svc, status="down", checked_at=now - timedelta(days=200)))
        db.commit()
    for rng, (window, bucket) in AVAILABILITY_RANGES.items():
        r = client.get(f"/api/services/{svc}/availability?range={rng}")
        assert r.status_code == 200, rng
        d = r.json()
        assert len(d["buckets"]) == window // bucket and d["bucket_seconds"] == bucket
    one_min = client.get(f"/api/services/{svc}/availability?range=1m").json()
    assert one_min["checks"] == 10 and one_min["uptime_pct"] == 80.0
    assert any(b["pct"] == 0.0 for b in one_min["buckets"])                       # failed buckets visible at 5s resolution
    day = client.get(f"/api/services/{svc}/availability?range=1mo").json()
    assert day["checks"] == 11 and day["buckets"][-1]["checks"] == 10 and day["buckets"][-4]["pct"] == 100.0   # 3 days ago
    year = client.get(f"/api/services/{svc}/availability?range=1y").json()
    assert year["checks"] == 12 and len(year["buckets"]) == 52
    assert client.get(f"/api/services/{svc}/availability?range=2h").status_code == 422
    assert client.get("/api/widgets/1/availability").status_code == 404


# ---------------------------------------------------------------- agent self-registration (join tokens)
def _enroll(anon, token, host="web-01", machine="machine-aaa"):
    return anon.post("/api/agent/enroll", json={"hostname": host, "machine_id": machine, "platform": "Linux", "agent_version": "2.2.0"}, headers={"Authorization": f"Bearer {token}"})


def test_join_token_lifecycle(client):
    sign_in(client)
    anon = TestClient(main.app)
    assert anon.post("/api/enrollments", json={}).status_code == 401          # admin only
    e = client.post("/api/enrollments", headers=CSRF, json={"label": "prod"}).json()
    token = e["token"]
    assert token.startswith("smwj_") and e["active"] and e["state"] == "active"
    # random + short-lived: 15 minutes by default, and every token is different
    from datetime import datetime, timezone
    remaining = (datetime.fromisoformat(e["expires_at"]) - datetime.now(timezone.utc)).total_seconds()
    assert 14 * 60 < remaining <= 15 * 60 and len(token) >= 37
    others = {client.post("/api/enrollments", headers=CSRF, json={}).json()["token"] for _ in range(5)}
    assert len(others) == 5 and token not in others
    assert client.post("/api/enrollments", headers=CSRF, json={"expires_minutes": 60 * 24 * 30}).status_code == 422   # no long-lived links

    # a bad/unknown token is rejected
    assert _enroll(anon, "smwj_wrong").status_code == 401

    # agent registers itself: a push server appears under its hostname with defaults
    r = _enroll(anon, token).json()
    assert r["name"] == "web-01" and len(r["agent_token"]) >= 32
    srv = next(s for s in client.get("/api/dashboard").json()["servers"] if s["id"] == r["server_id"])
    assert srv["monitor_mode"] == "push" and srv["last_status"] == "unknown" and srv["cpu_threshold"] == 85

    # ...and its own token works for reports (the join token does not)
    rep = report()
    assert anon.post("/api/agent/report", json=rep, headers={"Authorization": f"Bearer {r['agent_token']}"}).status_code == 200
    assert anon.post("/api/agent/report", json=rep, headers={"Authorization": f"Bearer {token}"}).status_code == 401

    # same machine re-installing -> same server, new token, no extra use consumed, old token dead
    again = _enroll(anon, token).json()
    assert again["server_id"] == r["server_id"] and again["agent_token"] != r["agent_token"]
    assert anon.post("/api/agent/report", json=rep, headers={"Authorization": f"Bearer {r['agent_token']}"}).status_code == 401
    # a different machine with the same hostname gets a distinct name
    other = _enroll(anon, token, host="web-01", machine="machine-bbb").json()
    assert other["name"] == "web-01-2" and other["server_id"] != r["server_id"]
    listing = client.get("/api/enrollments").json()
    assert next(i for i in listing if i["id"] == e["id"])["uses"] == 2

    # revoke: new agents blocked, already-joined servers keep working
    assert client.delete(f"/api/enrollments/{e['id']}", headers=CSRF).status_code == 200
    assert _enroll(anon, token, machine="machine-ccc").status_code == 401
    assert anon.post("/api/agent/report", json=rep, headers={"Authorization": f"Bearer {other['agent_token']}"}).status_code == 200


def test_join_token_limits_and_expiry(client):
    from datetime import datetime, timedelta, timezone
    from app.models import Enrollment
    sign_in(client)
    anon = TestClient(main.app)
    capped = client.post("/api/enrollments", headers=CSRF, json={"max_uses": 1}).json()
    assert _enroll(anon, capped["token"], host="a", machine="m1").status_code == 200
    assert _enroll(anon, capped["token"], host="b", machine="m2").status_code == 403    # used up
    assert _enroll(anon, capped["token"], host="a", machine="m1").status_code == 200    # same machine may re-register
    exp = client.post("/api/enrollments", headers=CSRF, json={"expires_minutes": 10}).json()
    with database.SessionLocal() as db:
        db.get(Enrollment, exp["id"]).expires_at = datetime.now(timezone.utc) - timedelta(minutes=1); db.commit()
    assert _enroll(anon, exp["token"], host="c", machine="m3").status_code == 401
    assert next(i for i in client.get("/api/enrollments").json() if i["id"] == exp["id"])["state"] == "expired"


def test_join_scripts_are_personalised(client, monkeypatch):
    sign_in(client)
    anon = TestClient(main.app)
    token = client.post("/api/enrollments", headers=CSRF, json={}).json()["token"]
    sh = anon.get(f"/api/agent/join/{token}", headers={"host": "monitor.example.com", "x-forwarded-proto": "https"}).text
    assert sh.startswith("#!/usr/bin/env bash") and f"SMWATCH_JOIN='{token}'" in sh and "SMWATCH_URL='https://monitor.example.com'" in sh
    assert sh.count("#!/usr/bin/env bash") == 1 and "systemctl" in sh
    dk = anon.get(f"/api/agent/join/{token}/docker", headers={"host": "monitor.example.com"}).text
    assert "docker run" in dk and "SMWATCH_JOIN=" in dk
    bad = anon.get("/api/agent/join/smwj_bogus").text
    assert "invalid, expired or revoked" in bad and bad.rstrip().endswith("exit 1")
    from app.config import get_settings
    monkeypatch.setattr(get_settings(), "public_url", "https://pub.example.org/")
    assert "SMWATCH_URL='https://pub.example.org'" in anon.get(f"/api/agent/join/{token}", headers={"host": "internal:8000"}).text


# ---------------------------------------------------------------- scheduled messages
def _mk_channel(client, name="Team chat"):
    return client.post("/api/channels", headers=CSRF, json={"name": name, "type": "webhook", "endpoint": "https://chat.example.net/hooks/abc"}).json()["id"]


def test_next_run_calculation_timezones():
    from datetime import datetime, timezone
    from app.models import ScheduledMessage
    from app.scheduler import compute_next_run

    def sm(**kw):
        return ScheduledMessage(name="x", text="t", channel_ids="[1]", **kw)
    # Addis Ababa is UTC+3 all year: 08:58 local weekday stand-up
    daily = sm(repeat="daily", time_of_day="08:58", days_of_week="", timezone="Africa/Addis_Ababa")
    after = datetime(2026, 11, 12, 5, 0, tzinfo=timezone.utc)            # Thu 08:00 local -> same day 08:58 local = 05:58 UTC
    assert compute_next_run(daily, after) == datetime(2026, 11, 12, 5, 58, tzinfo=timezone.utc)
    after = datetime(2026, 11, 12, 6, 0, tzinfo=timezone.utc)            # already past today's run -> tomorrow
    assert compute_next_run(daily, after) == datetime(2026, 11, 13, 5, 58, tzinfo=timezone.utc)
    weekdays = sm(repeat="weekly", time_of_day="08:58", days_of_week="1,2,3,4,5", timezone="Africa/Addis_Ababa")
    fri_late = datetime(2026, 11, 13, 6, 0, tzinfo=timezone.utc)         # Friday after the run -> next Monday
    assert compute_next_run(weekdays, fri_late) == datetime(2026, 11, 16, 5, 58, tzinfo=timezone.utc)
    # DST: New York is UTC-5 in November, UTC-4 in July
    ny = sm(repeat="daily", time_of_day="09:00", days_of_week="", timezone="America/New_York")
    assert compute_next_run(ny, datetime(2026, 11, 12, 0, 0, tzinfo=timezone.utc)).hour == 14
    assert compute_next_run(ny, datetime(2026, 7, 12, 0, 0, tzinfo=timezone.utc)).hour == 13
    once = sm(repeat="once", run_at=datetime(2026, 12, 1, 9, 0, tzinfo=timezone.utc), timezone="UTC", time_of_day="09:00", days_of_week="")
    assert compute_next_run(once, datetime(2026, 11, 1, tzinfo=timezone.utc)) == once.run_at
    assert compute_next_run(once, datetime(2026, 12, 2, tzinfo=timezone.utc)) is None


def test_scheduled_message_crud_and_validation(client):
    from datetime import datetime, timedelta, timezone
    sign_in(client)
    ch = _mk_channel(client)
    body = {"name": "Stand-up", "text": "Good morning {weekday}! Meet: https://meet.example/x", "channel_ids": [ch], "repeat": "weekly",
            "time_of_day": "08:58", "days_of_week": [1, 2, 3, 4, 5], "timezone": "Africa/Addis_Ababa"}
    r = client.post("/api/scheduled-messages", headers=CSRF, json=body)
    assert r.status_code == 200, r.text
    d = r.json()
    assert d["next_run_at"] and d["enabled"] and "Good morning" in d["preview"] and "{weekday}" not in d["preview"]
    for bad, code in [({"timezone": "Mars/Base"}, 422), ({"channel_ids": [9999]}, 422), ({"time_of_day": "25:00"}, 422), ({"repeat": "weekly", "days_of_week": []}, 422),
                      ({"repeat": "once", "run_at": (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()}, 422), ({"channel_ids": []}, 422)]:
        assert client.post("/api/scheduled-messages", headers=CSRF, json={**body, **bad}).status_code == code, bad
    # edit: change time and message; disable -> no next run
    upd = client.put(f"/api/scheduled-messages/{d['id']}", headers=CSRF, json={**body, "time_of_day": "09:30", "text": "new text", "enabled": False}).json()
    assert upd["time_of_day"] == "09:30" and upd["text"] == "new text" and upd["next_run_at"] is None
    assert client.delete(f"/api/scheduled-messages/{d['id']}", headers=CSRF).status_code == 200
    assert client.get("/api/scheduled-messages").json() == []


def test_due_schedule_sends_retries_and_skips_missed(client, monkeypatch):
    import json
    from datetime import datetime, timedelta, timezone
    from app import monitoring, scheduler
    from app.models import ScheduledMessage
    sign_in(client)
    ok_ch, bad_ch = _mk_channel(client, "good"), _mk_channel(client, "flaky")
    sent = []

    def fake_deliver(channel, text):
        sent.append((channel.name, text))
        return (False, "HTTP 500") if channel.name == "flaky" and len([s for s in sent if s[0] == "flaky"]) < 3 else (True, "Delivered")
    monkeypatch.setattr(monitoring, "deliver_channel", fake_deliver)
    now = datetime.now(timezone.utc)
    with database.SessionLocal() as db:
        item = ScheduledMessage(name="s", text="Hello {date}", channel_ids=json.dumps([ok_ch, bad_ch]), repeat="daily", time_of_day="09:00", days_of_week="", timezone="UTC", enabled=True, next_run_at=now - timedelta(seconds=5))
        db.add(item); db.commit()
        scheduler.run_due_schedules(db)                      # attempt 1: good sent, flaky fails -> retry scheduled
        assert [s[0] for s in sent] == ["good", "flaky"] and sent[0][1].startswith("Hello 20") and "{date}" not in sent[0][1]
        assert item.last_status == "failed" and item.attempts == 1 and json.loads(item.pending_channel_ids) == [bad_ch]
        item.next_run_at = now - timedelta(seconds=1); db.commit()
        scheduler.run_due_schedules(db)                      # attempt 2: only flaky is retried (good is not re-sent)
        assert [s[0] for s in sent] == ["good", "flaky", "flaky"] and item.attempts == 2
        item.next_run_at = now - timedelta(seconds=1); db.commit()
        scheduler.run_due_schedules(db)                      # attempt 3 succeeds -> sent, rescheduled for tomorrow
        assert item.last_status == "sent" and item.attempts == 0 and item.next_run_at > now
        # missed: worker was down for hours -> skipped, not sent late
        before = len(sent)
        item.next_run_at = now - timedelta(hours=3); db.commit()
        scheduler.run_due_schedules(db)
        assert item.last_status == "missed" and len(sent) == before and item.next_run_at > now
        # one-time message disables itself after sending
        once = ScheduledMessage(name="o", text="once", channel_ids=json.dumps([ok_ch]), repeat="once", run_at=now - timedelta(seconds=2), time_of_day="09:00", days_of_week="", timezone="UTC", enabled=True, next_run_at=now - timedelta(seconds=2))
        db.add(once); db.commit()
        scheduler.run_due_schedules(db)
        assert once.last_status == "sent" and once.enabled is False and once.next_run_at is None


def test_send_now_endpoint(client, monkeypatch):
    from app import monitoring
    sign_in(client)
    ch = _mk_channel(client)
    sid = client.post("/api/scheduled-messages", headers=CSRF, json={"name": "n", "text": "hi", "channel_ids": [ch], "repeat": "daily", "time_of_day": "09:00"}).json()["id"]
    monkeypatch.setattr(monitoring, "deliver_channel", lambda c, t: (True, "ok"))
    assert client.post(f"/api/scheduled-messages/{sid}/send", headers=CSRF).json()["ok"] is True
    monkeypatch.setattr(monitoring, "deliver_channel", lambda c, t: (False, "HTTP 404"))
    r = client.post(f"/api/scheduled-messages/{sid}/send", headers=CSRF)
    assert r.status_code == 502 and "HTTP 404" in r.json()["detail"]


# ---------------------------------------------------------------- on-demand logs
def _push_server(client, anon, caps=("logs",)):
    token = client.post("/api/enrollments", headers=CSRF, json={}).json()["token"]
    import secrets as _s
    r = _enroll(anon, token, host="log-box", machine=_s.token_hex(8)).json()
    auth = {"Authorization": f"Bearer {r['agent_token']}"}
    assert anon.post("/api/agent/report", json=report(capabilities=list(caps)), headers=auth).status_code == 200
    return r["server_id"], auth


def test_log_request_roundtrip(client):
    sign_in(client)
    anon = TestClient(main.app)
    sid, auth = _push_server(client, anon)
    assert anon.post(f"/api/servers/{sid}/logs", json={"source": "inventory"}).status_code == 401          # admin only
    assert anon.get("/api/agent/tasks").status_code == 401                                                  # agents only
    req = client.post(f"/api/servers/{sid}/logs", headers=CSRF, json={"source": "docker", "target": "nginx", "lines": 50, "grep": "error"}).json()
    assert client.get(f"/api/servers/{sid}/logs/{req['id']}").json()["status"] == "pending"
    tasks = anon.get("/api/agent/tasks", headers=auth).json()["tasks"]
    assert tasks == [{"id": req["id"], "source": "docker", "target": "nginx", "lines": 50, "since_minutes": 0, "grep": "error", "priority": ""}]
    assert anon.get("/api/agent/tasks", headers=auth).json()["tasks"] == []                                 # handed out exactly once
    assert anon.post(f"/api/agent/tasks/{req['id']}/result", headers=auth, json={"ok": True, "output": "2026 error: upstream timed out", "truncated": False}).status_code == 200
    done = client.get(f"/api/servers/{sid}/logs/{req['id']}").json()
    assert done["status"] == "done" and "upstream timed out" in done["output"]
    assert anon.post(f"/api/agent/tasks/{req['id']}/result", headers=auth, json={"ok": True, "output": "again"}).status_code == 404   # cannot overwrite


def test_log_requests_are_isolated_and_validated(client):
    sign_in(client)
    anon = TestClient(main.app)
    sid_a, auth_a = _push_server(client, anon)
    sid_b, auth_b = _push_server(client, anon)
    req = client.post(f"/api/servers/{sid_a}/logs", headers=CSRF, json={"source": "journal", "target": "nginx.service"}).json()
    assert anon.get("/api/agent/tasks", headers=auth_b).json()["tasks"] == []                               # B never sees A's request
    assert anon.post(f"/api/agent/tasks/{req['id']}/result", headers=auth_b, json={"ok": True, "output": "forged"}).status_code == 404
    assert client.get(f"/api/servers/{sid_b}/logs/{req['id']}").status_code == 404
    for bad in [{"source": "shell", "target": "x"}, {"source": "file", "target": "/var/log/x; rm -rf /"}, {"source": "file", "target": "$(id)"},
                {"source": "docker", "target": ""}, {"source": "journal", "target": "a", "lines": 99999}, {"source": "journal", "target": "a", "priority": "nope"}]:
        assert client.post(f"/api/servers/{sid_a}/logs", headers=CSRF, json=bad).status_code == 422, bad
    # an agent with logs turned off, and non-agent servers, are refused up front
    sid_off, _ = _push_server(client, anon, caps=())
    assert client.post(f"/api/servers/{sid_off}/logs", headers=CSRF, json={"source": "inventory"}).status_code == 422
    ping = client.post("/api/servers", headers=CSRF, json={"name": "p", "host": "93.184.216.40", "monitor_mode": "ping"}).json()["id"]
    assert client.post(f"/api/servers/{ping}/logs", headers=CSRF, json={"source": "inventory"}).status_code == 422
    # flood guard
    for _ in range(4):
        assert client.post(f"/api/servers/{sid_a}/logs", headers=CSRF, json={"source": "inventory"}).status_code == 200
    assert client.post(f"/api/servers/{sid_a}/logs", headers=CSRF, json={"source": "inventory"}).status_code == 429


def test_unanswered_log_request_times_out(client):
    from datetime import datetime, timedelta, timezone
    from app.models import LogRequest
    sign_in(client)
    anon = TestClient(main.app)
    sid, _ = _push_server(client, anon)
    rid = client.post(f"/api/servers/{sid}/logs", headers=CSRF, json={"source": "inventory"}).json()["id"]
    with database.SessionLocal() as db:
        db.get(LogRequest, rid).created_at = datetime.now(timezone.utc) - timedelta(minutes=2); db.commit()
    r = client.get(f"/api/servers/{sid}/logs/{rid}").json()
    assert r["status"] == "error" and "did not answer" in r["error"]


# ---------------------------------------------------------------- log long-polling (speed)
def test_agent_long_poll_wakes_immediately(client):
    import threading
    import time
    sign_in(client)
    anon = TestClient(main.app)
    sid, auth = _push_server(client, anon)
    t0 = time.monotonic()
    assert anon.get("/api/agent/tasks?wait=1", headers=auth).json()["tasks"] == []       # nothing queued: returns empty after ~1s
    assert 0.8 < time.monotonic() - t0 < 3
    got = {}

    def poll():
        start = time.monotonic()
        got["tasks"] = anon.get("/api/agent/tasks?wait=15", headers=auth).json()["tasks"]
        got["secs"] = time.monotonic() - start
    worker = threading.Thread(target=poll); worker.start()
    time.sleep(1.0)                                                                       # the agent is now parked in its long-poll
    queued = time.monotonic()
    rid = client.post(f"/api/servers/{sid}/logs", headers=CSRF, json={"source": "inventory"}).json()["id"]
    worker.join(10)
    assert got["tasks"] and got["tasks"][0]["id"] == rid
    assert got["secs"] < 6, "the poll should return when the request is queued, not at the 15s deadline"
    assert time.monotonic() - queued < 4                                                  # woken immediately (2s re-check is the worst case)


def test_dashboard_long_poll_returns_when_agent_answers(client):
    import threading
    import time
    sign_in(client)
    anon = TestClient(main.app)
    sid, auth = _push_server(client, anon)
    rid = client.post(f"/api/servers/{sid}/logs", headers=CSRF, json={"source": "docker", "target": "web"}).json()["id"]
    got = {}

    def wait_for_result():
        start = time.monotonic()
        got["r"] = client.get(f"/api/servers/{sid}/logs/{rid}?wait=15").json()
        got["secs"] = time.monotonic() - start
    reader = threading.Thread(target=wait_for_result); reader.start()
    time.sleep(0.8)
    assert anon.get("/api/agent/tasks", headers=auth).json()["tasks"][0]["id"] == rid
    anon.post(f"/api/agent/tasks/{rid}/result", headers=auth, json={"ok": True, "output": "hello logs"})
    reader.join(10)
    assert got["r"]["status"] == "done" and got["r"]["output"] == "hello logs" and got["secs"] < 6
    # without ?wait the call is instant and reports the current state
    assert client.get(f"/api/servers/{sid}/logs/{rid}").json()["status"] == "done"
    assert client.get(f"/api/servers/{sid}/logs/{rid}?wait=99").status_code == 422        # wait is capped


# ---------------------------------------------------------------- users, roles, profile
PW = "temporary-password-1"


def make_user(admin, email, role, password=PW, name=""):
    r = admin.post("/api/users", headers=CSRF, json={"email": email, "name": name, "role": role, "password": password})
    assert r.status_code == 200, r.text
    return r.json()


def session_for(email, password=PW, new_password=None):
    """A separate browser session. Temporary passwords must be replaced before anything else works."""
    c = TestClient(main.app)
    r = c.post("/api/auth/login", json={"email": email, "password": password})
    assert r.status_code == 200, r.text
    if new_password:
        assert c.post("/api/auth/password", headers=CSRF, json={"current_password": password, "new_password": new_password}).status_code == 200
    return c


def test_role_permission_matrix(client):
    sign_in(client)
    srv = client.post("/api/servers", headers=CSRF, json={"name": "m", "host": "93.184.216.50", "monitor_mode": "ping"}).json()["id"]
    ch = _mk_channel(client, "chat")
    make_user(client, "viewer@example.com", "viewer"); make_user(client, "operator@example.com", "operator")
    viewer = session_for("viewer@example.com", new_password="viewer-password-123"); operator = session_for("operator@example.com", new_password="operator-password-123")

    body = {"name": "x", "url": "https://example.com"}
    allowed_read = ["/api/dashboard", "/api/incidents", "/api/uptime", f"/api/servers/{srv}/history?range=1h", f"/api/servers/{srv}/availability?range=1h"]
    operator_only_get = ["/api/scheduled-messages", "/api/enrollments"]
    for path in allowed_read:
        assert viewer.get(path).status_code == 200, path
        assert operator.get(path).status_code == 200, path
    for path in operator_only_get:
        assert viewer.get(path).status_code == 403, path
        assert operator.get(path).status_code == 200, path
    # viewers: read-only
    for method, path, payload in [("post", "/api/servers", {"name": "v", "host": "93.184.216.51", "monitor_mode": "ping"}), ("post", "/api/services", body), ("put", f"/api/servers/{srv}", {"name": "v", "host": "1.1.1.1", "monitor_mode": "ping"}),
                                   ("delete", f"/api/servers/{srv}", None), ("post", "/api/monitor/run", None), ("post", f"/api/channels/{ch}/test", None), ("delete", f"/api/channels/{ch}", None),
                                   ("post", "/api/enrollments", {}), ("post", f"/api/servers/{srv}/logs", {"source": "inventory"}), ("post", "/api/scheduled-messages", {})]:
        r = getattr(viewer, method)(path, headers=CSRF, **({"json": payload} if payload is not None else {}))
        assert r.status_code == 403, (method, path, r.status_code)
        assert "viewer" in r.json()["detail"] and "operator" in r.json()["detail"]
    assert next(c for c in viewer.get("/api/channels").json() if c["id"] == ch) == {"id": ch, "name": "chat", "type": "webhook", "enabled": True}   # no configuration for viewers
    assert "endpoint" in next(c for c in operator.get("/api/channels").json() if c["id"] == ch)
    # operators: manage monitoring, but never users
    assert operator.post("/api/services", headers=CSRF, json=body).status_code == 200
    assert operator.post("/api/enrollments", headers=CSRF, json={}).status_code == 200
    for who in (viewer, operator):
        assert who.get("/api/users").status_code == 403
        assert who.post("/api/users", headers=CSRF, json={"email": "z@example.com", "role": "admin", "password": PW}).status_code == 403
        assert who.put("/api/users/1", headers=CSRF, json={"role": "viewer"}).status_code == 403
        assert who.delete("/api/users/1", headers=CSRF).status_code == 403
    assert client.get("/api/users").status_code == 200
    # nobody without a session gets anything
    assert TestClient(main.app).get("/api/users").status_code == 401


def test_user_management_rules(client):
    sign_in(client)
    me = client.get("/api/auth/me").json()
    assert me["role"] == "admin" and me["name"] == "Administrator" and me["must_change_password"] is False
    u = make_user(client, "Carol@Example.com", "operator", name="  Carol  ")
    assert u["email"] == "carol@example.com" and u["name"] == "Carol" and u["must_change_password"] is True      # normalised; temp password
    assert client.post("/api/users", headers=CSRF, json={"email": "carol@example.com", "role": "viewer", "password": PW}).status_code == 409
    for bad in [{"password": "short"}, {"role": "root"}, {"email": "not-an-email"}]:
        assert client.post("/api/users", headers=CSRF, json={"email": "d@example.com", "role": "viewer", "password": PW, **bad}).status_code == 422, bad
    # forced password change: nothing else works until it is replaced
    carol = TestClient(main.app)
    assert carol.post("/api/auth/login", json={"email": "carol@example.com", "password": PW}).status_code == 200
    assert carol.get("/api/auth/me").json()["must_change_password"] is True
    blocked = carol.get("/api/dashboard")
    assert blocked.status_code == 403 and blocked.json()["detail"] == "PASSWORD_CHANGE_REQUIRED"
    assert carol.post("/api/auth/password", headers=CSRF, json={"current_password": PW, "new_password": PW}).status_code == 422   # must differ
    assert carol.post("/api/auth/password", headers=CSRF, json={"current_password": PW, "new_password": "carol-own-password-1"}).status_code == 200
    assert carol.get("/api/dashboard").status_code == 200 and carol.get("/api/auth/me").json()["must_change_password"] is False
    # self-protection
    assert client.put(f"/api/users/{me['id']}", headers=CSRF, json={"role": "viewer"}).status_code == 409
    assert client.put(f"/api/users/{me['id']}", headers=CSRF, json={"active": False}).status_code == 409
    assert client.delete(f"/api/users/{me['id']}", headers=CSRF).status_code == 409
    assert client.put(f"/api/users/{me['id']}", headers=CSRF, json={"name": "Chief"}).json()["name"] == "Chief"
    client.put(f"/api/users/{me['id']}", headers=CSRF, json={"name": "Administrator"})
    assert client.delete(f"/api/users/{u['id']}", headers=CSRF).status_code == 200
    assert carol.get("/api/dashboard").status_code == 401                                           # a deleted user's session dies at once


def test_role_and_status_changes_apply_immediately(client):
    sign_in(client)
    u = make_user(client, "dave@example.com", "operator")
    dave = session_for("dave@example.com", new_password="dave-own-password-1")
    assert dave.post("/api/services", headers=CSRF, json={"name": "a", "url": "https://example.com"}).status_code == 200
    client.put(f"/api/users/{u['id']}", headers=CSRF, json={"role": "viewer"})
    assert dave.get("/api/dashboard").status_code in (200, 401)                                      # token_version bumped: signed out, must sign in again
    dave = TestClient(main.app); assert dave.post("/api/auth/login", json={"email": "dave@example.com", "password": "dave-own-password-1"}).status_code == 200
    assert dave.post("/api/services", headers=CSRF, json={"name": "b", "url": "https://example.com"}).status_code == 403    # now a viewer
    assert dave.get("/api/dashboard").status_code == 200
    # disabling: existing session dies, sign-in fails with the SAME generic message as a wrong password
    client.put(f"/api/users/{u['id']}", headers=CSRF, json={"active": False})
    assert dave.get("/api/dashboard").status_code == 401
    off = TestClient(main.app).post("/api/auth/login", json={"email": "dave@example.com", "password": "dave-own-password-1"})
    wrong = TestClient(main.app).post("/api/auth/login", json={"email": "dave@example.com", "password": "nope"})
    assert off.status_code == wrong.status_code == 401 and off.json() == wrong.json()
    client.put(f"/api/users/{u['id']}", headers=CSRF, json={"active": True})
    assert TestClient(main.app).post("/api/auth/login", json={"email": "dave@example.com", "password": "dave-own-password-1"}).status_code == 200
    assert next(x for x in client.get("/api/users").json() if x["id"] == u["id"])["last_login_at"]


def test_admin_password_reset_and_second_admin(client):
    sign_in(client)
    u = make_user(client, "erin@example.com", "admin")
    erin = session_for("erin@example.com", new_password="erin-own-password-12")
    assert erin.get("/api/users").status_code == 200                                                 # a second admin can manage users
    me = client.get("/api/auth/me").json()
    assert erin.put(f"/api/users/{me['id']}", headers=CSRF, json={"role": "viewer"}).status_code == 200   # ...including demoting the original admin
    assert erin.put(f"/api/users/{u['id']}", headers=CSRF, json={"active": False}).status_code == 409     # but not disabling the last admin (herself)
    erin.put(f"/api/users/{me['id']}", headers=CSRF, json={"role": "admin"})
    assert client.get("/api/dashboard").status_code == 401                                          # the demotion signed the original admin out
    sign_in(client)
    # reset: temporary again + old sessions revoked
    r = client.put(f"/api/users/{u['id']}", headers=CSRF, json={"password": "reset-password-123"})
    assert r.json()["must_change_password"] is True
    assert erin.get("/api/dashboard").status_code == 401
    assert TestClient(main.app).post("/api/auth/login", json={"email": "erin@example.com", "password": "erin-own-password-12"}).status_code == 401


def test_profile_update(client):
    sign_in(client)
    make_user(client, "frank@example.com", "viewer")
    frank = session_for("frank@example.com", new_password="frank-own-password-1")
    r = frank.put("/api/auth/profile", headers=CSRF, json={"name": " Frank Z "})
    assert r.status_code == 200 and r.json()["name"] == "Frank Z" and r.json()["email"] == "frank@example.com"
    assert frank.put("/api/auth/profile", headers=CSRF, json={"name": "F", "email": "frank2@example.com"}).status_code == 403                                   # needs the password
    assert frank.put("/api/auth/profile", headers=CSRF, json={"name": "F", "email": "frank2@example.com", "current_password": "wrong-password"}).status_code == 403
    assert frank.put("/api/auth/profile", headers=CSRF, json={"name": "F", "email": "admin@example.com", "current_password": "frank-own-password-1"}).status_code == 409   # taken
    ok = frank.put("/api/auth/profile", headers=CSRF, json={"name": "F", "email": "Frank2@Example.com", "current_password": "frank-own-password-1"})
    assert ok.status_code == 200 and ok.json()["email"] == "frank2@example.com"
    assert TestClient(main.app).post("/api/auth/login", json={"email": "frank2@example.com", "password": "frank-own-password-1"}).status_code == 200


# =================================================================== security hardening
def audit_rows(client, **params):
    q = "&".join(f"{k}={v}" for k, v in params.items())
    r = client.get(f"/api/audit?limit=500&{q}")
    assert r.status_code == 200, r.text
    return r.json()


def test_seamless_token_rotation(client):
    """Rotation is delivered to the agent over its own authenticated channel; the old token dies only once the agent has switched."""
    sign_in(client)
    anon = TestClient(main.app)
    sid, auth = _push_server(client, anon)
    old = auth["Authorization"].split()[1]
    before = anon.get("/api/dashboard", headers={}) if False else None

    rotate = client.post(f"/api/servers/{sid}/rotate-token", headers=CSRF).json()
    assert rotate["mode"] == "managed" and "install_token" not in rotate                      # the admin never sees (or has to copy) the new token
    srv = next(s for s in client.get("/api/dashboard").json()["servers"] if s["id"] == sid)
    assert srv["token_rotation_pending"] is True and "pending_token" not in srv and "pending_token_hash" not in srv

    # the agent keeps working with the old token and is handed the new one
    r = anon.post("/api/agent/report", json=report(), headers=auth)
    assert r.status_code == 200 and len(r.json()["rotate_token"]) >= 32
    new = r.json()["rotate_token"]
    assert new != old
    # using the new token completes the rotation: it is promoted and the old one is revoked
    assert anon.post("/api/agent/report", json=report(), headers={"Authorization": f"Bearer {new}"}).status_code == 200
    assert anon.post("/api/agent/report", json=report(), headers=auth).status_code == 401                     # old token is dead
    assert "rotate_token" not in anon.post("/api/agent/report", json=report(), headers={"Authorization": f"Bearer {new}"}).json()
    srv = next(s for s in client.get("/api/dashboard").json()["servers"] if s["id"] == sid)
    assert srv["token_rotation_pending"] is False and srv["token_issued_at"]
    actions = [e["action"] for e in audit_rows(client)]
    assert "server.token_rotate" in actions and "agent.token_rotated" in actions


def test_immediate_revoke_kills_the_old_token_at_once(client):
    sign_in(client)
    anon = TestClient(main.app)
    sid, auth = _push_server(client, anon)
    r = client.post(f"/api/servers/{sid}/rotate-token?immediate=true", headers=CSRF).json()
    assert r["mode"] == "immediate" and len(r["install_token"]) >= 32
    assert anon.post("/api/agent/report", json=report(), headers=auth).status_code == 401                      # a stolen token is useless immediately
    assert anon.post("/api/agent/report", json=report(), headers={"Authorization": f"Bearer {r['install_token']}"}).status_code == 200
    assert any(e["action"] == "server.token_revoke" for e in audit_rows(client))


def test_agent_ip_change_is_recorded(client, monkeypatch):
    from app import routes_agent
    sign_in(client)
    anon = TestClient(main.app)
    sid, auth = _push_server(client, anon)
    for ip in ("203.0.113.10", "203.0.113.10", "198.51.100.77"):                                  # same address twice, then a different one
        monkeypatch.setattr(routes_agent, "client_ip", lambda request, ip=ip: ip)
        assert anon.post("/api/agent/report", json=report(), headers=auth).status_code == 200
    changes = [e for e in audit_rows(client, category="agent") if e["action"] == "agent.ip_changed"]
    assert len(changes) >= 1 and "203.0.113.10 -> 198.51.100.77" in changes[0]["detail"]
    assert next(s for s in client.get("/api/dashboard").json()["servers"] if s["id"] == sid)["last_agent_ip"] == "198.51.100.77"


def test_token_guessing_is_throttled_on_every_agent_endpoint(client):
    """Guessing = presenting many DIFFERENT wrong credentials. After 5 distinct misses an address is locked out."""
    from app.security import login_limiter
    sign_in(client)
    anon = TestClient(main.app)
    sid, auth = _push_server(client, anon)
    seq = iter(range(10_000))
    guess = lambda: {"Authorization": f"Bearer guess-{next(seq):040d}"}  # noqa: E731
    for path, send in [("tasks", lambda: anon.get("/api/agent/tasks", headers=guess())),
                       ("result", lambda: anon.post("/api/agent/tasks/1/result", json={"ok": True}, headers=guess())),
                       ("report", lambda: anon.post("/api/agent/report", json=report(), headers=guess())),
                       ("join link", lambda: anon.get(f"/api/agent/join/smwj_guess_{next(seq)}")),
                       ("enroll", lambda: anon.post("/api/agent/enroll", json={"hostname": "h"}, headers=guess()))]:
        login_limiter._hits.clear(); login_limiter._seen.clear()
        codes = [send().status_code for _ in range(7)]
        assert codes[:5].count(429) == 0 and 429 in codes[5:], (path, codes)                       # 5 free misses, then locked out
    login_limiter._hits.clear(); login_limiter._seen.clear()
    assert anon.post("/api/agent/report", json=report(), headers=auth).status_code == 200          # the legitimate agent is unaffected
    assert any(e["action"] == "agent.auth_failed" and not e["success"] for e in audit_rows(client))


def test_a_stale_agent_cannot_lock_out_its_neighbours(client):
    """One agent repeating its old (rotated/revoked) token must not lock out healthy agents behind the same address."""
    from app.security import login_limiter
    sign_in(client)
    anon = TestClient(main.app)
    sid, good = _push_server(client, anon)
    stale = {"Authorization": "Bearer " + "s" * 43}
    login_limiter._hits.clear(); login_limiter._seen.clear()
    for _ in range(60):                                                                             # a misconfigured agent hammering, on every endpoint
        assert anon.post("/api/agent/report", json=report(), headers=stale).status_code == 401
        assert anon.get("/api/agent/tasks", headers=stale).status_code == 401
    assert anon.post("/api/agent/report", json=report(), headers=good).status_code == 200           # still never 429 for anyone
    assert anon.get("/api/agent/tasks", headers=good).status_code == 200


def test_report_flood_is_capped(client, monkeypatch):
    from app.config import get_settings
    sign_in(client)
    anon = TestClient(main.app)
    sid, auth = _push_server(client, anon)
    monkeypatch.setattr(get_settings(), "agent_min_report_seconds", 60.0)
    r = anon.post("/api/agent/report", json=report(), headers=auth)
    assert r.status_code == 429 and r.headers["retry-after"]                                       # right after a report, another is refused
    monkeypatch.setattr(get_settings(), "agent_min_report_seconds", 0.0)
    assert anon.post("/api/agent/report", json=report(), headers=auth).status_code == 200


def test_audit_trail_is_complete_admin_only_and_secret_free(client):
    sign_in(client)
    secret_pw = "audit-secret-password-999"
    u = make_user(client, "gina@example.com", "operator", password=secret_pw)
    # failed and successful sign-ins, wrong current password, role change, log request, install link, server + channel + deletion
    TestClient(main.app).post("/api/auth/login", json={"email": "gina@example.com", "password": "wrong-guess-123456"})
    TestClient(main.app).post("/api/auth/login", json={"email": "nobody@example.com", "password": "wrong-guess-123456"})
    gina = session_for("gina@example.com", password=secret_pw, new_password="gina-own-password-12")
    gina.post("/api/auth/password", headers=CSRF, json={"current_password": "not-my-password", "new_password": "another-new-password-1"})
    link = gina.post("/api/enrollments", headers=CSRF, json={"label": "audit-link"}).json()
    gina.delete(f"/api/enrollments/{link['id']}", headers=CSRF)
    srv = gina.post("/api/servers", headers=CSRF, json={"name": "audited", "host": "93.184.216.60", "monitor_mode": "ping"}).json()["id"]
    gina.delete(f"/api/servers/{srv}", headers=CSRF)
    anon = TestClient(main.app)
    sid, auth = _push_server(client, anon)
    client.post(f"/api/servers/{sid}/logs", headers=CSRF, json={"source": "docker", "target": "nginx", "grep": "needle"})
    client.put(f"/api/users/{u['id']}", headers=CSRF, json={"role": "viewer"})

    rows = audit_rows(client)
    actions = {(e["action"], e["success"]) for e in rows}
    for expected in [("auth.login", True), ("auth.login", False), ("auth.password_change", False), ("user.create", True), ("user.update", True), ("enroll.link_create", True),
                     ("enroll.link_revoke", True), ("server.create", True), ("server.delete", True), ("logs.read", True), ("agent.enroll", True)]:
        assert expected in actions, expected
    unknown = next(e for e in rows if e["action"] == "auth.login" and e["actor"] == "nobody@example.com")
    assert unknown["success"] is False and unknown["detail"] == "unknown user"
    read = next(e for e in rows if e["action"] == "logs.read")
    assert read["actor"] == "admin@example.com" and read["actor_role"] == "admin" and "docker:nginx" in read["detail"] and "needle" in read["detail"]
    # NOTHING secret is ever stored in the trail
    blob = json.dumps(rows) if (json := __import__("json")) else ""
    for secret in (secret_pw, "gina-own-password-12", "another-new-password-1", "wrong-guess-123456", auth["Authorization"].split()[1], link["token"]):
        assert secret not in blob, "a secret leaked into the audit log"
    # filters
    assert all(not e["success"] for e in audit_rows(client, failures="true"))
    assert all(e["action"].startswith("user.") for e in audit_rows(client, category="user"))
    assert audit_rows(client, q="gina@example.com")
    # only admins can read it; nobody can change it
    for who in (gina, TestClient(main.app)):
        assert who.get("/api/audit").status_code in (401, 403)
    for method in ("put", "post", "delete", "patch"):
        assert getattr(client, method)("/api/audit", headers=CSRF).status_code in (404, 405)


def test_password_hashing_upgrade_and_no_timing_oracle(client, monkeypatch):
    import hashlib
    from app import security
    from app.models import User
    h = security.hash_password("a-long-test-password")
    assert h.startswith("scrypt2$131072$8$1$") and security.verify_password("a-long-test-password", h)
    assert not security.verify_password("a-long-test-password!", h) and not security.verify_password("x", "scrypt2$bad") and not security.verify_password("x", "")
    assert not security.needs_rehash(h)
    # a legacy (weak) hash still works, and is silently upgraded at the next sign-in
    sign_in(client)
    make_user(client, "hank@example.com", "viewer", password="legacy-password-123")
    salt = bytes.fromhex("00112233445566778899aabbccddeeff")
    legacy = f"scrypt${salt.hex()}${hashlib.scrypt(b'legacy-password-123', salt=salt, n=16384, r=8, p=1).hex()}"
    with database.SessionLocal() as db:
        db.query(User).filter(User.email == "hank@example.com").update({"password_hash": legacy}); db.commit()
    assert security.needs_rehash(legacy) and security.verify_password("legacy-password-123", legacy)
    assert TestClient(main.app).post("/api/auth/login", json={"email": "hank@example.com", "password": "legacy-password-123"}).status_code == 200
    with database.SessionLocal() as db:
        upgraded = db.query(User).filter(User.email == "hank@example.com").one().password_hash
    assert upgraded.startswith("scrypt2$") and upgraded != legacy and security.verify_password("legacy-password-123", upgraded)
    # an unknown email costs the same work as a wrong password (no account enumeration by response time)
    calls = []
    real = main.verify_password
    monkeypatch.setattr(main, "verify_password", lambda p, h: (calls.append(h), real(p, h))[1])
    TestClient(main.app).post("/api/auth/login", json={"email": "ghost@example.com", "password": "whatever-123456"})
    assert len(calls) == 1 and calls[0].startswith("scrypt2$")


def test_change_password_cannot_be_brute_forced_with_a_stolen_session(client):
    from app.security import login_limiter
    sign_in(client)
    login_limiter._hits.clear()
    codes = [client.post("/api/auth/password", headers=CSRF, json={"current_password": f"guess-{i}-aaaaaaaa", "new_password": "brand-new-password-1"}).status_code for i in range(7)]
    assert codes[:5] == [403] * 5 and 429 in codes[5:]


def test_install_scripts_are_integrity_checked_and_download_no_code(client):
    import hashlib
    sign_in(client)
    anon = TestClient(main.app)
    token = client.post("/api/enrollments", headers=CSRF, json={}).json()["token"]
    agent_bytes = anon.get("/api/agent/agent.py").content
    sh = anon.get(f"/api/agent/join/{token}").text
    assert f"SMWATCH_AGENT_SHA256={hashlib.sha256(agent_bytes).hexdigest()}" in sh               # announced hash == the exact bytes served
    assert "require_secure_url" in sh and "does not match the checksum" in sh
    dk = anon.get(f"/api/agent/join/{token}/docker").text
    assert "SMWATCH_AGENT_IMAGE='shambi21/sm-watch-host-agent:latest'" in dk
    assert "urlretrieve" not in dk and "pip install" not in dk and "apt-get" not in dk           # nothing is fetched or executed at container start
    assert "--cap-drop ALL" in dk and "no-new-privileges" in dk and "--read-only" in dk and "require_secure_url" in dk


def test_docker_image_name_is_configurable(client, monkeypatch):
    from app.config import get_settings
    sign_in(client)
    token = client.post("/api/enrollments", headers=CSRF, json={}).json()["token"]
    monkeypatch.setattr(get_settings(), "agent_image", "registry.example.org/team/agent:1.2.3")
    assert "SMWATCH_AGENT_IMAGE='registry.example.org/team/agent:1.2.3'" in TestClient(main.app).get(f"/api/agent/join/{token}/docker").text


def test_account_lockout_is_tolerant_but_address_lockout_is_strict(client, monkeypatch):
    """Anyone who knows an admin's email must not be able to lock that admin out by failing a few times from elsewhere."""
    from app.security import login_limiter
    login_limiter._hits.clear(); login_limiter._seen.clear()
    wrong = {"email": "admin@example.com", "password": "wrong-password-123"}
    right = {"email": "admin@example.com", "password": "correct-horse-battery"}
    addresses = iter(f"203.0.113.{i}" for i in range(1, 200))
    monkeypatch.setattr(main, "client_ip", lambda request: next(addresses))
    assert all(TestClient(main.app).post("/api/auth/login", json=wrong).status_code == 401 for _ in range(12))       # 12 misses from 12 addresses
    monkeypatch.setattr(main, "client_ip", lambda request: "198.51.100.1")                                            # the real admin, elsewhere
    assert TestClient(main.app).post("/api/auth/login", json=right).status_code == 200                                # is NOT locked out
    login_limiter._hits.clear(); login_limiter._seen.clear()
    fresh = iter(f"192.0.2.{i}" for i in range(1, 250))
    monkeypatch.setattr(main, "client_ip", lambda request: next(fresh))                                               # every attempt from a NEW address
    codes = [TestClient(main.app).post("/api/auth/login", json=wrong).status_code for _ in range(24)]
    assert codes[:20] == [401] * 20 and 429 in codes[20:], codes                                                      # a sustained distributed attack DOES lock the account
    login_limiter._hits.clear(); login_limiter._seen.clear()


# =================================================================== log access policy
def test_log_policy_api_permissions_and_validation(client):
    sign_in(client)
    anon = TestClient(main.app)
    sid, auth = _push_server(client, anon)
    make_user(client, "pol-op@example.com", "operator"); make_user(client, "pol-view@example.com", "viewer")
    op = session_for("pol-op@example.com", new_password="operator-pass-12345"); viewer = session_for("pol-view@example.com", new_password="viewer-pass-123456")
    default = client.get(f"/api/servers/{sid}/log-policy").json()
    assert default["restricted"] is False and default["policy"]["docker"]["include"] == ["*"]                # default: unrestricted
    assert op.get(f"/api/servers/{sid}/log-policy").status_code == 200                                       # operators can see it...
    assert op.put(f"/api/servers/{sid}/log-policy", headers=CSRF, json={}).status_code == 403                # ...but only admins change it
    assert viewer.get(f"/api/servers/{sid}/log-policy").status_code == 403
    cat = op.get("/api/log-policy/catalog").json()["file_categories"]
    assert {"system", "auth", "web", "database", "packages", "mail", "apps"} <= {c["id"] for c in cat}
    for bad in [{"files": {"custom": ["../etc/passwd"]}}, {"files": {"custom": ["relative.log"]}}, {"docker": {"include": ["a;rm -rf /"]}}, {"files": {"categories": ["bogus"]}}, {"files": {"mode": "weird"}}]:
        assert client.put(f"/api/servers/{sid}/log-policy", headers=CSRF, json=bad).status_code == 422, bad
    assert client.put("/api/servers/99999/log-policy", headers=CSRF, json={}).status_code == 404


def test_log_policy_is_enforced_filtered_audited_and_delivered(client):
    import json as _json
    sign_in(client)
    anon = TestClient(main.app)
    sid, auth = _push_server(client, anon)
    policy = {"docker": {"enabled": True, "include": ["web-*"], "exclude": ["web-secret"]}, "journal": {"enabled": True, "units": ["nginx*"]},
              "files": {"enabled": True, "mode": "selected", "categories": ["web"], "custom": ["/srv/app/*.log"]}}
    r = client.put(f"/api/servers/{sid}/log-policy", headers=CSRF, json=policy)
    assert r.status_code == 200 and r.json()["restricted"] is True
    ask = lambda **q: client.post(f"/api/servers/{sid}/logs", headers=CSRF, json=q)                       # noqa: E731
    # allowed
    assert ask(source="docker", target="web-1").status_code == 200
    assert ask(source="journal", target="nginx.service").status_code == 200
    assert ask(source="file", target="/var/log/nginx/access.log").status_code == 200
    assert ask(source="file", target="/srv/app/worker.log").status_code == 200
    assert ask(source="inventory").status_code == 200
    # blocked, with a clear message, and the attempt is audited as a failure
    for q in [dict(source="docker", target="db"), dict(source="docker", target="web-secret"), dict(source="journal", target="all"), dict(source="journal", target="cron.service"),
              dict(source="file", target="/var/log/auth.log"), dict(source="file", target="/var/log/mysql/error.log")]:
        blocked = ask(**q)
        assert blocked.status_code == 403 and "log policy" in blocked.json()["detail"], q
    denied = [e for e in audit_rows(client) if e["action"] == "logs.denied"]
    assert len(denied) >= 6 and not denied[0]["success"] and "blocked by the server's log policy" in denied[0]["detail"]
    assert any(e["action"] == "server.log_policy" for e in audit_rows(client))
    # the agent's inventory answer is filtered before it reaches the dashboard, even if the agent listed everything
    from app.models import LogRequest
    with database.SessionLocal() as db:                                                                   # clear the per-server pending-request cap used up above
        db.query(LogRequest).delete(); db.commit()
    rid = ask(source="inventory").json()["id"]
    assert anon.get("/api/agent/tasks", headers=auth).json()["tasks"]
    full = {"files": ["/var/log/nginx/access.log", "/var/log/auth.log", "/srv/app/worker.log", "/var/log/mysql/error.log"], "journal": True, "units": [], "docker": True, "notes": [],
            "containers": [{"name": "web-1", "state": "running", "image": "x"}, {"name": "db", "state": "running", "image": "x"}, {"name": "web-secret", "state": "running", "image": "x"}]}
    anon.post(f"/api/agent/tasks/{rid}/result", headers=auth, json={"ok": True, "output": _json.dumps(full)})
    seen = _json.loads(client.get(f"/api/servers/{sid}/logs/{rid}").json()["output"])
    assert seen["files"] == ["/var/log/nginx/access.log", "/srv/app/worker.log"] and [c["name"] for c in seen["containers"]] == ["web-1"]
    assert seen["journal"] is True and seen["journal_all"] is False and any("restricted by an administrator" in n for n in seen["notes"])
    # the agent receives the compiled policy with its next report (and it can only narrow, never widen)
    reply = anon.post("/api/agent/report", json=report(capabilities=["logs"]), headers=auth).json()
    assert reply["log_policy"]["docker"] == {"enabled": True, "include": ["web-*"], "exclude": ["web-secret"]}
    assert "/var/log/nginx/*" in reply["log_policy"]["files"]["allow"] and "/srv/app/*.log" in reply["log_policy"]["files"]["allow"] and "/var/log/auth.log*" not in reply["log_policy"]["files"]["allow"]
    # switching everything off blocks all sources; resetting to the default stores nothing and unblocks
    off = {"docker": {"enabled": False}, "journal": {"enabled": False}, "files": {"enabled": False}}
    assert client.put(f"/api/servers/{sid}/log-policy", headers=CSRF, json=off).status_code == 200
    statuses = [ask(**q).status_code for q in [dict(source="docker", target="web-1"), dict(source="journal", target="all"), dict(source="file", target="/var/log/nginx/access.log")]]
    assert statuses == [403, 403, 403], statuses
    client.put(f"/api/servers/{sid}/log-policy", headers=CSRF, json={})
    assert client.get(f"/api/servers/{sid}/log-policy").json()["restricted"] is False and ask(source="docker", target="db").status_code == 200


# =================================================================== kubernetes
def _k8s_register(client, anon, name="prod"):
    token = client.post("/api/enrollments", headers=CSRF, json={"label": "k8s"}).json()["token"]
    r = anon.post(f"/api/agent/k8s/{token}?name={name}")
    return token, r


def _k8s_token(manifest: str) -> str:
    import re
    return re.search(r'token: "([^"]+)"', manifest).group(1)


HEALTHY = {"agent_version": "1.0.0", "k8s_version": "v1.34.1", "nodes_total": 2, "nodes_ready": 2, "pods_total": 10, "pods_running": 10, "cpu_m": 400, "cpu_alloc_m": 4000, "mem_mib": 900, "mem_alloc_mib": 8000}


def test_k8s_manifest_is_valid_least_privilege_yaml(client):
    import yaml
    sign_in(client)
    anon = TestClient(main.app)
    _, r = _k8s_register(client, anon, "yaml-test")
    assert r.status_code == 200, r.text
    docs = list(yaml.safe_load_all(r.text))
    kinds = [d["kind"] for d in docs]
    assert kinds == ["Namespace", "ServiceAccount", "ClusterRole", "ClusterRoleBinding", "Role", "RoleBinding", "Secret", "Deployment"]
    cluster_role = docs[2]
    verbs = {v for rule in cluster_role["rules"] for v in rule["verbs"]}
    resources = {x for rule in cluster_role["rules"] for x in rule["resources"]}
    assert verbs <= {"get", "list", "watch"}
    assert not resources & {"secrets", "configmaps", "pods/exec", "pods/attach"}
    role = docs[4]["rules"][0]
    assert role["resources"] == ["secrets"] and role["resourceNames"] == ["smwatch-agent"] and set(role["verbs"]) == {"get", "patch"}
    sec = docs[7]["spec"]["template"]["spec"]["containers"][0]["securityContext"]
    assert sec["readOnlyRootFilesystem"] and sec["allowPrivilegeEscalation"] is False


def test_k8s_registration_guards(client):
    sign_in(client)
    anon = TestClient(main.app)
    assert anon.post("/api/agent/k8s/smwj_wrong?name=x").status_code == 401
    token, r = _k8s_register(client, anon, "guarded")
    agent_token = _k8s_token(r.text)
    assert anon.post(f"/api/k8s-agent/report", json=HEALTHY, headers={"Authorization": f"Bearer {agent_token}"}).status_code == 200
    # a live cluster cannot be taken over by registering the same name again
    assert anon.post(f"/api/agent/k8s/{token}?name=guarded").status_code == 409
    assert anon.post(f"/api/agent/k8s/{token}?name=bad%20name!").status_code == 422


def test_k8s_report_status_incident_and_permissions(client):
    sign_in(client)
    anon = TestClient(main.app)
    _, r = _k8s_register(client, anon, "status-test")
    auth = {"Authorization": f"Bearer {_k8s_token(r.text)}"}
    cid = next(c["id"] for c in client.get("/api/clusters").json() if c["name"] == "status-test")
    assert anon.post("/api/k8s-agent/report", json=HEALTHY, headers={"Authorization": "Bearer nope"}).status_code == 401
    assert anon.post("/api/k8s-agent/report", json={**HEALTHY, "nodes_total": -1}, headers=auth).status_code == 422
    assert anon.post("/api/k8s-agent/report", json=HEALTHY, headers=auth).json()["log_policy"]["include"] == ["*"]
    assert client.get(f"/api/clusters/{cid}").json()["status"] == "up"
    bad = {**HEALTHY, "nodes_ready": 1, "pods_crashloop": 2, "problems": ["node worker-2 NotReady", "pod demo/crasher CrashLoopBackOff"]}
    anon.post("/api/k8s-agent/report", json=bad, headers=auth)
    assert client.get(f"/api/clusters/{cid}").json()["status"] == "alert"
    anon.post("/api/k8s-agent/report", json=HEALTHY, headers=auth)
    assert client.get(f"/api/clusters/{cid}").json()["status"] == "up"
    assert client.get(f"/api/clusters/{cid}/history").json()["samples"] >= 2
    assert client.get(f"/api/clusters/{cid}/history?range=1h").status_code == 200
    assert client.get(f"/api/clusters/{cid}/availability").status_code in (200, 404)
    # heartbeat loss -> down
    from datetime import datetime, timedelta, timezone
    from app.models import Cluster
    from app.routes_k8s import check_cluster_heartbeats
    with database.SessionLocal() as db:
        db.get(Cluster, cid).last_seen_at = datetime.now(timezone.utc) - timedelta(minutes=5)
        db.commit()
        check_cluster_heartbeats(db); db.commit()
    assert client.get(f"/api/clusters/{cid}").json()["status"] == "down"
    # roles
    make_user(client, "k8s-op@example.com", "operator"); make_user(client, "k8s-view@example.com", "viewer")
    op = session_for("k8s-op@example.com", new_password="operator-pass-12345"); viewer = session_for("k8s-view@example.com", new_password="viewer-pass-123456")
    assert viewer.get("/api/clusters").status_code == 200
    assert viewer.put(f"/api/clusters/{cid}", headers=CSRF, json={"enabled": False}).status_code == 403
    assert viewer.get(f"/api/clusters/{cid}/log-policy").status_code == 403
    assert op.put(f"/api/clusters/{cid}/log-policy", headers=CSRF, json={}).status_code == 403
    assert anon.get("/api/clusters").status_code == 401


def test_k8s_queries_policy_and_results(client):
    sign_in(client)
    anon = TestClient(main.app)
    _, r = _k8s_register(client, anon, "query-test")
    auth = {"Authorization": f"Bearer {_k8s_token(r.text)}"}
    cid = next(c["id"] for c in client.get("/api/clusters").json() if c["name"] == "query-test")
    q = f"/api/clusters/{cid}/query"
    assert client.post(q, headers=CSRF, json={"kind": "pods"}).status_code == 503      # agent never reported -> offline
    anon.post("/api/k8s-agent/report", json=HEALTHY, headers=auth)
    make_user(client, "q-op@example.com", "operator"); make_user(client, "q-view@example.com", "viewer")
    op = session_for("q-op@example.com", new_password="operator-pass-12345"); viewer = session_for("q-view@example.com", new_password="viewer-pass-123456")
    assert client.post(q, headers=CSRF, json={"kind": "bogus"}).status_code == 422
    assert client.post(q, headers=CSRF, json={"kind": "pods", "namespace": "a;b"}).status_code == 422
    assert viewer.post(q, headers=CSRF, json={"kind": "logs", "namespace": "demo", "name": "web-1"}).status_code == 403   # viewers read no logs
    rid = viewer.post(q, headers=CSRF, json={"kind": "pods"}).json()["id"]                                                  # ...but may list pods
    tasks = anon.get("/api/k8s-agent/tasks", headers=auth).json()["tasks"]
    assert [t["id"] for t in tasks] == [rid] and tasks[0]["kind"] == "pods"
    assert anon.get("/api/k8s-agent/tasks", headers={"Authorization": "Bearer nope"}).status_code == 401
    assert anon.post(f"/api/k8s-agent/tasks/{rid}/result", headers=auth, json={"ok": True, "output": json.dumps({"items": [{"name": "web-1"}]})}).status_code == 200
    got = viewer.get(f"{q}/{rid}").json()
    assert got["status"] == "done" and got["data"]["items"][0]["name"] == "web-1"
    assert anon.post(f"/api/k8s-agent/tasks/{rid}/result", headers=auth, json={"ok": True}).status_code == 404   # one answer per task
    # log policy: restrict to non-kube namespaces
    assert client.put(f"/api/clusters/{cid}/log-policy", headers=CSRF, json={"include": ["*"], "exclude": ["kube-*", "smwatch"]}).status_code == 200
    assert client.put(f"/api/clusters/{cid}/log-policy", headers=CSRF, json={"include": ["bad ns"]}).status_code == 422
    assert op.post(q, headers=CSRF, json={"kind": "logs", "namespace": "kube-system", "name": "coredns"}).status_code == 403
    ok = op.post(q, headers=CSRF, json={"kind": "logs", "namespace": "demo", "name": "web-1", "grep": "secret-term"})
    assert ok.status_code == 200
    events = client.get("/api/audit?limit=200").json()
    items = events["items"] if isinstance(events, dict) else events
    actions = {e["action"] for e in items}
    assert {"k8s.logs.denied", "k8s.logs.read", "k8s.log_policy", "k8s.register"} <= actions
    assert all(smwatch_secret not in json.dumps(items) for smwatch_secret in [_k8s_token(r.text)])
    # policy is also delivered to the agent in the report reply
    assert anon.post("/api/k8s-agent/report", json=HEALTHY, headers=auth).json()["log_policy"]["exclude"] == ["kube-*", "smwatch"]


def test_k8s_token_rotation_and_revoke(client):
    sign_in(client)
    anon = TestClient(main.app)
    _, r = _k8s_register(client, anon, "rotate-test")
    old = _k8s_token(r.text)
    cid = next(c["id"] for c in client.get("/api/clusters").json() if c["name"] == "rotate-test")
    h = lambda t: {"Authorization": f"Bearer {t}"}  # noqa: E731
    anon.post("/api/k8s-agent/report", json=HEALTHY, headers=h(old))
    assert client.post(f"/api/clusters/{cid}/rotate-token", headers=CSRF).json()["mode"] == "managed"
    delivered = anon.post("/api/k8s-agent/report", json=HEALTHY, headers=h(old)).json()["rotate_token"]
    assert anon.post("/api/k8s-agent/report", json=HEALTHY, headers=h(delivered)).status_code == 200   # agent switched
    assert anon.post("/api/k8s-agent/report", json=HEALTHY, headers=h(old)).status_code == 401           # old one is dead
    fresh = client.post(f"/api/clusters/{cid}/rotate-token?immediate=true", headers=CSRF).json()["install_token"]
    assert anon.post("/api/k8s-agent/report", json=HEALTHY, headers=h(delivered)).status_code == 401
    assert anon.post("/api/k8s-agent/report", json=HEALTHY, headers=h(fresh)).status_code == 200
    assert client.delete(f"/api/clusters/{cid}", headers=CSRF).json()["deleted"] is True
    assert client.get(f"/api/clusters/{cid}").status_code == 404


# =================================================================== alert message format
def test_alert_messages_are_structured_and_safe():
    from app import monitoring as m
    t = m.format_alert("Server", "alert", "This server (control plane)", ["Process kubelet PID 3937987 CPU 89.8% >= 80.0%", "CPU 91% >= 85%"], at=datetime(2026, 11, 13, 16, 49, tzinfo=timezone.utc))
    assert t.startswith("🟠 <b>ALERT</b> · Server\n<b>This server (control plane)</b>\n• Process kubelet (PID 3937987) CPU 89.8% ≥ 80.0%\n• CPU 91% ≥ 85%")
    assert t.endswith("🕒 13 Nov 2026, 16:49 UTC")
    single = m.format_alert("Service", "down", "API", "connection <refused> & reset", link="https://x.example")
    assert "&lt;refused&gt; &amp; reset" in single and "🔗 https://x.example" in single and "•" not in single
    back = m.format_alert("Server", "recovered", "web", "ok", duration=725)
    assert back.startswith("✅ <b>RECOVERED</b>") and "⏱ Was affected for 12m 5s" in back
    assert m.plain_text(single) == "🔴 DOWN · Service\nAPI\nconnection <refused> & reset\n" + m.plain_text(single).split("\n")[3] + "\n🔗 https://x.example"
    assert m.slack_text(back).startswith("✅ *RECOVERED* · Server\n*web*")
    assert m.human_duration(59) == "59s" and m.human_duration(3661) == "1h 1m" and m.human_duration(90000) == "1d 1h"


def test_telegram_sends_rich_text_and_falls_back_to_plain(monkeypatch):
    import urllib.parse
    from urllib.error import HTTPError
    from io import BytesIO
    from app import monitoring as m
    from app.models import Channel
    sent = []

    class Resp:
        def __init__(self, body): self.body = body
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def read(self): return self.body

    def fake(request, timeout=8):
        fields = dict(urllib.parse.parse_qsl(request.data.decode()))
        sent.append(fields)
        if "parse_mode" in fields and "BAD" in fields["text"]:
            raise HTTPError(request.full_url, 400, "bad", {}, BytesIO(b'{"ok": false, "description": "Bad Request: can\'t parse entities: Unsupported start tag"}'))
        return Resp(b'{"ok": true}')

    monkeypatch.setattr(m, "safe_urlopen", fake)
    channel = Channel(name="t", type="telegram", token="1:abc", chat_id="42")
    assert m.deliver_channel(channel, "<b>hi</b> a &amp; b", rich=True) == (True, "Delivered")
    assert sent[-1]["parse_mode"] == "HTML" and sent[-1]["text"] == "<b>hi</b> a &amp; b"
    assert m.deliver_channel(channel, "BAD <tag> old message", rich=True)[0] is True
    assert "parse_mode" not in sent[-1] and sent[-1]["text"] == "BAD <tag> old message"          # retried as plain text
    assert m.deliver_channel(channel, "plain <text> from a schedule")[0] and "parse_mode" not in sent[-1]


# =================================================================== retention and purge
def _seed_history():
    from datetime import timedelta
    from app.models import AlertEvent, AuditEvent, CheckResult, Incident
    now = datetime.now(timezone.utc)
    with database.SessionLocal() as db:
        for days in (1, 10, 400):
            db.add(CheckResult(target_type="service", target_id=9001, status="up", checked_at=now - timedelta(days=days)))
            db.add(AlertEvent(target_type="service", target_id=9001, severity="info", message="x", created_at=now - timedelta(days=days)))
        db.add(Incident(target_type="service", target_id=9001, target_name="old", title="t", started_at=now - timedelta(days=500), resolved_at=now - timedelta(days=499)))
        db.add(Incident(target_type="service", target_id=9001, target_name="open", title="t", started_at=now - timedelta(days=500)))
        db.add(AuditEvent(actor="old", action="auth.login", ts=now - timedelta(days=400)))
        db.commit()


def test_retention_admin_only_validation_and_manual_purge(client):
    from app.models import AlertEvent, AuditEvent, CheckResult, Incident
    sign_in(client)
    make_user(client, "ret-op@example.com", "operator")
    op = session_for("ret-op@example.com", new_password="operator-pass-12345")
    assert op.get("/api/retention").status_code == 403 and op.post("/api/retention/purge", headers=CSRF, json={"categories": ["checks"]}).status_code == 403
    view = client.get("/api/retention").json()
    assert view["settings"]["days"]["audit"] >= 30 and set(view["stats"]) >= {"checks", "metrics", "alerts", "incidents", "audit", "links", "transient"}
    assert client.put("/api/retention", headers=CSRF, json={"days": {"audit": 5}}).status_code == 422          # the audit log keeps >= 30 days
    assert client.put("/api/retention", headers=CSRF, json={"days": {"checks": 0}}).status_code == 422
    assert client.put("/api/retention", headers=CSRF, json={"days": {"bogus": 5}}).status_code == 422
    assert client.put("/api/retention", headers=CSRF, json={"time": "25:00"}).status_code == 422
    saved = client.put("/api/retention", headers=CSRF, json={"days": {"checks": 30, "alerts": 7}, "frequency": "daily", "time": "02:30"}).json()["settings"]
    assert saved["days"]["checks"] == 30 and saved["days"]["alerts"] == 7 and saved["frequency"] == "daily" and saved["time"] == "02:30"

    _seed_history()
    def count(model, **kw):
        with database.SessionLocal() as db:
            from sqlalchemy import select, func
            return db.scalar(select(func.count()).select_from(model).where(*[getattr(model, k) == v for k, v in kw.items()]))
    assert client.post("/api/retention/purge", headers=CSRF, json={"categories": ["audit"], "older_than_days": 5}).status_code == 422   # too recent for the audit log
    assert client.post("/api/retention/purge", headers=CSRF, json={"categories": ["audit"], "older_than_days": 0}).status_code == 422
    assert client.post("/api/retention/purge", headers=CSRF, json={"categories": ["nonsense"]}).status_code == 422
    r = client.post("/api/retention/purge", headers=CSRF, json={"categories": ["checks", "alerts", "incidents"], "older_than_days": 30}).json()
    assert r["deleted"]["checks"] >= 1 and r["deleted"]["alerts"] >= 1 and r["deleted"]["incidents"] >= 1
    assert count(CheckResult, target_id=9001) == 2 and count(Incident, target_id=9001) == 1                    # only the 400-day row went; the OPEN incident survives
    assert client.post("/api/retention/purge", headers=CSRF, json={"categories": ["audit"], "older_than_days": 365}).json()["deleted"]["audit"] >= 1
    assert client.post("/api/retention/purge", headers=CSRF, json={"categories": ["checks"], "older_than_days": 0}).json()["deleted"]["checks"] >= 2   # 0 = everything
    assert count(CheckResult, target_id=9001) == 0
    actions = {e["action"] for e in client.get("/api/audit?limit=200&category=purge").json()}
    assert {"purge.settings", "purge.manual"} <= actions


def test_scheduled_purge_follows_the_schedule(client):
    from datetime import timedelta
    from app import retention
    from app.models import CheckResult
    sign_in(client)
    client.put("/api/retention", headers=CSRF, json={"auto": True, "frequency": "daily", "time": "03:00", "days": {"checks": 30}})
    now = datetime(2026, 11, 13, 12, 0, tzinfo=timezone.utc)
    cfg = retention.defaults(); cfg.update(auto=True, frequency="daily", time="03:00")
    assert retention.due(cfg, now)                                                         # never ran
    cfg["last_run_at"] = datetime(2026, 11, 13, 3, 5, tzinfo=timezone.utc).isoformat()
    assert not retention.due(cfg, now)                                                     # today's slot already done
    cfg["last_run_at"] = datetime(2026, 11, 12, 3, 5, tzinfo=timezone.utc).isoformat()
    assert retention.due(cfg, now) and not retention.due(cfg, datetime(2026, 11, 13, 2, 0, tzinfo=timezone.utc))   # before 03:00 the slot is yesterday's
    cfg["auto"] = False
    assert not retention.due(cfg, now)
    cfg.update(auto=True, frequency="hourly", last_run_at=(now - timedelta(minutes=30)).isoformat())
    assert not retention.due(cfg, now)
    cfg["last_run_at"] = (now - timedelta(minutes=61)).isoformat()
    assert retention.due(cfg, now)
    cfg.update(frequency="weekly", weekday=0, time="03:00", last_run_at=datetime(2026, 11, 9, 3, 1, tzinfo=timezone.utc).isoformat())   # Mon 9 Nov ran; now is Fri 13 Nov
    assert not retention.due(cfg, now)
    cfg["last_run_at"] = datetime(2026, 11, 2, 3, 1, tzinfo=timezone.utc).isoformat()
    assert retention.due(cfg, now)
    # the worker hook really deletes by the saved retention and records the run
    _seed_history()
    with database.SessionLocal() as db:
        result = retention.run_scheduled(db)
        assert result is not None and result["checks"] >= 1
        from sqlalchemy import select
        assert db.scalar(select(CheckResult).where(CheckResult.target_id == 9001, CheckResult.checked_at < datetime.now(timezone.utc) - timedelta(days=31))) is None
        assert retention.run_scheduled(db) is None                                         # not due again straight away
