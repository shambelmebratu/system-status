import os

os.environ.update(ENVIRONMENT="test", JWT_SECRET="x" * 40, ADMIN_PASSWORD="correct-horse-battery", DATABASE_URL="sqlite://")

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
    new = client.post(f"/api/servers/{sid}/rotate-token", headers=CSRF).json()["install_token"]
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
