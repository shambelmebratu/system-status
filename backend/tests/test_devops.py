"""DevOps: heartbeat monitors and their ping URLs, maintenance windows, SLOs and burn-rate alerts."""
import os
import sys
from datetime import datetime, timedelta, timezone

os.environ.setdefault("ENVIRONMENT", "test"); os.environ.setdefault("JWT_SECRET", "x" * 40); os.environ.setdefault("DATABASE_URL", "sqlite://")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import pytest
from fastapi.testclient import TestClient

from test_api_auth import CSRF, _real_deliver_event, client, fresh_stats_cache, main, sign_in  # noqa: F401
from app import database, devops, monitoring
from app.models import CheckResult, Heartbeat, Service, Slo


@pytest.fixture()
def alerts(monkeypatch):
    sent = []
    monkeypatch.setattr(monitoring, "deliver_event", _real_deliver_event)   # older tests replace it with a no-op
    monkeypatch.setattr(monitoring, "send_alert", lambda message, session, target_type=None, state=None, only_channels=None: (sent.append((target_type, state, message)) or (True, None)))
    return sent


def test_heartbeat_pings_and_lateness(client, alerts):
    sign_in(client)
    hb = client.post("/api/heartbeats", headers=CSRF, json={"name": "Nightly backup", "period_seconds": 3600, "grace_seconds": 300}).json()
    token = hb["ping_url"].rsplit("/", 1)[1]
    assert token.startswith("hb_") and hb["last_status"] == "unknown"
    anon = TestClient(main.app)
    assert anon.get(f"/api/ping/{token}/start").text == "ok\n"
    assert anon.post(f"/api/ping/{token}", content=b"backup done: 12 GB").status_code == 200
    hb = client.get("/api/heartbeats").json()[0]
    assert hb["last_status"] == "up" and hb["last_duration_ms"] is not None and hb["next_due_at"]
    assert anon.get("/api/ping/hb_wrong-token").status_code == 404
    import time; time.sleep(1.1)
    assert anon.post(f"/api/ping/{token}/fail", content=b"pg_dump: connection refused\x00\x1b[31m").status_code == 200
    hb = client.get("/api/heartbeats").json()[0]
    assert hb["last_status"] == "down" and "connection refused" in hb["last_error"] and "\x00" not in hb["last_error"]
    assert alerts[-1][1] == "down" and alerts[-1][0] == "heartbeat"
    pings = client.get(f"/api/heartbeats/{hb['id']}/pings").json()
    assert [p["kind"] for p in pings] == ["fail", "success", "start"]
    time.sleep(1.1)
    anon.get(f"/api/ping/{token}")
    assert client.get("/api/heartbeats").json()[0]["last_status"] == "up" and alerts[-1][1] == "recovered"
    # overdue: the last ping is older than period + grace
    with database.SessionLocal() as db:
        h = db.get(Heartbeat, hb["id"]); h.last_ping_at = datetime.now(timezone.utc) - timedelta(hours=2); h.last_checked_at = None; db.commit()
        devops.check_heartbeats(db)
    hb = client.get("/api/heartbeats").json()[0]
    assert hb["last_status"] == "down" and "No ping for 2 h" in hb["last_error"] and hb["overdue"]
    new = client.post(f"/api/heartbeats/{hb['id']}/new-url", headers=CSRF).json()
    time.sleep(1.1)
    assert anon.get(f"/api/ping/{token}").status_code == 404 and anon.get("/api/ping/" + new["ping_url"].rsplit("/", 1)[1]).status_code == 200


def test_maintenance_holds_back_alerts_and_shows_on_status(client, alerts):
    sign_in(client)
    sid = client.post("/api/services", headers=CSRF, json={"name": "shop", "url": "https://shop.example.com", "public": True}).json()["id"]
    other = client.post("/api/services", headers=CSRF, json={"name": "blog", "url": "https://blog.example.com"}).json()["id"]
    now = datetime.now(timezone.utc)
    w = client.post("/api/maintenance", headers=CSRF, json={"title": "Database upgrade", "starts_at": (now - timedelta(minutes=5)).isoformat(), "ends_at": (now + timedelta(hours=1)).isoformat(),
                                                             "targets": [f"service:{sid}"]}).json()
    assert w["state"] == "active"
    m = monitoring
    with database.SessionLocal() as db:
        for target_id in (sid, other):
            svc = db.get(Service, target_id)
            m.queue_event(db, "service", svc, "critical", m.format_alert("Service", "down", svc.name, "boom"), deliver=True, state="down")
        db.commit()
        events = db.query(m.AlertEvent).order_by(m.AlertEvent.id.desc()).limit(2).all()
    assert any("maintenance window" in (e.delivery_error or "") for e in events) and [a[0] for a in alerts] == ["service"]   # only the other service alerted
    status = TestClient(main.app).get("/api/public/status").json()
    assert status["maintenance"] and status["maintenance"][0]["title"] == "Database upgrade" and status["maintenance"][0]["active"]
    client.post(f"/api/maintenance/{w['id']}/end", headers=CSRF)
    assert client.get("/api/maintenance").json()[0]["state"] == "done"
    bad = client.post("/api/maintenance", headers=CSRF, json={"title": "x", "starts_at": now.isoformat(), "ends_at": (now - timedelta(hours=1)).isoformat()})
    assert bad.status_code == 422


def test_slo_budget_and_burn_alerts(client, alerts):
    sign_in(client)
    sid = client.post("/api/services", headers=CSRF, json={"name": "api", "url": "https://api.example.com"}).json()["id"]
    now = datetime.now(timezone.utc)
    with database.SessionLocal() as db:   # 3 days of 1-minute checks with 0.05 % failures (within a 99.9 % objective) ...
        rows = [CheckResult(target_type="service", target_id=sid, status="down" if i % 2000 == 0 else "up", latency_ms=50, checked_at=now - timedelta(minutes=i + 61)) for i in range(4320)]
        db.add_all(rows); db.commit()
    slo = client.post("/api/slos", headers=CSRF, json={"name": "API availability", "target": f"service:{sid}", "objective": 99.9, "window_days": 30}).json()
    assert slo["state"] == "ok" and 99.9 < slo["sli"] < 100 and 0 < slo["budget_remaining_pct"] < 100 and slo["allowed_downtime_minutes"] == 43.2
    with database.SessionLocal() as db:   # ... then the last hour fails completely: a fast burn
        db.add_all([CheckResult(target_type="service", target_id=sid, status="down", checked_at=now - timedelta(minutes=i)) for i in range(60)]); db.commit()
    from app.stats import clear_cache; clear_cache()
    with database.SessionLocal() as db:
        devops.check_slos(db, force=True)
    assert alerts[-1][1] in ("slo_fast", "slo_exhausted") and "API availability" in alerts[-1][2]
    count = len(alerts)
    with database.SessionLocal() as db:
        devops.check_slos(db, force=True)
    assert len(alerts) == count                                                            # no repeat for the same state
    listed = client.get("/api/slos").json()[0]
    assert listed["burn_1h"] > 14.4 and len(listed["daily"]) == 30
    assert client.post("/api/slos", headers=CSRF, json={"name": "x", "target": "service:99999", "objective": 99}).status_code == 422
    assert any(m["key"] == f"service:{sid}" for m in client.get("/api/monitors").json())
