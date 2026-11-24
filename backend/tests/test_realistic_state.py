"""What the dashboard shows matches the real state: findings that describe a condition close when it is gone, pausing a monitor
closes its open incident, and the worker's alert thread sends queued alerts without waiting for the check loop."""
import os
import sys
from datetime import datetime, timezone

from fastapi.testclient import TestClient

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from test_api_auth import CSRF, client, main, sign_in  # noqa: F401
from app import database, monitoring, threats
from app.models import AlertEvent, Incident, SecurityFinding, Server


def _server(client, name):
    tok = client.post("/api/enrollments", headers=CSRF, json={}).json()["token"]
    return TestClient(main.app).post("/api/agent/enroll", headers={"Authorization": f"Bearer {tok}"}, json={"hostname": name, "machine_id": f"m-{name}"}).json()["server_id"]


def _open(db, sid, prefix):
    return [f.key for f in db.query(SecurityFinding).filter(SecurityFinding.server_id == sid, SecurityFinding.key.like(prefix + "%"), SecurityFinding.resolved_at.is_(None))]


def test_condition_findings_close_when_the_condition_is_gone(client):
    sign_in(client)
    sid = _server(client, "state-box")
    now = datetime.now(timezone.utc)
    with database.SessionLocal() as db:
        server = db.get(Server, sid)
        ok, bad = [{"id": "ssh_passwords", "ok": True, "title": "SSH passwords off"}], [{"id": "ssh_passwords", "ok": False, "title": "SSH passwords off", "severity": "high"}]
        threats.hardening_weakened(db, server, bad, ok, now, -1)
        threats.ports_opened(db, server, [{"port": 6379, "all_interfaces": True, "process": "redis"}], [], now, -1)
        db.commit()
        assert len(_open(db, sid, "weakened:")) == 1 and _open(db, sid, "port_opened:") == ["port_opened:6379:redis"]
        threats.hardening_weakened(db, server, ok, bad, now, -1)                            # turned back on
        threats.ports_opened(db, server, [{"port": 6379, "all_interfaces": False}], [], now, -1)   # back to localhost only
        db.commit()
        assert _open(db, sid, "weakened:") == [] and _open(db, sid, "port_opened:") == []


def test_pausing_monitoring_closes_the_open_incident(client):
    sign_in(client)
    sid = _server(client, "pause-inc")
    with database.SessionLocal() as db:
        db.add(Incident(target_type="server", target_id=sid, target_name="pause-inc", severity="critical", title="pause-inc is down", detail="No agent heartbeat", started_at=datetime.now(timezone.utc)))
        db.commit()
    assert client.post(f"/api/servers/{sid}/pause", headers=CSRF, json={"mode": "monitor", "minutes": 30}).status_code == 200
    with database.SessionLocal() as db:
        inc = db.query(Incident).filter(Incident.target_type == "server", Incident.target_id == sid).one()
        assert inc.resolved_at is not None and "monitoring paused" in inc.detail


def test_worker_queues_alerts_for_its_delivery_thread(client, monkeypatch):
    sign_in(client)
    sid = _server(client, "deliver-box")
    sent = []
    monkeypatch.setattr(monitoring, "deliver_event", lambda event, session: (sent.append(event.id), setattr(event, "sent", True)))
    monkeypatch.setattr(monitoring, "_background_delivery", True)
    monitoring._alert_wake.clear()
    with database.SessionLocal() as db:
        monitoring.queue_event(db, "server", db.get(Server, sid), "critical", "test", deliver=True)
        db.commit()
        mine = db.query(AlertEvent).filter(AlertEvent.target_type == "server", AlertEvent.target_id == sid).order_by(AlertEvent.id.desc()).first().id
        assert sent == [] and monitoring._alert_wake.is_set()          # the check loop never waits on a channel
        monitoring.retry_pending_alerts(db)                             # what the delivery thread runs every second
        db.commit()
        assert mine in sent and db.query(AlertEvent).filter(AlertEvent.id == mine).one().sent
