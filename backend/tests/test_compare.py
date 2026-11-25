"""Security → Compare: this hour / day / week / month against the one before, from hourly snapshots (state) and event tables (events)."""
import json
from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient

from test_api_auth import CSRF, client, main, sign_in  # noqa: F401
from app import database, secsnap
from app.models import SecurityFinding, SecuritySnapshot, SshFailureSample, SshLoginEvent


def _enroll(client, name):
    tok = client.post("/api/enrollments", headers=CSRF, json={}).json()["token"]
    r = TestClient(main.app).post("/api/agent/enroll", headers={"Authorization": f"Bearer {tok}"}, json={"hostname": name, "machine_id": f"cmp-{name}"}).json()
    return r["server_id"]


def test_day_to_day_compares_state_and_events(client):
    sign_in(client)
    sid = _enroll(client, "cmp-box")
    now = datetime.now(timezone.utc)
    with database.SessionLocal() as db:
        # yesterday: 3 critical threats open, 5 updates missing (the snapshot taken a day ago)
        db.add(SecuritySnapshot(ts=now - timedelta(days=1, minutes=5), data=json.dumps({"servers": {str(sid): {"critical": 3, "high": 0, "unreviewed": 3, "hardening_failed": 2,
                                                                                                              "updates": 5, "risky_ports": 1, "verified": 0, "untrusted": 1}}})))
        # today: one new critical finding (open), one resolved; yesterday: two new high findings
        db.add(SecurityFinding(server_id=sid, key="c1", kind="process_miner", severity="critical", title="miner", detail="", evidence="{}", source="agent",
                               first_seen=now - timedelta(hours=2), last_seen=now))
        db.add(SecurityFinding(server_id=sid, key="c2", kind="web_shell", severity="high", title="old shell", detail="", evidence="{}", source="agent",
                               first_seen=now - timedelta(hours=30), last_seen=now - timedelta(hours=3), resolved_at=now - timedelta(hours=3)))
        db.add(SecurityFinding(server_id=sid, key="c3", kind="web_shell", severity="high", title="other shell", detail="", evidence="{}", source="agent",
                               first_seen=now - timedelta(hours=28), last_seen=now - timedelta(hours=27), resolved_at=now - timedelta(hours=27)))
        db.add_all([SshFailureSample(server_id=sid, ts=now - timedelta(hours=1), total=30), SshFailureSample(server_id=sid, ts=now - timedelta(hours=26), total=10)])
        db.add(SshLoginEvent(server_id=sid, ts=now - timedelta(hours=1), ip="198.51.100.7", user="root", method="publickey", kind="login", new_source=True, failures_before=0))
        db.commit()
    r = client.get(f"/api/security/compare?period=day&server={sid}").json()
    cur, prev = r["current"], r["previous"]
    assert cur["events"]["new_critical"] == 1 and prev["events"]["new_high"] == 2
    assert cur["events"]["resolved"] == 1 and prev["events"]["resolved"] == 1
    assert cur["events"]["ssh_failed"] == 30 and prev["events"]["ssh_failed"] == 10
    assert cur["events"]["ssh_logins"] == 1 and cur["events"]["ssh_new_sources"] == 1
    assert prev["state"]["critical"] == 3 and prev["state"]["updates"] == 5 and prev["snapshot_at"]          # from the snapshot
    assert cur["state"]["critical"] == 1                                                                   # measured now
    row = next(s for s in r["servers"] if s["id"] == sid)
    assert row["then"]["critical"] == 3 and row["now"]["critical"] == 1
    assert len(r["series"]) == 14 and sum(p["ssh_failed"] for p in r["series"]) == 40


def test_no_snapshot_yet_says_so_and_other_periods_work(client):
    sign_in(client)
    for period, points in (("hour", 24), ("week", 12), ("month", 12)):
        r = client.get(f"/api/security/compare?period={period}&server=nothing-matches-this").json()
        assert r["previous"]["state"] is None and len(r["series"]) == points
    assert client.get("/api/security/compare?period=year").status_code == 422


def test_snapshots_are_hourly_and_old_ones_are_thinned():
    now = datetime.now(timezone.utc)
    with database.SessionLocal() as db:
        db.query(SecuritySnapshot).delete(); db.commit()
        assert secsnap.take(db, now) is True and secsnap.take(db, now + timedelta(minutes=10)) is False and secsnap.take(db, now + timedelta(minutes=60)) is True
        old_day = now - timedelta(days=40)
        db.add_all([SecuritySnapshot(ts=old_day.replace(hour=h, minute=0), data="{}") for h in (1, 2, 3)] + [SecuritySnapshot(ts=now - timedelta(days=500), data="{}")])
        db.commit()
        secsnap.prune(db, now); db.commit()
        left = [s.ts for s in db.query(SecuritySnapshot).all()]
        assert len([t for t in left if (now - (t if t.tzinfo else t.replace(tzinfo=timezone.utc))).days >= 39]) == 1      # one per old day, none older than 400 days
