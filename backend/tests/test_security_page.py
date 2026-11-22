"""The redesigned Security page's endpoints: one finding by id, and the activity timeline."""
import json
import os
import sys
from datetime import datetime, timedelta, timezone

os.environ.setdefault("ENVIRONMENT", "test"); os.environ.setdefault("JWT_SECRET", "x" * 40); os.environ.setdefault("DATABASE_URL", "sqlite://")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from test_api_auth import CSRF, client, fresh_stats_cache, sign_in  # noqa: F401
from app import database, secscan
from app.models import AlertEvent, Cluster, SecurityFinding, Server


def test_finding_detail_and_activity_timeline(client):
    sign_in(client)
    now = datetime.now(timezone.utc)
    with database.SessionLocal() as db:
        a = Server(name="timeline-a", host="203.0.113.40", monitor_mode="push"); b = Server(name="timeline-b", host="203.0.113.41", monitor_mode="push")
        c = Cluster(name="timeline-k8s", enabled=True)
        db.add_all([a, b, c]); db.flush()
        shell = SecurityFinding(server_id=a.id, key="t1", source="agent", kind="web_shell", severity="critical", title="Possible web shell: x.php", detail="d", evidence=json.dumps({"path": "/var/www/x.php"}),
                                first_seen=now - timedelta(hours=2), last_seen=now)
        old = SecurityFinding(server_id=b.id, key="t2", source="agent", kind="process_tunnel", severity="high", title="Tunnel: ngrok", detail="", evidence="{}",
                              first_seen=now - timedelta(days=20), last_seen=now - timedelta(hours=1), resolved_at=now - timedelta(hours=1))
        db.add_all([shell, old]); db.flush()
        db.add(AlertEvent(target_type="server", target_id=a.id, severity="critical", message="<b>🚨 POSSIBLE COMPROMISE</b>\nPossible web shell: x.php", state="threat", sent=True))
        secscan.store(db, "ports", c, "cluster", {"address": "198.51.100.9", "open": [], "grade": "A", "findings": 0}, now)
        db.commit()
        ids = {"a": a.id, "b": b.id, "shell": shell.id, "old": old.id}
    r = client.get(f"/api/security/findings/{ids['shell']}")
    assert r.status_code == 200 and r.json()["title"] == "Possible web shell: x.php" and r.json()["server"]["name"] == "timeline-a" and r.json()["evidence"]["path"] == "/var/www/x.php"
    assert client.get("/api/security/findings/999999").status_code == 404
    client.post(f"/api/security/findings/{ids['shell']}/acknowledge", headers=CSRF, json={"note": "pentest"})
    items = client.get("/api/security/activity?days=7").json()
    mine = [i for i in items if (i.get("server") or {}).get("id") in (ids["a"], ids["b"]) or "timeline-k8s" in i["title"]]
    kinds = {(i["type"], i.get("finding_id")) for i in mine}
    assert ("found", ids["shell"]) in kinds and ("acknowledged", ids["shell"]) in kinds and ("resolved", ids["old"]) in kinds
    assert ("found", ids["old"]) not in kinds                                                 # found 20 days ago: outside the 7 days
    assert any(i["type"] == "alert" and i["sent"] and i["title"] == "Possible web shell: x.php" for i in mine)
    assert any(i["type"] == "scan" and "cluster timeline-k8s" in i["title"] for i in mine)      # clusters by name, not "#id"
    assert any(i["type"] == "action" and i["title"] == "Finding acknowledged" for i in items)
    assert [i["at"] for i in items] == sorted((i["at"] for i in items), reverse=True)          # newest first
    ack = next(i for i in mine if i["type"] == "acknowledged")
    assert ack["actor"] == "admin@example.com" and ack["detail"] == "pentest"
    only_b = client.get(f"/api/security/activity?days=7&server={ids['b']}").json()
    assert only_b and all((i.get("server") or {}).get("id") == ids["b"] for i in only_b)      # the server filter applies
    assert client.get("/api/security/activity?days=91").status_code == 422
