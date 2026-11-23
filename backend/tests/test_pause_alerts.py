"""Pausing monitors, millisecond timeouts, security alert settings, and Docker / Kubernetes ports in the exposure scan."""
import json
import os
import sys
from datetime import datetime, timedelta, timezone

os.environ.setdefault("ENVIRONMENT", "test"); os.environ.setdefault("JWT_SECRET", "x" * 40); os.environ.setdefault("DATABASE_URL", "sqlite://")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from fastapi.testclient import TestClient

from test_api_auth import CSRF, _real_deliver_event, client, fresh_stats_cache, main, sign_in  # noqa: F401
from app import database, monitoring, secalerts, secscan
from app.models import AlertEvent, AuditEvent, Channel, CheckResult, Cluster, Server, Service

WEB_IPS = [{"iface": "eth0", "ip": "10.1.2.3"}]
BASE = {"cpu": 1, "memory": 1, "disk": 1, "load": 0, "swap": 0, "agent_version": "2.18.0", "capabilities": ["logs", "process"]}


def _enroll(client, anon, name):
    tok = client.post("/api/enrollments", headers=CSRF, json={}).json()["token"]
    r = anon.post("/api/agent/enroll", headers={"Authorization": f"Bearer {tok}"}, json={"hostname": name, "machine_id": f"m-{name}"}).json()
    return r["server_id"], {"Authorization": f"Bearer {r['agent_token']}"}


def _report(anon, auth, **extra):
    import time
    r = anon.post("/api/agent/report", headers=auth, json={**BASE, **extra})
    assert r.status_code == 200, r.text
    time.sleep(2.05)                                                                       # agent_min_report_seconds


def test_pause_a_service_and_resume(client, monkeypatch):
    sign_in(client)
    probed = []
    monkeypatch.setattr(monitoring, "probe_service", lambda s, force_cert=False: (probed.append(s.id), {"status": "down", "http_status": 500, "latency_ms": 5.0, "error": "boom"})[1])
    monkeypatch.setattr(monitoring, "SessionLocal", database.SessionLocal)
    svc = client.post("/api/services", headers=CSRF, json={"name": "pausable", "url": "https://example.org", "confirm_checks": 1}).json()["id"]
    # 1. pause monitoring for an hour: the worker neither checks it nor alerts
    r = client.post(f"/api/services/{svc}/pause", headers=CSRF, json={"mode": "monitor", "minutes": 60, "reason": "migration"})
    assert r.status_code == 200 and r.json()["paused"] == "monitor" and r.json()["paused_by"] == "admin@example.com" and r.json()["pause_reason"] == "migration"
    monitoring.run_once()
    assert svc not in probed
    with database.SessionLocal() as db:
        assert db.query(CheckResult).filter_by(target_type="service", target_id=svc).count() == 0
        assert db.query(AuditEvent).filter_by(action="service.pause").one().detail.startswith("pausable: monitoring and alerts paused until")
    # 2. editing the service keeps the pause
    edited = client.put(f"/api/services/{svc}", headers=CSRF, json={"name": "pausable", "url": "https://example.org", "confirm_checks": 1}).json()
    assert edited["paused"] == "monitor"
    # 3. "alerts" mode: checked, the failure is recorded, the alert is not sent
    client.post(f"/api/services/{svc}/pause", headers=CSRF, json={"mode": "alerts"})
    monkeypatch.setattr(monitoring, "deliver_event", _real_deliver_event)
    monitoring.run_once()
    assert svc in probed
    with database.SessionLocal() as db:
        assert db.get(Service, svc).last_status == "down"
        event = db.query(AlertEvent).filter_by(target_type="service", target_id=svc, state="down").one()
        assert not event.sent and "paused" in event.delivery_error and event.delivery_attempts == 10      # recorded, never retried
    # 4. resume
    resumed = client.post(f"/api/services/{svc}/resume", headers=CSRF).json()
    assert resumed["paused"] is None and resumed["pause_mode"] is None
    # 5. validation: a time in the past, an unknown mode, an unknown kind
    assert client.post(f"/api/services/{svc}/pause", headers=CSRF, json={"until": "2020-01-01T00:00:00Z"}).status_code == 422
    assert client.post(f"/api/services/{svc}/pause", headers=CSRF, json={"mode": "forever"}).status_code == 422
    assert client.post(f"/api/widgets/{svc}/pause", headers=CSRF, json={}).status_code == 404


def test_pause_expires_by_itself_and_pauses_push_agents(client):
    sign_in(client)
    anon = TestClient(main.app)
    sid, auth = _enroll(client, anon, "paused-box")
    assert client.post(f"/api/servers/{sid}/pause", headers=CSRF, json={"mode": "monitor"}).json()["paused_until"] is None      # until resumed
    r = anon.post("/api/agent/report", headers=auth, json={"cpu": 99, "memory": 99, "disk": 99, "load": 0, "swap": 0, "hostname": "paused-box", "ips": WEB_IPS})
    assert r.status_code == 200 and r.json()["status"] == "paused"                                    # the agent stays connected
    with database.SessionLocal() as db:
        server = db.get(Server, sid)
        assert server.last_seen_at is not None and "cpu" not in json.loads(server.last_metrics or "{}")       # nothing evaluated or stored
        server.paused_until = datetime.now(timezone.utc) - timedelta(seconds=1)                        # the pause ran out
        db.commit()
    with database.SessionLocal() as db:
        monitoring.expire_pauses(db); db.commit()
        server = db.get(Server, sid)
        assert server.pause_mode is None and server.last_status == "unknown"
        assert db.query(AuditEvent).filter_by(action="server.resume", actor="system").count() == 1


def test_timeout_in_milliseconds(client):
    sign_in(client)
    svc = client.post("/api/services", headers=CSRF, json={"name": "fast-api", "url": "https://example.org", "timeout_ms": 250}).json()
    assert svc["timeout_ms"] == 250 and svc["timeout_ms_effective"] == 250
    legacy = client.post("/api/services", headers=CSRF, json={"name": "old-client", "url": "https://example.org", "timeout_seconds": 3}).json()
    assert legacy["timeout_ms"] == 3000 and legacy["timeout_ms_effective"] == 3000                    # older clients still work
    default = client.post("/api/services", headers=CSRF, json={"name": "default", "url": "https://example.org"}).json()
    assert default["timeout_ms"] is None and default["timeout_ms_effective"] == 10000
    assert client.post("/api/services", headers=CSRF, json={"name": "x", "url": "https://example.org", "timeout_ms": 10}).status_code == 422


def test_security_alert_settings(client, monkeypatch):
    sign_in(client)
    with database.SessionLocal() as db:
        db.query(Channel).delete(); db.commit()
    tg = {"type": "telegram", "token": "1234567890:abcdefghij", "chat_id": "42"}
    ops = client.post("/api/channels", headers=CSRF, json={"name": "ops", **tg}).json()["id"]
    sec = client.post("/api/channels", headers=CSRF, json={"name": "security", **tg}).json()["id"]
    view = client.get("/api/security/alerts").json()
    assert view["enabled"] and view["threat_severity"] == "high" and all(view["categories"].values()) and {c["name"] for c in view["available_channels"]} == {"ops", "security"}
    assert {k["id"] for k in view["kinds"]} >= {"threat", "changes", "ssh_breach", "ssh_attack", "exposure", "kubernetes"}
    body = {**{k: view[k] for k in ("enabled", "threat_severity", "ssh_attack_threshold", "ssh_success_after_failures", "daily_login_alert")},
            "channels": [sec], "categories": {"ssh_new": False}, "ssh_attack_threshold": 50}
    saved = client.put("/api/security/alerts", headers=CSRF, json=body).json()
    assert saved["channels"] == [sec] and saved["categories"]["ssh_new"] is False and saved["categories"]["threat"] is True and saved["ssh_attack_threshold"] == 50
    with database.SessionLocal() as db:
        assert "ssh_new off" in db.query(AuditEvent).filter_by(action="security.alerts").one().detail
    got = []
    monkeypatch.setattr(monitoring, "deliver_channel", lambda channel, text, rich=False: (got.append(channel.name), (True, "Delivered"))[1])
    with database.SessionLocal() as db:
        server = Server(name="sec-box", host="", monitor_mode="push"); db.add(server); db.flush()
        for state in ("threat", "ssh_login_new", "down"):
            got.clear()
            event = AlertEvent(target_type="server", target_id=server.id, severity="warning", message="m", state=state); db.add(event); db.flush()
            _real_deliver_event(event, db)
            if state == "threat":
                assert got == ["security"] and event.sent                                              # security alerts go to the security channel only
            elif state == "ssh_login_new":
                assert got == [] and "turned off" in event.delivery_error and event.delivery_attempts == 10
            else:
                assert sorted(got) == ["ops", "security"]                                              # ordinary alerts are unchanged
        db.commit()
    assert client.post("/api/security/alerts/test", headers=CSRF).json()["sent"] is True
    recent = client.get("/api/security/alerts").json()["recent"]
    assert recent[0]["kind"] in ("ssh_new", "threat") and recent[0]["target"] == "sec-box"
    assert client.put("/api/security/alerts", headers=CSRF, json={**body, "channels": [99999]}).status_code == 422
    assert client.put("/api/security/alerts", headers=CSRF, json={**body, "categories": {"bogus": True}}).status_code == 422
    # all security alerts off
    client.put("/api/security/alerts", headers=CSRF, json={**body, "enabled": False})
    with database.SessionLocal() as db:
        assert secalerts.blocked(db, "ssh_attack", "server").startswith("Not sent: security alerts are turned off")
        assert secalerts.blocked(db, "down", "server") is None
        box = db.query(Server).filter_by(name="sec-box").one()
        db.query(AlertEvent).filter_by(target_type="server", target_id=box.id).delete(); db.delete(box); db.commit()      # leave no records for other tests


def test_docker_and_kubernetes_ports_are_scanned(client, monkeypatch):
    sign_in(client)
    anon = TestClient(main.app)
    sid, auth = _enroll(client, anon, "k8s-node-1")
    scan = {"checked_at": "2026-11-22T10:00:00+00:00", "findings": [], "authorized_keys": [], "hardening": [],
            "listening": [{"port": 9100, "address": "0.0.0.0", "all_interfaces": True, "process": "node_exporter"}],
            "published": [{"port": 16379, "private_port": 6379, "container": "cache", "image": "redis:7"}, {"port": 8081, "private_port": 80, "container": "web", "image": "nginx"}]}
    _report(anon, auth, hostname="k8s-node-1", ips=[{"iface": "eth0", "ip": "203.0.113.20"}], security=scan)
    with database.SessionLocal() as db:
        cluster = Cluster(name="prod", enabled=True, summary=json.dumps({
            "exposed": [{"namespace": "shop", "name": "api", "type": "NodePort", "ports": [{"port": 5432, "node_port": 31432, "target": "5432"}], "external": []},
                        {"namespace": "shop", "name": "front", "type": "LoadBalancer", "ports": [{"port": 443, "node_port": 30443, "target": "8443"}], "external": ["198.51.100.9"]}],
            "node_addresses": [{"name": "k8s-node-1", "internal": "10.0.0.5", "external": "203.0.113.20", "ready": True}]}))
        db.add(cluster); db.commit(); cid = cluster.id
        server = db.get(Server, sid)
        extra = secscan.server_extra_ports(server)
    assert set(extra) == {9100, 16379, 8081, 31432, 30443}
    probed = {}
    OPEN = {("203.0.113.20", 16379), ("203.0.113.20", 31432), ("203.0.113.20", 8081), ("198.51.100.9", 443)}
    monkeypatch.setattr(secscan, "_probe", lambda address, port, timeout: probed.setdefault(address, set()).add(port) or (address, port) in OPEN)
    monkeypatch.setattr(secscan, "validate_host", lambda host: None)
    with database.SessionLocal() as db:
        result = secscan.run_server_scan(db.get(Server, sid))
    found = {f["port"]: f for f in result["open"]}
    assert set(found) == {16379, 31432, 8081} and {22, 16379, 31432} <= probed["203.0.113.20"]    # common ports plus the extra ones
    assert found[16379]["risk"] == "critical" and "Redis" in found[16379]["service"] and "Docker container cache" in found[16379]["service"]   # risky as what runs inside
    assert found[31432]["risk"] == "critical" and "NodePort shop/api" in found[31432]["service"] and found[31432]["source"] == "kubernetes"
    assert found[8081]["risk"] == "medium" and "ufw" in found[8081]["advice"] and result["grade"] == "F"
    # the cluster itself: NodePorts on one node, the LoadBalancer's external address with the service port
    with database.SessionLocal() as db:
        c = db.get(Cluster, cid)
        r = secscan.run_cluster_scan(c)
        secscan.store(db, "ports", c, "cluster", r, datetime.now(timezone.utc)); db.commit()
    assert {(f["address"], f["port"]) for f in r["open"]} == {("203.0.113.20", 31432), ("198.51.100.9", 443)}
    row = next(c for c in client.get("/api/security/overview").json()["clusters"] if c["id"] == cid)
    assert row["name"] == "prod" and row["scan"]["grade"] == "F" and len(row["exposed"]) == 2
    with database.SessionLocal() as db:
        assert db.query(AlertEvent).filter_by(target_type="cluster", target_id=cid, state="security_finding").count() == 1
    with database.SessionLocal() as db:
        empty = Cluster(name="old-agent", enabled=True, summary=json.dumps({"nodes_total": 1}))
        assert secscan.cluster_targets(empty) == ([], "Needs the Kubernetes agent 1.4 or newer")
