"""Security features: two-factor sign-in, SSH brute-force detection, pending updates, exposure scans, TLS audits."""
import importlib
import os
import socket
import sys
import threading
import time

os.environ.setdefault("ENVIRONMENT", "test"); os.environ.setdefault("JWT_SECRET", "x" * 40); os.environ.setdefault("DATABASE_URL", "sqlite://")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import pytest
from fastapi.testclient import TestClient

from test_api_auth import CSRF, PW, _real_deliver_event, client, fresh_stats_cache, main, make_user, session_for, sign_in  # noqa: F401
from app import database, mfa, monitoring, netguard, secscan


def test_totp_matches_the_rfc_and_refuses_replays():
    secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"          # RFC 6238 test key "12345678901234567890"
    assert mfa._code(secret, 59 // 30)[-6:] == "287082" and mfa._code(secret, 1111111109 // 30) == "081804"
    now = 1_700_000_000
    code = mfa._code(secret, now // 30)
    step = mfa.verify(secret, code, None, now)
    assert step == now // 30 and mfa.verify(secret, code, step, now) is None                  # the same code twice: refused
    assert mfa.verify(secret, mfa._code(secret, now // 30 - 1), None, now) == now // 30 - 1     # 30 s of clock drift is fine
    assert mfa.verify(secret, mfa._code(secret, now // 30 - 3), None, now) is None
    codes, stored = mfa.new_recovery_codes()
    left = mfa.use_recovery_code(stored, codes[0].upper())
    assert left and mfa.use_recovery_code(left, codes[0]) is None and len(codes) == 10


def _code_for(client):
    setup = client.post("/api/auth/2fa/setup", headers=CSRF).json()
    assert setup["uri"].startswith("otpauth://totp/") and "<svg" in setup["qr_svg"]
    return setup["secret"]


def test_two_factor_sign_in_flow(client):
    sign_in(client)
    make_user(client, "mfa-user@example.com", "operator")
    u = session_for("mfa-user@example.com", new_password="mfa-user-pass-123")
    secret = _code_for(u)
    assert u.post("/api/auth/2fa/enable", headers=CSRF, json={"code": "000000"}).status_code == 422
    codes = u.post("/api/auth/2fa/enable", headers=CSRF, json={"code": mfa._code(secret, int(time.time()) // 30)}).json()["recovery_codes"]
    assert len(codes) == 10 and u.get("/api/auth/me").json()["totp_enabled"]                    # this session was renewed and still works
    fresh = TestClient(main.app)
    step1 = fresh.post("/api/auth/login", json={"email": "mfa-user@example.com", "password": "mfa-user-pass-123"}).json()
    assert step1["mfa_required"] and "smwatch_session" not in fresh.cookies                       # no session from the password alone
    assert fresh.get("/api/dashboard").status_code == 401
    assert fresh.post("/api/auth/mfa", json={"mfa_token": step1["mfa_token"], "code": "123456"}).status_code == 401
    current = mfa._code(secret, int(time.time()) // 30)
    with database.SessionLocal() as db:   # the code used to enable was this step; move on so the replay guard allows a fresh one
        from app.models import User
        acct = db.query(User).filter_by(email="mfa-user@example.com").one(); acct.totp_last_step -= 2; db.commit()
    assert fresh.post("/api/auth/mfa", json={"mfa_token": step1["mfa_token"], "code": current}).status_code == 200
    assert fresh.get("/api/dashboard").status_code == 200
    replay = TestClient(main.app)
    t = replay.post("/api/auth/login", json={"email": "mfa-user@example.com", "password": "mfa-user-pass-123"}).json()["mfa_token"]
    assert replay.post("/api/auth/mfa", json={"mfa_token": t, "code": current}).status_code == 401              # a code works once
    assert replay.post("/api/auth/mfa", json={"mfa_token": t, "code": codes[3]}).status_code == 200             # a recovery code works once
    assert TestClient(main.app).post("/api/auth/mfa", json={"mfa_token": "forged", "code": current}).status_code == 401
    events = [e["detail"] for e in client.get("/api/audit?category=auth").json() if e["actor"] == "mfa-user@example.com"]
    assert any("recovery code (9 left)" in (d or "") for d in events)
    # admin reset for a lost phone; nobody resets their own through user administration
    uid = next(x["id"] for x in client.get("/api/users").json() if x["email"] == "mfa-user@example.com")
    assert client.put(f"/api/users/{uid}", headers=CSRF, json={"reset_2fa": True}).json()["totp_enabled"] is False
    me = client.get("/api/auth/me").json()
    assert client.put(f"/api/users/{me['id']}", headers=CSRF, json={"reset_2fa": True}).status_code == 409


def test_policy_requires_setup(client):
    sign_in(client)
    assert client.put("/api/security/policy", headers=CSRF, json={"require_2fa": "everyone"}).status_code == 409   # admin first
    secret = _code_for(client)
    client.post("/api/auth/2fa/enable", headers=CSRF, json={"code": mfa._code(secret, int(time.time()) // 30)})
    assert client.put("/api/security/policy", headers=CSRF, json={"require_2fa": "everyone"}).status_code == 200
    pol = client.get("/api/security/policy").json()                      # Settings → Sign-in & access: policy + adoption for admins
    assert pol["require_2fa"] == "everyone" and pol["adoption"]["enabled"] >= 1 and pol["adoption"]["total"] >= pol["adoption"]["enabled"]
    try:
        make_user(client, "viewer-2fa@example.com", "viewer")
        v = session_for("viewer-2fa@example.com", new_password="viewer-2fa-pass-1")
        assert v.get("/api/dashboard").json()["detail"] == "MFA_SETUP_REQUIRED" and v.get("/api/auth/me").json()["mfa_setup_required"]
        s = _code_for(v)
        v.post("/api/auth/2fa/enable", headers=CSRF, json={"code": mfa._code(s, int(time.time()) // 30)})
        assert v.get("/api/dashboard").status_code == 200
        assert v.post("/api/auth/2fa/disable", headers=CSRF, json={"password": "viewer-2fa-pass-1", "code": "000000"}).status_code == 403
    finally:
        with database.SessionLocal() as db:   # leave the shared test database without a 2FA requirement
            mfa.set_policy(db, "none", "test"); db.commit()
            from app.models import User
            admin = db.query(User).filter_by(email="admin@example.com").one(); admin.totp_enabled, admin.totp_secret = False, None; db.commit()


def test_ssh_failures_are_parsed_by_the_agent(tmp_path, monkeypatch):
    sys.modules.pop("agent", None)
    monkeypatch.setenv("AGENT_STATE_DIR", str(tmp_path))
    agent = importlib.import_module("agent")
    lines = ["Nov 16 10:00:01 web sshd[1]: Failed password for root from 203.0.113.5 port 4242 ssh2",
             "Nov 16 10:00:02 web sshd[1]: Failed password for invalid user admin from 203.0.113.5 port 4243 ssh2",
             "Nov 16 10:00:03 web sshd[2]: Invalid user oracle from 198.51.100.7 port 5555",
             "Nov 16 10:00:04 web sshd[3]: Connection closed by authenticating user ubuntu 2001:db8::1 port 22 [preauth]",
             "Nov 16 10:00:05 web sshd[4]: Accepted publickey for deploy from 10.0.0.2 port 1 ssh2",
             "Nov 16 10:00:06 web CRON[5]: pam_unix(cron:session): session opened"]
    r = agent.parse_ssh_failures(lines)
    assert r["total"] == 4 and r["ips"] == {"203.0.113.5": 2, "198.51.100.7": 1, "2001:db8::1": 1} and r["users"]["root"] == 1 and r["distinct_ips"] == 3
    outputs = {"dist-upgrade": "Inst openssl [3.0.13-0ubuntu3.1] (3.0.13-0ubuntu3.4 Ubuntu:24.04/noble-security [amd64])\nInst curl [8.5.0-2ubuntu10.1] (8.5.0-2ubuntu10.4 Ubuntu:24.04/noble-updates [amd64])\n"}
    monkeypatch.setattr(agent, "_run", lambda command, timeout=120: (0, outputs["dist-upgrade"]))
    monkeypatch.setattr(agent.shutil, "which", lambda name: "/usr/bin/apt-get" if name == "apt-get" else None)
    monkeypatch.setattr(agent, "_host_path", lambda p: str(tmp_path / p.lstrip("/")))
    (tmp_path / "var/lib/dpkg").mkdir(parents=True); (tmp_path / "var/lib/dpkg/status").write_text("")
    (tmp_path / "run").mkdir(); (tmp_path / "run/reboot-required").write_text(""); (tmp_path / "run/reboot-required.pkgs").write_text("linux-image-6.8\n")
    u = agent.check_updates()
    assert u["manager"] == "apt" and u["total"] == 2 and u["security"] == 1 and u["packages"][0] == {"name": "openssl", "version": "3.0.13-0ubuntu3.4", "security": True}
    assert u["reboot_required"] and u["reboot_packages"] == ["linux-image-6.8"]
    sys.modules.pop("agent", None)


def test_ssh_attack_alert_and_dashboard(client, monkeypatch):
    sign_in(client)
    monkeypatch.setattr(monitoring, "deliver_event", _real_deliver_event)
    anon = TestClient(main.app)
    tok = client.post("/api/enrollments", headers=CSRF, json={}).json()["token"]
    r = anon.post("/api/agent/enroll", headers={"Authorization": f"Bearer {tok}"}, json={"hostname": "bastion", "machine_id": "sec1"}).json()
    auth = {"Authorization": f"Bearer {r['agent_token']}"}
    base = {"cpu": 1, "memory": 1, "disk": 1, "load": 0, "swap": 0, "hostname": "bastion"}
    updates = {"manager": "apt", "total": 7, "security": 3, "packages": [{"name": "openssl", "version": "3.0.13", "security": True}], "reboot_required": True}
    assert anon.post("/api/agent/report", headers=auth, json={**base, "ssh_failures": {"total": 20, "ips": {"203.0.113.5": 18, "198.51.100.7": 2}, "users": {"root": 20}}, "updates": updates}).status_code == 200
    time.sleep(2.1)
    anon.post("/api/agent/report", headers=auth, json={**base, "ssh_failures": {"total": 25, "ips": {"203.0.113.5": 25}, "users": {"admin": 25}}, "updates": updates})
    with database.SessionLocal() as db:
        events = db.query(monitoring.AlertEvent).filter_by(state="ssh_attack").all()
    assert len(events) == 1 and "45 failed SSH logins" in events[0].message and "203.0.113.5 (43)" in events[0].message
    ov = client.get("/api/security/overview").json()
    srv = next(s for s in ov["servers"] if s["id"] == r["server_id"])
    assert srv["ssh_24h"]["total"] == 45 and srv["updates"]["security"] == 3 and srv["updates"]["reboot_required"]
    assert ov["ssh"]["top_ips"][0] == {"ip": "203.0.113.5", "attempts": 43, "servers": 1} and ov["two_factor"]["total"] >= 1
    assert client.get("/api/security/ssh?hours=24").json()["per_server"][0]["name"] == "bastion"


def test_port_scan_finds_risky_ports(monkeypatch):
    monkeypatch.setattr(secscan, "_ip_blocked", lambda ip: None)                 # the "server" is this machine
    monkeypatch.setattr(netguard, "_ip_blocked", lambda ip: None)
    listeners = []
    for port in (0, 0):
        s = socket.socket(); s.bind(("127.0.0.1", 0)); s.listen(); listeners.append(s)
    ports = [s.getsockname()[1] for s in listeners]
    monkeypatch.setitem(secscan.PORTS, ports[0], ("Redis (test)", "critical", "Firewall it."))
    monkeypatch.setitem(secscan.PORTS, ports[1], ("HTTPS (test)", "info", ""))
    try:
        r = secscan.scan_ports("127.0.0.1", ports + [1], timeout=0.5)
    finally:
        for s in listeners: s.close()
    assert [f["port"] for f in r["open"]] == ports and r["grade"] == "F" and r["findings"] == 1
    assert r["open"][0]["risk"] == "critical" and r["checked_ports"] == 3


def test_tls_audit_of_a_real_site():
    try:
        r = secscan.audit_tls("example.com", 443, url="https://example.com")
    except OSError:
        pytest.skip("no network")
    if r.get("error"):
        pytest.skip(r["error"])
    assert r["grade"] in ("A+", "A", "B", "C", "F") and r["versions"]["TLS 1.2"] is True and r["days_left"] > 0 and r["key"]
    with pytest.raises(netguard.BlockedTargetError):
        secscan.audit_tls("169.254.169.254", 443)
