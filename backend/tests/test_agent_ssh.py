"""SSH activity on the agent: utmp/wtmp parsing, shell history parsing and secret masking (temp files only)."""
import importlib
import json
import os
import socket
import struct
import sys
import time

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
UTMP = struct.Struct("<hhi32s4s32s256shhiii16s20s")


def record(kind, pid, tty, user, host, ts, ip=""):
    addr = socket.inet_pton(socket.AF_INET, ip) + b"\0" * 12 if ip else b"\0" * 16
    return UTMP.pack(kind, 0, pid, tty.encode(), b"", user.encode(), host.encode(), 0, 0, 0, ts, 0, addr, b"\0" * 20)


@pytest.fixture()
def agent(tmp_path, monkeypatch):
    root = tmp_path / "host"
    for d in ("run", "var/log", "etc", "root", "home/alice", "home/bob", "home/eve/.local/share/fish"):
        (root / d).mkdir(parents=True)
    monkeypatch.setenv("AGENT_HOST_ROOT", str(root))
    monkeypatch.setenv("AGENT_LOGS", "on")
    monkeypatch.delenv("AGENT_SSH", raising=False)
    monkeypatch.setenv("AGENT_STATE_DIR", str(tmp_path / "state"))
    sys.modules.pop("agent", None)
    module = importlib.import_module("agent")
    monkeypatch.setattr(module, "IS_MAC", False)
    module.ROOT_FOR_TEST = root
    yield module
    sys.modules.pop("agent", None)


def test_active_sessions_and_count(agent, monkeypatch):
    me = os.getpid()
    now = int(time.time())
    (agent.ROOT_FOR_TEST / "run/utmp").write_bytes(
        record(2, 0, "~", "reboot", "6.1.0", now - 9000)
        + record(7, me, "pts/0", "alice", "203.0.113.7", now - 600, "203.0.113.7")
        + record(7, me, "pts/1", "root", "", now - 60, "198.51.100.2")          # address only in ut_addr_v6
        + record(7, me, "tty1", "bob", "", now - 50)                             # local console: not SSH
        + record(7, me, "pts/2", "carol", ":0", now - 40)                        # desktop: not SSH
        + record(7, 999999, "pts/3", "mallory", "192.0.2.9", now - 30)           # stale entry (process gone)
        + record(8, 0, "pts/4", "", "", now - 20))
    monkeypatch.setattr(agent, "_pid_alive", lambda pid: pid == me)
    sessions, note = agent.ssh_sessions()
    assert note is None
    assert [(s["user"], s["ip"], s["tty"]) for s in sessions] == [("alice", "203.0.113.7", "pts/0"), ("root", "198.51.100.2", "pts/1")]
    assert agent.ssh_count() == 2
    agent.apply_policy({"docker": {"enabled": True, "include": ["*"], "exclude": []}, "journal": {"enabled": True, "units": ["*"]}, "files": {"enabled": True, "allow": None}, "ssh": {"enabled": False, "history": False}})
    assert agent.ssh_count() is None
    with pytest.raises(ValueError, match="policy"):
        agent.ssh_answer("sessions", 100)


def test_login_history_pairs_logins_logouts_and_reboots(agent, monkeypatch):
    t = 1_700_000_000
    (agent.ROOT_FOR_TEST / "var/log/wtmp").write_bytes(
        record(7, 10, "pts/0", "alice", "203.0.113.7", t)
        + record(8, 10, "pts/0", "", "", t + 300)
        + record(7, 11, "pts/1", "root", "198.51.100.2", t + 400)
        + record(7, 12, "tty1", "bob", "", t + 450)                              # console login: ignored
        + record(2, 0, "~", "reboot", "6.1", t + 1000)                          # crash/reboot closes root's session
        + record(7, 13, "pts/0", "alice", "203.0.113.8", t + 2000))              # still open
    monkeypatch.setattr(agent, "_pid_alive", lambda pid: pid == 13)
    logins, note = agent.ssh_logins()
    assert note is None
    assert [(r["user"], r["ip"], r["login"], r["logout"], r["end"]) for r in logins] == [
        ("alice", "203.0.113.8", t + 2000, None, "active"),
        ("root", "198.51.100.2", t + 400, t + 1000, "reboot"),
        ("alice", "203.0.113.7", t, t + 300, "logout"),
    ]
    answer = json.loads(agent.fetch_logs({"source": "ssh", "target": "sessions"})[0])
    assert set(answer) >= {"sessions", "logins", "notes", "now", "history_available"} and len(answer["logins"]) == 3


def test_wtmpdb_is_used_when_present(agent, monkeypatch):
    import sqlite3
    (agent.ROOT_FOR_TEST / "var/lib/wtmpdb").mkdir(parents=True)
    with sqlite3.connect(agent.ROOT_FOR_TEST / "var/lib/wtmpdb/wtmp.db") as db:
        db.execute("CREATE TABLE wtmp(ID INTEGER PRIMARY KEY, Type INTEGER, User TEXT, Login INTEGER, Logout INTEGER, TTY TEXT, RemoteHost TEXT, Service TEXT)")
        db.execute("INSERT INTO wtmp VALUES (1, 3, 'deploy', 1700000000000000, 1700000600000000, 'pts/0', '203.0.113.5', 'sshd')")
        db.execute("INSERT INTO wtmp VALUES (2, 3, 'reboot', 1700000000000000, NULL, '~', '', '')")
    logins, note = agent.ssh_logins()
    assert note is None and logins == [{"user": "deploy", "login": 1700000000, "logout": 1700000600, "tty": "pts/0", "ip": "203.0.113.5", "end": "logout"}]


def test_shell_history_newest_first_with_timestamps_and_masking(agent):
    root = agent.ROOT_FOR_TEST
    (root / "etc/passwd").write_text("root:x:0:0:root:/root:/bin/bash\nalice:x:1000:1000::/home/alice:/bin/zsh\nbob:x:1001:1001::/home/bob:/bin/bash\n"
                                     "eve:x:1002:1002::/home/eve:/usr/bin/fish\nwww-data:x:33:33::/var/www:/usr/sbin/nologin\n")
    (root / "root/.bash_history").write_text("#1700000000\napt update\n#1700000100\nexport DB_PASSWORD=hunter2\n"
                                             "mysql -u root -pS3cret! shop\ncurl -H 'Authorization: Bearer abc.def.ghi' https://api\n"
                                             "git clone https://bob:ghp_abcdefghijklmnop1234@github.com/x/y\nls -la\n")
    (root / "home/alice/.zsh_history").write_text(": 1700000200:0;docker login -u me --password s3cr3t\n: 1700000300:0;echo one \\\ntwo\n: 1700000400:0;htop\n")
    (root / "home/eve/.local/share/fish/fish_history").write_text("- cmd: systemctl status nginx\n  when: 1700000500\n- cmd: sshpass -p topsecret ssh host\n  when: 1700000600\n")
    os.symlink("/etc/shadow", root / "home/bob/.bash_history")          # a history "file" pointing elsewhere is never followed
    result = agent.shell_history(100)
    by_user = {u["user"]: u for u in result["users"]}
    assert set(by_user) == {"root", "alice", "eve"}
    root_cmds = [c["cmd"] for c in by_user["root"]["commands"]]
    assert root_cmds[0] == "ls -la" and root_cmds[-1] == "apt update"                                      # newest first
    assert by_user["root"]["commands"][-1]["ts"] == 1700000000 and by_user["root"]["commands"][0]["ts"] is None
    text = json.dumps(result)
    for secret in ("hunter2", "S3cret!", "abc.def.ghi", "ghp_abcdefghijklmnop1234", "s3cr3t", "topsecret"):
        assert secret not in text, secret
    assert "export DB_PASSWORD=***" in root_cmds and "mysql -u root -p*** shop" in root_cmds
    assert [c["cmd"] for c in by_user["alice"]["commands"]] == ["htop", "echo one \ntwo", "docker login -u me --password ***"]
    assert by_user["eve"]["shell"] == "fish" and by_user["eve"]["commands"][1] == {"cmd": "systemctl status nginx", "ts": 1700000500}
    assert len(agent.shell_history(2)["users"][0]["commands"]) == 2


def test_redaction_keeps_ordinary_commands_intact(agent):
    for command in ("ls -la /var/log", "docker ps -a", "kubectl get pods -n prod", "grep -p foo file", "ssh -p 2222 admin@host", "tail -f /var/log/syslog"):
        assert agent.redact_command(command) == command


def test_ssh_off_and_nohistory(tmp_path, monkeypatch):
    monkeypatch.setenv("AGENT_HOST_ROOT", str(tmp_path))
    monkeypatch.setenv("AGENT_STATE_DIR", str(tmp_path / "state"))
    for mode, caps in (("off", []), ("nohistory", ["ssh"]), ("on", ["ssh", "ssh_history"])):
        monkeypatch.setenv("AGENT_SSH", mode)
        sys.modules.pop("agent", None)
        module = importlib.import_module("agent")
        assert [c for c in module.collect()["capabilities"] if c.startswith("ssh")] == caps
        if mode == "nohistory":
            with pytest.raises(ValueError, match="history"):
                module.ssh_answer("history", 100)
        if mode == "off":
            assert module.collect()["ssh_sessions"] is None
            with pytest.raises(ValueError, match="off"):
                module.ssh_answer("sessions", 100)
    sys.modules.pop("agent", None)
