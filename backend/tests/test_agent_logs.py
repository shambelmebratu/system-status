"""The agent's log readers and their safety boundaries (run against temp files; no Docker or journald needed)."""
import importlib
import json
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(__file__))


@pytest.fixture()
def agent(tmp_path, monkeypatch):
    logdir = tmp_path / "logs"; logdir.mkdir()
    (logdir / "app.log").write_text("\n".join(f"line {i} {'ERROR boom' if i % 10 == 0 else 'ok'}" for i in range(1, 501)) + "\n")
    (logdir / "old.log.gz").write_bytes(b"\x1f\x8b")
    secret = tmp_path / "secret.txt"; secret.write_text("TOP SECRET")
    os.symlink(secret, logdir / "sneaky.log")                       # allow-listed name pointing outside the allow-list
    monkeypatch.setenv("AGENT_LOG_PATHS", f"{logdir}/*.log")
    monkeypatch.setenv("AGENT_HOST_ROOT", "/")
    monkeypatch.setenv("AGENT_DOCKER_SOCKET", str(tmp_path / "no-docker.sock"))
    sys.path.insert(0, ROOT)
    sys.modules.pop("agent", None)
    module = importlib.import_module("agent")
    module.paths = {"log": str(logdir / "app.log"), "sneaky": str(logdir / "sneaky.log"), "secret": str(secret)}
    yield module
    sys.modules.pop("agent", None)


def test_file_tail_filter_and_limits(agent):
    out, truncated = agent.fetch_logs({"source": "file", "target": agent.paths["log"], "lines": 5})
    assert out.splitlines() == [f"line {i} {'ERROR boom' if i % 10 == 0 else 'ok'}" for i in range(496, 501)] and not truncated
    out, _ = agent.fetch_logs({"source": "file", "target": agent.paths["log"], "lines": 3, "grep": "error"})   # case-insensitive substring
    assert out.splitlines() == ["line 480 ERROR boom", "line 490 ERROR boom", "line 500 ERROR boom"]
    out, _ = agent.fetch_logs({"source": "file", "target": agent.paths["log"], "lines": 999999})
    assert len(out.splitlines()) == 500                                # capped at MAX_LOG_LINES (and the file size)
    out, _ = agent.fetch_logs({"source": "file", "target": agent.paths["log"], "lines": 10, "grep": ".*"})     # not a regex
    assert out == ""


@pytest.mark.parametrize("target", ["/etc/passwd", "/etc/shadow", "../../etc/passwd", "/var/log/../../etc/passwd", "", "a b", "x;rm -rf /", "$(id)", "`id`"])
def test_file_paths_outside_allowlist_are_refused(agent, target):
    with pytest.raises(ValueError):
        agent.fetch_logs({"source": "file", "target": target})


def test_symlink_escape_and_compressed_files_refused(agent):
    assert agent.paths["sneaky"] in agent.log_files()                 # it is listed (matches the glob)...
    with pytest.raises(ValueError, match="outside"):
        agent.fetch_logs({"source": "file", "target": agent.paths["sneaky"]})   # ...but may not be read
    assert not any(p.endswith(".gz") for p in agent.log_files())
    with pytest.raises(ValueError):
        agent.fetch_logs({"source": "file", "target": agent.paths["secret"]})


def test_inventory_and_unavailable_sources(agent):
    inv = json.loads(agent.fetch_logs({"source": "inventory"})[0])
    assert agent.paths["log"] in inv["files"] and inv["docker"] is False and inv["containers"] == []
    with pytest.raises(ValueError):
        agent.fetch_logs({"source": "docker", "target": "nginx"})
    with pytest.raises(ValueError):
        agent.fetch_logs({"source": "shell", "target": "x"})


def test_docker_stream_demux(agent):
    frame = lambda stream, data: bytes([stream, 0, 0, 0]) + len(data).to_bytes(4, "big") + data  # noqa: E731
    assert agent._demux(frame(1, b"out line\n") + frame(2, b"err line\n")) == "out line\nerr line\n"
    assert agent._demux(b"plain tty output\n") == "plain tty output\n"


def test_units_are_lazy_and_inventory_is_cached(agent, monkeypatch):
    calls = {"units": 0}

    def slow_units():
        calls["units"] += 1
        return ["nginx.service"]
    monkeypatch.setattr(agent, "journal_units", slow_units)
    monkeypatch.setattr(agent, "_journalctl", lambda: ["journalctl"])
    base = json.loads(agent.fetch_logs({"source": "inventory"})[0])
    assert base["units"] == [] and base["journal"] is True and calls["units"] == 0          # the slow journal scan is NOT part of opening the page
    units = json.loads(agent.fetch_logs({"source": "inventory", "target": "units"})[0])
    again = json.loads(agent.fetch_logs({"source": "inventory", "target": "units"})[0])
    assert units == again == {"units": ["nginx.service"]} and calls["units"] == 1           # cached
    assert agent.fetch_logs({"source": "inventory"})[0] == agent.fetch_logs({"source": "inventory"})[0]


# ---------------------------------------------------------------- wider coverage, containers, macOS
def test_binary_files_are_refused(agent, tmp_path):
    binary = tmp_path / "logs" / "wtmp.log"
    binary.write_bytes(b"\x00\x01\x02 not text \x00")
    with pytest.raises(ValueError, match="binary"):
        agent.fetch_logs({"source": "file", "target": str(binary)})


def test_nested_and_known_log_locations_are_discovered(tmp_path, monkeypatch):
    root = tmp_path / "host"
    for rel in ["var/log/nginx/access.log", "var/log/nginx/error.log.1", "var/log/postgresql/postgresql-15-main.log", "var/log/syslog", "var/log/auth.log",
                "var/log/apt/history.log", "var/log/myapp/deep/worker.log", "var/log/letsencrypt/letsencrypt.log", "var/log/audit/audit.log", "var/log/cron",
                "var/log/other/notes.txt", "var/log/journal/xyz/system.journal", "etc/passwd", "var/log/nginx/old.log.gz"]:
        path = root / rel; path.parent.mkdir(parents=True, exist_ok=True); path.write_text("x\n")
    monkeypatch.setenv("AGENT_HOST_ROOT", str(root))
    monkeypatch.setenv("AGENT_LOG_PATHS", "")
    sys.path.insert(0, ROOT); sys.modules.pop("agent", None)
    mod = importlib.import_module("agent")
    found = set(mod.log_files())
    for expected in ["/var/log/nginx/access.log", "/var/log/nginx/error.log.1", "/var/log/postgresql/postgresql-15-main.log", "/var/log/syslog", "/var/log/auth.log", "/var/log/apt/history.log",
                     "/var/log/myapp/deep/worker.log", "/var/log/letsencrypt/letsencrypt.log", "/var/log/audit/audit.log", "/var/log/cron"]:
        assert expected in found, expected
    for forbidden in ["/etc/passwd", "/var/log/other/notes.txt", "/var/log/journal/xyz/system.journal", "/var/log/nginx/old.log.gz"]:
        assert forbidden not in found, forbidden
    assert mod.fetch_logs({"source": "file", "target": "/var/log/nginx/access.log"})[0] == "x"     # readable through the host mount
    sys.modules.pop("agent", None)


def test_journal_source_selection(agent, monkeypatch):
    """Where the agent can read a journal from, in each environment it runs in."""
    monkeypatch.setattr(agent, "IS_MAC", False)
    monkeypatch.setattr(agent.shutil, "which", lambda name: "/usr/bin/journalctl" if name == "journalctl" else None)
    monkeypatch.setattr(agent, "AGENT_HOST_ROOT", "/")
    assert agent._journalctl() == ["/usr/bin/journalctl"]                                            # native install: the machine's own journal
    monkeypatch.setattr(agent, "AGENT_HOST_ROOT", "/host")
    monkeypatch.setattr(agent.os.path, "isdir", lambda p: p == "/host/var/log/journal")
    assert agent._journalctl() == ["/usr/bin/journalctl", "--root", "/host"]                          # container: read the HOST's journal files
    monkeypatch.setattr(agent.os.path, "isdir", lambda p: False)
    assert agent._journalctl() is None                                                              # container, host has no journal: say so, don't read the container's
    monkeypatch.setattr(agent, "IS_MAC", True)
    monkeypatch.setattr(agent.shutil, "which", lambda name: "/usr/bin/log" if name == "log" else None)
    assert agent._journalctl() == ["log"]


def test_macos_system_log_command(agent, monkeypatch):
    seen = {}
    monkeypatch.setattr(agent, "IS_MAC", True)
    monkeypatch.setattr(agent, "_journalctl", lambda: ["log"])
    monkeypatch.setattr(agent, "_run_limited", lambda cmd, **kw: (seen.setdefault("cmd", cmd), "2026-11-13 10:00:00 Df kernel[0]: hello\n2026-11-13 10:00:01 E myapp[1]: ERROR boom\n")[1:] + ("",))
    out, _ = agent.fetch_logs({"source": "journal", "target": "myapp", "lines": 10, "since_minutes": 15, "priority": "err", "grep": "boom"})
    assert out == "2026-11-13 10:00:01 E myapp[1]: ERROR boom"
    cmd = seen["cmd"]
    assert cmd[:2] == ["log", "show"] and cmd[cmd.index("--last") + 1] == "15m"
    assert 'process == "myapp"' in cmd[cmd.index("--predicate") + 1] and "messageType == error" in cmd[cmd.index("--predicate") + 1]
    with pytest.raises(ValueError):
        agent.fetch_logs({"source": "journal", "target": 'x" || true || "'})                          # quoting tricks never reach the predicate
    seen.clear(); agent.fetch_logs({"source": "journal", "target": "all"})
    assert seen["cmd"][seen["cmd"].index("--last") + 1] == "60m"                                    # unbounded asks are bounded to an hour


def test_docker_desktop_vm_is_explained(tmp_path, monkeypatch):
    root = tmp_path / "vm"; (root / "etc").mkdir(parents=True)
    (root / "etc/os-release").write_text('PRETTY_NAME="OrbStack"\n'); (root / "etc/hostname").write_text("orbstack\n")
    monkeypatch.setenv("AGENT_HOST_ROOT", str(root)); monkeypatch.setenv("AGENT_DOCKER_SOCKET", str(tmp_path / "none.sock"))
    sys.path.insert(0, ROOT); sys.modules.pop("agent", None)
    mod = importlib.import_module("agent")
    mod.IS_MAC = False                       # these tests also run on developers' Macs: pin the Linux behaviour
    monkeypatch.setattr(mod.shutil, "which", lambda name: None)
    inv = json.loads(mod.fetch_logs({"source": "inventory"})[0])
    assert inv["journal"] is False and inv["files"] == []
    assert "inside Docker on a Mac or Windows PC" in inv["notes"][0] and "install the agent directly" in inv["notes"][0]
    assert any("no systemd journal" in n for n in inv["notes"]) and any("No standard log files" in n for n in inv["notes"])
    sys.modules.pop("agent", None)
