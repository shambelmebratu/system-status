"""The agent's log readers and their safety boundaries (run against temp files; no Docker or journald needed)."""
import importlib
import json
import os
import sys
import threading

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
    assert cmd[:2] == ["log", "show"] and cmd[cmd.index("--last") + 1] == "900s"
    assert 'process == "myapp"' in cmd[cmd.index("--predicate") + 1] and "messageType == error" in cmd[cmd.index("--predicate") + 1]
    with pytest.raises(ValueError):
        agent.fetch_logs({"source": "journal", "target": 'x" || true || "'})                          # quoting tricks never reach the predicate
    seen.clear(); agent.fetch_logs({"source": "journal", "target": "all"})
    assert seen["cmd"][seen["cmd"].index("--last") + 1] == "3600s"                                    # unbounded asks are bounded to an hour


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


# ---------------------------------------------------------------- agent credentials: rotation, state, HTTPS
@pytest.fixture()
def cred_agent(tmp_path, monkeypatch):
    """A fresh agent module with an isolated state directory and a configured per-server token."""
    token = "t" * 20 + "o" * 20 + "k" * 4
    monkeypatch.setenv("SMWATCH_URL", "https://monitor.example.com"); monkeypatch.setenv("AGENT_TOKEN", token)
    monkeypatch.setenv("AGENT_STATE_DIR", str(tmp_path / "state")); monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("AGENT_DOCKER_SOCKET", str(tmp_path / "none")); monkeypatch.delenv("AGENT_TOKEN_FILE", raising=False)
    sys.path.insert(0, ROOT); sys.modules.pop("agent", None)
    mod = importlib.import_module("agent")
    mod.configured = token
    yield mod
    sys.modules.pop("agent", None)


def _restart(mod):
    mod.AGENT_TOKEN = ""     # a fresh process starts without a token in memory


def test_rotated_token_survives_restart_and_is_stored_privately(cred_agent):
    a = cred_agent
    assert a.ensure_token() and a.AGENT_TOKEN == a.configured
    new = "N" * 43
    a.adopt_rotated_token(new)
    assert a.AGENT_TOKEN == new
    path = a._state_file()
    assert oct(os.stat(path).st_mode & 0o777) == "0o600"                              # only the agent's own user can read it
    assert not os.path.exists(path + ".tmp")                                          # written atomically
    _restart(a)
    assert a.ensure_token() and a.AGENT_TOKEN == new                                  # the rotated token wins over the old configured one
    # ...but if an administrator deliberately installs a different token, stale saved state must NOT override it
    a._ENV_TOKEN = "X" * 43; _restart(a)
    assert a.ensure_token() and a.AGENT_TOKEN == "X" * 43


def test_malformed_or_repeated_rotation_messages_are_ignored(cred_agent):
    a = cred_agent
    a.ensure_token()
    for bad in ("", "short", a.configured, "a" * 31):
        a.adopt_rotated_token(bad)
        assert a.AGENT_TOKEN == a.configured, bad


def test_state_for_another_control_plane_is_not_trusted(cred_agent, monkeypatch):
    a = cred_agent
    a.ensure_token(); a.adopt_rotated_token("R" * 43)
    monkeypatch.setattr(a, "SMWATCH_URL", "https://other.example.org"); _restart(a)
    assert a.ensure_token() and a.AGENT_TOKEN == a.configured                         # a token saved for one server is never sent to another


def test_push_once_adopts_a_rotated_token_from_the_reply(cred_agent, monkeypatch):
    a = cred_agent
    a.ensure_token()
    monkeypatch.setattr(a, "collect", lambda: {"cpu": 1})
    sent = []

    class Reply:
        def __init__(self, body): self.body = body
        def __enter__(self): return self
        def __exit__(self, *x): return False
        def read(self): return json.dumps(self.body).encode()
    replies = [{"ok": True, "interval_seconds": 30, "rotate_token": "Z" * 43}, {"ok": True, "interval_seconds": 30}]
    monkeypatch.setattr(a.urllib.request, "urlopen", lambda req, timeout=0: (sent.append(req.get_header("Authorization")), Reply(replies.pop(0)))[1])
    a.push_once(); a.push_once()
    assert sent == [f"Bearer {a.configured}", "Bearer " + "Z" * 43]                    # the very next report already uses the new token


@pytest.mark.parametrize("url, ok", [
    ("https://watchstatus.ashewa.com", True), ("http://watchstatus.ashewa.com", False), ("http://203.0.113.9:8000", False), ("ftp://x.example.com", False),
    ("http://192.168.1.10:8000", True), ("http://10.1.2.3", True), ("http://172.16.5.5", True), ("http://172.40.0.1", False), ("http://169.254.1.1", True),
    ("http://127.0.0.1:8000", True), ("http://api:8000", True), ("http://monitor.lan", True), ("http://monitor.internal:8000", True),
    ("http://evil.local.attacker.io", False), ("http://[::1]:8000", True),
])
def test_plain_http_is_only_allowed_on_private_networks(cred_agent, monkeypatch, url, ok):
    monkeypatch.setattr(cred_agent, "SMWATCH_URL", url)
    assert (cred_agent.insecure_url_problem() is None) is ok, url


def test_insecure_override_and_check_command_refuse(cred_agent, monkeypatch, capsys):
    a = cred_agent
    monkeypatch.setattr(a, "SMWATCH_URL", "http://203.0.113.9:8000")
    assert a.check() == 1 and "not HTTPS" in capsys.readouterr().out                   # the connectivity test fails fast with the reason
    monkeypatch.setattr(a, "AGENT_ALLOW_INSECURE", True)
    assert a.insecure_url_problem() is None                                            # an explicit, deliberate opt-out exists


def test_real_process_restart_uses_the_rotated_token_not_the_environment_token(cred_agent, monkeypatch):
    """The bug that unit tests with a hand-reset token missed: a genuinely fresh process starts with the OLD token still in its
    environment (Docker keeps env vars forever) and must still prefer the rotated token saved on disk."""
    a = cred_agent
    old = a.configured
    a.ensure_token(); a.adopt_rotated_token("R" * 43)
    sys.modules.pop("agent", None)                                   # a new process: nothing in memory, same environment
    fresh = importlib.import_module("agent")
    assert fresh.AGENT_TOKEN == "" and fresh._ENV_TOKEN == old       # it does NOT start out with the environment token in use
    assert fresh.ensure_token() and fresh.AGENT_TOKEN == "R" * 43
    sys.modules.pop("agent", None)


def test_pull_mode_still_authenticates_with_the_configured_token(cred_agent, monkeypatch):
    a = cred_agent
    monkeypatch.setattr(a, "AGENT_MODE", "pull"); monkeypatch.setattr(a, "SMWATCH_URL", "")
    monkeypatch.setattr(sys, "argv", ["agent.py"]); monkeypatch.setattr(a.psutil, "cpu_percent", lambda interval=None: 0)
    started = {}
    import types
    monkeypatch.setitem(sys.modules, "uvicorn", types.SimpleNamespace(run=lambda app, host, port: started.update(app=app)))
    a.main()
    assert a.AGENT_TOKEN == a.configured and "app" in started          # /metrics checks this token: it must not be empty in pull mode


def test_check_command_accepts_a_configured_token(cred_agent, monkeypatch, capsys):
    """`agent.py --check` is what the installer runs before starting the service: it must work with a supplied token."""
    a = cred_agent
    monkeypatch.setattr(a, "push_once", lambda: 30)
    assert a.check() == 0 and "OK: report accepted" in capsys.readouterr().out
    monkeypatch.setattr(a, "_ENV_TOKEN", "")
    assert a.check() == 1 and "set SMWATCH_JOIN" in capsys.readouterr().out          # with nothing configured it still says so


# ---------------------------------------------------------------- log access policy (agent side)
FULL = {"docker": {"enabled": True, "include": ["*"], "exclude": []}, "journal": {"enabled": True, "units": ["*"]}, "files": {"enabled": True, "allow": None}}
NARROW = {"docker": {"enabled": True, "include": ["web-*"], "exclude": ["web-secret"]}, "journal": {"enabled": True, "units": ["nginx*"]},
          "files": {"enabled": True, "allow": ["/var/log/nginx/*", "/srv/app/*.log"]}}


def test_agent_enforces_the_policy_it_receives(cred_agent, tmp_path, monkeypatch):
    a = cred_agent
    assert a.policy_allows("docker", "anything") and a.policy_allows("file", "/var/log/auth.log")     # no policy yet: only local limits apply
    a.apply_policy(NARROW)
    assert a.policy_allows("docker", "web-1") and not a.policy_allows("docker", "web-secret") and not a.policy_allows("docker", "db")
    assert a.policy_allows("journal", "nginx.service") and not a.policy_allows("journal", "all") and not a.policy_allows("journal", "cron.service")
    assert a.policy_allows("file", "/var/log/nginx/error.log") and not a.policy_allows("file", "/var/log/auth.log")
    assert a.policy_allows("inventory", "") is True
    with pytest.raises(ValueError, match="log access policy"):
        a.fetch_logs({"source": "docker", "target": "db"})
    with pytest.raises(ValueError, match="log access policy"):
        a.fetch_logs({"source": "file", "target": "/var/log/auth.log"})
    a.apply_policy({"docker": {"enabled": False, "include": [], "exclude": []}, "journal": {"enabled": False, "units": []}, "files": {"enabled": False, "allow": []}})
    assert not any(a.policy_allows(s, t) for s, t in [("docker", "web-1"), ("journal", "all"), ("file", "/var/log/nginx/error.log")])


def test_agent_policy_survives_restart_and_ignores_garbage(cred_agent):
    a = cred_agent
    a.apply_policy(NARROW)
    path = a._policy_path()
    assert oct(os.stat(path).st_mode & 0o777) == "0o600"
    for junk in (None, "allow everything", {}, {"docker": 1}, {"docker": {"enabled": "yes"}}, {**NARROW, "files": {"enabled": True, "allow": [1, 2]}}):
        a.apply_policy(junk)
        assert a._policy == NARROW, junk                                                          # a malformed message can never loosen the policy
    sys.modules.pop("agent", None)                                                                # restart
    fresh = importlib.import_module("agent")
    assert fresh._policy is None and fresh.current_policy() == NARROW                             # remembered from disk before the first report
    assert not fresh.policy_allows("docker", "db")
    sys.modules.pop("agent", None)


def test_agent_filters_its_own_inventory(cred_agent, monkeypatch):
    a = cred_agent
    inv = {"files": ["/var/log/nginx/a.log", "/var/log/auth.log"], "containers": [{"name": "web-1"}, {"name": "db"}], "docker": True, "journal": True, "units": ["nginx.service", "cron.service"], "notes": []}
    monkeypatch.setattr(a, "log_inventory", lambda units=False: dict(inv) if not units else {"units": list(inv["units"])})
    a.apply_policy(NARROW)
    seen = json.loads(a.fetch_logs({"source": "inventory"})[0])
    assert seen["files"] == ["/var/log/nginx/a.log"] and [c["name"] for c in seen["containers"]] == ["web-1"] and seen["journal_all"] is False
    assert json.loads(a.fetch_logs({"source": "inventory", "target": "units"})[0])["units"] == ["nginx.service"]


def test_agent_and_control_plane_make_identical_decisions(cred_agent):
    """The two enforcement points must never disagree: compile a range of policies and compare every decision."""
    import itertools
    from app import log_policy as lp
    a = cred_agent
    policies = [{}, {"docker": {"include": ["web-*", "api"], "exclude": ["web-x*"]}}, {"docker": {"enabled": False}}, {"journal": {"units": ["nginx*", "ssh.service"]}},
                {"journal": {"enabled": False}}, {"files": {"mode": "selected", "categories": ["web", "auth"], "custom": ["/srv/*/logs/*.log"]}},
                {"files": {"mode": "selected", "categories": []}}, {"files": {"enabled": False}},
                {"docker": {"include": ["a?c", "[xy]-1"]}, "journal": {"units": ["*"]}, "files": {"mode": "all"}}]
    targets = {"docker": ["web-1", "web-x1", "api", "db", "abc", "x-1", "z-1"], "journal": ["all", "nginx.service", "nginx", "ssh.service", "cron.service"],
               "file": ["/var/log/nginx/a.log", "/var/log/auth.log", "/srv/app/logs/x.log", "/var/log/mysql/e.log", "/var/log/syslog"]}
    for raw in policies:
        compiled = lp.compile_for_agent(lp.LogPolicy.model_validate(raw))
        a._policy, a._policy_loaded = compiled, True
        for source, names in targets.items():
            for name in names:
                assert a.policy_allows(source, name) == lp.query_allowed(compiled, source, name), (raw, source, name)


def test_agent_never_forwards_its_token_to_a_redirect_target(cred_agent):
    """urllib re-sends Authorization on a redirect, even to another host. The agent must refuse the redirect instead."""
    import http.server, threading, urllib.request, urllib.error
    seen = []

    class Collector(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            seen.append(self.headers.get("Authorization")); self.send_response(200); self.end_headers(); self.wfile.write(b"{}")
        do_GET = do_POST
        def log_message(self, *a): pass

    collector = http.server.HTTPServer(("127.0.0.1", 0), Collector)

    class Redirector(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            self.send_response(307); self.send_header("Location", f"http://127.0.0.1:{collector.server_port}/steal"); self.end_headers()
        do_GET = do_POST
        def log_message(self, *a): pass

    redirector = http.server.HTTPServer(("127.0.0.1", 0), Redirector)
    for server in (collector, redirector):
        threading.Thread(target=server.serve_forever, daemon=True).start()
    a = cred_agent
    previous = urllib.request._opener
    try:
        a.SMWATCH_URL = f"http://127.0.0.1:{redirector.server_port}"
        a.AGENT_TOKEN = "t" * 40
        a.install_safe_opener()
        with pytest.raises(urllib.error.HTTPError) as caught:
            a._api("GET", "/api/agent/tasks")
        assert caught.value.code == 307 and "redirect" in str(caught.value.reason)
        with pytest.raises(urllib.error.HTTPError):
            a.push_once()
        assert seen == []                                               # the token never reached the other server
    finally:
        urllib.request.install_opener(previous) if previous else setattr(urllib.request, "_opener", None)
        collector.shutdown(); redirector.shutdown()


# =================================================================== real-traffic response times (access log summary)
@pytest.fixture()
def traffic_agent(tmp_path, monkeypatch):
    log = tmp_path / "access.log"
    log.write_text("")
    monkeypatch.setenv("AGENT_ACCESS_LOG", str(log))
    monkeypatch.setenv("AGENT_HOST_ROOT", "/")
    monkeypatch.setenv("AGENT_DOCKER_SOCKET", str(tmp_path / "no.sock"))
    sys.path.insert(0, ROOT)
    sys.modules.pop("agent", None)
    module = importlib.import_module("agent")
    yield module, log
    sys.modules.pop("agent", None)


LINE = '203.0.113.9 - - [14/Nov/2026:10:00:01 +0000] "GET /api/x HTTP/1.1" {status} 512 "curl/8" rt={rt} urt={urt}\n'


def test_access_log_lines_are_parsed(traffic_agent):
    a, _ = traffic_agent
    assert a.parse_access_line(LINE.format(status=200, rt="0.250", urt="0.200")) == (250.0, 200, 200.0)
    ms, status, upstream = a.parse_access_line(LINE.format(status=502, rt="1.500", urt="0.300, 0.400"))     # nginx lists retries
    assert (round(ms), status, round(upstream)) == (1500, 502, 700)
    assert a.parse_access_line(LINE.format(status=499, rt="0.020", urt="-"))[2] is None                    # no upstream (cache hit / client gone)
    assert a.parse_access_line('{"status":"404","request_time":"0.042","upstream_response_time":"0.040"}') == (42.0, 404, 40.0)
    assert a.parse_access_line('1.2.3.4 - - [x] "GET / HTTP/1.1" 200 5 "-"') is None                        # no timing in this format
    assert a.parse_access_line("garbage") is None and a.parse_access_line("") is None and a.parse_access_line("{not json") is None
    assert a.parse_access_line('x "GET / HTTP/1.1" 200 1 "ua with urt=9 inside" rt=0.1')[0] == 100.0      # the real timing field, not look-alikes


def test_traffic_summary_is_a_histogram_and_never_replays_history(traffic_agent):
    a, log = traffic_agent
    log.write_text(LINE.format(status=200, rt="9.999", urt="9.9") * 5)                    # old history: must be ignored
    assert a.traffic_stats() is None                                                       # first call only remembers the end of the file
    rows = [("0.004", 200), ("0.040", 200), ("0.040", 200), ("0.120", 200), ("0.900", 500), ("3.000", 404), ("30.0", 200)]
    with open(log, "a") as handle:
        for rt, status in rows:
            handle.write(LINE.format(status=status, rt=rt, urt="0.001"))
        handle.write('partial line without newline rt=1.0')                                # a half-written line waits for its newline
    t = a.traffic_stats()
    assert t["requests"] == 7 and t["errors_5xx"] == 1 and t["errors_4xx"] == 1 and t["upstream_count"] == 7
    assert sum(t["counts"]) == 7 and len(t["counts"]) == len(t["bounds"]) + 1
    assert t["counts"][0] == 1 and t["counts"][-1] == 1 and round(t["max_ms"]) == 30000          # 4 ms in the first bucket, 30 s above the last bound
    assert round(t["sum_ms"]) == round(sum(float(rt) * 1000 for rt, _ in rows))
    assert "203.0.113.9" not in json.dumps(t) and "curl" not in json.dumps(t)                  # nothing identifying leaves the server
    assert a.traffic_stats() is None                                                       # nothing new since
    with open(log, "a") as handle:
        handle.write("\n")                                                                  # completes the partial line
    assert a.traffic_stats()["requests"] == 1


def test_log_rotation_and_bounds_from_the_control_plane(traffic_agent, tmp_path):
    a, log = traffic_agent
    a.traffic_stats()
    log.write_text(LINE.format(status=200, rt="0.010", urt="0.005"))
    assert a.traffic_stats()["requests"] == 1
    os.rename(log, tmp_path / "access.log.1")                                               # logrotate moves the file and starts a new one
    log.write_text(LINE.format(status=200, rt="0.020", urt="0.005") * 3)
    assert a.traffic_stats()["requests"] == 3
    a.adopt_traffic_bounds([50, 10, 100, -5, "x"][:3])
    assert a._traffic_bounds == [10.0, 50.0, 100.0]
    a.adopt_traffic_bounds(["bad"]); a.adopt_traffic_bounds([])
    assert a._traffic_bounds == [10.0, 50.0, 100.0]                                         # garbage from a broken control plane is ignored
    with open(log, "a") as handle:
        handle.write(LINE.format(status=200, rt="0.030", urt="0.005"))
    assert a.traffic_stats()["bounds"] == [10.0, 50.0, 100.0]


def test_traffic_is_off_unless_configured(tmp_path, monkeypatch):
    monkeypatch.delenv("AGENT_ACCESS_LOG", raising=False)
    sys.path.insert(0, ROOT); sys.modules.pop("agent", None)
    a = importlib.import_module("agent")
    try:
        assert a.traffic_stats() is None and a.collect()["traffic"] is None
    finally:
        sys.modules.pop("agent", None)


def test_other_load_balancers_formats_are_understood(traffic_agent):
    a, _ = traffic_agent
    caddy = '{"level":"info","ts":1700000000.1,"logger":"http.log.access","request":{"method":"GET","uri":"/"},"duration":0.0425,"status":200,"size":10}'
    assert a.parse_access_line(caddy) == (42.5, 200, None)
    traefik = '{"ClientAddr":"1.2.3.4:5","DownstreamStatus":502,"Duration":123456789,"OriginDuration":100000000,"RequestMethod":"GET"}'
    ms, status, upstream = a.parse_access_line(traefik)
    assert (round(ms, 1), status, round(upstream)) == (123.5, 502, 100)
    haproxy = 'Nov 14 10:00:01 lb haproxy[123]: 203.0.113.9:5555 [14/Nov/2026:10:00:01.123] fe be/srv1 0/0/1/12/15 200 512 - - ---- 1/1/0/0/0 0/0 "GET / HTTP/1.1"'
    assert a.parse_access_line(haproxy) == (15.0, 200, 12.0)
    assert a.parse_access_line('Nov 14 lb haproxy[1]: 1.2.3.4:5 [x] fe be/<NOSRV> 0/-1/-1/-1/0 503 212 - - SC-- 1/1/0/0/0 0/0 "GET / HTTP/1.1"') == (0.0, 503, None)
    assert a.parse_access_line('{"msg":"hello"}') is None


def test_the_agent_explains_why_there_is_no_response_time_data(tmp_path, monkeypatch):
    log = tmp_path / "access.log"
    sys.path.insert(0, ROOT)
    def load(**env):
        for k in ("AGENT_ACCESS_LOG",):
            monkeypatch.delenv(k, raising=False)
        for k, v in env.items():
            monkeypatch.setenv(k, v)
        monkeypatch.setenv("AGENT_HOST_ROOT", "/")
        sys.modules.pop("agent", None)
        return importlib.import_module("agent")
    try:
        a = load()                                                                         # not configured, nothing standard on this machine
        a.ACCESS_LOG_CANDIDATES = (str(log),)
        assert a.traffic_status() == {"state": "off", "detected": []}
        log.write_text('1.2.3.4 - - [x] "GET / HTTP/1.1" 200 5 "-" "ua"\n' * 3)            # a log exists but has no timing field
        a._detected_cache.update(at=0.0)
        assert a.traffic_status()["detected"] == [{"path": str(log), "timing": False}]
        log.write_text('1.2.3.4 - - [x] "GET / HTTP/1.1" 200 5 "-" "ua" rt=0.100 urt=0.050\n')
        a._detected_cache.update(at=0.0)
        assert a.traffic_status()["detected"] == [{"path": str(log), "timing": True}]       # ... or one that only needs to be switched on
        a = load(AGENT_ACCESS_LOG=str(tmp_path / "missing.log")); a.traffic_stats()
        assert a.traffic_status()["state"] == "no_file"
        log.write_text("")
        a = load(AGENT_ACCESS_LOG=str(log)); a.traffic_stats(); assert a.traffic_stats() is None
        assert a.traffic_status()["state"] == "waiting"                                      # file fine, no new requests yet
        with open(log, "a") as handle:
            handle.write('1.2.3.4 - - [x] "GET / HTTP/1.1" 200 5 "-" "ua"\n' * 4)
        a.traffic_stats()
        st = a.traffic_status()
        assert st["state"] == "no_timing" and st["lines"] == 4 and st["parsed"] == 0        # requests are logged but without a response time
        with open(log, "a") as handle:
            handle.write('1.2.3.4 - - [x] "GET / HTTP/1.1" 200 5 "-" "ua" rt=0.100\n' * 2)
        a.traffic_stats()
        st = a.traffic_status()
        assert st["state"] == "ok" and st["lines"] == 2 and st["parsed"] == 2 and st["detected"] == []
        os.chmod(log, 0)
        a = load(AGENT_ACCESS_LOG=str(log)); a.traffic_stats()
        if os.geteuid() != 0:
            assert a.traffic_status()["state"] == "unreadable"
        os.chmod(log, 0o644)
    finally:
        sys.modules.pop("agent", None)


# =================================================================== CPU is measured over the whole interval
def test_cpu_is_the_average_and_peak_of_the_interval_not_one_snapshot(tmp_path, monkeypatch):
    sys.path.insert(0, ROOT); sys.modules.pop("agent", None)
    a = importlib.import_module("agent")
    try:
        a._cpu_thread = object()                                          # do not start the real sampler in this test
        monkeypatch.setattr(a, "proc_stat", lambda: {})
        monkeypatch.setattr(a.psutil, "cpu_percent", lambda interval=None: 12.5)
        assert a.cpu_window()[:2] == (12.5, None)                         # before one interval has passed: a short direct sample, no peak yet
        with a._cpu_lock:
            for value in (10.0, 20.0, 90.0, 20.0):                        # four 5-second readings, one short spike
                a._cpu_window["sum"] += value; a._cpu_window["n"] += 1; a._cpu_window["peak"] = max(a._cpu_window["peak"], value)
        a._cpu_mark["times"] = None                                       # no kernel counters to compare with: the average of the readings
        avg, peak, _ = a.cpu_window()
        assert round(avg, 1) == 35.0 and peak == 90.0                     # a snapshot taken at any one moment would show 10, 20 or 90
        assert a._cpu_window == {"sum": 0.0, "n": 0, "peak": 0.0}         # the next report starts a fresh window
        monkeypatch.undo()
        report = a.collect()
        assert 0 <= report["cpu"] <= 100 and report["cpu_peak"] is None or report["cpu_peak"] >= report["cpu"] - 0.1
    finally:
        sys.modules.pop("agent", None)


def test_cpu_breakdown_explains_busy_time_no_process_shows(monkeypatch):
    """CPU 90 % with quiet processes: the hypervisor's steal time and interrupt time are busy but belong to no process."""
    from collections import namedtuple
    sys.path.insert(0, ROOT); sys.modules.pop("agent", None)
    a = importlib.import_module("agent")
    try:
        T = namedtuple("scputimes", "user nice system idle iowait irq softirq steal guest guest_nice")
        before, after = T(100, 0, 50, 1000, 10, 0, 5, 0, 0, 0), T(105, 0, 55, 1010, 20, 0, 15, 60, 4, 0)   # 100 s of CPU time passed (guest is inside user)
        b = a.cpu_breakdown(before, after)
        assert b == {"user": 5.0, "nice": 0.0, "system": 5.0, "idle": 10.0, "iowait": 10.0, "irq": 0.0, "softirq": 10.0, "steal": 60.0}
        assert a.busy_percent(b) == 80.0                                  # iowait counts as idle; steal and softirq as busy
        a._cpu_thread = object()
        seq = iter([(before, {"processes": 1000, "procs_running": 2, "procs_blocked": 0}), (after, {"processes": 1600, "procs_running": 9, "procs_blocked": 1})])
        clock = iter([100.0, 130.0])
        def step():
            times, stat = next(seq)
            monkeypatch.setattr(a.psutil, "cpu_times", lambda: times)
            monkeypatch.setattr(a, "proc_stat", lambda: stat)
        monkeypatch.setattr(a.time, "monotonic", lambda: next(clock))
        step(); a.cpu_window()
        step(); avg, _, detail = a.cpu_window()
        assert avg == 80.0 and detail["forks_per_sec"] == 20.0 and detail["procs_running"] == 9 and detail["cpu_breakdown"]["steal"] == 60.0
        assert a.process_cpu_total([{"cpu": 150.0}, {"cpu": 50.0}]) == round(200 / (a.psutil.cpu_count() or 1), 1)   # % of ONE core each
    finally:
        sys.modules.pop("agent", None)


def test_live_snapshot_is_independent_of_the_report_counters(monkeypatch):
    sys.path.insert(0, ROOT); sys.modules.pop("agent", None)
    a = importlib.import_module("agent")
    try:
        a._cpu_mark.update(times="untouched", stat={"processes": 1}, t=1.0)
        snap = json.loads(a.fetch_logs({"source": "snapshot", "seconds": 0.2})[0])
        assert a._cpu_mark["times"] == "untouched"                        # the next regular report still covers its whole interval
        a._cpu_mark.update(times=None, stat=None, t=None)
        assert 0 <= snap["cpu"] <= 100 and snap["processes"] and snap["process_count"] >= len(snap["processes"]) and snap["sample_seconds"] >= 0.2
        assert any(p["pid"] == os.getpid() for p in snap["processes"]) or snap["process_count"] > a.AGENT_PROCESS_TOP_N
        from app.schemas import LiveSnapshot
        LiveSnapshot.model_validate(snap)
        monkeypatch.setattr(a, "AGENT_LOGS", "off")
        assert json.loads(a.fetch_logs({"source": "snapshot", "seconds": 0.2})[0])["cpu"] >= 0   # works whatever logs/ssh/security toggles say
        a._cpu_thread = object()                                          # no real sampler thread: it would outlive this test
        assert "sync" in a.collect()["capabilities"]
    finally:
        sys.modules.pop("agent", None)


def test_process_cpu_is_measured_between_reports_not_in_a_150ms_blip(monkeypatch):
    sys.path.insert(0, ROOT); sys.modules.pop("agent", None)
    a = importlib.import_module("agent")
    try:
        monkeypatch.setattr(a, "AGENT_PROCESS_SAMPLE_SECONDS", 0.05)
        slept = []
        real_sleep = a.time.sleep
        me = threading.get_ident()   # sampler threads left by other tests also sleep: count only this test's own calls
        monkeypatch.setattr(a.time, "sleep", lambda s: (slept.append(s) if threading.get_ident() == me else None, real_sleep(0.01))[1])
        first = a.process_rows()
        assert a._procs_primed and slept == [0.05] and first                # the first report primes the counters and waits once
        second = a.process_rows()
        assert slept == [0.05]                                              # later reports do not wait: they read the average since the last one
        assert any(row["pid"] == os.getpid() for row in second) and all(row["cpu"] >= 0 for row in second)
    finally:
        sys.modules.pop("agent", None)


# =================================================================== finer time filters ("last 15 seconds" ... "last month")
def test_time_filter_uses_the_timestamps_inside_log_files(agent, tmp_path):
    import calendar, time as _t
    now = _t.time()
    iso = lambda ago: _t.strftime("%Y-%m-%dT%H:%M:%SZ", _t.gmtime(now - ago))      # noqa: E731
    nginx = lambda ago: _t.strftime("%d/%b/%Y:%H:%M:%S +0000", _t.gmtime(now - ago))   # noqa: E731
    text = "\n".join([f"{iso(7200)} old error", "    old stack frame", f"{iso(600)} ten minutes ago", f"{iso(20)} twenty seconds ago", "    its continuation", f'1.2.3.4 - - [{nginx(5)}] "GET / HTTP/1.1" 200 5 "-" "ua"'])
    assert agent.filter_lines_by_time(text, 3600, now).splitlines() == [f"{iso(600)} ten minutes ago", f"{iso(20)} twenty seconds ago", "    its continuation", f'1.2.3.4 - - [{nginx(5)}] "GET / HTTP/1.1" 200 5 "-" "ua"']
    kept = agent.filter_lines_by_time(text, 30, now).splitlines()
    assert kept == [f"{iso(20)} twenty seconds ago", "    its continuation", f'1.2.3.4 - - [{nginx(5)}] "GET / HTTP/1.1" 200 5 "-" "ua"']      # wrapped lines follow their parent line
    assert agent.filter_lines_by_time("no timestamps at all\nstill none", 10, now) == "no timestamps at all\nstill none"                   # nothing to judge by: keep it
    assert agent.line_time("2026-11-14 10:00:00+03:00 x") - agent.line_time("2026-11-14 07:00:00Z x") == 0                                 # zones are honoured
    syslog = _t.strftime("%b %e %H:%M:%S", _t.localtime(now - 5)) + " host sshd[1]: x"
    assert abs(agent.line_time(syslog, now) - (now - 5)) < 2
    assert agent.line_time("Foo 99 99:99:99 nope") is None and agent.line_time("") is None


def test_fetch_logs_accepts_seconds_and_keeps_minutes(agent, tmp_path):
    import time as _t
    log = tmp_path / "logs" / "app.log"
    stamp = lambda ago: _t.strftime("%Y-%m-%dT%H:%M:%SZ", _t.gmtime(_t.time() - ago))   # noqa: E731
    log.write_text(f"{stamp(500)} five hundred seconds ago\n{stamp(8)} eight seconds ago\n{stamp(1)} one second ago\n")
    out, _ = agent.fetch_logs({"source": "file", "target": agent.paths["log"], "lines": 50, "since_seconds": 15})
    assert [l.split(" ", 1)[1] for l in out.splitlines()] == ["eight seconds ago", "one second ago"]
    out, _ = agent.fetch_logs({"source": "file", "target": agent.paths["log"], "lines": 50, "since_minutes": 15})
    assert len(out.splitlines()) == 3                                                    # the old minutes parameter still works
    out, _ = agent.fetch_logs({"source": "file", "target": agent.paths["log"], "lines": 50, "since_seconds": 600, "since_minutes": 0})
    assert len(out.splitlines()) == 3
    out, _ = agent.fetch_logs({"source": "file", "target": agent.paths["log"], "lines": 50})
    assert len(out.splitlines()) == 3                                                    # no time limit
