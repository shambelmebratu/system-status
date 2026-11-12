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
