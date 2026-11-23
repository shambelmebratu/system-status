"""The agent's threat scan ignores zombie processes: a killed miner waiting to be collected by its parent is not 'running malware'."""
import importlib
import os
import sys

import psutil

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class FakeProc:
    def __init__(self, pid, name, status, cmdline):
        self.info = {"pid": pid, "name": name, "username": "root", "cmdline": cmdline, "ppid": 1, "status": status}

    def as_dict(self, attrs):
        return {k: self.info[k] for k in attrs}

    def exe(self):
        return ""


def test_zombie_miner_is_not_reported(monkeypatch):
    agent = importlib.import_module("agent")
    procs = [FakeProc(592826, "xmrig", psutil.STATUS_ZOMBIE, []),
             FakeProc(700001, "xmrig", psutil.STATUS_RUNNING, ["/tmp/.x/xmrig", "--url=pool.example:443"])]
    monkeypatch.setattr(agent.psutil, "process_iter", lambda *a, **k: iter(procs))
    monkeypatch.setattr(agent, "_proc_exe", lambda pid: "")
    monkeypatch.setattr(agent, "_connections", lambda: [])
    findings: list = []
    agent._scan_processes(findings)
    pids = [f["pid"] for f in findings if f["kind"] == "process_miner"]
    assert pids == [700001]                 # the live one is still caught; the killed (zombie) one is not
