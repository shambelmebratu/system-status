"""Numbers shown on the server page are exact: chart averages over every sample, alert text that finds the real process,
and a live sample that never reports a process's lifetime CPU as one second's use."""
import importlib
import os
import sys
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import psutil
from fastapi.testclient import TestClient

from test_api_auth import CSRF, client, main, sign_in  # noqa: F401
from app import database
from app.models import MetricSample
from app.monitoring import evaluate_metrics, process_label

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def test_history_summary_is_exact_over_samples(client):
    sign_in(client)
    tok = client.post("/api/enrollments", headers=CSRF, json={}).json()["token"]
    sid = TestClient(main.app).post("/api/agent/enroll", headers={"Authorization": f"Bearer {tok}"}, json={"hostname": "acc-box", "machine_id": "acc1"}).json()["server_id"]
    now = datetime.now(timezone.utc)
    with database.SessionLocal() as db:
        # 50 samples at 10 % in the last hour, one sample at 90 % 20 h ago (an uneven spread: one lonely bucket)
        rows = [MetricSample(server_id=sid, ts=now - timedelta(minutes=m + 1), cpu=10, cpu_peak=12, memory=40, disk=50, load=1, swap=0) for m in range(50)]
        rows.append(MetricSample(server_id=sid, ts=now - timedelta(hours=20), cpu=90, cpu_peak=97, memory=40, disk=50, load=1, swap=0))
        db.add_all(rows); db.commit()
    h = client.get(f"/api/servers/{sid}/history?range=24h").json()
    assert h["samples"] == 51
    assert abs(h["summary"]["cpu"]["avg"] - (50 * 10 + 90) / 51) < 0.01      # 11.57 %, not the bucket mean (50 %)
    assert h["summary"]["cpu"]["max"] == 97 and h["summary"]["memory"]["avg"] == 40


def test_alert_names_the_program_when_the_process_renamed_itself():
    assert process_label({"name": "xmrig", "pid": 5, "cmd": "/tmp/.x/xmrig --url pool:443"}) == "xmrig PID 5"
    assert process_label({"name": "kworkerds", "pid": 7, "cmd": "/var/tmp/.k/miner -o pool"}) == "kworkerds PID 7 (miner)"
    assert process_label({"name": "nginx", "pid": 9}) == "nginx PID 9"                      # older agents: no command
    server = SimpleNamespace(cpu_threshold=99, memory_threshold=99, disk_threshold=99, load_threshold=99, swap_threshold=99, process_threshold=90, process_names="")
    status, failures = evaluate_metrics(server, {"cpu": 1, "memory": 1, "disk": 1, "load": 0, "swap": 0,
                                                 "processes": [{"name": "2.1.330", "pid": 3078, "cpu": 150.0, "cmd": "claude --resume"}]})
    assert status == "alert" and failures == ["Process 2.1.330 PID 3078 (claude) CPU 150.0% >= 90%"]


def test_live_sample_skips_processes_it_could_not_measure_twice(monkeypatch):
    agent = importlib.import_module("agent")
    start = __import__("time").time()

    class P:
        table = {}

        def __init__(self, pid):
            if pid not in P.table:
                raise psutil.NoSuchProcess(pid)
            self.pid, self.d = pid, P.table[pid]

        def oneshot(self):
            return __import__("contextlib").nullcontext()

        def status(self): return self.d["status"]
        def cpu_times(self): return SimpleNamespace(user=self.d["cpu"], system=0.0)
        def name(self): return self.d["name"]
        def username(self): return "root"
        def memory_percent(self): return 1.0
        def create_time(self): return self.d["created"]
        def cmdline(self): return [self.d["name"]]

    calls = {"n": 0}

    def pids():
        calls["n"] += 1
        if calls["n"] == 1:        # first pass: the old busy process is missed (a transient read error), the zombie is there
            P.table = {10: {"name": "steady", "cpu": 100.0, "created": start - 3600, "status": "running"},
                       30: {"name": "xmrig", "cpu": 999.0, "created": start - 7200, "status": "zombie"}}
        else:                      # second pass: 'old' (5000 s of lifetime CPU) appears, 'fresh' started during the sample
            P.table = {10: {"name": "steady", "cpu": 100.5, "created": start - 3600, "status": "running"},
                       20: {"name": "old", "cpu": 5000.0, "created": start - 86400, "status": "running"},
                       40: {"name": "fresh", "cpu": 0.2, "created": start + 0.1, "status": "running"},
                       30: {"name": "xmrig", "cpu": 999.0, "created": start - 7200, "status": "zombie"}}
        return list(P.table)

    monkeypatch.setattr(agent.psutil, "pids", pids)
    monkeypatch.setattr(agent.psutil, "Process", P)
    monkeypatch.setattr(agent.time, "sleep", lambda s: None)
    snap = agent.live_snapshot(1.0)
    by = {r["name"]: r["cpu"] for r in snap["processes"]}
    assert "old" not in by and "xmrig" not in by          # never 5000 s shown as one second's use; a zombie runs nothing
    assert "steady" in by and "fresh" in by
