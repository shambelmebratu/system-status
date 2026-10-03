import os
import platform
import socket
import time
from datetime import datetime, timezone
from typing import Any

import psutil
from fastapi import FastAPI, Header, HTTPException

app = FastAPI(title="Northstar Monitoring Agent")
AGENT_TOKEN = os.getenv("AGENT_TOKEN", "")
if len(AGENT_TOKEN) < 32:
    raise RuntimeError("AGENT_TOKEN is required and must contain at least 32 characters")
AGENT_HOST_ROOT = os.getenv("AGENT_HOST_ROOT", "/")
AGENT_PROCFS_PATH = os.getenv("AGENT_PROCFS_PATH", "/proc")
AGENT_DISK_PATH = os.getenv("AGENT_DISK_PATH", AGENT_HOST_ROOT)
AGENT_PROCESS_TOP_N = max(1, min(100, int(os.getenv("AGENT_PROCESS_TOP_N", "20"))))
AGENT_PROCESS_SAMPLE_SECONDS = max(0.05, min(1.0, float(os.getenv("AGENT_PROCESS_SAMPLE_SECONDS", "0.15"))))

# In the agent container, use the mounted host procfs so CPU, memory and
# process data describe the host rather than the agent container.
psutil.PROCFS_PATH = AGENT_PROCFS_PATH


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/metrics")
def metrics(authorization: str | None = Header(default=None)) -> dict[str, Any]:
    if AGENT_TOKEN and authorization != f"Bearer {AGENT_TOKEN}":
        raise HTTPException(401, "Invalid agent token")
    memory = psutil.virtual_memory()
    swap = psutil.swap_memory()
    processes = []
    candidates = []
    for process in psutil.process_iter(["pid", "name", "username", "memory_percent"]):
        try:
            process.cpu_percent(interval=None)
            candidates.append(process)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    if candidates:
        time.sleep(AGENT_PROCESS_SAMPLE_SECONDS)
    for process in candidates:
        try:
            processes.append({"pid": process.info["pid"], "name": process.info["name"] or "unknown", "user": process.info["username"] or "unknown", "cpu": round(process.cpu_percent(interval=None), 1), "memory": round(process.info["memory_percent"] or 0, 1)})
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    processes.sort(key=lambda item: item["cpu"], reverse=True)
    return {
        "hostname": socket.gethostname(),
        "platform": platform.platform(),
        "cpu": round(psutil.cpu_percent(interval=0.25), 1),
        "memory": round(memory.percent, 1),
        "disk": round(psutil.disk_usage(AGENT_DISK_PATH).percent, 1),
        "load": round(os.getloadavg()[0], 2),
        "swap": round(swap.percent, 1),
        "uptime_seconds": max(0, int(time.time() - psutil.boot_time())),
        "processes": processes[:AGENT_PROCESS_TOP_N],
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
