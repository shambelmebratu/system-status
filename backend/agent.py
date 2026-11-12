#!/usr/bin/env python3
"""Northstar monitoring agent.

Two modes (AGENT_MODE=push|pull|both; default push when NORTHSTAR_URL is set, otherwise pull):

* push - the agent POSTs metrics to the control plane on an interval. Needs only outbound HTTPS,
         so it works behind NAT/firewalls. Requires NORTHSTAR_URL and AGENT_TOKEN.
* pull - the agent serves GET /metrics for the control plane to poll (needs fastapi + uvicorn).

Push mode depends only on psutil and the standard library.
"""
import json
import logging
import os
import platform
import socket
import sys
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from typing import Any

import psutil

AGENT_VERSION = "2.1.0"
AGENT_TOKEN = os.getenv("AGENT_TOKEN", "")
NORTHSTAR_URL = os.getenv("NORTHSTAR_URL", "").rstrip("/")
AGENT_MODE = os.getenv("AGENT_MODE", "push" if NORTHSTAR_URL else "pull").lower()
AGENT_HOST_ROOT = os.getenv("AGENT_HOST_ROOT", "/")
AGENT_PROCFS_PATH = os.getenv("AGENT_PROCFS_PATH", "/proc")
AGENT_DISK_PATH = os.getenv("AGENT_DISK_PATH", AGENT_HOST_ROOT if os.name != "nt" else os.path.abspath(os.sep))
AGENT_PROCESS_TOP_N = max(1, min(100, int(os.getenv("AGENT_PROCESS_TOP_N", "20"))))
AGENT_PROCESS_SAMPLE_SECONDS = max(0.05, min(1.0, float(os.getenv("AGENT_PROCESS_SAMPLE_SECONDS", "0.15"))))
AGENT_PUSH_INTERVAL = max(5, int(os.getenv("AGENT_PUSH_INTERVAL", "30")))  # overridden by the server's configured interval

log = logging.getLogger("northstar-agent")

# In the agent container, use the mounted host procfs so data describes the host, not the container.
if os.path.isdir(AGENT_PROCFS_PATH) and AGENT_PROCFS_PATH != "/proc":
    psutil.PROCFS_PATH = AGENT_PROCFS_PATH

_net_lock = threading.Lock()
_net_last: tuple[float, int, int] | None = None


def _network_rates() -> tuple[float | None, float | None]:
    """Bytes/second received and sent since the previous call (None on the first call)."""
    global _net_last
    counters = psutil.net_io_counters()
    now = time.monotonic()
    with _net_lock:
        previous, _net_last = _net_last, (now, counters.bytes_recv, counters.bytes_sent)
    if not previous or now <= previous[0]:
        return None, None
    elapsed = now - previous[0]
    return (round(max(0, counters.bytes_recv - previous[1]) / elapsed, 1), round(max(0, counters.bytes_sent - previous[2]) / elapsed, 1))


def collect() -> dict[str, Any]:
    memory = psutil.virtual_memory()
    swap = psutil.swap_memory()
    candidates = []
    for process in psutil.process_iter(["pid", "name", "username", "memory_percent"]):
        try:
            process.cpu_percent(interval=None)
            candidates.append(process)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    if candidates:
        time.sleep(AGENT_PROCESS_SAMPLE_SECONDS)
    processes = []
    for process in candidates:
        try:
            processes.append({"pid": process.info["pid"], "name": (process.info["name"] or "unknown")[:100], "user": (process.info["username"] or "unknown")[:100], "cpu": round(process.cpu_percent(interval=None), 1), "memory": round(min(100.0, process.info["memory_percent"] or 0), 1)})
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    processes.sort(key=lambda item: item["cpu"], reverse=True)
    try:
        load = os.getloadavg()[0]
    except (AttributeError, OSError):  # Windows
        load = psutil.cpu_percent(interval=None) / 100 * (psutil.cpu_count() or 1)
    rx, tx = _network_rates()
    return {
        "hostname": socket.gethostname(),
        "platform": platform.platform()[:255],
        "agent_version": AGENT_VERSION,
        "cpu": round(psutil.cpu_percent(interval=0.25), 1),
        "cpu_count": psutil.cpu_count() or 1,
        "memory": round(memory.percent, 1),
        "disk": round(psutil.disk_usage(AGENT_DISK_PATH).percent, 1),
        "load": round(load, 2),
        "swap": round(swap.percent, 1),
        "uptime_seconds": max(0, int(time.time() - psutil.boot_time())),
        "net_rx_bps": rx,
        "net_tx_bps": tx,
        "processes": processes[:AGENT_PROCESS_TOP_N],
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


def push_once() -> int:
    """Sends one report. Returns the interval (seconds) the control plane wants next."""
    body = json.dumps(collect()).encode()
    request = urllib.request.Request(
        f"{NORTHSTAR_URL}/api/agent/report", data=body, method="POST",
        headers={"Content-Type": "application/json", "Authorization": f"Bearer {AGENT_TOKEN}", "User-Agent": f"northstar-agent/{AGENT_VERSION}"},
    )
    with urllib.request.urlopen(request, timeout=15) as response:
        reply = json.loads(response.read().decode() or "{}")
    return max(5, int(reply.get("interval_seconds", AGENT_PUSH_INTERVAL)))


def check() -> int:
    """One-shot connectivity test used by the installer and for troubleshooting: python agent.py --check"""
    if not NORTHSTAR_URL:
        print("FAIL: NORTHSTAR_URL is not set"); return 1
    if len(AGENT_TOKEN) < 32:
        print("FAIL: AGENT_TOKEN is missing or shorter than 32 characters"); return 1
    try:
        interval = push_once()
    except urllib.error.HTTPError as error:
        hints = {401: "the token was rejected: copy the install command again from the dashboard (or use Rotate token)",
                 403: "this server monitor is disabled in the dashboard", 404: "that URL is not a Northstar control plane (check NORTHSTAR_URL)",
                 429: "too many bad attempts from this IP; wait a few minutes"}
        print(f"FAIL: control plane answered HTTP {error.code}: {hints.get(error.code, error.reason)}"); return 1
    except urllib.error.URLError as error:
        print(f"FAIL: cannot reach {NORTHSTAR_URL}: {error.reason}\n      Check the URL is reachable from this server (not localhost), DNS, firewall and TLS."); return 1
    except Exception as error:
        print(f"FAIL: {type(error).__name__}: {error}"); return 1
    print(f"OK: report accepted by {NORTHSTAR_URL} (agent {AGENT_VERSION}, reports every {interval}s)")
    return 0


def push_loop() -> None:
    interval = AGENT_PUSH_INTERVAL
    failures = 0
    log.info("push mode: reporting to %s (agent %s)", NORTHSTAR_URL, AGENT_VERSION)
    while True:
        started = time.monotonic()
        try:
            interval = push_once()
            if failures:
                log.info("connection to control plane restored")
            failures = 0
        except urllib.error.HTTPError as error:
            failures += 1
            log.error("control plane rejected report: HTTP %s (%s)", error.code, "check AGENT_TOKEN" if error.code in (401, 403) else error.reason)
        except Exception as error:  # network down, DNS, TLS... keep retrying
            failures += 1
            log.warning("report failed (%s); retrying", error)
        delay = interval if not failures else min(interval, 5 * 2 ** min(failures - 1, 4))
        time.sleep(max(1.0, delay - (time.monotonic() - started)))


def _build_app():
    from fastapi import FastAPI, Header, HTTPException  # imported lazily: push-only installs don't need FastAPI

    api = FastAPI(title="Northstar Monitoring Agent")

    @api.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok", "version": AGENT_VERSION}

    @api.get("/metrics")
    def metrics(authorization: str | None = Header(default=None)) -> dict[str, Any]:
        if authorization != f"Bearer {AGENT_TOKEN}":
            raise HTTPException(401, "Invalid agent token")
        return collect()

    return api


def __getattr__(name: str):  # lets `uvicorn agent:app` build the pull server on demand
    if name == "app":
        globals()["app"] = _build_app()
        return globals()["app"]
    raise AttributeError(name)


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    if "--version" in sys.argv:
        print(AGENT_VERSION); return
    if "--check" in sys.argv:
        psutil.cpu_percent(interval=None); _network_rates()
        sys.exit(check())
    if len(AGENT_TOKEN) < 32:
        sys.exit("AGENT_TOKEN is required and must contain at least 32 characters")
    psutil.cpu_percent(interval=None)
    _network_rates()
    if AGENT_MODE in ("push", "both"):
        if not NORTHSTAR_URL:
            sys.exit("NORTHSTAR_URL is required in push mode")
        if AGENT_MODE == "both":
            threading.Thread(target=push_loop, daemon=True).start()
        else:
            push_loop()
    if AGENT_MODE in ("pull", "both"):
        import uvicorn
        uvicorn.run(_build_app(), host=os.getenv("AGENT_BIND", "0.0.0.0"), port=int(os.getenv("AGENT_PORT", "9100")))


if __name__ == "__main__":
    main()
