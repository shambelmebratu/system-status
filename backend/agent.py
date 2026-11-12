#!/usr/bin/env python3
"""SM-Watch monitoring agent.

Two modes (AGENT_MODE=push|pull|both; default push when SMWATCH_URL is set, otherwise pull):

* push - the agent POSTs metrics to the control plane on an interval. Needs only outbound HTTPS,
         so it works behind NAT/firewalls. Requires SMWATCH_URL plus ONE of:
           SMWATCH_JOIN  a join token from the dashboard: the agent registers itself as a new server on
                           first start and remembers its own token in AGENT_STATE_DIR (recommended)
           AGENT_TOKEN     a per-server token created in the dashboard
* pull - the agent serves GET /metrics for the control plane to poll (needs fastapi + uvicorn).

Push mode depends only on psutil and the standard library.
"""
from __future__ import annotations

import fnmatch
import glob
import hashlib
import http.client
import json
import logging
import os
import platform
import re
import shutil
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from typing import Any

import psutil

AGENT_VERSION = "2.3.0"
AGENT_TOKEN = os.getenv("AGENT_TOKEN", "")
SMWATCH_JOIN = os.getenv("SMWATCH_JOIN", "")
SMWATCH_URL = os.getenv("SMWATCH_URL", "").rstrip("/")
AGENT_STATE_DIR = os.getenv("AGENT_STATE_DIR", "/var/lib/sm-watch-agent")
AGENT_TOKEN_FILE = os.getenv("AGENT_TOKEN_FILE", "")          # read the per-server token from a file (used by the bundled host agent)
AGENT_LOGS = os.getenv("AGENT_LOGS", "on").lower()             # on | nodocker | off : whether the dashboard may read this server's logs
AGENT_TASK_POLL = max(2, int(os.getenv("AGENT_TASK_POLL", "5")))
AGENT_LOG_PATHS = os.getenv("AGENT_LOG_PATHS", "")             # extra comma-separated globs the dashboard may read
DOCKER_SOCKET = os.getenv("AGENT_DOCKER_SOCKET", "/var/run/docker.sock")
AGENT_MODE = os.getenv("AGENT_MODE", "push" if SMWATCH_URL else "pull").lower()
AGENT_HOST_ROOT = os.getenv("AGENT_HOST_ROOT", "/")
AGENT_PROCFS_PATH = os.getenv("AGENT_PROCFS_PATH", "/proc")
AGENT_DISK_PATH = os.getenv("AGENT_DISK_PATH", AGENT_HOST_ROOT if os.name != "nt" else os.path.abspath(os.sep))
AGENT_PROCESS_TOP_N = max(1, min(100, int(os.getenv("AGENT_PROCESS_TOP_N", "20"))))
AGENT_PROCESS_SAMPLE_SECONDS = max(0.05, min(1.0, float(os.getenv("AGENT_PROCESS_SAMPLE_SECONDS", "0.15"))))
AGENT_PUSH_INTERVAL = max(5, int(os.getenv("AGENT_PUSH_INTERVAL", "30")))  # overridden by the server's configured interval

log = logging.getLogger("sm-watch-agent")

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
        "hostname": host_name(),
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
        "capabilities": ["logs"] if AGENT_LOGS != "off" else [],
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


def host_name() -> str:
    """The real host name (inside Docker the container's own name is meaningless, so prefer the mounted host's)."""
    for path in (os.path.join(AGENT_HOST_ROOT, "etc/hostname"), ):
        try:
            with open(path) as handle:
                value = handle.read().strip()
            if value:
                return value
        except OSError:
            pass
    return socket.gethostname()


def machine_id() -> str:
    """Stable per-machine id so re-installing the agent on the same server does not create a duplicate."""
    for root in (AGENT_HOST_ROOT, "/"):
        for rel in ("etc/machine-id", "var/lib/dbus/machine-id"):
            try:
                with open(os.path.join(root, rel)) as handle:
                    value = handle.read().strip()
                if value:
                    return value
            except OSError:
                pass
    return hashlib.sha256(f"{host_name()}|{platform.node()}|{platform.machine()}".encode()).hexdigest()  # macOS/Windows fallback


def _state_file() -> str | None:
    for directory in (AGENT_STATE_DIR, os.path.join(os.path.expanduser("~"), ".sm-watch-agent")):
        try:
            os.makedirs(directory, mode=0o700, exist_ok=True)
            if os.access(directory, os.W_OK):
                return os.path.join(directory, "agent.json")
        except OSError:
            continue
    return None


def _load_state() -> dict:
    for directory in (AGENT_STATE_DIR, os.path.join(os.path.expanduser("~"), ".sm-watch-agent")):
        try:
            with open(os.path.join(directory, "agent.json")) as handle:
                state = json.load(handle)
            if state.get("url") == SMWATCH_URL and len(state.get("token", "")) >= 32:
                return state
        except (OSError, ValueError):
            continue
    return {}


def enroll() -> str:
    """Registers this machine with the control plane using the join token and returns its own agent token."""
    body = json.dumps({"hostname": host_name(), "machine_id": machine_id(), "platform": platform.platform()[:255], "agent_version": AGENT_VERSION}).encode()
    request = urllib.request.Request(
        f"{SMWATCH_URL}/api/agent/enroll", data=body, method="POST",
        headers={"Content-Type": "application/json", "Authorization": f"Bearer {SMWATCH_JOIN}", "User-Agent": f"sm-watch-agent/{AGENT_VERSION}"},
    )
    with urllib.request.urlopen(request, timeout=20) as response:
        reply = json.loads(response.read().decode())
    path = _state_file()
    if path:
        with open(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "w") as handle:
            json.dump({"url": SMWATCH_URL, "token": reply["agent_token"], "server_id": reply["server_id"], "name": reply["name"]}, handle)
    else:
        log.warning("could not save the agent token (no writable state directory); the agent will re-register on restart")
    log.info("registered with the control plane as %r (server id %s)", reply["name"], reply["server_id"])
    return reply["agent_token"]


def ensure_token() -> bool:
    """Sets the global AGENT_TOKEN from the environment, saved state, or a fresh enrollment. False when none is possible."""
    global AGENT_TOKEN
    if len(AGENT_TOKEN) >= 32:
        return True
    if AGENT_TOKEN_FILE:
        with open(AGENT_TOKEN_FILE) as handle:   # raises until the control plane has written it; the caller retries
            AGENT_TOKEN = handle.read().strip()
        return len(AGENT_TOKEN) >= 32
    saved = _load_state()
    if saved:
        AGENT_TOKEN = saved["token"]
        return True
    if SMWATCH_JOIN:
        AGENT_TOKEN = enroll()
        return True
    return False


def forget_token() -> None:
    """The control plane rejected our token (server deleted/rotated): drop it so we can re-enroll."""
    global AGENT_TOKEN
    AGENT_TOKEN = ""
    for directory in (AGENT_STATE_DIR, os.path.join(os.path.expanduser("~"), ".sm-watch-agent")):
        try:
            os.remove(os.path.join(directory, "agent.json"))
        except OSError:
            pass


# ---------------------------------------------------------------------------------------------------------------
# Logs. The dashboard can ask for logs, but only from this fixed set of sources. Nothing here runs a shell, accepts
# a command, or reads a path outside the allow-list; every request field is validated again on this side.
# ---------------------------------------------------------------------------------------------------------------
LOG_FILE_GLOBS = [
    "/var/log/nginx/*.log", "/var/log/apache2/*.log", "/var/log/httpd/*log", "/var/log/syslog", "/var/log/messages",
    "/var/log/auth.log", "/var/log/secure", "/var/log/kern.log", "/var/log/dmesg", "/var/log/cron*", "/var/log/mysql/*.log",
    "/var/log/postgresql/*.log", "/var/log/redis/*.log", "/var/log/mongodb/*.log", "/var/log/fail2ban.log", "/var/log/ufw.log",
] + [g.strip() for g in AGENT_LOG_PATHS.split(",") if g.strip().startswith("/")]
MAX_LOG_BYTES = 400_000
MAX_LOG_LINES = 2000
TARGET_RE = re.compile(r"^[A-Za-z0-9@_.:/\-]{1,300}$")
PRIORITIES = ("emerg", "alert", "crit", "err", "warning", "notice", "info", "debug")


def _host_path(path: str) -> str:
    """Maps a host path to where it is visible to this process (the Docker agent sees the host under AGENT_HOST_ROOT)."""
    return os.path.join(AGENT_HOST_ROOT, path.lstrip("/")) if AGENT_HOST_ROOT not in ("", "/") else path


def log_files() -> list[str]:
    """Readable files matching the allow-list, as host paths."""
    found = set()
    for pattern in LOG_FILE_GLOBS:
        for real in glob.glob(_host_path(pattern)):
            if os.path.isfile(real) and os.access(real, os.R_OK) and not real.endswith((".gz", ".xz", ".bz2", ".zip")):
                found.add("/" + os.path.relpath(real, AGENT_HOST_ROOT) if AGENT_HOST_ROOT not in ("", "/") else real)
    return sorted(found)


def _allowed_file(path: str) -> str:
    """Returns the real on-disk path for an allow-listed log file, or raises. Symlinks may not lead outside the allow-list."""
    if path not in log_files():
        raise ValueError("That file is not in this agent's log allow-list")
    real = os.path.realpath(_host_path(path))
    host_view = "/" + os.path.relpath(real, AGENT_HOST_ROOT) if AGENT_HOST_ROOT not in ("", "/") else real
    if not any(fnmatch.fnmatch(host_view, pattern) for pattern in LOG_FILE_GLOBS):
        raise ValueError("That file resolves outside this agent's log allow-list")
    return real


class _UnixHTTPConnection(http.client.HTTPConnection):
    def __init__(self, path: str, timeout: float = 15):
        super().__init__("localhost", timeout=timeout)
        self._path = path

    def connect(self) -> None:
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self._path)


def _docker(path: str, raw: bool = False):
    """Read-only GET against the local Docker Engine API (no docker CLI needed)."""
    connection = _UnixHTTPConnection(DOCKER_SOCKET)
    try:
        connection.request("GET", path)
        response = connection.getresponse()
        body = response.read(8_000_000)
        if response.status >= 400:
            raise RuntimeError(f"Docker API {response.status}: {body[:200].decode(errors='replace')}")
        return body if raw else json.loads(body.decode() or "null")
    finally:
        connection.close()


def docker_available() -> bool:
    return AGENT_LOGS == "on" and os.path.exists(DOCKER_SOCKET) and os.access(DOCKER_SOCKET, os.R_OK | os.W_OK)


def docker_containers() -> list[dict]:
    items = _docker("/containers/json?all=1")
    return sorted(({"name": (c.get("Names") or ["/?"])[0].lstrip("/"), "state": c.get("State", ""), "image": c.get("Image", "")[:80]} for c in items), key=lambda c: c["name"])


def _demux(stream: bytes) -> str:
    """Docker multiplexes stdout/stderr in 8-byte-header frames unless the container has a TTY."""
    out, i = [], 0
    while i + 8 <= len(stream):
        if stream[i] not in (0, 1, 2) or stream[i + 1:i + 4] != b"\x00\x00\x00":
            return stream.decode(errors="replace")  # not framed (TTY container)
        size = int.from_bytes(stream[i + 4:i + 8], "big")
        out.append(stream[i + 8:i + 8 + size])
        i += 8 + size
    return b"".join(out).decode(errors="replace")


def _journalctl() -> list[str] | None:
    if shutil.which("journalctl"):
        return ["journalctl"]
    # Docker agent: the host's journalctl, run inside the read-only host mount.
    if AGENT_HOST_ROOT not in ("", "/") and os.path.exists(os.path.join(AGENT_HOST_ROOT, "usr/bin/journalctl")) and shutil.which("chroot") and os.geteuid() == 0:
        return ["chroot", AGENT_HOST_ROOT, "/usr/bin/journalctl"]
    return None


def journal_units() -> list[str]:
    base = _journalctl()
    if not base:
        return []
    try:
        fields = subprocess.run(base + ["--no-pager", "-F", "_SYSTEMD_UNIT"], capture_output=True, text=True, timeout=15).stdout.split()
        return sorted({u for u in fields if u.endswith(".service") and TARGET_RE.match(u)})[:300]
    except (OSError, subprocess.SubprocessError):
        return []


def log_inventory() -> dict:
    inventory = {"files": log_files(), "journal": _journalctl() is not None, "units": [], "docker": docker_available(), "containers": [], "notes": []}
    if inventory["journal"]:
        inventory["units"] = journal_units()
    else:
        inventory["notes"].append("journald is not readable by the agent on this server")
    if inventory["docker"]:
        try:
            inventory["containers"] = docker_containers()
        except Exception as error:
            inventory["docker"] = False
            inventory["notes"].append(f"Docker: {error}")
    elif os.path.exists(DOCKER_SOCKET):
        inventory["notes"].append("Docker is installed but the agent has no access to it (AGENT_LOGS=nodocker, or not in the docker group)")
    return inventory


def _tail_file(path: str, max_bytes: int = 4_000_000) -> str:
    with open(path, "rb") as handle:
        handle.seek(0, os.SEEK_END)
        size = handle.tell()
        handle.seek(max(0, size - max_bytes))
        data = handle.read()
    text = data.decode(errors="replace")
    return text.split("\n", 1)[1] if size > max_bytes and "\n" in text else text


def fetch_logs(task: dict) -> tuple[str, bool]:
    """Runs one validated log request. Returns (text, truncated)."""
    source = task.get("source")
    target = str(task.get("target") or "")
    lines = max(1, min(MAX_LOG_LINES, int(task.get("lines") or 200)))
    since = max(0, min(60 * 24 * 30, int(task.get("since_minutes") or 0)))
    needle = str(task.get("grep") or "")[:200].lower()
    priority = task.get("priority") or ""
    if source == "inventory":
        return json.dumps(log_inventory()), False
    if not TARGET_RE.match(target) or ".." in target:
        raise ValueError("Invalid log target")
    scan = 20000 if needle else lines   # with a filter, look further back and keep the last matches

    if source == "docker":
        if not docker_available():
            raise ValueError("Docker logs are not available to this agent")
        if target not in {c["name"] for c in docker_containers()}:
            raise ValueError("No such container on this server")
        query = f"stdout=1&stderr=1&timestamps=1&tail={scan}" + (f"&since={int(time.time()) - since * 60}" if since else "")
        text = _demux(_docker(f"/containers/{target}/logs?{query}", raw=True))
    elif source == "journal":
        base = _journalctl()
        if not base:
            raise ValueError("journald is not available to this agent")
        command = base + ["--no-pager", "-o", "short-iso", "-n", str(scan)]
        if target != "all":
            command += ["-u", target]
        if since:
            command += ["--since", f"-{since}min"]
        if priority in PRIORITIES:
            command += ["-p", priority]
        result = subprocess.run(command, capture_output=True, text=True, timeout=25, errors="replace")
        if result.returncode != 0 and not result.stdout:
            raise RuntimeError((result.stderr or "journalctl failed").strip()[:300])
        text = result.stdout
    elif source == "file":
        text = _tail_file(_allowed_file(target))   # `since` does not apply: plain files have no reliable timestamps
    else:
        raise ValueError("Unknown log source")

    rows = [row for row in text.splitlines() if row.strip()]
    if needle:
        rows = [row for row in rows if needle in row.lower()]
    rows = rows[-lines:]
    output = "\n".join(rows)
    truncated = len(output.encode()) > MAX_LOG_BYTES
    if truncated:
        output = output.encode()[-MAX_LOG_BYTES:].decode(errors="replace").split("\n", 1)[-1]
    return output, truncated


def _api(method: str, path: str, payload: dict | None = None) -> dict:
    request = urllib.request.Request(
        f"{SMWATCH_URL}{path}", data=json.dumps(payload).encode() if payload is not None else None, method=method,
        headers={"Content-Type": "application/json", "Authorization": f"Bearer {AGENT_TOKEN}", "User-Agent": f"sm-watch-agent/{AGENT_VERSION}"},
    )
    with urllib.request.urlopen(request, timeout=20) as response:
        return json.loads(response.read().decode() or "{}")


def task_loop() -> None:
    """Polls the control plane for log requests. Runs in its own thread so metrics reporting is never delayed."""
    while True:
        try:
            if len(AGENT_TOKEN) >= 32:
                for task in _api("GET", "/api/agent/tasks").get("tasks", []):
                    try:
                        output, truncated = fetch_logs(task)
                        result = {"ok": True, "output": output, "truncated": truncated}
                    except Exception as error:
                        result = {"ok": False, "error": f"{type(error).__name__}: {error}"[:1500]}
                    _api("POST", f"/api/agent/tasks/{int(task['id'])}/result", result)
        except Exception as error:
            log.debug("task poll failed: %s", error)
        time.sleep(AGENT_TASK_POLL)


def push_once() -> int:
    """Sends one report. Returns the interval (seconds) the control plane wants next."""
    body = json.dumps(collect()).encode()
    request = urllib.request.Request(
        f"{SMWATCH_URL}/api/agent/report", data=body, method="POST",
        headers={"Content-Type": "application/json", "Authorization": f"Bearer {AGENT_TOKEN}", "User-Agent": f"sm-watch-agent/{AGENT_VERSION}"},
    )
    with urllib.request.urlopen(request, timeout=15) as response:
        reply = json.loads(response.read().decode() or "{}")
    return max(5, int(reply.get("interval_seconds", AGENT_PUSH_INTERVAL)))


def check() -> int:
    """One-shot connectivity test used by the installer and for troubleshooting: python agent.py --check"""
    if not SMWATCH_URL:
        print("FAIL: SMWATCH_URL is not set"); return 1
    if len(AGENT_TOKEN) < 32 and not SMWATCH_JOIN and not _load_state():
        print("FAIL: set SMWATCH_JOIN (a join token from the dashboard) or AGENT_TOKEN"); return 1
    try:
        ensure_token()
        interval = push_once()
    except urllib.error.HTTPError as error:
        hints = {401: "the token was rejected: the join token may have expired or been revoked, or the server was removed. Ask an admin for a fresh command",
                 403: "this server monitor is disabled in the dashboard, or the join token is used up", 404: "that URL is not a SM-Watch control plane (check SMWATCH_URL)",
                 429: "too many bad attempts from this IP; wait a few minutes"}
        print(f"FAIL: control plane answered HTTP {error.code}: {hints.get(error.code, error.reason)}"); return 1
    except urllib.error.URLError as error:
        print(f"FAIL: cannot reach {SMWATCH_URL}: {error.reason}\n      Check the URL is reachable from this server (not localhost), DNS, firewall and TLS."); return 1
    except Exception as error:
        print(f"FAIL: {type(error).__name__}: {error}"); return 1
    print(f"OK: report accepted by {SMWATCH_URL} (agent {AGENT_VERSION}, reports every {interval}s)")
    return 0


def push_loop() -> None:
    interval = AGENT_PUSH_INTERVAL
    failures = 0
    while True:  # first run: register with the join token, retrying until the control plane is reachable
        try:
            if ensure_token():
                break
            sys.exit("No credentials: set SMWATCH_JOIN (join token) or AGENT_TOKEN")
        except urllib.error.HTTPError as error:
            log.error("registration rejected: HTTP %s (%s)", error.code, "join token invalid, expired, revoked or used up; get a new command from the dashboard" if error.code in (401, 403) else error.reason)
        except Exception as error:
            log.warning("cannot register yet (%s); retrying in 15s", error)
        time.sleep(15)
    log.info("push mode: reporting to %s (agent %s)", SMWATCH_URL, AGENT_VERSION)
    if AGENT_LOGS != "off":
        threading.Thread(target=task_loop, daemon=True, name="tasks").start()
    while True:
        started = time.monotonic()
        try:
            interval = push_once()
            if failures:
                log.info("connection to control plane restored")
            failures = 0
        except urllib.error.HTTPError as error:
            failures += 1
            log.error("control plane rejected report: HTTP %s (%s)", error.code, "token no longer valid" if error.code in (401, 403) else error.reason)
            if error.code == 401 and AGENT_TOKEN_FILE:
                try:
                    forget_token(); ensure_token()   # the control plane may have issued a new token file
                except Exception:
                    pass
            elif error.code == 401 and SMWATCH_JOIN:
                log.info("token rejected (server removed or token rotated): will re-register")
                forget_token()
                try:
                    ensure_token()
                except Exception as enroll_error:
                    log.warning("re-registration failed: %s", enroll_error)
        except Exception as error:  # network down, DNS, TLS... keep retrying
            failures += 1
            log.warning("report failed (%s); retrying", error)
        delay = interval if not failures else min(interval, 5 * 2 ** min(failures - 1, 4))
        time.sleep(max(1.0, delay - (time.monotonic() - started)))


def _build_app():
    from fastapi import FastAPI, Header, HTTPException  # imported lazily: push-only installs don't need FastAPI

    api = FastAPI(title="SM-Watch Monitoring Agent")

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
    pull = AGENT_MODE in ("pull", "both")
    if pull and len(AGENT_TOKEN) < 32:
        sys.exit("AGENT_TOKEN (32+ characters) is required in pull mode")
    if not pull and len(AGENT_TOKEN) < 32 and not SMWATCH_JOIN and not AGENT_TOKEN_FILE and not _load_state():
        sys.exit("Set SMWATCH_JOIN (join token from the dashboard) or AGENT_TOKEN")
    psutil.cpu_percent(interval=None)
    _network_rates()
    if AGENT_MODE in ("push", "both"):
        if not SMWATCH_URL:
            sys.exit("SMWATCH_URL is required in push mode")
        if AGENT_MODE == "both":
            threading.Thread(target=push_loop, daemon=True).start()
        else:
            push_loop()
    if AGENT_MODE in ("pull", "both"):
        import uvicorn
        uvicorn.run(_build_app(), host=os.getenv("AGENT_BIND", "0.0.0.0"), port=int(os.getenv("AGENT_PORT", "9100")))


if __name__ == "__main__":
    main()
