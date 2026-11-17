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
import ipaddress
import json
import logging
import os
import platform
import re
import shutil
import socket
import struct
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from typing import Any

import psutil

AGENT_VERSION = "2.14.0"
_ENV_TOKEN = os.getenv("AGENT_TOKEN", "")                      # the token supplied by configuration; a rotation may supersede it (see _load_state)
AGENT_TOKEN = ""                                                # the token in use: resolved by ensure_token() (saved state first, then configuration)
AGENT_ALLOW_INSECURE = os.getenv("AGENT_ALLOW_INSECURE", "") == "1"   # permit http:// to a public address (not recommended)
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


# CPU is measured over the WHOLE reporting interval, not at the instant of the report: a background sampler reads the system CPU every
# few seconds and each report carries the average and the peak of those readings. (A single 0.25 s snapshot, which is what an
# instantaneous reading is, makes graphs and alerts jump around and miss what happened in between.)
AGENT_CPU_SAMPLE_SECONDS = max(1.0, min(30.0, float(os.getenv("AGENT_CPU_SAMPLE_SECONDS", "5"))))
_cpu_lock = threading.Lock()
_cpu_window = {"sum": 0.0, "n": 0, "peak": 0.0}
_cpu_thread: threading.Thread | None = None


def _cpu_sampler() -> None:
    psutil.cpu_percent(interval=None)   # prime: the first reading since process start is meaningless
    while True:
        time.sleep(AGENT_CPU_SAMPLE_SECONDS)
        value = psutil.cpu_percent(interval=None)
        with _cpu_lock:
            _cpu_window["sum"] += value
            _cpu_window["n"] += 1
            _cpu_window["peak"] = max(_cpu_window["peak"], value)


def cpu_window() -> tuple[float, float | None]:
    """(average, peak) CPU % since the previous call. Before the first interval has elapsed, a short direct sample."""
    global _cpu_thread
    if _cpu_thread is None:
        _cpu_thread = threading.Thread(target=_cpu_sampler, daemon=True, name="cpu")
        _cpu_thread.start()
    with _cpu_lock:
        n, total, peak = _cpu_window["n"], _cpu_window["sum"], _cpu_window["peak"]
        _cpu_window.update(sum=0.0, n=0, peak=0.0)
    if n == 0:
        value = psutil.cpu_percent(interval=0.25)
        return value, None
    return total / n, peak


_procs_primed = False


def process_rows() -> list[dict]:
    """Per-process CPU % averaged since the previous report (psutil keeps each process object between calls). The first call primes
    the counters and waits one short sample."""
    global _procs_primed
    if not _procs_primed:
        for process in psutil.process_iter():
            try:
                process.cpu_percent(interval=None)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        time.sleep(AGENT_PROCESS_SAMPLE_SECONDS)
        _procs_primed = True
    rows = []
    for process in psutil.process_iter(["pid", "name", "username", "memory_percent"]):
        try:
            rows.append({"pid": process.info["pid"], "name": (process.info["name"] or "unknown")[:100], "user": (process.info["username"] or "unknown")[:100], "cpu": round(process.cpu_percent(interval=None), 1), "memory": round(min(100.0, process.info["memory_percent"] or 0), 1)})
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    rows.sort(key=lambda item: item["cpu"], reverse=True)
    return rows


def collect() -> dict[str, Any]:
    memory = psutil.virtual_memory()
    swap = psutil.swap_memory()
    processes = process_rows()
    cpu, cpu_peak = cpu_window()
    try:
        load = os.getloadavg()[0]
    except (AttributeError, OSError):  # Windows
        load = cpu / 100 * (psutil.cpu_count() or 1)
    rx, tx = _network_rates()
    return {
        "hostname": host_name(),
        "platform": platform.platform()[:255],
        "os": os_name(),
        "kernel": kernel_version(),
        "arch": platform.machine()[:30],
        "agent_version": AGENT_VERSION,
        "cpu": round(min(100.0, cpu), 1),
        "cpu_peak": round(min(100.0, cpu_peak), 1) if cpu_peak is not None else None,
        "cpu_count": psutil.cpu_count() or 1,
        "memory": round(memory.percent, 1),
        "disk": round(psutil.disk_usage(AGENT_DISK_PATH).percent, 1),
        "load": round(load, 2),
        "swap": round(swap.percent, 1),
        "uptime_seconds": max(0, int(time.time() - psutil.boot_time())),
        "net_rx_bps": rx,
        "net_tx_bps": tx,
        "processes": processes[:AGENT_PROCESS_TOP_N],
        "capabilities": (["logs"] if AGENT_LOGS != "off" else []) + (["ssh"] if AGENT_SSH != "off" else []) + (["ssh_history"] if AGENT_SSH == "on" else []),
        "ssh_sessions": ssh_count(),
        "ssh_failures": ssh_failures(),
        "updates": updates_report(),
        "ips": local_addresses(),
        "public_ip": public_address(),
        "install": install_kind(),
        "traffic": traffic_stats(),
        "traffic_status": traffic_status(),
        "machine": hashlib.sha256(("smwatch-machine:" + machine_id()).encode()).hexdigest()[:32],   # lets the dashboard notice one machine monitored twice
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


_SKIP_IFACES = ("lo", "docker", "br-", "veth", "cni", "flannel", "cali", "vxlan", "kube", "virbr", "cilium", "weave", "podman", "tunl", "ipip", "gre", "sit", "dummy", "nodelocal", "antrea", "lxc", "ovs", "geneve", "tun", "nerdctl", "lxd")
AGENT_PUBLIC_IP = os.getenv("AGENT_PUBLIC_IP", "").strip()              # optional: tell the dashboard this server's public address
AGENT_PUBLIC_IP_URL = os.getenv("AGENT_PUBLIC_IP_URL", "").strip()      # optional: a URL that returns the caller's address (off by default: no outside calls)
_public_cache: dict = {"at": 0.0, "ip": ""}


def _host_namespace_addresses() -> list[dict]:
    """Addresses of the HOST, read from its network namespace (/proc/1/net) when the agent runs in a container with the host's /proc
    mounted: the container's own address on a Docker network says nothing about the machine."""
    base = os.path.join(os.getenv("AGENT_PROCFS_PATH") or "", "1", "net")
    if not os.getenv("AGENT_PROCFS_PATH"):
        return []
    try:
        with open(os.path.join(base, "route")) as handle:
            next(handle)
            networks = []
            for line in handle:
                f = line.split()
                if len(f) < 8 or int(f[1], 16) == 0 or int(f[2], 16) != 0:     # directly attached networks only
                    continue
                net = ipaddress.ip_network((socket.inet_ntoa(struct.pack("<L", int(f[1], 16))), bin(int(f[7], 16)).count("1")), strict=False)
                networks.append((f[0], net))
        found, last = [], None
        with open(os.path.join(base, "fib_trie")) as handle:
            for line in handle:
                line = line.strip()
                if line.startswith("|--"):
                    last = line[3:].strip()
                elif line.startswith("/32 host LOCAL") and last:
                    ip = ipaddress.ip_address(last)
                    iface = next((name for name, net in networks if ip in net), None)
                    if iface and not ip.is_loopback and not ip.is_link_local and not iface.lower().startswith(_SKIP_IFACES):
                        found.append({"iface": iface[:30], "ip": str(ip)})
        return found[:10]
    except (OSError, ValueError, StopIteration):
        return []


def local_addresses() -> list[dict]:
    """This machine's own (private) IPv4 addresses, without loopback, link-local and container-network interfaces."""
    host = _host_namespace_addresses()
    if host:
        return host
    found = []
    try:
        for name, addrs in psutil.net_if_addrs().items():
            if name.lower().startswith(_SKIP_IFACES):
                continue
            for addr in addrs:
                if addr.family != socket.AF_INET:
                    continue
                ip = ipaddress.ip_address(addr.address)
                if ip.is_loopback or ip.is_link_local or ip.is_unspecified:
                    continue
                found.append({"iface": name[:30], "ip": str(ip)})
    except Exception:   # never let an address lookup break a report
        return []
    return found[:10]


def public_address() -> str:
    """Only reported when the admin configured it (AGENT_PUBLIC_IP, or AGENT_PUBLIC_IP_URL fetched at most hourly)."""
    if AGENT_PUBLIC_IP:
        return AGENT_PUBLIC_IP
    if AGENT_PUBLIC_IP_URL and time.time() - _public_cache["at"] > 3600:
        _public_cache["at"] = time.time()
        try:
            with urllib.request.urlopen(AGENT_PUBLIC_IP_URL, timeout=5) as response:
                candidate = response.read(100).decode().strip()
            _public_cache["ip"] = str(ipaddress.ip_address(candidate))
        except Exception:
            _public_cache["ip"] = ""
    return _public_cache["ip"]


def install_kind() -> str:
    """How this agent runs, so the dashboard can show the right update command."""
    if os.getenv("SMWATCH_BUNDLED") == "1":
        return "bundled"
    if os.path.exists("/.dockerenv") or os.path.exists("/run/.containerenv"):
        return "docker"
    return "macos" if sys.platform == "darwin" else "systemd"


def os_name() -> str:
    """The operating system of the HOST, e.g. "Ubuntu 22.04.5 LTS" (inside Docker the container's own distro is meaningless)."""
    if sys.platform == "darwin":
        return f"macOS {platform.mac_ver()[0]}".strip()
    for path in (os.path.join(AGENT_HOST_ROOT, "etc/os-release"), os.path.join(AGENT_HOST_ROOT, "usr/lib/os-release"), "/etc/os-release"):
        try:
            with open(path) as handle:
                values = dict(line.rstrip("\n").split("=", 1) for line in handle if "=" in line and not line.startswith("#"))
            pretty = values.get("PRETTY_NAME", "").strip().strip('"')
            if pretty:
                return pretty[:100]
            name = values.get("NAME", "").strip().strip('"')
            if name:
                return f"{name} {values.get('VERSION_ID', '').strip().strip(chr(34))}".strip()[:100]
        except (OSError, ValueError):
            continue
    return platform.system()[:100]


def kernel_version() -> str:
    """The host's kernel (the kernel is shared with containers, so this is right inside Docker too)."""
    try:
        with open(os.path.join(os.getenv("AGENT_PROCFS_PATH") or "/proc", "sys/kernel/osrelease")) as handle:
            return handle.read().strip()[:60]
    except OSError:
        return platform.release()[:60]


# ---------------------------------------------------------------------------------------------------------------
# Real-traffic response times. When AGENT_ACCESS_LOG points at the access log of the load balancer / web server (nginx), the agent
# summarises the response times of the requests logged since its last report into a small histogram and sends ONLY that summary:
# no request, URL, address or user agent leaves the server. Needs `rt=$request_time` in the nginx log format (see the README).
# $request_time starts when nginx reads the first byte of the request, i.e. the moment it hit the load balancer.
# ---------------------------------------------------------------------------------------------------------------
AGENT_ACCESS_LOG = os.getenv("AGENT_ACCESS_LOG", "").strip()         # comma-separated paths or globs, as seen on the host
TRAFFIC_MAX_READ = 8 * 1024 * 1024                                    # most we read from one file per report; older lines are skipped
_traffic_bounds: list[float] = [5, 10, 25, 50, 75, 100, 150, 200, 300, 500, 750, 1000, 1500, 2000, 3000, 5000, 10000]   # replaced by the control plane's TRAFFIC_BUCKETS_MS
_traffic_files: dict[str, dict] = {}
_traffic_diag: dict = {}
_detected_cache: dict = {"at": 0.0, "found": []}
_traffic_last = 0.0
_RT = re.compile(r'(?:^|[\s,{"])(?:rt|request_time|reqtime)["]?\s*[=:]\s*"?([0-9]+(?:\.[0-9]+)?)')
_URT = re.compile(r'(?:^|[\s,{"])(?:urt|upstream_response_time)["]?\s*[=:]\s*"?([0-9.,:\s-]+)')
_STATUS = re.compile(r'"\s+(\d{3})\s')


_HAPROXY = re.compile(r"\s(-?\d+)/(-?\d+)/(-?\d+)/(-?\d+)/(\d+)\s(\d{3})\s")   # Tq/Tw/Tc/Tr/Tt then the status, as in HAProxy's http log


def _upstream_ms(raw) -> float | None:
    if raw in (None, "", "-"):
        return None
    parts = [float(x) for x in re.split(r"[,:\s]+", str(raw)) if re.match(r"^[0-9]+(\.[0-9]+)?$", x)]
    return sum(parts) * 1000 if parts else None


def parse_access_line(line: str) -> tuple[float, int, float | None] | None:
    """(request ms, HTTP status or 0, upstream ms or None) from an access log line, else None. Understood: nginx (rt= / request_time=,
    urt= / upstream_response_time=), JSON logs from nginx, Caddy (duration, seconds) and Traefik (Duration, nanoseconds), and HAProxy's http log."""
    line = line.strip()
    if not line:
        return None
    if line.startswith("{"):
        try:
            data = json.loads(line)
            status = int(data.get("status") or data.get("DownstreamStatus") or 0)
            if "request_time" in data or "rt" in data:                      # nginx JSON
                return float(data.get("request_time", data.get("rt"))) * 1000, status, _upstream_ms(data.get("upstream_response_time", data.get("urt")))
            if "Duration" in data:                                          # Traefik: nanoseconds
                origin = data.get("OriginDuration")
                return float(data["Duration"]) / 1e6, status, float(origin) / 1e6 if origin else None
            if "duration" in data:                                          # Caddy: seconds
                return float(data["duration"]) * 1000, status, None
            return None
        except (ValueError, TypeError):
            return None
    match = _RT.search(line)
    if match:
        found = _STATUS.search(line)
        u = _URT.search(line)
        return float(match.group(1)) * 1000, int(found.group(1)) if found else 0, _upstream_ms(u.group(1)) if u else None
    haproxy = _HAPROXY.search(line)
    if haproxy:
        reply = int(haproxy.group(4))
        return float(haproxy.group(5)), int(haproxy.group(6)), float(reply) if reply >= 0 else None
    return None


def _new_lines(path: str) -> list[str]:
    """Lines appended to `path` since the last call. The first call only remembers the end of the file (history is not replayed)."""
    state = _traffic_files.get(path)
    try:
        info = os.stat(path)
    except OSError:
        return []
    if state is None:
        _traffic_files[path] = {"inode": info.st_ino, "offset": info.st_size}
        return []
    if info.st_ino != state["inode"] or info.st_size < state["offset"]:   # rotated or truncated: start at the top of the new file
        state["inode"], state["offset"] = info.st_ino, 0
    start = state["offset"]
    if info.st_size - start > TRAFFIC_MAX_READ:
        start = info.st_size - TRAFFIC_MAX_READ
    if info.st_size <= start:
        return []
    with open(path, "rb") as handle:
        handle.seek(start)
        chunk = handle.read(info.st_size - start)
    end = chunk.rfind(b"\n")
    if end < 0:
        return []
    state["offset"] = start + end + 1
    return chunk[:end].decode("utf-8", errors="replace").split("\n")


def traffic_stats() -> dict | None:
    """Histogram + counters of the requests logged since the last report, or None (not configured / nothing new)."""
    global _traffic_last
    if not AGENT_ACCESS_LOG:
        return None
    import bisect
    now = time.monotonic()
    window = now - _traffic_last if _traffic_last else 0.0
    _traffic_last = now
    bounds = list(_traffic_bounds)
    counts = [0] * (len(bounds) + 1)
    total = errors5 = errors4 = up_count = 0
    sum_ms = peak = up_sum = 0.0
    sources = []
    diag = {"files": 0, "unreadable": 0, "lines": 0, "parsed": 0, "path": ""}
    for pattern in [p.strip() for p in AGENT_ACCESS_LOG.split(",") if p.strip()]:
        for path in sorted(glob.glob(_host_path(pattern))):
            if not os.path.isfile(path):
                continue
            diag["files"] += 1
            diag["path"] = diag["path"] or path
            if not os.access(path, os.R_OK):
                diag["unreadable"] += 1
                continue
            for line in _new_lines(path):
                diag["lines"] += 1
                parsed = parse_access_line(line)
                if parsed is None:
                    continue
                diag["parsed"] += 1
                ms, status, upstream = parsed
                if ms < 0 or ms > 3_600_000:
                    continue
                counts[bisect.bisect_left(bounds, ms)] += 1
                total += 1
                sum_ms += ms
                peak = max(peak, ms)
                if 500 <= status <= 599:
                    errors5 += 1
                elif 400 <= status <= 499:
                    errors4 += 1
                if upstream is not None:
                    up_sum += upstream
                    up_count += 1
            sources.append(os.path.basename(path))
    _traffic_diag.clear(); _traffic_diag.update(diag)
    if not total:
        return None
    return {"source": ",".join(sources)[:120], "window_seconds": round(window, 1), "requests": total, "errors_5xx": errors5, "errors_4xx": errors4,
            "sum_ms": round(sum_ms, 1), "max_ms": round(peak, 1), "upstream_sum_ms": round(up_sum, 1), "upstream_count": up_count, "bounds": bounds, "counts": counts}


ACCESS_LOG_CANDIDATES = ("/var/log/nginx/access.log", "/var/log/nginx/*access*.log", "/var/log/caddy/*.log", "/var/log/traefik/access.log", "/var/log/traefik/*.log", "/var/log/haproxy.log", "/var/log/haproxy/*.log")


def _tail_lines(path: str, count: int = 6) -> list[str]:
    try:
        with open(path, "rb") as handle:
            handle.seek(0, os.SEEK_END)
            size = handle.tell()
            handle.seek(max(0, size - 8192))
            return handle.read().decode("utf-8", errors="replace").splitlines()[-count:]
    except OSError:
        return []


def detect_access_logs() -> list[dict]:
    """Looks (at most every 5 minutes) for a web server / load balancer log in the usual places and checks, locally, whether its lines
    carry a response time. Only the answer (path, yes/no) is reported so the dashboard can say exactly what to do."""
    if time.time() - _detected_cache["at"] < 300:
        return _detected_cache["found"]
    found: list[dict] = []
    for pattern in ACCESS_LOG_CANDIDATES:
        for path in sorted(glob.glob(_host_path(pattern))):
            if os.path.isfile(path) and os.access(path, os.R_OK) and not path.endswith((".gz", ".1")):
                lines = _tail_lines(path)
                shown = "/" + os.path.relpath(path, AGENT_HOST_ROOT) if AGENT_HOST_ROOT not in ("", "/") else path
                if lines and not any(d["path"] == shown for d in found):
                    found.append({"path": shown[:200], "timing": any(parse_access_line(line) is not None for line in lines)})
    _detected_cache.update(at=time.time(), found=found[:5])
    return _detected_cache["found"]


def traffic_status() -> dict:
    """Why the response-time numbers are (not) there: reported with every report so the dashboard can explain it."""
    if not AGENT_ACCESS_LOG:
        return {"state": "off", "detected": detect_access_logs()}
    d = _traffic_diag
    if not d or not d.get("files"):
        state = "no_file"
    elif d.get("unreadable") and d["unreadable"] == d["files"]:
        state = "unreadable"
    elif not d.get("lines"):
        state = "waiting"
    elif not d.get("parsed"):
        state = "no_timing"
    else:
        state = "ok"
    return {"state": state, "path": (d.get("path") or AGENT_ACCESS_LOG)[:200], "lines": int(d.get("lines", 0)), "parsed": int(d.get("parsed", 0)), "detected": [] if state == "ok" else detect_access_logs()}


def adopt_traffic_bounds(values) -> None:
    global _traffic_bounds
    try:
        bounds = sorted({float(v) for v in values})
        if 1 <= len(bounds) <= 40 and all(b > 0 for b in bounds):
            _traffic_bounds = bounds
    except (TypeError, ValueError):
        pass


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
    if IS_MAC:   # the same id the installer registers with, so a re-registration never duplicates the machine
        try:
            out = subprocess.run(["ioreg", "-rd1", "-c", "IOPlatformExpertDevice"], capture_output=True, text=True, timeout=5).stdout
            match = re.search(r'"IOPlatformUUID" = "([^"]+)"', out)
            if match:
                return match.group(1)
        except (OSError, subprocess.SubprocessError):
            pass
    return hashlib.sha256(f"{host_name()}|{platform.node()}|{platform.machine()}".encode()).hexdigest()  # Windows/other fallback


def _state_dirs() -> tuple[str, str]:
    return (AGENT_STATE_DIR, os.path.join(os.path.expanduser("~"), ".sm-watch-agent"))


def _state_file() -> str | None:
    for directory in _state_dirs():
        try:
            os.makedirs(directory, mode=0o700, exist_ok=True)
            if os.access(directory, os.W_OK):
                return os.path.join(directory, "agent.json")
        except OSError:
            continue
    return None


def _fingerprint(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest() if value else ""


def _configured_token() -> str:
    """The token handed to the agent by configuration: AGENT_TOKEN, or the contents of AGENT_TOKEN_FILE."""
    if _ENV_TOKEN:
        return _ENV_TOKEN
    if AGENT_TOKEN_FILE:
        with open(AGENT_TOKEN_FILE) as handle:   # raises until the control plane has written it; the caller retries
            return handle.read().strip()
    return ""


def _load_state(configured: str = "") -> dict:
    """The agent's saved identity. A saved token (from registration or from a rotation) is only trusted while the configured
    token is the one it was saved next to, so deliberately installing a different token always takes effect."""
    for directory in _state_dirs():
        try:
            with open(os.path.join(directory, "agent.json")) as handle:
                state = json.load(handle)
            if state.get("url") == SMWATCH_URL and len(state.get("token", "")) >= 32 and (not configured or state.get("env_ref") == _fingerprint(configured)):
                return state
        except (OSError, ValueError):
            continue
    return {}


def _save_state(token: str, server_id: int | None, name: str | None) -> None:
    path = _state_file()
    if not path:
        log.warning("could not save the agent token (no writable state directory); the agent will re-register on restart")
        return
    try:
        env_ref = _fingerprint(_configured_token())
    except OSError:
        env_ref = ""
    payload = {"url": SMWATCH_URL, "token": token, "server_id": server_id, "name": name, "env_ref": env_ref}
    temporary = path + ".tmp"
    with open(os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "w") as handle:   # never world-readable, replaced atomically
        json.dump(payload, handle)
    os.replace(temporary, path)


def enroll() -> str:
    """Registers this machine with the control plane using the join token and returns its own agent token."""
    body = json.dumps({"hostname": host_name(), "machine_id": machine_id(), "platform": platform.platform()[:255], "agent_version": AGENT_VERSION}).encode()
    request = urllib.request.Request(
        f"{SMWATCH_URL}/api/agent/enroll", data=body, method="POST",
        headers={"Content-Type": "application/json", "Authorization": f"Bearer {SMWATCH_JOIN}", "User-Agent": f"sm-watch-agent/{AGENT_VERSION}"},
    )
    with urllib.request.urlopen(request, timeout=20) as response:
        reply = json.loads(response.read().decode())
    _save_state(reply["agent_token"], reply["server_id"], reply["name"])
    log.info("registered with the control plane as %r (server id %s)", reply["name"], reply["server_id"])
    return reply["agent_token"]


def adopt_rotated_token(new_token: str) -> None:
    """The control plane staged a new token for us (rotation). Switch to it; the old one stops working once we use the new one."""
    global AGENT_TOKEN
    if len(new_token) < 32 or new_token == AGENT_TOKEN:
        return
    saved = _load_state(_ENV_TOKEN) or {}
    AGENT_TOKEN = new_token
    _save_state(new_token, saved.get("server_id"), saved.get("name"))
    log.info("agent token rotated by the control plane")


def ensure_token() -> bool:
    """Sets the global AGENT_TOKEN from saved state, configuration, or a fresh enrollment. False when none is possible."""
    global AGENT_TOKEN
    if len(AGENT_TOKEN) >= 32:
        return True
    configured = _configured_token()
    saved = _load_state(configured)
    if saved:
        AGENT_TOKEN = saved["token"]
        return True
    if len(configured) >= 32:
        AGENT_TOKEN = configured
        return True
    if SMWATCH_JOIN:
        AGENT_TOKEN = enroll()
        return True
    return False


def forget_token() -> None:
    """The control plane rejected our token (server deleted/rotated): drop it so we can re-enroll."""
    global AGENT_TOKEN
    AGENT_TOKEN = ""
    for directory in _state_dirs():
        try:
            os.remove(os.path.join(directory, "agent.json"))
        except OSError:
            pass


# ---------------------------------------------------------------------------------------------------------------
# Log access policy: which logs this agent may expose. Set by an administrator on the control plane, delivered with each
# report reply, remembered on disk, and enforced HERE as well as on the control plane. It can only narrow what the agent's
# local settings allow, so a compromised control plane cannot make the agent expose more.
# ---------------------------------------------------------------------------------------------------------------
_policy: dict | None = None
_policy_loaded = False


def _policy_path() -> str | None:
    for directory in _state_dirs():
        try:
            os.makedirs(directory, mode=0o700, exist_ok=True)
            if os.access(directory, os.W_OK):
                return os.path.join(directory, "policy.json")
        except OSError:
            continue
    return None


def _valid_policy(value) -> bool:
    try:
        d, j, f = value["docker"], value["journal"], value["files"]
        return (isinstance(d["enabled"], bool) and isinstance(d["include"], list) and isinstance(d["exclude"], list) and isinstance(j["enabled"], bool)
                and isinstance(j["units"], list) and isinstance(f["enabled"], bool) and (f["allow"] is None or isinstance(f["allow"], list))
                and all(isinstance(x, str) for x in d["include"] + d["exclude"] + j["units"] + (f["allow"] or [])))
    except (KeyError, TypeError):
        return False


def current_policy() -> dict | None:
    global _policy, _policy_loaded
    if not _policy_loaded:
        _policy_loaded = True
        for directory in _state_dirs():
            try:
                with open(os.path.join(directory, "policy.json")) as handle:
                    candidate = json.load(handle)
                if _valid_policy(candidate):
                    _policy = candidate
                    break
            except (OSError, ValueError):
                continue
    return _policy


def apply_policy(candidate) -> None:
    """Adopts a policy from the control plane (ignored if malformed) and remembers it across restarts."""
    global _policy, _policy_loaded
    if not _valid_policy(candidate):
        return
    _policy_loaded = True
    if candidate == _policy:
        return
    _policy = candidate
    path = _policy_path()
    if path:
        try:
            temporary = path + ".tmp"
            with open(os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "w") as handle:
                json.dump(candidate, handle)
            os.replace(temporary, path)
        except OSError:
            log.warning("could not save the log policy; it applies until restart")
    log.info("log access policy updated by the control plane")


def _matches(name: str, patterns: list[str]) -> bool:
    return any(fnmatch.fnmatchcase(name, pattern) for pattern in patterns)


def policy_allows(source: str, target: str) -> bool:
    policy = current_policy()
    if policy is None or source == "inventory":
        return True
    if source == "docker":
        d = policy["docker"]
        return d["enabled"] and _matches(target, d["include"]) and not _matches(target, d["exclude"])
    if source == "journal":
        j = policy["journal"]
        return j["enabled"] and ("*" in j["units"] if target == "all" else _matches(target, j["units"]))
    if source == "file":
        f = policy["files"]
        return f["enabled"] and (f["allow"] is None or _matches(target, f["allow"]))
    return False


def apply_policy_to_inventory(inventory: dict) -> dict:
    policy = current_policy()
    if policy is None:
        return inventory
    if "files" in inventory:
        inventory["files"] = [path for path in inventory["files"] if policy_allows("file", path)]
        inventory["containers"] = [c for c in inventory.get("containers", []) if policy_allows("docker", c["name"])]
        inventory["docker"] = bool(inventory.get("docker")) and policy["docker"]["enabled"] and bool(inventory["containers"])
        inventory["journal"] = bool(inventory.get("journal")) and policy["journal"]["enabled"]
        inventory["journal_all"] = policy["journal"]["enabled"] and "*" in policy["journal"]["units"]
    if "units" in inventory:
        inventory["units"] = [u for u in inventory["units"] if policy_allows("journal", u)]
    return inventory


# ---------------------------------------------------------------------------------------------------------------
# Logs. The dashboard can ask for logs, but only from this fixed set of sources. Nothing here runs a shell, accepts
# a command, or reads a path outside the allow-list; every request field is validated again on this side.
# ---------------------------------------------------------------------------------------------------------------
IS_MAC = sys.platform == "darwin"
# A fixed allow-list of well-known log locations (never an arbitrary path). Binary files (wtmp, btmp, journal files)
# are not listed, and anything that turns out to be binary is refused when read.
LOG_FILE_GLOBS = [
    # generic: anything the system or a package writes as *.log, up to three directories deep
    "/var/log/*.log", "/var/log/*/*.log", "/var/log/*/*/*.log",
    # system
    "/var/log/syslog", "/var/log/syslog.1", "/var/log/messages", "/var/log/messages.1", "/var/log/auth.log", "/var/log/auth.log.1", "/var/log/secure",
    "/var/log/kern.log", "/var/log/kern.log.1", "/var/log/dmesg", "/var/log/daemon.log", "/var/log/user.log", "/var/log/debug", "/var/log/boot.log",
    "/var/log/cron", "/var/log/cron.log", "/var/log/maillog", "/var/log/mail.log", "/var/log/mail.err", "/var/log/audit/audit.log", "/var/log/dpkg.log",
    "/var/log/apt/history.log", "/var/log/apt/term.log", "/var/log/yum.log", "/var/log/dnf*.log", "/var/log/zypper.log", "/var/log/pacman.log",
    # web servers and proxies (access/error logs, including the most recent rotated copy)
    "/var/log/nginx/*", "/var/log/apache2/*", "/var/log/httpd/*", "/var/log/caddy/*", "/var/log/traefik/*", "/var/log/haproxy*", "/var/log/varnish/*",
    "/var/log/lighttpd/*", "/var/log/php*/*", "/var/log/php*-fpm.log", "/var/log/tomcat*/*", "/var/log/jetty*/*",
    # databases, queues, search
    "/var/log/mysql/*", "/var/log/mariadb/*", "/var/log/postgresql/*", "/var/log/redis/*", "/var/log/mongodb/*", "/var/log/rabbitmq/*",
    "/var/log/elasticsearch/*", "/var/log/kibana/*", "/var/log/kafka/*", "/var/log/zookeeper/*", "/var/log/cassandra/*", "/var/log/influxdb/*",
    # security, certificates, process managers
    "/var/log/fail2ban.log", "/var/log/ufw.log", "/var/log/letsencrypt/*", "/var/log/supervisor/*", "/var/log/pm2/*", "/var/log/unattended-upgrades/*",
    "/var/log/sm-watch-agent.log",
    # macOS
    "/Library/Logs/*.log", "/Library/Logs/*/*.log", "/var/log/system.log",
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
    """The command prefix for reading the system journal, or None when this agent cannot read one."""
    if IS_MAC:
        return ["log"] if shutil.which("log") else None            # macOS unified logging
    exe = shutil.which("journalctl")
    in_container = AGENT_HOST_ROOT not in ("", "/")
    if exe and in_container:
        # The agent runs in a container with the host mounted: read the HOST's journal files, never the container's own.
        if any(os.path.isdir(os.path.join(AGENT_HOST_ROOT, d)) for d in ("var/log/journal", "run/log/journal")):
            return [exe, "--root", AGENT_HOST_ROOT]
        return None
    if exe:
        return [exe]
    # No journalctl in this container: fall back to the host's own binary run inside the read-only host mount.
    if in_container and os.path.exists(os.path.join(AGENT_HOST_ROOT, "usr/bin/journalctl")) and shutil.which("chroot") and os.geteuid() == 0:
        return ["chroot", AGENT_HOST_ROOT, "/usr/bin/journalctl"]
    return None


def _run_limited(command: list[str], max_bytes: int = 30_000_000, timeout: float = 25) -> tuple[str, str]:
    """Runs a command, keeping at most max_bytes of its output (the macOS log can be enormous). Returns (stdout, stderr)."""
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    timer = threading.Timer(timeout, process.kill)
    timer.start()
    try:
        data = process.stdout.read(max_bytes) if process.stdout else b""
        process.kill()
        error = process.stderr.read(4000) if process.stderr else b""
    finally:
        timer.cancel()
        process.wait()
    return data.decode(errors="replace"), error.decode(errors="replace")


def journal_units() -> list[str]:
    base = _journalctl()
    if not base or IS_MAC:       # the macOS unified log has no unit list
        return []
    try:
        fields = subprocess.run(base + ["--no-pager", "-F", "_SYSTEMD_UNIT"], capture_output=True, text=True, timeout=15).stdout.split()
        return sorted({u for u in fields if u.endswith(".service") and TARGET_RE.match(u)})[:300]
    except (OSError, subprocess.SubprocessError):
        return []


_cache: dict[str, tuple[float, object]] = {}


def _cached(key: str, ttl: float, compute):
    """Tiny TTL cache: the dashboard asks for the inventory every time a Logs page opens."""
    hit = _cache.get(key)
    if hit and time.monotonic() - hit[0] < ttl:
        return hit[1]
    value = compute()
    _cache[key] = (time.monotonic(), value)
    return value


def log_inventory(units: bool = False) -> dict:
    """What this agent can read. The (slow) list of journal units is only built when asked for (units=True) and cached."""
    if units:
        return {"units": _cached("units", 600, journal_units)}
    return _cached("inventory", 20, _build_inventory)


def _environment_note() -> str | None:
    """Explains the most common reason a source is empty: the agent is in Docker on a Mac/Windows PC and sees Docker's VM."""
    try:
        with open(os.path.join(AGENT_HOST_ROOT, "etc/os-release")) as handle:
            release = handle.read().lower()
        host = host_name().lower()
    except OSError:
        return None
    if any(word in release or word in host for word in ("orbstack", "docker desktop", "docker-desktop", "linuxkit", "rancher desktop", "colima", "lima")):
        return ("This agent runs inside Docker on a Mac or Windows PC, so it sees Docker's small Linux VM and not the computer's own logs. "
                "To read this machine's system logs, install the agent directly on it (Servers → Add server → Install agent → shell command).")
    return None


def _build_inventory() -> dict:
    journal = _journalctl() is not None
    inventory = {"files": log_files(), "journal": journal, "journal_label": "System log" if IS_MAC else "System journal", "platform": "macos" if IS_MAC else "linux",
                 "units": [], "docker": docker_available(), "containers": [], "notes": []}
    if not journal:
        if IS_MAC:
            inventory["notes"].append("The macOS log tool is not available to this agent")
        elif AGENT_HOST_ROOT not in ("", "/") and shutil.which("journalctl") is None and not os.path.isdir(os.path.join(AGENT_HOST_ROOT, "var/log/journal")) and not os.path.isdir(os.path.join(AGENT_HOST_ROOT, "run/log/journal")):
            inventory["notes"].append("This host keeps no systemd journal (it is not a systemd machine, or journald is not running)")
        else:
            inventory["notes"].append("journald is not readable by the agent. Install the agent with the shell command (it joins the systemd-journal group), or give this container journalctl and the host's /var/log/journal")
    if not inventory["files"]:
        inventory["notes"].append("No standard log files were found on this host (nginx, syslog, auth, cron, databases, ...). Add your own with AGENT_LOG_PATHS=/path/*.log")
    if inventory["docker"]:
        try:
            inventory["containers"] = docker_containers()
        except Exception as error:
            inventory["docker"] = False
            inventory["notes"].append(f"Docker: {error}")
    elif os.path.exists(DOCKER_SOCKET):
        inventory["notes"].append("Docker is installed but the agent has no access to it (AGENT_LOGS=nodocker, or not in the docker group)")
    environment = _environment_note()
    if environment:
        inventory["notes"].insert(0, environment)
    return inventory


def _tail_file(path: str, max_bytes: int = 4_000_000) -> str:
    with open(path, "rb") as handle:
        if b"\x00" in handle.read(4096):
            raise ValueError("This looks like a binary file, not a text log")
        handle.seek(0, os.SEEK_END)
        size = handle.tell()
        handle.seek(max(0, size - max_bytes))
        data = handle.read()
    text = data.decode(errors="replace")
    return text.split("\n", 1)[1] if size > max_bytes and "\n" in text else text


_ISO_TS = re.compile(r"^\[?(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})(?:[.,]\d+)?\s*(Z|[+-]\d{2}:?\d{2})?")
_NGINX_TS = re.compile(r"\[(\d{2})/([A-Za-z]{3})/(\d{4}):(\d{2}):(\d{2}):(\d{2}) ([+-]\d{4})\]")
_SYSLOG_TS = re.compile(r"^([A-Z][a-z]{2})\s+(\d{1,2}) (\d{2}):(\d{2}):(\d{2})")
_MONTHS = {m: i for i, m in enumerate(("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"), 1)}


def line_time(line: str, now: float | None = None) -> float | None:
    """Epoch seconds of a log line, from the timestamp most logs start with (ISO 8601, nginx access, classic syslog), else None."""
    import calendar
    from datetime import timedelta
    m = _ISO_TS.match(line)
    if m:
        y, mo, d, hh, mi, ss = (int(m.group(i)) for i in range(1, 7))
        tz = m.group(7)
        try:
            stamp = calendar.timegm((y, mo, d, hh, mi, ss))
        except (ValueError, OverflowError):
            return None
        if tz and tz != "Z":
            sign = 1 if tz[0] == "+" else -1
            digits = tz[1:].replace(":", "")
            stamp -= sign * (int(digits[:2]) * 3600 + int(digits[2:4] or 0) * 60)
        elif not tz:
            stamp = time.mktime((y, mo, d, hh, mi, ss, 0, 0, -1))      # no zone given: the machine's own time
        return float(stamp)
    m = _NGINX_TS.search(line)
    if m and m.group(2) in _MONTHS:
        stamp = calendar.timegm((int(m.group(3)), _MONTHS[m.group(2)], int(m.group(1)), int(m.group(4)), int(m.group(5)), int(m.group(6))))
        tz = m.group(7)
        return float(stamp - (1 if tz[0] == "+" else -1) * (int(tz[1:3]) * 3600 + int(tz[3:5]) * 60))
    m = _SYSLOG_TS.match(line)
    if m and m.group(1) in _MONTHS:
        now = now or time.time()
        year = time.localtime(now).tm_year
        stamp = time.mktime((year, _MONTHS[m.group(1)], int(m.group(2)), int(m.group(3)), int(m.group(4)), int(m.group(5)), 0, 0, -1))
        return float(stamp - 366 * 86400) if stamp > now + 86400 else float(stamp)   # "Dec 31" read in January belongs to last year
    return None


def filter_lines_by_time(text: str, seconds: int, now: float | None = None) -> str:
    """Keeps the lines from the last `seconds`. A line without a timestamp (a stack trace line, a wrapped message) follows the decision
    made for the line before it; lines before the first timestamp are kept."""
    cutoff = (now or time.time()) - seconds
    keep, out = True, []
    for row in text.splitlines():
        stamp = line_time(row, now)
        if stamp is not None:
            keep = stamp >= cutoff
        if keep:
            out.append(row)
    return "\n".join(out)


# ------------------------------------------------------------------------------------------------ SSH activity
# Who is logged in over SSH right now (utmp), who logged in and out before (wtmp, or wtmpdb on newer distributions), and the
# most recent shell commands (bash / zsh / fish history files). Read on demand only, like logs, and nothing is changed.
# Command lines can contain passwords and tokens: obvious secrets are masked HERE, before anything leaves the server.
#   AGENT_SSH=on (default when logs are on) | nohistory (sessions and logins, no command history) | off
AGENT_SSH = os.getenv("AGENT_SSH", "on" if AGENT_LOGS != "off" else "off").lower()
SSH_HISTORY_MAX = 500
_UTMP = struct.Struct("<hhi32s4s32s256shhiii16s20s")   # glibc struct utmp: 384 bytes on x86_64, aarch64 and 32-bit builds alike
USER_PROCESS, DEAD_PROCESS, BOOT_TIME = 7, 8, 2


def _cstr(raw: bytes) -> str:
    return "".join(ch if ch.isprintable() else " " for ch in raw.split(b"\0", 1)[0].decode("utf-8", "replace")).strip()


def _utmp_address(raw: bytes) -> str:
    if not any(raw):
        return ""
    try:
        return socket.inet_ntop(socket.AF_INET, raw[:4]) if not any(raw[4:]) else socket.inet_ntop(socket.AF_INET6, raw)
    except (OSError, ValueError):
        return ""


def _utmp_records(path: str, max_bytes: int = 8_000_000) -> list[dict]:
    """Records of a utmp/wtmp file (only its newest `max_bytes`: wtmp grows for years)."""
    size = _UTMP.size
    with open(path, "rb") as handle:
        handle.seek(0, os.SEEK_END)
        end = handle.tell()
        start = max(0, end - max_bytes)
        start -= start % size
        handle.seek(start)
        data = handle.read()
    records = []
    for offset in range(0, len(data) - size + 1, size):
        kind, _, pid, line, _, user, host, _, _, _, sec, _, addr, _ = _UTMP.unpack_from(data, offset)
        records.append({"type": kind, "pid": pid, "tty": _cstr(line), "user": _cstr(user), "host": _cstr(host) or _utmp_address(addr), "ts": sec})
    return records


_HOST_RE = re.compile(r"[A-Za-z0-9._:%\-]{1,255}")


def _remote(host: str) -> bool:
    """A login that came over the network (SSH): the host is an address or a host name. Not a local console, a desktop (':0'),
    or the extra records terminal multiplexers write ('tmux(1234).%0', ':S.0' from screen, 'mosh [1234]')."""
    return bool(host) and not host.startswith(":") and bool(_HOST_RE.fullmatch(host))


def _owns_tty(pid: int, tty: str) -> bool | None:
    """Is process `pid` still attached to terminal `tty` (pts/N)? A utmp entry whose session crashed keeps its old pid, and Linux
    later hands that pid to an unrelated process: without this check such a ghost counts as a logged-in user. None = cannot tell."""
    match = re.fullmatch(r"pts/(\d+)", tty)
    if not match:
        return None
    try:
        with open(os.path.join(AGENT_PROCFS_PATH, str(pid), "stat")) as handle:
            fields = handle.read().rsplit(")", 1)[1].split()
        tty_nr = int(fields[4])
    except (OSError, ValueError, IndexError):
        return None
    major, minor = (tty_nr >> 8) & 0xFFF, (tty_nr & 0xFF) | ((tty_nr >> 12) & 0xFFF00)
    number = int(match.group(1))
    return 136 <= major <= 143 and (major - 136) * 256 + minor == number


def _first_existing(*paths: str) -> str | None:
    for path in paths:
        real = _host_path(path)
        if os.path.exists(real):
            return real
    return None


def _wtmpdb_rows(limit: int) -> list[dict] | None:
    """Newer systemd distributions (Debian 13, openSUSE, ...) keep logins in an SQLite database instead of wtmp."""
    path = _first_existing("/var/lib/wtmpdb/wtmp.db")
    if not path:
        return None
    import sqlite3
    for uri in (f"file:{path}?mode=ro", f"file:{path}?immutable=1"):   # immutable: the host filesystem is mounted read-only in Docker
        try:
            with sqlite3.connect(uri, uri=True, timeout=2) as db:
                rows = db.execute("SELECT User, Login, Logout, TTY, RemoteHost FROM wtmp WHERE RemoteHost IS NOT NULL AND RemoteHost != '' "
                                  "AND User != 'reboot' ORDER BY Login DESC LIMIT ?", (limit,)).fetchall()
            return [{"user": _cstr(str(u or "").encode()), "login": int(li / 1e6) if li else None, "logout": int(lo / 1e6) if lo else None,
                     "tty": _cstr(str(t or "").encode()), "ip": _cstr(str(h or "").encode())} for u, li, lo, t, h in rows]
        except Exception:   # locked, unreadable or an unexpected schema: try the next way, then give up quietly
            continue
    return None


def _pid_alive(pid: int) -> bool:
    try:
        return pid > 0 and psutil.pid_exists(pid)
    except Exception:
        return True


def ssh_sessions() -> tuple[list[dict], str | None]:
    """Current remote logins: (sessions, note). Each session: user, ip, tty, since (epoch seconds), pid."""
    path = _first_existing("/run/utmp", "/var/run/utmp")
    sessions: list[dict] = []
    if path and not IS_MAC:
        try:
            by_tty: dict[str, dict] = {}
            for r in _utmp_records(path, 2_000_000):
                if r["type"] != USER_PROCESS or not _remote(r["host"]) or not _pid_alive(r["pid"]) or _owns_tty(r["pid"], r["tty"]) is False:
                    continue
                by_tty[r["tty"]] = {"user": r["user"], "ip": r["host"], "tty": r["tty"], "since": r["ts"], "pid": r["pid"]}   # one session per terminal
            return sorted(by_tty.values(), key=lambda s: s["since"] or 0, reverse=True), None
        except OSError as error:
            return [], f"Cannot read {path}: {error.strerror or error}"
    if AGENT_HOST_ROOT in ("", "/"):   # macOS, or a distribution without utmp: ask the operating system
        try:
            for u in psutil.users():
                if _remote(u.host or ""):
                    sessions.append({"user": u.name, "ip": u.host, "tty": u.terminal or "", "since": int(u.started), "pid": getattr(u, "pid", None) or 0})
            return sessions, None
        except Exception as error:   # noqa: BLE001
            return [], f"Cannot list logged-in users: {error}"
    rows = _wtmpdb_rows(200)   # no utmp at all (systemd 257+): open wtmpdb sessions since the last boot
    if rows is not None:
        boot = psutil.boot_time()
        return [{"user": r["user"], "ip": r["ip"], "tty": r["tty"], "since": r["login"], "pid": 0} for r in rows if r["logout"] is None and (r["login"] or 0) >= boot], None
    return [], "This server keeps no login records the agent can read (no utmp or wtmpdb)."


def ssh_count() -> int | None:
    """For every report: the number of open SSH sessions (no names or addresses). None when SSH reporting is off."""
    policy = current_policy()
    if AGENT_SSH == "off" or (policy is not None and not policy.get("ssh", {}).get("enabled", True)):
        return None
    try:
        return len(ssh_sessions()[0])
    except Exception:   # noqa: BLE001  (never let this break a metrics report)
        return None


def ssh_logins(limit: int = 300) -> tuple[list[dict], str | None]:
    """Past remote logins, newest first: user, ip, tty, login, logout (epoch seconds), end: logout | reboot | active | unknown."""
    rows = _wtmpdb_rows(limit)
    if rows is not None:
        active = {(s["tty"], s["user"]) for s in ssh_sessions()[0]}
        for r in rows:
            r["end"] = "logout" if r["logout"] else ("active" if (r["tty"], r["user"]) in active else "unknown")
        return rows, None
    path = _first_existing("/var/log/wtmp")
    if not path or IS_MAC:
        return [], "No login history file (/var/log/wtmp) on this server."
    try:
        records = _utmp_records(path)
    except OSError as error:
        return [], f"Cannot read {path}: {error.strerror or error}"
    open_by_tty: dict[str, dict] = {}
    done: list[dict] = []
    for r in records:
        if r["type"] == BOOT_TIME:
            for s in open_by_tty.values():
                s["logout"], s["end"] = r["ts"], "reboot"
                done.append(s)
            open_by_tty.clear()
        elif r["type"] == USER_PROCESS and _remote(r["host"]):
            if r["tty"] in open_by_tty:   # the previous session on this terminal never wrote a logout record
                done.append(open_by_tty.pop(r["tty"]))
            open_by_tty[r["tty"]] = {"user": r["user"], "ip": r["host"], "tty": r["tty"], "login": r["ts"], "logout": None, "end": "unknown", "pid": r["pid"]}
        elif r["type"] == DEAD_PROCESS and r["tty"] in open_by_tty:
            s = open_by_tty.pop(r["tty"])
            s["logout"], s["end"] = r["ts"], "logout"
            done.append(s)
    for s in open_by_tty.values():
        s["end"] = "active" if _pid_alive(s["pid"]) else "unknown"
        done.append(s)
    done.sort(key=lambda s: s["login"] or 0, reverse=True)
    for s in done:
        s.pop("pid", None)
    return done[:limit], None


# Obvious secrets on a command line. Best effort: anything matching is replaced with *** before the command leaves the server.
_SECRET_PATTERNS = [
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*", re.S), "*** private key ***"),
    (re.compile(r"(?i)(\b[A-Z0-9_]*(?:PASSWORD|PASSWD|PASS|SECRET|TOKEN|API_?KEY|ACCESS_?KEY|PRIVATE_?KEY|CREDENTIALS?|AUTH)[A-Z0-9_]*\s*=\s*)(\"[^\"]*\"|'[^']*'|\S+)"), r"\1***"),
    (re.compile(r"(?i)(--?(?:password|passwd|pass|pwd|token|secret|api[-_]?key|access[-_]?key|secret[-_]?key|auth[-_]?token|client[-_]?secret)(?:=|\s+))(\"[^\"]*\"|'[^']*'|\S+)"), r"\1***"),
    (re.compile(r"(?i)\b((?:mysql|mysqldump|mysqladmin|mariadb|mariadb-dump)\b.*?\s-p)([^\s-][^\s]*)"), r"\1***"),
    (re.compile(r"(?i)(\bsshpass\s+-p\s*)(\S+)"), r"\1***"),
    (re.compile(r"(?i)(\b(?:-u|--user)\s+[^\s:]+:)(\S+)"), r"\1***"),                        # curl -u user:password
    (re.compile(r"([A-Za-z][A-Za-z0-9+.-]*://[^/\s:@]+:)([^@\s]+)(@)"), r"\1***\3"),           # scheme://user:password@host
    (re.compile(r"(?i)((?:authorization|x-api-key|api-key|private-token)\s*:\s*(?:bearer\s+|basic\s+|token\s+)?)([^\s'\"]+)"), r"\1***"),
    (re.compile(r"\b(ghp_|gho_|ghs_|ghu_|github_pat_|glpat-|xox[abprs]-|sk-|sk_live_|rk_live_|AKIA|ASIA|AIza|ya29\.)[A-Za-z0-9_\-.]{8,}"), r"\1***"),
    (re.compile(r"(?i)(\becho\s+)(\"[^\"]*\"|'[^']*'|\S+)(?=.*\|\s*(?:sudo\s+)?(?:chpasswd|passwd|htpasswd|docker\s+login|podman\s+login|helm\s+registry\s+login))"), r"\1***"),
    (re.compile(r"(?i)(\b(?:htpasswd)\s+(?:-\w+\s+)*\S+\s+\S+\s+)(\S+)"), r"\1***"),
]


def redact_command(command: str) -> str:
    for pattern, replacement in _SECRET_PATTERNS:
        command = pattern.sub(replacement, command)
    return command


def _tail_text(path: str, max_bytes: int = 512_000) -> str:
    with open(path, "rb") as handle:
        handle.seek(0, os.SEEK_END)
        size = handle.tell()
        handle.seek(max(0, size - max_bytes))
        data = handle.read()
    text = data.decode("utf-8", "replace")
    return text.split("\n", 1)[1] if size > max_bytes and "\n" in text else text   # drop the partial first line


def _parse_history(kind: str, text: str) -> list[dict]:
    out: list[dict] = []
    if kind == "fish":
        current: dict | None = None
        for line in text.splitlines():
            if line.startswith("- cmd: "):
                current = {"cmd": line[7:].replace("\\n", "\n").replace("\\\\", "\\"), "ts": None}
                out.append(current)
            elif current is not None and line.strip().startswith("when:"):
                try:
                    current["ts"] = int(line.split(":", 1)[1].strip())
                except ValueError:
                    pass
        return out
    stamp = None
    pending = ""
    for line in text.splitlines():
        if kind == "zsh" and line.startswith(": ") and ";" in line:   # extended history  ": 1700000000:0;command"
            head, command = line[2:].split(";", 1)
            try:
                stamp = int(head.split(":", 1)[0])
            except ValueError:
                stamp = None
            line = command
        elif kind == "bash" and re.fullmatch(r"#\d{9,11}", line):    # HISTTIMEFORMAT timestamps
            stamp = int(line[1:])
            continue
        if kind == "zsh" and line.endswith("\\"):                     # zsh stores multi-line commands with a trailing backslash
            pending += line[:-1] + "\n"
            continue
        command = (pending + line).strip()
        pending = ""
        if command:
            out.append({"cmd": command, "ts": stamp})
        stamp = None
    return out


HISTORY_FILES = ((".bash_history", "bash"), (".zsh_history", "zsh"), (".histfile", "zsh"), (".local/share/fish/fish_history", "fish"), (".history", "bash"), (".ash_history", "bash"))


def _home_dirs() -> list[tuple[str, str]]:
    """(user, home on the host). From /etc/passwd when readable, plus /root and /home/* as a fallback."""
    homes: dict[str, str] = {}
    try:
        with open(_host_path("/etc/passwd")) as handle:
            for row in handle:
                fields = row.strip().split(":")
                if len(fields) >= 7 and fields[5].startswith("/") and fields[5] not in ("/", "/nonexistent", "/dev/null") and not fields[6].endswith(("nologin", "false", "sync")):
                    homes.setdefault(fields[5], fields[0])
    except OSError:
        pass
    homes.setdefault("/root", "root")
    for real in glob.glob(_host_path("/home/*")) + glob.glob(_host_path("/Users/*")):
        host_view = "/" + os.path.relpath(real, AGENT_HOST_ROOT) if AGENT_HOST_ROOT not in ("", "/") else real
        homes.setdefault(host_view, os.path.basename(real))
    return [(user, home) for home, user in sorted(homes.items(), key=lambda kv: (kv[1] != "root", kv[1]))][:100]


def _container_facts() -> dict:
    """What limits this process's file access (only meaningful for the Docker agent)."""
    facts = {"docker": AGENT_HOST_ROOT not in ("", "/"), "uid": os.geteuid() if hasattr(os, "geteuid") else None, "userns": False, "selinux": False, "dac_read": False}
    try:
        with open("/proc/self/uid_map") as handle:
            first = handle.read().split()
        facts["userns"] = len(first) >= 3 and not (first[0] == "0" and first[1] == "0")    # root inside is not root outside
    except OSError:
        pass
    try:
        with open("/proc/self/status") as handle:
            capeff = int(next(line.split()[1] for line in handle if line.startswith("CapEff:")), 16)
        facts["dac_read"] = bool(capeff & (1 << 2)) or bool(capeff & (1 << 1))           # CAP_DAC_READ_SEARCH or CAP_DAC_OVERRIDE
    except (OSError, StopIteration, ValueError):
        pass
    for path in (_host_path("/sys/fs/selinux/enforce"), "/sys/fs/selinux/enforce"):
        try:
            with open(path) as handle:
                facts["selinux"] = handle.read().strip() == "1"
            break
        except OSError:
            continue
    return facts


def _history_advice(blocked: list[str], facts: dict) -> str:
    who = ", ".join(sorted(set(blocked)))
    if not facts["docker"]:
        return (f"The agent may not read the shell history of: {who}. Re-run the install command on this server with SMWATCH_HISTORY=on "
                "(this lets the agent read, never change, every file).")
    if facts["userns"]:
        return (f"The agent cannot read the shell history of: {who}. Docker on this server runs containers in a separate user namespace "
                "(rootless Docker or userns-remap), so the agent is not root on the host. Re-run the Docker install command with "
                "SMWATCH_HISTORY=on (it adds --userns=host), or use the shell install instead.")
    if facts["selinux"]:
        return (f"The agent cannot read the shell history of: {who}. SELinux is enforcing on this server and keeps containers out of home "
                "folders. Re-run the Docker install command with SMWATCH_HISTORY=on (it adds --security-opt label=disable).")
    return (f"The agent cannot read the shell history of: {who}. Re-run the Docker install command with SMWATCH_HISTORY=on "
            "(it gives the container read-only access to every file: --cap-add DAC_READ_SEARCH).")


def shell_history(lines: int = 100) -> dict:
    """The newest `lines` commands per user and shell, newest first, secrets masked. Anything that could not be read is explained
    in `notes` (never silently skipped: an empty answer must mean there really is no history)."""
    lines = max(1, min(SSH_HISTORY_MAX, lines))
    users, blocked, checked = [], [], 0
    for user, home in _home_dirs():
        home_real = _host_path(home)
        try:
            os.listdir(home_real)            # raises if the agent may not open this home folder (isfile() would just say False)
        except PermissionError:
            blocked.append(user)
            continue
        except OSError:
            continue                         # no such folder
        checked += 1
        for rel, kind in HISTORY_FILES:
            path = os.path.join(home_real, rel)
            try:
                real = os.path.realpath(path)
                if not os.path.isfile(real):
                    continue
                if not real.startswith(os.path.realpath(home_real) + os.sep):   # a history "file" linked elsewhere is not followed
                    continue
                stat = os.stat(real)
                entries = _parse_history(kind, _tail_text(real))
            except PermissionError:
                blocked.append(user)
                continue
            except OSError:
                continue
            if not entries:
                continue
            newest = entries[-lines:][::-1]
            users.append({"user": user, "shell": kind, "file": os.path.join(home, rel), "modified": int(stat.st_mtime), "total": len(entries),
                          "commands": [{"cmd": redact_command(e["cmd"])[:2000], "ts": e["ts"]} for e in newest]})
    notes = []
    if blocked:
        notes.append(_history_advice(blocked, _container_facts()))
    if not users and not blocked:
        notes.append(f"No shell history file was found in the {checked} home folder(s) the agent checked (.bash_history, .zsh_history, fish). "
                     "Users whose shell writes its history elsewhere (a custom HISTFILE) are not shown.")
    return {"users": users, "notes": notes}


def ssh_answer(target: str, lines: int) -> str:
    if AGENT_SSH == "off":
        raise ValueError("SSH activity is turned off on this server (AGENT_SSH=off)")
    policy = current_policy()
    ssh = (policy or {}).get("ssh", {"enabled": True, "history": True})
    if not ssh.get("enabled", True):
        raise ValueError("Blocked by this server's access policy")
    if target == "sessions":
        sessions, note = ssh_sessions()
        logins, login_note = ssh_logins()
        return json.dumps({"sessions": sessions, "logins": logins, "notes": [n for n in (note, login_note) if n], "now": int(time.time()), "history_available": AGENT_SSH == "on" and ssh.get("history", True)})
    if target == "history":
        if AGENT_SSH != "on" or not ssh.get("history", True):
            raise ValueError("Command history is turned off for this server")
        return json.dumps(shell_history(lines))
    raise ValueError("Unknown SSH request")


# ------------------------------------------------------------------------------------------------ security signals
# Failed SSH logins (from the auth log or the journal) and pending OS updates. Both are sent with the regular report; only counts,
# addresses and user names are sent, never log lines. AGENT_SECURITY=off turns both off.
AGENT_SECURITY = os.getenv("AGENT_SECURITY", "on").lower()
AGENT_UPDATES_HOURS = max(1.0, float(os.getenv("AGENT_UPDATES_HOURS", "6")))
SSH_FAIL_PATTERNS = [
    re.compile(r"Failed (?:password|publickey|keyboard-interactive/pam) for (?:invalid user )?(?P<user>\S*) from (?P<ip>[0-9a-fA-F:.]+)"),
    re.compile(r"Invalid user (?P<user>\S*) from (?P<ip>[0-9a-fA-F:.]+)"),
    re.compile(r"Connection closed by (?:authenticating|invalid) user (?P<user>\S*) (?P<ip>[0-9a-fA-F:.]+) port \d+ \[preauth\]"),
    re.compile(r"maximum authentication attempts exceeded for (?:invalid user )?(?P<user>\S*) from (?P<ip>[0-9a-fA-F:.]+)"),
    re.compile(r"Did not receive identification string from (?P<ip>[0-9a-fA-F:.]+)"),
]
_journal_since: dict = {"t": None}


def _auth_log() -> str | None:
    for path in ("/var/log/auth.log", "/var/log/secure"):
        real = _host_path(path)
        if os.path.isfile(real) and os.access(real, os.R_OK):
            return real
    return None


def parse_ssh_failures(lines: list[str]) -> dict:
    ips: dict[str, int] = {}
    users: dict[str, int] = {}
    total = 0
    for line in lines:
        if "sshd" not in line and "Failed password" not in line:
            continue
        for pattern in SSH_FAIL_PATTERNS:
            match = pattern.search(line)
            if match:
                try:
                    ip = str(ipaddress.ip_address(match.group("ip")))
                except ValueError:
                    break
                total += 1
                ips[ip] = ips.get(ip, 0) + 1
                user = match.groupdict().get("user")
                if user:
                    user = "".join(ch for ch in user if ch.isprintable())[:40]
                    users[user] = users.get(user, 0) + 1
                break
    top = lambda d, n: dict(sorted(d.items(), key=lambda kv: -kv[1])[:n])   # noqa: E731
    return {"total": total, "ips": top(ips, 25), "users": top(users, 15), "distinct_ips": len(ips)}


def ssh_failures() -> dict | None:
    """Failed SSH login attempts since the previous report, or None when this server's auth log cannot be read."""
    if AGENT_SECURITY == "off":
        return None
    path = _auth_log()
    if path:
        return parse_ssh_failures(_new_lines(path))
    base = _journalctl() if not IS_MAC else None
    if not base:
        return None
    now = time.time()
    since, _journal_since["t"] = _journal_since["t"], now
    if since is None:
        return {"total": 0, "ips": {}, "users": {}, "distinct_ips": 0}
    try:
        out = subprocess.run(base + ["--no-pager", "-o", "cat", "-u", "ssh.service", "-u", "sshd.service", "--since", f"@{int(since)}", "--until", f"@{int(now)}"],
                             capture_output=True, text=True, timeout=15, errors="replace").stdout
    except (OSError, subprocess.SubprocessError):
        return None
    return parse_ssh_failures([f"sshd: {line}" for line in out.splitlines()[-20000:]])


_updates: dict = {"at": 0.0, "value": None, "running": False}


def _run(command: list[str], timeout: float = 120) -> tuple[int, str]:
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=timeout, errors="replace", env={**os.environ, "LC_ALL": "C", "LANG": "C"})
        return result.returncode, result.stdout
    except (OSError, subprocess.SubprocessError) as error:
        return -1, str(error)


def check_updates() -> dict:
    """Pending package updates (security ones first) and whether a reboot is needed. Read-only: nothing is downloaded or installed."""
    root = AGENT_HOST_ROOT if AGENT_HOST_ROOT not in ("", "/") else ""
    reboot_file = _host_path("/var/run/reboot-required") if os.path.exists(_host_path("/var/run/reboot-required")) else _host_path("/run/reboot-required")
    reboot = os.path.exists(reboot_file)
    reboot_pkgs = []
    try:
        with open(reboot_file + ".pkgs") as handle:
            reboot_pkgs = sorted({line.strip() for line in handle if line.strip()})[:30]
    except OSError:
        pass
    result: dict = {"manager": None, "total": 0, "security": 0, "packages": [], "reboot_required": reboot, "reboot_packages": reboot_pkgs, "error": None,
                    "checked_at": datetime.now(timezone.utc).isoformat()}
    if os.path.exists(_host_path("/var/lib/dpkg/status")) and shutil.which("apt-get"):
        result["manager"] = "apt"
        opts = ["-o", "Debug::NoLocking=1", "-o", f"Dir::Cache={os.path.join(tempfile_dir(), 'apt-cache')}"]
        if root:   # the Docker agent reads the HOST's package lists and dpkg database (mounted read-only)
            opts += ["-o", f"Dir={root}", "-o", f"Dir::State::status={root}/var/lib/dpkg/status", "-o", f"Dir::Etc={root}/etc/apt", "-o", f"Dir::State::Lists={root}/var/lib/apt/lists"]
        code, out = _run(["apt-get", "-s", "-qq", *opts, "dist-upgrade"])
        if code != 0:
            result["error"] = (out or "apt-get failed").strip().splitlines()[-1][:200] if out else "apt-get failed"
        packages = []
        for line in out.splitlines():
            if line.startswith("Inst "):
                parts = line.split()
                name, security = parts[1], "-security" in line or "security." in line
                version = re.search(r"\(([^ )]+)", line)
                packages.append({"name": name, "version": version.group(1) if version else "", "security": security})
        result["total"], result["security"] = len(packages), sum(p["security"] for p in packages)
        result["packages"] = sorted(packages, key=lambda p: (not p["security"], p["name"]))[:60]
        stamp = _host_path("/var/lib/apt/periodic/update-success-stamp")
        lists = _host_path("/var/lib/apt/lists")
        try:
            result["lists_age_hours"] = round((time.time() - os.stat(stamp if os.path.exists(stamp) else lists).st_mtime) / 3600, 1)
        except OSError:
            pass
    elif not root and (shutil.which("dnf") or shutil.which("yum")):
        tool = shutil.which("dnf") or shutil.which("yum")
        result["manager"] = os.path.basename(tool)
        code, out = _run([tool, "-q", "-C", "check-update"])
        names = [line.split()[0] for line in out.splitlines() if line and not line.startswith((" ", "Obsoleting", "Last metadata")) and len(line.split()) >= 3]
        _, sec = _run([tool, "-q", "-C", "updateinfo", "list", "--security"])
        security = {line.split()[-1].rsplit("-", 2)[0] for line in sec.splitlines() if len(line.split()) >= 3}
        packages = [{"name": n.rsplit(".", 1)[0], "version": "", "security": n.rsplit(".", 1)[0] in security} for n in names]
        result["total"], result["security"] = len(packages), sum(p["security"] for p in packages)
        result["packages"] = sorted(packages, key=lambda p: (not p["security"], p["name"]))[:60]
        if code not in (0, 100):
            result["error"] = "the package cache is empty or stale (run 'dnf makecache')"
        if shutil.which("needs-restarting"):
            rc, _ = _run(["needs-restarting", "-r"], 30)
            result["reboot_required"] = rc == 1
    elif not root and shutil.which("apk"):
        result["manager"] = "apk"
        _, out = _run(["apk", "version", "-l", "<"])
        packages = [{"name": line.split()[0].rsplit("-", 2)[0], "version": "", "security": False} for line in out.splitlines()[1:] if line.strip()]
        result["total"], result["packages"] = len(packages), packages[:60]
    else:
        result["error"] = "No supported package manager found" + (" for the host (the Docker agent supports Debian and Ubuntu hosts)" if root else "")
    return result


def tempfile_dir() -> str:
    import tempfile
    return tempfile.gettempdir()


def updates_report() -> dict | None:
    """The cached update summary; refreshed in the background every AGENT_UPDATES_HOURS (apt simulation takes a few seconds)."""
    if AGENT_SECURITY == "off" or IS_MAC:
        return None
    if not _updates["running"] and time.time() - _updates["at"] > AGENT_UPDATES_HOURS * 3600:
        _updates["running"] = True

        def work():
            try:
                _updates["value"] = check_updates()
            except Exception as error:   # noqa: BLE001
                _updates["value"] = {"error": str(error)[:200], "manager": None, "total": 0, "security": 0, "packages": [], "reboot_required": False, "checked_at": datetime.now(timezone.utc).isoformat()}
            finally:
                _updates["at"], _updates["running"] = time.time(), False
        threading.Thread(target=work, daemon=True).start()
    return _updates["value"]


def fetch_logs(task: dict) -> tuple[str, bool]:
    """Runs one validated log request. Returns (text, truncated)."""
    source = task.get("source")
    target = str(task.get("target") or "")
    lines = max(1, min(MAX_LOG_LINES, int(task.get("lines") or 200)))
    since = max(0, min(31 * 86400, max(int(task.get("since_seconds") or 0), int(task.get("since_minutes") or 0) * 60)))   # seconds; 0 = no time limit
    needle = str(task.get("grep") or "")[:200].lower()
    priority = task.get("priority") or ""
    if source == "inventory":
        return json.dumps(apply_policy_to_inventory(dict(log_inventory(units=target == "units")))), False
    if source == "ssh":
        return ssh_answer(target, lines), False
    if not TARGET_RE.match(target) or ".." in target:
        raise ValueError("Invalid log target")
    if not policy_allows(str(source), target):
        raise ValueError("Blocked by this server's log access policy")
    scan = 20000 if needle else lines   # with a filter, look further back and keep the last matches

    if source == "docker":
        if not docker_available():
            raise ValueError("Docker logs are not available to this agent")
        if target not in {c["name"] for c in docker_containers()}:
            raise ValueError("No such container on this server")
        query = f"stdout=1&stderr=1&timestamps=1&tail={scan}" + (f"&since={int(time.time()) - since}" if since else "")
        text = _demux(_docker(f"/containers/{target}/logs?{query}", raw=True))
    elif source == "journal":
        base = _journalctl()
        if not base:
            raise ValueError("The system journal is not available to this agent")
        if IS_MAC:
            window = since or 3600                                  # the unified log is huge: always bound the time window
            command = base + ["show", "--style", "compact", "--last", f"{min(window, 86400)}s"]
            predicates = []
            if target != "all":
                predicates.append(f'process == "{target}"')          # target is validated: letters, digits and . _ : / @ - only
            if priority in ("emerg", "alert", "crit", "err"):
                predicates.append("(messageType == error || messageType == fault)")
            if predicates:
                command += ["--predicate", " && ".join(predicates)]
            text, error_text = _run_limited(command)
            if not text.strip() and error_text.strip():
                raise RuntimeError(error_text.strip()[:300])
        else:
            command = base + ["--no-pager", "-o", "short-iso", "-n", str(scan)]
            if target != "all":
                command += ["-u", target]
            if since:
                command += ["--since", f"-{since}s"]
            if priority in PRIORITIES:
                command += ["-p", priority]
            result = subprocess.run(command, capture_output=True, text=True, timeout=25, errors="replace")
            if result.returncode != 0 and not result.stdout:
                raise RuntimeError((result.stderr or "journalctl failed").strip()[:300])
            text = result.stdout
    elif source == "file":
        text = _tail_file(_allowed_file(target))
        if since:   # files carry no timestamps of their own: use the ones in the lines (ISO, nginx, syslog) when they have them
            text = filter_lines_by_time(text, since)
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


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """The agent never follows HTTP redirects. urllib would re-send the Authorization header (this agent's token) to wherever a
    redirect points, including another host or plain http: a misconfigured or hostile proxy could collect tokens that way."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(req.full_url, code, f"refused to follow a redirect to {newurl} (credentials are never forwarded)", headers, fp)


def install_safe_opener() -> None:
    urllib.request.install_opener(urllib.request.build_opener(_NoRedirect))


def _api(method: str, path: str, payload: dict | None = None, timeout: float = 20) -> dict:
    request = urllib.request.Request(
        f"{SMWATCH_URL}{path}", data=json.dumps(payload).encode() if payload is not None else None, method=method,
        headers={"Content-Type": "application/json", "Authorization": f"Bearer {AGENT_TOKEN}", "User-Agent": f"sm-watch-agent/{AGENT_VERSION}"},
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.loads(response.read().decode() or "{}")


def _run_task(task: dict) -> None:
    try:
        output, truncated = fetch_logs(task)
        result = {"ok": True, "output": output, "truncated": truncated}
    except Exception as error:
        result = {"ok": False, "error": f"{type(error).__name__}: {error}"[:1500]}
    try:
        _api("POST", f"/api/agent/tasks/{int(task['id'])}/result", result)
    except Exception as error:
        log.debug("could not deliver log result: %s", error)


def task_loop() -> None:
    """Long-polls the control plane for log requests: the server holds the request open and answers the moment the
    dashboard asks for something, so there is no polling delay. Requests run concurrently in a small pool. This loop
    lives in its own thread so metrics reporting is never delayed."""
    from concurrent.futures import ThreadPoolExecutor

    pool = ThreadPoolExecutor(max_workers=4, thread_name_prefix="logs")
    failures = 0
    while True:
        started = time.monotonic()
        try:
            if len(AGENT_TOKEN) < 32:
                time.sleep(AGENT_TASK_POLL)
                continue
            tasks = _api("GET", "/api/agent/tasks?wait=20", timeout=35).get("tasks", [])
            failures = 0
            for task in tasks:
                pool.submit(_run_task, task)
            if not tasks and time.monotonic() - started < 2:
                time.sleep(AGENT_TASK_POLL)   # an older control plane without long-polling answers instantly: don't spin
        except urllib.error.HTTPError as error:
            failures += 1
            log.debug("task poll rejected: HTTP %s", error.code)
            time.sleep(min(15, 2 * failures))
        except Exception as error:
            failures += 1
            log.debug("task poll failed: %s", error)
            time.sleep(min(15, 2 * failures))


# Networks where unencrypted HTTP is acceptable. An explicit list (not ipaddress.is_private, which also counts documentation
# ranges such as 203.0.113.0/24) so the agent applies exactly the same policy as the installer scripts.
_PRIVATE_NETWORKS = [ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16", "::1/128", "fc00::/7", "fe80::/10")]


def _is_internal_host(host: str) -> bool:
    """True for addresses where unencrypted HTTP is acceptable: private/loopback/link-local IPs and internal-looking names."""
    host = host.strip("[]").lower()
    try:
        address = ipaddress.ip_address(host)
        return any(address in network for network in _PRIVATE_NETWORKS if network.version == address.version)
    except ValueError:
        return "." not in host or host.endswith((".local", ".lan", ".internal", ".home.arpa", ".localdomain", ".docker"))


def insecure_url_problem() -> str | None:
    """The agent runs code and ships logs on behalf of the control plane: refuse to talk to a public server in clear text."""
    parsed = urllib.parse.urlsplit(SMWATCH_URL)
    if parsed.scheme == "https" or AGENT_ALLOW_INSECURE:
        return None
    if parsed.scheme == "http" and parsed.hostname and _is_internal_host(parsed.hostname):
        return None   # LAN / VPN / Docker network
    return (f"{SMWATCH_URL} is not HTTPS and is not a private address. Credentials and logs would cross the network unencrypted "
            "and could be read or altered. Use an https:// address (see the README: HTTPS with nginx), or set AGENT_ALLOW_INSECURE=1 to override.")


def push_once() -> int:
    """Sends one report. Returns the interval (seconds) the control plane wants next."""
    body = json.dumps(collect()).encode()
    request = urllib.request.Request(
        f"{SMWATCH_URL}/api/agent/report", data=body, method="POST",
        headers={"Content-Type": "application/json", "Authorization": f"Bearer {AGENT_TOKEN}", "User-Agent": f"sm-watch-agent/{AGENT_VERSION}"},
    )
    with urllib.request.urlopen(request, timeout=15) as response:
        reply = json.loads(response.read().decode() or "{}")
    if reply.get("rotate_token"):
        adopt_rotated_token(str(reply["rotate_token"]))
    if "log_policy" in reply:
        apply_policy(reply["log_policy"])
    if reply.get("traffic_buckets_ms"):
        adopt_traffic_bounds(reply["traffic_buckets_ms"])
    return max(5, int(reply.get("interval_seconds", AGENT_PUSH_INTERVAL)))


def check() -> int:
    """One-shot connectivity test used by the installer and for troubleshooting: python agent.py --check"""
    if not SMWATCH_URL:
        print("FAIL: SMWATCH_URL is not set"); return 1
    problem = insecure_url_problem()
    if problem:
        print(f"FAIL: {problem}"); return 1
    try:
        configured = _configured_token()
    except OSError:
        configured = ""
    if len(configured) < 32 and not SMWATCH_JOIN and not _load_state(configured):
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
        import hmac
        if not hmac.compare_digest((authorization or "").encode(), f"Bearer {AGENT_TOKEN}".encode()):   # constant time: no timing oracle on the token
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
    install_safe_opener()   # before any request: tokens are never re-sent to a redirect target
    if "--version" in sys.argv:
        print(AGENT_VERSION); return
    if "--check" in sys.argv:
        psutil.cpu_percent(interval=None); _network_rates()
        sys.exit(check())
    problem = insecure_url_problem() if SMWATCH_URL else None
    if problem:
        sys.exit(problem)
    pull = AGENT_MODE in ("pull", "both")
    try:
        configured = _configured_token()
    except OSError:
        configured = ""   # the token file may not exist yet; the registration loop keeps retrying
    if pull and len(configured) < 32:
        sys.exit("AGENT_TOKEN (32+ characters) is required in pull mode")
    if pull:
        globals()["AGENT_TOKEN"] = configured   # the pull server authenticates the control plane with this token
    if not pull and len(configured) < 32 and not SMWATCH_JOIN and not AGENT_TOKEN_FILE and not _load_state():
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
        # Pull mode receives the agent token on every check. AGENT_TLS_CERT + AGENT_TLS_KEY serve it over https so the token is
        # never readable on the network (without them: keep the port on a private network or behind a TLS proxy).
        cert, key = os.getenv("AGENT_TLS_CERT", ""), os.getenv("AGENT_TLS_KEY", "")
        tls = {"ssl_certfile": cert, "ssl_keyfile": key} if cert and key else {}
        if not tls:
            log.warning("pull mode without TLS: the agent token travels unencrypted. Set AGENT_TLS_CERT and AGENT_TLS_KEY, or restrict port %s to a private network.", os.getenv("AGENT_PORT", "9100"))
        uvicorn.run(_build_app(), host=os.getenv("AGENT_BIND", "0.0.0.0"), port=int(os.getenv("AGENT_PORT", "9100")), **tls)


if __name__ == "__main__":
    main()
