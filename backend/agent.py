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

AGENT_VERSION = "2.8.0"
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
        "ips": local_addresses(),
        "public_ip": public_address(),
        "install": install_kind(),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


_SKIP_IFACES = ("lo", "docker", "br-", "veth", "cni", "flannel", "cali", "vxlan", "kube", "virbr", "cilium", "weave", "podman")
AGENT_PUBLIC_IP = os.getenv("AGENT_PUBLIC_IP", "").strip()              # optional: tell the dashboard this server's public address
AGENT_PUBLIC_IP_URL = os.getenv("AGENT_PUBLIC_IP_URL", "").strip()      # optional: a URL that returns the caller's address (off by default: no outside calls)
_public_cache: dict = {"at": 0.0, "ip": ""}


def local_addresses() -> list[dict]:
    """This machine's own (private) IPv4 addresses, without loopback, link-local and container-network interfaces."""
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


def fetch_logs(task: dict) -> tuple[str, bool]:
    """Runs one validated log request. Returns (text, truncated)."""
    source = task.get("source")
    target = str(task.get("target") or "")
    lines = max(1, min(MAX_LOG_LINES, int(task.get("lines") or 200)))
    since = max(0, min(60 * 24 * 30, int(task.get("since_minutes") or 0)))
    needle = str(task.get("grep") or "")[:200].lower()
    priority = task.get("priority") or ""
    if source == "inventory":
        return json.dumps(apply_policy_to_inventory(dict(log_inventory(units=target == "units")))), False
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
        query = f"stdout=1&stderr=1&timestamps=1&tail={scan}" + (f"&since={int(time.time()) - since * 60}" if since else "")
        text = _demux(_docker(f"/containers/{target}/logs?{query}", raw=True))
    elif source == "journal":
        base = _journalctl()
        if not base:
            raise ValueError("The system journal is not available to this agent")
        if IS_MAC:
            minutes = since or 60                                   # the unified log is huge: always bound the time window
            command = base + ["show", "--style", "compact", "--last", f"{min(minutes, 60 * 24)}m"]
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
        uvicorn.run(_build_app(), host=os.getenv("AGENT_BIND", "0.0.0.0"), port=int(os.getenv("AGENT_PORT", "9100")))


if __name__ == "__main__":
    main()
