"""Which agent version this control plane ships, so the dashboard can say "update available"."""
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
_cache: dict[str, tuple[float, str]] = {}


def _read(name: str) -> str:
    path = ROOT / name
    try:
        mtime = path.stat().st_mtime
        cached = _cache.get(name)
        if cached and cached[0] == mtime:
            return cached[1]
        match = re.search(r'^AGENT_VERSION\s*=\s*"([^"]+)"', path.read_text(), re.M)
        version = match.group(1) if match else ""
        _cache[name] = (mtime, version)
        return version
    except OSError:
        return ""


def latest_server_agent() -> str:
    return _read("agent.py")


def latest_k8s_agent() -> str:
    return _read("k8s_agent.py")


def version_tuple(value: str | None) -> tuple[int, ...]:
    return tuple(int(x) for x in re.findall(r"\d+", value or "")[:4])


def is_outdated(current: str | None, latest: str) -> bool:
    return bool(current and latest and version_tuple(current) and version_tuple(current) < version_tuple(latest))
