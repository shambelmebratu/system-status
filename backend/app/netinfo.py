"""Which addresses are really public. An address that sits inside a network this control plane is itself attached to (a Docker
network, a LAN) is local, whatever its number looks like: 172.80.x.x is a perfectly valid public range, but also what a custom
Docker address pool can hand out."""
import ipaddress
import socket
import time
from functools import lru_cache

from .config import get_settings


@lru_cache(maxsize=1)
def _local_networks_cached(bucket: int) -> tuple:
    networks = []
    try:
        with open("/proc/net/route") as handle:
            next(handle)
            for line in handle:
                fields = line.split()
                if len(fields) < 8:
                    continue
                dest, gateway, mask = (int(fields[1], 16), int(fields[2], 16), int(fields[7], 16))
                if dest == 0 or gateway != 0:      # skip the default route and routes through a gateway: keep directly attached networks
                    continue
                network = ipaddress.ip_network((socket.ntohl(dest), bin(socket.ntohl(mask)).count("1")), strict=False)
                if network.prefixlen > 0:
                    networks.append(network)
    except (OSError, ValueError):
        pass
    return tuple(networks)


def local_networks() -> tuple:
    return _local_networks_cached(int(time.time() // 300))     # re-read every 5 minutes


def is_public(value: str | None) -> bool:
    """Globally routable AND not inside a network this control plane is directly attached to."""
    try:
        ip = ipaddress.ip_address(value or "")
    except ValueError:
        return False
    if not ip.is_global:
        return False
    return not any(ip.version == n.version and ip in n for n in local_networks())


def running_in_container() -> bool:
    import os
    return os.path.exists("/.dockerenv")


def in_container_network(value: str | None) -> bool:
    """True when this API runs in a container and `value` is an address on one of the networks it is attached to."""
    try:
        ip = ipaddress.ip_address(value or "")
    except ValueError:
        return False
    return running_in_container() and any(ip.version == n.version and ip in n for n in local_networks())


@lru_cache(maxsize=1)
def _resolved(bucket: int, host: str) -> str:
    try:
        for info in socket.getaddrinfo(host, None, socket.AF_INET, socket.SOCK_STREAM):
            if is_public(info[4][0]):
                return info[4][0]
    except OSError:
        pass
    return ""


def control_plane_public_ip() -> str:
    """The public address of the machine running SM-Watch: HOST_PUBLIC_IP if set, else what PUBLIC_URL's host name resolves to."""
    settings = get_settings()
    if settings.host_public_ip and is_public(settings.host_public_ip):
        return settings.host_public_ip
    from urllib.parse import urlsplit
    host = urlsplit(settings.public_url).hostname if settings.public_url else None
    return _resolved(int(time.time() // 600), host) if host else ""
