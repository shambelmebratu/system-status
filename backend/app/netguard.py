"""Outbound-request guard against SSRF.

Monitoring private LAN hosts is a core use case, so RFC1918 ranges are allowed by
default (see BLOCK_PRIVATE_TARGETS). Loopback, link-local (cloud metadata),
unspecified, multicast and the stack's own internal service names are always
blocked. Redirects are re-validated on every hop.
"""
import ipaddress
import re
import socket
import urllib.parse
import urllib.request

from .config import get_settings

_HOST_RE = re.compile(r"^(?=.{1,253}$)[A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?$|^[0-9A-Fa-f:.]+$")
_METADATA = {ipaddress.ip_address("169.254.169.254"), ipaddress.ip_address("fd00:ec2::254")}


class BlockedTargetError(ValueError):
    pass


def _ip_blocked(ip: ipaddress._BaseAddress) -> str | None:
    if getattr(ip, "ipv4_mapped", None):
        ip = ip.ipv4_mapped
    if ip in _METADATA or ip.is_link_local:
        return "link-local/metadata addresses are not allowed"
    if ip.is_loopback or ip.is_unspecified or ip.is_multicast or ip.is_reserved:
        return "loopback/reserved addresses are not allowed"
    if get_settings().block_private_targets and ip.is_private:
        return "private addresses are not allowed"
    return None


def validate_host(host: str, resolve: bool = True) -> str:
    """Validate a bare hostname or IP. Returns it unchanged or raises BlockedTargetError."""
    host = (host or "").strip().strip("[]")
    if not host or host.startswith("-") or not _HOST_RE.match(host):
        raise BlockedTargetError("Invalid host name")
    blocked_names = {name.strip().lower() for name in get_settings().blocked_hosts.split(",") if name.strip()}
    if host.lower().rstrip(".") in blocked_names:
        raise BlockedTargetError(f"Host '{host}' is not allowed")
    try:
        addresses = [ipaddress.ip_address(host)]
    except ValueError:
        if not resolve:
            return host
        try:
            addresses = [ipaddress.ip_address(info[4][0]) for info in socket.getaddrinfo(host, None)]
        except socket.gaierror:
            return host  # unresolved: the check itself will report the failure
    for address in addresses:
        reason = _ip_blocked(address)
        if reason:
            raise BlockedTargetError(f"Host '{host}' rejected: {reason}")
    return host


def validate_url(url: str, resolve: bool = True) -> str:
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise BlockedTargetError("URL must be http:// or https:// with a host")
    if parsed.username or parsed.password:
        raise BlockedTargetError("Credentials in URLs are not allowed")
    validate_host(parsed.hostname, resolve=resolve)
    return url


class _GuardedRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        validate_url(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


_opener = urllib.request.build_opener(_GuardedRedirect)


def safe_urlopen(request: urllib.request.Request, timeout: float):
    """urlopen that validates the destination and every redirect hop."""
    validate_url(request.full_url)
    return _opener.open(request, timeout=timeout)
