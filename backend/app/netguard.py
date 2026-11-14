"""Outbound-request guard against SSRF.

Monitoring private LAN hosts is a core use case, so RFC1918 ranges are allowed by
default (see BLOCK_PRIVATE_TARGETS). Loopback, link-local (cloud metadata),
unspecified, multicast and the stack's own internal service names are always
blocked. Redirects are re-validated on every hop.
"""
import http.client
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
        new = super().redirect_request(req, fp, code, msg, headers, newurl)
        if new is not None:
            old_origin, new_origin = urllib.parse.urlsplit(req.full_url), urllib.parse.urlsplit(newurl)
            downgrade = old_origin.scheme == "https" and new_origin.scheme != "https"
            if downgrade or (old_origin.scheme, old_origin.netloc.lower()) != (new_origin.scheme, new_origin.netloc.lower()):
                # urllib copies every header to the redirect target. An agent token, webhook secret or bot token must never
                # travel to a different host (or from https down to http) just because the first server said "go there".
                for name in list(new.headers):
                    if name.lower() in ("authorization", "cookie", "proxy-authorization"):
                        del new.headers[name]
                for name in list(new.unredirected_hdrs):
                    if name.lower() in ("authorization", "cookie", "proxy-authorization"):
                        del new.unredirected_hdrs[name]
        return new


def _check_peer(sock, host: str) -> None:
    """validate_url() resolves the name BEFORE the request; the connection resolves it again. A hostile DNS server can answer the
    second lookup differently ("DNS rebinding") and point the request at 127.0.0.1 or the cloud metadata address. Checking the
    address we are ACTUALLY connected to closes that gap."""
    if urllib.request.getproxies():   # behind an outbound proxy (HTTP(S)_PROXY) the peer IS the proxy: it resolves the name, not us
        return
    try:
        peer = ipaddress.ip_address(sock.getpeername()[0].split("%")[0])
    except (OSError, ValueError, IndexError):
        return
    reason = _ip_blocked(peer)
    if reason:
        sock.close()
        raise BlockedTargetError(f"Host '{host}' rejected: {reason}")


class _GuardedHTTPConnection(http.client.HTTPConnection):
    def connect(self):
        super().connect()
        _check_peer(self.sock, self.host)


class _GuardedHTTPSConnection(http.client.HTTPSConnection):
    def connect(self):
        # Checked on the plain TCP socket, before the TLS handshake sends anything.
        http.client.HTTPConnection.connect(self)
        _check_peer(self.sock, self.host)
        server_hostname = self._tunnel_host or self.host
        self.sock = self._context.wrap_socket(self.sock, server_hostname=server_hostname)


class _GuardedHTTPHandler(urllib.request.HTTPHandler):
    def http_open(self, req):
        return self.do_open(_GuardedHTTPConnection, req)


class _GuardedHTTPSHandler(urllib.request.HTTPSHandler):
    def https_open(self, req):
        return self.do_open(_GuardedHTTPSConnection, req, context=self._context)


_opener = urllib.request.build_opener(_GuardedHTTPHandler, _GuardedHTTPSHandler, _GuardedRedirect)


def safe_urlopen(request: urllib.request.Request, timeout: float):
    """urlopen that validates the destination, the address actually connected to, and every redirect hop."""
    validate_url(request.full_url)
    return _opener.open(request, timeout=timeout)


def insecure_pull_problem(endpoint: str) -> str | None:
    """A pull-mode check sends the agent token to the agent. Over plain http to a public address anyone on the path can read it
    (and then read that server's metrics). Private/VPN addresses are accepted; ALLOW_INSECURE_PULL=true overrides."""
    parsed = urllib.parse.urlsplit(endpoint)
    if parsed.scheme != "http" or get_settings().allow_insecure_pull:
        return None
    try:
        addresses = [ipaddress.ip_address((parsed.hostname or "").strip("[]"))]
    except ValueError:
        try:
            addresses = [ipaddress.ip_address(info[4][0]) for info in socket.getaddrinfo(parsed.hostname, None)]
        except (socket.gaierror, UnicodeError):
            return None   # unresolved: the check itself will fail
    cgnat = ipaddress.ip_network("100.64.0.0/10")   # Tailscale and other overlay networks
    if all(a.is_private or a in cgnat for a in addresses):
        return None
    return "the agent token would be sent unencrypted over the internet. Use an https:// endpoint (put the agent behind a TLS proxy or set AGENT_TLS_CERT/AGENT_TLS_KEY on it), use push mode, or set ALLOW_INSECURE_PULL=true to accept the risk."
