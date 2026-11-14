import os

os.environ.update(ENVIRONMENT="test", JWT_SECRET="x" * 40, DATABASE_URL="sqlite://")

import pytest
from fastapi import HTTPException
from pydantic import ValidationError

from app.config import Settings
from app.crypto import decrypt, encrypt
from app.netguard import BlockedTargetError, validate_host, validate_url
from app.security import LoginLimiter


def test_insecure_defaults_rejected_in_production():
    with pytest.raises(ValidationError):
        Settings(environment="production", jwt_secret="change-this-secret-before-production", admin_password="change-me-now", _env_file=None)
    Settings(environment="production", jwt_secret="y" * 40, admin_password="a-long-password-1", _env_file=None)


@pytest.mark.parametrize("url", [
    "http://169.254.169.254/latest/meta-data", "http://127.0.0.1:8000", "http://localhost/",
    "http://api:8000/api/health", "http://[::1]/", "http://[::ffff:169.254.169.254]/",
    "file:///etc/passwd", "http://user:pw@example.com/", "gopher://x/",
])
def test_blocked_urls(url):
    with pytest.raises(BlockedTargetError):
        validate_url(url)


def test_allowed_and_option_injection():
    assert validate_url("http://10.0.0.5:9100")
    assert validate_host("192.168.1.10")
    for bad in ("-f", "--help", "a b", "x;rm", ""):
        with pytest.raises(BlockedTargetError):
            validate_host(bad)


def test_encryption_roundtrip_and_legacy_plaintext():
    token = encrypt("secret-token")
    assert token.startswith("enc:v1:") and "secret-token" not in token
    assert decrypt(token) == "secret-token"
    assert decrypt("legacy-plain") == "legacy-plain"


def test_login_limiter():
    limiter = LoginLimiter()
    for _ in range(5):
        limiter.fail("k")
    with pytest.raises(HTTPException) as caught:
        limiter.check("k")
    assert caught.value.status_code == 429
    limiter.reset("k")
    limiter.check("k")


def test_encryption_key_formats(monkeypatch):
    from cryptography.fernet import Fernet
    from app import config, crypto

    for value in ("", "replace-with-anything", "not base64 !!", Fernet.generate_key().decode()):
        monkeypatch.setenv("ENCRYPTION_KEY", value)
        config.get_settings.cache_clear(); crypto._fernet.cache_clear()
        assert crypto.decrypt(crypto.encrypt("tok")) == "tok"
    config.get_settings.cache_clear(); crypto._fernet.cache_clear()


def test_client_ip_behind_proxies():
    from types import SimpleNamespace
    from app.security import client_ip

    def req(peer, xff=None):
        return SimpleNamespace(client=SimpleNamespace(host=peer) if peer else None, headers={"x-forwarded-for": xff} if xff else {})
    assert client_ip(req("172.18.0.5", "203.0.113.7")) == "203.0.113.7"                 # behind our proxy: the real visitor
    assert client_ip(req("172.18.0.5", "6.6.6.6, 203.0.113.7")) == "203.0.113.7"        # a forged left part is ignored (right-most wins)
    assert client_ip(req("127.0.0.1", "2001:db8::1")) == "2001:db8::1"                  # IPv6 works
    assert client_ip(req("8.8.8.8", "6.6.6.6")) == "8.8.8.8"                  # public peer: header NOT trusted
    assert client_ip(req("172.18.0.5", "not-an-ip")) == "172.18.0.5"                    # garbage falls back to the peer
    assert client_ip(req("172.18.0.5")) == "172.18.0.5" and client_ip(req(None)) == "unknown"
    assert client_ip(req("testclient", "1.2.3.4")) == "testclient"                      # non-IP peer (test client): unchanged


def test_outbound_requests_check_the_connected_address_and_keep_credentials_on_origin(monkeypatch):
    import http.server, threading, urllib.request
    from app import netguard
    seen = {}

    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *args): pass
        def do_GET(self):
            seen[self.server.server_port] = self.headers.get("Authorization")
            if self.path == "/go":
                self.send_response(302); self.send_header("Location", f"http://127.0.0.1:{other.server_port}/x"); self.end_headers()
            else:
                self.send_response(200); self.end_headers(); self.wfile.write(b"ok")

    first, other = http.server.HTTPServer(("127.0.0.1", 0), Handler), http.server.HTTPServer(("127.0.0.1", 0), Handler)
    for server in (first, other):
        threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        # DNS rebinding: even when the name check is fooled, the address actually connected to is checked.
        monkeypatch.setattr(netguard, "validate_url", lambda url, resolve=True: url)
        with pytest.raises(BlockedTargetError):
            netguard.safe_urlopen(urllib.request.Request(f"http://127.0.0.1:{first.server_port}/x"), timeout=3)
        # A redirect to another origin never receives the Authorization header.
        monkeypatch.setattr(netguard, "_ip_blocked", lambda ip: None)
        request = urllib.request.Request(f"http://127.0.0.1:{first.server_port}/go", headers={"Authorization": "Bearer secret"})
        netguard.safe_urlopen(request, timeout=3).read()
        assert seen[first.server_port] == "Bearer secret" and seen[other.server_port] is None
    finally:
        first.shutdown(); other.shutdown()
