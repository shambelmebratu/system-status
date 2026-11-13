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
