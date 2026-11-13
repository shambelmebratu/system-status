import hashlib
import hmac
import secrets
import threading
import time
from collections import defaultdict, deque

import jwt
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from .config import get_settings
from .database import get_db

COOKIE_NAME = "smwatch_session"
CSRF_HEADER = "x-requested-with"
CSRF_VALUE = "smwatch"

bearer = HTTPBearer(auto_error=False)


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, n=16384, r=8, p=1)
    return f"scrypt${salt.hex()}${digest.hex()}"


def verify_password(password: str, encoded: str) -> bool:
    try:
        _, salt, expected = encoded.split("$")
        actual = hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt), n=16384, r=8, p=1).hex()
        return hmac.compare_digest(actual, expected)
    except (ValueError, TypeError):
        return False


def create_token(user_id: int, email: str, version: int) -> str:
    settings = get_settings()
    now = int(time.time())
    claims = {"sub": str(user_id), "email": email, "ver": version, "iat": now, "exp": now + settings.session_hours * 3600, "jti": secrets.token_hex(8)}
    return jwt.encode(claims, settings.jwt_secret, algorithm="HS256")


class LoginLimiter:
    """In-memory sliding-window limiter keyed by client IP and by email (single API process)."""

    def __init__(self) -> None:
        self._hits: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def _prune(self, key: str, now: float, window: int) -> deque[float]:
        hits = self._hits[key]
        while hits and now - hits[0] > window:
            hits.popleft()
        if not hits:
            self._hits.pop(key, None)
            return deque()
        return hits

    def check(self, *keys: str) -> None:
        settings = get_settings()
        now = time.monotonic()
        with self._lock:
            for key in keys:
                if len(self._prune(key, now, settings.login_window_seconds)) >= settings.login_max_attempts:
                    raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "Too many failed sign-in attempts. Try again later.")

    def fail(self, *keys: str) -> None:
        now = time.monotonic()
        with self._lock:
            for key in keys:
                self._hits[key].append(now)

    def reset(self, *keys: str) -> None:
        with self._lock:
            for key in keys:
                self._hits.pop(key, None)


login_limiter = LoginLimiter()


def require_user(request: Request, credentials: HTTPAuthorizationCredentials | None = Depends(bearer), db: Session = Depends(get_db)) -> dict:
    from .models import User

    token = credentials.credentials if credentials else None
    from_cookie = False
    if not token:
        token = request.cookies.get(COOKIE_NAME)
        from_cookie = True
    if not token:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Authentication required")
    # Cookie sessions need a CSRF guard on state-changing calls (on top of SameSite=Strict):
    # browsers cannot add a custom header cross-origin without a CORS preflight.
    if from_cookie and request.method not in ("GET", "HEAD", "OPTIONS") and request.headers.get(CSRF_HEADER) != CSRF_VALUE:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Missing CSRF header")
    try:
        claims = jwt.decode(token, get_settings().jwt_secret, algorithms=["HS256"], options={"require": ["exp", "sub"]})
    except jwt.PyJWTError as error:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid or expired session") from error
    account = db.get(User, int(claims["sub"]))
    if not account or account.token_version != claims.get("ver", 0) or not account.active:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Session is no longer valid")
    # Until a temporary password is replaced, the account can do nothing except change it (or sign out).
    if account.must_change_password and request.url.path not in PASSWORD_CHANGE_PATHS:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "PASSWORD_CHANGE_REQUIRED")
    # The role is read from the database on EVERY request, so a demotion or deactivation takes effect immediately.
    return {**claims, "uid": account.id, "role": account.role, "name": account.name, "email": account.email}


RANK = {"viewer": 1, "operator": 2, "admin": 3}
PASSWORD_CHANGE_PATHS = {"/api/auth/me", "/api/auth/password", "/api/auth/logout"}


def _at_least(minimum: str):
    def guard(user: dict = Depends(require_user)) -> dict:
        if RANK.get(user["role"], 0) < RANK[minimum]:
            raise HTTPException(status.HTTP_403_FORBIDDEN, f"Your role ({user['role']}) is not allowed to do this. It needs the {minimum} role.")
        return user
    guard.__name__ = f"require_{minimum}"
    return guard


require_operator = _at_least("operator")   # create/edit/delete monitors, alerts, schedules; read logs; manage agent links
require_admin = _at_least("admin")         # manage users
