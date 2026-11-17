"""Two-factor sign-in (TOTP, RFC 6238) with one-time recovery codes, and the admin policy that can require it."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import struct
import time
import urllib.parse

from sqlalchemy.orm import Session

STEP = 30
DIGITS = 6
POLICY_KEY = "security"
POLICIES = ("none", "admins", "everyone")


def new_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")


def _code(secret: str, counter: int) -> str:
    key = base64.b32decode(secret + "=" * (-len(secret) % 8), casefold=True)
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    value = (struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF) % (10 ** DIGITS)
    return str(value).zfill(DIGITS)


def verify(secret: str, code: str, last_step: int | None, now: float | None = None) -> int | None:
    """The time step the code belongs to (accepting one step of clock drift either way), or None. A step at or before `last_step`
    is refused, so an observed code cannot be replayed."""
    code = "".join(ch for ch in (code or "") if ch.isdigit())
    if len(code) != DIGITS or not secret:
        return None
    current = int((now or time.time()) // STEP)
    for step in (current - 1, current, current + 1):
        if hmac.compare_digest(_code(secret, step), code) and (last_step is None or step > last_step):
            return step
    return None


def uri(secret: str, account: str, issuer: str) -> str:
    label = urllib.parse.quote(f"{issuer}:{account}")
    return f"otpauth://totp/{label}?secret={secret}&issuer={urllib.parse.quote(issuer)}&algorithm=SHA1&digits={DIGITS}&period={STEP}"


def qr_svg(text: str) -> str:
    import io
    import segno
    out = io.BytesIO()
    segno.make(text, error="m").save(out, kind="svg", scale=5, border=2, dark="#0b1220", light="#ffffff", xmldecl=False, svgns=True)
    return out.getvalue().decode()


def _hash(code: str) -> str:
    return hashlib.sha256(code.replace("-", "").lower().encode()).hexdigest()


def new_recovery_codes() -> tuple[list[str], str]:
    codes = [f"{secrets.token_hex(3)}-{secrets.token_hex(3)}" for _ in range(10)]
    return codes, json.dumps([_hash(c) for c in codes])


def use_recovery_code(stored: str | None, code: str) -> str | None:
    """New stored value with the code removed, or None when the code is not valid."""
    hashes = json.loads(stored or "[]")
    digest = _hash(code.strip())
    if digest not in hashes:
        return None
    hashes.remove(digest)
    return json.dumps(hashes)


def policy(db: Session) -> str:
    from .models import AppSetting
    row = db.get(AppSetting, POLICY_KEY)
    try:
        value = json.loads(row.value).get("require_2fa", "none") if row else "none"
    except ValueError:
        value = "none"
    return value if value in POLICIES else "none"


def set_policy(db: Session, value: str, user: str) -> None:
    from .models import AppSetting
    row = db.get(AppSetting, POLICY_KEY) or AppSetting(key=POLICY_KEY)
    data = json.loads(row.value) if row.value else {}
    data["require_2fa"] = value
    row.value, row.updated_by = json.dumps(data), user
    db.add(row)


def required_for(db: Session, role: str) -> bool:
    p = policy(db)
    return p == "everyone" or (p == "admins" and role == "admin")
