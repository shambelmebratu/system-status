"""QA: multi-step API tests.

A test is a list of steps. Each step sends one HTTP request (method, URL, headers, body), then checks assertions against the answer
(status, JSON values, headers, body text, response time) and may extract values into variables for later steps ({{name}}), for
example: log in, keep the token, call the API with it. Requests go through the same outbound guard as every check (no loopback,
metadata or internal services; every redirect re-checked). Stored results never contain Authorization/cookie headers or values of
variables marked secret.
"""
from __future__ import annotations

import json
import re
import time
import urllib.error
import urllib.request
import uuid
from datetime import datetime, timedelta, timezone

from pydantic import BaseModel, Field, field_validator

from .netguard import BlockedTargetError, safe_urlopen, validate_url

MAX_BODY = 2_000_000
STORED_BODY = 2000
METHODS = "GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS"
SECRET_HEADERS = {"authorization", "cookie", "set-cookie", "x-api-key", "api-key", "x-auth-token", "proxy-authorization"}
VAR = re.compile(r"\{\{\s*([A-Za-z_$][A-Za-z0-9_.$-]*)\s*\}\}")


# ------------------------------------------------------------------------------------------------ definitions
class Assertion(BaseModel):
    kind: str = Field(pattern="^(status|json|header|body|time)$")
    path: str = Field(default="", max_length=200)       # json: a.b[0].c   header: name
    op: str = Field(default="eq", pattern="^(eq|ne|lt|lte|gt|gte|contains|not_contains|exists|not_exists|matches|in|type)$")
    value: str = Field(default="", max_length=2000)


class Extract(BaseModel):
    var: str = Field(pattern=r"^[A-Za-z_][A-Za-z0-9_]{0,40}$")
    source: str = Field(default="json", pattern="^(json|header|status|body)$")
    path: str = Field(default="", max_length=200)


class Step(BaseModel):
    name: str = Field(default="", max_length=100)
    method: str = Field(default="GET", pattern=f"^({METHODS})$")
    url: str = Field(min_length=1, max_length=2000)
    headers: dict[str, str] = Field(default_factory=dict)
    body: str = Field(default="", max_length=100_000)
    timeout_seconds: int = Field(default=10, ge=1, le=60)
    assertions: list[Assertion] = Field(default_factory=list, max_length=30)
    extract: list[Extract] = Field(default_factory=list, max_length=20)

    @field_validator("headers")
    @classmethod
    def headers_ok(cls, v: dict[str, str]) -> dict[str, str]:
        if len(v) > 40:
            raise ValueError("At most 40 headers per step")
        for k, val in v.items():
            if not re.fullmatch(r"[A-Za-z0-9!#$%&'*+.^_`|~-]{1,100}", k) or "\n" in val or "\r" in val or len(val) > 4000:
                raise ValueError(f"Invalid header: {k[:40]}")
        return v


class TestDefinition(BaseModel):
    steps: list[Step] = Field(min_length=1, max_length=20)
    variables: dict[str, str] = Field(default_factory=dict)
    secret_variables: list[str] = Field(default_factory=list, max_length=50)

    @field_validator("variables")
    @classmethod
    def vars_ok(cls, v: dict[str, str]) -> dict[str, str]:
        if len(v) > 50 or any(not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,40}", k) or len(val) > 4000 for k, val in v.items()):
            raise ValueError("Variable names may contain letters, digits and _ (up to 50 variables)")
        return v


# ------------------------------------------------------------------------------------------------ helpers
def substitute(text: str, variables: dict[str, str]) -> str:
    def value(match):
        name = match.group(1)
        if name == "$timestamp":
            return str(int(time.time()))
        if name == "$isoTime":
            return datetime.now(timezone.utc).isoformat()
        if name == "$uuid":
            return str(uuid.uuid4())
        return str(variables.get(name, match.group(0)))
    return VAR.sub(value, text or "")


_MISSING = object()


def json_path(data, path: str):
    """a.b[0].c / $.a.b / [2].name / items[-1]. Returns _MISSING when the path does not exist."""
    path = (path or "").strip()
    if path in ("", "$"):
        return data
    path = path[2:] if path.startswith("$.") else path.lstrip("$")
    for part in re.findall(r"[^.\[\]]+|\[-?\d+\]", path):
        if part.startswith("["):
            index = int(part[1:-1])
            if not isinstance(data, list) or not -len(data) <= index < len(data):
                return _MISSING
            data = data[index]
        elif isinstance(data, dict) and part in data:
            data = data[part]
        elif isinstance(data, list) and part.isdigit() and int(part) < len(data):
            data = data[int(part)]
        else:
            return _MISSING
    return data


def _number(value):
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _type_of(value) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, (int, float)):
        return "number"
    if isinstance(value, str):
        return "string"
    if isinstance(value, list):
        return "array"
    if isinstance(value, dict):
        return "object"
    return type(value).__name__


def compare(actual, op: str, expected: str) -> bool:
    if op == "exists":
        return actual is not _MISSING
    if op == "not_exists":
        return actual is _MISSING
    if actual is _MISSING:
        return False
    if op == "type":
        return _type_of(actual) == expected.strip().lower()
    text = actual if isinstance(actual, str) else json.dumps(actual) if isinstance(actual, (dict, list, bool)) or actual is None else str(actual)
    if op in ("eq", "ne"):
        a, b = _number(actual), _number(expected)
        equal = (a == b) if a is not None and b is not None and not isinstance(actual, str) else text == expected
        return equal if op == "eq" else not equal
    if op in ("lt", "lte", "gt", "gte"):
        a, b = _number(actual), _number(expected)
        if a is None or b is None:
            return False
        return {"lt": a < b, "lte": a <= b, "gt": a > b, "gte": a >= b}[op]
    if op == "contains":
        return expected in text if not isinstance(actual, list) else any(str(x) == expected or x == _number(expected) for x in actual)
    if op == "not_contains":
        return not compare(actual, "contains", expected)
    if op == "matches":
        try:
            return re.search(expected, text) is not None
        except re.error:
            return False
    if op == "in":
        return text in [v.strip() for v in expected.split(",")]
    return False


def _show(value, limit: int = 200) -> str:
    if value is _MISSING:
        return "(missing)"
    text = value if isinstance(value, str) else json.dumps(value, default=str)
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _mask(text: str, secrets: list[str]) -> str:
    for s in secrets:
        if s and len(s) >= 4:
            text = text.replace(s, "***")
    return text


OP_WORDS = {"eq": "equals", "ne": "is not", "lt": "is less than", "lte": "is at most", "gt": "is greater than", "gte": "is at least", "contains": "contains",
            "not_contains": "does not contain", "exists": "exists", "not_exists": "does not exist", "matches": "matches", "in": "is one of", "type": "is of type"}


def describe(a: Assertion) -> str:
    subject = {"status": "Status code", "json": f"JSON {a.path or '$'}", "header": f"Header {a.path}", "body": "Body", "time": "Response time (ms)"}[a.kind]
    return f"{subject} {OP_WORDS[a.op]}{'' if a.op in ('exists', 'not_exists') else ' ' + a.value}"


# ------------------------------------------------------------------------------------------------ running
def run_test(definition: dict) -> dict:
    """Runs every step in order (pure network I/O; safe in a worker thread). Stops at the first failing step."""
    spec = TestDefinition.model_validate(definition)
    variables = dict(spec.variables)
    secrets = [variables[k] for k in spec.secret_variables if k in variables]
    started = time.perf_counter()
    results: list[dict] = []
    failed_at = None
    for index, step in enumerate(spec.steps):
        name = step.name or f"Step {index + 1}"
        if failed_at is not None:
            results.append({"name": name, "method": step.method, "url": _mask(substitute(step.url, variables), secrets), "status": "skipped"})
            continue
        url = substitute(step.url, variables)
        headers = {k: substitute(v, variables) for k, v in step.headers.items()}
        body = substitute(step.body, variables) if step.body else ""
        entry: dict = {"name": name, "method": step.method, "url": _mask(url, secrets), "request_headers": {k: ("***" if k.lower() in SECRET_HEADERS else _mask(v, secrets)) for k, v in headers.items()},
                       "request_body": _mask(body[:STORED_BODY], secrets) if body else ""}
        t0 = time.perf_counter()
        status_code, resp_headers, raw = None, {}, b""
        try:
            validate_url(url)
            data = body.encode() if body and step.method not in ("GET", "HEAD") else None
            if data is not None and not any(k.lower() == "content-type" for k in headers):
                headers["Content-Type"] = "application/json" if body.lstrip()[:1] in ("{", "[") else "text/plain"
            request = urllib.request.Request(url, data=data, method=step.method, headers={"User-Agent": "SM-Watch-QA/1.0", **headers})
            try:
                with safe_urlopen(request, timeout=step.timeout_seconds) as response:
                    status_code, resp_headers, raw = response.status, dict(response.headers), response.read(MAX_BODY + 1)
            except urllib.error.HTTPError as error:   # a 4xx/5xx is an answer, not a failure: the assertions decide
                status_code, resp_headers, raw = error.code, dict(error.headers or {}), error.read(MAX_BODY + 1)
                error.close()
        except BlockedTargetError as error:
            entry.update(status="error", error=f"Blocked: {error}")
        except Exception as error:   # noqa: BLE001
            reason = getattr(error, "reason", error)
            entry.update(status="error", error=("Timed out" if "timed out" in str(reason).lower() else _mask(str(reason), secrets))[:300])
        elapsed = round((time.perf_counter() - t0) * 1000, 1)
        entry["ms"] = elapsed
        if entry.get("status") == "error":
            failed_at = index
            results.append(entry)
            continue
        text = raw[:MAX_BODY].decode("utf-8", "replace")
        try:
            parsed = json.loads(text) if text.strip()[:1] in ("{", "[") else _MISSING
        except ValueError:
            parsed = _MISSING
        lower_headers = {k.lower(): v for k, v in resp_headers.items()}
        checks = []
        for a in step.assertions:
            expected = substitute(a.value, variables)
            actual = {"status": status_code, "time": elapsed, "body": text,
                      "json": json_path(parsed, a.path) if parsed is not _MISSING else _MISSING,
                      "header": lower_headers.get(a.path.lower(), _MISSING)}[a.kind]
            ok = compare(actual, a.op, expected)
            shown_actual = "***" if a.kind == "header" and a.path.lower() in SECRET_HEADERS else _mask(_show(actual if a.kind != "body" else (text[:200] + ("…" if len(text) > 200 else ""))), secrets)
            checks.append({"text": describe(a.model_copy(update={"value": _mask(expected, secrets)})), "ok": ok, "actual": shown_actual})
        if not step.assertions:   # no assertions: any 2xx/3xx passes
            checks.append({"text": "Status code is below 400 (no assertions set)", "ok": status_code is not None and status_code < 400, "actual": str(status_code)})
        for x in step.extract:
            value = {"status": status_code, "body": text, "header": lower_headers.get(x.path.lower(), _MISSING),
                     "json": json_path(parsed, x.path) if parsed is not _MISSING else _MISSING}[x.source]
            if value is not _MISSING and value is not None:
                variables[x.var] = value if isinstance(value, str) else json.dumps(value)
                if x.source == "header" and x.path.lower() in SECRET_HEADERS or re.search(r"token|secret|pass|key|cookie|session", x.var, re.I):
                    secrets.append(variables[x.var])
        passed = all(c["ok"] for c in checks)
        entry.update(status="passed" if passed else "failed", status_code=status_code, checks=checks, size=len(raw),
                     response_headers={k: ("***" if k.lower() in SECRET_HEADERS else v[:300]) for k, v in list(resp_headers.items())[:30]},
                     response_body=_mask(text[:STORED_BODY], secrets), truncated=len(text) > STORED_BODY,
                     extracted=[x.var for x in step.extract if x.var in variables])
        if not passed:
            failed_at = index
        results.append(entry)
    total = round((time.perf_counter() - started) * 1000, 1)
    first_bad = next((r for r in results if r["status"] in ("failed", "error")), None)
    error = None
    if first_bad:
        failing = [c["text"] + f" (got {c['actual']})" for c in first_bad.get("checks", []) if not c["ok"]][:3]
        error = f"{first_bad['name']}: " + (first_bad.get("error") or "; ".join(failing))
    return {"status": "failed" if first_bad else "passed", "duration_ms": total, "steps": results, "error": error[:1000] if error else None}


def apply_test_result(session, test, result: dict, trigger: str = "schedule") -> None:
    """Records the run, the uptime sample, the incident and (debounced) alerts: the same rules as every other monitor."""
    from .models import TestRun
    from .monitoring import (format_alert, outage_seconds, queue_event, record_result, reminder_minutes, settle_status, should_notify_again,
                             sync_incident)
    now = datetime.now(timezone.utc)
    previous = test.last_status
    raw = "up" if result["status"] == "passed" else "down"
    session.add(TestRun(test_id=test.id, started_at=now, duration_ms=result["duration_ms"], status=result["status"], trigger=trigger,
                        results=json.dumps(result["steps"]), error=result["error"]))
    record_result(session, "test", test.id, raw, result["duration_ms"], None, result["error"])
    test.last_run_at = test.last_checked_at = now
    test.last_duration_ms, test.last_error = result["duration_ms"], result["error"]
    status = settle_status(test, raw)
    if status == previous and raw == "down" and previous != "down":
        session.commit()   # first failure: kept in history, alert after ALERT_AFTER_FAILURES
        return
    test.last_status = status
    resolved = sync_incident(session, "test", test, status, test.last_error)
    if status == "down" and (previous != "down" or should_notify_again(session, "test", test.id, reminder_minutes(test))):
        state = "down" if previous != "down" else "still_down"
        queue_event(session, "test", test, "critical", format_alert("API test", state, test.name, test.last_error, at=now), deliver=True, state=state)
    elif status == "up" and previous == "down":
        queue_event(session, "test", test, "info", format_alert("API test", "recovered", test.name, f"All steps pass again ({round(result['duration_ms'])} ms)", at=now, duration=outage_seconds(resolved)), deliver=True, state="recovered")
    session.commit()


def prune_runs(session, keep_days: int) -> int:
    from sqlalchemy import delete
    from .models import TestRun
    return session.execute(delete(TestRun).where(TestRun.started_at < datetime.now(timezone.utc) - timedelta(days=keep_days))).rowcount or 0
