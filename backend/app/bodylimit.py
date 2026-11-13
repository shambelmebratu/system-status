"""Refuses oversized request bodies before they are read into memory or parsed.

Every API body is small JSON, except agent answers (log text, cluster lists). Without a cap, anyone (no login needed) could post
hundreds of megabytes to an endpoint and make the API buffer and parse it."""
import json

from .config import get_settings

RESULT_SUFFIX = "/result"


class BodyLimitMiddleware:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or scope["method"] in ("GET", "HEAD", "OPTIONS"):
            return await self.app(scope, receive, send)
        settings = get_settings()
        path = scope.get("path", "")
        agent_result = path.startswith(("/api/agent/tasks/", "/api/k8s-agent/tasks/")) and path.endswith(RESULT_SUFFIX)
        limit = (settings.max_agent_result_kb if agent_result else settings.max_request_body_kb) * 1024
        declared = dict(scope["headers"]).get(b"content-length")
        too_big = False
        try:
            too_big = declared is not None and int(declared) > limit
        except ValueError:
            too_big = True
        if too_big:
            return await self._reject(send, limit)

        received = 0
        rejected = False

        async def limited_receive():
            nonlocal received, rejected
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > limit:          # no (or a lying) Content-Length: stop as soon as the stream passes the cap
                    rejected = True
                    return {"type": "http.disconnect"}
            return message

        sent = False

        async def guarded_send(message):
            nonlocal sent
            if rejected and not sent:
                sent = True
                await self._reject(send, limit)
                return
            if not rejected:
                await send(message)

        await self.app(scope, limited_receive, guarded_send)
        if rejected and not sent:
            await self._reject(send, limit)

    @staticmethod
    async def _reject(send, limit: int) -> None:
        body = json.dumps({"detail": f"Request body too large (limit {limit // 1024} KB)"}).encode()
        await send({"type": "http.response.start", "status": 413, "headers": [(b"content-type", b"application/json"), (b"content-length", str(len(body)).encode()), (b"connection", b"close")]})
        await send({"type": "http.response.body", "body": body})
