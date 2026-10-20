import json
from typing import Any, Callable, Optional

from lightguard.core import LightGuardAgent


class LightGuardASGIMiddleware:
    """
    Lightweight ASGI middleware for FastAPI, Starlette, and Quart.
    Intercepts incoming HTTP request bodies and scans for adversarial prompt injections
    and jailbreak directives with sub-millisecond overhead before hitting application routes.
    """

    def __init__(
        self,
        app: Any,
        guard: Optional[LightGuardAgent] = None,
        block_on_violation: bool = True,
        scan_paths: Optional[list[str]] = None,
    ):
        self.app = app
        self.guard = guard if guard is not None else LightGuardAgent()
        self.block = block_on_violation
        self.scan_paths = scan_paths

    async def __call__(self, scope: dict[str, Any], receive: Callable, send: Callable) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        path = scope.get("path", "")
        method = scope.get("method", "GET").upper()

        # If scan_paths is specified, filter by path prefix
        if self.scan_paths and not any(path.startswith(p) for p in self.scan_paths):
            await self.app(scope, receive, send)
            return

        # Only scan mutative payloads
        if method not in ("POST", "PUT", "PATCH"):
            await self.app(scope, receive, send)
            return

        # Buffer the body messages
        body_chunks = []
        more_body = True
        while more_body:
            message = await receive()
            body_chunks.append(message.get("body", b""))
            more_body = message.get("more_body", False)

        raw_body = b"".join(body_chunks)

        # Inspect if text/json
        violation_details = None
        if raw_body:
            try:
                body_str = raw_body.decode("utf-8")
                # Recursively extract text from JSON or scan raw text
                texts_to_scan = []
                try:
                    parsed_json = json.loads(body_str)
                    texts_to_scan = self._extract_strings(parsed_json)
                except Exception:
                    texts_to_scan = [body_str]

                for item in texts_to_scan:
                    obs = self.guard.process_observation(item)
                    if obs["is_untrusted"]:
                        violation_details = {
                            "t1_flagged": obs["t1_flagged"],
                            "t2_risk_score": obs["t2_risk_score"],
                            "was_obfuscated": obs["t0_was_obfuscated"],
                            "total_latency_ms": obs["total_latency_ms"],
                        }
                        break
            except UnicodeDecodeError:
                pass

        if violation_details and self.block:
            error_response = {
                "error": "LightGuard Security Block",
                "message": "Untrusted prompt injection or adversarial directive detected in request payload.",
                "diagnostics": violation_details,
            }
            res_body = json.dumps(error_response).encode("utf-8")
            await send({
                "type": "http.response.start",
                "status": 403,
                "headers": [
                    [b"content-type", b"application/json"],
                    [b"content-length", str(len(res_body)).encode("ascii")],
                    [b"x-lightguard-status", b"blocked"],
                ],
            })
            await send({
                "type": "http.response.body",
                "body": res_body,
                "more_body": False,
            })
            return

        # Re-stream the consumed body back to the downstream application
        body_sent = False

        async def custom_receive() -> dict[str, Any]:
            nonlocal body_sent
            if not body_sent:
                body_sent = True
                return {"type": "http.request", "body": raw_body, "more_body": False}
            return {"type": "http.request", "body": b"", "more_body": False}

        await self.app(scope, custom_receive, send)

    def _extract_strings(self, data: Any) -> list[str]:
        strings = []
        if isinstance(data, str):
            strings.append(data)
        elif isinstance(data, dict):
            for v in data.values():
                strings.extend(self._extract_strings(v))
        elif isinstance(data, list):
            for item in data:
                strings.extend(self._extract_strings(item))
        return strings
