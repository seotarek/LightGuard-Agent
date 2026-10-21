import json
from typing import Any, Callable, Optional

from lightguard.core import LightGuardAgent


class LightGuardFlaskMiddleware:
    """
    WSGI middleware for Flask and Django applications.
    Intercepts incoming HTTP request bodies and scans for adversarial prompt injections
    and jailbreak directives with sub-millisecond overhead before reaching route handlers.
    """

    def __init__(
        self,
        app: Any,
        guard: Optional[LightGuardAgent] = None,
        block_on_violation: bool = True,
        max_body_size: int = 10 * 1024 * 1024,
    ):
        self.app = app
        self.guard = guard if guard is not None else LightGuardAgent()
        self.block = block_on_violation
        self.max_body_size = max_body_size

    def __call__(self, environ: dict[str, Any], start_response: Callable) -> Any:
        method = environ.get("REQUEST_METHOD", "GET").upper()

        if method in ("POST", "PUT", "PATCH"):
            try:
                content_length = int(environ.get("CONTENT_LENGTH", 0) or 0)
            except (ValueError, TypeError):
                content_length = 0

            if content_length > self.max_body_size:
                error_body = json.dumps({
                    "error": "LightGuard Security Block",
                    "message": f"Payload too large: Content-Length ({content_length} bytes) exceeds limit ({self.max_body_size} bytes).",
                }).encode("utf-8")
                start_response("413 Payload Too Large", [
                    ("Content-Type", "application/json"),
                    ("Content-Length", str(len(error_body))),
                    ("X-LightGuard-Status", "blocked"),
                ])
                return [error_body]

            if content_length > 0:
                wsgi_input = environ.get("wsgi.input")
                if wsgi_input:
                    body_bytes = wsgi_input.read(min(content_length, self.max_body_size + 1))
                    if len(body_bytes) > self.max_body_size:
                        error_body = json.dumps({
                            "error": "LightGuard Security Block",
                            "message": f"Payload too large: Body exceeds limit ({self.max_body_size} bytes).",
                        }).encode("utf-8")
                        start_response("413 Payload Too Large", [
                            ("Content-Type", "application/json"),
                            ("Content-Length", str(len(error_body))),
                            ("X-LightGuard-Status", "blocked"),
                        ])
                        return [error_body]
                    # Reset input buffer for subsequent framework reads
                    from io import BytesIO
                    environ["wsgi.input"] = BytesIO(body_bytes)

                    violation = False
                    try:
                        body_str = body_bytes.decode("utf-8")
                        try:
                            parsed_json = json.loads(body_str)
                            texts = self._extract_strings(parsed_json)
                        except Exception:
                            texts = [body_str]

                        for item in texts:
                            obs = self.guard.process_observation(item)
                            if obs["is_untrusted"]:
                                violation = True
                                break
                    except UnicodeDecodeError:
                        pass

                    if violation and self.block:
                        error_body = json.dumps({
                            "error": "LightGuard Security Block",
                            "message": "Untrusted prompt injection or adversarial directive detected in request payload.",
                        }).encode("utf-8")
                        status = "403 Forbidden"
                        response_headers = [
                            ("Content-Type", "application/json"),
                            ("Content-Length", str(len(error_body))),
                            ("X-LightGuard-Status", "blocked"),
                        ]
                        start_response(status, response_headers)
                        return [error_body]

        return self.app(environ, start_response)

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
