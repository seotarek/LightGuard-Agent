"""Standalone Model Context Protocol (MCP) Security Gateway.

Intercepts JSON-RPC 2.0 communications between MCP clients (Claude Desktop,
Cursor, Zed) and upstream MCP servers, neutralizing indirect prompt injections
and blocking unauthorized high-stakes actions in real time (< 0.2ms).
"""

import json
import sys
from typing import Optional, Tuple

from lightguard.core import LightGuardAgent
from lightguard.mcp import LightGuardMCPProxy


class MCPSecurityGateway:
    """JSON-RPC 2.0 Security Proxy for Model Context Protocol."""

    def __init__(self, guard: Optional[LightGuardAgent] = None):
        self.guard = guard if guard is not None else LightGuardAgent()
        self.proxy = LightGuardMCPProxy(guard=self.guard)

    def process_client_to_server(self, raw_message: str) -> Tuple[bool, str]:
        """Inspect client requests before sending to the MCP server.

        Returns (allowed, forwarded_or_error_message).
        """
        try:
            req = json.loads(raw_message)
        except Exception:
            return True, raw_message

        method = req.get("method", "")
        req_id = req.get("id")

        if method == "tools/call":
            params = req.get("params", {})
            tool_name = params.get("name", "")
            tool_args = params.get("arguments", {})

            validation = self.proxy.intercept_request(
                tool_name=tool_name,
                arguments=tool_args,
            )

            if not validation["allowed"]:
                err_resp = {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {
                        "code": -32001,
                        "message": f"LightGuard Security Violation: {validation['reason']}",
                        "data": {
                            "tool_name": tool_name,
                            "blocked_by": "LightGuard MCP Gateway",
                        },
                    },
                }
                return False, json.dumps(err_resp)

        return True, raw_message

    def process_server_to_client(self, raw_message: str) -> Tuple[bool, str]:
        """Inspect and sanitize server responses before returning to the LLM.

        Returns (is_clean, sanitized_message).
        """
        try:
            resp = json.loads(raw_message)
        except Exception:
            return True, raw_message

        result = resp.get("result")
        if not isinstance(result, dict):
            return True, raw_message

        # Handle tool execution contents
        content_items = result.get("content", [])
        modified = False

        if isinstance(content_items, list):
            for item in content_items:
                if isinstance(item, dict) and item.get("type") == "text":
                    raw_text = item.get("text", "")
                    obs = self.guard.process_observation(raw_text)
                    if obs["is_untrusted"]:
                        item["text"] = obs["sanitized_observation"]
                        modified = True
                        self.proxy.session_is_untrusted = True

        if modified:
            return False, json.dumps(resp)

        return True, raw_message


def run_stdio_gateway(upstream_cmd: list[str]) -> None:
    """Run an interactive bidirectional stdio proxy forwarding to upstream process."""
    import subprocess
    import threading

    gateway = MCPSecurityGateway()

    proc = subprocess.Popen(
        upstream_cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=sys.stderr,
        text=True,
        bufsize=1,
    )

    def forward_stdin():
        try:
            for line in sys.stdin:
                allowed, out = gateway.process_client_to_server(line.strip())
                if allowed:
                    if proc.stdin:
                        proc.stdin.write(out + "\n")
                        proc.stdin.flush()
                else:
                    # Echo error back directly to client stdout
                    sys.stdout.write(out + "\n")
                    sys.stdout.flush()
        except Exception:
            pass

    def forward_stdout():
        try:
            if proc.stdout:
                for line in proc.stdout:
                    _, out = gateway.process_server_to_client(line.strip())
                    sys.stdout.write(out + "\n")
                    sys.stdout.flush()
        except Exception:
            pass

    t_in = threading.Thread(target=forward_stdin, daemon=True)
    t_out = threading.Thread(target=forward_stdout, daemon=True)
    t_in.start()
    t_out.start()

    proc.wait()


if __name__ == "__main__":
    if len(sys.argv) > 1:
        run_stdio_gateway(sys.argv[1:])
    else:
        print("Usage: python -m lightguard.mcp_gateway <upstream_mcp_command> [args...]")
        sys.exit(1)
